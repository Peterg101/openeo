"""FastAPI application factory for the OpenEO web UI.

Security model (see SECURITY.md):
  * One app-level dependency (`guard`) runs for EVERY route. A request is
    refused unless its (method, path) is in PUBLIC_ROUTES or it carries a valid
    session cookie, an accepted bearer token (GET /metrics, GET /api only) or the
    internal loopback token. A new route is therefore authenticated by default.
  * State-changing requests must be same-origin (Origin/Referer vs Host) and
    use Content-Type: application/json.

Written to run on both pydantic v1 (Debian Bookworm fastapi 0.92) and v2: the
only body type used is a plain `dict` and responses are built by hand.
"""
import datetime
import hmac
import json
import logging
import numbers

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from lib import internal_auth
from lib.webapp import csrf, passwords
from lib.webapp.deps import (Deps, get_audit, get_auth, get_config_db, get_data_log,
                             get_deps, get_limiter, get_modules, get_restart, get_run_cmd,
                             get_sessions, get_snapshot, get_updater)
from lib.webapp.loginpage import NO_PASSWORD_MESSAGE, render_login_page
from lib.webapp.secret_keys import mask_value, public_module_config
from lib.webapp.sessions import ABSOLUTE_TIMEOUT
from lib.webapp.settings_validation import SettingsError, validate_settings
from lib.webapp.staticfiles import resolve_static

_LOGGER = logging.getLogger(__name__)

SESSION_COOKIE = "openeo_session"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
UPDATE_ACTIONS = ("openeo", "raspberrypi", "reboot", "status")

# The ONLY routes reachable without authentication.
PUBLIC_ROUTES = frozenset({
    ("GET", "/login"),
    ("POST", "/login"),
    ("GET", "/health"),
    ("HEAD", "/health"),
    ("GET", "/favicon.ico"),
})
# Routes that also accept `Authorization: Bearer <api token>`.
BEARER_ROUTES = frozenset({("GET", "/metrics"), ("GET", "/api")})

DEBUG_COMMANDS = (
    ["whoami"],
    ["df", "-k"],
    ["netstat", "-4l"],
    ["ps", "-ef"],            # filtered for "openeo" in Python, not by a shell pipe
    ["free", "-h"],
    ["systemctl", "status", "openeo", "--no-pager", "--output=short-precise"],
    ["ls", "-l", "/home/pi/releases/"],
    ["journalctl", "--list-boots"],
    ["journalctl", "-b", "2"],
    ["journalctl", "-b", "1"],
    ["journalctl"],
)
MAX_DEBUG_OUTPUT = 512 * 1024


def json_response(obj, status_code=200):
    # json.dumps (not JSONResponse) to keep the historic output for odd floats
    return Response(content=json.dumps(obj, default=str), status_code=status_code,
                    media_type="application/json")


def _client_ip(request):
    return request.client.host if request.client else "unknown"


def _authenticate(request, deps):
    """Return "session" | "bearer" | "internal" | None."""
    token = request.cookies.get(SESSION_COOKIE)
    if token and deps.sessions.validate(token):
        return "session"
    supplied = request.headers.get(internal_auth.HEADER)
    if (supplied and deps.internal_token and _client_ip(request) in deps.internal_hosts
            and _consteq(supplied, deps.internal_token)):
        return "internal"
    authz = request.headers.get("authorization", "")
    if (request.method, request.url.path) in BEARER_ROUTES and authz[:7].lower() == "bearer ":
        if deps.auth.check_api_token(authz[7:].strip()):
            return "bearer"
    return None


def _consteq(a, b):
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _check_state_change(request):
    if not csrf.origin_allowed(request.headers.get("origin"), request.headers.get("referer"),
                               request.headers.get("host")):
        raise HTTPException(status_code=403, detail="Cross-origin request refused")
    if not csrf.is_json_content_type(request.headers.get("content-type")):
        raise HTTPException(status_code=415, detail="Content-Type must be application/json")


def guard(request: Request, deps: Deps = Depends(get_deps)):
    """Runs before every route: authentication, CSRF origin and content type."""
    key = (request.method, request.url.path)
    state_changing = request.method not in SAFE_METHODS
    if key in PUBLIC_ROUTES:
        request.state.principal = None
        if state_changing:
            _check_state_change(request)
        return
    principal = _authenticate(request, deps)
    if principal is None:
        raise HTTPException(status_code=401, detail="Not authenticated",
                            headers={"WWW-Authenticate": "Bearer"} if key in BEARER_ROUTES else None)
    request.state.principal = principal
    if state_changing:
        _check_state_change(request)


def require_session(request: Request):
    """Credential management is for a logged-in browser session only."""
    if getattr(request.state, "principal", None) != "session":
        raise HTTPException(status_code=403, detail="Requires an interactive login")


def _set_cookie(response, token):
    response.set_cookie(SESSION_COOKIE, token, max_age=ABSOLUTE_TIMEOUT, path="/",
                        httponly=True, samesite="strict")


def _clear_cookie(response):
    response.delete_cookie(SESSION_COOKIE, path="/")


def _string_field(payload, name):
    value = payload.get(name)
    if not isinstance(value, str):
        raise HTTPException(status_code=400, detail="'%s' is required" % name)
    return value


def build_metrics(snapshot):
    lines = []
    for key, value in snapshot.items():
        if key[0] == "_":
            continue
        if isinstance(value, bool):
            value = int(value)
        if isinstance(value, numbers.Number):
            if key == "eo_charger_state_id":
                lines.append("# HELP %s %s" % (key, snapshot.get("eo_charger_state", "")))
            lines.append("# TYPE %s gauge" % key)
            lines.append("%s{} %s" % (key, value))
    return "\n".join(lines) + ("\n" if lines else "")


def build_api_status(snapshot):
    status = {"eo_charger_state": {"id": snapshot.get("eo_charger_state_id"),
                                   "status": snapshot.get("eo_charger_state")}}
    for key, value in snapshot.items():
        if key[0] != "_" and isinstance(value, numbers.Number):
            if key not in ("eo_charger_state_id", "eo_charger_state"):
                status[key] = value
    return status


def _config_view(modules):
    return {name: public_module_config(m.pluginConfig) for name, m in modules.items()}


def create_app(deps: Deps) -> FastAPI:
    app = FastAPI(dependencies=[Depends(guard)], docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.state.deps = deps

    # ---- plumbing -------------------------------------------------------
    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        if not request.url.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request, exc):
        if (exc.status_code == 401 and request.method == "GET"
                and "text/html" in request.headers.get("accept", "")):
            return RedirectResponse("/login", status_code=303)
        return Response(content=json.dumps({"detail": exc.detail}), status_code=exc.status_code,
                        media_type="application/json", headers=getattr(exc, "headers", None))

    # ---- public ---------------------------------------------------------
    @app.api_route("/health", methods=["GET", "HEAD"])
    def health():
        return json_response({"status": "ok"})

    @app.get("/login")
    def login_page(request: Request, sessions=Depends(get_sessions), auth=Depends(get_auth)):
        if sessions.validate(request.cookies.get(SESSION_COOKIE)):
            return RedirectResponse("/", status_code=303)
        return HTMLResponse(render_login_page(auth.has_password()),
                            headers={"Content-Security-Policy":
                                     "default-src 'none'; style-src 'unsafe-inline'; "
                                     "script-src 'unsafe-inline'; connect-src 'self'; "
                                     "form-action 'self'; base-uri 'none'"})

    @app.get("/favicon.ico")
    def favicon(deps: Deps = Depends(get_deps)):
        found = resolve_static(deps.static_dir, "/favicon.ico")
        if not found:
            raise HTTPException(status_code=404, detail="Not Found")
        return FileResponse(found[0], media_type=found[1])

    @app.post("/login")
    def login(request: Request, payload: dict = Body(...), auth=Depends(get_auth),
              sessions=Depends(get_sessions), limiter=Depends(get_limiter),
              audit=Depends(get_audit)):
        if not auth.has_password():
            raise HTTPException(status_code=503, detail=NO_PASSWORD_MESSAGE)
        ip = _client_ip(request)
        wait = limiter.retry_after(ip)
        if wait > 0:
            return Response(content=json.dumps({"detail": "Too many attempts, retry later"}),
                            status_code=429, media_type="application/json",
                            headers={"Retry-After": str(wait)})
        password = _string_field(payload, "password")
        username = payload.get("username", "admin")
        ok = auth.verify_password(password) and username == "admin"
        if not ok:
            limiter.record_failure(ip)
            audit("login failed from %s" % ip)
            raise HTTPException(status_code=401, detail="Incorrect password")
        limiter.record_success(ip)
        audit("login from %s" % ip)
        response = json_response({"status": "ok"})
        _set_cookie(response, sessions.create())
        return response

    # ---- session / credential management --------------------------------
    @app.post("/logout")
    def logout(request: Request, sessions=Depends(get_sessions), audit=Depends(get_audit)):
        require_session(request)
        sessions.revoke(request.cookies.get(SESSION_COOKIE))
        audit("logout")
        response = json_response({"status": "ok"})
        _clear_cookie(response)
        return response

    @app.get("/auth/status")
    def auth_status(auth=Depends(get_auth)):
        return json_response({"authenticated": True, "api_token_enabled": auth.api_token_enabled()})

    def _verify_current(request, payload, auth, limiter, field):
        ip = _client_ip(request)
        wait = limiter.retry_after(ip)
        if wait > 0:
            raise HTTPException(status_code=429, detail="Too many attempts, retry later",
                                headers={"Retry-After": str(wait)})
        if not auth.verify_password(_string_field(payload, field)):
            limiter.record_failure(ip)
            raise HTTPException(status_code=403, detail="Current password is incorrect")
        limiter.record_success(ip)

    @app.post("/change_password")
    def change_password(request: Request, payload: dict = Body(...), auth=Depends(get_auth),
                        sessions=Depends(get_sessions), limiter=Depends(get_limiter),
                        audit=Depends(get_audit)):
        require_session(request)
        _verify_current(request, payload, auth, limiter, "current_password")
        new = _string_field(payload, "new_password")
        problem = passwords.password_policy_error(new)
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        auth.set_password(new)
        sessions.revoke_all()
        audit("admin password changed; all sessions revoked")
        response = json_response({"status": "ok", "relogin": True})
        _clear_cookie(response)
        return response

    @app.post("/api_token")
    def api_token_create(request: Request, payload: dict = Body(...), auth=Depends(get_auth),
                         limiter=Depends(get_limiter), audit=Depends(get_audit)):
        require_session(request)
        _verify_current(request, payload, auth, limiter, "password")
        token = auth.create_api_token()
        audit("API token generated")
        return json_response({"token": token})   # the only time the plaintext is shown

    @app.post("/api_token/revoke")
    def api_token_revoke(request: Request, auth=Depends(get_auth), audit=Depends(get_audit)):
        require_session(request)
        auth.revoke_api_token()
        audit("API token revoked")
        return json_response({"status": "ok"})

    # ---- read-only data ---------------------------------------------------
    @app.get("/metrics")
    def metrics(snapshot=Depends(get_snapshot)):
        return Response(content=build_metrics(dict(snapshot())), media_type="text/plain")

    @app.get("/api")
    def api_status(snapshot=Depends(get_snapshot)):
        return json_response(build_api_status(dict(snapshot())))

    @app.get("/getstatus")
    def getstatus(snapshot=Depends(get_snapshot)):
        return json_response({k: v for k, v in dict(snapshot()).items() if k[0] != "_"})

    @app.get("/getconfig")
    def getconfig(modules=Depends(get_modules)):
        return json_response(_config_view(modules()))

    @app.get("/get_user_settings")
    def get_user_settings(modules=Depends(get_modules)):
        user_settings = {}
        for modulename, module in modules().items():
            if not hasattr(module, "get_user_settings"):
                continue
            try:
                fields = module.get_user_settings()
                if not module.CORE_PLUGIN:
                    fields.insert(0, {"type": "boolean", "name": "enabled",
                                      "label": "Enable Module",
                                      "default": module.pluginConfig["enabled"]})
                if isinstance(fields, list) and len(fields) > 0:
                    safe = []
                    for field in fields:
                        field = dict(field)
                        if "default" in field:
                            field["default"] = mask_value(field.get("name"), field["default"])
                        safe.append(field)
                    user_settings[modulename] = {"name": module.PRETTY_NAME, "fields": safe}
            except Exception as e:
                _LOGGER.error("Exception getting options for %r: %r" % (module, e))
        return json_response(user_settings)

    @app.get("/getsessiondata")
    def getsessiondata(modules=Depends(get_modules)):
        mods = modules()
        data = mods["chargersession"].get_sessions() if "chargersession" in mods else []
        return json_response(data)

    @app.get("/getchartdata")
    def getchartdata(request: Request, data_log=Depends(get_data_log)):
        log = data_log()
        if log is None:
            raise HTTPException(status_code=404, detail="Not Found")
        q = request.query_params
        since = q.get("since", "")
        try:
            since = datetime.datetime.strptime(since, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            since = None
        series = q.get("series", "").split(",")
        if series == [""]:
            series = None
        if q.get("type", "") == "plotly":
            return json_response(log.get_plotly(since, series))
        return json_response(log.get_data(since, series))

    @app.get("/debugdata")
    def debugdata(run_cmd=Depends(get_run_cmd), db=Depends(get_config_db)):
        results = {}
        for argv in DEBUG_COMMANDS:
            label = " ".join(argv)
            try:
                code, out, err = run_cmd(argv)
            except Exception as e:   # missing binary, timeout ...
                results[label] = "Error: %s" % e
                continue
            if code != 0:
                results[label] = "Error: %s" % ((err or "").strip() or "exit status %s" % code)
                continue
            if argv[0] == "ps":
                out = "\n".join(l for l in out.splitlines() if "openeo" in l)
            results[label] = out.strip()[-MAX_DEBUG_OUTPUT:]
        results["log"] = db.logget()
        return json_response(results)

    # ---- actions ------------------------------------------------------------
    @app.post("/update")
    def update(payload: dict = Body(...), updater=Depends(get_updater), audit=Depends(get_audit)):
        action = payload.get("action")
        if action not in UPDATE_ACTIONS:
            raise HTTPException(status_code=400, detail="Unknown action")
        if action != "status":
            audit("update action: %s" % action)
        return json_response(updater(action))

    @app.post("/restart")
    def restart(restart_fn=Depends(get_restart), audit=Depends(get_audit)):
        audit("restart requested")
        restart_fn()
        return json_response({"status": "requested"})

    @app.post("/setsettings")
    def setsettings(payload: dict = Body(...), db=Depends(get_config_db),
                    modules=Depends(get_modules), audit=Depends(get_audit)):
        mods = modules()
        try:
            updates = validate_settings(payload, mods)    # validate ALL before writing ANY
        except SettingsError as e:
            raise HTTPException(status_code=400, detail=str(e))
        for module, key, value in updates:
            db.set(module, key, value)
        audit("settings changed: " + ", ".join(sorted("%s:%s" % (m, k) for m, k, _ in updates)))
        # Instruct all modules to reconfigure themselves.
        for name, module in mods.items():
            stored = db.get(name)
            if stored is not None:
                module.configure(stored)
        return json_response({"status": "success", "config": _config_view(mods)})

    # ---- static UI (must stay last: catch-all) --------------------------------
    @app.api_route("/{full_path:path}", methods=["GET", "HEAD"])
    def static_files(full_path: str, deps: Deps = Depends(get_deps)):
        found = resolve_static(deps.static_dir, "/" + full_path)
        if not found:
            raise HTTPException(status_code=404, detail="Not Found")
        return FileResponse(found[0], media_type=found[1])

    return app
