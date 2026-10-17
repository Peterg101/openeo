"""FastAPI application factory for the OpenEO web UI (the HTTP layer).

Routes are thin: parse the request, call ONE service method (lib/webapp/services/),
map the service's domain errors to HTTP, build the response. Access control
decisions live in lib/webapp/policy.py; `guard` below applies them.

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
from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from lib import internal_auth
from lib.webapp import policy
from lib.webapp.deps import (Deps, get_auth_service, get_deps, get_settings_service,
                             get_status_service, get_system_service)
from lib.webapp.loginpage import render_login_page
from lib.webapp.policy import BEARER_ROUTES, PUBLIC_ROUTES
from lib.webapp.services.auth import AuthService
from lib.webapp.services.errors import (AuthError, Forbidden, NotConfigured, NotFound, RateLimited,
                                        ServiceError, ValidationError)
from lib.webapp.services.settings import SettingsService
from lib.webapp.services.status import StatusService
from lib.webapp.services.system import SystemService
from lib.webapp.sessions import ABSOLUTE_TIMEOUT
from lib.webapp.staticfiles import resolve_static

__all__ = ["BEARER_ROUTES", "PUBLIC_ROUTES", "SESSION_COOKIE", "create_app"]

SESSION_COOKIE: str = "openeo_session"


def json_response(obj: Any, status_code: int = 200) -> Response:
    # json.dumps (not JSONResponse) to keep the historic output for odd floats
    return Response(content=json.dumps(obj, default=str), status_code=status_code,
                    media_type="application/json")


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _set_cookie(response: Response, token: str) -> None:
    response.set_cookie(SESSION_COOKIE, token, max_age=ABSOLUTE_TIMEOUT, path="/",
                        httponly=True, samesite="strict")


def _clear_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


_STATUS_FOR_ERROR: tuple[tuple[type[ServiceError], int], ...] = (
    (ValidationError, 400),
    (AuthError, 401),
    (Forbidden, 403),
    (NotFound, 404),
    (NotConfigured, 503),
)


def _http_error(exc: ServiceError) -> HTTPException:
    """Map a domain error onto the HTTP exception the client sees."""
    if isinstance(exc, RateLimited):
        return HTTPException(status_code=429, detail=exc.message,
                             headers={"Retry-After": str(exc.retry_after)})
    for error_type, status in _STATUS_FOR_ERROR:
        if isinstance(exc, error_type):
            return HTTPException(status_code=status, detail=exc.message)
    return HTTPException(status_code=500, detail=exc.message)


def _reject(rejection: policy.Rejection | None) -> None:
    if rejection is not None:
        raise HTTPException(status_code=rejection.status, detail=rejection.detail)


def guard(request: Request, deps: Deps = Depends(get_deps)) -> None:
    """Runs before every route: authentication, CSRF origin and content type."""
    method, path = request.method, request.url.path
    state_changing = policy.is_state_change(method)

    def check_state_change() -> None:
        _reject(policy.state_change_rejection(
            request.headers.get("origin"), request.headers.get("referer"),
            request.headers.get("host"), request.headers.get("content-type")))

    if policy.is_public(method, path):
        request.state.principal = None
        if state_changing:
            check_state_change()
        return
    principal = policy.decide_principal(
        method=method, path=path, session_token=request.cookies.get(SESSION_COOKIE),
        internal_supplied=request.headers.get(internal_auth.HEADER),
        client_ip=_client_ip(request), authorization=request.headers.get("authorization", ""),
        sessions=deps.sessions, credentials=deps.auth,
        internal_token=deps.internal_token, internal_hosts=deps.internal_hosts)
    if principal is None:
        raise HTTPException(status_code=401, detail="Not authenticated",
                            headers={"WWW-Authenticate": "Bearer"} if (method, path) in BEARER_ROUTES else None)
    request.state.principal = principal
    if state_changing:
        check_state_change()


def require_session(request: Request) -> None:
    _reject(policy.requires_interactive_login(getattr(request.state, "principal", None)))


def create_app(deps: Deps) -> FastAPI:
    app = FastAPI(dependencies=[Depends(guard)], docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.state.deps = deps

    # ---- plumbing -------------------------------------------------------
    @app.middleware("http")
    async def security_headers(request: Request,
                               call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        if not request.url.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, StarletteHTTPException)
        if (exc.status_code == 401 and request.method == "GET"
                and "text/html" in request.headers.get("accept", "")):
            return RedirectResponse("/login", status_code=303)
        return Response(content=json.dumps({"detail": exc.detail}), status_code=exc.status_code,
                        media_type="application/json", headers=getattr(exc, "headers", None))

    # ---- public ---------------------------------------------------------
    @app.api_route("/health", methods=["GET", "HEAD"])
    def health() -> Response:
        return json_response({"status": "ok"})

    @app.get("/login")
    def login_page(request: Request, auth: AuthService = Depends(get_auth_service)) -> Response:
        if auth.session_is_valid(request.cookies.get(SESSION_COOKIE)):
            return RedirectResponse("/", status_code=303)
        return HTMLResponse(render_login_page(auth.has_password()),
                            headers={"Content-Security-Policy":
                                     "default-src 'none'; style-src 'unsafe-inline'; "
                                     "script-src 'unsafe-inline'; connect-src 'self'; "
                                     "form-action 'self'; base-uri 'none'"})

    @app.get("/favicon.ico")
    def favicon(deps: Deps = Depends(get_deps)) -> Response:
        found = resolve_static(deps.static_dir, "/favicon.ico")
        if not found:
            raise HTTPException(status_code=404, detail="Not Found")
        return FileResponse(found[0], media_type=found[1])

    @app.post("/login")
    def login(request: Request, payload: dict[str, Any] = Body(...),
              auth: AuthService = Depends(get_auth_service)) -> Response:
        try:
            token = auth.login(payload, _client_ip(request))
        except ServiceError as e:
            raise _http_error(e)
        response = json_response({"status": "ok"})
        _set_cookie(response, token)
        return response

    # ---- session / credential management --------------------------------
    @app.post("/logout")
    def logout(request: Request, auth: AuthService = Depends(get_auth_service)) -> Response:
        require_session(request)
        auth.logout(request.cookies.get(SESSION_COOKIE))
        response = json_response({"status": "ok"})
        _clear_cookie(response)
        return response

    @app.get("/auth/status")
    def auth_status(auth: AuthService = Depends(get_auth_service)) -> Response:
        return json_response(auth.status())

    @app.post("/change_password")
    def change_password(request: Request, payload: dict[str, Any] = Body(...),
                        auth: AuthService = Depends(get_auth_service)) -> Response:
        require_session(request)
        try:
            auth.change_password(payload, _client_ip(request))
        except ServiceError as e:
            raise _http_error(e)
        response = json_response({"status": "ok", "relogin": True})
        _clear_cookie(response)
        return response

    @app.post("/api_token")
    def api_token_create(request: Request, payload: dict[str, Any] = Body(...),
                         auth: AuthService = Depends(get_auth_service)) -> Response:
        require_session(request)
        try:
            token = auth.create_api_token(payload, _client_ip(request))
        except ServiceError as e:
            raise _http_error(e)
        return json_response({"token": token})   # the only time the plaintext is shown

    @app.post("/api_token/revoke")
    def api_token_revoke(request: Request, auth: AuthService = Depends(get_auth_service)) -> Response:
        require_session(request)
        auth.revoke_api_token()
        return json_response({"status": "ok"})

    # ---- read-only data ---------------------------------------------------
    @app.get("/metrics")
    def metrics(status: StatusService = Depends(get_status_service)) -> Response:
        return Response(content=status.metrics(), media_type="text/plain")

    @app.get("/api")
    def api_status(status: StatusService = Depends(get_status_service)) -> Response:
        return json_response(status.api_status())

    @app.get("/getstatus")
    def getstatus(status: StatusService = Depends(get_status_service)) -> Response:
        return json_response(status.status())

    @app.get("/getconfig")
    def getconfig(settings: SettingsService = Depends(get_settings_service)) -> Response:
        return json_response(settings.config_view())

    @app.get("/get_user_settings")
    def get_user_settings(settings: SettingsService = Depends(get_settings_service)) -> Response:
        return json_response(settings.user_settings())

    @app.get("/getsessiondata")
    def getsessiondata(status: StatusService = Depends(get_status_service)) -> Response:
        return json_response(status.session_data())

    @app.get("/getchartdata")
    def getchartdata(request: Request, status: StatusService = Depends(get_status_service)) -> Response:
        q = request.query_params
        try:
            data = status.chart_data(q.get("type", ""), q.get("since", ""), q.get("series", ""))
        except ServiceError as e:
            raise _http_error(e)
        return json_response(data)

    @app.get("/debugdata")
    def debugdata(system: SystemService = Depends(get_system_service)) -> Response:
        return json_response(system.debug_data())

    # ---- actions ------------------------------------------------------------
    @app.post("/update")
    def update(payload: dict[str, Any] = Body(...),
               system: SystemService = Depends(get_system_service)) -> Response:
        try:
            result = system.update(payload)
        except ServiceError as e:
            raise _http_error(e)
        return json_response(result)

    @app.post("/restart")
    def restart(system: SystemService = Depends(get_system_service)) -> Response:
        system.restart()
        return json_response({"status": "requested"})

    @app.post("/setsettings")
    def setsettings(payload: dict[str, Any] = Body(...),
                    settings: SettingsService = Depends(get_settings_service)) -> Response:
        try:
            config = settings.apply(payload)
        except ServiceError as e:
            raise _http_error(e)
        return json_response({"status": "success", "config": config})

    # ---- static UI (must stay last: catch-all) --------------------------------
    @app.api_route("/{full_path:path}", methods=["GET", "HEAD"])
    def static_files(full_path: str, deps: Deps = Depends(get_deps)) -> Response:
        found = resolve_static(deps.static_dir, "/" + full_path)
        if not found:
            raise HTTPException(status_code=404, detail="Not Found")
        return FileResponse(found[0], media_type=found[1])

    return app
