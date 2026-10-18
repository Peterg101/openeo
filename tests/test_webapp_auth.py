"""Authentication, sessions, CSRF and the auth-on-every-route sweep."""
import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from lib import internal_auth
from lib.webapp import app as appmod
from lib.webapp.app import PUBLIC_ROUTES, SESSION_COOKIE, create_app

# Frozen on purpose: adding a public route must be a conscious edit of THIS test too.
EXPECTED_PUBLIC = {("GET", "/login"), ("POST", "/login"), ("GET", "/health"),
                   ("HEAD", "/health"), ("GET", "/favicon.ico")}


def test_public_allowlist_is_exactly_what_we_expect():
    assert set(PUBLIC_ROUTES) == EXPECTED_PUBLIC


def _concrete(path):
    return path.replace("{full_path:path}", "static/index.html")


def test_every_route_requires_auth_except_the_allowlist(env):
    """A route added later without auth fails here."""
    seen = set()
    for route in env.app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods:
            path = _concrete(route.path)
            seen.add((method, route.path))
            r = env.client.request(method, path, json={} if method == "POST" else None,
                                   headers={"Origin": "http://testserver"},
                                   follow_redirects=False)
            if (method, path) in PUBLIC_ROUTES:
                continue
            assert r.status_code in (401, 303), "%s %s answered %s unauthenticated" % (
                method, path, r.status_code)
    # sanity: the sweep really saw the interesting routes
    for expected in [("POST", "/setsettings"), ("GET", "/getconfig"), ("POST", "/restart"),
                     ("GET", "/debugdata"), ("GET", "/metrics"), ("POST", "/update")]:
        assert expected in seen


def test_every_public_route_is_actually_a_route(env):
    registered = {(m, _concrete(r.path)) for r in env.app.routes if isinstance(r, APIRoute)
                  for m in r.methods}
    assert set(PUBLIC_ROUTES) <= registered | {("HEAD", "/health")}


def test_unknown_paths_do_not_leak_when_logged_out(env):
    assert env.client.get("/no/such/thing").status_code == 401
    assert env.client.get("/static/ui.js").status_code == 401


def test_html_navigation_redirects_to_login(env):
    r = env.client.get("/", headers={"Accept": "text/html"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_health_is_public_and_minimal(env):
    r = env.client.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    assert env.client.head("/health").status_code == 200


def test_login_page_is_public_and_self_contained(env):
    r = env.client.get("/login")
    assert r.status_code == 200 and "Log in" in r.text
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert "http://" not in r.text and "https://" not in r.text  # no external assets


def test_login_page_says_when_no_password_is_set(env):
    env.db.data["configserver"]["_admin_password_hash"] = ""
    r = env.client.get("/login")
    assert "edit openeo-setup.txt on the SD card" in r.text
    assert "disabled" in r.text


def test_login_refused_when_no_password_set(env):
    env.db.data["configserver"].pop("_admin_password_hash")
    r = env.login()
    assert r.status_code == 503
    assert "openeo-setup.txt" in r.json()["detail"]
    assert SESSION_COOKIE not in r.cookies


def test_login_sets_hardened_cookie_and_grants_access(env):
    r = env.login()
    assert r.status_code == 200
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie.replace("Strict", "strict")
    assert "Path=/" in cookie and "Secure" not in cookie
    assert env.client.get("/getstatus").status_code == 200
    assert env.client.get("/auth/status").json() == {"authenticated": True, "api_token_enabled": False}


def test_wrong_password_and_wrong_user_rejected(env):
    assert env.login(password="nope nope nope").status_code == 401
    r = env.post("/login", {"username": "root", "password": env.password})
    assert r.status_code == 401
    assert env.client.get("/getstatus").status_code == 401


def test_login_requires_password_field(env):
    assert env.post("/login", {}).status_code == 400
    assert env.post("/login", {"password": 5}).status_code == 400


def test_login_page_redirects_when_already_logged_in(env):
    env.login()
    r = env.client.get("/login", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"


def test_logout_revokes_the_session(env):
    env.login()
    token = env.client.cookies.get(SESSION_COOKIE)
    assert env.post("/logout").status_code == 200
    stale = TestClient(env.app, base_url="http://testserver")
    stale.cookies.set(SESSION_COOKIE, token)
    assert stale.get("/getstatus").status_code == 401


def test_session_idle_expiry(env):
    env.login()
    env.clock.advance(12 * 3600 - 10)
    assert env.client.get("/getstatus").status_code == 200   # activity refreshes idle timer
    env.clock.advance(12 * 3600 + 10)
    assert env.client.get("/getstatus").status_code == 401


def test_session_absolute_expiry(env):
    env.login()
    for _ in range(31):                       # stay active every day...
        env.clock.advance(24 * 3600)
        status = env.client.get("/getstatus").status_code
        if status == 401:
            break
    assert status == 401                       # ...but the 30 day cap still ends it


def test_login_rate_limiting_backs_off_then_recovers(env):
    for _ in range(5):
        assert env.login(password="wrong wrong wrong").status_code == 401
    r = env.login()                            # even the right password is refused now
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0
    env.clock.advance(31)
    assert env.login().status_code == 200


def test_rate_limit_backoff_grows(env):
    for _ in range(5):
        env.login(password="wrong wrong wrong")
    env.clock.advance(31)
    assert env.login(password="wrong wrong wrong").status_code == 401   # 6th failure
    r = env.login()
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 30


def test_change_password_flow_invalidates_every_session(env):
    other = TestClient(env.app, base_url="http://testserver")
    env.login(client=other)
    env.login()
    new = "a brand new passphrase"
    r = env.post("/change_password", {"current_password": env.password, "new_password": new})
    assert r.status_code == 200 and r.json()["relogin"] is True
    assert env.client.get("/getstatus").status_code == 401
    assert other.get("/getstatus").status_code == 401
    assert env.login(password=env.password).status_code == 401
    assert env.login(password=new).status_code == 200
    assert "hash" not in str(env.audit).lower() and new not in str(env.audit)


def test_change_password_checks_current_and_policy(env):
    env.login()
    r = env.post("/change_password", {"current_password": "wrong wrong", "new_password": "long enough pw"})
    assert r.status_code == 403
    r = env.post("/change_password", {"current_password": env.password, "new_password": "short"})
    assert r.status_code == 400 and "at least" in r.json()["detail"]
    assert env.post("/change_password", {"new_password": "long enough pw"}).status_code == 400
    assert env.client.get("/getstatus").status_code == 200   # nothing changed


def test_change_password_attempts_are_rate_limited(env):
    env.login()
    for _ in range(5):
        env.post("/change_password", {"current_password": "bad bad bad", "new_password": "long enough pw"})
    r = env.post("/change_password", {"current_password": env.password, "new_password": "long enough pw"})
    assert r.status_code == 429


# ---- CSRF / content type ---------------------------------------------------

def test_cross_origin_post_is_rejected(env):
    env.login()
    r = env.client.post("/restart", json={}, headers={"Origin": "http://evil.example"})
    assert r.status_code == 403 and env.restarts == []
    r = env.client.post("/restart", json={}, headers={"Origin": "null"})
    assert r.status_code == 403


def test_referer_is_checked_when_origin_absent(env):
    env.login()
    r = env.client.post("/restart", json={}, headers={"Referer": "http://evil.example/x"})
    assert r.status_code == 403
    r = env.client.post("/restart", json={}, headers={"Referer": "http://testserver/page"})
    assert r.status_code == 200


def test_post_without_origin_is_allowed_for_non_browser_clients(env):
    env.login()
    assert env.client.post("/restart", json={}).status_code == 200


def test_form_encoded_post_is_refused(env):
    env.login()
    r = env.client.post("/setsettings", data={"switch:on": "true"},
                        headers={"Origin": "http://testserver"})
    assert r.status_code == 415
    r = env.client.post("/restart", content=b"x", headers={"Content-Type": "text/plain"})
    assert r.status_code == 415 and env.restarts == []


def test_csrf_also_guards_login(env):
    r = env.client.post("/login", json={"password": env.password},
                        headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


def test_no_wildcard_cors_headers_ever(env):
    env.login()
    for path in ("/getstatus", "/getconfig"):
        r = env.client.get(path, headers={"Origin": "http://evil.example"})
        assert "access-control-allow-origin" not in r.headers
    r = env.client.options("/getstatus", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_restart_is_post_only(env):
    env.login()
    assert env.client.get("/restart").status_code in (404, 405)
    assert env.restarts == []
    assert env.post("/restart").json() == {"status": "requested"}
    assert env.restarts == [1]


def test_security_headers(env):
    r = env.client.get("/health")
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


# ---- bearer token / internal token ------------------------------------------

def test_bearer_token_lifecycle_for_metrics_and_api(env):
    assert env.client.get("/metrics", headers={"Authorization": "Bearer nope"}).status_code == 401
    env.login()
    r = env.post("/api_token", {"password": "wrong wrong wrong"})
    assert r.status_code == 403
    r = env.post("/api_token", {"password": env.password})
    token = r.json()["token"]
    assert token.startswith("oeo_")
    assert env.client.get("/auth/status").json()["api_token_enabled"] is True
    stored = env.db.get("configserver", "_api_token_hash")
    assert stored and token not in stored                       # stored hashed

    anon = TestClient(env.app, base_url="http://testserver")
    auth = {"Authorization": "Bearer " + token}
    m = anon.get("/metrics", headers=auth)
    assert m.status_code == 200 and "eo_amps_requested{} 16" in m.text
    assert "_private" not in m.text and "app_version" not in m.text
    assert "eo_solar_active{} 1" in m.text
    assert "# HELP eo_charger_state_id Charging" in m.text
    api = anon.get("/api", headers=auth).json()
    assert api["eo_charger_state"] == {"id": 2, "status": "Charging"}
    assert api["eo_amps_requested"] == 16 and "_private" not in api and "name" not in api
    # ...but the token opens nothing else
    assert anon.get("/getconfig", headers=auth).status_code == 401
    assert anon.get("/getstatus", headers=auth).status_code == 401
    assert anon.post("/restart", json={}, headers=auth).status_code == 401
    assert anon.get("/metrics", headers={"Authorization": "Bearer oeo_wrong"}).status_code == 401

    env.post("/api_token/revoke")
    assert anon.get("/metrics", headers=auth).status_code == 401
    assert env.client.get("/auth/status").json()["api_token_enabled"] is False


def test_bearer_off_by_default(env):
    anon = TestClient(env.app, base_url="http://testserver")
    assert anon.get("/metrics", headers={"Authorization": "Bearer "}).status_code == 401
    assert anon.get("/metrics", headers={"Authorization": "Bearer x"}).status_code == 401


def test_internal_token_only_from_loopback_with_right_value(env):
    h = {internal_auth.HEADER: "internal-secret"}
    anon = TestClient(env.app, base_url="http://testserver")
    assert anon.get("/getstatus", headers=h).status_code == 200
    assert anon.get("/getstatus", headers={internal_auth.HEADER: "wrong"}).status_code == 401
    env.deps.internal_hosts = ("127.0.0.1",)          # request now comes from a "foreign" host
    assert anon.get("/getstatus", headers=h).status_code == 401


def test_internal_principal_cannot_manage_credentials(env):
    h = {internal_auth.HEADER: "internal-secret", "Origin": "http://testserver"}
    anon = TestClient(env.app, base_url="http://testserver")
    for path, body in [("/change_password", {"current_password": env.password, "new_password": "x" * 12}),
                       ("/api_token", {"password": env.password}), ("/api_token/revoke", {}),
                       ("/logout", {})]:
        assert anon.post(path, json=body, headers=h).status_code == 403, path
    # but it can proxy normal UI calls (and must still send JSON)
    assert anon.post("/update", json={"action": "status"}, headers=h).status_code == 200
    h2 = dict(h, **{"Content-Type": "application/x-www-form-urlencoded"})
    assert anon.post("/update", content=b"action=status", headers=h2).status_code == 415


def test_internal_token_empty_never_matches(env):
    env.deps.internal_token = ""
    anon = TestClient(env.app, base_url="http://testserver")
    assert anon.get("/getstatus", headers={internal_auth.HEADER: ""}).status_code == 401
