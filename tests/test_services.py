"""Services and policy called directly: no TestClient, no FastAPI."""
import datetime
import urllib.error
import urllib.request

import pytest

from conftest import Clock, FakePlugin
from lib import cloudproxy, internal_auth
from lib.webapp import passwords, policy
from lib.webapp.authstore import AuthStore
from lib.webapp.secret_keys import MASK
from lib.webapp.services.auth import AuthService
from lib.webapp.services.errors import (AuthError, Forbidden, NotConfigured, NotFound, RateLimited,
                                        ServiceError, ValidationError)
from lib.webapp.services.settings import SettingsService
from lib.webapp.services.status import StatusService, build_api_status, build_metrics
from lib.webapp.services.system import DEBUG_COMMANDS, MAX_DEBUG_OUTPUT, UPDATE_ACTIONS, SystemService
from lib.webapp.sessions import LoginRateLimiter, SessionStore

PW = "correct horse battery"


# ---- AuthService ------------------------------------------------------------
@pytest.fixture
def authsvc(fake_db, tmp_path):
    clock = Clock()
    fake_db.set("configserver", "_admin_password_hash", passwords.hash_password(PW, n=2 ** 4))
    events = []
    parts = dict(creds=AuthStore(fake_db, str(tmp_path / "pending")), sessions=SessionStore(clock=clock),
                 limiter=LoginRateLimiter(clock=clock), events=events, clock=clock, db=fake_db)
    svc = AuthService(parts["creds"], parts["sessions"], parts["limiter"], events.append)
    svc.parts = parts
    return svc


def test_login_returns_a_live_session_token_and_audits(authsvc):
    token = authsvc.login({"password": PW}, "1.2.3.4")
    assert authsvc.session_is_valid(token) and not authsvc.session_is_valid("other")
    assert authsvc.parts["events"] == ["login from 1.2.3.4"]


def test_login_failures_count_toward_lockout_and_name_the_wait(authsvc):
    for _ in range(5):
        with pytest.raises(AuthError, match="Incorrect password"):
            authsvc.login({"password": "wrong wrong"}, "ip")
    with pytest.raises(RateLimited) as e:
        authsvc.login({"password": PW}, "ip")
    assert e.value.retry_after > 0 and e.value.message == "Too many attempts, retry later"
    assert authsvc.login({"password": PW}, "other-ip")           # other clients unaffected
    authsvc.parts["clock"].advance(31)
    assert authsvc.login({"password": PW}, "ip")


def test_login_rejects_other_user_and_missing_field(authsvc):
    with pytest.raises(AuthError):
        authsvc.login({"username": "root", "password": PW}, "ip")
    with pytest.raises(ValidationError, match="'password' is required"):
        authsvc.login({}, "ip")


def test_login_without_a_stored_password_is_not_configured(authsvc):
    authsvc.parts["db"].data["configserver"]["_admin_password_hash"] = ""
    with pytest.raises(NotConfigured, match="openeo-setup.txt"):
        authsvc.login({"password": PW}, "ip")
    assert authsvc.has_password() is False


def test_logout_revokes_only_that_session(authsvc):
    a, b = authsvc.login({"password": PW}, "ip"), authsvc.login({"password": PW}, "ip")
    authsvc.logout(a)
    assert not authsvc.session_is_valid(a) and authsvc.session_is_valid(b)
    authsvc.logout(None)                         # harmless


def test_change_password_policy_and_revocation(authsvc):
    t = authsvc.login({"password": PW}, "ip")
    with pytest.raises(Forbidden):
        authsvc.change_password({"current_password": "nope nope", "new_password": "long enough pw"}, "ip")
    with pytest.raises(ValidationError, match="at least"):
        authsvc.change_password({"current_password": PW, "new_password": "short"}, "ip")
    with pytest.raises(ValidationError):
        authsvc.change_password({"current_password": PW}, "ip")
    assert authsvc.session_is_valid(t)
    authsvc.change_password({"current_password": PW, "new_password": "a new passphrase"}, "ip")
    assert not authsvc.session_is_valid(t)
    assert authsvc.login({"password": "a new passphrase"}, "ip")


def test_change_password_shares_the_lockout(authsvc):
    for _ in range(5):
        with pytest.raises(Forbidden):
            authsvc.change_password({"current_password": "bad bad bad", "new_password": "x" * 12}, "ip")
    with pytest.raises(RateLimited):
        authsvc.change_password({"current_password": PW, "new_password": "x" * 12}, "ip")


def test_api_token_lifecycle(authsvc):
    assert authsvc.status() == {"authenticated": True, "api_token_enabled": False}
    with pytest.raises(Forbidden):
        authsvc.create_api_token({"password": "nope nope"}, "ip")
    token = authsvc.create_api_token({"password": PW}, "ip")
    assert token.startswith("oeo_") and authsvc.parts["creds"].check_api_token(token)
    assert authsvc.status()["api_token_enabled"] is True
    authsvc.revoke_api_token()
    assert not authsvc.parts["creds"].check_api_token(token)
    assert authsvc.parts["events"][-2:] == ["API token generated", "API token revoked"]


# ---- SettingsService ----------------------------------------------------------
@pytest.fixture
def settings(fake_db):
    plugins = {
        "switch": FakePlugin({"enabled": {}, "on": {}}, {"enabled": True, "on": False}, core=True),
        "cloud": FakePlugin({"enabled": {}, "authtoken": {}}, {"enabled": False, "authtoken": "ABCDE", "_x": 1},
                            fields=[{"type": "textinput", "name": "authtoken", "default": "ABCDE"}]),
    }
    for n, p in plugins.items():
        fake_db.set(n, dict(p.pluginConfig))
    events = []
    svc = SettingsService(fake_db, lambda: plugins, events.append)
    svc.plugins, svc.events, svc.db = plugins, events, fake_db
    return svc


def test_config_view_masks_and_hides(settings):
    assert settings.config_view() == {"switch": {"enabled": True, "on": False},
                                      "cloud": {"enabled": False, "authtoken": MASK}}


def test_user_settings_adds_enable_toggle_and_masks_without_mutating(settings):
    view = settings.user_settings()
    assert "switch" not in view                       # no settings fields -> omitted
    assert [f["name"] for f in view["cloud"]["fields"]] == ["enabled", "authtoken"]
    assert view["cloud"]["fields"][1]["default"] == MASK and view["cloud"]["name"] == "Fake"
    assert settings.plugins["cloud"].get_user_settings()[0]["default"] == "ABCDE"


def test_apply_writes_reconfigures_audits_and_returns_view(settings):
    view = settings.apply({"switch:on": True, "cloud:authtoken": "NEW12", "cloud:enabled": "true"})
    assert settings.db.get("switch", "on") == "true" and settings.db.get("cloud", "authtoken") == "NEW12"
    assert view["cloud"]["authtoken"] == MASK and "NEW12" not in str(view)
    assert settings.events == ["settings changed: cloud:authtoken, cloud:enabled, switch:on"]
    assert settings.plugins["switch"].configured_with and settings.plugins["cloud"].configured_with


def test_apply_is_all_or_nothing(settings):
    before = dict(settings.db.data["switch"])
    with pytest.raises(ValidationError, match="unknown setting"):
        settings.apply({"switch:on": True, "switch:bogus": 1})
    assert settings.db.data["switch"] == before and settings.events == []


def test_apply_skips_modules_without_stored_config(settings):
    settings.db.data.pop("switch")
    settings.apply({"cloud:enabled": True})
    assert settings.plugins["switch"].configured_with == []


# ---- StatusService -------------------------------------------------------------
SNAP = {"eo_charger_state_id": 2, "eo_charger_state": "Charging", "x": 1.5, "flag": True, "_p": 1, "s": "t"}


def test_metrics_and_api_status_pure_functions():
    text = build_metrics(SNAP)
    assert text.splitlines() == ["# HELP eo_charger_state_id Charging", "# TYPE eo_charger_state_id gauge",
                                 "eo_charger_state_id{} 2", "# TYPE x gauge", "x{} 1.5",
                                 "# TYPE flag gauge", "flag{} 1"]
    assert build_metrics({}) == ""
    assert build_api_status(SNAP) == {"eo_charger_state": {"id": 2, "status": "Charging"}, "x": 1.5, "flag": True}


def test_status_service_views():
    class Log:
        def get_plotly(self, since, series): return ("plotly", since, series)
        def get_data(self, since, series): return ("data", since, series)

    class Sess:
        def get_sessions(self): return [1]

    log = Log()
    svc = StatusService(lambda: SNAP, lambda: {"chargersession": Sess()}, lambda: log)
    assert "_p" not in svc.status() and svc.status()["s"] == "t"
    assert svc.metrics().startswith("# HELP") and svc.api_status()["x"] == 1.5
    assert svc.session_data() == [1]
    assert StatusService(lambda: SNAP, lambda: {}, lambda: None).session_data() == []
    kind, since, series = svc.chart_data("plotly", "2025-01-02 03:04:05.000006", "a,b")
    assert (kind, series) == ("plotly", ["a", "b"]) and since == datetime.datetime(2025, 1, 2, 3, 4, 5, 6)
    assert svc.chart_data("raw", "garbage", "") == ("data", None, None)


def test_chart_data_not_found_without_logger():
    with pytest.raises(NotFound):
        StatusService(lambda: {}, lambda: {}, lambda: None).chart_data("", "", "")


# ---- SystemService ---------------------------------------------------------------
def make_system(fake_db, run=None, updater=None):
    events, restarts, seen = [], [], []

    def default_run(argv):
        seen.append(argv)
        return 0, "out-" + argv[0], ""
    svc = SystemService(run or default_run, fake_db, updater or (lambda a: {"ran": a}),
                        lambda: restarts.append(1), events.append)
    return svc, events, restarts, seen


def test_debug_data_each_command_is_an_argv_list(fake_db):
    svc, _, _, seen = make_system(fake_db)
    out = svc.debug_data()
    assert [tuple(a) for a in seen] == list(DEBUG_COMMANDS)
    assert out["whoami"] == "out-whoami" and "log" in out and out["ps -ef"] == ""


def test_debug_data_errors_filtering_and_truncation(fake_db):
    def run(argv):
        if argv[0] == "ps":
            return 0, "a openeo\nb sshd\nc openeo.py", ""
        if argv[0] == "df":
            return 1, "", ""
        if argv[0] == "free":
            raise OSError("missing")
        if argv[0] == "whoami":
            return 3, "", " boom \n"
        return 0, "x" * (MAX_DEBUG_OUTPUT + 10), ""
    out = make_system(fake_db, run=run)[0].debug_data()
    assert out["ps -ef"] == "a openeo\nc openeo.py"
    assert out["df -k"] == "Error: exit status 1" and out["whoami"] == "Error: boom"
    assert out["free -h"] == "Error: missing" and len(out["netstat -4l"]) == MAX_DEBUG_OUTPUT


def test_update_validates_action_and_audits_real_ones(fake_db):
    svc, events, _, _ = make_system(fake_db)
    assert set(UPDATE_ACTIONS) == {"openeo", "raspberrypi", "reboot", "status"}
    assert svc.update({"action": "status"}) == {"ran": "status"} and events == []
    assert svc.update({"action": "reboot"}) == {"ran": "reboot"} and events == ["update action: reboot"]
    for bad in ({}, {"action": "rm"}, {"action": 5}, {"action": None}):
        with pytest.raises(ValidationError, match="Unknown action"):
            svc.update(bad)


def test_restart_audits_then_restarts(fake_db):
    svc, events, restarts, _ = make_system(fake_db)
    svc.restart()
    assert events == ["restart requested"] and restarts == [1]


def test_domain_errors_carry_messages():
    assert str(ServiceError("m")) == "m" and RateLimited(7).retry_after == 7


# ---- policy ---------------------------------------------------------------------
class Sess:
    def __init__(self, ok): self.ok = ok
    def validate(self, t): return self.ok and t == "tok"


class Creds:
    def __init__(self, ok=False): self.ok = ok
    def check_api_token(self, t): return self.ok and t == "bt"


def principal(**kw):
    args = dict(method="GET", path="/getstatus", session_token=None, internal_supplied=None,
                client_ip="127.0.0.1", authorization="", sessions=Sess(False), credentials=Creds(),
                internal_token="secret", internal_hosts=("127.0.0.1",))
    args.update(kw)
    return policy.decide_principal(**args)


def test_policy_principal_order_and_rules():
    assert principal() is None
    assert principal(session_token="tok", sessions=Sess(True)) == "session"
    assert principal(session_token="bad", sessions=Sess(True)) is None
    assert principal(internal_supplied="secret") == "internal"
    assert principal(internal_supplied="secret", client_ip="10.0.0.9") is None
    assert principal(internal_supplied="wrong") is None
    assert principal(internal_supplied="secret", internal_token="") is None
    # session wins over internal when both are valid
    assert principal(session_token="tok", sessions=Sess(True), internal_supplied="secret") == "session"
    # bearer only on the bearer routes
    assert principal(path="/metrics", authorization="Bearer bt", credentials=Creds(True)) == "bearer"
    assert principal(path="/api", authorization="bearer bt", credentials=Creds(True)) == "bearer"
    assert principal(path="/getstatus", authorization="Bearer bt", credentials=Creds(True)) is None
    assert principal(path="/metrics", method="POST", authorization="Bearer bt", credentials=Creds(True)) is None
    assert principal(path="/metrics", authorization="Bearer nope", credentials=Creds(True)) is None
    assert principal(path="/metrics", authorization="Basic bt", credentials=Creds(True)) is None


def test_policy_public_and_state_change_helpers():
    assert policy.is_public("POST", "/login") and not policy.is_public("GET", "/getstatus")
    assert not policy.is_public("POST", "/health")
    assert policy.is_state_change("POST") and policy.is_state_change("DELETE")
    assert not policy.is_state_change("GET") and not policy.is_state_change("HEAD")


def test_policy_state_change_rejections():
    ok = "application/json"
    assert policy.state_change_rejection("http://h", None, "h", ok) is None
    assert policy.state_change_rejection(None, None, "h", ok) is None
    assert policy.state_change_rejection("http://evil", None, "h", ok) == policy.Rejection(403, "Cross-origin request refused")
    assert policy.state_change_rejection(None, None, "h", "text/plain") == policy.Rejection(415, "Content-Type must be application/json")
    # origin is judged before content type
    assert policy.state_change_rejection("http://evil", None, "h", "text/plain").status == 403


def test_policy_interactive_login_only():
    assert policy.requires_interactive_login("session") is None
    for p in ("bearer", "internal", None):
        assert policy.requires_interactive_login(p) == policy.Rejection(403, "Requires an interactive login")


# ---- cloud proxy (pure, opener injected) -------------------------------------------------
class Resp:
    def __init__(self, body=b"ok", headers=None): self.body, self.headers = body, headers or [("X", "1")]
    def getheaders(self): return self.headers
    def read(self): return self.body


class FakeOpener:
    def __init__(self, response=None, error=None):
        self.requests, self.response, self.error = [], response or Resp(), error

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        if self.error:
            raise self.error
        return self.response


def test_proxy_builds_loopback_request_with_internal_token():
    op = FakeOpener()
    r = cloudproxy.proxy_request("GET /getstatus?a=1", 8080, op, token="tok")
    req, timeout = op.requests[0]
    assert req.full_url == "http://127.0.0.1:8080/getstatus?a=1" and req.get_method() == "GET"
    assert req.get_header(internal_auth.HEADER.capitalize()) == "tok" and timeout == cloudproxy.TIMEOUT
    assert (r.body, r.bodylen, r.headers) == (b"ok", 2, [("X", "1")])


def test_proxy_post_is_json_with_body():
    op = FakeOpener()
    cloudproxy.proxy_request('POST /setsettings {"a": 1}', 80, op, token="t")
    req, _ = op.requests[0]
    assert req.data == b'{"a": 1}' and req.get_header("Content-type") == "application/json"
    assert req.get_method() == "POST"


@pytest.mark.parametrize("cmd", ["", "garbage", "DELETE /x", "GET @evil.com/", "GET :81/x",
                                 "GET //evil.com", "GET /a/../b", "POST http://evil.com/ {}"])
def test_proxy_refuses_bad_commands_without_network(cmd):
    op = FakeOpener()
    r = cloudproxy.proxy_request(cmd, 80, op)
    assert (r.body, r.headers, r.bodylen) == (b"", [], 0) and op.requests == []


def test_proxy_relays_http_errors():
    class Body:   # what http.client gives HTTPError as its file object
        def read(self): return b"nope"
        def getheaders(self): return [("Content-Type", "text/plain")]
        def close(self): pass
    err = urllib.error.HTTPError("http://x", 404, "nf", {}, Body())
    r = cloudproxy.proxy_request("GET /missing", 80, FakeOpener(error=err))
    assert r.body == b"nope" and r.headers == [("Content-Type", "text/plain")]


def test_default_opener_does_not_follow_redirects():
    handler = cloudproxy.NoRedirect()
    req = urllib.request.Request("http://127.0.0.1/x")
    assert handler.redirect_request(req, None, 302, "Found", {}, "http://evil/") is None
