"""Pure helpers: passwords, sessions, rate limiter, csrf, secrets, settings, authstore."""
import os

import pytest

from conftest import Clock
from lib.webapp import authstore, csrf, passwords, secret_keys
from lib.webapp.sessions import LoginRateLimiter, SessionStore
from lib.webapp.settings_validation import SettingsError, validate_settings
from lib.webapp.staticfiles import resolve_static


# ---- passwords ---------------------------------------------------------------
def test_hash_roundtrip_and_salting():
    h1 = passwords.hash_password("s3cret-pass", n=2 ** 4)
    h2 = passwords.hash_password("s3cret-pass", n=2 ** 4)
    assert h1 != h2                                   # random salt
    assert h1.startswith("scrypt$16$8$1$")
    assert passwords.verify_password("s3cret-pass", h1)
    assert not passwords.verify_password("s3cret-pasS", h1)
    assert "s3cret-pass" not in h1


def test_default_parameters_are_strong():
    h = passwords.hash_password("anything goes")
    assert h.startswith("scrypt$16384$8$1$")
    assert passwords.verify_password("anything goes", h)


def test_unicode_password():
    h = passwords.hash_password("pässwörd-✓", n=2 ** 4)
    assert passwords.verify_password("pässwörd-✓", h)


@pytest.mark.parametrize("stored", [
    "", "garbage", "md5$1$2", "scrypt$16$8$1$AAAA", "scrypt$x$8$1$AAAA$AAAA",
    "scrypt$15$8$1$" + "QUFBQUFBQUFBQUFB" + "$" + "QUFBQUFBQUFBQUFBQUFBQUFB",     # n not power of 2
    "scrypt$%d$8$1$QUFBQUFBQUFBQUFB$QUFBQUFBQUFBQUFBQUFBQUFB" % (2 ** 30),        # absurd cost
    "scrypt$16$8$1$!!!$QUFBQUFBQUFBQUFBQUFBQUFB",                                  # bad base64
    "scrypt$16$8$1$QQ==$QUFBQUFBQUFBQUFBQUFBQUFB",                                 # salt too short
    None, 5,
])
def test_malformed_hashes_never_verify(stored):
    assert passwords.verify_password("x", stored) is False
    assert passwords.looks_like_hash(stored) is False


def test_verify_rejects_non_string_password():
    h = passwords.hash_password("abcdefgh", n=2 ** 4)
    assert passwords.verify_password(None, h) is False


@pytest.mark.parametrize("pw,ok", [("short", False), ("12345678", True), ("x" * 128, True),
                                   ("x" * 129, False), ("abc\x00defgh", False), (None, False)])
def test_password_policy(pw, ok):
    assert (passwords.password_policy_error(pw) is None) is ok


# ---- sessions -----------------------------------------------------------------
def test_sessions_tokens_are_random_and_bounded():
    clock = Clock()
    s = SessionStore(clock=clock, max_sessions=3)
    tokens = [s.create() for _ in range(3)]
    assert len(set(tokens)) == 3 and all(len(t) >= 43 for t in tokens)     # 32 random bytes
    clock.advance(1)
    s.validate(tokens[1]); s.validate(tokens[2])
    s.create()                                       # evicts the least recently used
    assert s.count() == 3 and not s.validate(tokens[0])
    assert s.validate(tokens[1])


def test_sessions_reject_junk_and_revoke():
    s = SessionStore(clock=Clock())
    t = s.create()
    assert not s.validate(None) and not s.validate("") and not s.validate(5) and not s.validate("nope")
    s.revoke(t); s.revoke(None)
    assert not s.validate(t)
    t = s.create()
    s.revoke_all()
    assert s.count() == 0 and not s.validate(t)


def test_sessions_expire_and_are_purged():
    clock = Clock()
    s = SessionStore(clock=clock, idle_timeout=10, absolute_timeout=95)
    a = s.create()
    clock.advance(11)
    assert not s.validate(a)
    b = s.create()
    for _ in range(10):
        clock.advance(9)
        assert s.validate(b)
    clock.advance(9)
    assert not s.validate(b)                          # past absolute limit despite activity
    c = s.create()
    clock.advance(200)
    s.create()                                        # create() purges the dead one
    assert s.count() == 1 and not s.validate(c)


def test_rate_limiter_schedule():
    clock = Clock()
    rl = LoginRateLimiter(clock=clock, free_attempts=3, base_delay=10, max_delay=50)
    for _ in range(2):
        rl.record_failure("ip")
    assert rl.retry_after("ip") == 0
    rl.record_failure("ip")
    assert rl.retry_after("ip") == 10 and rl.retry_after("other") == 0
    clock.advance(10)
    assert rl.retry_after("ip") == 0
    rl.record_failure("ip"); assert rl.retry_after("ip") == 20
    clock.advance(20); rl.record_failure("ip"); assert rl.retry_after("ip") == 40
    clock.advance(40); rl.record_failure("ip"); assert rl.retry_after("ip") == 50   # capped
    rl.record_success("ip")
    assert rl.retry_after("ip") == 0


def test_rate_limiter_memory_is_bounded():
    clock = Clock()
    rl = LoginRateLimiter(clock=clock, max_entries=8, free_attempts=1)
    for i in range(8):
        rl.record_failure("ip%d" % i)
        clock.advance(1)
    rl.record_failure("new")
    assert len(rl._state) <= 7                         # a quarter dropped to make room
    clock.advance(4000)
    for i in range(9):
        rl.record_failure("late%d" % i)
    assert len(rl._state) <= 9


# ---- csrf ---------------------------------------------------------------------------
@pytest.mark.parametrize("origin,referer,host,ok", [
    ("http://pi.local", None, "pi.local", True),
    ("http://PI.local", None, "pi.local", True),
    ("http://pi.local:8080", None, "pi.local:8080", True),
    ("http://pi.local:8080", None, "pi.local", False),
    ("http://evil.example", None, "pi.local", False),
    ("null", None, "pi.local", False),
    ("", None, "pi.local", False),
    (None, "http://pi.local/settings", "pi.local", True),
    (None, "http://evil.example/", "pi.local", False),
    ("http://pi.local", "http://evil.example/", "pi.local", True),    # Origin wins over Referer
    (None, None, "pi.local", True),
    ("http://pi.local", None, "", False),
    ("http://[::1", None, "pi.local", False),
])
def test_origin_allowed(origin, referer, host, ok):
    assert csrf.origin_allowed(origin, referer, host) is ok


@pytest.mark.parametrize("ct,ok", [("application/json", True), ("Application/JSON; charset=utf-8", True),
                                   ("application/x-www-form-urlencoded", False), ("text/plain", False),
                                   ("", False), (None, False), ("application/jsonp", False)])
def test_json_content_type(ct, ok):
    assert csrf.is_json_content_type(ct) is ok


# ---- secret keys ------------------------------------------------------------------
def test_secret_key_helpers():
    assert secret_keys.is_secret_key("mqtt_password") and secret_keys.is_secret_key("authtoken")
    assert secret_keys.is_secret_key("_anything") and not secret_keys.is_secret_key("mqtt_host")
    assert not secret_keys.is_secret_key(5)
    assert secret_keys.mask_value("authtoken", "abc") == secret_keys.MASK
    assert secret_keys.mask_value("authtoken", "") == "" and secret_keys.mask_value("authtoken", None) is None
    assert secret_keys.mask_value("port", 80) == 80
    cfg = {"mqtt_password": "p", "mqtt_username": "u", "_x": 1, "port": 1, "authtoken": ""}
    assert secret_keys.public_module_config(cfg) == {"mqtt_password": "********", "mqtt_username": "u",
                                                     "port": 1, "authtoken": ""}
    red = secret_keys.redact_config_for_log(cfg)
    assert red["mqtt_password"] == "********" and red["mqtt_username"] == "********"
    assert red["_x"] == "********" and red["port"] == 1 and red["authtoken"] == ""


# ---- settings validation ------------------------------------------------------------
class P:
    pluginParamSpec = {"on": {}, "authtoken": {}}


def test_validate_settings_conversions():
    ups = validate_settings({"m:on": True, "m:authtoken": "t"}, {"m": P()})
    assert ups == [("m", "on", "true"), ("m", "authtoken", "t")]
    assert validate_settings({"m:on": 1.5}, {"m": P()}) == [("m", "on", "1.5")]
    assert validate_settings({"m:authtoken": "********"}, {"m": P()}) == []
    assert validate_settings({}, {"m": P()}) == []


def test_validate_settings_reports_all_problems():
    with pytest.raises(SettingsError) as e:
        validate_settings({"x:on": 1, "m:zzz": 1, "bad": 1, 5: 1}, {"m": P()})
    msg = str(e.value)
    assert "x:on: unknown module" in msg and "m:zzz: unknown setting" in msg and "expected module:key" in msg
    with pytest.raises(SettingsError):
        validate_settings([1], {})


# ---- authstore -------------------------------------------------------------------------
def test_authstore_password_and_pending_import(fake_db, tmp_path):
    pending = tmp_path / "pw.hash"
    store = authstore.AuthStore(fake_db, str(pending))
    assert not store.has_password() and not store.verify_password("whatever1")
    pending.write_text("not a hash")
    assert not store.has_password() and pending.exists()            # junk is ignored, not deleted
    pending.write_text(passwords.hash_password("first-pass-1", n=2 ** 4) + "\n")
    assert store.verify_password("first-pass-1")
    assert not pending.exists()                                     # consumed
    store.set_password("second-pass-2")
    assert store.verify_password("second-pass-2") and not store.verify_password("first-pass-1")
    with pytest.raises(ValueError):
        store.set_password("short")


def test_authstore_pending_unreadable(fake_db, tmp_path):
    store = authstore.AuthStore(fake_db, str(tmp_path / "missing"))
    assert store.import_pending() is False
    (tmp_path / "bin").write_bytes(b"\xff\xfe\x00")
    assert authstore.AuthStore(fake_db, str(tmp_path / "bin")).import_pending() is False


def test_authstore_api_token(fake_db, tmp_path):
    store = authstore.AuthStore(fake_db, str(tmp_path / "x"))
    assert not store.api_token_enabled() and not store.check_api_token("anything") and not store.check_api_token("")
    t1 = store.create_api_token()
    assert store.api_token_enabled() and store.check_api_token(t1) and not store.check_api_token(t1 + "x")
    t2 = store.create_api_token()
    assert t1 != t2 and not store.check_api_token(t1) and store.check_api_token(t2)
    store.revoke_api_token()
    assert not store.check_api_token(t2) and not store.api_token_enabled()


# ---- staticfiles -----------------------------------------------------------------------
def test_resolve_static(tmp_path):
    (tmp_path / "static").mkdir()
    (tmp_path / "static" / "index.html").write_text("x")
    (tmp_path / "static" / "a.svg").write_text("x")
    assert resolve_static(str(tmp_path), "/")[1].startswith("text/html")
    assert resolve_static(str(tmp_path), "/static/a.svg")[1] == "image/svg+xml"
    assert resolve_static(str(tmp_path), "/static/a.py") is None
    assert resolve_static(str(tmp_path), None) is None
    assert resolve_static(str(tmp_path), "/static/../../etc/passwd") is None
