"""Setup portal: start decision, validators, handlers with an injected runner, HTTP."""
import io
import json
import os
import stat
import subprocess
import threading
import types
import urllib.request

import pytest

import portal
import setupfile


class Runner:
    """Records argv lists and answers from a {prefix: result} script."""

    def __init__(self, script=None):
        self.calls, self.script = [], script or {}

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        for prefix, result in self.script.items():
            if list(argv[:len(prefix)]) == list(prefix):
                if isinstance(result, Exception):
                    raise result
                return result(argv, kwargs) if callable(result) else result
        return R()


def R(out="", rc=0, err=""):
    return types.SimpleNamespace(stdout=out, returncode=rc, stderr=err)


LISTING = "uuid-home:802-11-wireless\nuuid-eth:802-3-ethernet\nuuid-ap:802-11-wireless\nuuid-lo:loopback\n"


def nm(profiles, listing_rc=0):
    script = {("sudo", "nmcli", "-t", "-f"): R(LISTING_FOR(profiles), listing_rc)}
    for uuid, (name, mode, iface) in profiles.items():
        script[("sudo", "nmcli", "-t", "-g", "connection.id,802-11-wireless.mode,connection.interface-name",
                "connection", "show", uuid)] = R("%s\n%s\n%s\n" % (name, mode, iface))
    return Runner(script)


def LISTING_FOR(profiles):
    return "".join("%s:802-11-wireless\n" % u for u in profiles) + "x:802-3-ethernet\n"


# ---- start decision --------------------------------------------------------------------
def test_saved_profiles_ignore_ap_and_other_interfaces():
    run = nm({"u1": ("home", "infrastructure", "wlan0"), "u2": ("openeo-AP", "ap", "wlan1"),
              "u3": ("other-ap", "ap", ""), "u4": ("usb", "infrastructure", "wlan1"),
              "u5": ("any-iface", "infrastructure", "")})
    assert portal.saved_wifi_client_profiles(run) == ["u1", "u5"]


def test_saved_profiles_none_when_nmcli_fails_or_profile_unreadable():
    assert portal.saved_wifi_client_profiles(nm({}, listing_rc=1)) is None
    run = Runner({("sudo", "nmcli", "-t", "-f"): R("u1:802-11-wireless\n"),
                  ("sudo", "nmcli", "-t", "-g"): R("", 1)})
    assert portal.saved_wifi_client_profiles(run) == []
    run = Runner({("sudo", "nmcli", "-t", "-f"): R("u1:802-11-wireless\n"),
                  ("sudo", "nmcli", "-t", "-g"): R("short\n")})      # tolerate missing fields
    assert portal.saved_wifi_client_profiles(run) == ["u1"]


@pytest.mark.parametrize("saved,force,psk,start", [
    ([], False, True, True),               # fresh Pi, password set -> portal
    (["u1"], False, True, False),          # Wi-Fi already saved -> exit cleanly
    (["u1"], True, True, True),            # force_portal overrides
    ([], False, False, False),             # no valid password -> never open an AP
    ([], True, False, False),              # ...even when forced
    (None, False, True, False),            # NetworkManager unknown -> stay down
    (None, True, True, True),
])
def test_decide_start(saved, force, psk, start):
    go, reason = portal.decide_start(saved, force, psk)
    assert go is start and reason


def test_decide_reasons_are_explanatory():
    assert "hotspot password" in portal.decide_start([], False, False)[1]
    assert "already saved" in portal.decide_start(["u"], False, True)[1]
    assert "force_portal" in portal.decide_start(["u"], True, True)[1]


def test_read_stored_psk():
    ok = Runner({("sudo", "cat"): R("wifi-pass-1\n")})
    assert portal.read_stored_psk(ok) == "wifi-pass-1"
    assert ok.calls[0][0] == ["sudo", "cat", setupfile.PSK_FILE]
    assert portal.read_stored_psk(Runner({("sudo", "cat"): R("short\n")})) is None
    assert portal.read_stored_psk(Runner({("sudo", "cat"): R("", 1)})) is None


def test_read_force_portal(tmp_path, monkeypatch):
    f = tmp_path / "s.txt"
    f.write_text("force_portal=yes\n")
    monkeypatch.setattr(setupfile, "find_setup_file", lambda: str(f))
    assert portal.read_force_portal() is True
    monkeypatch.setattr(setupfile, "find_setup_file", lambda: str(tmp_path / "gone"))
    assert portal.read_force_portal() is False
    monkeypatch.setattr(setupfile, "find_setup_file", lambda: None)
    assert portal.read_force_portal() is False


def _main(monkeypatch, saved, force, psk, ap_rc=0, serve_error=None):
    run = Runner({("sudo", portal.PORTAL_SCRIPT, "start"): R("", ap_rc)})
    monkeypatch.setattr(portal, "saved_wifi_client_profiles", lambda r: saved)
    monkeypatch.setattr(portal, "read_force_portal", lambda: force)
    monkeypatch.setattr(portal, "read_stored_psk", lambda r: psk)
    served = []

    def serve(directory, timeout):
        served.append((directory, timeout))
        if serve_error:
            raise serve_error
    rc = portal.main(["--timeout", "5"], run=run, serve_fn=serve)
    return rc, run, served


def test_main_exits_cleanly_without_touching_the_network(monkeypatch, capsys):
    rc, run, served = _main(monkeypatch, ["u1"], False, "wifi-pass-1")
    assert rc == 0 and served == [] and run.calls == []
    assert "not starting" in capsys.readouterr().out


def test_main_no_password_never_starts_ap(monkeypatch):
    rc, run, served = _main(monkeypatch, [], False, None)
    assert rc == 0 and run.calls == [] and served == []


def test_main_starts_serves_and_always_stops_ap(monkeypatch):
    rc, run, served = _main(monkeypatch, [], False, "wifi-pass-1")
    assert rc == 0 and served and served[0][1] == 5
    verbs = [c[0][-1] for c in run.calls]
    assert verbs == ["start", "stop"]


def test_main_stops_ap_when_serving_blows_up(monkeypatch):
    rc, run, _ = _main(monkeypatch, [], False, "wifi-pass-1", serve_error=OSError("bind"))
    assert rc == 0 and [c[0][-1] for c in run.calls] == ["start", "stop"]


def test_main_gives_up_when_ap_wont_start(monkeypatch):
    rc, run, served = _main(monkeypatch, [], False, "wifi-pass-1", ap_rc=3)
    assert rc == 1 and served == [] and [c[0][-1] for c in run.calls] == ["start", "stop"]


def test_bind_address_is_the_ap_address_only():
    assert portal.BIND_ADDRESS == "192.168.4.1" and portal.PORT == 81
    created = []

    class FakeServer:
        def __init__(self, addr, handler):
            created.append(addr)

        def serve_forever(self):
            pass

        def shutdown(self):
            created.append("shutdown")
    portal.shutdown_event.set()
    try:
        cwd = os.getcwd()
        portal.serve(os.path.dirname(portal.__file__), 1, server_factory=FakeServer)
    finally:
        portal.shutdown_event.clear()
        os.chdir(cwd)
    assert created[0] == ("192.168.4.1", 81) and created[0][0] not in ("", "0.0.0.0")
    assert "0.0.0.0" not in open(portal.__file__).read().replace('"0.0.0.0"', "").replace("never 0.0.0.0", "")


# ---- validators ----------------------------------------------------------------------------
GOOD_KEYS = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEexample pete@mac",
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCexample==",
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBexample",
    "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIexample",
    "ssh-dss AAAAB3NzaC1kc3MAAACBexample",
    "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb2Mexample",
]
BAD_KEYS = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEexample\nssh-rsa AAAAB3NzaC1yc2EAAAevil",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEexample\r\nssh-rsa AAAAB3NzaC1yc2EAAAevil",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEexample comment\nextra",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEexample\n",
    'command="rm -rf /" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEexample',
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEexample comment\x07bell",
    "ssh-ed25519 notbase64!!", "ssh-foo AAAA", "", None, 5, "ssh-rsa " + "A" * 9000,
]


@pytest.mark.parametrize("key", GOOD_KEYS)
def test_good_keys(key):
    assert portal.is_valid_key(key)


@pytest.mark.parametrize("key", BAD_KEYS)
def test_bad_keys_including_newline_injection(key):
    assert not portal.is_valid_key(key)


@pytest.mark.parametrize("ssid,ok", [("Home WiFi", True), ("a.b-c_d", True), ("", False), ("x" * 33, False),
                                     ("bad;ssid", False), (None, False), ("new\nline", False)])
def test_ssid(ssid, ok):
    assert bool(portal.is_valid_ssid(ssid)) is ok


@pytest.mark.parametrize("pw,ok", [("password1", True), ("p" * 63, True), ("p" * 64, False), ("a" * 64, True),
                                   ("short", False), ("has space1", False), ("tab\tpass1", False), (None, False)])
def test_wifi_password(pw, ok):
    assert bool(portal.is_valid_password(pw)) is ok


def test_valid_timezone_uses_runner_and_fails_closed():
    run = Runner({("timedatectl",): R("Europe/London\nUTC\n")})
    assert portal.is_valid_timezone("Europe/London", run)
    assert not portal.is_valid_timezone("Mars/Base", run)
    assert not portal.is_valid_timezone("x", Runner({("timedatectl",): subprocess.CalledProcessError(1, "x")}))


# ---- handlers ------------------------------------------------------------------------------
def test_set_wifi_validates_then_runs_nmcli_argv(monkeypatch):
    monkeypatch.setattr(portal, "can_access_internet", lambda: True)
    run = Runner({("sudo", "nmcli", "connection", "up"): R("connected", 0)})
    r = portal.api_set_wifi({"ssid": "Home", "password": "password1"}, run)
    assert r == {"connected_to_wifi": True, "nmcli_message": "connected", "internet_access": True}
    assert all(isinstance(c[0], list) and not c[1].get("shell") for c in run.calls)
    add = [c[0] for c in run.calls if c[0][3] == "add"][0]
    assert add[-2:] == ["ssid", "Home"]
    assert portal.api_set_wifi({"ssid": "bad;ssid", "password": "password1"}, run) == {"error": "Invalid SSID"}
    assert portal.api_set_wifi({"ssid": "Home", "password": "x"}, run) == {"error": "Invalid Password"}
    fail = Runner({("sudo", "nmcli", "connection", "up"): R("", 4, "no secrets")})
    assert portal.api_set_wifi({"ssid": "Home", "password": "password1"}, fail)["nmcli_message"] == "no secrets"


def test_setup_wifi_connection_error_paths():
    boom = Runner({("sudo", "nmcli", "connection", "add"): subprocess.CalledProcessError(1, "x", stderr="bad\n")})
    assert portal.setup_wifi_connection("S", "password1", boom) == (False, "nmcli error: bad")
    boom = Runner({("sudo", "nmcli", "connection", "add"): subprocess.CalledProcessError(1, "x")})
    assert portal.setup_wifi_connection("S", "password1", boom)[1].startswith("nmcli error:")
    boom = Runner({("sudo", "nmcli", "connection", "add"): RuntimeError("weird")})
    assert portal.setup_wifi_connection("S", "password1", boom) == (False, "Exception: weird")


def test_set_timezone_sequence_and_validation(monkeypatch):
    monkeypatch.setattr(portal, "get_current_timezone", lambda: "Europe/London")
    run = Runner({("timedatectl",): R("Europe/London\n")})
    assert portal.api_set_timezone({"timezone": "Europe/London"}, run) == {"timezone": "Europe/London"}
    verbs = [c[0][:2] for c in run.calls]
    assert ["sudo", "rm"] in verbs and ["sudo", "tee"] in verbs and ["sudo", "dpkg-reconfigure"] in verbs
    tee = [c for c in run.calls if c[0][:2] == ["sudo", "tee"]][0]
    assert tee[1]["input"] == "Europe/London\n"
    n = len(run.calls)
    for bad in ({}, {"timezone": ""}, {"timezone": 5}, {"timezone": "Mars/Base; rm -rf /"}):
        assert "error" in portal.api_set_timezone(bad, run)
    assert not any(c[0][:2] == ["sudo", "rm"] for c in run.calls[n:])
    fail = Runner({("timedatectl",): R("UTC\n"), ("sudo", "dpkg-reconfigure"): R("", 1, "nope")})
    assert portal.api_set_timezone({"timezone": "UTC"}, fail) == {"error": "tzdata error: nope"}
    crash = Runner({("timedatectl",): R("UTC\n"), ("sudo", "rm"): OSError("denied")})
    assert portal.api_set_timezone({"timezone": "UTC"}, crash) == {"error": "denied"}


def test_get_timezones(monkeypatch):
    monkeypatch.setattr(portal, "get_current_timezone", lambda: "UTC")
    r = portal.api_get_timezones({}, Runner({("timedatectl",): R("UTC\n\nEurope/London\n")}))
    assert r == {"timezones": ["UTC", "Europe/London"], "current": "UTC"}
    err = subprocess.CalledProcessError(1, "x", stderr="bad")
    assert "bad" in portal.api_get_timezones({}, Runner({("timedatectl",): err}))["error"]
    assert portal.api_get_timezones({}, Runner({("timedatectl",): OSError("x")})) == {"error": "x"}


def test_set_ssh_writes_private_file_atomically(tmp_path):
    d = tmp_path / ".ssh"
    key = GOOD_KEYS[0]
    r = portal.api_set_ssh({"key": key}, Runner(), ssh_dir=str(d))
    assert r == {"SSH": key + "\n"}
    assert stat.S_IMODE(os.stat(d / "authorized_keys").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    assert (d / "authorized_keys").read_text() == key + "\n"
    assert not (d / "authorized_keys.tmp").exists()
    # an injected second line is refused and the existing key is untouched
    assert portal.api_set_ssh({"key": GOOD_KEYS[1] + "\n" + GOOD_KEYS[0]}, Runner(), ssh_dir=str(d)) == {"error": "Invalid Key"}
    assert (d / "authorized_keys").read_text() == key + "\n"
    assert portal.api_set_ssh({}, Runner(), ssh_dir=str(d)) == {"error": "Invalid Key"}


def test_get_ssh_public_key_variants(tmp_path):
    assert portal.get_ssh_public_key(str(tmp_path / "none")) == ""
    f = tmp_path / "k"
    f.write_text("line1\nline2\n")
    assert portal.get_ssh_public_key(str(f)) == "line1\n"
    assert portal.get_ssh_public_key(str(tmp_path)).startswith("Error reading file")


def test_get_wifi_data():
    run = Runner({("sudo", "nmcli", "--get-values=SSID,IN-USE"): R("B:\nA:*\nA:\nopeneo:\n:\n")})
    assert portal.get_wifi_data(run) == {"SSID": ["A", "B"], "CONNECTED": "A"}
    bad = Runner({("sudo",): subprocess.CalledProcessError(1, "nmcli")})
    assert "error" in portal.get_wifi_data(bad)
    assert "error" in portal.get_wifi_data(Runner({("sudo",): OSError("x")}))


def test_api_get_wifi_combines_sources(monkeypatch):
    monkeypatch.setattr(portal, "can_access_internet", lambda: False)
    monkeypatch.setattr(portal, "get_ip_address", lambda i: "10.0.0.5")
    monkeypatch.setattr(portal, "get_ssh_public_key", lambda: "key")
    run = Runner({("sudo", "nmcli"): R("A:*\n")})
    assert portal.api_get_wifi({}, run) == {"SSID": ["A"], "CONNECTED": "A", "INTERNET": False,
                                           "SSH": "key", "IP": "10.0.0.5"}


def test_small_system_helpers(tmp_path):
    assert portal.get_ip_address("definitely-not-an-interface") is None
    assert portal.can_access_internet(host="127.0.0.1", port=1, timeout=0.2) is False
    srv = __import__("socket").socket()
    srv.bind(("127.0.0.1", 0)); srv.listen(1)
    assert portal.can_access_internet(host="127.0.0.1", port=srv.getsockname()[1]) is True
    srv.close()
    assert portal.get_current_timezone() in (None, portal.get_current_timezone())


# ---- request dispatch (CSRF, content type, verbs) ---------------------------------------------------
def hdr(**kw):
    base = {"Host": "192.168.4.1:81", "Content-Type": "application/json"}
    base.update(kw)
    return base


def test_state_changing_endpoints_are_post_only():
    for name in ("set_wifi", "set_timezone", "set_ssh"):
        assert portal.dispatch("GET", name, hdr(), b"")[0] == 405
    for name in ("get_wifi", "get_timezones"):
        assert portal.dispatch("POST", name, hdr(), b"{}")[0] == 405
    assert portal.dispatch("GET", "nope", hdr(), b"")[0] == 404
    assert portal.dispatch("POST", "nope", hdr(), b"{}")[0] == 404


def test_post_requires_json_same_origin_object():
    body = json.dumps({"key": GOOD_KEYS[0]}).encode()
    assert portal.dispatch("POST", "set_ssh", hdr(Origin="http://evil.example"), body)[0] == 403
    assert portal.dispatch("POST", "set_ssh", hdr(Referer="http://evil.example/"), body)[0] == 403
    assert portal.dispatch("POST", "set_ssh", {"Host": "192.168.4.1:81", "Content-Type": "text/plain"}, body)[0] == 415
    assert portal.dispatch("POST", "set_ssh", {"Host": "192.168.4.1:81"}, body)[0] == 415
    assert portal.dispatch("POST", "set_ssh", hdr(), b"{broken")[0] == 400
    assert portal.dispatch("POST", "set_ssh", hdr(), b"\xff")[0] == 400
    assert portal.dispatch("POST", "set_ssh", hdr(), b"[1]")[0] == 400


def test_dispatch_success_and_error_status(monkeypatch, tmp_path):
    monkeypatch.setattr(portal, "SSH_DIR", str(tmp_path / ".ssh"))
    status, result = portal.dispatch("POST", "set_ssh", hdr(Origin="http://192.168.4.1:81"),
                                     json.dumps({"key": GOOD_KEYS[0]}).encode())
    assert status == 200 and result == {"SSH": GOOD_KEYS[0] + "\n"}
    status, result = portal.dispatch("POST", "set_ssh", hdr(), json.dumps({"key": "nope"}).encode())
    assert (status, result) == (500, {"error": "Invalid Key"})
    monkeypatch.setattr(portal, "can_access_internet", lambda: True)
    assert portal.dispatch("POST", "set_wifi", hdr(), b"")[0] == 500      # empty body -> {} -> invalid SSID


# ---- real HTTP round trip on loopback -------------------------------------------------------------------
@pytest.fixture
def http_portal(monkeypatch, tmp_path):
    monkeypatch.setattr(portal, "SSH_DIR", str(tmp_path / ".ssh"))
    (tmp_path / "index.html").write_text("<h1>portal</h1>")
    srv = portal.ThreadedServer(("127.0.0.1", 0), portal.APIServerHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    cwd = os.getcwd()
    os.chdir(tmp_path)
    yield "http://127.0.0.1:%d" % srv.server_port
    os.chdir(cwd)
    srv.shutdown()


def _req(url, data=None, headers=None, method=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_http_round_trip(http_portal):
    assert _req(http_portal + "/")[0] == 200
    body = json.dumps({"key": GOOD_KEYS[0]}).encode()
    status, raw = _req(http_portal + "/api/set_ssh", body, {"Content-Type": "application/json"})
    assert status == 200 and json.loads(raw) == {"SSH": GOOD_KEYS[0] + "\n"}
    assert _req(http_portal + "/api/set_ssh", body, {"Content-Type": "application/x-www-form-urlencoded"})[0] == 415
    assert _req(http_portal + "/api/set_wifi?ssid=a&password=b")[0] == 405         # state change via GET refused
    assert _req(http_portal + "/api/set_timezone?timezone=UTC")[0] == 405
    assert _req(http_portal + "/something", b"x", {"Content-Type": "application/json"})[0] == 404
    big = b"x" * (portal.MAX_BODY + 1)
    assert _req(http_portal + "/api/set_ssh", big, {"Content-Type": "application/json"})[0] == 413
    assert _req(http_portal + "/api/set_ssh", b"{}", {"Content-Type": "application/json", "Content-Length": "abc"})[0] in (400, 413)
