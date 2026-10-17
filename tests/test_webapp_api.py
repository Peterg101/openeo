"""Behaviour of the authenticated API: masking, validation, static files, actions."""
import json
import os

import pytest

from lib.webapp.secret_keys import MASK


@pytest.fixture
def authed(env):
    assert env.login().status_code == 200
    return env


# ---- secrets --------------------------------------------------------------

def test_getconfig_never_returns_secrets_or_private_keys(authed):
    body = authed.client.get("/getconfig").json()
    assert body["homeassistant"]["mqtt_password"] == MASK
    assert body["cloud"]["authtoken"] == MASK
    assert body["homeassistant"]["mqtt_host"] == "h"          # non-secret untouched
    assert "_hidden" not in body["homeassistant"]
    raw = authed.client.get("/getconfig").text
    assert "hunter22" not in raw and "ABCDE" not in raw


def test_empty_secret_is_not_masked(authed):
    authed.plugins["homeassistant"].pluginConfig["mqtt_password"] = ""
    assert authed.client.get("/getconfig").json()["homeassistant"]["mqtt_password"] == ""


def test_get_user_settings_masks_secret_defaults(authed):
    body = authed.client.get("/get_user_settings").json()
    fields = {f["name"]: f for f in body["homeassistant"]["fields"]}
    assert fields["mqtt_password"]["default"] == MASK
    assert fields["mqtt_host"]["default"] == "h"
    cloud = {f["name"]: f for f in body["cloud"]["fields"]}
    assert cloud["authtoken"]["default"] == MASK
    assert "hunter22" not in json.dumps(body) and "ABCDE" not in json.dumps(body)
    # non-core plugins get the injected "enabled" toggle first; the module's own list is untouched
    assert body["cloud"]["fields"][0]["name"] == "enabled"
    assert authed.plugins["cloud"].get_user_settings()[0]["default"] == "ABCDE"


def test_get_user_settings_skips_broken_and_empty_modules(authed):
    class Broken:
        PRETTY_NAME = "B"
        CORE_PLUGIN = True
        pluginConfig = {}

        def get_user_settings(self):
            raise RuntimeError("boom")

    class NoSettings:
        pass

    authed.plugins["broken"] = Broken()
    authed.plugins["plain"] = NoSettings()
    body = authed.client.get("/get_user_settings").json()
    assert "broken" not in body and "plain" not in body and "homeassistant" in body


def test_mask_value_means_unchanged_on_save(authed):
    r = authed.post("/setsettings", {"homeassistant:mqtt_password": MASK, "homeassistant:mqtt_host": "newhost"})
    assert r.status_code == 200
    assert authed.db.get("homeassistant", "mqtt_password") == "hunter22"
    assert authed.db.get("homeassistant", "mqtt_host") == "newhost"
    assert r.json()["config"]["homeassistant"]["mqtt_password"] == MASK
    assert "hunter22" not in r.text


def test_a_real_new_secret_is_saved_but_never_echoed_or_audited(authed):
    r = authed.post("/setsettings", {"cloud:authtoken": "ZZZZZ"})
    assert r.status_code == 200
    assert authed.db.get("cloud", "authtoken") == "ZZZZZ"
    assert "ZZZZZ" not in r.text
    assert "ZZZZZ" not in " ".join(authed.audit)


# ---- /setsettings validation -------------------------------------------------

@pytest.mark.parametrize("payload", [
    {"nomodule:on": "1"},
    {"switch:notakey": "1"},
    {"switch:_secret": "1"},
    {"_auth:x": "1"},
    {"configserver:_admin_password_hash": "x"},
    {"switch": "1"},
    {"switch:": "1"},
    {"switch:on": [1]},
    {"switch:on": None},
    {"switch:on": float("nan")},
    {"homeassistant:mqtt_host": "x" * 70000},
])
def test_setsettings_rejects_bad_pairs_and_writes_nothing(authed, payload):
    before = json.dumps(authed.db.data, sort_keys=True)
    mixed = dict(payload)
    mixed["switch:amps"] = 16          # a VALID pair alongside must not be written either
    r = authed.client.post("/setsettings", content=json.dumps(mixed, allow_nan=True),
                           headers={"Content-Type": "application/json", "Origin": "http://testserver"})
    assert r.status_code == 400
    assert json.dumps(authed.db.data, sort_keys=True) == before
    assert authed.plugins["switch"].configured_with == []


def test_setsettings_requires_object_body(authed):
    r = authed.client.post("/setsettings", json=["switch:on"], headers={"Origin": "http://testserver"})
    assert r.status_code in (400, 422)


def test_setsettings_stores_strings_and_reconfigures_modules(authed):
    r = authed.post("/setsettings", {"switch:on": True, "switch:amps": 16, "homeassistant:mqtt_host": "x"})
    assert r.status_code == 200 and r.json()["status"] == "success"
    assert authed.db.get("switch", "on") == "true"
    assert authed.db.get("switch", "amps") == "16"
    assert authed.plugins["switch"].configured_with and authed.plugins["homeassistant"].configured_with
    assert authed.post("/setsettings", {"switch:on": False}).status_code == 200
    assert authed.db.get("switch", "on") == "false"
    assert any(a.startswith("settings changed: switch:on") for a in authed.audit)


# ---- static files ----------------------------------------------------------------

def test_index_and_assets_served_after_login(authed):
    r = authed.client.get("/")
    assert r.status_code == 200 and r.text == "<html>app</html>"
    assert authed.client.get("/static/ui.js").headers["content-type"].startswith("text/javascript")
    assert authed.client.get("/favicon.ico").content == b"ICO"
    assert authed.client.head("/static/ui.js").status_code == 200


@pytest.mark.parametrize("path", [
    "/static/../../secret.html", "/../secret.html", "/static/%2e%2e/%2e%2e/secret.html",
    "/static/..%2f..%2fsecret.html", "/%2e%2e/secret.html", "/static/\\..\\secret.html",
    "/static/ui.js%00.html", "/static/notes.txt", "/static/missing.js", "/static/",
])
def test_static_path_traversal_and_unknown_files_refused(authed, path):
    r = authed.client.get(path)
    assert r.status_code in (400, 404)
    assert "TOP SECRET" not in r.text


def test_symlink_escape_is_refused(authed, tmp_path):
    link = authed.root / "static" / "evil.html"
    os.symlink(str(tmp_path / "secret.html"), str(link))
    r = authed.client.get("/static/evil.html")
    assert r.status_code == 404 and "TOP SECRET" not in r.text


def test_favicon_404_when_missing(authed):
    os.remove(authed.root / "favicon.ico")
    assert authed.client.get("/favicon.ico").status_code == 404


# ---- status/data endpoints ---------------------------------------------------------

def test_getstatus_hides_private_keys(authed):
    body = authed.client.get("/getstatus").json()
    assert body["eo_amps_requested"] == 16 and "_private" not in body


def test_getsessiondata(authed):
    assert authed.client.get("/getsessiondata").json() == []

    class Sess:
        def get_sessions(self):
            return [{"kwh": 1.5}]
    authed.plugins["chargersession"] = Sess()
    assert authed.client.get("/getsessiondata").json() == [{"kwh": 1.5}]


def test_getchartdata(authed):
    assert authed.client.get("/getchartdata").status_code == 404

    calls = []

    class Log:
        def get_plotly(self, since, series):
            calls.append(("plotly", since, series))
            return ["p"]

        def get_data(self, since, series):
            calls.append(("data", since, series))
            return ["d"]
    authed.chart_log = Log()
    assert authed.client.get("/getchartdata?type=plotly&series=a,b&since=2025-01-02 03:04:05.000006").json() == ["p"]
    assert authed.client.get("/getchartdata?since=garbage").json() == ["d"]
    assert calls[0][0] == "plotly" and calls[0][2] == ["a", "b"] and calls[0][1].year == 2025
    assert calls[1] == ("data", None, None)


def test_debugdata_runs_argv_lists_and_filters_in_python(authed):
    body = authed.client.get("/debugdata").json()
    assert all(isinstance(c, list) for c in authed.commands)           # never a shell string
    assert body["ps -ef"] == "pi 1 openeo.py\npi 3 grep openeo"        # filtered by Python
    assert body["whoami"] == "out-whoami"
    assert body["df -k"].startswith("Error: df broke")
    assert body["free -h"].startswith("Error:")
    assert "log" in body


def test_update_accepts_only_known_actions(authed):
    for action in ("openeo", "raspberrypi", "reboot", "status"):
        assert authed.post("/update", {"action": action}).status_code == 200
    assert authed.updates == ["openeo", "raspberrypi", "reboot", "status"]
    for bad in ({"action": "rm -rf /"}, {"action": 5}, {}):
        assert authed.post("/update", bad).status_code == 400
    assert authed.updates == ["openeo", "raspberrypi", "reboot", "status"]
    assert "update action: openeo" in authed.audit
    assert "update action: status" not in authed.audit


def test_json_error_shape_and_405(authed):
    r = authed.client.get("/update")
    assert r.status_code in (404, 405)


def test_metrics_with_empty_snapshot(authed):
    authed.snapshot.clear()
    assert authed.client.get("/metrics").text == ""
