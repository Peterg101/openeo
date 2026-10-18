import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (ROOT, os.path.join(ROOT, "portal")):
    if p not in sys.path:
        sys.path.insert(0, p)


# ---------------------------------------------------------------------------
# The real globalState creates /home/pi/etc/config.db at import time, so the whole
# test session runs against this stub instead (tests that need the real file
# load it explicitly under another name).
# ---------------------------------------------------------------------------
import types  # noqa: E402

_gs = types.ModuleType("globalState")
_gs.MIN_CHARGING_CURRENT = 6
_gs.MAX_CHARGING_CURRENT = 32
_gs.stateDict = {}
_gs.stateSnapshot = {}
_gs.configDB = None
sys.modules["globalState"] = _gs


# test_comms.py is a manual hardware script (it talks to the charger board at import
# time and has no test functions); it can only run on a Pi with the EO board attached.
collect_ignore = ["test_comms.py"]


class FakeConfigDB:
    """In-memory stand-in for openeoConfigClass (same get/set/logwrite surface)."""

    def __init__(self):
        self.data = {}
        self.log = []

    def get(self, module, key=None, default=None):
        if key is None:
            return dict(self.data[module]) if module in self.data else None
        return self.data.get(module, {}).get(key, default)

    def set(self, module, key_or_dict, value=None, triggerModuleReonfigure=True):
        if isinstance(key_or_dict, dict):
            self.data.setdefault(module, {}).update(key_or_dict)
        else:
            self.data.setdefault(module, {})[key_or_dict] = value

    def logget(self):
        return "\n".join(self.log)

    def logwrite(self, message):
        self.log.append(message)


class FakePlugin:
    PRETTY_NAME = "Fake"
    CORE_PLUGIN = False

    def __init__(self, spec, config=None, fields=None, core=False):
        self.pluginParamSpec = spec
        self.pluginConfig = dict(config or {})
        self._fields = fields if fields is not None else []
        self.CORE_PLUGIN = core
        self.configured_with = []

    def configure(self, cfg):
        self.configured_with.append(cfg)
        self.pluginConfig = dict(cfg)

    def get_user_settings(self):
        return [dict(f) for f in self._fields]


@pytest.fixture
def fake_db():
    return FakeConfigDB()


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class Env:
    """Everything a web-app test wants to poke at."""
    pass


@pytest.fixture
def env(tmp_path, fake_db):
    from fastapi.testclient import TestClient
    from lib.webapp.app import create_app
    from lib.webapp.deps import Deps
    from lib.webapp import passwords

    e = Env()
    e.clock = Clock()
    e.db = fake_db
    e.password = "correct horse battery"
    e.db.set("configserver", "_admin_password_hash",
             passwords.hash_password(e.password, n=2 ** 4))   # cheap for tests

    root = tmp_path / "root"
    (root / "static").mkdir(parents=True)
    (root / "static" / "index.html").write_text("<html>app</html>")
    (root / "static" / "ui.js").write_text("console.log(1)")
    (root / "static" / "notes.txt").write_text("not servable")
    (root / "favicon.ico").write_bytes(b"ICO")
    (tmp_path / "secret.html").write_text("TOP SECRET")
    e.root = root

    e.snapshot = {"eo_charger_state_id": 2, "eo_charger_state": "Charging", "eo_amps_requested": 16,
                  "eo_solar_active": True, "app_version": "v1", "_private": 5, "name": "x"}
    e.plugins = {
        "switch": FakePlugin({"enabled": {}, "on": {}, "amps": {}}, {"enabled": True, "on": False},
                             core=True),
        "homeassistant": FakePlugin({"enabled": {}, "mqtt_password": {}, "mqtt_host": {}},
                                    {"enabled": False, "mqtt_password": "hunter22", "mqtt_host": "h",
                                     "_hidden": "x"},
                                    fields=[{"type": "textinput", "name": "mqtt_password",
                                             "default": "hunter22"},
                                            {"type": "textinput", "name": "mqtt_host", "default": "h"}]),
        "cloud": FakePlugin({"enabled": {}, "authtoken": {}}, {"enabled": False, "authtoken": "ABCDE"},
                            fields=[{"type": "textinput", "name": "authtoken", "default": "ABCDE"}]),
    }
    for name, plugin in e.plugins.items():
        e.db.set(name, dict(plugin.pluginConfig))
    e.updates, e.restarts, e.commands, e.audit = [], [], [], []
    e.chart_log = None

    def updater(action):
        e.updates.append(action)
        return {"openeo_upgrade_log": "", "openeo_upgrade_running": False}

    def run_cmd(argv):
        e.commands.append(argv)
        if argv[0] == "ps":
            return 0, "pi 1 openeo.py\nroot 2 sshd\npi 3 grep openeo", ""
        if argv[0] == "df":
            return 1, "", "df broke"
        if argv[0] == "free":
            raise OSError("no free")
        return 0, "out-" + argv[0], ""

    e.deps = Deps(config_db=e.db, modules=lambda: e.plugins, snapshot=lambda: e.snapshot,
                  data_log=lambda: e.chart_log, updater=updater,
                  restart=lambda: e.restarts.append(1), run_cmd=run_cmd,
                  static_dir=str(root), clock=e.clock, internal_token="internal-secret",
                  internal_hosts=("testclient",), audit=e.audit.append)
    e.app = create_app(e.deps)
    e.client = TestClient(e.app, base_url="http://testserver")
    ORIGIN = {"Origin": "http://testserver"}

    def post(path, payload=None, client=None, headers=None):
        h = dict(ORIGIN)
        h.update(headers or {})
        return (client or e.client).post(path, json={} if payload is None else payload, headers=h)

    def login(client=None, password=None):
        return post("/login", {"password": password or e.password}, client=client)

    e.post, e.login = post, login
    return e


@pytest.fixture
def gs(fake_db):
    """The stubbed globalState, reset for each test."""
    _gs.stateDict.clear()
    _gs.stateDict.update({"eo_overall_limit_current": 32, "eo_current_solar": 0,
                          "_moduleDict": {}})
    _gs.stateSnapshot = {}
    _gs.configDB = fake_db
    return _gs
