"""The uvicorn runner (off the main thread) and production wiring."""
import json
import socket
import threading
import time
import urllib.request

import pytest

from lib.webapp import providers


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_server_runs_in_a_plain_thread_and_stops_cleanly(env):
    import lib.configserver as cs
    port = _free_port()
    server = cs._make_server(env.app, port)
    errors = []

    def run():
        try:
            server.run()
        except BaseException as e:   # signal-handler problems would surface here
            errors.append(e)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    body = None
    for _ in range(100):
        try:
            body = urllib.request.urlopen("http://127.0.0.1:%d/health" % port, timeout=2).read()
            break
        except OSError:
            time.sleep(0.1)
    server.should_exit = True
    t.join(10)
    assert body is not None and json.loads(body) == {"status": "ok"}
    assert not t.is_alive() and errors == []


def test_make_server_config_is_lightweight(env):
    import lib.configserver as cs
    server = cs._make_server(env.app, "8099")
    c = server.config
    assert (c.host, c.port, c.workers, c.reload, c.lifespan) == ("0.0.0.0", 8099, 1, False, "off")
    assert server.install_signal_handlers() is None
    with server.capture_signals():
        pass


def test_plugin_starts_server_thread_and_survives_errors(gs, monkeypatch):
    import lib.configserver as cs
    started = []

    def boom():
        raise RuntimeError("no deps")
    monkeypatch.setattr(providers, "build_deps", boom)
    plugin = cs.configserverClassPlugin({"port": 8123})
    plugin.serverthread.join(5)
    assert plugin.pluginConfig["port"] == 8123 and not plugin.serverthread.is_alive()


def test_plugin_warns_when_no_admin_password(gs, env, monkeypatch, caplog):
    import lib.configserver as cs
    env.db.data["configserver"].pop("_admin_password_hash")
    ran = []

    class FakeServer:
        def run(self):
            ran.append(1)
    monkeypatch.setattr(providers, "build_deps", lambda: env.deps)
    monkeypatch.setattr(cs, "_make_server", lambda app, port: FakeServer())
    with caplog.at_level("WARNING"):
        plugin = cs.configserverClassPlugin({"port": 1})
        plugin.serverthread.join(5)
    assert ran == [1]
    assert any("No admin password is set" in r.message for r in caplog.records)


def test_run_cmd_uses_argv_lists():
    code, out, err = providers.run_cmd(["echo", "a b; echo hacked"])
    assert code == 0 and out.strip() == "a b; echo hacked"
    code, out, err = providers.run_cmd(["sh", "-c", "echo oops >&2; exit 3"])
    assert code == 3 and "oops" in err


def test_build_deps_wires_global_state(gs, monkeypatch):
    gs.stateDict["_moduleDict"] = {"m": 1}
    gs.stateDict["_dataLog"] = "LOG"
    gs.stateSnapshot = {"a": 1}
    timers = []

    class T:
        def __init__(self, delay, fn):
            timers.append((delay, fn))

        def start(self):
            timers.append("started")
    monkeypatch.setattr(providers.threading, "Timer", T)
    d = providers.build_deps()
    assert d.modules() == {"m": 1} and d.snapshot() == {"a": 1} and d.data_log() == "LOG"
    assert d.config_db is gs.configDB and d.static_dir.endswith("configserver")
    d.restart()
    import util
    assert timers == [(1.0, util.restart_python), "started"]
    d.audit("hello")
    assert "hello" in gs.configDB.log
    assert d.internal_token
