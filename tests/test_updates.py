"""Update source: one shared repo constant, safe update script, updater actions."""
import os
import re
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_single_repo_constant_shared_by_download_and_checkversion(gs):
    import openeo_download
    import lib.checkversion as cv
    assert openeo_download.GITHUB_REPO == "Peterg101/openeo"
    assert cv.checkversionClassPlugin.GITHUB_REPO is openeo_download.GITHUB_REPO or \
        cv.checkversionClassPlugin.GITHUB_REPO == openeo_download.GITHUB_REPO


def test_checkversion_lists_published_releases_from_the_fork(gs):
    import lib.checkversion as cv
    plugin = cv.checkversionClassPlugin({})
    urls = []

    def fake(url):
        urls.append(url)
        return [{"name": "v2", "draft": False, "prerelease": False},
                {"name": "v3-beta", "draft": False, "prerelease": True},
                {"name": "v9", "draft": True, "prerelease": False},
                {"name": "v1", "draft": False, "prerelease": False}]
    plugin.fetch_json = fake
    assert plugin.get_releases() == ["v2", "v1"]
    assert urls == ["https://api.github.com/repos/Peterg101/openeo/releases"]
    plugin.fetch_json = lambda url: (_ for _ in ()).throw(OSError("offline"))
    assert plugin.get_releases() == ["Unknown"]


def test_checkversion_poll_only_for_release_builds(gs):
    import lib.checkversion as cv
    plugin = cv.checkversionClassPlugin({})
    plugin.get_releases = lambda: ["v2", "v1"]
    gs.stateDict["app_version"] = "main"
    assert plugin.poll() == 0 and "openeo_latest_version" not in gs.stateDict
    gs.stateDict["app_version"] = "v1"
    assert plugin.poll() == 0 and gs.stateDict["openeo_latest_version"] == "v2"


def test_update_script_downloads_to_a_file_and_does_not_pipe_to_python():
    text = open(os.path.join(ROOT, "tools", "update_openeo.sh")).read()
    assert "Peterg101/openeo" in text and "minceheid" not in text
    assert not re.search(r"\|\s*python", text)
    assert "mktemp" in text and "--fail" in text


def test_no_update_path_points_at_upstream():
    for rel in ("openeo_download.py", "lib/checkversion.py", "tools/update_openeo.sh"):
        assert "minceheid" not in open(os.path.join(ROOT, rel)).read(), rel
    readme = open(os.path.join(ROOT, "README.md")).read()
    assert "minceheid" not in readme and "| python3" not in readme


def test_updater_only_starts_known_actions(gs, monkeypatch):
    import lib.configserver_updater as up
    started = []

    class FakeThread:
        def __init__(self, target, args):
            started.append(args[0])

        def start(self):
            pass
    monkeypatch.setattr(up.threading, "Thread", FakeThread)
    for action in ("openeo", "raspberrypi", "reboot"):
        r = up.OpenEO_updater(action)
        assert r["openeo_upgrade_running"] is False
    assert started == ["openeo", "raspberrypi", "reboot"]
    started.clear()
    for action in ("status", "evil", ""):
        up.OpenEO_updater(action)
    assert started == []


def test_updater_commands_are_fixed_argv_lists(gs, monkeypatch):
    import lib.configserver_updater as up
    seen = []

    class P:
        stdout = None
        def poll(self): return 0

    def popen(command, **kw):
        seen.append(command)
        raise OSError("not here")
    monkeypatch.setattr(up.subprocess, "Popen", popen)
    gs.stateDict["openeo_upgrade_log"] = ""
    for action in ("openeo", "raspberrypi", "reboot", "bogus"):
        up._upgrade_function(action)
    assert seen == [["/home/pi/openeo/tools/update_openeo.sh"], ["/home/pi/openeo/tools/update_raspberrypi.sh"],
                    ["/home/pi/openeo/tools/update_reboot.sh"]]
    assert "Error: Unable to execute" in gs.stateDict["openeo_upgrade_log"]
    assert not up.updaterLock.locked()
