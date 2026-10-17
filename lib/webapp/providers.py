"""Production wiring: the ONE place the web app touches globalState.

Imports are lazy so that unit tests (which never import this module) do not
need the hardware-dependent parts of the application.
"""
import os
import subprocess
import threading

from lib import internal_auth
from lib.webapp.deps import Deps

STATIC_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "configserver")
CMD_TIMEOUT = 30


def run_cmd(argv):
    """Run an argv list (never a shell string). Returns (returncode, stdout, stderr)."""
    result = subprocess.run(argv, capture_output=True, text=True, timeout=CMD_TIMEOUT)
    return result.returncode, result.stdout, result.stderr


def build_deps():
    import globalState
    import util
    import lib.configserver_updater as updater

    def restart():
        # Let the HTTP response go out before the process is replaced.
        threading.Timer(1.0, util.restart_python).start()

    return Deps(
        config_db=globalState.configDB,
        modules=lambda: globalState.stateDict["_moduleDict"],
        snapshot=lambda: globalState.stateSnapshot,
        data_log=lambda: globalState.stateDict.get("_dataLog"),
        updater=updater.OpenEO_updater,
        restart=restart,
        run_cmd=run_cmd,
        static_dir=STATIC_ROOT,
        internal_token=internal_auth.TOKEN,
        audit=globalState.configDB.logwrite,
    )
