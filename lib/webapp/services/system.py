"""Debug report, software update and restart."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, get_args

from lib.webapp.protocols import Audit, ConfigDB, Restarter, RunCmd, UpdateAction, Updater
from lib.webapp.services.errors import ValidationError

UPDATE_ACTIONS: tuple[str, ...] = get_args(UpdateAction)

DEBUG_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("whoami",),
    ("df", "-k"),
    ("netstat", "-4l"),
    ("ps", "-ef"),            # filtered for "openeo" in Python, not by a shell pipe
    ("free", "-h"),
    ("systemctl", "status", "openeo", "--no-pager", "--output=short-precise"),
    ("ls", "-l", "/home/pi/releases/"),
    ("journalctl", "--list-boots"),
    ("journalctl", "-b", "2"),
    ("journalctl", "-b", "1"),
    ("journalctl",),
)
MAX_DEBUG_OUTPUT = 512 * 1024


class SystemService:
    def __init__(self, run_cmd: RunCmd, config_db: ConfigDB, updater: Updater,
                 restarter: Restarter, audit: Audit) -> None:
        self._run = run_cmd
        self._db = config_db
        self._updater = updater
        self._restart = restarter
        self._audit = audit

    def debug_data(self) -> dict[str, str]:
        results: dict[str, str] = {}
        for argv in DEBUG_COMMANDS:
            label = " ".join(argv)
            try:
                code, out, err = self._run(list(argv))
            except Exception as e:   # missing binary, timeout ...
                results[label] = "Error: %s" % e
                continue
            if code != 0:
                results[label] = "Error: %s" % ((err or "").strip() or "exit status %s" % code)
                continue
            if argv[0] == "ps":
                out = "\n".join(l for l in out.splitlines() if "openeo" in l)
            results[label] = out.strip()[-MAX_DEBUG_OUTPUT:]
        results["log"] = self._db.logget()
        return results

    def update(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        action = payload.get("action")
        if action not in UPDATE_ACTIONS:
            raise ValidationError("Unknown action")
        if action != "status":
            self._audit("update action: %s" % action)
        return self._updater(str(action))

    def restart(self) -> None:
        self._audit("restart requested")
        self._restart()


def argv_label(argv: Sequence[str]) -> str:
    return " ".join(argv)
