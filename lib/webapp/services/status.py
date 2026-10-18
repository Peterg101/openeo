"""Read-only status, metrics and data views."""
from __future__ import annotations

import datetime
import numbers
from collections.abc import Mapping
from typing import Any

from lib.webapp.protocols import DataLogAccessor, ModulesAccessor, SnapshotAccessor
from lib.webapp.services.errors import NotFound

_CHART_TIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"


def build_metrics(snapshot: Mapping[str, Any]) -> str:
    """Prometheus text exposition of the public numeric values."""
    lines: list[str] = []
    for key, value in snapshot.items():
        if key[0] == "_":
            continue
        if isinstance(value, bool):
            value = int(value)
        if isinstance(value, numbers.Number):
            if key == "eo_charger_state_id":
                lines.append("# HELP %s %s" % (key, snapshot.get("eo_charger_state", "")))
            lines.append("# TYPE %s gauge" % key)
            lines.append("%s{} %s" % (key, value))
    return "\n".join(lines) + ("\n" if lines else "")


def build_api_status(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    status: dict[str, Any] = {"eo_charger_state": {"id": snapshot.get("eo_charger_state_id"),
                                                   "status": snapshot.get("eo_charger_state")}}
    for key, value in snapshot.items():
        if key[0] != "_" and isinstance(value, numbers.Number):
            if key not in ("eo_charger_state_id", "eo_charger_state"):
                status[key] = value
    return status


class StatusService:
    def __init__(self, snapshot: SnapshotAccessor, modules: ModulesAccessor,
                 data_log: DataLogAccessor) -> None:
        self._snapshot = snapshot
        self._modules = modules
        self._data_log = data_log

    def metrics(self) -> str:
        return build_metrics(dict(self._snapshot()))

    def api_status(self) -> dict[str, Any]:
        return build_api_status(dict(self._snapshot()))

    def status(self) -> dict[str, Any]:
        return {k: v for k, v in dict(self._snapshot()).items() if k[0] != "_"}

    def session_data(self) -> Any:
        modules = self._modules()
        return modules["chargersession"].get_sessions() if "chargersession" in modules else []

    def chart_data(self, kind: str, since_text: str, series_text: str) -> Any:
        """`kind` "plotly" selects the plotly shape; anything else is raw data."""
        log = self._data_log()
        if log is None:
            raise NotFound("Not Found")
        since: datetime.datetime | None
        try:
            since = datetime.datetime.strptime(since_text, _CHART_TIME_FORMAT)
        except ValueError:
            since = None
        series: list[str] | None = series_text.split(",")
        if series == [""]:
            series = None
        if kind == "plotly":
            return log.get_plotly(since, series)
        return log.get_data(since, series)
