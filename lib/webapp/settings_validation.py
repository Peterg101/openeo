"""Validation of `POST /setsettings` payloads (pure, no I/O)."""
from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from lib.webapp.protocols import SettingUpdate
from lib.webapp.secret_keys import MASK, is_secret_key

MAX_VALUE_LENGTH: int = 65536


class SettingsError(ValueError):
    pass


def _to_storable(value: Any) -> str:
    """Scalar JSON value -> the string form the config database has always held."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise SettingsError("non-finite number")
        return str(value)
    if isinstance(value, str):
        if len(value) > MAX_VALUE_LENGTH:
            raise SettingsError("value too long")
        return value
    raise SettingsError("value must be a string, number or boolean")


def validate_settings(payload: Any, modules: Mapping[str, Any]) -> list[SettingUpdate]:
    """Validate every pair before anything is written.

    `payload` is {"module:key": value}. `modules` is {name: plugin} where each
    plugin exposes `pluginParamSpec`. Returns a list of (module, key, value)
    to write. Raises SettingsError listing every problem if any pair is bad.
    A secret key whose value is the mask means "unchanged" and is skipped.
    """
    if not isinstance(payload, dict):
        raise SettingsError("body must be a JSON object")
    updates: list[SettingUpdate] = []
    problems: list[str] = []
    for name, value in payload.items():
        if not isinstance(name, str) or ":" not in name:
            problems.append("%r: expected module:key" % (name,))
            continue
        module, key = name.split(":", 1)
        if not key or key.startswith("_") or module.startswith("_"):
            problems.append("%s: private keys cannot be written" % name)
            continue
        plugin = modules.get(module)
        if plugin is None:
            problems.append("%s: unknown module" % name)
            continue
        if key not in getattr(plugin, "pluginParamSpec", {}):
            problems.append("%s: unknown setting" % name)
            continue
        if is_secret_key(key) and value == MASK:
            continue
        try:
            updates.append(SettingUpdate(module, key, _to_storable(value)))
        except SettingsError as e:
            problems.append("%s: %s" % (name, e))
    if problems:
        raise SettingsError("; ".join(problems))
    return updates
