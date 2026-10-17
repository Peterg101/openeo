"""Central list of configuration keys that hold secrets, and masking helpers.

Nothing that is a secret may leave the box in an API response or a log line.
Add a key here and every consumer (the /getconfig and /get_user_settings
responses, the config-change log, the startup config log) picks it up.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

MASK: str = "********"

# Keys (the part after "module:") whose values are secrets.
SECRET_KEYS: frozenset[str] = frozenset({
    "mqtt_password",   # homeassistant module
    "authtoken",       # cloud module
    "password",
    "api_token",
    "secret",
})


# Redacted in logs only (still shown to the logged-in admin in the UI).
LOG_ONLY_REDACT: frozenset[str] = frozenset({"mqtt_username"})


def is_secret_key(key: Any) -> bool:
    """True for secret keys and for any private (underscore-prefixed) key."""
    return isinstance(key, str) and (key in SECRET_KEYS or key.startswith("_"))


def mask_value(key: Any, value: Any) -> Any:
    """Return the mask for a non-empty secret value, otherwise the value."""
    if is_secret_key(key) and value not in (None, "", False):
        return MASK
    return value


def public_module_config(module_config: Mapping[str, Any]) -> dict[str, Any]:
    """A module's config for display: private keys dropped, secrets masked."""
    return {
        key: mask_value(key, value)
        for key, value in module_config.items()
        if not (isinstance(key, str) and key.startswith("_"))
    }


def redact_config_for_log(module_config: Mapping[str, Any]) -> dict[str, Any]:
    """Copy of a module config that is safe to write to a log."""
    return {
        key: (MASK if (is_secret_key(key) or key in LOG_ONLY_REDACT) and value not in (None, "") else value)
        for key, value in module_config.items()
    }
