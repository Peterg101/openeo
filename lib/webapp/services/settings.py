"""Configuration views and validated settings changes."""
from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from lib.webapp.protocols import Audit, ConfigDB, ModulesAccessor
from lib.webapp.secret_keys import mask_value, public_module_config
from lib.webapp.services.errors import ValidationError
from lib.webapp.settings_validation import SettingsError, validate_settings

_LOGGER = logging.getLogger(__name__)


class SettingsService:
    def __init__(self, config_db: ConfigDB, modules: ModulesAccessor, audit: Audit) -> None:
        self._db = config_db
        self._modules = modules
        self._audit = audit

    def config_view(self) -> dict[str, dict[str, Any]]:
        """Every module's config, private keys dropped and secrets masked."""
        return _config_view(self._modules())

    def user_settings(self) -> dict[str, Any]:
        """Settings-form schema per module, with secret defaults masked."""
        result: dict[str, Any] = {}
        for modulename, module in self._modules().items():
            if not hasattr(module, "get_user_settings"):
                continue
            try:
                fields = module.get_user_settings()
                if not module.CORE_PLUGIN:
                    fields.insert(0, {"type": "boolean", "name": "enabled",
                                      "label": "Enable Module",
                                      "default": module.pluginConfig["enabled"]})
                if isinstance(fields, list) and len(fields) > 0:
                    safe: list[dict[str, Any]] = []
                    for field in fields:
                        field = dict(field)
                        if "default" in field:
                            field["default"] = mask_value(field.get("name"), field["default"])
                        safe.append(field)
                    result[modulename] = {"name": module.PRETTY_NAME, "fields": safe}
            except Exception as e:
                _LOGGER.error("Exception getting options for %r: %r" % (module, e))
        return result

    def apply(self, payload: Any) -> dict[str, dict[str, Any]]:
        """Validate ALL pairs, write them, reconfigure modules; returns the new config view."""
        modules = self._modules()
        try:
            updates = validate_settings(payload, modules)
        except SettingsError as e:
            raise ValidationError(str(e)) from e
        for update in updates:
            self._db.set(update.module, update.key, update.value)
        self._audit("settings changed: " + ", ".join(
            sorted("%s:%s" % (u.module, u.key) for u in updates)))
        for name, module in modules.items():
            stored = self._db.get(name)
            if stored is not None:
                module.configure(stored)
        return _config_view(modules)


def _config_view(modules: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {name: public_module_config(m.pluginConfig) for name, m in modules.items()}
