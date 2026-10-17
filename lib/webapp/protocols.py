"""Shared types: the collaborators the web app is given, and the values it passes around.

Collaborators are `typing.Protocol`s so real objects (openeoConfigClass, plugin
instances, SessionStore ...) and test fakes both satisfy them structurally.
No pydantic models here: the code must run on pydantic v1 and v2.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal, NamedTuple, Protocol

# How a request proved who it is.
Principal = Literal["session", "bearer", "internal"]
# The actions POST /update understands.
UpdateAction = Literal["openeo", "raspberrypi", "reboot", "status"]

JsonDict = dict[str, Any]


class ConfigDB(Protocol):
    """The slice of openeoConfigClass the web app uses."""

    def get(self, module: str, key: str | None = None, default: Any = None) -> Any: ...

    def set(self, module: str, key_or_dict: str | Mapping[str, Any], value: Any = None,
            triggerModuleReonfigure: bool = True) -> None: ...

    def logget(self) -> str: ...

    def logwrite(self, message: str) -> None: ...


class Plugin(Protocol):
    """The slice of a plugin module (PluginSuperClass) the web app uses."""

    PRETTY_NAME: str
    CORE_PLUGIN: bool
    pluginParamSpec: Mapping[str, Any]
    pluginConfig: dict[str, Any]

    def configure(self, configParam: Any) -> Any: ...

    def get_user_settings(self) -> list[dict[str, Any]]: ...


class SessionSource(Protocol):
    """Server-side session store (lib.webapp.sessions.SessionStore)."""

    def create(self) -> str: ...
    def validate(self, token: str | None) -> bool: ...
    def revoke(self, token: str | None) -> None: ...
    def revoke_all(self) -> None: ...


class RateLimiter(Protocol):
    """Login backoff (lib.webapp.sessions.LoginRateLimiter)."""

    def retry_after(self, key: str) -> int: ...
    def record_failure(self, key: str) -> None: ...
    def record_success(self, key: str) -> None: ...


class CredentialStore(Protocol):
    """Admin password and API token storage (lib.webapp.authstore.AuthStore)."""

    def import_pending(self) -> bool: ...
    def has_password(self) -> bool: ...
    def verify_password(self, password: str) -> bool: ...
    def set_password(self, password: str) -> None: ...
    def api_token_enabled(self) -> bool: ...
    def create_api_token(self) -> str: ...
    def revoke_api_token(self) -> None: ...
    def check_api_token(self, token: str) -> bool: ...


class DataLog(Protocol):
    """Chart-data source (lib.logger plugin)."""

    def get_plotly(self, since: Any, series: list[str] | None) -> Any: ...
    def get_data(self, since: Any, series: list[str] | None) -> Any: ...


class SessionDataSource(Protocol):
    def get_sessions(self) -> Any: ...


Clock = Callable[[], float]
ModulesAccessor = Callable[[], Mapping[str, Any]]
SnapshotAccessor = Callable[[], Mapping[str, Any]]
DataLogAccessor = Callable[[], Any]
Updater = Callable[[str], dict[str, Any]]
Restarter = Callable[[], None]
Audit = Callable[[str], None]
# argv list -> (returncode, stdout, stderr); never a shell string
RunCmd = Callable[[Sequence[str]], tuple[int, str, str]]


class SettingUpdate(NamedTuple):
    """One validated write; compares equal to a plain (module, key, value) tuple."""

    module: str
    key: str
    value: str
