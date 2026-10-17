"""Dependency container and the FastAPI provider functions built on it.

`create_app(deps)` stores a Deps instance on the app; every route asks for the
service it needs through one of the `get_*_service` providers below. Tests
either hand fakes to `create_app` or replace a provider through
`app.dependency_overrides`.

Nothing in this module (or in the routes) touches globalState; the single place
that does is lib/webapp/providers.py.
"""
from __future__ import annotations

import time
from collections.abc import Sequence

from fastapi import Depends, Request

from lib.webapp.authstore import AuthStore
from lib.webapp.protocols import (Audit, Clock, ConfigDB, CredentialStore, DataLogAccessor,
                                  ModulesAccessor, RateLimiter, Restarter, RunCmd, SessionSource,
                                  SnapshotAccessor, Updater)
from lib.webapp.services.auth import AuthService
from lib.webapp.services.settings import SettingsService
from lib.webapp.services.status import StatusService
from lib.webapp.services.system import SystemService
from lib.webapp.sessions import LoginRateLimiter, SessionStore

LOOPBACK_HOSTS: tuple[str, ...] = ("127.0.0.1", "::1")


def _noop(message: str) -> None:
    return None


class Deps:
    def __init__(self, *, config_db: ConfigDB, modules: ModulesAccessor, snapshot: SnapshotAccessor,
                 updater: Updater, restart: Restarter, run_cmd: RunCmd, static_dir: str,
                 data_log: DataLogAccessor | None = None, clock: Clock = time.monotonic,
                 sessions: SessionSource | None = None, limiter: RateLimiter | None = None,
                 auth: CredentialStore | None = None, internal_token: str = "",
                 internal_hosts: Sequence[str] = LOOPBACK_HOSTS, audit: Audit = _noop) -> None:
        self.config_db = config_db          # get(module, key, default) / set(...) / logwrite
        self.modules = modules              # () -> {name: plugin instance}
        self.snapshot = snapshot            # () -> status snapshot dict
        self.data_log: DataLogAccessor = data_log or (lambda: None)   # () -> logger object or None
        self.updater = updater              # (action) -> status dict
        self.restart = restart              # () -> None (schedules a restart)
        self.run_cmd = run_cmd              # (argv list) -> (returncode, stdout, stderr)
        self.static_dir = static_dir
        self.clock = clock
        self.sessions: SessionSource = sessions if sessions is not None else SessionStore(clock=clock)
        self.limiter: RateLimiter = limiter if limiter is not None else LoginRateLimiter(clock=clock)
        self.auth: CredentialStore = auth if auth is not None else AuthStore(config_db)
        self.internal_token = internal_token
        self.internal_hosts: tuple[str, ...] = tuple(internal_hosts)
        self.audit = audit                  # (message) -> None


def get_deps(request: Request) -> Deps:
    deps: Deps = request.app.state.deps
    return deps


def get_auth_service(deps: Deps = Depends(get_deps)) -> AuthService:
    return AuthService(deps.auth, deps.sessions, deps.limiter, deps.audit)


def get_settings_service(deps: Deps = Depends(get_deps)) -> SettingsService:
    return SettingsService(deps.config_db, deps.modules, deps.audit)


def get_status_service(deps: Deps = Depends(get_deps)) -> StatusService:
    return StatusService(deps.snapshot, deps.modules, deps.data_log)


def get_system_service(deps: Deps = Depends(get_deps)) -> SystemService:
    return SystemService(deps.run_cmd, deps.config_db, deps.updater, deps.restart, deps.audit)
