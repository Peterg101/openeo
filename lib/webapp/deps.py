"""Dependency container and the FastAPI provider functions built on it.

`create_app(deps)` stores a Deps instance on the app; every route asks for the
piece it needs through one of the `get_*` providers below. Tests either hand
fakes to `create_app` or replace a provider through `app.dependency_overrides`.

Nothing in this module (or in the routes) touches globalState; the single place
that does is lib/webapp/providers.py.
"""
import time

from fastapi import Depends, Request

from lib.webapp.authstore import AuthStore
from lib.webapp.sessions import LoginRateLimiter, SessionStore

LOOPBACK_HOSTS = ("127.0.0.1", "::1")


def _noop(*_args, **_kwargs):
    return None


class Deps:
    def __init__(self, *, config_db, modules, snapshot, updater, restart, run_cmd,
                 static_dir, data_log=None, clock=time.monotonic, sessions=None,
                 limiter=None, auth=None, internal_token="", internal_hosts=LOOPBACK_HOSTS,
                 audit=_noop):
        self.config_db = config_db          # get(module, key=None, default) / set(...)
        self.modules = modules              # () -> {name: plugin instance}
        self.snapshot = snapshot            # () -> status snapshot dict
        self.data_log = data_log or (lambda: None)   # () -> logger object or None
        self.updater = updater              # (action) -> status dict
        self.restart = restart              # () -> None (schedules a restart)
        self.run_cmd = run_cmd              # (argv list) -> (returncode, stdout, stderr)
        self.static_dir = static_dir
        self.clock = clock
        self.sessions = sessions if sessions is not None else SessionStore(clock=clock)
        self.limiter = limiter if limiter is not None else LoginRateLimiter(clock=clock)
        self.auth = auth if auth is not None else AuthStore(config_db)
        self.internal_token = internal_token
        self.internal_hosts = tuple(internal_hosts)
        self.audit = audit                  # (message) -> None


def get_deps(request: Request) -> Deps:
    return request.app.state.deps


def get_config_db(deps: Deps = Depends(get_deps)):
    return deps.config_db


def get_modules(deps: Deps = Depends(get_deps)):
    return deps.modules


def get_snapshot(deps: Deps = Depends(get_deps)):
    return deps.snapshot


def get_data_log(deps: Deps = Depends(get_deps)):
    return deps.data_log


def get_updater(deps: Deps = Depends(get_deps)):
    return deps.updater


def get_restart(deps: Deps = Depends(get_deps)):
    return deps.restart


def get_run_cmd(deps: Deps = Depends(get_deps)):
    return deps.run_cmd


def get_sessions(deps: Deps = Depends(get_deps)):
    return deps.sessions


def get_limiter(deps: Deps = Depends(get_deps)):
    return deps.limiter


def get_auth(deps: Deps = Depends(get_deps)):
    return deps.auth


def get_audit(deps: Deps = Depends(get_deps)):
    return deps.audit
