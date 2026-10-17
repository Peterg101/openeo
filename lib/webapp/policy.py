"""Pure access-control decisions for the HTTP layer (no framework imports).

`lib.webapp.app.guard` extracts plain values from the request and asks these
functions what to do; keeping the decisions here makes them unit-testable.
"""
from __future__ import annotations

import hmac
from collections.abc import Sequence
from dataclasses import dataclass

from lib.webapp import csrf
from lib.webapp.protocols import CredentialStore, Principal, SessionSource

SAFE_METHODS: tuple[str, ...] = ("GET", "HEAD", "OPTIONS")

# The ONLY routes reachable without authentication.
PUBLIC_ROUTES: frozenset[tuple[str, str]] = frozenset({
    ("GET", "/login"),
    ("POST", "/login"),
    ("GET", "/health"),
    ("HEAD", "/health"),
    ("GET", "/favicon.ico"),
})
# Routes that also accept `Authorization: Bearer <api token>`.
BEARER_ROUTES: frozenset[tuple[str, str]] = frozenset({("GET", "/metrics"), ("GET", "/api")})


@dataclass(frozen=True)
class Rejection:
    """An HTTP-level refusal: status code plus client-safe detail."""

    status: int
    detail: str


def is_public(method: str, path: str) -> bool:
    return (method, path) in PUBLIC_ROUTES


def is_state_change(method: str) -> bool:
    return method not in SAFE_METHODS


def _constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def decide_principal(*, method: str, path: str, session_token: str | None,
                     internal_supplied: str | None, client_ip: str, authorization: str,
                     sessions: SessionSource, credentials: CredentialStore,
                     internal_token: str, internal_hosts: Sequence[str]) -> Principal | None:
    """Who is making this request, or None if they have not proven it."""
    if session_token and sessions.validate(session_token):
        return "session"
    if (internal_supplied and internal_token and client_ip in internal_hosts
            and _constant_time_equal(internal_supplied, internal_token)):
        return "internal"
    if (method, path) in BEARER_ROUTES and authorization[:7].lower() == "bearer ":
        if credentials.check_api_token(authorization[7:].strip()):
            return "bearer"
    return None


def state_change_rejection(origin: str | None, referer: str | None, host: str | None,
                           content_type: str | None) -> Rejection | None:
    """Same-origin and JSON-only rules for every state-changing request."""
    if not csrf.origin_allowed(origin, referer, host):
        return Rejection(403, "Cross-origin request refused")
    if not csrf.is_json_content_type(content_type):
        return Rejection(415, "Content-Type must be application/json")
    return None


def requires_interactive_login(principal: Principal | None) -> Rejection | None:
    """Credential management is for a logged-in browser session only."""
    if principal != "session":
        return Rejection(403, "Requires an interactive login")
    return None
