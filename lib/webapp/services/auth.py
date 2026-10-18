"""Login, logout, password change and API-token management."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from lib.webapp import passwords
from lib.webapp.loginpage import NO_PASSWORD_MESSAGE
from lib.webapp.protocols import Audit, CredentialStore, RateLimiter, SessionSource
from lib.webapp.services.errors import AuthError, Forbidden, NotConfigured, RateLimited, ValidationError

ADMIN_USER = "admin"


def _string_field(payload: Mapping[str, Any], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str):
        raise ValidationError("'%s' is required" % name)
    return value


class AuthService:
    def __init__(self, credentials: CredentialStore, sessions: SessionSource,
                 limiter: RateLimiter, audit: Audit) -> None:
        self._credentials = credentials
        self._sessions = sessions
        self._limiter = limiter
        self._audit = audit

    # -- queries ---------------------------------------------------------
    def has_password(self) -> bool:
        return self._credentials.has_password()

    def session_is_valid(self, token: str | None) -> bool:
        return self._sessions.validate(token)

    def status(self) -> dict[str, Any]:
        return {"authenticated": True, "api_token_enabled": self._credentials.api_token_enabled()}

    # -- commands ----------------------------------------------------------
    def login(self, payload: Mapping[str, Any], client_ip: str) -> str:
        """Verify the password and return a new session token."""
        if not self._credentials.has_password():
            raise NotConfigured(NO_PASSWORD_MESSAGE)
        wait = self._limiter.retry_after(client_ip)
        if wait > 0:
            raise RateLimited(wait)
        password = _string_field(payload, "password")
        username = payload.get("username", ADMIN_USER)
        if not (self._credentials.verify_password(password) and username == ADMIN_USER):
            self._limiter.record_failure(client_ip)
            self._audit("login failed from %s" % client_ip)
            raise AuthError("Incorrect password")
        self._limiter.record_success(client_ip)
        self._audit("login from %s" % client_ip)
        return self._sessions.create()

    def logout(self, token: str | None) -> None:
        self._sessions.revoke(token)
        self._audit("logout")

    def change_password(self, payload: Mapping[str, Any], client_ip: str) -> None:
        self._verify_current(payload, client_ip, "current_password")
        new = _string_field(payload, "new_password")
        problem = passwords.password_policy_error(new)
        if problem:
            raise ValidationError(problem)
        self._credentials.set_password(new)
        self._sessions.revoke_all()
        self._audit("admin password changed; all sessions revoked")

    def create_api_token(self, payload: Mapping[str, Any], client_ip: str) -> str:
        """Returns the plaintext token - the only time it is ever available."""
        self._verify_current(payload, client_ip, "password")
        token = self._credentials.create_api_token()
        self._audit("API token generated")
        return token

    def revoke_api_token(self) -> None:
        self._credentials.revoke_api_token()
        self._audit("API token revoked")

    def _verify_current(self, payload: Mapping[str, Any], client_ip: str, field: str) -> None:
        wait = self._limiter.retry_after(client_ip)
        if wait > 0:
            raise RateLimited(wait)
        if not self._credentials.verify_password(_string_field(payload, field)):
            self._limiter.record_failure(client_ip)
            raise Forbidden("Current password is incorrect")
        self._limiter.record_success(client_ip)
