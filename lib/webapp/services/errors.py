"""Domain errors raised by the services; the HTTP layer maps them to status codes."""
from __future__ import annotations


class ServiceError(Exception):
    """Base class: `message` is safe to show to the client."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ValidationError(ServiceError):
    """The request was well-formed JSON but unacceptable (HTTP 400)."""


class AuthError(ServiceError):
    """Authentication failed (HTTP 401)."""


class Forbidden(ServiceError):
    """Authenticated but not allowed, e.g. wrong current password (HTTP 403)."""


class NotFound(ServiceError):
    """The thing asked for does not exist (HTTP 404)."""


class NotConfigured(ServiceError):
    """The feature cannot work until the owner sets it up (HTTP 503)."""


class RateLimited(ServiceError):
    """Too many attempts (HTTP 429)."""

    def __init__(self, retry_after: int) -> None:
        super().__init__("Too many attempts, retry later")
        self.retry_after = retry_after
