"""CSRF helpers shared by the main web UI and the setup portal."""
from __future__ import annotations

from urllib.parse import urlsplit


def _netloc(value: str) -> str:
    try:
        return urlsplit(value).netloc.lower()
    except ValueError:
        return ""


def origin_allowed(origin: str | None, referer: str | None, host: str | None) -> bool:
    """Same-origin check for state-changing requests.

    * `Origin` present   -> its host[:port] must equal the `Host` header
      (the literal "null" origin never matches).
    * else `Referer` present -> same rule.
    * neither present    -> allowed (non-browser clients; SameSite=Strict on the
      session cookie covers the browser case).
    """
    host = (host or "").lower()
    if origin is not None:
        return bool(host) and _netloc(origin) == host
    if referer:
        return bool(host) and _netloc(referer) == host
    return True


def is_json_content_type(content_type: str | None) -> bool:
    """True for application/json, with or without parameters (charset ...)."""
    if not content_type:
        return False
    return content_type.split(";", 1)[0].strip().lower() == "application/json"
