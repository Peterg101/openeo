"""The cloud service's proxy request, as a pure function over an injected opener.

lib/cloud.py owns the socket and the thread; everything about *what* may be
fetched on the cloud's behalf lives here so it can be tested without either.
"""
from __future__ import annotations

import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol

from lib import cloudpath, internal_auth

_LOGGER = logging.getLogger(__name__)

_COMMAND = re.compile("^(GET|POST) ([^ ]+) ?(.*)$")
TIMEOUT: int = 30


class Response(Protocol):
    """What urllib's response (and HTTPError) offer."""

    def getheaders(self) -> list[tuple[str, str]]: ...
    def read(self) -> bytes: ...


class Opener(Protocol):
    def open(self, request: urllib.request.Request, timeout: float | None = None) -> Response: ...


@dataclass(frozen=True)
class ProxyResult:
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    @property
    def bodylen(self) -> int:
        return len(self.body)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: the proxy must not be led off the local web UI."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def build_default_opener() -> Opener:
    return urllib.request.build_opener(NoRedirect)  # type: ignore[return-value]


def proxy_request(command: str, port: int, opener: Opener,
                  token: str = internal_auth.TOKEN) -> ProxyResult:
    """Run one `GET <path>` / `POST <path> <json>` command against the local web UI.

    Malformed commands and unsafe paths return an empty result without any
    network access. HTTP error statuses are relayed, not raised.
    """
    m = _COMMAND.search(command)
    if not m:
        _LOGGER.error("OpenEO Cloud error: Malformed command")
        return ProxyResult()
    method = m.group(1)
    try:
        url = cloudpath.build_proxy_url(m.group(2), port)
    except ValueError as e:
        _LOGGER.error("OpenEO Cloud error: refused to proxy path (%s)" % e)
        return ProxyResult()

    headers = {internal_auth.HEADER: token}
    data: bytes | None = None
    if method == "POST":
        data = m.group(3).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    response: Response
    try:
        response = opener.open(request, timeout=TIMEOUT)
    except urllib.error.HTTPError as e:
        response = e   # HTTPError is itself a response (status, headers, body)
    return ProxyResult(headers=list(response.getheaders()), body=response.read())
