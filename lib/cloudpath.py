"""Validation of the request paths that the cloud service asks us to proxy.

The cloud sends lines such as  `GET /getstatus`.  Whatever it sends is built
into a URL that points at the local web UI, so the path must not be able to
change the authority (host/port) of that URL.
"""
import re
from urllib.parse import unquote, urlsplit

MAX_PATH_LENGTH = 2048
_PRINTABLE_NO_SPACE = re.compile(r"^[\x21-\x7e]+$")


def validate_proxy_path(path):
    """Return `path` if it is safe to proxy, otherwise raise ValueError."""
    if not isinstance(path, str) or not path:
        raise ValueError("empty path")
    if len(path) > MAX_PATH_LENGTH:
        raise ValueError("path too long")
    if not _PRINTABLE_NO_SPACE.match(path):
        raise ValueError("illegal characters in path")
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("path must start with a single /")
    if "@" in path:
        raise ValueError("'@' not allowed")
    if "\\" in path:
        raise ValueError("backslash not allowed")
    if "://" in path:
        raise ValueError("scheme not allowed")
    if ":" in path.split("?", 1)[0].split("/", 2)[1]:
        # "/:81/x" style authority tricks; a ':' in the query string is fine
        raise ValueError("':' not allowed in first segment")
    decoded = unquote(path.split("?", 1)[0])
    if "\\" in decoded or any(seg == ".." for seg in decoded.split("/")):
        raise ValueError("path traversal not allowed")
    return path


def build_proxy_url(path, port):
    """The only URL the cloud proxy may open: loopback, our port, a checked path."""
    validate_proxy_path(path)
    url = "http://127.0.0.1:%d%s" % (int(port), path)
    parts = urlsplit(url)
    if parts.scheme != "http" or parts.hostname != "127.0.0.1" or parts.port != int(port):
        raise ValueError("URL escaped loopback")
    return url
