"""Safe resolution of request paths to files under the static directory."""
from __future__ import annotations

import os
from typing import Any

# extension -> content type; anything else is never served
CONTENT_TYPES: dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
}

DEFAULT_PAGE: str = "static/index.html"


def resolve_static(root: str, request_path: Any) -> tuple[str, str] | None:
    """Map a URL path onto a file strictly inside `root`.

    Returns (absolute path, content type) or None. The path is resolved (so
    `..` and symlinks are followed) and must still be inside the resolved root.
    """
    if not isinstance(request_path, str) or "\x00" in request_path or "\\" in request_path:
        return None
    rel = request_path.lstrip("/")
    if rel == "":
        rel = DEFAULT_PAGE
    ext = os.path.splitext(rel)[1].lower()
    content_type = CONTENT_TYPES.get(ext)
    if content_type is None:
        return None
    root_real = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(root_real, rel))
    if os.path.commonpath([root_real, candidate]) != root_real:
        return None
    if not os.path.isfile(candidate):
        return None
    return candidate, content_type
