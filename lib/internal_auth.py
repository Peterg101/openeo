"""Per-process secret used by the cloud proxy to call the local web UI.

The token is generated when the process starts, never written to disk, and only
accepted by the web UI from the loopback address.
"""
import secrets

HEADER: str = "X-OpenEO-Internal"
TOKEN: str = secrets.token_urlsafe(32)
