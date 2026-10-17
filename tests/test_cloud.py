"""Cloud module: proxy path validation, pinned TLS, proxy plumbing."""
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
import types

import pytest

from lib import cloud_tls, cloudpath, internal_auth


# ---- path validator -----------------------------------------------------------
@pytest.mark.parametrize("path", [
    "/", "/getstatus", "/static/ui.js", "/getchartdata?type=plotly&series=a,b&since=2025-01-01%2010:00:00.0",
    "/a/b/c?x=1&y=2", "/update",
])
def test_good_paths_pass(path):
    assert cloudpath.validate_proxy_path(path) == path


@pytest.mark.parametrize("path", [
    "@evil.com/", "/@evil.com/", "evil.com/x", ":81/api/set_ssh", "/:81/api/set_ssh",
    "http://evil.com/", "//evil.com/", "/x://evil.com", "\\\\evil.com\\x", "/a\\b",
    "", "getstatus", "/with space", "/tab\there", "/new\nline", "/nul\x00", "/ünicode",
    "/../../etc/passwd", "/a/../b", "/%2e%2e/secret", "/a/%2E%2E/b", "/..%5c", "/x" + "a" * 3000,
    None, 5, b"/x",
])
def test_bypass_payloads_rejected(path):
    with pytest.raises(ValueError):
        cloudpath.validate_proxy_path(path)


def test_build_url_is_always_loopback():
    assert cloudpath.build_proxy_url("/getstatus?x=1", 80) == "http://127.0.0.1:80/getstatus?x=1"
    assert cloudpath.build_proxy_url("/x", "8080") == "http://127.0.0.1:8080/x"
    for payload in ("@evil.com/", ":81/api/set_ssh", "/@evil.com", "http://evil.com"):
        with pytest.raises(ValueError):
            cloudpath.build_proxy_url(payload, 80)


def test_build_url_defence_in_depth(monkeypatch):
    """Even if the validator were weakened, the parsed URL must still be loopback:port."""
    monkeypatch.setattr(cloudpath, "validate_proxy_path", lambda p: p)
    with pytest.raises(ValueError, match="escaped loopback"):
        cloudpath.build_proxy_url("@evil.com", 80)     # would parse as user@evil.com


# ---- pinned TLS -------------------------------------------------------------------
def test_pinned_certificate_in_repo_matches_the_pin():
    pem = open(cloud_tls.PINNED_CERT_FILE).read()
    der = ssl.PEM_cert_to_DER_cert(pem)
    assert cloud_tls.fingerprint_sha256(der) == cloud_tls.PINNED_SHA256
    cloud_tls.verify_pinned_peer(der)
    ctx = cloud_tls.make_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is False
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_wrong_or_missing_peer_certificate_rejected():
    for bad in (b"not the cert", b"", None):
        with pytest.raises(ssl.SSLError):
            cloud_tls.verify_pinned_peer(bad)


@pytest.fixture
def selfsigned(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("openssl binary not available")
    made = []

    def make(name):
        key, crt = str(tmp_path / (name + ".key")), str(tmp_path / (name + ".pem"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                        "-out", crt, "-days", "2", "-subj", "/O=" + name], check=True,
                       capture_output=True)
        made.append(crt)
        return key, crt
    return make


def _tls_server(key, crt):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)

    def serve():
        try:
            conn, _ = sock.accept()
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.sendall(b"hello")
        except (ssl.SSLError, OSError):
            pass
        finally:
            sock.close()
    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def test_context_trusts_only_the_pinned_cert(selfsigned):
    key_a, crt_a = selfsigned("a")
    key_b, crt_b = selfsigned("b")
    # server presents cert A, client pinned to A -> handshake works and pin matches
    port = _tls_server(key_a, crt_a)
    ctx = cloud_tls.make_ssl_context(crt_a)
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="x") as s:
        der = s.getpeercert(True)
        assert s.recv(5) == b"hello"
    pin = cloud_tls.fingerprint_sha256(der)
    cloud_tls.verify_pinned_peer(der, pinned=pin)
    with pytest.raises(ssl.SSLError):
        cloud_tls.verify_pinned_peer(der, pinned="0" * 64)
    # server presents cert B, client trusts only A -> handshake itself fails (chain check)
    port = _tls_server(key_b, crt_b)
    with pytest.raises(ssl.SSLError):
        ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="x")


# ---- cloud plugin ----------------------------------------------------------------------
@pytest.fixture
def cloudmod(gs):
    import lib.cloud as mod
    return mod


def test_cloud_is_disabled_by_default(cloudmod):
    assert cloudmod.cloudClassPlugin.pluginParamSpec["enabled"]["default"] is False
    assert cloudmod.cloudClassPlugin({}).pluginConfig["enabled"] is False


class _Local(http.server.BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def _reply(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        _Local.seen.append((self.command, self.path, {k.lower(): v for k, v in self.headers.items()}, body))
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/evil")
            self.end_headers()
        elif self.path.startswith("/missing"):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"nope")
        else:
            self.send_response(200)
            self.send_header("X-Test", "1")
            self.end_headers()
            self.wfile.write(b"ok:" + body)

    do_GET = do_POST = _reply


@pytest.fixture
def local_ui(cloudmod, monkeypatch):
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Local)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _Local.seen = []
    monkeypatch.setattr(cloudmod.cloudClassPlugin, "_local_port", staticmethod(lambda: srv.server_port))
    yield srv
    srv.shutdown()


def test_get_output_sends_internal_token_to_loopback_only(cloudmod, local_ui):
    plugin = cloudmod.cloudClassPlugin({})
    r = plugin.get_output("GET /getstatus?a=1")
    assert r["body"] == b"ok:" and r["bodylen"] == 3
    assert ("X-Test", "1") in r["headers"]
    method, path, headers, _ = _Local.seen[0]
    assert (method, path) == ("GET", "/getstatus?a=1")
    assert headers[internal_auth.HEADER.lower()] == internal_auth.TOKEN


def test_get_output_post_sends_json(cloudmod, local_ui):
    plugin = cloudmod.cloudClassPlugin({})
    r = plugin.get_output('POST /setsettings {"switch:on": true}')
    assert r["body"] == b'ok:{"switch:on": true}'
    _, _, headers, body = _Local.seen[0]
    assert headers["content-type"] == "application/json" and body == b'{"switch:on": true}'


def test_get_output_refuses_ssrf_payloads_without_connecting(cloudmod, local_ui):
    plugin = cloudmod.cloudClassPlugin({})
    for cmd in ["GET @evil.com/", "GET :81/api/set_ssh", "GET http://evil.com/", "GET //evil.com/",
                "POST @evil.com/ {}", "GET /a/../b", "DELETE /x", "garbage", ""]:
        r = plugin.get_output(cmd)
        assert r["body"] == b"" and r["bodylen"] == 0 and r["headers"] == []
    assert _Local.seen == []


def test_get_output_does_not_follow_redirects_and_passes_errors_through(cloudmod, local_ui):
    plugin = cloudmod.cloudClassPlugin({})
    r = plugin.get_output("GET /redirect")
    assert r["headers"] and len(_Local.seen) == 1          # 302 returned as-is, not followed
    r = plugin.get_output("GET /missing")
    assert r["body"] == b"nope"                            # HTTP errors are relayed, not raised


def test_local_port_from_configserver_module(cloudmod, gs):
    gs.stateDict["_moduleDict"] = {"configserver": types.SimpleNamespace(pluginConfig={"port": 8081})}
    assert cloudmod.cloudClassPlugin._local_port() == 8081
    gs.stateDict["_moduleDict"] = {}
    assert cloudmod.cloudClassPlugin._local_port() == 80


def test_poll_starts_thread_only_when_enabled(cloudmod, gs, monkeypatch):
    started = []
    monkeypatch.setattr(cloudmod.cloudClassPlugin, "_thread_start", lambda self: started.append(1))
    plugin = cloudmod.cloudClassPlugin({"enabled": "true"})     # configure() polls once
    assert started == [1]
    started.clear()
    plugin.poll()
    assert started == [1]
    plugin.configure({"enabled": "false"})
    closed = []
    plugin.ssl_sock = types.SimpleNamespace(close=lambda: closed.append(1))
    plugin.poll()
    assert closed == [1] and plugin.ssl_sock is None and started == [1]


def test_poll_gives_up_after_too_many_failures(cloudmod, gs, monkeypatch):
    monkeypatch.setattr(cloudmod.cloudClassPlugin, "_thread_start", lambda self: None)
    plugin = cloudmod.cloudClassPlugin({"enabled": "true"})
    plugin.failurecount = plugin.maxfailurecount + 1
    plugin.poll()
    assert gs.configDB.data["cloud"]["enabled"] is False and plugin.failurecount == 0


def test_user_settings_shape(cloudmod, gs):
    gs.stateDict["eo_serial_number"] = "EO123"
    f = cloudmod.cloudClassPlugin({"authtoken": "abcde"}).get_user_settings()[0]
    assert f["name"] == "authtoken" and "EO123" in f["label"]
