#!/usr/bin/env python3
"""OpenEO Wi-Fi setup portal.

Security properties (see SECURITY.md):
  * Only starts when the Pi has no saved Wi-Fi client connection, or when the setup
    file says force_portal=yes, AND a valid hotspot password is stored.
  * The access point is WPA2-PSK; the HTTP server binds the AP address only.
  * Runs as the unprivileged `pi` user; privileged steps go through sudo.
  * Every state-changing call is POST with a JSON body from the same origin.

Handlers are plain functions taking the parsed request and an injectable
subprocess runner, so they can be tested without a Pi.
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import re
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import urllib.parse
from collections.abc import Callable, Sequence
from typing import Any, Protocol, TypeGuard

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
import setupfile  # noqa: E402
from lib.webapp.csrf import is_json_content_type, origin_allowed  # noqa: E402

BIND_ADDRESS: str = "192.168.4.1"      # the AP address - never 0.0.0.0
PORT: int = 81
DEFAULT_TIMEOUT: int = 30 * 60
CONNECTION_NAME: str = "custom-wifi"
AP_CONNECTION_NAME: str = "openeo-AP"
WIFI_INTERFACE: str = "wlan0"
SSH_DIR: str = "/home/pi/.ssh"
AUTH_KEYS_FILE: str = os.path.join(SSH_DIR, "authorized_keys")
PORTAL_SCRIPT: str = os.path.join(HERE, "tools", "openeo_portal.bash")
MAX_BODY: int = 16 * 1024

shutdown_event: threading.Event = threading.Event()


class RunResult(Protocol):
    returncode: int
    stdout: Any
    stderr: Any


class Runner(Protocol):
    """subprocess.run-compatible callable (argv list in, never a shell string)."""

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> RunResult: ...


class Headers(Protocol):
    """Read access to request headers (http.client.HTTPMessage or a plain dict)."""

    def get(self, name: str, default: Any = None, /) -> Any: ...
Handler = Callable[[dict[str, Any], Runner], dict[str, Any]]


def default_run(argv: Sequence[str], **kwargs: Any) -> RunResult:
    return subprocess.run(argv, **kwargs)


# =========================
# Start-up decision
# =========================

def saved_wifi_client_profiles(run: Runner = default_run) -> list[str] | None:
    """UUIDs of saved Wi-Fi *client* profiles for wlan0 (excluding the AP profile).

    Returns a list, or None if NetworkManager could not be queried.
    """
    listing = run(["sudo", "nmcli", "-t", "-f", "UUID,TYPE", "connection", "show"],
                  capture_output=True, text=True)
    if listing.returncode != 0:
        return None
    found: list[str] = []
    for line in listing.stdout.splitlines():
        uuid, _, kind = line.partition(":")
        if kind.strip() != "802-11-wireless":
            continue
        info = run(["sudo", "nmcli", "-t", "-g",
                    "connection.id,802-11-wireless.mode,connection.interface-name",
                    "connection", "show", uuid], capture_output=True, text=True)
        if info.returncode != 0:
            continue
        fields = info.stdout.strip("\n").split("\n")
        name = fields[0] if fields else ""
        mode = fields[1] if len(fields) > 1 else ""
        iface = fields[2] if len(fields) > 2 else ""
        if name == AP_CONNECTION_NAME or mode == "ap":
            continue
        if iface not in ("", WIFI_INTERFACE):
            continue
        found.append(uuid)
    return found


def read_stored_psk(run: Runner = default_run) -> str | None:
    """The stored hotspot passphrase if present and valid, else None (read via sudo)."""
    result = run(["sudo", "cat", setupfile.PSK_FILE], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    psk = result.stdout.rstrip("\n")
    return psk if setupfile.is_valid_hotspot_psk(psk) else None


def decide_start(saved_profiles: list[str] | None, force_portal: bool,
                 psk_valid: bool) -> tuple[bool, str]:
    """(start?, reason) - the single policy for whether the AP and portal come up."""
    if not psk_valid:
        return False, "no valid hotspot password stored (8-63 printable ASCII); set hotspot_password in openeo-setup.txt"
    if force_portal:
        return True, "force_portal=yes in openeo-setup.txt"
    if saved_profiles is None:
        return False, "could not query NetworkManager for saved Wi-Fi connections"
    if saved_profiles:
        return False, "a Wi-Fi connection is already saved; setup portal not needed"
    return True, "no saved Wi-Fi connection"


def read_force_portal() -> bool:
    path = setupfile.find_setup_file()
    if not path:
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return setupfile.read_force_portal(f.read())
    except OSError:
        return False


# =========================
# Validators
# =========================

def is_valid_ssid(ssid: object) -> TypeGuard[str]:
    return (isinstance(ssid, str) and 1 <= len(ssid) <= 32
            and re.fullmatch(r"[\w \-\.]+", ssid) is not None)


def is_valid_password(password: object) -> TypeGuard[str]:
    """WPA passphrase (8-63 printable ASCII, no spaces) or a 64-digit hex PSK."""
    if not isinstance(password, str):
        return False
    if re.fullmatch(r"[0-9A-Fa-f]{64}", password):
        return True
    return re.fullmatch(r"[\x21-\x7E]{8,63}", password) is not None


_KEY_RE: re.Pattern[str] = re.compile(
    r"(ssh-dss AAAAB3NzaC1kc3|ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNT"
    r"|sk-ecdsa-sha2-nistp256@openssh\.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb2"
    r"|ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"
    r"|sk-ssh-ed25519@openssh\.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t"
    r"|ssh-rsa AAAAB3NzaC1yc2)[0-9A-Za-z+/]+={0,3}( [\x20-\x7E]*)?")


def is_valid_key(key: object) -> TypeGuard[str]:
    """A single-line OpenSSH public key. Newlines/control characters are rejected."""
    return (isinstance(key, str) and len(key) <= 8192
            and "\n" not in key and "\r" not in key
            and _KEY_RE.fullmatch(key) is not None)


def is_valid_timezone(timezone: str, run: Runner = default_run) -> bool:
    try:
        result = run(["timedatectl", "list-timezones"], capture_output=True, text=True, check=True)
        return timezone in set(result.stdout.splitlines())
    except Exception:
        return False


# =========================
# API handlers: (body dict, run) -> result dict ("error" key = failure)
# =========================

def get_current_timezone() -> str | None:
    try:
        with open("/etc/timezone", "r") as f:
            return f.read().strip() or None
    except Exception:
        return None


def get_ip_address(ifname: str) -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        import fcntl
        packed = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", ifname[:15].encode("utf-8")))
        return socket.inet_ntoa(packed[20:24])
    except (IOError, ImportError):
        return None
    finally:
        s.close()


def can_access_internet(host: str = "8.8.8.8", port: int = 53, timeout: float = 3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def get_ssh_public_key(path: str | None = None) -> str:
    path = path or AUTH_KEYS_FILE
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.readline()
    except FileNotFoundError:
        return ""
    except Exception as e:
        return "Error reading file: %s" % e


def get_wifi_data(run: Runner = default_run) -> dict[str, Any]:
    try:
        result = run(["sudo", "nmcli", "--get-values=SSID,IN-USE", "dev", "wifi", "list",
                      "ifname", WIFI_INTERFACE], capture_output=True, text=True, check=True)
        ssids: list[str] = []
        active = ""
        for line in result.stdout.splitlines():
            row = line.split(":")
            if row[0] not in ssids and row[0] not in ("openeo", ""):
                ssids.append(row[0])
            if len(row) > 1 and row[1] == "*":
                active = row[0]
        return {"SSID": sorted(ssids), "CONNECTED": active}
    except subprocess.CalledProcessError as e:
        return {"error": "Command failed: %s" % e}
    except Exception as e:
        return {"error": str(e)}


def api_get_wifi(body: dict[str, Any], run: Runner = default_run) -> dict[str, Any]:
    data = get_wifi_data(run)
    data["INTERNET"] = can_access_internet()
    data["SSH"] = get_ssh_public_key()
    data["IP"] = get_ip_address(WIFI_INTERFACE)
    return data


def setup_wifi_connection(ssid: str, password: str, run: Runner = default_run) -> tuple[bool, str]:
    try:
        run(["sudo", "nmcli", "connection", "delete", CONNECTION_NAME], check=False)
        run(["sudo", "nmcli", "connection", "add", "type", "wifi", "ifname", WIFI_INTERFACE,
             "con-name", CONNECTION_NAME, "ssid", ssid], check=True)
        run(["sudo", "nmcli", "connection", "modify", CONNECTION_NAME,
             "wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", password], check=True)
        result = run(["sudo", "nmcli", "connection", "up", CONNECTION_NAME],
                     capture_output=True, text=True)
        ok = result.returncode == 0
        return ok, (result.stdout if ok else result.stderr).strip()
    except subprocess.CalledProcessError as e:
        return False, "nmcli error: %s" % (e.stderr.strip() if e.stderr else e)
    except Exception as e:
        return False, "Exception: %s" % e


def api_set_wifi(body: dict[str, Any], run: Runner = default_run) -> dict[str, Any]:
    ssid, password = body.get("ssid"), body.get("password")
    if not is_valid_ssid(ssid):
        return {"error": "Invalid SSID"}
    if not is_valid_password(password):
        return {"error": "Invalid Password"}
    connected, message = setup_wifi_connection(ssid, password, run)
    return {"connected_to_wifi": connected, "nmcli_message": message,
            "internet_access": can_access_internet()}


def api_get_timezones(body: dict[str, Any], run: Runner = default_run) -> dict[str, Any]:
    try:
        result = run(["timedatectl", "list-timezones"], capture_output=True, text=True, check=True)
        return {"timezones": [t for t in result.stdout.splitlines() if t.strip()],
                "current": get_current_timezone()}
    except subprocess.CalledProcessError as e:
        return {"error": "Failed to list timezones: %s" % (e.stderr or "").strip()}
    except Exception as e:
        return {"error": str(e)}


def api_set_timezone(body: dict[str, Any], run: Runner = default_run) -> dict[str, Any]:
    timezone = body.get("timezone")
    if not timezone or not isinstance(timezone, str):
        return {"error": "Missing or invalid 'timezone' parameter"}
    if not is_valid_timezone(timezone, run):
        return {"error": "Unknown timezone: '%s'" % timezone}
    try:
        run(["sudo", "rm", "-f", "/etc/localtime"], check=True)
        run(["sudo", "tee", "/etc/timezone"], input=timezone + "\n", text=True,
            check=True, stdout=subprocess.DEVNULL)
        result = run(["sudo", "dpkg-reconfigure", "-f", "noninteractive", "tzdata"],
                     capture_output=True, text=True)
        if result.returncode != 0:
            return {"error": "tzdata error: %s" % result.stderr.strip()}
        return {"timezone": get_current_timezone()}
    except Exception as e:
        return {"error": str(e)}


def api_set_ssh(body: dict[str, Any], run: Runner = default_run,
                ssh_dir: str | None = None) -> dict[str, Any]:
    key = body.get("key")
    if not is_valid_key(key):
        return {"error": "Invalid Key"}
    ssh_dir = ssh_dir or SSH_DIR
    auth_file = os.path.join(ssh_dir, "authorized_keys")
    os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
    os.chmod(ssh_dir, 0o700)
    tmp = auth_file + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key + "\n")
    os.replace(tmp, auth_file)
    return {"SSH": get_ssh_public_key(auth_file)}


API_HANDLERS_GET: dict[str, Handler] = {"get_wifi": api_get_wifi, "get_timezones": api_get_timezones}
API_HANDLERS_POST: dict[str, Handler] = {"set_wifi": api_set_wifi, "set_timezone": api_set_timezone,
                     "set_ssh": api_set_ssh}


def dispatch(method: str, api_name: str, headers: Headers, raw_body: bytes,
             run: Runner = default_run) -> tuple[int, dict[str, Any]]:
    """Pure request handling. Returns (status, json-able payload)."""
    handlers = API_HANDLERS_POST if method == "POST" else API_HANDLERS_GET
    if api_name not in handlers:
        other = API_HANDLERS_GET if method == "POST" else API_HANDLERS_POST
        if api_name in other:
            return 405, {"error": "Method not allowed"}
        return 404, {"error": "Unknown API endpoint"}
    body: Any = {}
    if method == "POST":
        if not origin_allowed(headers.get("Origin"), headers.get("Referer"), headers.get("Host")):
            return 403, {"error": "Cross-origin request refused"}
        if not is_json_content_type(headers.get("Content-Type")):
            return 415, {"error": "Content-Type must be application/json"}
        try:
            body = json.loads(raw_body.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return 400, {"error": "Invalid JSON"}
        if not isinstance(body, dict):
            return 400, {"error": "JSON object expected"}
    result = handlers[api_name](body, run)
    return (500 if "error" in result else 200), result


class APIServerHandler(http.server.SimpleHTTPRequestHandler):
    api_prefix = "/api/"

    def _api(self, method: str) -> None:
        name = urllib.parse.urlparse(self.path).path[len(self.api_prefix):].strip("/")
        raw = b""
        if method == "POST":
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                self._send(413, {"error": "Body too large"})
                return
            raw = self.rfile.read(length)
        try:
            status, result = dispatch(method, name, self.headers, raw)
        except Exception as e:
            status, result = 500, {"error": str(e)}
        self._send(status, result)

    def _send(self, status: int, result: Any) -> None:
        data = json.dumps(result, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path.startswith(self.api_prefix):
            self._api("GET")
        else:
            super().do_GET()

    def do_POST(self) -> None:
        if self.path.startswith(self.api_prefix):
            self._api("POST")
        else:
            self.send_error(404)

    def log_message(self, format: str, *args: Any) -> None:
        sys.stdout.write("%s - %s\n" % (self.client_address[0], format % args))


class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()


def start_ap(run: Runner = default_run) -> bool:
    return run(["sudo", PORTAL_SCRIPT, "start"], check=False).returncode == 0


def stop_ap(run: Runner = default_run) -> None:
    run(["sudo", PORTAL_SCRIPT, "stop"], check=False)


def serve(directory: str, timeout: float,
          server_factory: Callable[[tuple[str, int], type[APIServerHandler]], Any] = ThreadedServer) -> None:
    """Serve the portal on the AP address until timeout/SIGTERM."""
    os.chdir(directory)
    httpd = server_factory((BIND_ADDRESS, PORT), APIServerHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print("[PORTAL] serving %s on %s:%d" % (directory, BIND_ADDRESS, PORT))
    shutdown_event.wait(timeout)
    httpd.shutdown()


def main(argv: Sequence[str] | None = None, run: Runner = default_run,
         serve_fn: Callable[[str, float], None] = serve) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default=os.path.join(HERE, "html"), help="Directory to serve")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    args = parser.parse_args(argv)

    start, reason = decide_start(saved_wifi_client_profiles(run), read_force_portal(),
                                 read_stored_psk(run) is not None)
    if not start:
        print("[PORTAL] not starting: %s" % reason)
        return 0
    print("[PORTAL] starting: %s" % reason)

    if not start_ap(run):
        print("[PORTAL] access point failed to start; giving up")
        stop_ap(run)
        return 1
    try:
        signal.signal(signal.SIGTERM, lambda *_: shutdown_event.set())
        serve_fn(args.dir, args.timeout)
    except Exception as e:
        print("[PORTAL] error: %s" % e)
    finally:
        stop_ap(run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
