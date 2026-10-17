#!/usr/bin/env python3
"""First-boot setup-file handling (runs as root, early in boot).

The owner edits `openeo-setup.txt` on the SD card's boot partition (from a Mac or
PC). On boot this step:

  * parses it (comments, blank lines, CRLF, stray whitespace tolerated; a later
    assignment overrides an earlier one),
  * stores the Wi-Fi hotspot passphrase in /etc/openeo/hotspot.psk (root:root 0600),
  * stores the admin password as a scrypt hash in a pi-owned 0600 file that the web
    app imports into its config database,
  * rewrites the setup file with the plain-text values blanked.

The parsing/decision logic is pure and unit tested; all side effects are injected
through `Hooks`.
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from lib.webapp import passwords  # noqa: E402  (stdlib-only module)

SETUP_FILE_NAME = "openeo-setup.txt"
SETUP_FILE_CANDIDATES = ("/boot/firmware/" + SETUP_FILE_NAME, "/boot/" + SETUP_FILE_NAME)
PSK_DIR = "/etc/openeo"
PSK_FILE = PSK_DIR + "/hotspot.psk"
CONFIG_DIR = "/home/pi/etc"
PENDING_ADMIN_FILE = CONFIG_DIR + "/admin_password.hash"
CONFIG_DB = CONFIG_DIR + "/config.db"

HEADER = (
    "# OpenEO first-boot setup. Fill these in, save, eject, then boot the Pi.\n"
    "# The Pi reads them once and then removes the plain-text values from this file.\n"
)
TRUE_VALUES = ("yes", "true", "1", "on", "y")


def parse_setup(text):
    """Parse the setup file into a dict of lower-cased keys.

    Unknown keys are kept (and ignored later). A '#' only starts a comment at
    the beginning of a line, so passwords may contain '#'.
    """
    values = {}
    if text.startswith("﻿"):
        text = text[1:]
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip().lower()] = value.strip()
    return values


def parse_bool(value):
    return str(value).strip().lower() in TRUE_VALUES


def is_valid_hotspot_psk(psk):
    """WPA2 passphrase: 8-63 printable ASCII characters."""
    return (isinstance(psk, str) and 8 <= len(psk) <= 63
            and all(0x20 <= ord(c) <= 0x7e for c in psk))


def read_force_portal(text):
    return parse_bool(parse_setup(text).get("force_portal", "no"))


def render_applied(force_portal, applied, when):
    """The text written back to the setup file after values were consumed."""
    lines = [HEADER.rstrip("\n")]
    if applied:
        lines.append("# Applied on %s: %s. The plain-text values were removed."
                     % (when, ", ".join(applied)))
    lines += ["hotspot_password=", "admin_password=", "force_portal=%s" % force_portal, ""]
    return "\n".join(lines)


class Hooks:
    """Side effects, replaced by fakes in tests."""
    def store_psk(self, psk):            # pragma: no cover - interface
        raise NotImplementedError
    def store_admin_hash(self, stored):  # pragma: no cover - interface
        raise NotImplementedError
    def have_psk(self):                  # pragma: no cover - interface
        raise NotImplementedError
    def have_admin(self):                # pragma: no cover - interface
        raise NotImplementedError


class Result:
    def __init__(self):
        self.applied = []     # names of values stored
        self.errors = []      # values rejected (left in the file for the owner to fix)
        self.warnings = []
        self.new_text = None  # replacement file text, or None to leave the file alone
        self.force_portal = False


def apply_setup(text, hooks, now="", hash_fn=passwords.hash_password):
    """Apply a parsed setup file. Never logs or returns a plain-text secret."""
    values = parse_setup(text)
    result = Result()
    result.force_portal = parse_bool(values.get("force_portal", "no"))
    remaining = {}

    psk = values.get("hotspot_password", "")
    if psk:
        if not is_valid_hotspot_psk(psk):
            result.errors.append("hotspot_password must be 8-63 printable ASCII characters; not applied")
            remaining["hotspot_password"] = psk
        else:
            try:
                hooks.store_psk(psk)
                result.applied.append("hotspot_password")
            except Exception as e:
                result.errors.append("could not store hotspot password: %s" % e.__class__.__name__)
                remaining["hotspot_password"] = psk

    admin = values.get("admin_password", "")
    if admin:
        problem = passwords.password_policy_error(admin)
        if problem:
            result.errors.append("admin_password rejected: %s; not applied" % problem)
            remaining["admin_password"] = admin
        else:
            try:
                hooks.store_admin_hash(hash_fn(admin))
                result.applied.append("admin_password")
            except Exception as e:
                result.errors.append("could not store admin password: %s" % e.__class__.__name__)
                remaining["admin_password"] = admin

    if not psk and not hooks.have_psk():
        result.warnings.append("no hotspot password set: the setup hotspot will NOT start. "
                               "Fill in hotspot_password in %s" % SETUP_FILE_NAME)
    if not admin and not hooks.have_admin():
        result.warnings.append("no admin password set: the web UI will refuse all logins. "
                               "Fill in admin_password in %s" % SETUP_FILE_NAME)

    if result.applied:
        text_out = render_applied(values.get("force_portal", "no"), result.applied, now)
        for name, value in remaining.items():   # keep rejected values so they can be corrected
            text_out = text_out.replace("%s=\n" % name, "%s=%s\n" % (name, value), 1)
        result.new_text = text_out
    return result


# ---------------------------------------------------------------------------
# Real side effects
# ---------------------------------------------------------------------------

def _write_private(path, data, uid, gid):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(data)
    os.chown(tmp, uid, gid)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


class SystemHooks(Hooks):
    def __init__(self):
        import pwd
        pw = pwd.getpwnam("pi")
        self.pi_uid, self.pi_gid = pw.pw_uid, pw.pw_gid

    def store_psk(self, psk):
        os.makedirs(PSK_DIR, mode=0o700, exist_ok=True)
        os.chmod(PSK_DIR, 0o700)
        _write_private(PSK_FILE, psk + "\n", 0, 0)

    def store_admin_hash(self, stored):
        if not os.path.isdir(CONFIG_DIR):
            os.mkdir(CONFIG_DIR)
            os.chown(CONFIG_DIR, self.pi_uid, self.pi_gid)
        _write_private(PENDING_ADMIN_FILE, stored + "\n", self.pi_uid, self.pi_gid)

    def have_psk(self):
        return os.path.isfile(PSK_FILE)

    def have_admin(self):
        if os.path.isfile(PENDING_ADMIN_FILE):
            return True
        try:
            import sqlite3
            conn = sqlite3.connect("file:%s?mode=ro" % CONFIG_DB, uri=True)
            try:
                row = conn.execute("SELECT 1 FROM configuration_v2 WHERE module='configserver' "
                                   "AND key='_admin_password_hash' AND value!=''").fetchone()
            finally:
                conn.close()
            return row is not None
        except Exception:
            return False


def find_setup_file(candidates=SETUP_FILE_CANDIDATES, exists=os.path.isfile):
    for path in candidates:
        if exists(path):
            return path
    return None


def main():
    path = find_setup_file()
    hooks = SystemHooks()
    if path is None:
        text = ""
        print("openeo-setup: no %s found on the boot partition" % SETUP_FILE_NAME)
    else:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
            text = f.read()
    result = apply_setup(text, hooks, now=time.strftime("%Y-%m-%d %H:%M"))
    for name in result.applied:
        print("openeo-setup: applied %s" % name)
    for line in result.errors:
        print("openeo-setup: ERROR: %s" % line)
    for line in result.warnings:
        print("openeo-setup: WARNING: %s" % line)
    if result.new_text is not None and path is not None:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(result.new_text)
        os.replace(tmp, path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
