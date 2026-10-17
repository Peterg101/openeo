"""First-boot setup file: parsing, applying, and the real-file side effects."""
import os
import stat
import sys

import pytest

import setupfile
from lib.webapp import passwords


class FakeHooks(setupfile.Hooks):
    def __init__(self, have_psk=False, have_admin=False, fail=()):
        self.psk = self.admin = None
        self._have_psk, self._have_admin, self.fail = have_psk, have_admin, fail

    def store_psk(self, psk):
        if "psk" in self.fail:
            raise OSError("disk full")
        self.psk = psk

    def store_admin_hash(self, stored):
        if "admin" in self.fail:
            raise OSError("disk full")
        self.admin = stored

    def have_psk(self):
        return self._have_psk or self.psk is not None

    def have_admin(self):
        return self._have_admin or self.admin is not None


FAST = lambda pw: passwords.hash_password(pw, n=2 ** 4)   # noqa: E731


# ---- parsing ----------------------------------------------------------------------
def test_template_in_repo_parses_to_blanks():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    text = open(os.path.join(root, "openeo-setup.txt")).read()
    assert setupfile.parse_setup(text) == {"hotspot_password": "", "admin_password": "", "force_portal": "no"}


def test_parse_handles_crlf_cr_bom_comments_whitespace():
    text = "\ufeff# comment\r\n\r\n  Hotspot_Password =  my secret pass \r\nadmin_password=abc#def\rforce_portal=Yes\r\nnoequals\r\n"
    assert setupfile.parse_setup(text) == {"hotspot_password": "my secret pass",
                                           "admin_password": "abc#def", "force_portal": "Yes"}


def test_later_values_override_earlier_ones():
    assert setupfile.parse_setup("admin_password=one\nadmin_password=two\n")["admin_password"] == "two"


def test_equals_inside_value_is_kept():
    assert setupfile.parse_setup("hotspot_password=a=b=c")["hotspot_password"] == "a=b=c"


@pytest.mark.parametrize("v,expected", [("yes", True), ("YES", True), ("true", True), ("1", True),
                                        ("on", True), ("no", False), ("", False), ("0", False), ("maybe", False)])
def test_parse_bool(v, expected):
    assert setupfile.parse_bool(v) is expected


@pytest.mark.parametrize("psk,ok", [("12345678", True), ("a" * 63, True), ("a" * 64, False), ("short", False),
                                    ("with space ok", True), ("tab\there!", False), ("ünïcödé-pass", False),
                                    ("new\nline12", False), ("", False), (None, False)])
def test_hotspot_psk_validation(psk, ok):
    assert setupfile.is_valid_hotspot_psk(psk) is ok


def test_read_force_portal():
    assert setupfile.read_force_portal("force_portal=yes") is True
    assert setupfile.read_force_portal("") is False


# ---- applying ---------------------------------------------------------------------------
def test_apply_stores_both_and_blanks_file():
    hooks = FakeHooks()
    r = setupfile.apply_setup("hotspot_password=wifi-pass-1\nadmin_password=admin-pass-1\nforce_portal=yes\n",
                              hooks, now="2025-01-01 00:00", hash_fn=FAST)
    assert hooks.psk == "wifi-pass-1"
    assert passwords.verify_password("admin-pass-1", hooks.admin) and "admin-pass-1" not in hooks.admin
    assert r.applied == ["hotspot_password", "admin_password"] and r.errors == [] and r.warnings == []
    assert r.force_portal is True
    assert setupfile.parse_setup(r.new_text) == {"hotspot_password": "", "admin_password": "", "force_portal": "yes"}
    assert "wifi-pass-1" not in r.new_text and "admin-pass-1" not in r.new_text
    assert "Applied on 2025-01-01 00:00: hotspot_password, admin_password" in r.new_text
    assert r.new_text.startswith("# OpenEO first-boot setup.")


def test_nothing_to_apply_leaves_file_alone_and_warns_when_nothing_stored():
    r = setupfile.apply_setup("hotspot_password=\nadmin_password=\nforce_portal=no\n", FakeHooks(), hash_fn=FAST)
    assert r.new_text is None and r.applied == []
    assert len(r.warnings) == 2
    assert "hotspot will NOT start" in r.warnings[0] and "refuse all logins" in r.warnings[1]
    assert not setupfile.apply_setup("", FakeHooks(), hash_fn=FAST).force_portal


def test_no_warning_when_already_stored():
    r = setupfile.apply_setup("", FakeHooks(have_psk=True, have_admin=True), hash_fn=FAST)
    assert r.warnings == [] and r.new_text is None


def test_only_one_value_given():
    hooks = FakeHooks(have_psk=True)
    r = setupfile.apply_setup("admin_password=admin-pass-1\n", hooks, hash_fn=FAST)
    assert hooks.psk is None and hooks.admin and r.applied == ["admin_password"] and r.warnings == []


def test_invalid_values_are_not_applied_and_stay_for_the_owner_to_fix():
    hooks = FakeHooks()
    r = setupfile.apply_setup("hotspot_password=short\nadmin_password=tiny\n", hooks, hash_fn=FAST)
    assert hooks.psk is None and hooks.admin is None and r.applied == []
    assert len(r.errors) == 2 and r.new_text is None
    assert "short" not in " ".join(r.errors + r.warnings).replace("too short", "")  # no secret echoed


def test_mixed_valid_and_invalid_keeps_only_the_rejected_one():
    hooks = FakeHooks()
    r = setupfile.apply_setup("hotspot_password=bad\nadmin_password=admin-pass-1\n", hooks, hash_fn=FAST)
    assert r.applied == ["admin_password"] and hooks.psk is None
    assert setupfile.parse_setup(r.new_text) == {"hotspot_password": "bad", "admin_password": "", "force_portal": "no"}


def test_storage_failure_keeps_value_and_reports_without_secret():
    hooks = FakeHooks(fail=("psk", "admin"))
    r = setupfile.apply_setup("hotspot_password=wifi-pass-1\nadmin_password=admin-pass-1\n", hooks, hash_fn=FAST)
    assert r.applied == [] and len(r.errors) == 2 and r.new_text is None
    assert all("pass-1" not in e for e in r.errors)


def test_force_portal_preserved_in_rewrite():
    r = setupfile.apply_setup("hotspot_password=wifi-pass-1\nforce_portal=no\n", FakeHooks(), hash_fn=FAST)
    assert setupfile.parse_setup(r.new_text)["force_portal"] == "no"


# ---- real side effects, redirected into tmp ------------------------------------------------
@pytest.fixture
def sysenv(tmp_path, monkeypatch):
    import pwd
    me = pwd.getpwuid(os.getuid())
    monkeypatch.setattr(setupfile, "PSK_DIR", str(tmp_path / "etc-openeo"))
    monkeypatch.setattr(setupfile, "PSK_FILE", str(tmp_path / "etc-openeo" / "hotspot.psk"))
    monkeypatch.setattr(setupfile, "CONFIG_DIR", str(tmp_path / "pietc"))
    monkeypatch.setattr(setupfile, "PENDING_ADMIN_FILE", str(tmp_path / "pietc" / "admin.hash"))
    monkeypatch.setattr(setupfile, "CONFIG_DB", str(tmp_path / "pietc" / "config.db"))
    monkeypatch.setattr(pwd, "getpwnam", lambda n: me)
    # chown to our own ids works unprivileged; chown to root does not
    real_chown = os.chown
    monkeypatch.setattr(os, "chown", lambda p, u, g: real_chown(p, os.getuid(), os.getgid()))
    return tmp_path


def test_system_hooks_write_private_files(sysenv):
    h = setupfile.SystemHooks()
    assert not h.have_psk() and not h.have_admin()
    h.store_psk("wifi-pass-1")
    assert open(setupfile.PSK_FILE).read() == "wifi-pass-1\n"
    assert stat.S_IMODE(os.stat(setupfile.PSK_FILE).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(setupfile.PSK_DIR).st_mode) == 0o700
    h.store_admin_hash("scrypt$x")
    assert stat.S_IMODE(os.stat(setupfile.PENDING_ADMIN_FILE).st_mode) == 0o600
    assert h.have_psk() and h.have_admin()


def test_have_admin_checks_database_too(sysenv):
    import sqlite3
    os.makedirs(setupfile.CONFIG_DIR)
    conn = sqlite3.connect(setupfile.CONFIG_DB)
    conn.execute("CREATE TABLE configuration_v2 (module TEXT, key TEXT, value, update_ts)")
    h = setupfile.SystemHooks()
    assert not h.have_admin()
    conn.execute("INSERT INTO configuration_v2 VALUES ('configserver','_admin_password_hash','',0)")
    conn.commit()
    assert not h.have_admin()                 # blank hash does not count
    conn.execute("UPDATE configuration_v2 SET value='scrypt$x'")
    conn.commit(); conn.close()
    assert h.have_admin()


def test_find_setup_file_prefers_firmware():
    seen = {"/boot/openeo-setup.txt"}
    assert setupfile.find_setup_file(exists=lambda p: p in seen) == "/boot/openeo-setup.txt"
    seen.add("/boot/firmware/openeo-setup.txt")
    assert setupfile.find_setup_file(exists=lambda p: p in seen) == "/boot/firmware/openeo-setup.txt"
    assert setupfile.find_setup_file(exists=lambda p: False) is None


def test_main_end_to_end_with_crlf_file(sysenv, monkeypatch, capsys):
    f = sysenv / "openeo-setup.txt"
    f.write_bytes(b"# edited on a PC\r\nhotspot_password=wifi-pass-1\r\nadmin_password=admin-pass-1\r\nforce_portal=no\r\n")
    monkeypatch.setattr(setupfile, "find_setup_file", lambda *a, **k: str(f))
    monkeypatch.setattr(passwords, "hash_password", FAST)
    monkeypatch.setattr(setupfile, "apply_setup",
                        lambda text, hooks, now="": setupfile.apply_setup.__wrapped__(text, hooks, now)
                        if hasattr(setupfile.apply_setup, "__wrapped__") else _orig(text, hooks, now))
    assert setupfile.main() == 0
    out = capsys.readouterr().out
    assert "applied hotspot_password" in out and "wifi-pass-1" not in out and "admin-pass-1" not in out
    assert open(setupfile.PSK_FILE).read() == "wifi-pass-1\n"
    stored = open(setupfile.PENDING_ADMIN_FILE).read().strip()
    assert passwords.verify_password("admin-pass-1", stored)
    text = f.read_text()
    assert "wifi-pass-1" not in text and "admin-pass-1" not in text and "force_portal=no" in text
    assert "\r" not in text


_orig = setupfile.apply_setup


def test_main_without_file_warns(sysenv, monkeypatch, capsys):
    monkeypatch.setattr(setupfile, "find_setup_file", lambda *a, **k: None)
    assert setupfile.main() == 0
    out = capsys.readouterr().out
    assert "no openeo-setup.txt found" in out and "WARNING" in out
