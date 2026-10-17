"""The systemd units ship the privileges the services need, and no more."""
import configparser
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UNITS = os.path.join(ROOT, "portal", "config", "etc", "systemd", "system")


def _unit(name):
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read(os.path.join(UNITS, name))
    return parser


def test_portal_runs_as_pi_with_only_the_bind_capability():
    service = _unit("openeo_portal.service")["Service"]
    assert service["User"] == "pi"
    # Port 81 needs CAP_NET_BIND_SERVICE; on first boot python3 has not been setcap'd yet.
    assert service["AmbientCapabilities"] == "CAP_NET_BIND_SERVICE"


def test_portal_starts_after_the_first_boot_step():
    unit = _unit("openeo_portal.service")["Unit"]
    assert "openeo_firstboot.service" in unit["After"].split()


def test_first_boot_step_runs_before_openeo_and_portal():
    unit = _unit("openeo_firstboot.service")["Unit"]
    assert set(unit["Before"].split()) == {"openeo.service", "openeo_portal.service"}
