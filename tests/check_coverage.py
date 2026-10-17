#!/usr/bin/env python3
"""Fail if any module is below its coverage floor in pyproject.toml.

Usage (after `pytest --cov --cov-branch`):  python tests/check_coverage.py
"""
import json
import os
import subprocess
import sys

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - python < 3.11
    import tomli as tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    with open(os.path.join(ROOT, "pyproject.toml"), "rb") as f:
        thresholds = tomllib.load(f)["tool"]["openeo"]["coverage_thresholds"]
    out = os.path.join(ROOT, "coverage.json")
    subprocess.run([sys.executable, "-m", "coverage", "json", "-o", out, "-q"], cwd=ROOT, check=True)
    with open(out) as f:
        files = json.load(f)["files"]
    os.remove(out)
    failed = False
    print("%-36s %8s %8s" % ("module", "covered", "floor"))
    for path, floor in sorted(thresholds.items()):
        entry = files.get(path)
        pct = entry["summary"]["percent_covered"] if entry else 0.0
        flag = "" if pct >= floor else "   <-- BELOW FLOOR"
        failed |= pct < floor
        print("%-36s %7.1f%% %7d%%%s" % (path, pct, floor, flag))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
