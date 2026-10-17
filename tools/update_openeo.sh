#!/usr/bin/bash
# Update OpenEO from the Peterg101/openeo fork. The downloader is saved to a
# temporary file first (not piped straight into an interpreter) so that a failed or
# truncated download is never executed.
set -u

REPO="Peterg101/openeo"
URL="https://github.com/${REPO}/raw/refs/heads/main/openeo_download.py"

date
echo "Updating OpenEO from ${REPO}"
TMP=$(mktemp /tmp/openeo_download.XXXXXX.py) || exit 1
trap 'rm -f "$TMP"' EXIT
curl -sSL --fail --proto '=https' --tlsv1.2 -o "$TMP" "$URL" || { echo >&2 "Download of openeo_download.py failed"; exit 1; }
python3 "$TMP"
