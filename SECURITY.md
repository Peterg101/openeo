# Security

This fork ([Peterg101/openeo](https://github.com/Peterg101/openeo)) hardens OpenEO after a
security review. Charger control (EO_comms, scheduling, load management, switch logic) is
unchanged. This file lists every change, how to set the device up, and what is still open.

## Setup file (`openeo-setup.txt`)

The SD-card image ships `openeo-setup.txt` on the boot partition (`bootfs` on a Mac):

```
hotspot_password=      # 8-63 printable ASCII: password of the "OpenEO" setup Wi-Fi
admin_password=        # >= 8 characters: web UI login
force_portal=no        # yes = start the setup hotspot even if Wi-Fi is already saved
```

At boot `openeo_firstboot.service` (root, before `openeo` and the portal) parses it (comments,
CRLF, stray whitespace tolerated; later lines win), writes the hotspot passphrase to
`/etc/openeo/hotspot.psk` (root:root 0600), writes a scrypt hash of the admin password to a
pi-owned 0600 file that the web app imports into its config database, and rewrites the setup
file with the values blanked. Invalid values are *not* applied and are left in the file so you can
fix them. With no admin password stored, the web UI refuses every login and says why.

## Changes by finding

### 1. Setup portal
* Starts only if the Pi has **no saved Wi-Fi client connection** on wlan0 (the `openeo-AP` profile
  is ignored) or `force_portal=yes`; otherwise exits cleanly. If NetworkManager cannot be queried it
  stays down.
* The access point is **WPA2-PSK** using `hotspot_password`. Without a valid passphrase the AP and
  portal never start (there is no open fallback), and the AP script re-checks that NetworkManager
  really holds `wpa-psk` before bringing it up.
* HTTP server binds `192.168.4.1:81` only (was all interfaces). The `80 -> 81` iptables redirect
  stays on `wlan1` only and is now removed on stop.
* Runs as `pi` (was root) with only `CAP_NET_BIND_SERVICE` granted by its unit (port 81); privileged steps use `sudo`. `dnsmasq` is no longer enabled at boot.
* `set_wifi` / `set_timezone` are POST (were state-changing GETs); all POSTs need
  `Content-Type: application/json` and a same-origin `Origin`/`Referer`.
* `set_ssh`: the key must be one line (newline / CR / control characters rejected; the old regex
  let `key\nssh-rsa attacker` through); written atomically with mode 0600.
* Handlers are plain functions with an injected subprocess runner (`portal/portal.py`).

### 2. Main web UI (FastAPI, `lib/webapp/`)
* Rewritten as a FastAPI app built by `create_app(deps)`; routes get their collaborators through
  `Depends` providers (`lib/webapp/deps.py`); the only code touching `globalState` is
  `lib/webapp/providers.py`. uvicorn runs single-worker, no reload, signal handlers disabled so it
  can run in the plugin thread.
* **Login**: single admin; scrypt (N=2^14, r=8, p=1) with random salt stored in the config DB under
  the private key `configserver:_admin_password_hash`; constant-time compare. Server-side sessions
  (random 32-byte token, cookie `HttpOnly; SameSite=Strict; Path=/`, 12 h idle / 30 day absolute,
  all revoked on password change); per-IP exponential login backoff (HTTP 429).
* **Every route is authenticated by default** (one app-level dependency). Public: `GET/POST /login`,
  `GET /health`, `GET /favicon.ico`. A test walks `app.routes` and fails if anything else answers
  without a session.
* `/metrics` and `/api` also accept `Authorization: Bearer <token>`; the token is generated in
  Settings -> Security, shown once, stored as SHA-256, off by default.
* **CSRF**: state-changing requests need `Content-Type: application/json` and, if `Origin`
  (or `Referer`) is present, it must match `Host`. The dev-mode `Access-Control-Allow-Origin: *`
  branches are gone.
* `/restart` is POST-only. `/update` accepts only `openeo`, `raspberrypi`, `reboot` (+ `status`).
* `/getconfig`, `/get_user_settings` and the `/setsettings` response mask `mqtt_password`,
  `authtoken` and anything in `SECRET_KEYS` as `********`; sending the mask back means "unchanged".
  Secrets are also masked in the config-change log, the startup config log and the debug report.
* `/setsettings` validates **all** pairs first: module must exist, key must be in that module's
  `pluginParamSpec`, no underscore-prefixed keys; any failure is a 400 and nothing is written.
* `/debugdata` runs argv lists (no `shell=True`); the `ps | grep` filter is done in Python.
* Static files resolve through `realpath` and must stay inside the static directory (symlinks and
  `..`, encoded or not, are refused); only html/ico/png/svg/js/css are served.
* Per-request database logging of every GET was dropped (SD-card wear); state changes and auth
  events are still logged, without secrets.

### 3. Cloud module
* TLS verification is on. `ssl.openeo.uk:8381` presents a **self-signed certificate with no SAN**
  (valid to Nov 2035), so public-CA and hostname verification are impossible. The certificate is
  **pinned**: `lib/cloud_certs/ssl.openeo.uk.pem` is the only trust anchor, chain verification is
  required (`CERT_REQUIRED`) and the SHA-256 fingerprint of the presented certificate is compared
  with the pin (`lib/cloud_tls.py`). If the operator rotates the certificate, connections fail
  closed until the new certificate is committed.
* Proxied paths are validated (`lib/cloudpath.py`): must start with a single `/`; no `@`, `\`,
  scheme, `..`, whitespace or control characters; no `:` in the first segment. The URL is always
  `http://127.0.0.1:<configserver port><path>`; redirects are never followed.
* Proxied requests authenticate with a random per-process token (`lib/internal_auth.py`) that the web
  app accepts only from loopback, and which cannot manage credentials (password, API token, logout).
* The module remains disabled by default (`enabled: False`, also in `globalState.defaultConfig`).
  Existing installs that already stored `enabled=true` keep their choice.

### 4. Updates
`openeo_download.py` holds the single `GITHUB_REPO = "Peterg101/openeo"`; `lib/checkversion.py`
imports it. `tools/update_openeo.sh` downloads the updater to a temp file and runs it instead of
`curl | python3 -`. `CHANGELOG.md` history is untouched.

## Known limitations / not covered
* The web UI is plain HTTP on the LAN: the login password and session cookie travel in clear text.
  Use it only on a trusted network (or put a TLS proxy in front).
* Sessions live in RAM; restarting openeo logs everyone out.
* DNS rebinding: a hostile page that rebinds its name to the charger can reach the unauthenticated
  routes (`/login`, `/health`) but carries no session cookie, so it can only guess passwords
  (rate limited per client IP). A `Host` allowlist would close this; not added.
* The portal `set_ssh` endpoint lets anyone who knows the hotspot password install an SSH key, and
  `pi` has `NOPASSWD: ALL` sudo, so that key is root. The hotspot password is the only barrier.
* `tools/debug` uploads a debug report to a third-party host (`eo.scott.land`); secrets are now
  redacted from it, but it still contains logs and configuration.
* The SD image build and the on-device flows (nmcli AP with WPA2, first-boot service
  ordering, uvicorn on the Pi's apt packages) were not exercised on real hardware by this change.
* The OpenEO Cloud service itself is a third party and, if enabled, can drive anything the web UI can
  (except credential management).

## Running the tests
```
python -m pip install pytest pytest-cov psutil fastapi uvicorn httpx
python -m pytest tests --cov --cov-branch && python tests/check_coverage.py
(cd openeo-ui && npm ci && npm test)
```
