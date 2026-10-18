"""Admin credential storage on top of the existing config database.

Everything lives in module "configserver" under keys with a leading underscore,
which every exporter in this code base already treats as private. The password
is only ever stored as a scrypt hash; the API token only as a SHA-256 digest
(it is 256 bits of randomness, so a fast hash is appropriate).

The root first-boot step cannot safely write to the pi-owned SQLite file, so it
drops the hash in PENDING_PASSWORD_FILE (owned by pi, mode 0600) and the web app
imports it into the database the next time it looks.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets

from lib.webapp import passwords
from lib.webapp.protocols import ConfigDB

MODULE: str = "configserver"
PASSWORD_KEY: str = "_admin_password_hash"
API_TOKEN_KEY: str = "_api_token_hash"
API_TOKEN_PREFIX: str = "oeo_"

PENDING_PASSWORD_FILE: str = "/home/pi/etc/admin_password.hash"


class AuthStore:
    def __init__(self, config_db: ConfigDB, pending_file: str = PENDING_PASSWORD_FILE) -> None:
        self.db = config_db
        self.pending_file = pending_file

    # -- admin password -------------------------------------------------
    def import_pending(self) -> bool:
        """Move a hash left by the first-boot step into the database."""
        try:
            if not os.path.isfile(self.pending_file):
                return False
            with open(self.pending_file, "r", encoding="ascii") as f:
                stored = f.read().strip()
            if not passwords.looks_like_hash(stored):
                return False
            self.db.set(MODULE, PASSWORD_KEY, stored, triggerModuleReonfigure=False)
            os.remove(self.pending_file)
            return True
        except (OSError, UnicodeDecodeError):
            return False

    def get_hash(self) -> str:
        self.import_pending()
        stored = self.db.get(MODULE, PASSWORD_KEY, "")
        return stored if passwords.looks_like_hash(stored) else ""

    def has_password(self) -> bool:
        return bool(self.get_hash())

    def verify_password(self, password: str) -> bool:
        stored = self.get_hash()
        return bool(stored) and passwords.verify_password(password, stored)

    def set_password(self, password: str) -> None:
        error = passwords.password_policy_error(password)
        if error:
            raise ValueError(error)
        self.db.set(MODULE, PASSWORD_KEY, passwords.hash_password(password),
                    triggerModuleReonfigure=False)

    # -- API token (for /metrics and /api) ---------------------------------
    @staticmethod
    def _token_digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def api_token_enabled(self) -> bool:
        return bool(self.db.get(MODULE, API_TOKEN_KEY, ""))

    def create_api_token(self) -> str:
        """Create (replacing any previous) token. The plaintext is returned once."""
        token = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
        self.db.set(MODULE, API_TOKEN_KEY, self._token_digest(token), triggerModuleReonfigure=False)
        return token

    def revoke_api_token(self) -> None:
        self.db.set(MODULE, API_TOKEN_KEY, "", triggerModuleReonfigure=False)

    def check_api_token(self, token: str) -> bool:
        stored = self.db.get(MODULE, API_TOKEN_KEY, "")
        if not stored or not token:
            return False
        return hmac.compare_digest(self._token_digest(token), stored)
