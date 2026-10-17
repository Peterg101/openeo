"""In-memory server-side sessions and login rate limiting.

Sessions live only in RAM: a restart of openeo logs everyone out, which is an
acceptable trade-off for not persisting bearer credentials on the SD card.
Both classes take an injectable clock so tests never sleep.
"""
import hashlib
import secrets
import threading
import time

IDLE_TIMEOUT = 12 * 60 * 60            # 12 hours without activity
ABSOLUTE_TIMEOUT = 30 * 24 * 60 * 60   # 30 days regardless of activity
MAX_SESSIONS = 50


def _digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SessionStore:
    def __init__(self, clock=time.monotonic, idle_timeout=IDLE_TIMEOUT,
                 absolute_timeout=ABSOLUTE_TIMEOUT, max_sessions=MAX_SESSIONS):
        self._clock = clock
        self.idle_timeout = idle_timeout
        self.absolute_timeout = absolute_timeout
        self.max_sessions = max_sessions
        self._sessions = {}   # sha256(token) -> [created, last_seen]
        self._lock = threading.Lock()

    def create(self):
        """Start a session and return its random 32-byte (url-safe) token."""
        token = secrets.token_urlsafe(32)
        now = self._clock()
        with self._lock:
            self._purge(now)
            while len(self._sessions) >= self.max_sessions:
                oldest = min(self._sessions, key=lambda k: self._sessions[k][1])
                del self._sessions[oldest]
            self._sessions[_digest(token)] = [now, now]
        return token

    def validate(self, token):
        """True (and refreshes the idle timer) if the token is a live session."""
        if not token or not isinstance(token, str):
            return False
        key = _digest(token)
        now = self._clock()
        with self._lock:
            entry = self._sessions.get(key)
            if entry is None:
                return False
            created, last_seen = entry
            if now - created > self.absolute_timeout or now - last_seen > self.idle_timeout:
                del self._sessions[key]
                return False
            entry[1] = now
            return True

    def revoke(self, token):
        if token:
            with self._lock:
                self._sessions.pop(_digest(token), None)

    def revoke_all(self):
        with self._lock:
            self._sessions.clear()

    def count(self):
        with self._lock:
            return len(self._sessions)

    def _purge(self, now):
        dead = [k for k, (created, last) in self._sessions.items()
                if now - created > self.absolute_timeout or now - last > self.idle_timeout]
        for k in dead:
            del self._sessions[k]


class LoginRateLimiter:
    """Per-key (client IP) exponential backoff after repeated failures."""

    def __init__(self, clock=time.monotonic, free_attempts=5, base_delay=30,
                 max_delay=15 * 60, max_entries=1000):
        self._clock = clock
        self.free_attempts = free_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_entries = max_entries
        self._state = {}   # key -> [failures, locked_until, last_failure]
        self._lock = threading.Lock()

    def retry_after(self, key):
        """Seconds the caller must wait before another attempt (0 = go ahead)."""
        now = self._clock()
        with self._lock:
            entry = self._state.get(key)
            if not entry:
                return 0
            return max(0, int(entry[1] - now + 0.999))

    def record_failure(self, key):
        now = self._clock()
        with self._lock:
            if len(self._state) >= self.max_entries:
                self._prune(now)
            entry = self._state.setdefault(key, [0, 0.0, now])
            entry[0] += 1
            entry[2] = now
            if entry[0] >= self.free_attempts:
                delay = min(self.max_delay, self.base_delay * 2 ** (entry[0] - self.free_attempts))
                entry[1] = now + delay

    def record_success(self, key):
        with self._lock:
            self._state.pop(key, None)

    def _prune(self, now):
        stale = [k for k, e in self._state.items() if now - e[2] > 3600 and e[1] <= now]
        for k in stale:
            del self._state[k]
        if len(self._state) >= self.max_entries:
            # Still full of live lockouts: drop the oldest quarter.
            for k in sorted(self._state, key=lambda k: self._state[k][2])[: self.max_entries // 4]:
                del self._state[k]
