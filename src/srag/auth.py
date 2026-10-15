"""API key authentication, roles and a per-user rate limit.

Only SHA-256 hashes of the keys are stored. Keys are compared in constant time.
"""

import hashlib
import hmac
import json
import secrets
import threading
import time
from pathlib import Path

from srag.models import User


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class UserDirectory:
    def __init__(self, entries: list[dict]) -> None:
        self._entries = [(e["key_sha256"], User(e["name"], tuple(e["roles"]))) for e in entries]

    @classmethod
    def from_file(cls, path: Path) -> "UserDirectory":
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def authenticate(self, key: str | None) -> User | None:
        if not key:
            return None
        candidate = hash_key(key)
        found = None
        for stored, user in self._entries:  # check every entry so timing does not reveal which one matched
            if hmac.compare_digest(stored, candidate):
                found = user
        return found


def create_demo_users(path: Path) -> dict[str, str]:
    """Create two demo users with random keys. Returns name -> key (shown once)."""
    users = {
        "user1": ["public", "staff"],
        "user2": ["public", "staff", "security-admin"],
    }
    keys = {name: "srag_" + secrets.token_urlsafe(24) for name in users}
    entries = [{"name": n, "roles": r, "key_sha256": hash_key(keys[n])} for n, r in users.items()]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entries, indent=1), encoding="utf-8")
    return keys


class RateLimiter:
    """Sliding window: at most `limit` requests per user in the last 60 seconds."""

    def __init__(self, limit: int, window_s: float = 60.0) -> None:
        self.limit = limit
        self.window = window_s
        self._calls: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, user: str) -> bool:
        now = time.monotonic()
        with self._lock:
            calls = [t for t in self._calls.get(user, []) if now - t < self.window]
            if len(calls) >= self.limit:
                self._calls[user] = calls
                return False
            calls.append(now)
            self._calls[user] = calls
            return True
