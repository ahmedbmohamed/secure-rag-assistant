"""Accounts, passwords, MFA, sessions, lockout and rate limits.

* Passwords are hashed with PBKDF2-HMAC-SHA256 (600,000 iterations, random salt).
* People sign in with a password and a 6-digit authenticator code (TOTP). The session lives in an
  HttpOnly cookie that JavaScript cannot read.
* Five failed attempts lock the account for 15 minutes, and an IP address with too many failures is
  blocked for 15 minutes, which stops password and API key guessing.
* API keys are for service accounts (scripts, integrations). Only their SHA-256 hash is stored.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from srag.models import User

PBKDF2_ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 14  # Demo Bank policy: at least 14 characters
_COMMON = {
    "password",
    "passw0rd",
    "welcome",
    "letmein",
    "qwerty",
    "azerty",
    "admin",
    "changeme",
    "123456",
    "iloveyou",
    "motdepasse",
    "secret",
    "dragon",
    "football",
}


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        # Spend the same time as a real check, so an unknown username cannot be told apart by timing.
        hashlib.pbkdf2_hmac("sha256", password.encode(), b"0" * 16, PBKDF2_ITERATIONS)
        return False
    _, iterations, salt, digest = stored.split("$")
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(iterations))
    return hmac.compare_digest(candidate, base64.b64decode(digest))


def password_problems(password: str, username: str = "") -> list[str]:
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"at least {MIN_PASSWORD_LENGTH} characters")
    lowered = password.lower()
    if username and username.lower() in lowered:
        problems.append("must not contain the username")
    if any(word in lowered for word in _COMMON):
        problems.append("must not contain a common password")
    if len(set(password)) < 6:
        problems.append("too many repeated characters")
    return problems


@dataclass
class Account:
    name: str
    roles: list[str]
    password_hash: str | None = None
    totp_secret: str | None = None
    mfa_enabled: bool = False
    totp_last_step: int = -1
    disabled: bool = False
    api_key_sha256: str | None = None
    service: bool = False  # service accounts use an API key and cannot sign in to the web interface
    created: str = ""

    def user(self) -> User:
        return User(self.name, tuple(self.roles))

    def public(self) -> dict:
        return {
            "name": self.name,
            "roles": self.roles,
            "mfa_enabled": self.mfa_enabled,
            "disabled": self.disabled,
            "service": self.service,
            "created": self.created,
        }


class UserStore:
    """Accounts kept in a JSON file, written atomically so a crash never leaves it half written."""

    def __init__(self, path: Path | None, accounts: list[Account] | None = None) -> None:
        self.path = path
        self._lock = threading.Lock()
        if accounts is not None:
            self.accounts = {a.name: a for a in accounts}
        elif path and path.exists():
            known = set(Account.__dataclass_fields__)
            entries = json.loads(path.read_text(encoding="utf-8"))
            # Entries from an older version keep their name and roles but have no password: run create_users.py.
            self.accounts = {e["name"]: Account(**{k: v for k, v in e.items() if k in known}) for e in entries}
        else:
            self.accounts = {}

    def get(self, name: str) -> Account | None:
        return self.accounts.get(name)

    def by_api_key(self, key: str | None) -> Account | None:
        if not key:
            return None
        candidate = hash_key(key)
        found = None
        for account in self.accounts.values():  # check every entry: the timing does not reveal a match
            if account.api_key_sha256 and hmac.compare_digest(account.api_key_sha256, candidate):
                found = account
        return found

    def save(self) -> None:
        if not self.path:
            return
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps([asdict(a) for a in self.accounts.values()], indent=1), encoding="utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)

    def add(self, account: Account) -> None:
        if account.name in self.accounts:
            raise ValueError("this username already exists")
        account.created = account.created or time.strftime("%Y-%m-%d")
        self.accounts[account.name] = account
        self.save()


@dataclass
class Session:
    user: str
    created: float
    last_seen: float
    mfa_ok: bool
    pending_secret: str | None = None  # MFA enrollment in progress


@dataclass
class SessionStore:
    idle_seconds: int = 30 * 60
    max_seconds: int = 8 * 3600
    _sessions: dict[str, Session] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @staticmethod
    def _id(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()  # only a hash of the token is kept in memory

    def create(self, user: str, mfa_ok: bool) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._sessions[self._id(token)] = Session(user, now, now, mfa_ok)
        return token

    def get(self, token: str | None) -> Session | None:
        if not token:
            return None
        now = time.time()
        with self._lock:
            session = self._sessions.get(self._id(token))
            if session is None:
                return None
            if now - session.last_seen > self.idle_seconds or now - session.created > self.max_seconds:
                del self._sessions[self._id(token)]
                return None
            session.last_seen = now
            return session

    def delete(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._sessions.pop(self._id(token), None)

    def delete_user(self, user: str) -> None:
        with self._lock:
            for key in [k for k, s in self._sessions.items() if s.user == user]:
                del self._sessions[key]


class LoginGuard:
    """Counts failures per account and per IP address and blocks both for a while."""

    def __init__(self, threshold: int = 5, lock_seconds: int = 900, ip_limit: int = 20) -> None:
        self.threshold = threshold
        self.lock_seconds = lock_seconds
        self.ip_limit = ip_limit
        self._user_failures: dict[str, list[float]] = {}
        self._ip_failures: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def _recent(self, store: dict[str, list[float]], key: str, now: float) -> list[float]:
        recent = [t for t in store.get(key, []) if now - t < self.lock_seconds]
        store[key] = recent
        return recent

    def ip_blocked(self, ip: str | None) -> bool:
        if not ip:
            return False
        with self._lock:
            return len(self._recent(self._ip_failures, ip, time.time())) >= self.ip_limit

    def user_locked(self, user: str) -> bool:
        with self._lock:
            return self._locked_until.get(user, 0) > time.time()

    def failure(self, ip: str | None, user: str | None = None) -> bool:
        """Record a failure. Returns True when this failure locks the account."""
        now = time.time()
        with self._lock:
            if ip:
                self._recent(self._ip_failures, ip, now).append(now)
            if user:
                failures = self._recent(self._user_failures, user, now)
                failures.append(now)
                if len(failures) >= self.threshold:
                    self._locked_until[user] = now + self.lock_seconds
                    self._user_failures[user] = []
                    return True
        return False

    def success(self, user: str) -> None:
        with self._lock:
            self._user_failures.pop(user, None)

    def unlock(self, user: str) -> None:
        with self._lock:
            self._locked_until.pop(user, None)
            self._user_failures.pop(user, None)

    def locked_users(self) -> set[str]:
        now = time.time()
        with self._lock:
            return {u for u, until in self._locked_until.items() if until > now}


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


def generate_password() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
    while True:
        candidate = "-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4))
        if not password_problems(candidate):
            return candidate


def create_demo_accounts(path: Path) -> dict[str, str]:
    """Create the demo accounts. Returns the secrets to show once (passwords and API keys)."""
    people = {"admin": ["admin"], "user1": ["public", "staff"], "user2": ["public", "staff", "security-admin"]}
    services = {"svc-eval-staff": ["public", "staff"], "svc-eval-admin": ["public", "staff", "security-admin"]}
    shown: dict[str, str] = {}
    accounts = []
    for name, roles in people.items():
        password = generate_password()
        shown[name] = password
        accounts.append(Account(name=name, roles=roles, password_hash=hash_password(password)))
    for name, roles in services.items():
        key = "srag_" + secrets.token_urlsafe(24)
        shown[name] = key
        accounts.append(Account(name=name, roles=roles, api_key_sha256=hash_key(key), service=True))
    store = UserStore(path, accounts=[])
    for account in accounts:
        store.add(account)
    return shown
