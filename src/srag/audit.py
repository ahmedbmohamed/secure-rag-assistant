"""Append-only audit log in JSON lines, chained with SHA-256, ready for a SIEM (see deploy/wazuh).

Each line stores the hash of the previous line. Deleting, reordering or editing a line breaks the
chain, and `python -m srag.audit logs/audit.jsonl` shows where. Questions are stored masked, with a
SHA-256 of the original, so the log can prove what was asked without becoming a copy of the
sensitive data itself.

The chain makes tampering visible. It cannot stop an administrator from rewriting the whole file,
which is why the log should also be forwarded to the SIEM as it is written.
"""

import hashlib
import json
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

from srag.guards.pii import mask

GENESIS = "0" * 64


def _digest(previous: str, record: dict) -> str:
    body = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256((previous + body).encode("utf-8")).hexdigest()


def _last_hash(path: Path) -> str:
    if not path.exists() or path.stat().st_size == 0:
        return GENESIS
    with path.open("rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 65536))
        lines = [line for line in f.read().splitlines() if line.strip()]
    try:
        return json.loads(lines[-1]).get("hash", GENESIS)
    except (json.JSONDecodeError, IndexError):
        return GENESIS


class AuditLog:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.events: list[dict] = []  # kept in memory too, for tests and the admin page
        self._previous = GENESIS
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._previous = _last_hash(path)

    def write(self, event: str, user: str | None = None, question: str | None = None, **fields) -> dict:
        record = {
            "ts": datetime.now(UTC).isoformat(timespec="seconds"),
            "app": "secure-rag",
            "event": event,
            "user": user,
        }
        if question is not None:
            record["question"] = mask(question).text
            record["question_sha256"] = hashlib.sha256(question.encode()).hexdigest()
        record.update(fields)
        with self._lock:
            record["prev"] = self._previous
            record["hash"] = _digest(self._previous, {k: v for k, v in record.items() if k != "hash"})
            self._previous = record["hash"]
            self.events.append(record)
            if len(self.events) > 5000:
                self.events = self.events[-5000:]
            if self.path:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record


def verify_chain(path: Path) -> list[str]:
    """Return the problems found, an empty list when the chain is intact."""
    problems = []
    previous = None
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            problems.append(f"line {number}: not valid JSON")
            previous = None
            continue
        stored = record.get("hash")
        expected = _digest(record.get("prev", ""), {k: v for k, v in record.items() if k != "hash"})
        if stored != expected:
            problems.append(f"line {number}: content modified")
        if previous is not None and record.get("prev") != previous:
            problems.append(f"line {number}: chain broken (a line was removed, inserted or reordered before it)")
        previous = stored
    return problems


if __name__ == "__main__":
    log = Path(sys.argv[1] if len(sys.argv) > 1 else "logs/audit.jsonl")
    found = verify_chain(log)
    if found:
        print("Audit log TAMPERED:", *found, sep="\n  ")
        sys.exit(1)
    print(f"Audit log intact: {log}")
