"""Append-only audit log in JSON lines, ready to be collected by a SIEM (see deploy/wazuh).

Questions are stored masked, with a SHA-256 of the original, so the log can prove what was asked
without becoming a copy of the sensitive data itself.
"""

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path

from srag.guards.pii import mask


class AuditLog:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.events: list[dict] = []  # kept in memory too, for tests and the health endpoint
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)

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
            self.events.append(record)
            if len(self.events) > 1000:
                self.events = self.events[-1000:]
            if self.path:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record
