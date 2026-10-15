"""Signed manifest of the indexed documents.

At ingestion, the SHA-256 of every document and the name of the embedding model are written to
a manifest signed with an HMAC key. At startup the API recomputes what the database holds and
compares it with the manifest. A document added, removed or modified directly in the database
(without the key) is detected and the service refuses to start.
"""

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class IntegrityReport:
    ok: bool
    problems: list[str]


def _signature(payload: dict, key: str) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key.encode(), body, hashlib.sha256).hexdigest()


def write_manifest(path: Path, doc_hashes: dict[str, str], embed_model: str, quarantined: list[str], key: str) -> dict:
    payload = {
        "documents": dict(sorted(doc_hashes.items())),
        "embed_model": embed_model,
        "quarantined": sorted(quarantined),
    }
    manifest = {**payload, "signature": _signature(payload, key)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest


def verify(path: Path, stored_hashes: dict[str, str], embed_model: str, key: str) -> IntegrityReport:
    if not path.exists():
        return IntegrityReport(False, ["manifest not found, run the ingestion first"])
    manifest = json.loads(path.read_text(encoding="utf-8"))
    signature = manifest.pop("signature", "")
    if not hmac.compare_digest(signature, _signature(manifest, key)):
        return IntegrityReport(False, ["manifest signature is invalid (manifest modified or wrong key)"])
    problems = []
    if manifest["embed_model"] != embed_model:
        problems.append(f"index built with {manifest['embed_model']}, service configured with {embed_model}")
    expected = manifest["documents"]
    for doc_id in sorted(set(expected) - set(stored_hashes)):
        problems.append(f"missing document: {doc_id}")
    for doc_id in sorted(set(stored_hashes) - set(expected)):
        problems.append(f"unexpected document: {doc_id}")
    for doc_id in sorted(set(expected) & set(stored_hashes)):
        if expected[doc_id] != stored_hashes[doc_id]:
            problems.append(f"modified document: {doc_id}")
    return IntegrityReport(not problems, problems)
