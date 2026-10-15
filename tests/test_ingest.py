import json

from srag.ingest.chunking import chunk_document
from srag.ingest.pipeline import ingest
from srag.integrity import verify
from srag.store import MemoryStore


def test_collections_are_loaded(docs):
    by_source = {s: [d for d in docs if d.source == s] for s in ("owasp", "nist", "internal")}
    assert len(by_source["owasp"]) == 10
    assert len(by_source["nist"]) >= 100
    assert len(by_source["internal"]) == 3
    runbook = next(d for d in docs if d.id == "internal-demo-bank-incident-runbook")
    assert runbook.roles == ("security-admin",)


def test_owasp_noise_is_removed(docs):
    a05 = next(d for d in docs if d.id == "owasp-a05")
    assert a05.reference == "A05:2025"
    assert "<table>" not in a05.text
    assert "List of Mapped CWEs" not in a05.text
    assert "## How to prevent" in a05.text


def test_chunks_carry_their_origin(docs):
    ac2 = next(d for d in docs if d.id == "nist-ac-2")
    chunks = chunk_document(ac2)
    assert chunks[0].text.startswith("[NIST SP 800-53 AC-2 Account Management | Control statement]")
    assert all(len(c.text) <= 1000 for c in chunks)
    assert len({c.id for c in chunks}) == len(chunks)


def test_poisoned_document_is_quarantined(store, settings):
    manifest = json.loads(settings.manifest_path.read_text())
    assert manifest["quarantined"] == ["internal-vendor-integration-note"]
    assert all(c.doc_id != "internal-vendor-integration-note" for c in store.chunks)


def test_manifest_matches_index(store, embedder, settings):
    report = verify(settings.manifest_path, store.doc_hashes(), embedder.name, settings.manifest_key)
    assert report.ok, report.problems


def test_tampering_is_detected(store, embedder, settings):
    hashes = store.doc_hashes()
    modified = {**hashes, "owasp-a05": "0" * 64}
    report = verify(settings.manifest_path, modified, embedder.name, settings.manifest_key)
    assert not report.ok and "modified document: owasp-a05" in report.problems

    missing = {k: v for k, v in hashes.items() if k != "nist-ac-2"}
    assert "missing document: nist-ac-2" in verify(settings.manifest_path, missing, embedder.name, "test-key").problems

    extra = {**hashes, "internal-planted": "1" * 64}
    assert (
        "unexpected document: internal-planted"
        in verify(settings.manifest_path, extra, embedder.name, "test-key").problems
    )

    assert not verify(settings.manifest_path, hashes, embedder.name, "wrong-key").ok
    assert not verify(settings.manifest_path, hashes, "another-model", "test-key").ok


def test_edited_manifest_is_rejected(store, embedder, settings):
    manifest = json.loads(settings.manifest_path.read_text())
    manifest["documents"]["owasp-a05"] = "0" * 64
    settings.manifest_path.write_text(json.dumps(manifest))
    report = verify(settings.manifest_path, store.doc_hashes(), embedder.name, settings.manifest_key)
    assert not report.ok
    assert "signature" in report.problems[0]


def test_reingest_replaces_index(docs, embedder, settings):
    s = MemoryStore()
    ingest(docs, s, embedder, settings)
    first = s.count()
    ingest(docs, s, embedder, settings)
    assert s.count() == first
