import json

import pytest

from srag.ingest.chunking import chunk_document
from srag.ingest.pipeline import ingest
from srag.integrity import verify
from srag.store import MemoryStore


def test_collections_are_loaded(docs):
    by_source = {s: [d for d in docs if d.source == s] for s in ("owasp", "nist", "internal")}
    assert len(by_source["owasp"]) == 10
    assert len(by_source["nist"]) >= 100
    assert len(by_source["internal"]) == 6  # 3 Markdown, 1 PDF, 1 Word, 1 Excel
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


def test_pdf_word_excel_are_read_with_their_roles(docs):
    by_id = {d.id: d for d in docs}
    pdf = by_id["internal-demo-bank-backup-policy-pdf"]
    assert "RPO" in pdf.text and pdf.roles == ("staff", "security-admin")
    word = by_id["internal-demo-bank-access-review-procedure-docx"]
    assert "# Demo Bank Access Review Procedure" in word.text
    assert "System type: Administrator accounts | Review frequency: Every month" in word.text  # table row
    excel = by_id["internal-demo-bank-vendor-risk-register-xlsx"]
    assert "Vendor: Vendor 1 | Service: Card payment processing" in excel.text
    assert "## Sheet: Risk scale" in excel.text
    assert excel.roles == ("security-admin",) and excel.classification == "confidential"


def test_unlabelled_unsupported_and_dangerous_files(tmp_path):
    import zipfile

    from srag.ingest import files
    from srag.ingest.loaders import load_internal

    (tmp_path / "notes.md").write_text("# Notes\n\nNo front matter, so no roles were given for this file.")
    (tmp_path / "script.exe").write_bytes(b"MZ")
    (tmp_path / "broken.docx").write_bytes(b"not a zip")
    with zipfile.ZipFile(tmp_path / "bomb.xlsx", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("xl/huge.xml", b"0" * (files.MAX_UNZIPPED_BYTES + 1))
    skipped: list[dict] = []
    docs = load_internal(tmp_path, skipped)
    reasons = {s["file"]: s["reason"] for s in skipped}
    assert [d.id for d in docs] == ["internal-notes"]
    assert docs[0].roles == ("security-admin",)  # deny by default
    assert "no roles given" in reasons["notes.md"]
    assert "unsupported format" in reasons["script.exe"]
    assert "not a valid Office file" in reasons["broken.docx"]
    assert "zip bomb" in reasons["bomb.xlsx"]


def test_scanned_pdf_without_text_is_reported(tmp_path):
    from reportlab.pdfgen import canvas

    from srag.ingest.files import UnreadableFile, pdf_to_markdown

    path = tmp_path / "scan.pdf"
    c = canvas.Canvas(str(path))
    c.rect(100, 100, 200, 200, fill=1)  # a drawing, no text layer
    c.save()
    with pytest.raises(UnreadableFile, match="OCR"):
        pdf_to_markdown(path)
