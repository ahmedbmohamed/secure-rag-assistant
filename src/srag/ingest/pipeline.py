"""Ingestion: load, chunk, scan for injected instructions, embed, index, sign the manifest.

python -m srag.ingest.pipeline
"""

import argparse
import json
import time
from dataclasses import dataclass, field

from srag.config import Settings, get_settings
from srag.embeddings import Embedder, make_embedder
from srag.guards import injection
from srag.ingest.chunking import chunk_document
from srag.ingest.loaders import load_all
from srag.integrity import write_manifest
from srag.models import Chunk, Document
from srag.store import Store, make_store


@dataclass
class IngestReport:
    documents: int = 0
    chunks: int = 0
    quarantined_documents: list[str] = field(default_factory=list)
    quarantined_chunks: list[dict] = field(default_factory=list)
    seconds: float = 0.0


def ingest(docs: list[Document], store: Store, embedder: Embedder, settings: Settings) -> IngestReport:
    started = time.perf_counter()
    report = IngestReport()
    kept: list[Chunk] = []
    hashes: dict[str, str] = {}

    for doc in docs:
        chunks = chunk_document(doc, settings.chunk_size, settings.chunk_overlap)
        flagged = []
        for chunk in chunks:
            result = injection.scan(chunk.text, settings.injection_threshold)
            if result.flagged:
                flagged.append({"chunk": chunk.id, "score": result.score, "rules": result.rules})
        if flagged:
            # One poisoned chunk makes the whole document suspect: nothing from it is indexed.
            report.quarantined_documents.append(doc.id)
            report.quarantined_chunks += flagged
            continue
        kept += chunks
        hashes[doc.id] = doc.sha256

    vectors = embedder.embed_documents([c.text for c in kept])
    store.reset(embedder.dim)
    batch = 256
    for start in range(0, len(kept), batch):
        store.add(kept[start : start + batch], vectors[start : start + batch], hashes)

    write_manifest(settings.manifest_path, hashes, embedder.name, report.quarantined_documents, settings.manifest_key)
    report.documents = len(hashes)
    report.chunks = len(kept)
    report.seconds = round(time.perf_counter() - started, 1)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Index the documents")
    parser.parse_args()
    settings = get_settings()
    docs = load_all(settings.data_dir)
    embedder = make_embedder(settings.embedder, settings.embed_model, settings.embed_cache_dir)
    store = make_store(settings.database_url)
    report = ingest(docs, store, embedder, settings)
    print(json.dumps(report.__dict__, indent=1))


if __name__ == "__main__":
    main()
