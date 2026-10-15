"""Build the assistant from the settings, with the startup security checks."""

from dataclasses import dataclass

from srag.audit import AuditLog
from srag.config import Settings
from srag.embeddings import make_embedder
from srag.ingest.loaders import load_all
from srag.ingest.pipeline import ingest
from srag.integrity import IntegrityReport, verify
from srag.llm import make_llm, ollama_model_digest
from srag.rag import Assistant
from srag.store import MemoryStore, make_store


class StartupCheckFailed(RuntimeError):
    pass


@dataclass
class Service:
    assistant: Assistant
    integrity: IntegrityReport
    settings: Settings


def build_service(settings: Settings, audit: AuditLog | None = None) -> Service:
    audit = audit or AuditLog(settings.audit_log)
    embedder = make_embedder(settings.embedder, settings.embed_model, settings.embed_cache_dir)
    store = make_store(settings.database_url)
    if isinstance(store, MemoryStore):
        # Demo mode without a database: index in memory at startup.
        ingest(load_all(settings.data_dir), store, embedder, settings)

    report = verify(settings.manifest_path, store.doc_hashes(), embedder.name, settings.manifest_key)
    if not report.ok:
        audit.write("integrity_failed", problems=report.problems)
        raise StartupCheckFailed("Index integrity check failed: " + "; ".join(report.problems))

    if settings.llm_mode == "local" and settings.ollama_model_digest:
        digest = ollama_model_digest(settings.ollama_url, settings.ollama_model)
        if digest != settings.ollama_model_digest:
            audit.write("integrity_failed", problems=[f"model digest {digest} does not match the pinned digest"])
            raise StartupCheckFailed("The LLM served by Ollama is not the pinned model.")

    assistant = Assistant(
        store=store,
        embedder=embedder,
        llm=make_llm(settings),
        audit=audit,
        top_k=settings.top_k,
        candidates=settings.candidates,
        min_score=settings.effective_min_score,
        injection_threshold=settings.injection_threshold,
    )
    audit.write("startup", mode=settings.llm_mode, model=assistant.llm.name, documents=len(store.doc_hashes()))
    return Service(assistant=assistant, integrity=report, settings=settings)
