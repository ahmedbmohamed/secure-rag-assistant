import os
from pathlib import Path

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from srag.audit import AuditLog
from srag.auth import UserDirectory, hash_key
from srag.config import Settings
from srag.embeddings import HashingEmbedder
from srag.ingest.loaders import load_all
from srag.ingest.pipeline import ingest
from srag.llm import ChatLLM
from srag.models import User
from srag.rag import Assistant
from srag.store import MemoryStore, PgVectorStore

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

USER1 = User("user1", ("public", "staff"))
USER2 = User("user2", ("public", "staff", "security-admin"))
KEYS = {"user1": "key-user1", "user2": "key-user2"}


class ScriptedChatModel(BaseChatModel):
    """Returns a fixed reply (or raises) and records every prompt it receives."""

    reply: str = "Use parameterized queries [S1]."
    fail: bool = False
    prompts: list = []

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.prompts.append([m.content for m in messages])
        if self.fail:
            raise ConnectionError("connection refused")
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=self.reply))])


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        data_dir=DATA,
        embedder="hashing",
        manifest_path=tmp_path / "manifest.json",
        manifest_key="test-key",
        audit_log=tmp_path / "audit.jsonl",
        users_file=tmp_path / "users.json",
        ollama_url="http://localhost:11434",
    )


@pytest.fixture(scope="session")
def docs():
    return load_all(DATA)


@pytest.fixture
def embedder():
    return HashingEmbedder()


@pytest.fixture
def store(docs, embedder, settings):
    s = MemoryStore()
    ingest(docs, s, embedder, settings)
    return s


@pytest.fixture
def model():
    return ScriptedChatModel(prompts=[])


@pytest.fixture
def audit(settings):
    return AuditLog(settings.audit_log)


@pytest.fixture
def assistant(store, embedder, model, audit, settings):
    return Assistant(
        store=store,
        embedder=embedder,
        llm=ChatLLM(model, "scripted", "local"),
        audit=audit,
        min_score=settings.effective_min_score,
    )


@pytest.fixture
def users():
    return UserDirectory(
        [
            {"name": USER1.name, "roles": list(USER1.roles), "key_sha256": hash_key(KEYS["user1"])},
            {"name": USER2.name, "roles": list(USER2.roles), "key_sha256": hash_key(KEYS["user2"])},
        ]
    )


@pytest.fixture
def pg_url():
    url = os.environ.get("SRAG_TEST_DATABASE_URL")
    if not url:
        pytest.skip("SRAG_TEST_DATABASE_URL not set")
    return url


@pytest.fixture
def pg_store(pg_url, docs, embedder, settings):
    s = PgVectorStore(pg_url)
    ingest(docs, s, embedder, settings)
    return s
