"""Plain data types shared by every module."""

import hashlib
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Document:
    id: str
    title: str
    text: str
    source: str  # owasp, nist, internal
    reference: str = ""  # clause or control id, e.g. "A05:2025" or "AC-2"
    url: str = ""
    roles: tuple[str, ...] = ("public",)
    classification: str = "public"

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Chunk:
    id: str
    doc_id: str
    ordinal: int
    text: str
    title: str
    section: str
    source: str
    reference: str
    url: str
    roles: tuple[str, ...]


@dataclass(frozen=True)
class Hit:
    chunk: Chunk
    score: float  # dense cosine similarity
    rank_score: float  # fused rank (reciprocal rank fusion)


@dataclass(frozen=True)
class User:
    name: str
    roles: tuple[str, ...]


@dataclass(frozen=True)
class Source:
    label: str  # "S1", "S2"... as cited in the answer
    chunk: Chunk
    score: float


@dataclass
class Answer:
    text: str
    sources: list[Source] = field(default_factory=list)
    refused: bool = False
    reason: str | None = None
    mode: str = "local"
    masked_entities: int = 0
    latency_ms: int = 0
