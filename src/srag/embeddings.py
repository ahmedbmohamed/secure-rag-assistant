"""Text embeddings computed on this machine.

FastEmbedEmbedder runs BAAI/bge-small-en-v1.5 with ONNX Runtime on the CPU. The model is
downloaded once (the Docker image does it at build time) and then works offline.
HashingEmbedder needs no model at all. It is a deterministic bag of words used by the tests.
"""

import hashlib
from typing import Protocol

import numpy as np

from srag.text import keywords


class Embedder(Protocol):
    name: str
    dim: int

    def embed_documents(self, texts: list[str]) -> np.ndarray: ...

    def embed_query(self, text: str) -> np.ndarray: ...


def _normalize(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return (matrix / norms).astype(np.float32)


class HashingEmbedder:
    def __init__(self, dim: int = 4096) -> None:
        self.dim = dim
        self.name = f"hashing-{dim}"

    def _vector(self, text: str) -> np.ndarray:
        tokens = keywords(text)
        features = tokens + [f"{a} {b}" for a, b in zip(tokens, tokens[1:], strict=False)]
        vec = np.zeros(self.dim, dtype=np.float32)
        for feature in features:
            h = int.from_bytes(hashlib.blake2b(feature.encode(), digest_size=8).digest(), "little")
            vec[h % self.dim] += 1.0 if (h >> 32) & 1 else -1.0
        return vec

    def embed_documents(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        return _normalize(np.stack([self._vector(t) for t in texts]))

    def embed_query(self, text: str) -> np.ndarray:
        return self.embed_documents([text])[0]


class FastEmbedEmbedder:
    def __init__(self, model_name: str = "BAAI/bge-small-en-v1.5", cache_dir: str | None = None) -> None:
        from fastembed import TextEmbedding

        self._model = TextEmbedding(model_name=model_name, cache_dir=cache_dir)
        self.name = model_name
        self.dim = len(next(iter(self._model.embed(["probe"]))))

    def embed_documents(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        return _normalize(np.array(list(self._model.passage_embed(texts)), dtype=np.float32))

    def embed_query(self, text: str) -> np.ndarray:
        return _normalize(np.array(list(self._model.query_embed([text])), dtype=np.float32))[0]


def make_embedder(kind: str, model_name: str, cache_dir=None) -> Embedder:
    if kind == "hashing":
        return HashingEmbedder()
    return FastEmbedEmbedder(model_name, str(cache_dir) if cache_dir else None)
