"""Hybrid search (vector + keyword) with access control applied inside the query.

The role filter runs in the database, before ranking. A chunk the user is not allowed to read is
never returned, so it can never reach the prompt, whatever the question says.

Two implementations share one interface: PgVectorStore (PostgreSQL + pgvector + full-text
search) for real use, and MemoryStore (NumPy + BM25) for tests and quick demos.
"""

import math
from collections import Counter
from typing import Protocol

import numpy as np

from srag.models import Chunk, Hit
from srag.text import keywords

RRF_K = 60


def _fuse(dense: list[tuple[str, float]], lexical: list[str]) -> dict[str, float]:
    fused: dict[str, float] = {}
    for rank, (cid, _) in enumerate(dense, start=1):
        fused[cid] = fused.get(cid, 0.0) + 1.0 / (RRF_K + rank)
    for rank, cid in enumerate(lexical, start=1):
        fused[cid] = fused.get(cid, 0.0) + 1.0 / (RRF_K + rank)
    return fused


class Store(Protocol):
    def reset(self, dim: int) -> None: ...

    def add(self, chunks: list[Chunk], vectors: np.ndarray, doc_hashes: dict[str, str]) -> None: ...

    def search(self, vector: np.ndarray, text: str, roles: tuple[str, ...], k: int, candidates: int) -> list[Hit]: ...

    def doc_hashes(self) -> dict[str, str]: ...

    def documents(self, roles: tuple[str, ...]) -> list[dict]: ...

    def count(self) -> int: ...


class MemoryStore:
    def __init__(self) -> None:
        self.reset(0)

    def reset(self, dim: int) -> None:
        self.chunks: list[Chunk] = []
        self.vectors = np.zeros((0, dim), dtype=np.float32)
        self.hashes: dict[str, str] = {}
        self._tf: list[Counter] = []
        self._df: Counter = Counter()
        self._lengths: list[int] = []

    def add(self, chunks: list[Chunk], vectors: np.ndarray, doc_hashes: dict[str, str]) -> None:
        self.chunks += chunks
        self.vectors = np.vstack([self.vectors, vectors]) if len(self.vectors) else vectors
        self.hashes.update(doc_hashes)
        for chunk in chunks:
            tf = Counter(keywords(chunk.text))
            self._tf.append(tf)
            self._lengths.append(sum(tf.values()))
            self._df.update(tf.keys())

    def _bm25(self, terms: list[str], allowed: list[int], k1: float = 1.5, b: float = 0.75) -> list[str]:
        n = len(self.chunks)
        avg = (sum(self._lengths) / n) if n else 1.0
        scores = []
        for i in allowed:
            s = 0.0
            for term in terms:
                f = self._tf[i].get(term, 0)
                if not f:
                    continue
                idf = math.log(1 + (n - self._df[term] + 0.5) / (self._df[term] + 0.5))
                s += idf * f * (k1 + 1) / (f + k1 * (1 - b + b * self._lengths[i] / avg))
            if s > 0:
                scores.append((s, i))
        scores.sort(reverse=True)
        return [self.chunks[i].id for _, i in scores]

    def search(self, vector, text, roles, k, candidates):
        allowed = [i for i, c in enumerate(self.chunks) if set(c.roles) & set(roles)]
        if not allowed:
            return []
        sims = self.vectors[allowed] @ vector
        order = np.argsort(-sims)[:candidates]
        dense = [(self.chunks[allowed[j]].id, float(sims[j])) for j in order]
        lexical = self._bm25(keywords(text), allowed)[:candidates]
        fused = _fuse(dense, lexical)
        by_id = {c.id: i for i, c in enumerate(self.chunks)}
        hits = []
        for cid, rank_score in sorted(fused.items(), key=lambda x: -x[1])[:k]:
            i = by_id[cid]
            hits.append(Hit(chunk=self.chunks[i], score=float(self.vectors[i] @ vector), rank_score=rank_score))
        return hits

    def doc_hashes(self) -> dict[str, str]:
        return dict(self.hashes)

    def documents(self, roles):
        seen: dict[str, dict] = {}
        for c in self.chunks:
            if set(c.roles) & set(roles) and c.doc_id not in seen:
                seen[c.doc_id] = {"id": c.doc_id, "title": c.title, "source": c.source, "reference": c.reference}
        return list(seen.values())

    def count(self) -> int:
        return len(self.chunks)


class PgVectorStore:
    def __init__(self, url: str) -> None:
        import psycopg
        from pgvector.psycopg import register_vector

        self._conn = psycopg.connect(url, autocommit=True)
        self._conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        register_vector(self._conn)

    def reset(self, dim: int) -> None:
        c = self._conn
        c.execute("DROP TABLE IF EXISTS chunks")
        c.execute(
            f"""CREATE TABLE chunks (
                id text PRIMARY KEY,
                doc_id text NOT NULL,
                ordinal int NOT NULL,
                title text NOT NULL,
                section text NOT NULL,
                source text NOT NULL,
                reference text NOT NULL,
                url text NOT NULL,
                roles text[] NOT NULL,
                text text NOT NULL,
                doc_sha256 text NOT NULL,
                embedding vector({int(dim)}) NOT NULL,
                tsv tsvector GENERATED ALWAYS AS (to_tsvector('english', text)) STORED
            )"""
        )
        if dim <= 2000:  # pgvector HNSW limit; larger test vectors use an exact scan
            c.execute("CREATE INDEX chunks_embedding ON chunks USING hnsw (embedding vector_cosine_ops)")
        c.execute("CREATE INDEX chunks_tsv ON chunks USING gin (tsv)")
        c.execute("CREATE INDEX chunks_roles ON chunks USING gin (roles)")

    def add(self, chunks, vectors, doc_hashes):
        rows = [
            (
                ch.id,
                ch.doc_id,
                ch.ordinal,
                ch.title,
                ch.section,
                ch.source,
                ch.reference,
                ch.url,
                list(ch.roles),
                ch.text,
                doc_hashes[ch.doc_id],
                vec,
            )
            for ch, vec in zip(chunks, vectors, strict=True)
        ]
        with self._conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO chunks (id, doc_id, ordinal, title, section, source, reference, url, roles, text,"
                " doc_sha256, embedding) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                rows,
            )

    def search(self, vector, text, roles, k, candidates):
        terms = keywords(text)
        tsquery = " | ".join(terms) if terms else "zzzznomatch"
        sql = """
        WITH dense AS (
            SELECT id, row_number() OVER (ORDER BY embedding <=> %(q)s) AS r
            FROM chunks WHERE roles && %(roles)s
            ORDER BY embedding <=> %(q)s LIMIT %(n)s
        ), lexical AS (
            SELECT id, row_number() OVER (ORDER BY ts_rank_cd(tsv, query) DESC) AS r
            FROM chunks, to_tsquery('english', %(tsq)s) AS query
            WHERE roles && %(roles)s AND tsv @@ query
            ORDER BY ts_rank_cd(tsv, query) DESC LIMIT %(n)s
        ), fused AS (
            SELECT id, sum(1.0 / (%(rrf)s + r)) AS rrf FROM (
                SELECT id, r FROM dense UNION ALL SELECT id, r FROM lexical
            ) u GROUP BY id
        )
        SELECT c.id, c.doc_id, c.ordinal, c.text, c.title, c.section, c.source, c.reference, c.url, c.roles,
               1 - (c.embedding <=> %(q)s) AS sim, f.rrf
        FROM fused f JOIN chunks c USING (id)
        WHERE c.roles && %(roles)s
        ORDER BY f.rrf DESC LIMIT %(k)s
        """
        with self._conn.cursor() as cur:
            cur.execute("SET hnsw.ef_search = 100")
            cur.execute(
                sql,
                {
                    "q": np.asarray(vector, dtype=np.float32),
                    "roles": list(roles),
                    "n": candidates,
                    "tsq": tsquery,
                    "rrf": RRF_K,
                    "k": k,
                },
            )
            rows = cur.fetchall()
        return [
            Hit(
                chunk=Chunk(
                    id=r[0],
                    doc_id=r[1],
                    ordinal=r[2],
                    text=r[3],
                    title=r[4],
                    section=r[5],
                    source=r[6],
                    reference=r[7],
                    url=r[8],
                    roles=tuple(r[9]),
                ),
                score=float(r[10]),
                rank_score=float(r[11]),
            )
            for r in rows
        ]

    def doc_hashes(self) -> dict[str, str]:
        rows = self._conn.execute("SELECT DISTINCT doc_id, doc_sha256 FROM chunks").fetchall()
        return dict(rows)

    def documents(self, roles):
        rows = self._conn.execute(
            "SELECT DISTINCT ON (doc_id) doc_id, title, source, reference FROM chunks "
            "WHERE roles && %s ORDER BY doc_id",
            (list(roles),),
        ).fetchall()
        return [{"id": r[0], "title": r[1], "source": r[2], "reference": r[3]} for r in rows]

    def count(self) -> int:
        return self._conn.execute("SELECT count(*) FROM chunks").fetchone()[0]


def make_store(database_url: str | None) -> Store:
    return PgVectorStore(database_url) if database_url else MemoryStore()
