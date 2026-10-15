"""Offline evaluation of retrieval, refusal and injection detection. No LLM needed.

    python eval/run_eval.py            # print and write reports/eval.json
    python eval/run_eval.py --gate     # also fail (exit 1) if a metric is below eval/gates.json

Metrics
- hit@5: the expected document is among the 5 chunks given to the LLM
- MRR@5: mean reciprocal rank of the first expected document
- out-of-scope rejection: off-topic questions refused by the relevance threshold
- in-scope false rejection: real questions wrongly refused by that threshold
- injection precision and recall on a labelled set of attacks and normal questions
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np

from srag.config import HOME, get_settings
from srag.embeddings import make_embedder
from srag.guards.injection import scan
from srag.ingest.loaders import load_all
from srag.ingest.pipeline import ingest
from srag.models import User
from srag.store import MemoryStore, make_store

EVAL = Path(__file__).resolve().parent
ADMIN = User("eval", ("public", "staff", "security-admin"))


def read_jsonl(name: str) -> list[dict]:
    return [json.loads(line) for line in (EVAL / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gate", action="store_true")
    parser.add_argument("--reindex", action="store_true", help="index into the configured database first")
    args = parser.parse_args()

    settings = get_settings()
    embedder = make_embedder(settings.embedder, settings.embed_model, settings.embed_cache_dir)
    store = make_store(settings.database_url)
    if isinstance(store, MemoryStore) or args.reindex:
        ingest(load_all(settings.data_dir), store, embedder, settings)

    def search(q: str):
        return store.search(embedder.embed_query(q), q, ADMIN.roles, settings.top_k, settings.candidates)

    hits5, rr, in_scores, misses = [], [], [], []
    for row in read_jsonl("retrieval.jsonl"):
        hits = search(row["question"])
        ids = [h.chunk.doc_id for h in hits]
        rank = next((i + 1 for i, d in enumerate(ids) if d in row["expected"]), None)
        hits5.append(rank is not None)
        rr.append(1.0 / rank if rank else 0.0)
        in_scores.append(max((h.score for h in hits), default=0.0))
        if rank is None:
            misses.append({"question": row["question"], "expected": row["expected"], "got": ids})

    out_scores = [max((h.score for h in search(r["question"])), default=0.0) for r in read_jsonl("out_of_scope.jsonl")]
    threshold = settings.effective_min_score

    labels, preds = [], []
    for row in read_jsonl("injection.jsonl"):
        labels.append(row["label"])
        preds.append(int(scan(row["text"], settings.injection_threshold).flagged))
    tp = sum(1 for y, p in zip(labels, preds, strict=True) if y and p)
    fp = sum(1 for y, p in zip(labels, preds, strict=True) if not y and p)
    fn = sum(1 for y, p in zip(labels, preds, strict=True) if y and not p)

    metrics = {
        "embedder": embedder.name,
        "questions": len(hits5),
        "hit_at_5": round(float(np.mean(hits5)), 3),
        "mrr_at_5": round(float(np.mean(rr)), 3),
        "min_score": threshold,
        "out_of_scope_rejection": round(float(np.mean([s < threshold for s in out_scores])), 3),
        "in_scope_false_rejection": round(float(np.mean([s < threshold for s in in_scores])), 3),
        "score_in_scope_min": round(float(min(in_scores)), 3),
        "score_out_of_scope_max": round(float(max(out_scores)), 3),
        "injection_precision": round(tp / (tp + fp), 3) if tp + fp else 0.0,
        "injection_recall": round(tp / (tp + fn), 3) if tp + fn else 0.0,
        "retrieval_misses": misses,
    }
    out = HOME / "reports" / "eval.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(metrics, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: v for k, v in metrics.items() if k != "retrieval_misses"}, indent=1))
    for miss in misses:
        print("MISS", miss["question"], "->", miss["got"][:3])

    if args.gate:
        gates = json.loads((EVAL / "gates.json").read_text())
        failed = []
        for name, rule in gates.items():
            value = metrics[name]
            if ("min" in rule and value < rule["min"]) or ("max" in rule and value > rule["max"]):
                failed.append(f"{name}={value} (rule {rule})")
        if failed:
            print("QUALITY GATE FAILED:", *failed, sep="\n  ")
            return 1
        print("Quality gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
