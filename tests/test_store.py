import pytest

from tests.conftest import USER1, USER2


def _search(store, embedder, question, user, k=5):
    return store.search(embedder.embed_query(question), question, user.roles, k, 20)


@pytest.fixture(params=["memory", "pgvector"])
def any_store(request, store):
    if request.param == "memory":
        return store
    return request.getfixturevalue("pg_store")


def test_relevant_control_is_found(any_store, embedder):
    hits = _search(any_store, embedder, "account management review of user accounts", USER1)
    assert "nist-ac-2" in [h.chunk.doc_id for h in hits]


def test_owasp_category_is_found(any_store, embedder):
    hits = _search(any_store, embedder, "How to prevent SQL injection with parameterized queries", USER1)
    assert hits[0].chunk.doc_id == "owasp-a05"


def test_restricted_document_is_invisible_without_role(any_store, embedder):
    question = "incident runbook on-call contacts ransomware escalation severity"
    staff = _search(any_store, embedder, question, USER1, k=20)
    admin = _search(any_store, embedder, question, USER2, k=20)
    assert all(h.chunk.doc_id != "internal-demo-bank-incident-runbook" for h in staff)
    assert any(h.chunk.doc_id == "internal-demo-bank-incident-runbook" for h in admin)


def test_document_list_respects_roles(any_store):
    staff = {d["id"] for d in any_store.documents(USER1.roles)}
    admin = {d["id"] for d in any_store.documents(USER2.roles)}
    assert "internal-demo-bank-incident-runbook" not in staff
    assert "internal-demo-bank-incident-runbook" in admin
    assert "internal-demo-bank-security-policy" in staff


def test_no_roles_no_results(any_store, embedder):
    from srag.models import User

    assert _search(any_store, embedder, "password policy", User("nobody", ("guest",))) == []


def test_scores_are_cosine_similarities(any_store, embedder):
    hits = _search(any_store, embedder, "multi-factor authentication for remote access", USER1)
    assert all(-1.0 <= h.score <= 1.0 for h in hits)
    assert hits == sorted(hits, key=lambda h: -h.rank_score)
