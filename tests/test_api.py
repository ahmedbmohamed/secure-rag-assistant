import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from srag.integrity import IntegrityReport
from srag.service import Service
from tests.conftest import KEYS


@pytest.fixture
def client(assistant, users, settings):
    service = Service(assistant=assistant, integrity=IntegrityReport(True, []), settings=settings)
    app = create_app(service=service, users=users, audit=assistant.audit)
    with TestClient(app) as c:
        yield c


def auth(user="user1"):
    return {"X-API-Key": KEYS[user]}


def test_health_is_public(client):
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["mode"] == "local" and body["integrity"] == "ok"


def test_key_required(client, assistant):
    assert client.post("/ask", json={"question": "How to prevent injection?"}).status_code == 401
    assert (
        client.post("/ask", json={"question": "How to prevent injection?"}, headers={"X-API-Key": "wrong"}).status_code
        == 401
    )
    assert assistant.audit.events[-1]["event"] == "auth_failed"


def test_ask(client):
    r = client.post("/ask", json={"question": "How do I prevent SQL injection?"}, headers=auth())
    assert r.status_code == 200
    body = r.json()
    assert body["refused"] is False
    assert body["sources"][0]["label"] == "S1"
    assert body["sources"][0]["source"] in {"owasp", "nist", "internal"}


def test_input_validation(client):
    assert client.post("/ask", json={"question": ""}, headers=auth()).status_code == 422
    assert client.post("/ask", json={"question": "x" * 2001}, headers=auth()).status_code == 422


def test_documents_depend_on_role(client):
    staff = {d["id"] for d in client.get("/documents", headers=auth("user1")).json()}
    admin = {d["id"] for d in client.get("/documents", headers=auth("user2")).json()}
    assert "internal-demo-bank-incident-runbook" in admin - staff


def test_rate_limit(client, settings):
    for _ in range(settings.rate_limit_per_minute):
        assert client.get("/me", headers=auth()).status_code == 200
    assert client.get("/me", headers=auth()).status_code == 429
    assert client.get("/me", headers=auth("user2")).status_code == 200  # limits are per user


def test_llm_outage_returns_503(client, model):
    model.fail = True
    r = client.post("/ask", json={"question": "How do I prevent SQL injection?"}, headers=auth())
    assert r.status_code == 503
    assert "not sent to any other provider" in r.json()["detail"]
