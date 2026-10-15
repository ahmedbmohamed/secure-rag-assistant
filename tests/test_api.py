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
    assert body["status"] == "ok" and body["mode"] == "local" and body["integrity"] == "verified"


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


def test_web_interface_is_served_with_security_headers(client):
    page = client.get("/")
    assert page.status_code == 200 and "Secure RAG Assistant" in page.text
    csp = page.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert page.headers["x-frame-options"] == "DENY"
    script = client.get("/static/app.js")
    assert script.status_code == 200 and "textContent" in script.text
    assert "innerHTML" not in script.text.replace("never innerHTML", "")


def test_api_responses_are_not_cached(client):
    r = client.post("/ask", json={"question": "How do I prevent SQL injection?"}, headers=auth())
    assert r.headers["cache-control"] == "no-store"


def test_health_shows_when_the_llm_is_down(client, model, assistant):
    assert client.get("/health").json()["llm"] == "up"
    model.fail = True
    client.post("/ask", json={"question": "How do I prevent SQL injection?"}, headers=auth())
    assert client.get("/health").json()["llm"] == "down"
    model.fail = False
    client.post("/ask", json={"question": "How do I prevent SQL injection?"}, headers=auth())
    assert client.get("/health").json()["llm"] == "up"


def test_llm_status_uses_the_ping_when_there_is_one():
    from srag.llm import ChatLLM
    from tests.conftest import ScriptedChatModel

    answers = [True, False]
    llm = ChatLLM(ScriptedChatModel(prompts=[]), "scripted", "local", ping=lambda: answers.pop(0))
    assert llm.available() is True
    llm._checked = 0  # cache expired
    assert llm.available() is False
