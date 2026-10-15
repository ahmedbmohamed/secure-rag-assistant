import json
import time

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from srag import totp
from srag.audit import AuditLog, verify_chain
from srag.auth import LoginGuard, SessionStore, hash_password, password_problems, verify_password
from srag.integrity import IntegrityReport
from srag.service import Service
from tests.conftest import KEYS, PASSWORDS


@pytest.fixture
def app_client(assistant, users, settings):
    service = Service(assistant=assistant, integrity=IntegrityReport(True, []), settings=settings)
    with TestClient(create_app(service=service, users=users, audit=assistant.audit)) as c:
        yield c


def sign_in(client, username, password):
    """First sign-in of an account: password, then MFA enrollment with the authenticator secret."""
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.json() == {"status": "mfa_setup"}, r.text
    secret = client.get("/auth/mfa/setup").json()["secret"]
    code = totp.code_at(secret, totp.current_step())
    r = client.post("/auth/mfa", json={"code": code})
    assert r.status_code == 200, r.text
    return secret


# ---------- building blocks ----------
def test_password_hashing():
    stored = hash_password("Correct-Horse-Battery-71")
    assert stored.startswith("pbkdf2_sha256$")
    assert verify_password("Correct-Horse-Battery-71", stored)
    assert not verify_password("correct-horse-battery-71", stored)
    assert not verify_password("anything", None)
    assert hash_password("same-password-here") != hash_password("same-password-here")  # random salt


def test_password_policy():
    assert password_problems("short1!") != []
    assert "must not contain the username" in password_problems("alice-is-the-best-2026", "alice")
    assert "must not contain a common password" in password_problems("MyPassword-is-long-1", "bob")
    assert password_problems("Correct-Horse-Battery-71", "alice") == []


def test_totp_rfc_vector_and_replay():
    import base64

    secret = base64.b32encode(b"12345678901234567890").decode()
    assert totp.code_at(secret, 1) == "287082"  # RFC 6238, T=59 s, last 6 digits
    s = totp.generate_secret()
    step = totp.current_step()
    assert totp.verify(s, totp.code_at(s, step)) == step
    assert totp.verify(s, totp.code_at(s, step), last_used_step=step) is None  # no replay
    assert totp.verify(s, "12345") is None


def test_lockout_and_ip_block():
    guard = LoginGuard(threshold=3, lock_seconds=60, ip_limit=5)
    assert not guard.failure("10.0.0.1", "bob")
    assert not guard.failure("10.0.0.1", "bob")
    assert guard.failure("10.0.0.1", "bob")  # third failure locks
    assert guard.user_locked("bob")
    guard.unlock("bob")
    assert not guard.user_locked("bob")
    for _ in range(2):
        guard.failure("10.0.0.1")
    assert guard.ip_blocked("10.0.0.1")
    assert not guard.ip_blocked("10.0.0.2")


def test_session_expiry():
    store = SessionStore(idle_seconds=1, max_seconds=60)
    token = store.create("alice", mfa_ok=True)
    assert store.get(token).user == "alice"
    time.sleep(1.1)
    assert store.get(token) is None


def test_audit_chain_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(3):
        log.write("ask", "alice", question=f"question {i}")
    assert verify_chain(path) == []
    AuditLog(path).write("ask", "alice", question="after restart")  # the chain continues across restarts
    assert verify_chain(path) == []

    lines = path.read_text().splitlines()
    edited = json.loads(lines[1])
    edited["user"] = "mallory"
    path.write_text("\n".join([lines[0], json.dumps(edited), *lines[2:]]) + "\n")
    assert any("content modified" in p for p in verify_chain(path))

    path.write_text("\n".join([lines[0], *lines[2:]]) + "\n")  # a line removed
    assert any("chain broken" in p for p in verify_chain(path))


# ---------- sign-in flow ----------
def test_first_sign_in_enrolls_mfa_then_asks(app_client, users):
    assert app_client.get("/me").status_code == 401
    r = app_client.post("/auth/login", json={"username": "alice", "password": PASSWORDS["alice"]})
    assert r.json() == {"status": "mfa_setup"}
    cookie = r.cookies.get("srag_session")
    assert "httponly" in r.headers["set-cookie"].lower() and "samesite=strict" in r.headers["set-cookie"].lower()
    assert app_client.get("/me").status_code == 401  # password alone is not enough
    assert app_client.get("/auth/mfa/qr.svg").headers["content-type"].startswith("image/svg")
    secret = app_client.get("/auth/mfa/setup").json()["secret"]

    assert app_client.post("/auth/mfa", json={"code": "000000"}).status_code == 401
    r = app_client.post("/auth/mfa", json={"code": totp.code_at(secret, totp.current_step())})
    assert r.status_code == 200
    assert r.cookies.get("srag_session") != cookie  # new session token after sign-in
    assert users.get("alice").mfa_enabled
    assert app_client.get("/me").json()["name"] == "alice"
    assert app_client.post("/ask", json={"question": "How do I prevent SQL injection?"}).status_code == 200


def test_second_sign_in_requires_code_and_refuses_replay(app_client, users):
    secret = sign_in(app_client, "alice", PASSWORDS["alice"])
    app_client.post("/auth/logout")
    assert app_client.get("/me").status_code == 401
    r = app_client.post("/auth/login", json={"username": "alice", "password": PASSWORDS["alice"]})
    assert r.json() == {"status": "mfa_required"}
    used = totp.code_at(secret, users.get("alice").totp_last_step)
    assert app_client.post("/auth/mfa", json={"code": used}).status_code == 401  # replayed code


def test_wrong_passwords_lock_the_account(app_client, assistant):
    for _ in range(5):
        r = app_client.post("/auth/login", json={"username": "alice", "password": "wrong-password-123456"})
        assert r.status_code == 401
    r = app_client.post("/auth/login", json={"username": "alice", "password": PASSWORDS["alice"]})
    assert r.status_code == 401  # locked, even with the right password
    events = [e["event"] for e in assistant.audit.events]
    assert "account_locked" in events and "login_refused_locked" in events
    assert (
        r.json()["detail"]
        == app_client.post("/auth/login", json={"username": "nobody", "password": "x"}).json()["detail"]
    )  # same message for unknown users: no account enumeration


def test_too_many_failures_block_the_ip(app_client, settings):
    for i in range(settings.ip_failure_limit):
        app_client.post("/auth/login", json={"username": f"guess{i}", "password": "wrong"})
    assert app_client.post("/auth/login", json={"username": "alice", "password": PASSWORDS["alice"]}).status_code == 429
    assert app_client.get("/me", headers={"X-API-Key": KEYS["user1"]}).status_code == 429


def test_api_key_guessing_is_blocked(app_client, settings):
    for _ in range(settings.ip_failure_limit):
        assert app_client.get("/me", headers={"X-API-Key": "srag_guess"}).status_code == 401
    assert app_client.get("/me", headers={"X-API-Key": KEYS["user1"]}).status_code == 429


def test_service_accounts_cannot_sign_in(app_client):
    r = app_client.post("/auth/login", json={"username": "user1", "password": "anything-at-all-123"})
    assert r.status_code == 401


def test_cross_site_post_is_refused(app_client):
    sign_in(app_client, "alice", PASSWORDS["alice"])
    r = app_client.post(
        "/ask", json={"question": "How do I prevent SQL injection?"}, headers={"Origin": "https://evil.example"}
    )
    assert r.status_code == 403


# ---------- administration ----------
def test_admin_manages_accounts(app_client, users):
    sign_in(app_client, "admin", PASSWORDS["admin"])
    names = {u["name"] for u in app_client.get("/admin/users").json()}
    assert {"alice", "admin", "user1"} <= names
    assert all("password_hash" not in u and "totp_secret" not in u for u in app_client.get("/admin/users").json())

    weak = app_client.post("/admin/users", json={"username": "bob", "roles": ["staff"], "password": "short"})
    assert weak.status_code == 422
    bad_role = app_client.post(
        "/admin/users", json={"username": "bob", "roles": ["root"], "password": "Long-Enough-Phrase-55"}
    )
    assert bad_role.status_code == 422
    r = app_client.post(
        "/admin/users", json={"username": "bob", "roles": ["staff"], "password": "Long-Enough-Phrase-55"}
    )
    assert r.status_code == 201 and r.json()["roles"] == ["staff"]
    assert users.get("bob") is not None

    assert app_client.patch("/admin/users/bob", json={"disabled": True}).json()["disabled"] is True
    assert app_client.patch("/admin/users/admin", json={"disabled": True}).status_code == 422  # not yourself
    assert app_client.patch("/admin/users/admin", json={"roles": ["staff"]}).status_code == 422
    overview = app_client.get("/admin/overview").json()
    assert overview["events"]["user_created"] >= 1


def test_admin_role_cannot_read_documents_and_staff_cannot_administer(app_client):
    sign_in(app_client, "admin", PASSWORDS["admin"])
    assert app_client.get("/documents").json() == []  # separation of duties
    app_client.post("/auth/logout")
    sign_in(app_client, "alice", PASSWORDS["alice"])
    assert app_client.get("/admin/users").status_code == 403


def test_disabled_user_loses_open_session(app_client, users):
    sign_in(app_client, "alice", PASSWORDS["alice"])
    users.get("alice").disabled = True
    assert app_client.get("/me").status_code == 401


# ---------- feedback ----------
def test_feedback_once_per_own_answer(app_client, assistant):
    headers = {"X-API-Key": KEYS["user1"]}
    answer = app_client.post("/ask", json={"question": "How do I prevent SQL injection?"}, headers=headers).json()
    body = {"answer_id": answer["id"], "helpful": False, "comment": "Wrong, write to me at a@b.example"}
    assert app_client.post("/feedback", json=body, headers=headers).status_code == 200
    assert app_client.post("/feedback", json=body, headers=headers).status_code == 409
    other = {"X-API-Key": KEYS["user2"]}
    assert app_client.post("/feedback", json={**body, "helpful": True}, headers=other).status_code == 404
    logged = [e for e in assistant.audit.events if e["event"] == "feedback"][-1]
    assert logged["answer_id"] == answer["id"] and logged["helpful"] is False
    assert "<EMAIL_1>" in logged["comment"] and "a@b.example" not in logged["comment"]  # comment masked
