"""REST API and web interface: sign-in with MFA, sessions, roles, questions, feedback, administration.

uvicorn api.main:app
"""

import re
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from srag import __version__, totp
from srag.audit import AuditLog
from srag.auth import (
    Account,
    LoginGuard,
    RateLimiter,
    SessionStore,
    UserStore,
    hash_password,
    password_problems,
    verify_password,
)
from srag.config import get_settings
from srag.guards.pii import mask
from srag.llm import LLMUnavailable
from srag.service import Service, build_service

WEB_DIR = Path(__file__).resolve().parents[1] / "web"
COOKIE = "srag_session"
KNOWN_ROLES = ["public", "staff", "security-admin", "admin"]
USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
GENERIC_LOGIN_ERROR = "Invalid username or password, or account temporarily locked."
SECURITY_EVENTS = {
    "login_failed",
    "account_locked",
    "mfa_failed",
    "blocked_injection",
    "auth_failed",
    "ip_blocked",
    "csrf_blocked",
    "rate_limited",
    "user_created",
    "user_updated",
    "login_refused_locked",
}

# Strict browser policy for the web interface: only files served by this API, no inline scripts,
# no framing. The interactive API docs (/docs) load their own assets and are left out of it.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class CodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class AskRequest(BaseModel):
    question: str = Field(min_length=3, max_length=2000)


class FeedbackRequest(BaseModel):
    answer_id: str = Field(min_length=8, max_length=64)
    helpful: bool
    comment: str = Field(default="", max_length=500)


class NewUser(BaseModel):
    username: str = Field(max_length=64)
    roles: list[str]
    password: str = Field(max_length=256)


class UserChange(BaseModel):
    disabled: bool | None = None
    roles: list[str] | None = None
    reset_mfa: bool = False
    unlock: bool = False
    password: str | None = Field(default=None, max_length=256)


class SourceOut(BaseModel):
    label: str
    title: str
    section: str
    reference: str
    source: str
    url: str
    score: float
    excerpt: str


class AskResponse(BaseModel):
    id: str
    answer: str
    refused: bool
    reason: str | None
    sources: list[SourceOut]
    mode: str
    masked_entities: int
    latency_ms: int


@dataclass
class Principal:
    account: Account
    method: str  # "session" or "api_key"


def create_app(
    service: Service | None = None, users: UserStore | None = None, audit: AuditLog | None = None
) -> FastAPI:
    state: dict = {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        settings = service.settings if service else get_settings()
        state["audit"] = audit or (service.assistant.audit if service else AuditLog(settings.audit_log))
        state["service"] = service or build_service(settings, state["audit"])
        state["settings"] = state["service"].settings
        state["users"] = users or UserStore(state["settings"].users_file)
        state["sessions"] = SessionStore(
            idle_seconds=state["settings"].session_idle_minutes * 60,
            max_seconds=state["settings"].session_max_hours * 3600,
        )
        state["guard"] = LoginGuard(
            threshold=state["settings"].lockout_threshold,
            lock_seconds=state["settings"].lockout_minutes * 60,
            ip_limit=state["settings"].ip_failure_limit,
        )
        state["limiter"] = RateLimiter(state["settings"].rate_limit_per_minute)
        state["answers"] = OrderedDict()  # answer id -> [user, feedback given]
        yield

    app = FastAPI(title="Secure RAG Assistant", version=__version__, lifespan=lifespan)
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        if not request.url.path.startswith(("/docs", "/redoc", "/openapi.json")):
            response.headers.update(SECURITY_HEADERS)
        response.headers["Cache-Control"] = "no-store"
        return response

    # ---------- helpers ----------
    def ip_of(request: Request) -> str | None:
        return request.client.host if request.client else None

    def log(event: str, user: str | None = None, request: Request | None = None, **fields) -> None:
        if request is not None:
            fields.setdefault("client_ip", ip_of(request))
        state["audit"].write(event, user, **fields)

    def set_cookie(response: Response, token: str) -> None:
        response.set_cookie(
            COOKIE,
            token,
            httponly=True,
            secure=state["settings"].cookie_secure,
            samesite="strict",
            path="/",
            max_age=state["settings"].session_max_hours * 3600,
        )

    def same_origin(request: Request) -> bool:
        origin = request.headers.get("origin")
        if not origin:
            return True  # non-browser clients and same-origin requests from older browsers
        return urlparse(origin).netloc == request.headers.get("host")

    def principal(request: Request, x_api_key: str | None = Header(default=None)) -> Principal:
        ip = ip_of(request)
        guard: LoginGuard = state["guard"]
        if x_api_key is not None:
            if guard.ip_blocked(ip):
                log("ip_blocked", None, request)
                raise HTTPException(status_code=429, detail="Too many failed attempts from this address.")
            account = state["users"].by_api_key(x_api_key)
            if account is None or account.disabled:
                guard.failure(ip)
                log("auth_failed", None, request, method="api_key", path=request.url.path)
                raise HTTPException(status_code=401, detail="Invalid API key")
            found = Principal(account, "api_key")
        else:
            session = state["sessions"].get(request.cookies.get(COOKIE))
            account = state["users"].get(session.user) if session else None
            if session is None or not session.mfa_ok or account is None or account.disabled:
                raise HTTPException(status_code=401, detail="Sign in required")
            if request.method not in ("GET", "HEAD") and not same_origin(request):
                log("csrf_blocked", account.name, request)
                raise HTTPException(status_code=403, detail="Cross-site request refused")
            found = Principal(account, "session")
        if not state["limiter"].allow(found.account.name):
            log("rate_limited", found.account.name, request)
            raise HTTPException(status_code=429, detail="Too many requests, try again in a minute")
        return found

    def admin(p: Principal = Depends(principal)) -> Principal:
        if "admin" not in p.account.roles:
            raise HTTPException(status_code=403, detail="Administrator role required")
        return p

    # ---------- pages and status ----------
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/health")
    def health():
        svc: Service = state["service"]
        return {
            "status": "ok",
            "version": __version__,
            "mode": svc.assistant.mode,
            "model": svc.assistant.llm.name,
            "documents": len(svc.assistant.store.doc_hashes()),
            "chunks": svc.assistant.store.count(),
            "integrity": svc.integrity_mode if svc.integrity.ok else "failed",
            "mfa_required": state["settings"].require_mfa,
        }

    # ---------- sign-in ----------
    @app.post("/auth/login")
    def login(body: LoginRequest, request: Request, response: Response):
        ip = ip_of(request)
        guard: LoginGuard = state["guard"]
        name = body.username.strip().lower()
        if guard.ip_blocked(ip):
            log("ip_blocked", name, request)
            raise HTTPException(status_code=429, detail="Too many failed attempts from this address. Try again later.")
        account = state["users"].get(name)
        if account is not None and account.service:
            account = None  # service accounts cannot sign in to the web interface
        if account is not None and guard.user_locked(name):
            log("login_refused_locked", name, request)
            raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)
        password_ok = verify_password(body.password, account.password_hash if account else None)
        if not (password_ok and account is not None and not account.disabled):
            locked = guard.failure(ip, name if account else None)
            log("login_failed", name, request, reason="bad_credentials")
            if locked:
                log("account_locked", name, request, minutes=state["settings"].lockout_minutes)
            raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)

        state["sessions"].delete(request.cookies.get(COOKIE))
        needs_setup = state["settings"].require_mfa and not account.mfa_enabled
        mfa_ok = not account.mfa_enabled and not state["settings"].require_mfa
        token = state["sessions"].create(account.name, mfa_ok=mfa_ok)
        if needs_setup:
            state["sessions"].get(token).pending_secret = totp.generate_secret()
        set_cookie(response, token)
        if mfa_ok:
            guard.success(account.name)
            log("login_success", account.name, request, mfa=False)
            return {"status": "ok"}
        return {"status": "mfa_setup" if needs_setup else "mfa_required"}

    def pending_session(request: Request):
        session = state["sessions"].get(request.cookies.get(COOKIE))
        if session is None or session.mfa_ok:
            raise HTTPException(status_code=401, detail="Sign in first")
        return session

    @app.get("/auth/mfa/setup")
    def mfa_setup(request: Request):
        session = pending_session(request)
        if not session.pending_secret:
            raise HTTPException(status_code=409, detail="MFA is already set up for this account")
        return {"secret": session.pending_secret, "uri": totp.provisioning_uri(session.pending_secret, session.user)}

    @app.get("/auth/mfa/qr.svg", include_in_schema=False)
    def mfa_qr(request: Request):
        session = pending_session(request)
        if not session.pending_secret:
            raise HTTPException(status_code=409, detail="MFA is already set up for this account")
        svg = totp.qr_svg(totp.provisioning_uri(session.pending_secret, session.user))
        return Response(content=svg, media_type="image/svg+xml")

    @app.post("/auth/mfa")
    def mfa_verify(body: CodeRequest, request: Request, response: Response):
        session = pending_session(request)
        guard: LoginGuard = state["guard"]
        account = state["users"].get(session.user)
        if account is None or account.disabled or guard.user_locked(account.name):
            raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)
        secret = session.pending_secret or account.totp_secret
        step = totp.verify(secret, body.code, -1 if session.pending_secret else account.totp_last_step)
        if step is None:
            locked = guard.failure(ip_of(request), account.name)
            log("mfa_failed", account.name, request)
            if locked:
                log("account_locked", account.name, request, minutes=state["settings"].lockout_minutes)
                state["sessions"].delete(request.cookies.get(COOKIE))
            raise HTTPException(status_code=401, detail="Invalid code")
        if session.pending_secret:
            account.totp_secret = session.pending_secret
            account.mfa_enabled = True
            log("mfa_enrolled", account.name, request)
        account.totp_last_step = step  # each code works once
        state["users"].save()
        # New token after sign-in: a token seen before authentication becomes useless (session fixation).
        state["sessions"].delete(request.cookies.get(COOKIE))
        set_cookie(response, state["sessions"].create(account.name, mfa_ok=True))
        guard.success(account.name)
        log("login_success", account.name, request, mfa=True)
        return {"status": "ok"}

    @app.post("/auth/logout")
    def logout(request: Request, response: Response):
        session = state["sessions"].get(request.cookies.get(COOKIE))
        state["sessions"].delete(request.cookies.get(COOKIE))
        response.delete_cookie(COOKIE, path="/")
        if session:
            log("logout", session.user, request)
        return {"status": "ok"}

    # ---------- assistant ----------
    @app.get("/me")
    def me(p: Principal = Depends(principal)):
        return {
            "name": p.account.name,
            "roles": p.account.roles,
            "mode": state["service"].assistant.mode,
            "admin": "admin" in p.account.roles,
            "auth": p.method,
        }

    @app.get("/documents")
    def documents(p: Principal = Depends(principal)):
        return state["service"].assistant.store.documents(p.account.user().roles)

    @app.post("/ask", response_model=AskResponse)
    def ask(body: AskRequest, p: Principal = Depends(principal)):
        answer = state["service"].assistant.ask(body.question, p.account.user())
        answers: OrderedDict = state["answers"]
        answers[answer.id] = [p.account.name, False]
        while len(answers) > 5000:
            answers.popitem(last=False)
        return AskResponse(
            id=answer.id,
            answer=answer.text,
            refused=answer.refused,
            reason=answer.reason,
            mode=answer.mode,
            masked_entities=answer.masked_entities,
            latency_ms=answer.latency_ms,
            sources=[
                SourceOut(
                    label=s.label,
                    title=s.chunk.title,
                    section=s.chunk.section,
                    reference=s.chunk.reference,
                    source=s.chunk.source,
                    url=s.chunk.url,
                    score=s.score,
                    excerpt=s.chunk.text.split("\n", 1)[-1][:600],
                )
                for s in answer.sources
            ],
        )

    @app.post("/feedback")
    def feedback(body: FeedbackRequest, request: Request, p: Principal = Depends(principal)):
        entry = state["answers"].get(body.answer_id)
        if entry is None or entry[0] != p.account.name:
            raise HTTPException(status_code=404, detail="Unknown answer")
        if entry[1]:
            raise HTTPException(status_code=409, detail="Feedback already given for this answer")
        entry[1] = True
        log(
            "feedback",
            p.account.name,
            request,
            answer_id=body.answer_id,
            helpful=body.helpful,
            comment=mask(body.comment).text if body.comment else "",
        )
        return {"status": "ok"}

    # ---------- administration ----------
    def validate_roles(roles: list[str]) -> list[str]:
        unknown = [r for r in roles if r not in KNOWN_ROLES]
        if unknown or not roles:
            raise HTTPException(status_code=422, detail=f"Roles must be among {KNOWN_ROLES}")
        return sorted(set(roles), key=KNOWN_ROLES.index)

    def check_password(password: str, username: str) -> None:
        problems = password_problems(password, username)
        if problems:
            raise HTTPException(status_code=422, detail="Password: " + ", ".join(problems))

    @app.get("/admin/users")
    def list_users(_: Principal = Depends(admin)):
        locked = state["guard"].locked_users()
        return [{**a.public(), "locked": a.name in locked} for a in state["users"].accounts.values()]

    @app.post("/admin/users", status_code=201)
    def create_user(body: NewUser, request: Request, p: Principal = Depends(admin)):
        name = body.username.strip().lower()
        if not USERNAME.match(name):
            raise HTTPException(status_code=422, detail="Username: 3 to 32 lowercase letters, digits, dot or dash")
        roles = validate_roles(body.roles)
        check_password(body.password, name)
        try:
            state["users"].add(Account(name=name, roles=roles, password_hash=hash_password(body.password)))
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        log("user_created", p.account.name, request, target=name, roles=roles)
        return {**state["users"].get(name).public(), "locked": False}

    @app.patch("/admin/users/{name}")
    def update_user(name: str, body: UserChange, request: Request, p: Principal = Depends(admin)):
        account = state["users"].get(name)
        if account is None:
            raise HTTPException(status_code=404, detail="Unknown user")
        changes = []
        if body.disabled is not None:
            if name == p.account.name and body.disabled:
                raise HTTPException(status_code=422, detail="You cannot disable your own account")
            account.disabled = body.disabled
            changes.append("disabled" if body.disabled else "enabled")
        if body.roles is not None:
            roles = validate_roles(body.roles)
            if name == p.account.name and "admin" not in roles:
                raise HTTPException(status_code=422, detail="You cannot remove your own administrator role")
            account.roles = roles
            changes.append("roles=" + ",".join(roles))
        if body.reset_mfa:
            account.totp_secret, account.mfa_enabled, account.totp_last_step = None, False, -1
            changes.append("mfa_reset")
        if body.password:
            check_password(body.password, name)
            account.password_hash = hash_password(body.password)
            changes.append("password_reset")
        if body.unlock:
            state["guard"].unlock(name)
            changes.append("unlocked")
        if not changes:
            raise HTTPException(status_code=422, detail="Nothing to change")
        state["users"].save()
        if body.disabled or body.reset_mfa or body.password or body.roles is not None:
            state["sessions"].delete_user(name)  # rights changed: open sessions must sign in again
        log("user_updated", p.account.name, request, target=name, changes=changes)
        return {**account.public(), "locked": name in state["guard"].locked_users()}

    @app.get("/admin/overview")
    def overview(_: Principal = Depends(admin)):
        events = state["audit"].events
        counts: dict[str, int] = {}
        for e in events:
            counts[e["event"]] = counts.get(e["event"], 0) + 1
        feedback_events = [e for e in events if e["event"] == "feedback"]
        recent = [
            {k: e.get(k) for k in ("ts", "event", "user", "client_ip", "reason", "target")}
            for e in events
            if e["event"] in SECURITY_EVENTS
        ][-15:][::-1]
        return {
            "feedback": {
                "helpful": sum(1 for e in feedback_events if e.get("helpful")),
                "not_helpful": sum(1 for e in feedback_events if not e.get("helpful")),
            },
            "events": counts,
            "recent_security_events": recent,
            "skipped_files": state["service"].skipped_files,
        }

    @app.exception_handler(LLMUnavailable)
    async def llm_unavailable(_: Request, exc: LLMUnavailable):
        # Fail closed: no fallback to another provider.
        return JSONResponse(
            status_code=503,
            content={"detail": "The LLM is unavailable. The request was not sent to any other provider."},
        )

    return app


app = create_app()
