"""REST API and web interface: authentication, rate limit, question answering, health.

uvicorn api.main:app
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from srag import __version__
from srag.audit import AuditLog
from srag.auth import RateLimiter, UserDirectory
from srag.config import get_settings
from srag.llm import LLMUnavailable
from srag.models import User
from srag.service import Service, build_service

WEB_DIR = Path(__file__).resolve().parents[1] / "web"

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


class AskRequest(BaseModel):
    question: str = Field(min_length=3, max_length=2000)


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
    answer: str
    refused: bool
    reason: str | None
    sources: list[SourceOut]
    mode: str
    masked_entities: int
    latency_ms: int


def create_app(
    service: Service | None = None, users: UserDirectory | None = None, audit: AuditLog | None = None
) -> FastAPI:
    state: dict = {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        settings = get_settings() if service is None or users is None else None
        state["audit"] = audit or (service.assistant.audit if service else AuditLog(settings.audit_log))
        state["service"] = service or build_service(settings, state["audit"])
        state["users"] = users or UserDirectory.from_file(state["service"].settings.users_file)
        state["limiter"] = RateLimiter(state["service"].settings.rate_limit_per_minute)
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

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(WEB_DIR / "index.html")

    def current_user(request: Request, x_api_key: str | None = Header(default=None)) -> User:
        user = state["users"].authenticate(x_api_key)
        client = request.client.host if request.client else None
        if user is None:
            state["audit"].write("auth_failed", None, client_ip=client, path=request.url.path)
            raise HTTPException(status_code=401, detail="Invalid or missing API key")
        if not state["limiter"].allow(user.name):
            state["audit"].write("rate_limited", user.name, client_ip=client)
            raise HTTPException(status_code=429, detail="Too many requests, try again in a minute")
        return user

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
            "integrity": "ok" if svc.integrity.ok else "failed",
        }

    @app.get("/me")
    def me(user: User = Depends(current_user)):
        return {"name": user.name, "roles": list(user.roles), "mode": state["service"].assistant.mode}

    @app.get("/documents")
    def documents(user: User = Depends(current_user)):
        return state["service"].assistant.store.documents(user.roles)

    @app.post("/ask", response_model=AskResponse)
    def ask(body: AskRequest, user: User = Depends(current_user)):
        answer = state["service"].assistant.ask(body.question, user)
        return AskResponse(
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

    @app.exception_handler(LLMUnavailable)
    async def llm_unavailable(_: Request, exc: LLMUnavailable):
        # Fail closed: no fallback to another provider.
        return JSONResponse(
            status_code=503,
            content={"detail": "The LLM is unavailable. The request was not sent to any other provider."},
        )

    return app


app = create_app()
