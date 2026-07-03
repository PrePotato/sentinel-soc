"""SENTINEL SOC — FastAPI application entrypoint.

Run:  uvicorn app.main:app --reload --port 8000
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm

from . import ai, cache, db, nvd
from .auth import authenticate, create_token, get_current_user, require_admin
from .config import settings
from .schemas import EventRecord, ExplainRequest, ExplainResponse, Snapshot, Token
from .ws import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init()         # PostgreSQL event log (optional)
    await cache.connect()   # Redis cache (optional)
    engine.start()          # spin up the telemetry broadcast loops
    yield
    await engine.stop()
    await cache.close()
    await db.close()


app = FastAPI(title="SENTINEL SOC API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_origin_regex=settings.cors_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ───────────────────────────────────────────────
@app.get("/api/health")
async def health() -> dict:
    return {
        "status": "ok",
        "service": "sentinel-soc",
        "clients": len(engine.clients),
        "postgres": db.available(),
        "redis": cache.available(),
        "nvd_live": nvd.is_live(),
    }


# ── Auth ─────────────────────────────────────────────────
@app.post("/api/auth/login", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends()) -> Token:
    from fastapi import HTTPException, status

    user = authenticate(form.username, form.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return create_token(user["username"], user["role"])


@app.get("/api/me")
async def me(user: dict = Depends(get_current_user)) -> dict:
    return user


# ── Telemetry ────────────────────────────────────────────
@app.get("/api/snapshot", response_model=Snapshot)
async def snapshot(_: dict = Depends(get_current_user)) -> Snapshot:
    return engine.snapshot


@app.post("/api/scan", response_model=Snapshot)
async def manual_scan(_: dict = Depends(require_admin)) -> Snapshot:
    """Trigger a fresh scan of the environment (admin only)."""
    snap = engine.rescan()
    await engine.broadcast("snapshot", snap.model_dump())
    return snap


# ── Event log (PostgreSQL-backed, searchable) ────────────
@app.get("/api/events", response_model=list[EventRecord])
async def events(
    limit: int = 100,
    q: str | None = None,
    severity: str | None = None,
    _: dict = Depends(get_current_user),
) -> list[EventRecord]:
    """Searchable security event log persisted to PostgreSQL (empty if no DB)."""
    return await db.recent_events(limit=limit, q=q, severity=severity)


# ── AI ───────────────────────────────────────────────────
@app.post("/api/ai/explain", response_model=ExplainResponse)
async def ai_explain(req: ExplainRequest, _: dict = Depends(get_current_user)) -> ExplainResponse:
    return ai.explain(req.question, req.context)


# ── Live WebSocket ───────────────────────────────────────
@app.websocket("/ws/live")
async def ws_live(ws: WebSocket) -> None:
    await engine.connect(ws)
    try:
        while True:
            # We don't expect inbound messages, but keep the socket drained.
            await ws.receive_text()
    except WebSocketDisconnect:
        engine.disconnect(ws)
    except Exception:
        engine.disconnect(ws)
