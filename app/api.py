"""
FastAPI — document RAG only (Chroma + embeddings).

  POST /v1/chat       → RAG Q&A (gateway-compatible)
  POST /v1/docs/chat  → same RAG path
  POST /v1/docs/reindex
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app import __version__

logger = logging.getLogger("app")


class ChatRequest(BaseModel):
    """Gateway-compatible chat body."""

    message: str = Field(..., min_length=1, description="User question")
    session_id: Optional[str] = Field(
        default=None,
        description="Optional client correlation id (RAG is stateless)",
    )
    reset_session: bool = Field(
        default=False,
        description="Ignored — RAG has no session memory",
    )


class ChatResponse(BaseModel):
    success: bool
    response: Optional[str] = None
    session_id: Optional[str] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    error_detail: Optional[str] = None
    retryable: Optional[bool] = None
    sources: Optional[list[dict[str, Any]]] = None
    agents_used: Optional[list[str]] = None
    mode: Optional[str] = None
    backend: Optional[str] = None
    embed_provider: Optional[str] = None
    embed_model: Optional[str] = None
    embed_dim: Optional[int] = None


class DocsChatRequest(BaseModel):
    message: str = Field(..., min_length=1, description="Document question")
    session_id: Optional[str] = Field(
        default=None,
        description="Optional client correlation id (RAG is stateless)",
    )


class DocsChatResponse(BaseModel):
    success: bool
    response: Optional[str] = None
    session_id: Optional[str] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    error_detail: Optional[str] = None
    retryable: Optional[bool] = None
    sources: Optional[list[dict[str, Any]]] = None
    agents_used: Optional[list[str]] = None
    mode: Optional[str] = None
    backend: Optional[str] = None
    embed_provider: Optional[str] = None
    embed_model: Optional[str] = None
    embed_dim: Optional[int] = None


def _cors_origins() -> list[str]:
    raw = os.getenv("CORS_ORIGINS", "*").strip()
    if raw == "*":
        return ["*"]
    return [o.strip() for o in raw.split(",") if o.strip()]


def _check_bearer(
    authorization: Optional[str] = Header(default=None),
) -> None:
    expected = os.getenv("API_BEARER_TOKEN", "").strip()
    if not expected:
        return
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ", 1)[1].strip()
    if not secrets.compare_digest(token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _run_rag_chat(message: str, session_id: Optional[str]) -> dict[str, Any]:
    from agents.rag_agent import get_rag_agent, is_enabled

    if not is_enabled():
        return {
            "success": False,
            "response": None,
            "session_id": session_id,
            "error": "RAG disabled (RAG_ENABLED=false)",
            "error_code": "disabled",
            "sources": [],
        }
    rag = get_rag_agent()
    result = rag.chat(message)
    result["session_id"] = session_id
    return result


def create_app() -> FastAPI:
    app = FastAPI(
        title=os.getenv("APP_NAME", "hermes_security_agent"),
        version=__version__,
        description=(
            "Document RAG agent (Chroma). "
            "POST /v1/chat and POST /v1/docs/chat for Q&A over data/docs."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.on_event("startup")
    def _startup() -> None:
        logger.info("Starting RAG service v%s", __version__)
        try:
            from agents.rag_agent import get_rag_agent, is_enabled as rag_enabled

            if rag_enabled():
                rag = get_rag_agent()
                logger.info("RAG readiness: %s", rag.readiness())
            else:
                logger.warning("RAG_ENABLED=false — document endpoints disabled")
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            logger.exception(
                "RAG init failed at startup (non-fatal): %s — /v1/docs/* may need reindex",
                exc,
            )

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": os.getenv("APP_NAME", "hermes_security_agent"),
        }

    @app.get("/ready")
    def ready() -> dict[str, Any]:
        from agents.rag_agent import get_rag_agent, is_enabled

        if not is_enabled():
            raise HTTPException(
                status_code=503,
                detail={"status": "disabled", "error": "RAG_ENABLED=false"},
            )
        rag = get_rag_agent()
        if not rag.ready:
            rag.initialize()
        rd = rag.readiness()
        if not rd.get("ready"):
            raise HTTPException(
                status_code=503,
                detail={"status": "not_ready", "rag": rd},
            )
        return {"status": "ready", "rag": rd}

    @app.get("/v1/docs/ready")
    def docs_ready() -> dict[str, Any]:
        return ready()

    @app.get("/v1/docs/info")
    def docs_info() -> dict[str, Any]:
        from agents.rag_agent import get_rag_agent, is_enabled

        rag = get_rag_agent()
        return {
            "service": os.getenv("APP_NAME", "hermes_security_agent"),
            "version": __version__,
            "design": "rag-only",
            "enabled": is_enabled(),
            "docs_chat_path": "/v1/docs/chat",
            "chat_path": "/v1/chat",
            "reindex_path": "/v1/docs/reindex",
            "rag": rag.readiness(),
        }

    @app.get("/v1/docs/files")
    def docs_files() -> dict[str, Any]:
        from agents.rag_agent import get_rag_agent

        return get_rag_agent().list_files()

    @app.post("/v1/docs/reindex")
    def docs_reindex(
        _: None = Depends(_check_bearer),
    ) -> dict[str, Any]:
        """Full rebuild of Chroma for the current RAG_EMBED_* identity."""
        from agents.rag_agent import get_rag_agent, is_enabled

        if not is_enabled():
            raise HTTPException(
                status_code=503,
                detail={"success": False, "error": "RAG_ENABLED=false"},
            )
        rag = get_rag_agent()
        logger.info("POST /v1/docs/reindex")
        result = rag.reindex(force=True)
        if not result.get("success"):
            raise HTTPException(status_code=500, detail=result)
        return result

    @app.post("/v1/docs/chat", response_model=DocsChatResponse)
    def docs_chat(
        body: DocsChatRequest,
        _: None = Depends(_check_bearer),
    ) -> DocsChatResponse:
        """Document RAG Q&A."""
        try:
            logger.info(
                "POST /v1/docs/chat msg_len=%d preview=%r",
                len(body.message or ""),
                (body.message or "")[:80],
            )
            result = _run_rag_chat(body.message, body.session_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("docs chat failed: %s", exc, exc_info=True)
            return DocsChatResponse(
                success=False,
                response=None,
                session_id=body.session_id,
                error="Ichki server xatosi (RAG). Iltimos keyinroq urinib ko'ring.",
                error_code="internal",
                error_detail=str(exc)[:500],
                retryable=True,
                sources=[],
            )
        return DocsChatResponse(
            success=bool(result.get("success")),
            response=result.get("response"),
            session_id=body.session_id,
            error=result.get("error"),
            error_code=result.get("error_code"),
            error_detail=result.get("error_detail"),
            retryable=result.get("retryable"),
            sources=result.get("sources"),
            agents_used=result.get("agents_used"),
            mode=result.get("mode"),
            backend=result.get("backend"),
            embed_provider=result.get("embed_provider"),
            embed_model=result.get("embed_model"),
            embed_dim=result.get("embed_dim"),
        )

    @app.get("/v1/info")
    def info() -> dict[str, Any]:
        from agents.rag_agent import get_rag_agent, is_enabled as rag_enabled

        rag_rd: dict[str, Any] = {"enabled": rag_enabled()}
        try:
            if rag_enabled():
                rd = get_rag_agent().readiness()
                rag_rd.update(
                    {
                        k: rd.get(k)
                        for k in ("ready", "identity", "chunk_count", "error")
                    }
                )
        except Exception as exc:  # noqa: BLE001
            rag_rd["error"] = str(exc)
        return {
            "service": os.getenv("APP_NAME", "hermes_security_agent"),
            "version": __version__,
            "design": "rag-only",
            "gateway_compatible": True,
            "chat_path": "/v1/chat",
            "docs_chat_path": "/v1/docs/chat",
            "ready": bool(rag_rd.get("ready")),
            "rag": rag_rd,
        }

    @app.post("/v1/chat", response_model=ChatResponse)
    def chat(
        body: ChatRequest,
        _: None = Depends(_check_bearer),
    ) -> ChatResponse:
        """Gateway entry: document RAG Q&A."""
        try:
            logger.info(
                "POST /v1/chat session_id=%r msg_len=%d preview=%r",
                body.session_id,
                len(body.message or ""),
                (body.message or "")[:80],
            )
            result = _run_rag_chat(body.message, body.session_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("chat endpoint failed: %s", exc, exc_info=True)
            return ChatResponse(
                success=False,
                response=None,
                session_id=body.session_id,
                error="Ichki server xatosi (RAG). Iltimos keyinroq urinib ko'ring.",
                error_code="internal",
                error_detail=str(exc)[:500],
                retryable=True,
            )
        return ChatResponse(
            success=bool(result.get("success")),
            response=result.get("response"),
            session_id=body.session_id,
            error=result.get("error"),
            error_code=result.get("error_code"),
            error_detail=result.get("error_detail"),
            retryable=result.get("retryable"),
            sources=result.get("sources"),
            agents_used=result.get("agents_used"),
            mode=result.get("mode"),
            backend=result.get("backend"),
            embed_provider=result.get("embed_provider"),
            embed_model=result.get("embed_model"),
            embed_dim=result.get("embed_dim"),
        )

    return app


app = create_app()
