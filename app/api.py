"""
FastAPI — hermes_security_agent

  POST /v1/chat              → RAG Q&A (or nginx log analysis if body looks like error.log)
  POST /v1/docs/*            → document RAG
  POST /v1/nginx/analyze     → multipart error.log upload(s)
  POST /v1/nginx/analyze/text
  POST /v1/nginx/analyze/path
"""

from __future__ import annotations

import logging
import os
import re
import secrets
from typing import Any, Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from app import __version__

logger = logging.getLogger("app")

_NGINX_TS = re.compile(
    r"\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[[a-z]+\]",
    re.I,
)


class ChatFileAttachment(BaseModel):
    """Open WebUI / gateway may forward attached files here."""

    filename: Optional[str] = None
    name: Optional[str] = None
    content: Optional[str] = None
    content_base64: Optional[str] = None
    encoding: Optional[str] = None  # utf-8 | base64
    media_type: Optional[str] = None


class ChatRequest(BaseModel):
    """Gateway-compatible chat body (text and/or file attachments)."""

    message: str = Field(
        default="",
        description="User question and/or inlined log text from gateway",
    )
    session_id: Optional[str] = Field(
        default=None,
        description="Optional client correlation id",
    )
    reset_session: bool = Field(
        default=False,
        description="Ignored for stateless agents",
    )
    files: Optional[list[ChatFileAttachment]] = Field(
        default=None,
        description="Attached files from Open WebUI (via gateway)",
    )
    use_llm: Optional[bool] = Field(
        default=None,
        description="Nginx analyzer LLM enrichment when analyzing logs",
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
    overall_health_score: Optional[int] = None
    total_log_entries: Optional[int] = None


class DocsChatRequest(BaseModel):
    message: str = Field(..., min_length=1, description="Document question")
    session_id: Optional[str] = Field(default=None)


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


class NginxTextRequest(BaseModel):
    log_text: str = Field(..., min_length=1, description="Raw nginx error.log content")
    source_name: str = Field(default="error.log")
    use_llm: Optional[bool] = Field(
        default=None,
        description=(
            "LLM group-level analysis after rules. Default: on if OPENAI_API_KEY set "
            "(or NGINX_ANALYZER_LLM). Never analyzes every row."
        ),
    )
    polish: Optional[bool] = Field(
        default=None,
        description="Deprecated alias: true enables use_llm",
    )
    as_markdown: bool = Field(
        default=True,
        description="If true, response field contains full Markdown report",
    )


class NginxPathRequest(BaseModel):
    paths: list[str] = Field(
        ...,
        min_length=1,
        description="Absolute or relative paths to error.log files on the server",
    )
    use_llm: Optional[bool] = Field(default=None)
    polish: Optional[bool] = Field(default=None)


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


def _looks_like_nginx_error_log(text: str) -> bool:
    if not text or len(text) < 40:
        return False
    hits = len(_NGINX_TS.findall(text))
    if hits >= 2:
        return True
    if hits >= 1 and any(
        k in text.lower()
        for k in (
            "fastcgi",
            "upstream",
            "modsecurity",
            "php fatal",
            "php warning",
            "php notice",
            "connect() failed",
            "permission denied",
            "wp-login",
            "wp-admin",
        )
    ):
        return True
    lowered = text.strip().lower()
    if lowered.startswith("analyze nginx") or lowered.startswith("nginx error"):
        return False  # instruction without logs — leave to RAG
    return False


def _decode_chat_file(f: ChatFileAttachment) -> tuple[str, str]:
    """Return (filename, text)."""
    import base64

    name = (f.filename or f.name or "upload.log").replace("\\", "/").rsplit("/", 1)[-1]
    if f.content and (f.encoding or "utf-8").lower() in {"utf-8", "text", "plain", ""}:
        return name, f.content
    b64 = f.content_base64 or (
        f.content if (f.encoding or "").lower() == "base64" else None
    )
    if b64:
        raw = base64.b64decode(b64, validate=False)
        return name, raw.decode("utf-8", errors="replace")
    if f.content:
        return name, f.content
    return name, ""


def _collect_attachment_texts(
    files: Optional[list[ChatFileAttachment]],
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for f in files or []:
        name, text = _decode_chat_file(f)
        if text.strip():
            out.append((name, text))
    return out


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


def _run_nginx_text(
    text: str,
    source_name: str = "error.log",
    *,
    use_llm: Optional[bool] = None,
    polish: Optional[bool] = None,
) -> dict[str, Any]:
    from agents.nginx_analyzer import get_nginx_analyzer

    return get_nginx_analyzer().analyze_text(
        text,
        source_name=source_name,
        use_llm=use_llm,
        polish=polish,
    )


def create_app() -> FastAPI:
    app = FastAPI(
        title=os.getenv("APP_NAME", "hermes_security_agent"),
        version=__version__,
        description=(
            "hermes_security_agent: document RAG + Nginx Error Log Analyzer. "
            "Upload error.log via POST /v1/nginx/analyze or paste logs into /v1/chat."
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
        logger.info("Starting hermes_security_agent v%s", __version__)
        try:
            from agents.nginx_analyzer import get_nginx_analyzer

            logger.info("Nginx analyzer: %s", get_nginx_analyzer().readiness())
        except Exception:
            logger.exception("Nginx analyzer init failed (non-fatal)")
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
                "RAG init failed at startup (non-fatal): %s",
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
        from agents.nginx_analyzer import get_nginx_analyzer

        nginx_rd = get_nginx_analyzer().readiness()
        rag_rd: dict[str, Any] = {"enabled": False}
        try:
            from agents.rag_agent import get_rag_agent, is_enabled

            if is_enabled():
                rag = get_rag_agent()
                if not rag.ready:
                    rag.initialize()
                rag_rd = rag.readiness()
            else:
                rag_rd = {"enabled": False}
        except Exception as exc:  # noqa: BLE001
            rag_rd = {"ready": False, "error": str(exc)}

        # Service is ready if nginx analyzer is up (always) — RAG optional
        return {
            "status": "ready",
            "nginx_analyzer": nginx_rd,
            "rag": rag_rd,
        }

    # ------------------------------------------------------------------
    # Nginx Error Log Analyzer
    # ------------------------------------------------------------------

    @app.get("/v1/nginx/info")
    def nginx_info() -> dict[str, Any]:
        from agents.nginx_analyzer import get_nginx_analyzer

        return {
            "service": os.getenv("APP_NAME", "hermes_security_agent"),
            "version": __version__,
            "agent": "nginx_log_analyzer",
            "endpoints": {
                "upload": "POST /v1/nginx/analyze",
                "text": "POST /v1/nginx/analyze/text",
                "path": "POST /v1/nginx/analyze/path",
                "report_md": "POST /v1/nginx/analyze (Accept: text/markdown)",
            },
            "readiness": get_nginx_analyzer().readiness(),
        }

    @app.post("/v1/nginx/analyze")
    async def nginx_analyze_upload(
        files: list[UploadFile] = File(
            ...,
            description="One or more nginx error.log files",
        ),
        use_llm: Optional[bool] = None,
        polish: Optional[bool] = None,
        _: None = Depends(_check_bearer),
    ) -> dict[str, Any]:
        """Analyze uploaded nginx error.log file(s); returns JSON + Markdown report."""
        from agents.nginx_analyzer import get_nginx_analyzer

        if not files:
            raise HTTPException(status_code=400, detail="No files uploaded")

        upload_pairs: list[tuple[str, Any]] = []
        for f in files:
            upload_pairs.append((f.filename or "error.log", f.file))

        logger.info(
            "POST /v1/nginx/analyze files=%s use_llm=%s polish=%s",
            [f.filename for f in files],
            use_llm,
            polish,
        )
        try:
            result = get_nginx_analyzer().analyze_uploads(
                upload_pairs, use_llm=use_llm, polish=polish
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("nginx analyze failed: %s", exc, exc_info=True)
            raise HTTPException(
                status_code=500,
                detail={"success": False, "error": str(exc)[:500]},
            ) from exc
        return result

    @app.post("/v1/nginx/analyze/text")
    def nginx_analyze_text(
        body: NginxTextRequest,
        _: None = Depends(_check_bearer),
    ) -> dict[str, Any]:
        logger.info(
            "POST /v1/nginx/analyze/text len=%d source=%s use_llm=%s",
            len(body.log_text or ""),
            body.source_name,
            body.use_llm,
        )
        try:
            result = _run_nginx_text(
                body.log_text,
                source_name=body.source_name,
                use_llm=body.use_llm,
                polish=body.polish,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("nginx text analyze failed: %s", exc, exc_info=True)
            raise HTTPException(
                status_code=500,
                detail={"success": False, "error": str(exc)[:500]},
            ) from exc
        return result

    @app.post("/v1/nginx/analyze/text/md", response_class=PlainTextResponse)
    def nginx_analyze_text_md(
        body: NginxTextRequest,
        _: None = Depends(_check_bearer),
    ) -> str:
        result = _run_nginx_text(
            body.log_text,
            source_name=body.source_name,
            use_llm=body.use_llm,
            polish=body.polish,
        )
        return str(result.get("report_markdown") or result.get("response") or "")

    @app.post("/v1/nginx/analyze/path")
    def nginx_analyze_path(
        body: NginxPathRequest,
        _: None = Depends(_check_bearer),
    ) -> dict[str, Any]:
        from agents.nginx_analyzer import get_nginx_analyzer

        logger.info(
            "POST /v1/nginx/analyze/path paths=%s use_llm=%s",
            body.paths,
            body.use_llm,
        )
        try:
            result = get_nginx_analyzer().analyze_paths(
                body.paths, use_llm=body.use_llm, polish=body.polish
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("nginx path analyze failed: %s", exc, exc_info=True)
            raise HTTPException(
                status_code=500,
                detail={"success": False, "error": str(exc)[:500]},
            ) from exc
        if not result.get("success") and result.get("error_code") == "not_found":
            raise HTTPException(status_code=404, detail=result)
        return result

    # ------------------------------------------------------------------
    # Document RAG
    # ------------------------------------------------------------------

    @app.get("/v1/docs/ready")
    def docs_ready() -> dict[str, Any]:
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

    @app.get("/v1/docs/info")
    def docs_info() -> dict[str, Any]:
        from agents.rag_agent import get_rag_agent, is_enabled

        rag = get_rag_agent()
        return {
            "service": os.getenv("APP_NAME", "hermes_security_agent"),
            "version": __version__,
            "design": "rag+nginx_analyzer",
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
        from agents.nginx_analyzer import get_nginx_analyzer
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
            "design": "rag+nginx_analyzer",
            "gateway_compatible": True,
            "chat_path": "/v1/chat",
            "docs_chat_path": "/v1/docs/chat",
            "nginx_analyze_path": "/v1/nginx/analyze",
            "nginx_analyzer": get_nginx_analyzer().readiness(),
            "rag": rag_rd,
        }

    @app.post("/v1/chat", response_model=ChatResponse)
    def chat(
        body: ChatRequest,
        _: None = Depends(_check_bearer),
    ) -> ChatResponse:
        """
        Gateway / Open WebUI entry:
        - Attached error.log files (body.files) or log-like message → nginx analyzer
        - Else → document RAG
        """
        try:
            attachments = _collect_attachment_texts(body.files)
            msg = body.message or ""
            logger.info(
                "POST /v1/chat session_id=%r msg_len=%d files=%d preview=%r",
                body.session_id,
                len(msg),
                len(attachments),
                msg[:80],
            )

            # Prefer explicit file attachments for multi-file analysis
            log_blobs: list[tuple[str, str]] = []
            for name, text in attachments:
                lower = name.lower()
                if (
                    _looks_like_nginx_error_log(text)
                    or lower.endswith(".log")
                    or "error" in lower
                    or "nginx" in lower
                ):
                    log_blobs.append((name, text))

            if not log_blobs and _looks_like_nginx_error_log(msg):
                log_blobs.append(("chat_paste.log", msg))

            if log_blobs:
                from agents.nginx_analyzer import get_nginx_analyzer
                from agents.nginx_analyzer.parser import iter_text_lines
                from agents.nginx_analyzer.classifier import analyze_entries
                from agents.nginx_analyzer.report import render_report
                from agents.nginx_analyzer.llm_enrich import enrich_with_llm
                from agents.nginx_analyzer.llm_enrich import llm_analysis_enabled_default

                def _all_entries():
                    for name, text in log_blobs:
                        yield from iter_text_lines(text, source_file=name)

                analysis = analyze_entries(
                    _all_entries(),
                    files=[n for n, _ in log_blobs],
                )
                do_llm = body.use_llm
                if do_llm is None:
                    do_llm = llm_analysis_enabled_default()
                if do_llm:
                    try:
                        analysis.llm_meta = enrich_with_llm(analysis)
                    except Exception as exc:  # noqa: BLE001
                        analysis.errors.append(f"llm_analysis: {exc}")
                analysis.report_markdown = render_report(analysis)
                data = analysis.to_dict()
                data["success"] = True
                data["response"] = analysis.report_markdown
                data["agents_used"] = ["nginx_log_analyzer"] + (
                    ["llm_enrichment"] if analysis.llm_used else []
                )
                data["mode"] = (
                    "nginx_error_log_analysis_llm"
                    if analysis.llm_used
                    else "nginx_error_log_analysis"
                )
                data["backend"] = "nginx_analyzer"
                result = data
            elif not msg.strip() and not attachments:
                return ChatResponse(
                    success=False,
                    response=None,
                    session_id=body.session_id,
                    error="message or files required",
                    error_code="validation",
                )
            else:
                # Non-log attachments: append text into RAG query context
                if attachments and not log_blobs:
                    parts = [msg] if msg.strip() else []
                    for name, text in attachments:
                        parts.append(
                            f"\n\n----- FILE: {name} -----\n{text[:200_000]}"
                        )
                    msg = "\n".join(parts).strip() or "Describe the attached content."
                result = _run_rag_chat(msg, body.session_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("chat endpoint failed: %s", exc, exc_info=True)
            return ChatResponse(
                success=False,
                response=None,
                session_id=body.session_id,
                error="Ichki server xatosi. Iltimos keyinroq urinib ko'ring.",
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
            overall_health_score=result.get("overall_health_score"),
            total_log_entries=result.get("total_log_entries"),
        )

    return app


app = create_app()
