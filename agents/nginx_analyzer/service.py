"""
Nginx Error Log Analyzer service.

Pipeline:
  1) Stream-parse every log row (code)
  2) Classify + group + severity (rules/tools)
  3) Optional LLM enrichment on *groups* (not per-row)
  4) Markdown report
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any, BinaryIO, Optional, Union

from agents.nginx_analyzer.classifier import analyze_entries
from agents.nginx_analyzer.llm_enrich import enrich_with_llm, llm_analysis_enabled_default
from agents.nginx_analyzer.models import AnalysisResult
from agents.nginx_analyzer.parser import iter_file, iter_stream, iter_text_lines
from agents.nginx_analyzer.report import render_report

logger = logging.getLogger("nginx_analyzer")

_lock = threading.RLock()
_service: Optional["NginxLogAnalyzerService"] = None


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _load_dotenv_once() -> None:
    try:
        from dotenv import load_dotenv

        root = Path(__file__).resolve().parent.parent.parent
        env = root / ".env"
        if env.is_file():
            load_dotenv(env)
    except Exception:
        pass


class NginxLogAnalyzerService:
    """Senior-ops style analyzer for one or more nginx error.log files."""

    name = "nginx_log_analyzer"

    def __init__(self) -> None:
        _load_dotenv_once()
        # Group-level LLM analysis (default: on if OPENAI_API_KEY set)
        self.llm_analysis = llm_analysis_enabled_default()
        # Back-compat alias: polish-only executive blurb if full analysis off
        self.llm_polish = _env_bool("NGINX_ANALYZER_LLM_POLISH", False)
        self.max_upload_mb = int(os.getenv("NGINX_ANALYZER_MAX_UPLOAD_MB") or "512")

    def readiness(self) -> dict[str, Any]:
        return {
            "ready": True,
            "agent": self.name,
            "llm_analysis": self.llm_analysis,
            "llm_polish": self.llm_polish,
            "max_upload_mb": self.max_upload_mb,
            "capabilities": [
                "stream_parse",
                "classify",
                "group",
                "severity",
                "markdown_report",
                "multi_file",
                "llm_group_enrichment",
            ],
            "llm_note": (
                "LLM never reads every row. Rules classify all lines; "
                "LLM only analyzes grouped categories with ≤3 examples each."
            ),
        }

    def analyze_text(
        self,
        text: str,
        *,
        source_name: str = "error.log",
        use_llm: Optional[bool] = None,
        polish: Optional[bool] = None,
    ) -> dict[str, Any]:
        entries = list(iter_text_lines(text, source_file=source_name))
        result = analyze_entries(entries, files=[source_name])
        return self._finalize(result, use_llm=use_llm, polish=polish)

    def analyze_paths(
        self,
        paths: list[Union[str, Path]],
        *,
        use_llm: Optional[bool] = None,
        polish: Optional[bool] = None,
    ) -> dict[str, Any]:
        resolved: list[Path] = []
        errors: list[str] = []
        for p in paths:
            path = Path(p)
            if not path.is_file():
                errors.append(f"Not a file: {p}")
                continue
            resolved.append(path)

        def _gen():
            for path in resolved:
                try:
                    yield from iter_file(path)
                except OSError as exc:
                    errors.append(f"{path.name}: {exc}")

        result = analyze_entries(_gen(), files=[p.name for p in resolved])
        result.errors.extend(errors)
        return self._finalize(result, use_llm=use_llm, polish=polish)

    def analyze_uploads(
        self,
        files: list[tuple[str, BinaryIO]],
        *,
        use_llm: Optional[bool] = None,
        polish: Optional[bool] = None,
    ) -> dict[str, Any]:
        names: list[str] = []
        errors: list[str] = []
        max_bytes = self.max_upload_mb * 1024 * 1024

        def _gen():
            for name, fh in files:
                safe_name = Path(name or "error.log").name
                names.append(safe_name)
                try:
                    if hasattr(fh, "seek"):
                        try:
                            fh.seek(0)
                        except Exception:
                            pass
                    if hasattr(fh, "seek") and hasattr(fh, "tell"):
                        try:
                            fh.seek(0, 2)
                            size = fh.tell()
                            fh.seek(0)
                            if size > max_bytes:
                                errors.append(
                                    f"{safe_name}: exceeds max upload "
                                    f"{self.max_upload_mb}MB"
                                )
                                continue
                        except Exception:
                            pass
                    yield from iter_stream(fh, source_file=safe_name)
                except Exception as exc:  # noqa: BLE001
                    logger.exception("upload parse failed: %s", safe_name)
                    errors.append(f"{safe_name}: {exc}")

        result = analyze_entries(_gen(), files=names)
        result.errors.extend(errors)
        return self._finalize(result, use_llm=use_llm, polish=polish)

    def analyze_directory(
        self,
        directory: Union[str, Path],
        *,
        pattern: str = "error.log*",
        use_llm: Optional[bool] = None,
        polish: Optional[bool] = None,
    ) -> dict[str, Any]:
        d = Path(directory)
        if not d.is_dir():
            return {
                "success": False,
                "error": f"Not a directory: {directory}",
                "error_code": "not_found",
            }
        paths = sorted(d.glob(pattern), key=lambda p: p.name)
        extra = []
        for name in ("error.log", "error.log.1", "nginx_error.log"):
            p = d / name
            if p.is_file() and p not in paths:
                extra.append(p)
        paths = list(dict.fromkeys(list(paths) + extra))
        if not paths:
            return {
                "success": False,
                "error": f"No files matching {pattern!r} in {directory}",
                "error_code": "empty",
            }
        return self.analyze_paths(paths, use_llm=use_llm, polish=polish)

    def _finalize(
        self,
        result: AnalysisResult,
        *,
        use_llm: Optional[bool] = None,
        polish: Optional[bool] = None,
    ) -> dict[str, Any]:
        # resolve flags: use_llm wins; polish alone = light executive only
        if use_llm is None and polish is True:
            # back-compat: polish=true enables full group LLM analysis
            do_llm = True
        elif use_llm is None:
            do_llm = self.llm_analysis
        else:
            do_llm = bool(use_llm)

        if do_llm:
            try:
                meta = enrich_with_llm(result)
                result.llm_meta = meta
                if not meta.get("used"):
                    err = meta.get("error") or "llm not used"
                    result.errors.append(f"llm_analysis: {err}")
                    logger.warning("LLM analysis skipped: %s", err)
            except Exception as exc:  # noqa: BLE001
                logger.exception("LLM analysis failed")
                result.errors.append(f"llm_analysis: {exc}")
                result.llm_meta = {"used": False, "error": str(exc)[:500]}

        result.report_markdown = render_report(result)

        agents = [self.name]
        if result.llm_used:
            agents.append("llm_enrichment")

        data = result.to_dict()
        data["success"] = True
        data["response"] = result.report_markdown
        data["agents_used"] = agents
        data["mode"] = (
            "nginx_error_log_analysis_llm"
            if result.llm_used
            else "nginx_error_log_analysis"
        )
        data["backend"] = "nginx_analyzer"
        return data


def get_nginx_analyzer() -> NginxLogAnalyzerService:
    global _service
    with _lock:
        if _service is None:
            _service = NginxLogAnalyzerService()
        return _service


def analyze_text(text: str, **kwargs: Any) -> dict[str, Any]:
    return get_nginx_analyzer().analyze_text(text, **kwargs)


def analyze_paths(paths: list[Union[str, Path]], **kwargs: Any) -> dict[str, Any]:
    return get_nginx_analyzer().analyze_paths(paths, **kwargs)


def analyze_files(
    files: list[tuple[str, BinaryIO]],
    **kwargs: Any,
) -> dict[str, Any]:
    return get_nginx_analyzer().analyze_uploads(files, **kwargs)
