"""
LLM enrichment for *already classified & grouped* nginx events.

Important:
- Does NOT inspect every log row with the model.
- Rules/tools own parse + classify + counts.
- LLM receives compact JSON (category, counts, ≤3 examples) and deepens analysis.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Optional

from agents.nginx_analyzer.models import AnalysisResult, EventGroup, Severity

logger = logging.getLogger("nginx_analyzer.llm")

_JSON_FENCE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.I)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def llm_analysis_enabled_default() -> bool:
    """Default on when key present, unless NGINX_ANALYZER_LLM=false."""
    raw = os.getenv("NGINX_ANALYZER_LLM")
    if raw is not None:
        return _env_bool("NGINX_ANALYZER_LLM", True)
    key = (os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY") or "").strip()
    return bool(key)


def _api_key() -> str:
    return (
        os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY") or os.getenv("HERMES_API_KEY") or ""
    ).strip()


def _max_groups() -> int:
    try:
        return max(1, min(30, int(os.getenv("NGINX_ANALYZER_LLM_MAX_GROUPS") or "15")))
    except ValueError:
        return 15


def _build_payload(result: AnalysisResult) -> dict[str, Any]:
    """Compact evidence package — never full log dump."""
    groups = result.groups[: _max_groups()]
    return {
        "total_log_entries": result.total_entries,
        "files": result.files,
        "overall_health_score_rule_based": result.health_score,
        "security_scan_lines": result.security_events,
        "blocked_attack_lines": result.blocked_attacks,
        "events": [
            {
                "id": i,
                "category": g.category,
                "severity": g.severity.value,
                "priority": g.priority.value,
                "occurrences": g.occurrences,
                "rule_description": g.description,
                "rule_root_cause": g.root_cause,
                "rule_impact": g.impact,
                "rule_recommendations": g.recommendations,
                "confidence_rule": g.confidence,
                "examples": g.examples[:3],
                "first_seen": g.first_seen,
                "last_seen": g.last_seen,
                "tags": {
                    "security_scan": g.is_security_scan,
                    "blocked_attack": g.is_blocked_attack,
                    "application_bug": g.is_application_bug,
                    "infrastructure": g.is_infrastructure,
                    "configuration": g.is_config,
                },
            }
            for i, g in enumerate(groups)
        ],
    }


def _extract_json(text: str) -> Optional[dict[str, Any]]:
    text = (text or "").strip()
    if not text:
        return None
    m = _JSON_FENCE.search(text)
    if m:
        text = m.group(1).strip()
    # raw object
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        pass
    # find first { ... last }
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            data = json.loads(text[start : end + 1])
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def enrich_with_llm(result: AnalysisResult) -> dict[str, Any]:
    """
    Mutates result.groups with LLM-refined narrative fields.
    Returns meta: {used, model, groups_enriched, error?}.
    """
    meta: dict[str, Any] = {
        "used": False,
        "model": None,
        "groups_enriched": 0,
        "mode": "group_level_not_per_row",
    }
    key = _api_key()
    if not key:
        meta["error"] = "OPENAI_API_KEY not set"
        return meta
    if not result.groups:
        meta["error"] = "no groups to enrich"
        return meta

    try:
        from langchain_core.messages import HumanMessage, SystemMessage
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        meta["error"] = f"langchain import failed: {exc}"
        return meta

    model = os.getenv("LLM_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-4.1"
    meta["model"] = model
    payload = _build_payload(result)

    system = """Siz Senior Linux System Administrator, Senior Nginx Engineer, PHP Expert, DevOps Engineer va Cybersecurity Analyst siz.

Sizga ALLAQACHON sinflangan nginx error log hodisalari keladi (tool/qoidalar guruhlagan).
Har bir raw log qatorini KO'RMAYSIZ — faqat toifa, sonlar va har birida max 3 misol.

Vazifa: har bir hodisani chuqurroq tahlil qiling va executive xulosa yozing.

MUHIM: Barcha matnli maydonlarni O'ZBEK TILIDA yozing (lotin yozuvida, professional texnik uslub).
Kategoriya nomlarini o'zbekcha qoldiring yoki qisqa o'zbekcha tushuntiring.

QAT'IY QOIDALAR:
1. Faqat JSON dagi dalillardan foydalaning. IP, CVE, hostname yoki logda yo'q voqeani o'ylab topmang.
2. Internet skanerlari (wp-admin, .env, phpmyadmin va hokazo) — HUJUM URINISHI / shovqin; server nosozligi yoki isbotlangan compromise EMAS.
3. ModSecurity / WAF rad etish — MUVAFFAQIYATLI BLOK; muvaffaqiyatli hujum EMAS.
4. Farqlang: skaner urinishi | bloklangan hujum | ilova xatosi | infratuzilma | konfiguratsiya.
5. Severity ni odatda saqlang (tool bergan).
6. Tavsiyalar aniq va amaliy bo'lsin (o'zbekcha).
7. Ishonchsiz bo'lsangiz confidence ni pasaytiring va tavsifda ayting.
8. Faqat BITTA JSON obyekt qaytaring (JSON tashqarisida markdown yo'q).

JSON sxema:
{
  "executive_summary": "2-4 paragraf, o'zbekcha, professional",
  "overall_assessment": "bitta jumla — umumiy holat (o'zbekcha)",
  "top_actions": ["...", "...", "..."],
  "events": [
    {
      "id": 0,
      "description": "o'zbekcha tavsif",
      "root_cause": "o'zbekcha ildiz sabab",
      "possible_impact": "o'zbekcha ta'sir",
      "recommended_actions": ["o'zbekcha chora", "..."],
      "confidence_score": 0-100,
      "analyst_notes": "ixtiyoriy qisqa izoh o'zbekcha"
    }
  ]
}
Har bir kirish event id uchun events[] yozuvi bo'lsin."""

    llm = ChatOpenAI(
        model=model,
        api_key=key,
        temperature=0,
        base_url=os.getenv("OPENAI_BASE_URL") or None,
    )

    try:
        msg = llm.invoke(
            [
                SystemMessage(content=system),
                HumanMessage(
                    content=(
                        "Quyidagi oldindan sinflangan nginx error hodisalarini tahlil qiling "
                        "va faqat JSON qaytaring. Barcha matn O'ZBEKCHA bo'lsin.\n\n"
                        + json.dumps(payload, ensure_ascii=False, indent=2)
                    )
                ),
            ]
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("LLM enrich invoke failed")
        meta["error"] = str(exc)[:500]
        return meta

    content = getattr(msg, "content", None) or str(msg)
    if isinstance(content, list):
        content = " ".join(
            b.get("text", str(b)) if isinstance(b, dict) else str(b) for b in content
        )
    data = _extract_json(str(content))
    if not data:
        meta["error"] = "LLM returned non-JSON or unparseable content"
        meta["raw_preview"] = str(content)[:400]
        return meta

    # Apply per-event enrichment
    events_out = data.get("events")
    if isinstance(events_out, list):
        by_id: dict[int, dict[str, Any]] = {}
        for item in events_out:
            if not isinstance(item, dict):
                continue
            try:
                eid = int(item.get("id"))
            except (TypeError, ValueError):
                continue
            by_id[eid] = item

        for i, g in enumerate(result.groups[: _max_groups()]):
            item = by_id.get(i)
            if not item:
                continue
            _apply_event_enrichment(g, item)
            meta["groups_enriched"] += 1

    exec_sum = (data.get("executive_summary") or "").strip()
    assessment = (data.get("overall_assessment") or "").strip()
    top_actions = data.get("top_actions") if isinstance(data.get("top_actions"), list) else []
    top_actions = [str(a).strip() for a in top_actions if str(a).strip()]

    result.llm_executive_summary = exec_sum
    result.llm_overall_assessment = assessment
    result.llm_top_actions = top_actions
    result.llm_used = True

    meta["used"] = True
    meta["has_executive_summary"] = bool(exec_sum)
    return meta


def _apply_event_enrichment(g: EventGroup, item: dict[str, Any]) -> None:
    desc = (item.get("description") or "").strip()
    root = (item.get("root_cause") or "").strip()
    impact = (item.get("possible_impact") or item.get("impact") or "").strip()
    notes = (item.get("analyst_notes") or "").strip()

    if desc:
        g.description = desc
    if root:
        g.root_cause = root
    if impact:
        g.impact = impact
    if notes:
        g.analyst_notes = notes

    recs = item.get("recommended_actions") or item.get("recommendations")
    if isinstance(recs, list) and recs:
        cleaned = [str(r).strip() for r in recs if str(r).strip()]
        if cleaned:
            g.recommendations = cleaned

    conf = item.get("confidence_score")
    if conf is not None:
        try:
            c = int(conf)
            g.confidence = max(0, min(100, c))
        except (TypeError, ValueError):
            pass

    g.llm_enriched = True
