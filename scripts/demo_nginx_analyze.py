#!/usr/bin/env python3
"""Smoke demo: analyze sample nginx error.log and print report summary."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
except Exception:
    pass

from agents.nginx_analyzer import analyze_paths  # noqa: E402


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Nginx error.log analyzer demo")
    ap.add_argument(
        "--no-llm",
        action="store_true",
        help="Rules only (no LLM enrichment)",
    )
    ap.add_argument(
        "--llm",
        action="store_true",
        help="Force LLM group enrichment",
    )
    args = ap.parse_args()
    use_llm: bool | None
    if args.no_llm:
        use_llm = False
    elif args.llm:
        use_llm = True
    else:
        use_llm = None  # service default

    sample = ROOT / "data" / "samples" / "nginx_error_sample.log"
    if not sample.is_file():
        print("sample missing:", sample)
        return 1
    result = analyze_paths([sample], use_llm=use_llm)
    print("success:", result.get("success"))
    print("entries:", result.get("total_log_entries"))
    print("categories:", result.get("detected_categories"))
    print("health:", result.get("overall_health_score"))
    print("llm_used:", result.get("llm_used"), result.get("llm_meta"))
    print("critical:", result.get("critical_issues"), "high:", result.get("high_priority_issues"))
    print("security_events:", result.get("security_events"))
    print("blocked_attacks:", result.get("blocked_attacks"))
    md = result.get("report_markdown") or ""
    out = ROOT / "logs" / "nginx_sample_report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    print("events:")
    for e in result.get("events") or []:
        mark = "LLM" if e.get("llm_enriched") else "rules"
        print(
            f"  [{e.get('severity')}] {e.get('occurrences')}x {e.get('category')} ({mark})"
        )
    print("wrote", out)
    return 0 if result.get("success") else 2


if __name__ == "__main__":
    raise SystemExit(main())
