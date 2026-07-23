"""O'zbekcha professional Markdown incident hisobotlari."""

from __future__ import annotations

from agents.nginx_analyzer.models import AnalysisResult, EventGroup, Severity

_PRIORITY_UZ = {
    "Critical": "Kritik",
    "High": "Yuqori",
    "Medium": "O'rta",
    "Low": "Past",
    "Informational": "Axborot",
}

_SEVERITY_UZ = {
    "CRITICAL": "KRITIK",
    "HIGH": "YUQORI",
    "MEDIUM": "O'RTA",
    "LOW": "PAST",
    "INFO": "AXBOROT",
}


def _pri(g: EventGroup) -> str:
    return _PRIORITY_UZ.get(g.priority.value, g.priority.value)


def _sev(g: EventGroup) -> str:
    return _SEVERITY_UZ.get(g.severity.value, g.severity.value)


def render_report(result: AnalysisResult) -> str:
    lines: list[str] = []
    a = lines.append

    a("====================================")
    a("SERVER SOG'LOMLIK HISOBOTI")
    a("Nginx Error Log tahlili")
    a("====================================")
    a("")
    a("> **hermes_security_agent** · Nginx Error Log Analyzer")
    a("> Faqat logdagi dalillar asosida — o'ylab topilgan voqealar yo'q.")
    a("")

    a("## Qisqacha xulosa")
    a("")
    if result.llm_used and result.llm_executive_summary:
        a("### AI tahlilchi xulosasi")
        a("")
        a(result.llm_executive_summary.strip())
        a("")
        if result.llm_overall_assessment:
            a(f"**Baholash:** {result.llm_overall_assessment.strip()}")
            a("")
        if result.llm_top_actions:
            a("**Ustuvor chora-tadbirlar (AI):**")
            for i, act in enumerate(result.llm_top_actions[:8], 1):
                a(f"{i}. {act}")
            a("")
        a(
            "_Sonlar va jiddiylik darajasi qoidalar bilan tekshirilgan; "
            "matnli tahlil LLM yordamida boyitilgan._"
        )
        a("")

    a("### Miqdoriy ko'rsatkichlar")
    a("")
    a("| Ko'rsatkich | Qiymat |")
    a("|-------------|-------:|")
    a(f"| Jami log qatorlari | {result.total_entries} |")
    a(f"| Tahlil qilingan qatorlar | {result.parsed_entries} |")
    a(f"| Fayllar soni | {len(result.files)} |")
    a(f"| Aniqlangan toifalar | {len(result.groups)} |")
    a(f"| Kritik muammolar (toifa) | {result.critical_count} |")
    a(f"| Yuqori ustuvorlik | {result.high_count} |")
    a(f"| O'rta | {result.medium_count} |")
    a(f"| Past | {result.low_count} |")
    a(f"| Axborot | {result.info_count} |")
    a(f"| Xavfsizlik skanerlari (qator) | {result.security_events} |")
    a(f"| Bloklangan hujumlar (qator) | {result.blocked_attacks} |")
    a(f"| Noma'lum hodisalar (qator) | {result.unknown_count} |")
    a(f"| **Umumiy sog'lomlik balli** | **{result.health_score} / 100** |")
    a("")

    if result.files:
        a("**Manba fayllar:**")
        for f in result.files:
            a(f"- `{f}`")
        a("")

    a("### Umumiy sog'lomlik balli")
    a("")
    a(f"## {result.health_score} / 100")
    a("")
    a(_score_label(result.health_score))
    a("")

    for title, sev in [
        ("Kritik", Severity.CRITICAL),
        ("Yuqori", Severity.HIGH),
        ("O'rta", Severity.MEDIUM),
        ("Past", Severity.LOW),
        ("Axborot", Severity.INFO),
    ]:
        items = [g for g in result.groups if g.severity == sev]
        a(f"**{title}**")
        if not items:
            a("- Aniqlanmadi")
        else:
            for g in items:
                a(f"- {g.occurrences}x {g.category}")
        a("")

    a("### Asosiy tavsiyalar")
    a("")
    recs = _top_recommendations(result)
    if not recs:
        a("- Ushbu loglardan shoshilinch chora-tadbir chiqmadi.")
    else:
        for i, rec in enumerate(recs, 1):
            a(f"{i}. {rec}")
    a("")

    a("---")
    a("")
    a("## Muhim farqlar")
    a("")
    a("| Turi | Ma'nosi |")
    a("|------|---------|")
    a("| **Hujum urinishi / skaner** | Tekshiruv trafik; komprometatsiya isboti emas |")
    a("| **Bloklangan hujum** | WAF/ModSecurity so'rovni rad etgan |")
    a("| **Muvaffaqiyatli buzilish** | Qo'shimcha dalil kerak (faqat skanerdan chiqarilmaydi) |")
    a("| **Ilova xatosi** | PHP/koddagi nuqson |")
    a("| **Infratuzilma** | Upstream, xotira, disk, tarmoq, process crash |")
    a("| **Konfiguratsiya** | nginx/PHP limitlari, yo'llar, sertifikat, DNS |")
    a("")

    a("---")
    a("")
    a("## Batafsil topilmalar")
    a("")
    a("Hodisalar ustuvorlik bo'yicha tartiblangan (Kritik → Axborot), keyin hajm bo'yicha.")
    a("")

    if not result.groups:
        a("_Berilgan loglarda sinflashtiriladigan hodisa topilmadi._")
        a("")
    else:
        for idx, g in enumerate(result.groups, 1):
            lines.extend(_render_group(idx, g))

    a("---")
    a("")
    a("## Metodologiya")
    a("")
    a("- Qatorlar oqim bilan o'qiladi va aniq imzolar (regex) bilan sinflanadi (100MB+ uchun mos).")
    a("- O'xshash hodisalar **guruhlanadi**; har toifada ko'pi bilan **3 ta misol** ko'rsatiladi.")
    a("- Internet skanerlari (WordPress, `.env`, `phpMyAdmin` va hokazo) — "
      "**Xavfsizlik skaneri / PAST**, server nosozligi emas.")
    a("- ModSecurity rad etishlari — **ModSecurity bloki / AXBOROT** (muvaffaqiyatli himoya).")
    a("- Ishonch foizi imzo kuchini bildiradi; past ishonchli **Noma'lum**larni qo'lda ko'rib chiqing.")
    a("- Hisobot logda bo'lmagan voqeani o'ylab topmaydi.")
    a("")
    a("====================================")
    a("HISOBOT YAKUNI")
    a("====================================")
    a("")

    return "\n".join(lines)


def _score_label(score: int) -> str:
    if score >= 90:
        return "_Holat: Sog'lom — asosan axborot yoki kichik shovqin._"
    if score >= 75:
        return "_Holat: Qoniqarli — yuqori/o'rta bandlarga e'tibor tavsiya etiladi._"
    if score >= 50:
        return "_Holat: Pasaygan — yuqori ustuvorlikdagi muammolar bor._"
    if score >= 25:
        return "_Holat: Yomon — kritik/yuqori muammolar xizmatga ta'sir qilishi mumkin._"
    return "_Holat: Kritik — zudlik bilan incident response tavsiya etiladi._"


def _top_recommendations(result: AnalysisResult, limit: int = 8) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for g in result.groups:
        if g.is_security_scan and not g.is_blocked_attack:
            continue
        for rec in g.recommendations:
            key = rec.strip().lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(f"**[{_pri(g)} · {g.category}]** {rec}")
            if len(out) >= limit:
                return out
    if not out:
        for g in result.groups:
            if g.is_security_scan or g.is_blocked_attack:
                for rec in g.recommendations[:2]:
                    key = rec.strip().lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(rec)
                    if len(out) >= limit:
                        return out
    return out


def _render_group(idx: int, g: EventGroup) -> list[str]:
    a: list[str] = []
    a.append(f"### {idx}. {g.category}")
    a.append("")
    a.append("| Maydon | Qiymat |")
    a.append("|--------|--------|")
    a.append(f"| **Toifa** | {g.category} |")
    a.append(f"| **Takrorlanish** | {g.occurrences} |")
    a.append(f"| **Jiddiylik** | {_sev(g)} |")
    a.append(f"| **Ustuvorlik** | {_pri(g)} |")
    a.append(f"| **Ishonch** | {g.confidence}% |")
    if g.first_seen or g.last_seen:
        a.append(f"| **Birinchi ko'rinish** | {g.first_seen or '—'} |")
        a.append(f"| **Oxirgi ko'rinish** | {g.last_seen or '—'} |")
    if g.source_files:
        a.append(
            f"| **Manbalar** | {', '.join(f'`{s}`' for s in sorted(g.source_files))} |"
        )
    tags = []
    if g.is_security_scan:
        tags.append("xavfsizlik-skaneri")
    if g.is_blocked_attack:
        tags.append("bloklangan-hujum")
    if g.is_application_bug:
        tags.append("ilova-xatosi")
    if g.is_infrastructure:
        tags.append("infratuzilma")
    if g.is_config:
        tags.append("konfiguratsiya")
    if tags:
        a.append(f"| **Teglar** | {', '.join(tags)} |")
    a.append(
        f"| **Tahlil manbai** | "
        f"{'Qoidalar + LLM' if g.llm_enriched else 'Faqat qoidalar'} |"
    )
    a.append("")
    a.append("#### Tavsif")
    a.append("")
    a.append(g.description)
    a.append("")
    a.append("#### Misol log qatorlari")
    a.append("")
    if not g.examples:
        a.append("_Misol saqlanmagan._")
    else:
        for ex in g.examples[:3]:
            a.append("```")
            a.append(ex[:2000])
            a.append("```")
    a.append("")
    a.append("#### Ildiz sabab")
    a.append("")
    a.append(g.root_cause)
    a.append("")
    a.append("#### Mumkin bo'lgan ta'sir")
    a.append("")
    a.append(g.impact)
    a.append("")
    a.append("#### Tavsiya etilgan chora-tadbirlar")
    a.append("")
    for rec in g.recommendations:
        a.append(f"- {rec}")
    a.append("")
    if g.analyst_notes:
        a.append("#### Tahlilchi izohlari (LLM)")
        a.append("")
        a.append(g.analyst_notes)
        a.append("")
    a.append(f"**Ishonch balli:** {g.confidence}%")
    a.append("")
    a.append("---")
    a.append("")
    return a
