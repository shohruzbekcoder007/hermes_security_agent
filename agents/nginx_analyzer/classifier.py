"""Classify and group Nginx log entries."""

from __future__ import annotations

import hashlib
import re
from collections import OrderedDict
from collections.abc import Iterable
from typing import Optional

from agents.nginx_analyzer.models import (
    PRIORITY_ORDER,
    SEVERITY_ORDER,
    SEVERITY_TO_PRIORITY,
    AnalysisResult,
    CategoryProfile,
    EventGroup,
    LogEntry,
    Severity,
)
from agents.nginx_analyzer.i18n_uz import localize_profile
from agents.nginx_analyzer.patterns import (
    SECURITY_SCAN_PROFILE,
    UNKNOWN_PROFILE,
    is_security_path,
    match_rule,
)

_MAX_EXAMPLES = 3
_NORMALIZE_NUM = re.compile(r"\b\d+\b")
_NORMALIZE_IP = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|"
    r"\b[0-9a-f:]{2,}\b",
    re.I,
)
_NORMALIZE_PID = re.compile(r"\b\d+#\d+\b")
_NORMALIZE_CONN = re.compile(r"\*\d+")


def _search_blob(entry: LogEntry) -> str:
    parts = [entry.message or "", entry.request or "", entry.raw or ""]
    return " ".join(parts)


def _fingerprint(category: str, entry: LogEntry, rule_id: str) -> str:
    """Stable key for grouping similar events."""
    base = entry.message or entry.raw
    # Strip variable parts
    norm = _NORMALIZE_IP.sub("<ip>", base)
    norm = _NORMALIZE_PID.sub("<pid>", norm)
    norm = _NORMALIZE_CONN.sub("*<n>", norm)
    norm = _NORMALIZE_NUM.sub("<n>", norm)
    # Keep request path template for security scans
    req = entry.request or ""
    path = ""
    m = re.search(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s"]+)', req, re.I)
    if m:
        path = _NORMALIZE_NUM.sub("<n>", m.group(1).split("?")[0])
    key = f"{category}|{rule_id}|{path}|{norm[:240]}"
    return hashlib.sha1(key.encode("utf-8", errors="ignore")).hexdigest()[:16]


def classify_entry(entry: LogEntry) -> tuple[str, CategoryProfile, str]:
    """
    Returns (rule_id, profile, fingerprint).
    Security path probes win only when no stronger infrastructure signal matches first —
    match_rule is checked first; security path is a specialized override for noise.
    """
    blob = _search_blob(entry)
    path_hit = is_security_path(blob) or is_security_path(entry.request or "")

    # ModSecurity / critical infra first via RULES
    matched = match_rule(blob)
    if matched:
        rule_id, profile = matched
        # If it's a plain file-not-found / open() failed on a scanner path → Security Scan
        if path_hit and profile.category in {
            "File Not Found",
            "Fayl topilmadi",
            "Permission Error",
            "Ruxsat xatosi",
        }:
            # Permission on sensitive path still HIGH if real — keep Permission Error
            if profile.category in {"File Not Found", "Fayl topilmadi"}:
                profile = SECURITY_SCAN_PROFILE
                rule_id = "security_scan_path"
        profile = localize_profile(rule_id, profile)
        return rule_id, profile, _fingerprint(profile.category, entry, rule_id)

    if path_hit:
        profile = localize_profile("security_scan_path", SECURITY_SCAN_PROFILE)
        return (
            "security_scan_path",
            profile,
            _fingerprint(profile.category, entry, "security_scan_path"),
        )

    # Level-based soft fallback
    level = (entry.level or "").lower()
    if level in {"crit", "alert", "emerg"}:
        profile = CategoryProfile(
            category="Unknown",
            severity=Severity.HIGH,
            description=UNKNOWN_PROFILE.description
            + f" Nginx darajasi: [{level}].",
            root_cause=UNKNOWN_PROFILE.root_cause,
            impact=UNKNOWN_PROFILE.impact,
            recommendations=list(UNKNOWN_PROFILE.recommendations),
            confidence=45,
            is_infrastructure=True,
        )
        profile = localize_profile("unknown_high", profile)
        return "unknown_high", profile, _fingerprint(profile.category, entry, "unknown_high")

    profile = localize_profile("unknown", UNKNOWN_PROFILE)
    return (
        "unknown",
        profile,
        _fingerprint(profile.category, entry, "unknown"),
    )


def analyze_entries(
    entries: Iterable[LogEntry],
    *,
    files: Optional[list[str]] = None,
) -> AnalysisResult:
    groups: OrderedDict[str, EventGroup] = OrderedDict()
    total = 0
    parsed = 0

    for entry in entries:
        total += 1
        if not (entry.message or entry.raw):
            continue
        parsed += 1
        rule_id, profile, fp = classify_entry(entry)
        key = fp

        if key not in groups:
            groups[key] = EventGroup(
                category=profile.category,
                severity=profile.severity,
                priority=SEVERITY_TO_PRIORITY[profile.severity],
                description=profile.description,
                root_cause=profile.root_cause,
                impact=profile.impact,
                recommendations=list(profile.recommendations),
                confidence=profile.confidence,
                is_security_scan=profile.is_security_scan,
                is_blocked_attack=profile.is_blocked_attack,
                is_application_bug=profile.is_application_bug,
                is_infrastructure=profile.is_infrastructure,
                is_config=profile.is_config,
                fingerprint=fp,
            )
        g = groups[key]
        g.occurrences += 1
        g.source_files.add(entry.source_file)
        if entry.timestamp:
            if not g.first_seen:
                g.first_seen = entry.timestamp
            g.last_seen = entry.timestamp
        if len(g.examples) < _MAX_EXAMPLES:
            example = entry.raw.strip()
            if example and example not in g.examples:
                g.examples.append(example)
        # Keep higher confidence if duplicate profiles disagree
        g.confidence = max(g.confidence, profile.confidence)

    # Merge groups with same category for executive rollup? Keep fine-grained groups
    # but also produce category rollup in report. For API events list, merge by category
    # for cleaner reports when fingerprints explode.
    merged = _merge_by_category(list(groups.values()))

    result = AnalysisResult(
        total_entries=total,
        parsed_entries=parsed,
        skipped_lines=max(0, total - parsed),
        files=list(files or []),
        groups=merged,
    )
    _compute_stats(result)
    return result


def _merge_by_category(groups: list[EventGroup]) -> list[EventGroup]:
    """Merge fingerprints that share category into one category bucket."""
    by_cat: OrderedDict[str, EventGroup] = OrderedDict()
    for g in groups:
        cat = g.category
        if cat not in by_cat:
            by_cat[cat] = EventGroup(
                category=g.category,
                severity=g.severity,
                priority=g.priority,
                occurrences=0,
                description=g.description,
                root_cause=g.root_cause,
                impact=g.impact,
                recommendations=list(g.recommendations),
                confidence=g.confidence,
                is_security_scan=g.is_security_scan,
                is_blocked_attack=g.is_blocked_attack,
                is_application_bug=g.is_application_bug,
                is_infrastructure=g.is_infrastructure,
                is_config=g.is_config,
                fingerprint=g.fingerprint,
            )
        m = by_cat[cat]
        m.occurrences += g.occurrences
        m.source_files |= g.source_files
        m.confidence = max(m.confidence, g.confidence)
        # Prefer worse severity if mixed
        if SEVERITY_ORDER[g.severity] < SEVERITY_ORDER[m.severity]:
            m.severity = g.severity
            m.priority = g.priority
            m.description = g.description
            m.root_cause = g.root_cause
            m.impact = g.impact
            m.recommendations = list(g.recommendations)
        if g.first_seen and (not m.first_seen or g.first_seen < m.first_seen):
            m.first_seen = g.first_seen
        if g.last_seen and (not m.last_seen or g.last_seen > m.last_seen):
            m.last_seen = g.last_seen
        for ex in g.examples:
            if len(m.examples) >= _MAX_EXAMPLES:
                break
            if ex not in m.examples:
                m.examples.append(ex)
        # Union flags
        m.is_security_scan = m.is_security_scan or g.is_security_scan
        m.is_blocked_attack = m.is_blocked_attack or g.is_blocked_attack
        m.is_application_bug = m.is_application_bug or g.is_application_bug
        m.is_infrastructure = m.is_infrastructure or g.is_infrastructure
        m.is_config = m.is_config or g.is_config

    ordered = sorted(
        by_cat.values(),
        key=lambda x: (
            PRIORITY_ORDER[x.priority],
            -x.occurrences,
            x.category.lower(),
        ),
    )
    return ordered


def _compute_stats(result: AnalysisResult) -> None:
    for g in result.groups:
        if g.severity == Severity.CRITICAL:
            result.critical_count += 1
        elif g.severity == Severity.HIGH:
            result.high_count += 1
        elif g.severity == Severity.MEDIUM:
            result.medium_count += 1
        elif g.severity == Severity.LOW:
            result.low_count += 1
        else:
            result.info_count += 1
        if g.is_security_scan:
            result.security_events += g.occurrences
        if g.is_blocked_attack:
            result.blocked_attacks += g.occurrences
        if g.category == "Unknown":
            result.unknown_count += g.occurrences

    result.health_score = _health_score(result)


def _health_score(result: AnalysisResult) -> int:
    """
    Start at 100; subtract weighted penalties.
    Security scans and ModSecurity blocks barely affect score.
    """
    score = 100.0
    for g in result.groups:
        n = g.occurrences
        # Diminishing returns for high volume noise
        weight = min(n, 50) + max(0, n - 50) ** 0.5
        if g.is_security_scan or g.is_blocked_attack:
            score -= min(3.0, weight * 0.01)
            continue
        if g.severity == Severity.CRITICAL:
            score -= min(40.0, 12.0 + weight * 0.4)
        elif g.severity == Severity.HIGH:
            score -= min(25.0, 6.0 + weight * 0.25)
        elif g.severity == Severity.MEDIUM:
            score -= min(12.0, 2.0 + weight * 0.1)
        elif g.severity == Severity.LOW:
            score -= min(5.0, 0.5 + weight * 0.02)
        else:
            score -= min(2.0, weight * 0.01)
    return max(0, min(100, int(round(score))))
