"""Data models for Nginx error log analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Priority(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


SEVERITY_TO_PRIORITY = {
    Severity.CRITICAL: Priority.CRITICAL,
    Severity.HIGH: Priority.HIGH,
    Severity.MEDIUM: Priority.MEDIUM,
    Severity.LOW: Priority.LOW,
    Severity.INFO: Priority.INFORMATIONAL,
}

PRIORITY_ORDER = {
    Priority.CRITICAL: 0,
    Priority.HIGH: 1,
    Priority.MEDIUM: 2,
    Priority.LOW: 3,
    Priority.INFORMATIONAL: 4,
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class LogEntry:
    raw: str
    source_file: str
    line_no: int
    timestamp: Optional[str] = None
    level: Optional[str] = None  # emerg/alert/crit/error/warn/notice/info/debug
    pid: Optional[str] = None
    tid: Optional[str] = None
    message: str = ""
    client: Optional[str] = None
    server: Optional[str] = None
    request: Optional[str] = None
    host: Optional[str] = None
    upstream: Optional[str] = None
    referrer: Optional[str] = None


@dataclass
class CategoryProfile:
    category: str
    severity: Severity
    description: str
    root_cause: str
    impact: str
    recommendations: list[str]
    confidence: int  # 0-100 default for this category
    is_security_scan: bool = False
    is_blocked_attack: bool = False
    is_application_bug: bool = False
    is_infrastructure: bool = False
    is_config: bool = False


@dataclass
class EventGroup:
    category: str
    severity: Severity
    priority: Priority
    occurrences: int = 0
    description: str = ""
    root_cause: str = ""
    impact: str = ""
    recommendations: list[str] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)
    confidence: int = 70
    source_files: set[str] = field(default_factory=set)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    is_security_scan: bool = False
    is_blocked_attack: bool = False
    is_application_bug: bool = False
    is_infrastructure: bool = False
    is_config: bool = False
    fingerprint: str = ""
    llm_enriched: bool = False
    analyst_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "occurrences": self.occurrences,
            "severity": self.severity.value,
            "priority": self.priority.value,
            "description": self.description,
            "example_log_entries": self.examples[:3],
            "root_cause": self.root_cause,
            "possible_impact": self.impact,
            "recommended_actions": self.recommendations,
            "confidence_score": self.confidence,
            "source_files": sorted(self.source_files),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "llm_enriched": self.llm_enriched,
            "analyst_notes": self.analyst_notes or None,
            "tags": {
                "security_scan": self.is_security_scan,
                "blocked_attack": self.is_blocked_attack,
                "application_bug": self.is_application_bug,
                "infrastructure": self.is_infrastructure,
                "configuration": self.is_config,
            },
        }


@dataclass
class AnalysisResult:
    total_entries: int = 0
    parsed_entries: int = 0
    skipped_lines: int = 0
    files: list[str] = field(default_factory=list)
    groups: list[EventGroup] = field(default_factory=list)
    unknown_count: int = 0
    security_events: int = 0
    blocked_attacks: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    health_score: int = 100
    report_markdown: str = ""
    errors: list[str] = field(default_factory=list)
    llm_used: bool = False
    llm_executive_summary: str = ""
    llm_overall_assessment: str = ""
    llm_top_actions: list[str] = field(default_factory=list)
    llm_meta: dict[str, Any] = field(default_factory=dict)
    # Rasmiy kiberhujumlar jadvali (attack type counts + response)
    security_matrix: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_log_entries": self.total_entries,
            "parsed_entries": self.parsed_entries,
            "skipped_lines": self.skipped_lines,
            "files": self.files,
            "detected_categories": len(self.groups),
            "critical_issues": self.critical_count,
            "high_priority_issues": self.high_count,
            "medium_issues": self.medium_count,
            "low_issues": self.low_count,
            "informational": self.info_count,
            "security_events": self.security_events,
            "blocked_attacks": self.blocked_attacks,
            "unknown_events": self.unknown_count,
            "overall_health_score": self.health_score,
            "events": [g.to_dict() for g in self.groups],
            "security_matrix": self.security_matrix,
            "report_markdown": self.report_markdown,
            "errors": self.errors,
            "llm_used": self.llm_used,
            "llm_executive_summary": self.llm_executive_summary or None,
            "llm_overall_assessment": self.llm_overall_assessment or None,
            "llm_top_actions": self.llm_top_actions,
            "llm_meta": self.llm_meta,
        }
