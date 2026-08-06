"""
Rasmiy hisobot jadvali uchun kiberhujum turlari.

Jadval ustunlari (namuna format):
  1) Axborot uzatish tarmoqlaridagi kiberhujumlar soni (tur bo'yicha)
  2) Muhim infratuzilma kiberxavfsizlik hodisalari
  3) Korporativ tarmoq baxtsiz hodisa / uzilishlar
  4) Javob natijalari
  5) Eslatma
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from agents.nginx_analyzer.models import LogEntry

# Tartib rasmiy jadvaldagi kabi saqlanadi
ATTACK_TYPES: list[str] = [
    "PHP Injection hujumlar",
    "SQL Injection hujumlar",
    "URL Manipulatsiya hujumlar",
    "XSS hujumlar",
    "Vulnerability Scanning",
    "Web Shell / Backdoor probing",
    "Sensitive Data Exposure",
]

# (type_name, patterns) — birinchi mos kelgan g'olib
_ATTACK_RULES: list[tuple[str, re.Pattern[str]]] = [
    (
        "SQL Injection hujumlar",
        re.compile(
            r"sql\s*injection|union\s+select|or\s+1\s*=\s*1|and\s+1\s*=\s*1|"
            r"information_schema|sleep\s*\(|benchmark\s*\(|/\*\*/|"
            r"REQUEST-942|id\s*[\"']942\d{3}|libinjection|"
            r"'\s*or\s*'|\"\s*or\s*\"|waitfor\s+delay|xp_cmdshell",
            re.I,
        ),
    ),
    (
        "XSS hujumlar",
        re.compile(
            r"cross.?site|xss|<script|%3cscript|javascript:|onerror\s*=|"
            r"onload\s*=|svg/onload|document\.cookie|REQUEST-941|id\s*[\"']941\d{3}",
            re.I,
        ),
    ),
    (
        "PHP Injection hujumlar",
        re.compile(
            r"php\s*injection|eval-stdin|allow_url_include|auto_prepend_file|"
            r"php://input|php://filter|data://text/plain|"
            r"assert\s*\(|preg_replace\s*\(.*/e|create_function|"
            r"base64_decode\s*\(\s*['\"]|system\s*\(\s*\$_|"
            r"passthru\s*\(|shell_exec\s*\(|`.*\$_(GET|POST|REQUEST)",
            re.I,
        ),
    ),
    (
        "Web Shell / Backdoor probing",
        re.compile(
            r"/shell\.php|/c99\.php|/r57\.php|/wso\.php|/b374k|/filesman\.php|"
            r"/green\d*\.php|/dex\.php|/alfa\.php|/mini\.php|/cmd\.php|"
            r"/backdoor|/webshell|eval-stdin\.php|/upload\.php\b|"
            r"/indoxploit|/madspot|/configbak",
            re.I,
        ),
    ),
    (
        "Sensitive Data Exposure",
        re.compile(
            r"/\.env|\.env\.|/id_rsa|\.git/|/\.aws|/aws\.yml|/credentials|"
            r"/config\.json|/phpinfo|/phpmyadmin|/adminer\.php|/pma/|"
            r"/backup\.|/dump\.sql|/wp-config\.php|/web\.config|"
            r"/\.htpasswd|/\.DS_Store|/composer\.json",
            re.I,
        ),
    ),
    (
        "URL Manipulatsiya hujumlar",
        re.compile(
            r"\.\./|%2e%2e|%252e|/\./|/etc/passwd|/proc/self|"
            r"path.?traversal|directory.?traversal|"
            r"%00|null\s*byte|//\w+@|@127\.0\.0\.1|"
            r"REQUEST-930|id\s*[\"']930\d{3}",
            re.I,
        ),
    ),
    (
        "Vulnerability Scanning",
        re.compile(
            r"/wp-admin|/wp-login|/wp-content|/wp-includes|/xmlrpc\.php|"
            r"/phpunit|/vendor/phpunit|/cgi-bin|/boaform|/HNAP1|"
            r"/manager/html|/actuator|/solr/|/console/|/jenkins|"
            r"/hudson|/owa/auth|/autodiscover|/telescope|/_ignition|"
            r"/containers/json|/v2/_catalog|nikto|nmap|sqlmap|"
            r"masscan|zgrab|nuclei|dirbuster|gobuster|"
            r"modsecurity|inbound anomaly|access denied with code 403",
            re.I,
        ),
    ),
]

# Korporativ tarmoq uzilishi / baxtsiz hodisa (infra)
_OUTAGE_RE = re.compile(
    r"no live upstreams|out of memory|no space left|disk full|"
    r"worker process \d+ exited|too many open files|"
    r"all upstream servers are unavailable|"
    r"connect\(\) failed.*while connecting to upstream",
    re.I,
)

# Muhim infratuzilmada haqiqiy kiberxavfsizlik hodisasi (muvaffaqiyatli compromise dalili)
# Oddiy skaner/blok uchun ishlatilmaydi — faqat aniq "success" belgilari
_CRITICAL_INFRA_INCIDENT_RE = re.compile(
    r"webshell\s+uploaded|backdoor\s+installed|successful\s+exploit|"
    r"privilege\s+escalation|ransomware|data\s+exfiltration|"
    r"unauthorized\s+admin\s+login\s+success",
    re.I,
)

RESPONSE_BLOCKED = (
    "Hujum Firewall orqali muvaffaqiyatli bloklandi, "
    "Web application (Veb-sayt) barqaror ishlamoqda"
)

RESPONSE_ALL_BLOCKED = (
    "Barcha hujumlar Firewall orqali muvaffaqiyatli bloklandi, "
    "Web application (Veb-sayt) barqaror ishlamoqda"
)

RESPONSE_NONE = "Hodisa qayd etilmadi"

RESPONSE_OUTAGE = (
    "Infratuzilma / xizmat uzilishi belgilari aniqlandi; "
    "sabab tahlil qilindi, barqarorlikni tiklash choralari tavsiya etiladi"
)

RESPONSE_CRITICAL_INCIDENT = (
    "Ehtimoliy jiddiy kiberxavfsizlik hodisasi belgilari aniqlandi; "
    "qo'shimcha tekshiruv va incident response talab etiladi "
    "(avtomatik «bloklandi» deb baholanmadi)"
)

RESPONSE_MIXED = (
    "Qisman hujumlar Firewall orqali bloklandi; "
    "qisman infratuzilma yoki boshqa hodisalar qayd etildi — batafsil topilmalarga qarang"
)

RESPONSE_APP_ISSUE = (
    "Kiberhujum emas — ilova / konfiguratsiya xatosi logda qayd etilgan; "
    "Web application barqarorligi alohida tekshirilishi kerak"
)

# back-compat aliases
_DEFAULT_RESPONSE_BLOCKED = RESPONSE_BLOCKED
_DEFAULT_RESPONSE_ALL = RESPONSE_ALL_BLOCKED
_RESPONSE_OUTAGE = RESPONSE_OUTAGE


def response_for_attack_row(
    count: int,
    *,
    treated_as_blocked: bool = True,
) -> str:
    """
    Bitta hujum turi qatori uchun «Javob natijalari».
    0 ta hodisa → «Hodisa qayd etilmadi» (bloklandi deb yozilmaydi).
    """
    if count <= 0:
        return RESPONSE_NONE
    if treated_as_blocked:
        return RESPONSE_BLOCKED
    return RESPONSE_CRITICAL_INCIDENT


def response_for_total(
    total_attacks: int,
    *,
    corporate_outages: int = 0,
    critical_infra_incidents: int = 0,
    all_security_treated_blocked: bool = True,
) -> str:
    """Jami qatori uchun «Javob natijalari» — vaziyatga qarab."""
    if critical_infra_incidents > 0:
        return RESPONSE_CRITICAL_INCIDENT
    if total_attacks <= 0 and corporate_outages <= 0:
        return RESPONSE_NONE
    if total_attacks <= 0 and corporate_outages > 0:
        return RESPONSE_OUTAGE
    if total_attacks > 0 and corporate_outages > 0:
        return RESPONSE_MIXED
    if total_attacks > 0 and all_security_treated_blocked:
        return RESPONSE_ALL_BLOCKED
    if total_attacks > 0:
        return RESPONSE_MIXED
    return RESPONSE_NONE


@dataclass
class SecurityMatrixRow:
    no: int
    label: str  # "0 - PHP Injection hujumlar" yoki faqat tur
    network_attacks: int  # ustun 2
    critical_infra_incidents: int | str  # ustun 3 — son yoki "-"
    corporate_outages: int | str  # ustun 4
    response: str  # ustun 5
    note: str = ""  # ustun 6

    def display_network(self) -> str:
        if self.network_attacks <= 0 and self.label.startswith("0 -"):
            return self.label
        # "11 - SQL Injection hujumlar"
        base = self.label
        if " - " in base:
            # already has count prefix from builder
            return base
        return f"{self.network_attacks} - {base}"


@dataclass
class SecurityMatrix:
    """Rasmiy kiberhujumlar jadvali ma'lumotlari."""

    attack_counts: dict[str, int] = field(
        default_factory=lambda: {t: 0 for t in ATTACK_TYPES}
    )
    critical_infra_incidents: int = 0
    corporate_outages: int = 0
    blocked_security_events: int = 0
    total_security_classified: int = 0

    def add_attack(self, attack_type: str, n: int = 1) -> None:
        if attack_type not in self.attack_counts:
            self.attack_counts[attack_type] = 0
        self.attack_counts[attack_type] += n
        self.total_security_classified += n

    def total_attacks(self) -> int:
        return sum(self.attack_counts.values())

    def rows(self) -> list[SecurityMatrixRow]:
        rows: list[SecurityMatrixRow] = []
        # Skaner/WAF hodisalari odatda bloklangan urinish deb baholanadi;
        # faqat alohida «muvaffaqiyatli compromise» dalili bo'lsa — boshqacha.
        treated_blocked = self.critical_infra_incidents <= 0
        for i, t in enumerate(ATTACK_TYPES, start=1):
            cnt = int(self.attack_counts.get(t, 0))
            label = f"{cnt} - {t}"
            resp = response_for_attack_row(cnt, treated_as_blocked=treated_blocked)
            rows.append(
                SecurityMatrixRow(
                    no=i,
                    label=label,
                    network_attacks=cnt,
                    critical_infra_incidents="-",
                    corporate_outages="-",
                    response=resp,
                    note="",
                )
            )
        return rows

    def total_row(self) -> SecurityMatrixRow:
        total = self.total_attacks()
        return SecurityMatrixRow(
            no=0,
            label=str(total),
            network_attacks=total,
            critical_infra_incidents="-",
            corporate_outages="-",
            response=response_for_total(
                total,
                corporate_outages=self.corporate_outages,
                critical_infra_incidents=self.critical_infra_incidents,
                all_security_treated_blocked=self.critical_infra_incidents <= 0,
            ),
            note="",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_counts": dict(self.attack_counts),
            "total_attacks": self.total_attacks(),
            "critical_infra_incidents": self.critical_infra_incidents,
            "corporate_outages": self.corporate_outages,
            "blocked_security_events": self.blocked_security_events,
            "rows": [
                {
                    "no": r.no,
                    "network_column": r.label,
                    "critical_infra": r.critical_infra_incidents,
                    "corporate_outages": r.corporate_outages,
                    "response": r.response,
                    "note": r.note,
                    "count": r.network_attacks,
                }
                for r in self.rows()
            ],
            "total": {
                "network_column": str(self.total_attacks()),
                "response": _DEFAULT_RESPONSE_ALL,
            },
        }


def classify_attack_type(text: str) -> Optional[str]:
    """Log matnidan hujum turini aniqlash (birinchi mos kelgan)."""
    if not text:
        return None
    for name, pat in _ATTACK_RULES:
        if pat.search(text):
            return name
    return None


def is_outage_event(text: str) -> bool:
    return bool(text and _OUTAGE_RE.search(text))


def is_critical_infra_incident(text: str) -> bool:
    return bool(text and _CRITICAL_INFRA_INCIDENT_RE.search(text))


def classify_entry_for_matrix(
    entry: LogEntry,
    *,
    is_security_scan: bool,
    is_blocked_attack: bool,
    is_infrastructure: bool = False,
    category: str = "",
) -> tuple[Optional[str], bool, bool]:
    """
    Returns (attack_type|None, is_outage, is_critical_infra_incident).
    """
    blob = " ".join(
        [
            entry.message or "",
            entry.request or "",
            entry.raw or "",
            category or "",
        ]
    )
    attack: Optional[str] = None
    if is_security_scan or is_blocked_attack:
        attack = classify_attack_type(blob)
        if attack is None:
            # Umumiy skaner / WAF — Vulnerability Scanning ga
            attack = "Vulnerability Scanning"

    outage = is_outage_event(blob) or (
        is_infrastructure
        and any(
            k in (category or "").lower()
            for k in (
                "upstream",
                "xotira",
                "disk",
                "worker",
                "timeout",
                "crash",
                "resurs",
            )
        )
    )
    # Outage ni alohida sanash; security scan bilan chalkashtirmaslik
    if is_security_scan or is_blocked_attack:
        outage = False

    crit = is_critical_infra_incident(blob)
    return attack, outage, crit
