"""
Classification rules for Nginx error.log lines.

Order matters: first matching rule wins. More specific patterns first.
"""

from __future__ import annotations

import re
from typing import Optional

from agents.nginx_analyzer.models import CategoryProfile, Severity

# ---------------------------------------------------------------------------
# Security scanner path signatures (URI / request path)
# ---------------------------------------------------------------------------

SECURITY_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.I)
    for p in [
        r"/wp-admin",
        r"/wp-login\.php",
        r"/wp-content",
        r"/wp-includes",
        r"/xmlrpc\.php",
        r"/\.env",
        r"/\.git",
        r"/vendor/phpunit",
        r"/phpunit",
        r"/shell\.php",
        r"/green\d*\.php",
        r"/dex\.php",
        r"/c99\.php",
        r"/r57\.php",
        r"/adminer\.php",
        r"/phpmyadmin",
        r"/pma/",
        r"/myadmin",
        r"/cgi-bin/",
        r"/boaform/",
        r"/HNAP1",
        r"/manager/html",
        r"/actuator",
        r"/solr/",
        r"/console/",
        r"/\.aws/",
        r"/aws\.yml",
        r"/config\.json",
        r"/debug/default",
        r"/telescope",
        r"/_ignition",
        r"/eval-stdin\.php",
        r"/alfacgiapi",
        r"/cgi-bin/luci",
        r"/setup\.cgi",
        r"/GponForm",
        r"/hudson",
        r"/jenkins",
        r"/owa/auth",
        r"/autodiscover",
        r"/\.well-known/security\.txt",
        r"/vendor/phpunit/phpunit",
        r"/containers/json",
        r"/v2/_catalog",
    ]
]

# ---------------------------------------------------------------------------
# Classification rules: (name, compiled regex on full line or message, profile)
# ---------------------------------------------------------------------------


def _prof(
    category: str,
    severity: Severity,
    description: str,
    root_cause: str,
    impact: str,
    recommendations: list[str],
    confidence: int = 85,
    **flags: bool,
) -> CategoryProfile:
    return CategoryProfile(
        category=category,
        severity=severity,
        description=description,
        root_cause=root_cause,
        impact=impact,
        recommendations=recommendations,
        confidence=confidence,
        is_security_scan=flags.get("is_security_scan", False),
        is_blocked_attack=flags.get("is_blocked_attack", False),
        is_application_bug=flags.get("is_application_bug", False),
        is_infrastructure=flags.get("is_infrastructure", False),
        is_config=flags.get("is_config", False),
    )


# Each rule: (id, regex on lowercased message+request, profile, optional fingerprint key extract)
Rule = tuple[str, re.Pattern[str], CategoryProfile]

RULES: list[Rule] = [
    # --- ModSecurity (before generic 403) ---
    (
        "modsec_anomaly",
        re.compile(
            r"modsecurity|mod_security|inbound anomaly score|access denied with code 403|"
            r"\[client .*\] ModSecurity|OWASP_CRS|id \"9\d{5}\"",
            re.I,
        ),
        _prof(
            "ModSecurity Block",
            Severity.INFO,
            "Web application firewall (ModSecurity) denied a request based on security rules.",
            "Request matched a ModSecurity/CRS rule (SQLi, XSS, scanners, protocol anomalies, etc.).",
            "No application impact if blocks are expected; legitimate traffic may be blocked if rules are too strict (false positives).",
            [
                "Review ModSecurity audit log for rule IDs and false positives.",
                "Tune or whitelist only verified legitimate business paths.",
                "Keep CRS rules updated; do not disable WAF globally.",
            ],
            confidence=92,
            is_blocked_attack=True,
        ),
    ),
    # --- Memory / disk / resources ---
    (
        "oom",
        re.compile(r"out of memory|cannot allocate memory|oom|memory exhausted|enomem", re.I),
        _prof(
            "Memory Exhausted",
            Severity.CRITICAL,
            "Process or system ran out of available memory.",
            "RAM/cgroup limit reached; possible memory leak, traffic spike, or undersized instance.",
            "Worker crashes, 502/504 errors, full site outage risk.",
            [
                "Check free -h, dmesg OOM killer, and cgroup memory limits.",
                "Raise PHP-FPM/nginx memory limits only after finding leaks.",
                "Add monitoring/alerts on memory usage.",
            ],
            confidence=95,
            is_infrastructure=True,
        ),
    ),
    (
        "disk_full",
        re.compile(r"no space left on device|disk full|enospc", re.I),
        _prof(
            "Disk Full",
            Severity.CRITICAL,
            "Filesystem has no free space for writes (logs, temp, sessions, uploads).",
            "Disk filled by logs, backups, uploads, or runaway temp files.",
            "Cannot write logs, sessions, or uploads; application and logging failures.",
            [
                "df -h and du -sh /*; clear old logs and temp files.",
                "Rotate/compress logs; expand volume if capacity is legitimately used.",
            ],
            confidence=98,
            is_infrastructure=True,
        ),
    ),
    (
        "too_many_files",
        re.compile(r"too many open files|emfile", re.I),
        _prof(
            "Resource Exhaustion",
            Severity.CRITICAL,
            "Process hit open file descriptor limit (ulimit -n).",
            "Too many concurrent connections/files; low nofile limit or FD leak.",
            "New connections fail; intermittent 5xx under load.",
            [
                "Increase worker_rlimit_nofile and system nofile limits.",
                "Audit connection reuse and upstream keepalives.",
            ],
            confidence=93,
            is_infrastructure=True,
        ),
    ),
    # --- Worker crashes ---
    (
        "worker_crash",
        re.compile(
            r"worker process \d+ exited on signal|worker process \d+ exited with code|"
            r"exited on signal 1[12]|segmentation fault|core dumped",
            re.I,
        ),
        _prof(
            "Worker Process Crash",
            Severity.CRITICAL,
            "Nginx worker process terminated abnormally.",
            "Bug in nginx module, bad third-party module, OOM kill, or corrupted state.",
            "Brief connection drops; repeated crashes can cause service instability.",
            [
                "Check dmesg/journal for OOM or segfaults.",
                "Reproduce with recent config/module changes; try without third-party modules.",
                "Ensure nginx/openssl versions are patched.",
            ],
            confidence=90,
            is_infrastructure=True,
        ),
    ),
    # --- PHP language errors (must run before FastCGI/upstream generics) ---
    (
        "php_fatal",
        re.compile(
            r"PHP Fatal error|PHP Parse error|Uncaught (Error|Exception|TypeError|ValueError)|"
            r"Allowed memory size of \d+ bytes exhausted|"
            r"Maximum execution time of \d+ seconds exceeded|"
            r"Call to undefined function|Call to undefined method|Call to a member function",
            re.I,
        ),
        _prof(
            "PHP Fatal Error",
            Severity.CRITICAL,
            "PHP fatal or uncaught error stopped request execution.",
            "Application bug, missing dependency, memory_limit, or max_execution_time.",
            "Affected endpoints return 500; features broken for users.",
            [
                "Open the file/line from the log; fix the underlying bug.",
                "Increase memory_limit only after ruling out leaks.",
                "Add monitoring on PHP-FPM error rate.",
            ],
            confidence=95,
            is_application_bug=True,
        ),
    ),
    (
        "php_parse",
        re.compile(r"PHP Parse error|syntax error, unexpected", re.I),
        _prof(
            "PHP Parse Error",
            Severity.CRITICAL,
            "PHP could not parse a script due to syntax error.",
            "Bad deploy, incomplete file write, or PHP version mismatch.",
            "Entire script fails; 500 on all hits to that file.",
            [
                "Fix syntax at the reported file:line.",
                "Ensure deploy is atomic; match PHP version with codebase.",
            ],
            confidence=96,
            is_application_bug=True,
        ),
    ),
    (
        "php_deprecated",
        re.compile(r"PHP Deprecated:|deprecated:", re.I),
        _prof(
            "PHP Deprecated",
            Severity.LOW,
            "Code uses a feature deprecated in the current PHP version.",
            "Legacy code not yet updated for the running PHP version.",
            "Works today but will break on future PHP upgrades.",
            [
                "Plan remediation before next PHP major upgrade.",
                "Suppress only temporarily; prefer fixing call sites.",
            ],
            confidence=90,
            is_application_bug=True,
        ),
    ),
    (
        "php_warning",
        re.compile(
            r"PHP Warning:|Warning:.*(Undefined array key|Undefined variable|"
            r"Trying to access array offset|Division by zero|failed to open stream)",
            re.I,
        ),
        _prof(
            "PHP Warning",
            Severity.MEDIUM,
            "PHP warning indicates likely application defect under some inputs.",
            "Missing validation, bad assumptions about array keys/variables, or I/O failures.",
            "May degrade data quality or lead to fatals later; noisy logs.",
            [
                "Fix undefined keys/variables with proper validation/defaults.",
                "Reduce log noise after root-cause fix.",
            ],
            confidence=88,
            is_application_bug=True,
        ),
    ),
    (
        "php_notice",
        re.compile(
            r"PHP Notice:|Notice:.*(Undefined index|Undefined offset|Undefined variable|"
            r"Trying to get property|Trying to access array offset)",
            re.I,
        ),
        _prof(
            "PHP Notice",
            Severity.LOW,
            "PHP notice for non-fatal coding issues (undefined index/offset/property).",
            "Missing isset/?? checks or optional fields not handled.",
            "Usually not user-visible immediately; pollutes logs and may hide real issues.",
            [
                "Add null-safe access and input validation.",
                "Raise coding standards / static analysis (PHPStan).",
            ],
            confidence=88,
            is_application_bug=True,
        ),
    ),
    # --- PHP-FPM infrastructure (after language-level PHP messages) ---
    (
        "php_fpm_timeout",
        re.compile(
            r"upstream timed out.*fastcgi|fastcgi://.*timed out|"
            r"upstream timed out \(110:.*while reading response header from upstream.*fastcgi",
            re.I,
        ),
        _prof(
            "PHP-FPM Timeout",
            Severity.HIGH,
            "Nginx timed out waiting for PHP-FPM (FastCGI) response.",
            "Slow PHP code, blocked I/O, insufficient pm children, or request_terminate_timeout too low/high.",
            "Users see 504 Gateway Timeout; degraded UX under load.",
            [
                "Profile slow endpoints; optimize DB queries.",
                "Tune pm.max_children, request_terminate_timeout, and nginx fastcgi_read_timeout.",
                "Check PHP-FPM status and slowlog.",
            ],
            confidence=88,
            is_infrastructure=True,
            is_application_bug=True,
        ),
    ),
    (
        "php_fpm_crash",
        re.compile(
            r"recv\(\) failed.*Connection reset by peer.*fastcgi|"
            r"connect\(\) failed \(.*\).*fastcgi|"
            r"connect\(\) failed.*while connecting to upstream.*fastcgi|"
            r"upstream prematurely closed connection.*fastcgi",
            re.I,
        ),
        _prof(
            "PHP-FPM Crash",
            Severity.HIGH,
            "PHP-FPM closed the connection unexpectedly or rejected connect.",
            "FPM pool overloaded, process crash (segfault), socket backlog full, or wrong socket path.",
            "502 Bad Gateway for PHP pages; intermittent site outages.",
            [
                "Verify php-fpm is running and socket/path matches nginx.",
                "Inspect php-fpm error log and pool pm settings.",
                "Check for segfaults and max_children exhaustion.",
            ],
            confidence=86,
            is_infrastructure=True,
        ),
    ),
    # --- Upstream / reverse proxy ---
    (
        "upstream_timeout",
        re.compile(r"upstream timed out|timed out \(110", re.I),
        _prof(
            "Upstream Timeout",
            Severity.HIGH,
            "Nginx timed out connecting to or reading from an upstream server.",
            "Backend slow, overloaded, network latency, or timeout values too aggressive.",
            "502/504 for proxied applications; cascading timeouts under load.",
            [
                "Measure backend latency; scale or optimize upstream.",
                "Align proxy_connect/send/read_timeout with app SLAs.",
            ],
            confidence=90,
            is_infrastructure=True,
        ),
    ),
    (
        "no_live_upstream",
        re.compile(r"no live upstreams|all upstream servers are unavailable", re.I),
        _prof(
            "Upstream Error",
            Severity.CRITICAL,
            "No healthy upstream backends available for the request.",
            "All backends down, failing health checks, or misconfigured upstream block.",
            "Full outage for the virtual host / location.",
            [
                "Check backend health and nginx upstream status.",
                "Fix DNS/IP of upstream servers; restore capacity.",
            ],
            confidence=95,
            is_infrastructure=True,
        ),
    ),
    (
        "upstream_connect",
        re.compile(
            r"connect\(\) failed.*upstream|failed \(111: Connection refused\).*(upstream|while connecting)|"
            r"while connecting to upstream",
            re.I,
        ),
        _prof(
            "Upstream Error",
            Severity.HIGH,
            "Nginx could not establish a connection to the upstream.",
            "Backend not listening, wrong port, firewall drop, or process down.",
            "502 Bad Gateway for affected routes.",
            [
                "Confirm upstream process listens on configured host:port.",
                "Check firewall/security groups and SELinux if applicable.",
            ],
            confidence=90,
            is_infrastructure=True,
        ),
    ),
    (
        "upstream_reset",
        re.compile(
            r"connection reset by peer|upstream prematurely closed connection|"
            r"recv\(\) failed \(104:",
            re.I,
        ),
        _prof(
            "Reverse Proxy Error",
            Severity.HIGH,
            "Upstream closed the connection before nginx finished reading.",
            "Backend crash, keep-alive mismatch, request size limits, or app abort.",
            "Intermittent 502 errors; user-facing failures.",
            [
                "Correlate with backend application logs at the same timestamp.",
                "Review keep-alive and buffer settings (proxy_http_version 1.1).",
            ],
            confidence=84,
            is_infrastructure=True,
        ),
    ),
    (
        "upstream_header",
        re.compile(r"while reading response header from upstream|upstream sent too big header", re.I),
        _prof(
            "Reverse Proxy Error",
            Severity.MEDIUM,
            "Problem reading or buffering upstream response headers.",
            "Oversized cookies/headers, buffer sizes too small, or malformed response.",
            "502 for some responses; session/cookie issues possible.",
            [
                "Increase proxy_buffer_size / proxy_buffers if headers are large.",
                "Reduce Set-Cookie payload size in the application.",
            ],
            confidence=85,
            is_infrastructure=True,
            is_config=True,
        ),
    ),
    # --- SSL/TLS ---
    (
        "ssl_handshake",
        re.compile(
            r"ssl_do_handshake\(\) failed|ssl handshake failed|sslv3 alert|"
            r"tlsv1 alert|ssl3_get_record|unknown protocol|wrong version number",
            re.I,
        ),
        _prof(
            "SSL Error",
            Severity.MEDIUM,
            "TLS handshake failed between client and nginx (or nginx and upstream).",
            "Protocol mismatch, expired/wrong cert, SNI issues, or scanner noise.",
            "HTTPS clients may fail; scanners often generate noise.",
            [
                "Verify certificate chain and expiry (openssl s_client).",
                "Align ssl_protocols/ciphers with client requirements.",
                "If scanners only, treat as noise unless volume is abusive.",
            ],
            confidence=80,
            is_infrastructure=True,
        ),
    ),
    (
        "cert_verify",
        re.compile(r"certificate verify failed|unable to get local issuer|self signed certificate", re.I),
        _prof(
            "TLS Error",
            Severity.HIGH,
            "Certificate verification failed (often nginx as TLS client to upstream).",
            "Missing CA bundle, self-signed upstream cert, or hostname mismatch.",
            "HTTPS reverse proxy to upstream fails.",
            [
                "Install correct CA; or set proxy_ssl_trusted_certificate.",
                "Fix upstream certificate SAN to match the hostname used.",
            ],
            confidence=88,
            is_config=True,
            is_infrastructure=True,
        ),
    ),
    # --- DNS ---
    (
        "dns",
        re.compile(r"host not found in upstream|could not be resolved|resolver|getaddrinfo", re.I),
        _prof(
            "DNS Error",
            Severity.HIGH,
            "Hostname resolution failed for an upstream or peer.",
            "DNS outage, wrong resolver config, or hostname typo.",
            "Cannot reach upstream; 502 for name-based upstreams.",
            [
                "Verify resolver directive and DNS servers.",
                "Test dig/nslookup from the host; fix hostnames in config.",
            ],
            confidence=90,
            is_infrastructure=True,
            is_config=True,
        ),
    ),
    # --- Permissions / files ---
    (
        "permission",
        re.compile(r"permission denied|open\(\) .* failed \(13:", re.I),
        _prof(
            "Permission Error",
            Severity.HIGH,
            "Nginx worker cannot open a file or path due to OS permissions.",
            "Wrong ownership/mode, SELinux/AppArmor denials, or path outside allowed roots.",
            "Static files or configs fail to load; 403/500 symptoms.",
            [
                "Check ownership (www-data/nginx) and directory traverse bits.",
                "Review SELinux audit logs if enforcing.",
                "Ensure alias/root paths are correct.",
            ],
            confidence=92,
            is_config=True,
            is_infrastructure=True,
        ),
    ),
    (
        "file_not_found",
        re.compile(
            r"open\(\) .* failed \(2: No such file|no such file or directory|"
            r"Primary script unknown",
            re.I,
        ),
        _prof(
            "File Not Found",
            Severity.MEDIUM,
            "Referenced file, script, or path does not exist on disk.",
            "Deploy missing files, wrong root/alias, or bot probing non-existent paths.",
            "404 or 502 depending on context; bots often cause noise.",
            [
                "Confirm application deploy paths match nginx root/alias.",
                "If path is a known scanner URI, treat as security scan noise.",
            ],
            confidence=78,
            is_config=True,
        ),
    ),
    (
        "client_body",
        re.compile(r"client intended to send too large body|client_max_body_size", re.I),
        _prof(
            "Configuration Error",
            Severity.MEDIUM,
            "Upload or request body exceeded client_max_body_size.",
            "Limit too low for legitimate uploads, or abuse attempt with huge body.",
            "Large uploads fail with 413.",
            [
                "Raise client_max_body_size only for required locations.",
                "Ensure PHP post_max_size / upload_max_filesize align.",
            ],
            confidence=95,
            is_config=True,
        ),
    ),
    (
        "broken_pipe",
        re.compile(r"broken pipe|writev\(\) failed \(32:", re.I),
        _prof(
            "Network Error",
            Severity.MEDIUM,
            "Client or peer closed connection while nginx was writing.",
            "User cancelled request, load balancer timeout, or flaky network.",
            "Usually low impact; high volume may indicate timeout misalignment.",
            [
                "Align LB idle timeouts with nginx/application.",
                "Ignore isolated cases from short-lived clients.",
            ],
            confidence=75,
            is_infrastructure=True,
        ),
    ),
    (
        "config_error",
        re.compile(
            r"emerg.*unknown directive|emerg.*invalid|emerg.*host not found|"
            r"configuration file .* test failed|unexpected \"",
            re.I,
        ),
        _prof(
            "Configuration Error",
            Severity.CRITICAL,
            "Nginx configuration is invalid or failed to load.",
            "Syntax error, bad directive, or missing file included by config.",
            "Reload/restart may fail; site may stay on old config or go down.",
            [
                "Run nginx -t and fix reported lines.",
                "Validate includes and map/geo files.",
            ],
            confidence=94,
            is_config=True,
        ),
    ),
    # --- Bot / security probes (message-level; path-based also handled in classifier) ---
    (
        "bot_activity",
        re.compile(
            r"access forbidden by rule|limiting requests|limiting connections|"
            r"directory index of .* is forbidden",
            re.I,
        ),
        _prof(
            "Bot Activity",
            Severity.LOW,
            "Automated client hit rate limits or forbidden locations.",
            "Bots, scrapers, or aggressive clients exceeding limit_req/limit_conn.",
            "Usually noise; if legitimate users, rate limits may be too tight.",
            [
                "Confirm whether clients are bots or real users.",
                "Tune limit_req zones; block abusive IPs at firewall if needed.",
            ],
            confidence=75,
            is_security_scan=True,
        ),
    ),
    (
        "network_refused",
        re.compile(r"connection refused|connect\(\) failed \(111:", re.I),
        _prof(
            "Network Error",
            Severity.HIGH,
            "TCP connection refused by peer.",
            "Target service not listening or firewalled.",
            "Dependent feature unavailable (proxy, mail, auth, etc.).",
            [
                "Verify service status and listen address.",
                "Check local firewall rules.",
            ],
            confidence=85,
            is_infrastructure=True,
        ),
    ),
]

SECURITY_SCAN_PROFILE = _prof(
    "Security Scan",
    Severity.LOW,
    "Automated Internet scanner probing common vulnerable paths "
    "(CMS admin, .env, phpMyAdmin, webshells, IoT exploits, etc.).",
    "Unsolicited internet background noise — not evidence of successful compromise by itself.",
    "Log noise and minor resource use. Not a server failure. "
    "Successful compromise would require additional evidence (unexpected writes, webshell execution, auth bypass).",
    [
        "Ensure WAF/ModSecurity remains enabled.",
        "Do not expose admin panels publicly without MFA/VPN.",
        "Optionally drop known scanner IPs at CDN/firewall.",
        "Do not treat pure probe traffic as an outage.",
    ],
    confidence=90,
    is_security_scan=True,
)

UNKNOWN_PROFILE = _prof(
    "Unknown",
    Severity.LOW,
    "Log line did not match a known signature.",
    "Unrecognized application, module, or rare error text.",
    "Unknown until manually reviewed; may hide novel issues.",
    [
        "Manually review sample lines.",
        "Extend analyzer patterns if a new recurring class appears.",
    ],
    confidence=40,
)


def is_security_path(text: str) -> bool:
    if not text:
        return False
    for pat in SECURITY_PATH_PATTERNS:
        if pat.search(text):
            return True
    return False


def match_rule(text: str) -> Optional[tuple[str, CategoryProfile]]:
    if not text:
        return None
    for rule_id, pattern, profile in RULES:
        if pattern.search(text):
            return rule_id, profile
    return None
