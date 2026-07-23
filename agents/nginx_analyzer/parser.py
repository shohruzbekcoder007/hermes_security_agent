"""Stream-parse Nginx error.log lines (supports large files)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO, Optional, TextIO, Union

from agents.nginx_analyzer.models import LogEntry

# Standard nginx error log:
# 2024/01/15 12:34:56 [error] 1234#0: *56 message, client: 1.2.3.4, server: example.com,
#   request: "GET / HTTP/1.1", host: "example.com", referrer: "..."
_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<level>[a-z]+)\]\s+"
    r"(?P<pid>\d+)#(?P<tid>\d+):\s*"
    r"(?:\*(?P<cid>\d+)\s+)?"
    r"(?P<msg>.*)$",
    re.I,
)

_FIELD_RE = re.compile(
    r",\s*(?P<key>client|server|request|host|referrer|upstream):\s*"
    r"(?P<val>\"[^\"]*\"|[^,]+)",
    re.I,
)


def parse_line(raw: str, source_file: str, line_no: int) -> Optional[LogEntry]:
    line = raw.rstrip("\r\n")
    if not line.strip():
        return None

    m = _LINE_RE.match(line)
    if not m:
        # Continuation / non-standard line — keep as free-form message
        return LogEntry(
            raw=line,
            source_file=source_file,
            line_no=line_no,
            message=line,
        )

    msg = (m.group("msg") or "").strip()
    entry = LogEntry(
        raw=line,
        source_file=source_file,
        line_no=line_no,
        timestamp=m.group("ts"),
        level=m.group("level").lower() if m.group("level") else None,
        pid=m.group("pid"),
        tid=m.group("tid"),
        message=msg,
    )

    for fm in _FIELD_RE.finditer("," + msg if not msg.startswith(",") else msg):
        key = fm.group("key").lower()
        val = fm.group("val").strip().strip('"')
        if key == "client":
            entry.client = val
        elif key == "server":
            entry.server = val
        elif key == "request":
            entry.request = val
        elif key == "host":
            entry.host = val
        elif key == "referrer":
            entry.referrer = val
        elif key == "upstream":
            entry.upstream = val

    # Also parse fields when they appear after the main message
    for fm in _FIELD_RE.finditer(line):
        key = fm.group("key").lower()
        val = fm.group("val").strip().strip('"')
        if key == "client" and not entry.client:
            entry.client = val
        elif key == "server" and not entry.server:
            entry.server = val
        elif key == "request" and not entry.request:
            entry.request = val
        elif key == "host" and not entry.host:
            entry.host = val
        elif key == "referrer" and not entry.referrer:
            entry.referrer = val
        elif key == "upstream" and not entry.upstream:
            entry.upstream = val

    return entry


def iter_text_lines(
    text: str,
    source_file: str = "<text>",
) -> Iterator[LogEntry]:
    for i, raw in enumerate(text.splitlines(), start=1):
        entry = parse_line(raw, source_file, i)
        if entry is not None:
            yield entry


def iter_file(
    path: Union[str, Path],
    *,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> Iterator[LogEntry]:
    p = Path(path)
    name = p.name
    with p.open("r", encoding=encoding, errors=errors) as fh:
        yield from iter_stream(fh, source_file=name)


def iter_stream(
    fh: Union[TextIO, BinaryIO],
    source_file: str = "<stream>",
    *,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> Iterator[LogEntry]:
    # Support binary file-like (UploadFile.file)
    if hasattr(fh, "mode") and "b" in getattr(fh, "mode", ""):
        # binary
        line_no = 0
        for raw_b in fh:  # type: ignore[assignment]
            line_no += 1
            if isinstance(raw_b, bytes):
                raw = raw_b.decode(encoding, errors=errors)
            else:
                raw = str(raw_b)
            entry = parse_line(raw, source_file, line_no)
            if entry is not None:
                yield entry
        return

    line_no = 0
    for raw in fh:  # type: ignore[assignment]
        line_no += 1
        if isinstance(raw, bytes):
            raw = raw.decode(encoding, errors=errors)
        entry = parse_line(str(raw), source_file, line_no)
        if entry is not None:
            yield entry
