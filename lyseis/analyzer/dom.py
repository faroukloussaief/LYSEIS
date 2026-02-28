"""
lyseis.analyzer.dom
~~~~~~~~~~~~~~~~~~~~
Client-side attack surface indicators.

v0.1-r2 additions:
  - SSR hydration data leaks (__NEXT_DATA__, __PRELOADED_STATE__, etc.)
  - localStorage / sessionStorage credential storage (XSS amplification)
  - JSONP callback injection patterns
  - document.cookie assignment detection
"""

from __future__ import annotations

from ..models import Finding, JSSource, Severity
from . import patterns


def _get_context(lines: list[str], line_no: int, radius: int = 2) -> str:
    start = max(0, line_no - 1 - radius)
    end   = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


def _line_of_offset(content: str, offset: int) -> int:
    return content[:offset].count("\n") + 1


# Line-level rules: (finding_type, pattern, severity)
_LINE_RULES: list[tuple[str, object, Severity]] = [
    ("POST_MESSAGE_SINK",   patterns.POST_MESSAGE,      Severity.MEDIUM),
    ("CORS_WILDCARD",       patterns.CORS_WILDCARD,     Severity.HIGH),
    ("STORAGE_CRED_LEAK",   patterns.STORAGE_CREDS,     Severity.MEDIUM),
    ("COOKIE_ASSIGNMENT",   patterns.COOKIE_SET,        Severity.INFO),
    ("JSONP_CALLBACK",      patterns.JSONP_CALLBACK,    Severity.MEDIUM),
]


def analyze(source: JSSource, config) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.content.splitlines()

    # ---------------------------------------------------------------- #
    # Line-level rules
    # ---------------------------------------------------------------- #
    for line_no, line in enumerate(lines, 1):
        context = _get_context(lines, line_no)

        for rule_name, pattern, severity in _LINE_RULES:
            for match in pattern.finditer(line):
                findings.append(
                    Finding(
                        type=rule_name,
                        value=match.group(0)[:250],
                        severity=severity,
                        source_url=source.url,
                        source_type=source.source_type,
                        line_number=line_no,
                        context=context[:400],
                    )
                )

    # ---------------------------------------------------------------- #
    # Full-content: Feature flag blobs (may span multiple lines)
    # ---------------------------------------------------------------- #
    for match in patterns.FEATURE_FLAG.finditer(source.content):
        line_no = _line_of_offset(source.content, match.start())
        context = _get_context(lines, line_no)
        findings.append(
            Finding(
                type="FEATURE_FLAG_BLOB",
                value=match.group(0)[:300],
                severity=Severity.MEDIUM,
                source_url=source.url,
                source_type=source.source_type,
                line_number=line_no,
                context=context[:400],
            )
        )

    # ---------------------------------------------------------------- #
    # Full-content: SSR hydration leaks (Next.js, Redux, Nuxt, etc.)
    # ---------------------------------------------------------------- #
    for match in patterns.SSR_HYDRATION.finditer(source.content):
        line_no = _line_of_offset(source.content, match.start())
        # Extract the blob value — up to 500 chars after the `=`
        blob_start = match.end()
        blob = source.content[blob_start: blob_start + 500].strip()
        findings.append(
            Finding(
                type="SSR_HYDRATION_LEAK",
                value=match.group(0)[:200] + " " + blob[:200],
                severity=Severity.HIGH,
                source_url=source.url,
                source_type=source.source_type,
                line_number=line_no,
                context=_get_context(lines, line_no, radius=3)[:400],
            )
        )

    return findings
