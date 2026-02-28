"""
lyseis.analyzer.infrared
~~~~~~~~~~~~~~~~~~~~~~~~
Infrastructure-level information leak detection.

v0.1-r2 additions:
  - Localhost / loopback URL references
  - Non-standard service ports (DB, debug, internal)
  - AWS cloud metadata endpoint (169.254.169.254) — SSRF vector
  - Node.js debugger port 9229 — RCE if externally exposed
"""

from __future__ import annotations

from ..models import Finding, JSSource, Severity
from . import patterns


_LINE_RULES: list[tuple[str, object, Severity]] = [
    # Original
    ("INTERNAL_IP",        patterns.INTERNAL_IP,       Severity.HIGH),
    ("S3_BUCKET_URL",      patterns.S3_BUCKET,         Severity.MEDIUM),
    ("GCS_BUCKET_URL",     patterns.GCS_BUCKET,        Severity.MEDIUM),
    ("AZURE_BLOB_URL",     patterns.AZURE_BLOB,        Severity.MEDIUM),
    ("SOURCEMAP_REF",      patterns.SOURCEMAP,         Severity.HIGH),
    ("STAGING_URL",        patterns.STAGING_SUBDOMAIN, Severity.MEDIUM),

    # New in r2
    ("LOCALHOST_URL",      patterns.LOCALHOST_URL,     Severity.INFO),
    ("NON_STANDARD_PORT",  patterns.NON_STANDARD_PORT, Severity.MEDIUM),
    ("CLOUD_METADATA_SSRF",patterns.CLOUD_METADATA,    Severity.CRITICAL),
    ("NODE_DEBUGGER_PORT", patterns.NODE_DEBUGGER,     Severity.HIGH),
]


def _get_context(lines: list[str], line_no: int, radius: int = 2) -> str:
    start = max(0, line_no - 1 - radius)
    end   = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


def analyze(source: JSSource, config) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.content.splitlines()

    for line_no, line in enumerate(lines, 1):
        context = _get_context(lines, line_no)

        for rule_name, pattern, severity in _LINE_RULES:
            for match in pattern.finditer(line):
                findings.append(
                    Finding(
                        type=rule_name,
                        value=match.group(0)[:200],
                        severity=severity,
                        source_url=source.url,
                        source_type=source.source_type,
                        line_number=line_no,
                        context=context[:400],
                    )
                )

    return findings
