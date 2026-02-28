"""
lyseis.analyzer.endpoints
~~~~~~~~~~~~~~~~~~~~~~~~~
API route, GraphQL, and WebSocket endpoint detection.

v0.1-r2 changes:
  - Per-file cap on REST_PATH findings (max 40) to prevent SPA noise flood
  - Path deduplication within a single file before emitting findings
  - Versioned API pattern broadened to catch /v1/... without /api/ prefix
"""

from __future__ import annotations

from ..models import Finding, JSSource, Severity
from . import patterns

# Maximum distinct REST paths to report per JS file.
# SPAs can have 500+ path strings — a cap keeps results actionable.
_MAX_ENDPOINT_FINDINGS = 40


def _get_context(lines: list[str], line_no: int, radius: int = 2) -> str:
    start = max(0, line_no - 1 - radius)
    end   = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


def analyze(source: JSSource, config) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.content.splitlines()

    # Deduplication sets per category so we don't report /api/users 50 times
    seen_paths: set[str]    = set()
    seen_versioned: set[str] = set()
    seen_graphql: set[str]  = set()
    seen_ws: set[str]       = set()

    endpoint_count = 0

    for line_no, line in enumerate(lines, 1):
        context = _get_context(lines, line_no)

        # REST / API paths (capped + deduplicated)
        if endpoint_count < _MAX_ENDPOINT_FINDINGS:
            for match in patterns.REST_PATH.finditer(line):
                path = match.group(1)
                if path in seen_paths:
                    continue
                seen_paths.add(path)
                endpoint_count += 1
                findings.append(
                    Finding(
                        type="API_ENDPOINT",
                        value=path[:200],
                        severity=Severity.MEDIUM,
                        source_url=source.url,
                        source_type=source.source_type,
                        line_number=line_no,
                        context=context[:400],
                    )
                )
                if endpoint_count >= _MAX_ENDPOINT_FINDINGS:
                    break

        # Versioned API paths — deduplicated, no cap (typically few unique ones)
        for match in patterns.VERSIONED_API.finditer(line):
            path = match.group(1)
            if path in seen_versioned:
                continue
            seen_versioned.add(path)
            findings.append(
                Finding(
                    type="VERSIONED_API_PATH",
                    value=path[:200],
                    severity=Severity.MEDIUM,
                    source_url=source.url,
                    source_type=source.source_type,
                    line_number=line_no,
                    context=context[:400],
                )
            )

        # GraphQL — deduplicated
        for match in patterns.GRAPHQL_REF.finditer(line):
            value = match.group(0)
            if value in seen_graphql:
                continue
            seen_graphql.add(value)
            findings.append(
                Finding(
                    type="GRAPHQL_REFERENCE",
                    value=value[:200],
                    severity=Severity.HIGH,
                    source_url=source.url,
                    source_type=source.source_type,
                    line_number=line_no,
                    context=context[:400],
                )
            )

        # WebSocket — deduplicated
        for match in patterns.WEBSOCKET_URL.finditer(line):
            value = match.group(0)
            if value in seen_ws:
                continue
            seen_ws.add(value)
            findings.append(
                Finding(
                    type="WEBSOCKET_ENDPOINT",
                    value=value[:200],
                    severity=Severity.MEDIUM,
                    source_url=source.url,
                    source_type=source.source_type,
                    line_number=line_no,
                    context=context[:400],
                )
            )

    return findings
