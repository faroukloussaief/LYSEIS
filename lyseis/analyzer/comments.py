"""
lyseis.analyzer.comments
~~~~~~~~~~~~~~~~~~~~~~~~
Extracts interesting developer comments and meaningful debug signals.

v0.1-r2 changes:
  - console.log is now keyword-proximity gated (CONSOLE_CREDENTIAL_LEAK)
    to eliminate the false positive flood from bare console.log calls
  - process.env and import.meta.env patterns kept as DEBUG_FLAG (INFO)
  - Added Vite import.meta.env detection
"""

from __future__ import annotations

from ..models import Finding, JSSource, Severity
from . import patterns


def _line_of_offset(content: str, offset: int) -> int:
    """Return 1-based line number for a byte offset in content."""
    return content[:offset].count("\n") + 1


def _get_context(lines: list[str], line_no: int, radius: int = 2) -> str:
    start = max(0, line_no - 1 - radius)
    end   = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


def analyze(source: JSSource, config) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.content.splitlines()
    seen_comment_offsets: set[int] = set()

    # ---------------------------------------------------------------- #
    # Interesting comments (block + line) — full content scan
    # Cap block comment length to 5000 chars to prevent regex backtrack
    # ---------------------------------------------------------------- #
    content_slice = source.content[:500_000]  # safety cap on huge files
    for match in patterns.INTERESTING_COMMENT.finditer(content_slice):
        offset = match.start()
        if offset in seen_comment_offsets:
            continue
        seen_comment_offsets.add(offset)

        line_no = _line_of_offset(source.content, offset)
        findings.append(
            Finding(
                type="INTERESTING_COMMENT",
                value=match.group(0)[:250].strip(),
                severity=Severity.INFO,
                source_url=source.url,
                source_type=source.source_type,
                line_number=line_no,
                context=_get_context(lines, line_no)[:400],
            )
        )

    # ---------------------------------------------------------------- #
    # Debug flags: __DEV__, DEBUG=true, process.env.*, import.meta.env.*
    # (console.log NOT included here — handled separately below)
    # ---------------------------------------------------------------- #
    for line_no, line in enumerate(lines, 1):
        for match in patterns.DEBUG_FLAG.finditer(line):
            findings.append(
                Finding(
                    type="DEBUG_FLAG",
                    value=match.group(0)[:200],
                    severity=Severity.INFO,
                    source_url=source.url,
                    source_type=source.source_type,
                    line_number=line_no,
                    context=_get_context(lines, line_no)[:400],
                )
            )

    # ---------------------------------------------------------------- #
    # console.log — ONLY when a credential keyword is inside the call
    # (avoids hundreds of informational console.log("Button clicked") hits)
    # ---------------------------------------------------------------- #
    for line_no, line in enumerate(lines, 1):
        for match in patterns.CONSOLE_CREDENTIAL_LEAK.finditer(line):
            findings.append(
                Finding(
                    type="CONSOLE_CREDENTIAL_LEAK",
                    value=match.group(0)[:200],
                    severity=Severity.MEDIUM,  # escalated: credential in log output
                    source_url=source.url,
                    source_type=source.source_type,
                    line_number=line_no,
                    context=_get_context(lines, line_no)[:400],
                )
            )

    return findings
