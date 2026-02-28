"""
lyseis.analyzer.sinks
~~~~~~~~~~~~~~~~~~~~~
Detects dangerous JavaScript execution sinks and client-side attack vectors.

Coverage:
  DOM XSS sinks      — eval, innerHTML, document.write, insertAdjacentHTML
  Code execution     — new Function(), setTimeout/setInterval with string args
  Open redirect      — window.location.href assignments, location.replace/assign
  Domain relaxation  — document.domain reassignment
  Base64 decode      — atob() calls containing high-entropy content (hidden secrets)

Severity rationale:
  eval() / new Function() / document.write() with non-literal args → HIGH
  innerHTML / outerHTML /insertAdjacentHTML assignment → HIGH
  setTimeout/setInterval with string literal → MEDIUM
  open redirect sink → MEDIUM
  document.domain reassignment → HIGH
  atob() with long base64 → INFO (entropy analyzer may upgrade if keyword-gated)
"""

from __future__ import annotations

import math

from ..models import Finding, JSSource, Severity
from . import patterns


# Sinks that represent direct or near-direct code execution / XSS
_HIGH_SINKS: list[tuple[str, object]] = [
    ("EVAL_SINK",             patterns.EVAL_SINK),
    ("NEW_FUNCTION_SINK",     patterns.NEW_FUNCTION_SINK),
    ("DOCUMENT_WRITE_SINK",   patterns.DOCUMENT_WRITE_SINK),
    ("INNER_HTML_SINK",       patterns.INNER_HTML_SINK),
    ("OUTER_HTML_SINK",       patterns.OUTER_HTML_SINK),
    ("INSERT_ADJACENT_HTML",  patterns.INSERT_ADJACENT_HTML),
    ("DOCUMENT_DOMAIN_SET",   patterns.DOCUMENT_DOMAIN),
]

_MEDIUM_SINKS: list[tuple[str, object]] = [
    ("SETTIMEOUT_STRING_ARG",  patterns.SETTIMEOUT_STRING),
    ("SETINTERVAL_STRING_ARG", patterns.SETINTERVAL_STRING),
    ("OPEN_REDIRECT_SINK",     patterns.OPEN_REDIRECT),
]


def _get_context(lines: list[str], line_no: int, radius: int = 2) -> str:
    start = max(0, line_no - 1 - radius)
    end   = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def analyze(source: JSSource, config) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.content.splitlines()

    for line_no, line in enumerate(lines, 1):
        context = _get_context(lines, line_no)

        # HIGH severity DOM sinks
        for sink_name, pattern in _HIGH_SINKS:
            for match in pattern.finditer(line):
                findings.append(
                    Finding(
                        type=sink_name,
                        value=line.strip()[:200],
                        severity=Severity.HIGH,
                        source_url=source.url,
                        source_type=source.source_type,
                        line_number=line_no,
                        context=context[:400],
                    )
                )

        # MEDIUM severity sinks
        for sink_name, pattern in _MEDIUM_SINKS:
            for match in pattern.finditer(line):
                findings.append(
                    Finding(
                        type=sink_name,
                        value=line.strip()[:200],
                        severity=Severity.MEDIUM,
                        source_url=source.url,
                        source_type=source.source_type,
                        line_number=line_no,
                        context=context[:400],
                    )
                )

        # atob() — flag as INFO; upgrade if the decoded content has high entropy
        for match in patterns.ATOB_CALL.finditer(line):
            b64_content = match.group(1)
            entropy = _shannon_entropy(b64_content)
            # High entropy base64 near a credential keyword hints at an encoded secret
            window_start = max(0, match.start() - 80)
            window_end   = min(len(line), match.end() + 80)
            has_keyword  = bool(patterns.ENTROPY_CONTEXT_KEYWORDS.search(
                line[window_start:window_end]
            ))
            severity = Severity.HIGH if (entropy > 4.0 and has_keyword) else Severity.INFO
            findings.append(
                Finding(
                    type="ATOB_BASE64_DECODE",
                    value=b64_content[:120],
                    severity=severity,
                    source_url=source.url,
                    source_type=source.source_type,
                    line_number=line_no,
                    context=context[:400],
                )
            )

    return findings
