"""
lyseis.analyzer.entropy
~~~~~~~~~~~~~~~~~~~~~~~~
Shannon entropy analysis for detecting high-entropy strings that may
be secrets, keys, or tokens.

Severity gating:
  HIGH  — entropy > 4.5, length >= 20, AND a credential keyword appears
           within 80 characters of the string (reduces false positives
           from minified JS, base64 images, CSS hashes, etc.)
  INFO  — entropy > 4.5, length >= 20, but NO keyword context found
"""

from __future__ import annotations

import math

from ..models import Finding, JSSource, Severity
from . import patterns

# Entropy threshold (bits per character)
ENTROPY_THRESHOLD = 4.5
MIN_STRING_LENGTH = 20
KEYWORD_WINDOW = 80       # characters each side to search for a credential keyword


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of string `s` in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _get_context(lines: list[str], line_no: int, radius: int = 2) -> str:
    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


def analyze(source: JSSource, config) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.content.splitlines()

    for line_no, line in enumerate(lines, 1):
        for match in patterns.LONG_STRING.finditer(line):
            candidate = match.group(1)

            if len(candidate) < MIN_STRING_LENGTH:
                continue

            entropy = shannon_entropy(candidate)
            if entropy < ENTROPY_THRESHOLD:
                continue

            # Keyword proximity gating
            start = max(0, match.start() - KEYWORD_WINDOW)
            end = min(len(line), match.end() + KEYWORD_WINDOW)
            context_window = line[start:end]
            has_keyword = bool(patterns.ENTROPY_CONTEXT_KEYWORDS.search(context_window))

            severity = Severity.HIGH if has_keyword else Severity.INFO

            findings.append(
                Finding(
                    type="HIGH_ENTROPY_STRING",
                    value=candidate[:150],
                    severity=severity,
                    source_url=source.url,
                    source_type=source.source_type,
                    line_number=line_no,
                    context=_get_context(lines, line_no)[:400],
                )
            )

    return findings
