"""
lyseis.models
~~~~~~~~~~~~~
Core data models for the pipeline. Every analyzer produces Finding objects.
ScanResult aggregates them for the reporter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SourceType(str, Enum):
    EXTERNAL = "external"
    INLINE = "inline"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


# Severity ordering for sorting (lower = more severe)
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.INFO: 3,
}


@dataclass
class JSSource:
    """A single JS source unit — either a fetched external file or an inline script block."""

    url: str
    content: str
    source_type: SourceType


@dataclass
class Finding:
    """An atomic finding produced by one analyzer against one JSSource."""

    type: str                        # e.g. "AWS_ACCESS_KEY", "API_ENDPOINT"
    value: str                       # The extracted raw value (truncated if needed)
    severity: Severity
    source_url: str                  # JS file URL or "inline:<page_url>#N"
    source_type: SourceType
    line_number: int | None = None
    context: str = ""                # ±2 surrounding lines for human review


@dataclass
class ScanResult:
    """Aggregated output of a full scan. Passed to the reporter."""

    target: str
    js_sources: list[JSSource] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def deduplicate(self) -> None:
        """Remove duplicate findings by (type, normalized value)."""
        seen: set[tuple[str, str]] = set()
        unique: list[Finding] = []
        for f in self.findings:
            key = (f.type, f.value.strip()[:200])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique

    def sorted_findings(self) -> list[Finding]:
        """Return findings sorted from most to least severe."""
        return sorted(self.findings, key=lambda f: _SEVERITY_ORDER[f.severity])

    def counts_by_severity(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts
