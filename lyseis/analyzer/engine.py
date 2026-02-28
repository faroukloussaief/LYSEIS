"""
lyseis.analyzer.engine
~~~~~~~~~~~~~~~~~~~~~~~
Orchestrates all analyzer modules against a list of JSSource objects.

Analyzer registry: add a new analyzer by importing it and appending
its `analyze` function to _ANALYZERS. No other changes required.
"""

from __future__ import annotations

from ..config import Config
from ..models import Finding, JSSource
from ..utils import get_logger
from . import comments, dom, endpoints, entropy, infrared, secrets

# Registered analyzers — order does not affect correctness.
_ANALYZERS = [
    secrets.analyze,
    endpoints.analyze,
    entropy.analyze,
    comments.analyze,
    infrared.analyze,
    dom.analyze,
]


def run(sources: list[JSSource], config: Config) -> list[Finding]:
    """
    Fan-out all registered analyzers against every JSSource.

    Returns a flat list of raw (un-deduplicated) Finding objects.
    Deduplication happens later in ScanResult.deduplicate().
    """
    logger = get_logger(__name__, verbose=config.verbose)
    all_findings: list[Finding] = []

    for source in sources:
        logger.debug(f"Analyzing: {source.url} ({len(source.content)} chars)")
        for analyzer_fn in _ANALYZERS:
            try:
                results = analyzer_fn(source, config)
                all_findings.extend(results)
            except Exception as exc:
                # Never let one broken analyzer kill the whole scan
                logger.warning(
                    f"Analyzer {analyzer_fn.__module__} failed on {source.url}: {exc}"
                )

    return all_findings
