"""
lyseis.config
~~~~~~~~~~~~~
Runtime configuration dataclass. Single source of truth for all
user-supplied parameters. Passed by reference through the entire pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Config:
    # Required
    url: str

    # Crawl behaviour
    allow_external: bool = False
    delay: float = 0.5
    timeout: int = 10
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Lyseis/0.1"

    # Output
    json_output: bool = False
    output_path: str | None = None
    no_color: bool = False

    # UX
    silent: bool = False
    verbose: bool = False
