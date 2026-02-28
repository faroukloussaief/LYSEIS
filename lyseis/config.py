"""
lyseis.config
~~~~~~~~~~~~~
Runtime configuration dataclass. Single source of truth for all
user-supplied parameters. Passed by reference through the entire pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Config:
    # Required
    url: str

    # Crawl behaviour
    allow_external: bool = False
    delay: float = 0.5
    timeout: int = 15
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )

    # Bot protection bypass
    stealth_mode: bool = False          # use cloudscraper (Cloudflare JS-challenge bypass)
    proxy: str | None = None            # HTTP/SOCKS proxy e.g. "socks5://127.0.0.1:9050"
    max_retries: int = 2                # retry count on bot-block 403/503

    # Output
    json_output: bool = False
    output_path: str | None = None
    no_color: bool = False

    # UX
    silent: bool = False
    verbose: bool = False
