"""
lyseis.crawler
~~~~~~~~~~~~~~
Fetches the target HTML page, extracts all <script> references
(both external src= URLs and inline blocks), normalizes them,
enforces same-origin scope, then downloads each external JS file.

Returns a List[JSSource] ready for the analysis engine.
"""

from __future__ import annotations

import sys
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .config import Config
from .models import JSSource, SourceType
from .utils import get_logger, rate_limit


def _build_session(config: Config) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": config.user_agent})
    return session


def _same_origin(base: str, target: str) -> bool:
    """Check whether `target` shares scheme+host with `base`."""
    b = urlparse(base)
    t = urlparse(target)
    return b.scheme == t.scheme and b.netloc == t.netloc


def _fetch(session: requests.Session, url: str, timeout: int, logger) -> str | None:
    """Perform a GET request and return response text, or None on failure."""
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        resp.raise_for_status()
        return resp.text
    except requests.exceptions.Timeout:
        logger.warning(f"Timeout fetching: {url}")
    except requests.exceptions.TooManyRedirects:
        logger.warning(f"Too many redirects: {url}")
    except requests.exceptions.ConnectionError as exc:
        logger.warning(f"Connection error for {url}: {exc}")
    except requests.exceptions.HTTPError as exc:
        logger.warning(f"HTTP {exc.response.status_code} for {url}")
    except requests.exceptions.RequestException as exc:
        logger.warning(f"Request failed for {url}: {exc}")
    return None


def crawl(config: Config) -> list[JSSource]:
    """
    Main crawl entry point.

    1. Fetch the landing page HTML.
    2. Extract <script src="..."> external references.
    3. Extract inline <script>...</script> blocks.
    4. Resolve + scope-filter external URLs.
    5. Fetch each external JS file.
    6. Return a deduplicated List[JSSource].
    """
    logger = get_logger(__name__, verbose=config.verbose)
    session = _build_session(config)
    sources: list[JSSource] = []

    # ------------------------------------------------------------------ #
    # Step 1 — fetch landing page
    # ------------------------------------------------------------------ #
    logger.debug(f"Fetching landing page: {config.url}")
    html = _fetch(session, config.url, config.timeout, logger)
    if not html:
        logger.error(f"Failed to fetch target URL: {config.url}")
        return sources

    soup = BeautifulSoup(html, "lxml")

    # ------------------------------------------------------------------ #
    # Step 2 — collect external JS URLs
    # ------------------------------------------------------------------ #
    seen_urls: set[str] = set()
    external_urls: list[str] = []

    for tag in soup.find_all("script", src=True):
        raw_src: str = tag.get("src", "").strip()
        if not raw_src:
            continue

        abs_url = urljoin(config.url, raw_src)

        # Skip non-http(s) schemes (data:, blob:, etc.)
        if not abs_url.startswith(("http://", "https://")):
            logger.debug(f"Skipping non-HTTP src: {abs_url}")
            continue

        # Same-origin enforcement
        if not config.allow_external and not _same_origin(config.url, abs_url):
            logger.debug(f"Skipping cross-origin JS: {abs_url}")
            continue

        if abs_url not in seen_urls:
            seen_urls.add(abs_url)
            external_urls.append(abs_url)

    logger.debug(f"Found {len(external_urls)} external JS URL(s)")

    # ------------------------------------------------------------------ #
    # Step 3 — extract inline script blocks
    # ------------------------------------------------------------------ #
    inline_count = 0
    for i, tag in enumerate(soup.find_all("script", src=False)):
        content = tag.string or ""
        content = content.strip()
        if not content:
            continue
        sources.append(
            JSSource(
                url=f"inline:{config.url}#{i}",
                content=content,
                source_type=SourceType.INLINE,
            )
        )
        inline_count += 1

    logger.debug(f"Found {inline_count} inline script block(s)")

    # ------------------------------------------------------------------ #
    # Step 4 — fetch external JS files
    # ------------------------------------------------------------------ #
    for url in external_urls:
        rate_limit(config.delay)
        logger.debug(f"Fetching JS: {url}")
        content = _fetch(session, url, config.timeout, logger)
        if content is None:
            continue
        content = content.strip()
        if not content:
            logger.debug(f"Empty response body: {url}")
            continue
        sources.append(
            JSSource(
                url=url,
                content=content,
                source_type=SourceType.EXTERNAL,
            )
        )

    logger.debug(f"Crawl complete. Total JS sources: {len(sources)}")
    return sources
