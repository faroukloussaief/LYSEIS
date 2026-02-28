"""
lyseis.crawler
~~~~~~~~~~~~~~
Fetches the target HTML page, extracts all <script> references
(both external src= URLs and inline blocks), normalizes them,
enforces same-origin scope, then downloads each external JS file.

v0.1-r3: Bot protection bypass
  - Full browser-like headers on every request (Accept, Sec-Fetch-*, etc.)
  - --stealth flag activates cloudscraper for Cloudflare JS-challenge bypass
  - Automatic bot-block detection (403/429/503 with WAF signatures)
  - Auto-retry with cloudscraper if initial request is blocked
  - Optional proxy support (--proxy)
"""

from __future__ import annotations

import sys
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .config import Config
from .models import JSSource, SourceType
from .utils import get_logger, rate_limit


# ------------------------------------------------------------------ #
# Realistic browser headers — mimic a Chrome 122 on Windows request
# Using a real browser header set is the single most effective bypass
# for basic bot detection (DataDome, Imperva, Akamai at low tiers).
# ------------------------------------------------------------------ #

_BROWSER_HEADERS: dict[str, str] = {
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Cache-Control": "max-age=0",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Sec-CH-UA": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
}

_JS_HEADERS: dict[str, str] = {
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Sec-Fetch-Dest": "script",
    "Sec-Fetch-Mode": "no-cors",
    "Sec-Fetch-Site": "same-origin",
}

# Signatures found in bot-protection challenge pages
_BOT_BLOCK_SIGNATURES: list[str] = [
    "cloudflare",
    "checking your browser",
    "just a moment",
    "enable javascript and cookies",
    "cf_clearance",
    "cf-browser-verification",
    "_iuam",
    # Imperva / Incapsula
    "incap_ses",
    "visid_incap",
    "_incapsula_",
    # DataDome
    "datadome",
    "dd_referrer",
    # PerimeterX / HUMAN
    "px_uuid",
    "x-px-",
    "perimeterx",
    "_pxhd",
    # Akamai
    "akamai-bot",
    "ak_bmsc",
    # Generic
    "bot protection",
    "access denied",
    "security check",
    "verify you are human",
]

_BLOCKED_STATUS_CODES: frozenset[int] = frozenset({403, 429, 503, 521, 522, 523, 524})


def _is_bot_blocked(resp: requests.Response) -> bool:
    """Return True if the response looks like a bot-protection challenge."""
    if resp.status_code not in _BLOCKED_STATUS_CODES:
        return False
    body_lower = resp.text.lower()
    headers_lower = str(resp.headers).lower()
    combined = body_lower + " " + headers_lower
    return any(sig in combined for sig in _BOT_BLOCK_SIGNATURES)


def _build_stealth_session(config: Config):
    """
    Build a cloudscraper session for Cloudflare JS-challenge bypass.
    Falls back to a standard session if cloudscraper is not installed.
    """
    try:
        import cloudscraper  # type: ignore

        session = cloudscraper.create_scraper(
            browser={
                "browser": "chrome",
                "platform": "windows",
                "desktop": True,
                "mobile": False,
            },
            delay=10,           # seconds to wait for JS challenge resolution
        )
    except ImportError:
        # Graceful degradation: inform user but keep running
        print(
            "[!] --stealth mode requested but 'cloudscraper' is not installed.\n"
            "    Install with: pip install cloudscraper\n"
            "    Falling back to standard requests session.",
            file=sys.stderr,
        )
        session = requests.Session()

    session.headers.update({"User-Agent": config.user_agent})

    if config.proxy:
        proxies = {"http": config.proxy, "https": config.proxy}
        session.proxies.update(proxies)

    return session


def _build_session(config: Config) -> requests.Session:
    """Build a standard requests.Session with full browser headers."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": config.user_agent,
        **_BROWSER_HEADERS,
    })
    if config.proxy:
        proxies = {"http": config.proxy, "https": config.proxy}
        session.proxies.update(proxies)
    return session


def _same_origin(base: str, target: str) -> bool:
    """Check whether `target` shares scheme+host with `base`."""
    b = urlparse(base)
    t = urlparse(target)
    return b.scheme == t.scheme and b.netloc == t.netloc


def _fetch_with_retry(
    session,
    url: str,
    config: Config,
    logger,
    extra_headers: dict | None = None,
) -> str | None:
    """
    GET `url` with automatic bot-block detection and retry.

    Strategy:
      1. Try with current session (standard or stealth).
      2. If bot-blocked and NOT already in stealth mode, auto-retry
         with a cloudscraper session (transparent escalation).
      3. Respect max_retries on transient errors (5xx).
    """
    headers = extra_headers or {}

    for attempt in range(1, config.max_retries + 2):  # +2: 1 base + max_retries
        try:
            resp = session.get(
                url,
                headers=headers,
                timeout=config.timeout,
                allow_redirects=True,
            )

            # Bot protection check
            if _is_bot_blocked(resp):
                logger.warning(
                    f"Bot protection detected on {url} "
                    f"(HTTP {resp.status_code}) "
                    f"— {'retry' if attempt <= config.max_retries else 'giving up'}"
                )
                if not config.stealth_mode and attempt == 1:
                    # Auto-escalate to cloudscraper on first block
                    logger.debug("Auto-escalating to stealth session for retry.")
                    stealth_cfg = config.__class__(
                        **{**config.__dict__, "stealth_mode": True}
                    )
                    stealth_session = _build_stealth_session(stealth_cfg)
                    return _fetch_with_retry(
                        stealth_session, url, stealth_cfg, logger, extra_headers
                    )
                if attempt <= config.max_retries:
                    time.sleep(2 ** attempt)  # exponential back-off
                    continue
                return None

            resp.raise_for_status()
            return resp.text

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching: {url} (attempt {attempt})")
        except requests.exceptions.TooManyRedirects:
            logger.warning(f"Too many redirects: {url}")
            return None
        except requests.exceptions.ConnectionError as exc:
            logger.warning(f"Connection error for {url}: {exc}")
        except requests.exceptions.HTTPError as exc:
            logger.warning(f"HTTP {exc.response.status_code} for {url}")
            return None
        except requests.exceptions.RequestException as exc:
            logger.warning(f"Request failed for {url}: {exc}")

        if attempt <= config.max_retries:
            time.sleep(1.5 * attempt)

    return None


# ------------------------------------------------------------------ #
# Duplicate-safe URL normaliser
# ------------------------------------------------------------------ #

def _normalise_url(raw: str, base: str) -> str | None:
    """Resolve relative paths, reject non-HTTP schemes."""
    abs_url = urljoin(base, raw.strip())
    if abs_url.startswith(("http://", "https://")):
        return abs_url
    return None


def crawl(config: Config) -> list[JSSource]:
    """
    Main crawl entry point.

    1. Build session (stealth or standard).
    2. Fetch landing page HTML.
    3. Extract <script src="..."> external references.
    4. Extract inline <script>...</script> blocks.
    5. Resolve + scope-filter external URLs.
    6. Fetch each external JS file.
    7. Return a deduplicated List[JSSource].
    """
    logger = get_logger(__name__, verbose=config.verbose)

    session = (
        _build_stealth_session(config) if config.stealth_mode
        else _build_session(config)
    )

    sources: list[JSSource] = []

    # ---------------------------------------------------------------- #
    # Step 1 — fetch landing page
    # ---------------------------------------------------------------- #
    logger.debug(f"Fetching landing page: {config.url}")
    html = _fetch_with_retry(session, config.url, config, logger, _BROWSER_HEADERS)

    if not html:
        logger.error(f"Failed to fetch target URL: {config.url}")
        return sources

    soup = BeautifulSoup(html, "lxml")

    # ---------------------------------------------------------------- #
    # Step 2 — collect external JS URLs
    # ---------------------------------------------------------------- #
    seen_urls: set[str] = set()
    external_urls: list[str] = []

    for tag in soup.find_all("script", src=True):
        raw_src: str = tag.get("src", "").strip()
        if not raw_src:
            continue

        abs_url = _normalise_url(raw_src, config.url)
        if abs_url is None:
            logger.debug(f"Skipping non-HTTP src: {raw_src}")
            continue

        if not config.allow_external and not _same_origin(config.url, abs_url):
            logger.debug(f"Skipping cross-origin JS: {abs_url}")
            continue

        if abs_url not in seen_urls:
            seen_urls.add(abs_url)
            external_urls.append(abs_url)

    logger.debug(f"Found {len(external_urls)} external JS URL(s)")

    # ---------------------------------------------------------------- #
    # Step 3 — extract inline script blocks
    # ---------------------------------------------------------------- #
    inline_count = 0
    for i, tag in enumerate(soup.find_all("script", src=False)):
        content = (tag.string or "").strip()
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

    # ---------------------------------------------------------------- #
    # Step 4 — fetch external JS files
    # ---------------------------------------------------------------- #
    for url in external_urls:
        rate_limit(config.delay)
        logger.debug(f"Fetching JS: {url}")
        content = _fetch_with_retry(session, url, config, logger, _JS_HEADERS)
        if not content or not content.strip():
            logger.debug(f"Empty or blocked response: {url}")
            continue
        sources.append(
            JSSource(
                url=url,
                content=content.strip(),
                source_type=SourceType.EXTERNAL,
            )
        )

    logger.debug(f"Crawl complete. Total JS sources: {len(sources)}")
    return sources
