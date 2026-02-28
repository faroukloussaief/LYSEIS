"""
lyseis.crawler
~~~~~~~~~~~~~~
Fetches the target HTML page, extracts all <script> references
(both external src= URLs and inline blocks), normalizes them,
enforces same-origin scope, then downloads each external JS file.

v0.1-r4: Three-tier bypass stack
  Tier 1 (default)    → requests + full browser headers (basic WAFs)
  Tier 2 (--stealth)  → cloudscraper (Cloudflare JS challenge, auto-activates on block)
  Tier 3 (--browser)  → Playwright headless Chromium (Turnstile, JS-rendered SPAs)
  Tier 3 (--flaresolverr) → FlareSolverr service (Turnstile + strong WAFs)
"""

from __future__ import annotations

import sys
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .browser import fetch_with_playwright, fetch_with_flaresolverr, is_challenge_page
from .config import Config
from .models import JSSource, SourceType
from .utils import get_logger, rate_limit


# ------------------------------------------------------------------ #
# Realistic Chrome 122 header sets
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

_BOT_BLOCK_SIGNATURES: list[str] = [
    "cloudflare", "checking your browser", "just a moment",
    "enable javascript and cookies", "cf_clearance", "cf-browser-verification",
    "_iuam", "turnstile",
    "incap_ses", "visid_incap", "_incapsula_",
    "datadome", "dd_referrer",
    "px_uuid", "x-px-", "perimeterx", "_pxhd",
    "akamai-bot", "ak_bmsc",
    "bot protection", "access denied", "security check",
    "verify you are human",
]

_BLOCKED_STATUS_CODES: frozenset[int] = frozenset({403, 429, 503, 521, 522, 523, 524})


def _is_bot_blocked(resp: requests.Response) -> bool:
    if resp.status_code not in _BLOCKED_STATUS_CODES:
        return False
    combined = resp.text.lower() + " " + str(resp.headers).lower()
    return any(sig in combined for sig in _BOT_BLOCK_SIGNATURES)


def _build_stealth_session(config: Config):
    try:
        import cloudscraper  # type: ignore
        session = cloudscraper.create_scraper(
            browser={"browser": "chrome", "platform": "windows", "desktop": True},
            delay=10,
        )
    except ImportError:
        print(
            "[!] --stealth requires 'cloudscraper'. Install: pip install cloudscraper\n"
            "    Falling back to standard requests.",
            file=sys.stderr,
        )
        session = requests.Session()

    session.headers.update({"User-Agent": config.user_agent})
    if config.proxy:
        session.proxies.update({"http": config.proxy, "https": config.proxy})
    return session


def _build_session(config: Config) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": config.user_agent, **_BROWSER_HEADERS})
    if config.proxy:
        session.proxies.update({"http": config.proxy, "https": config.proxy})
    return session


def _same_origin(base: str, target: str) -> bool:
    b, t = urlparse(base), urlparse(target)
    return b.scheme == t.scheme and b.netloc == t.netloc


def _normalise_url(raw: str, base: str) -> str | None:
    abs_url = urljoin(base, raw.strip())
    return abs_url if abs_url.startswith(("http://", "https://")) else None


def _fetch_with_retry(
    session,
    url: str,
    config: Config,
    logger,
    extra_headers: dict | None = None,
) -> str | None:
    """
    GET url with bot-block detection, auto-escalation to cloudscraper,
    and DNS-aware fast-fail logic.
    """
    headers = extra_headers or {}

    for attempt in range(1, config.max_retries + 2):
        try:
            resp = session.get(url, headers=headers, timeout=config.timeout, allow_redirects=True)

            if _is_bot_blocked(resp):
                if not config.stealth_mode and attempt == 1:
                    logger.debug("Bot-block detected — auto-escalating to cloudscraper stealth.")
                    import dataclasses
                    stealth_cfg = dataclasses.replace(config, stealth_mode=True)
                    return _fetch_with_retry(
                        _build_stealth_session(stealth_cfg), url, stealth_cfg, logger, extra_headers
                    )
                logger.warning(
                    f"Bot protection on {url} (HTTP {resp.status_code}) — "
                    f"{'retry' if attempt <= config.max_retries else 'giving up'}"
                )
                if attempt <= config.max_retries:
                    time.sleep(2 ** attempt)
                    continue
                return None

            resp.raise_for_status()
            return resp.text

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout: {url} (attempt {attempt}/{config.max_retries + 1})")
        except requests.exceptions.TooManyRedirects:
            logger.warning(f"Too many redirects: {url}")
            return None
        except requests.exceptions.ConnectionError as exc:
            exc_str = str(exc).lower()
            if any(k in exc_str for k in ("nameresolutionerror", "failed to resolve", "name or service not known")):
                host = urlparse(url).netloc
                logger.error(
                    f"DNS resolution failed for '{host}'.\n"
                    f"  • Check for typos in the URL\n"
                    f"  • Verify your internet/DNS connection\n"
                    f"  • The domain may not exist"
                )
                return None
            logger.warning(f"Connection error: {url} — {exc} (attempt {attempt}/{config.max_retries + 1})")
        except requests.exceptions.HTTPError as exc:
            logger.warning(f"HTTP {exc.response.status_code}: {url}")
            return None
        except requests.exceptions.RequestException as exc:
            logger.warning(f"Request failed: {url} — {exc}")

        if attempt <= config.max_retries:
            time.sleep(1.5 * attempt)

    return None


# ------------------------------------------------------------------ #
# Main crawl entry point
# ------------------------------------------------------------------ #

def crawl(config: Config) -> list[JSSource]:
    """
    Three-tier crawl pipeline.

    1. Fetch the landing page HTML (using the appropriate backend).
    2. Extract <script src="..."> external references.
    3. Extract inline <script>...</script> blocks.
    4. Fetch each external JS file.
    5. Return deduplicated List[JSSource].
    """
    logger = get_logger(__name__, verbose=config.verbose)
    sources: list[JSSource] = []
    clearance_cookies: dict[str, str] = {}

    # ---------------------------------------------------------------- #
    # Step 1 — fetch landing page using the highest available tier
    # ---------------------------------------------------------------- #
    logger.debug(f"Fetching landing page: {config.url}")
    html: str | None = None

    if config.flaresolverr_url:
        # Tier 3a: FlareSolverr
        html, clearance_cookies = fetch_with_flaresolverr(config.url, config, logger)

    elif config.browser_mode:
        # Tier 3b: Playwright headless browser
        html = fetch_with_playwright(config.url, config, logger)

    else:
        # Tier 1/2: requests (+ optional cloudscraper)
        session = _build_stealth_session(config) if config.stealth_mode else _build_session(config)
        html = _fetch_with_retry(session, config.url, config, logger, _BROWSER_HEADERS)

    if not html:
        logger.error(f"Failed to fetch: {config.url}")
        return sources

    # Double-check we didn't land on a challenge page even in browser mode
    if is_challenge_page(html) and not config.browser_mode and not config.flaresolverr_url:
        logger.warning(
            "Response appears to be a bot challenge page.\n"
            "  Try one of:\n"
            "    --stealth              (Cloudflare JS challenge)\n"
            "    --browser              (Cloudflare Turnstile — needs Playwright)\n"
            "    --flaresolverr URL     (strongest — needs FlareSolverr running)"
        )

    # ---------------------------------------------------------------- #
    # Step 2 — build the requests session for JS file downloads
    # (inject FlareSolverr clearance cookies if we have them)
    # ---------------------------------------------------------------- #
    if config.browser_mode:
        # Use standard session for JS files; browser already solved challenge
        dl_session = _build_session(config)
    elif config.stealth_mode:
        dl_session = _build_stealth_session(config)
    else:
        dl_session = _build_session(config)

    if clearance_cookies:
        dl_session.cookies.update(clearance_cookies)
        logger.debug(f"Injected {len(clearance_cookies)} clearance cookie(s) into download session.")

    # ---------------------------------------------------------------- #
    # Step 3 — parse HTML, collect external JS URLs
    # ---------------------------------------------------------------- #
    soup = BeautifulSoup(html, "lxml")
    seen_urls: set[str] = set()
    external_urls: list[str] = []

    for tag in soup.find_all("script", src=True):
        raw_src: str = tag.get("src", "").strip()
        if not raw_src:
            continue
        abs_url = _normalise_url(raw_src, config.url)
        if abs_url is None:
            continue
        if not config.allow_external and not _same_origin(config.url, abs_url):
            logger.debug(f"Skipping cross-origin JS: {abs_url}")
            continue
        if abs_url not in seen_urls:
            seen_urls.add(abs_url)
            external_urls.append(abs_url)

    logger.debug(f"Found {len(external_urls)} external JS URL(s)")

    # ---------------------------------------------------------------- #
    # Step 4 — extract inline blocks
    # ---------------------------------------------------------------- #
    inline_count = 0
    for i, tag in enumerate(soup.find_all("script", src=False)):
        content = (tag.string or "").strip()
        if not content:
            continue
        sources.append(JSSource(
            url=f"inline:{config.url}#{i}",
            content=content,
            source_type=SourceType.INLINE,
        ))
        inline_count += 1

    logger.debug(f"Found {inline_count} inline script block(s)")

    # ---------------------------------------------------------------- #
    # Step 5 — download external JS files
    # ---------------------------------------------------------------- #
    for url in external_urls:
        rate_limit(config.delay)
        logger.debug(f"Fetching JS: {url}")
        content = _fetch_with_retry(dl_session, url, config, logger, _JS_HEADERS)
        if not content or not content.strip():
            logger.debug(f"Empty or blocked response: {url}")
            continue
        sources.append(JSSource(
            url=url,
            content=content.strip(),
            source_type=SourceType.EXTERNAL,
        ))

    logger.debug(f"Crawl complete. Total JS sources: {len(sources)}")
    return sources
