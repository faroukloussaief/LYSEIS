"""
lyseis.browser
~~~~~~~~~~~~~~
Headless browser fetch engine for pages protected by Cloudflare Turnstile
and other JavaScript-rendered bot challenges that cloudscraper cannot solve.

Two backends supported:

  1. Playwright (--browser)
     Launches a local Chromium headless browser with stealth patches.
     Gives Turnstile time to execute and resolve before capturing HTML.
     Requires:
       pip install playwright playwright-stealth
       playwright install chromium

  2. FlareSolverr (--flaresolverr http://localhost:8191)
     Delegates to a running FlareSolverr instance, which handles the
     full Cloudflare challenge lifecycle using a real browser internally.
     Returns validated clearance cookies that are injected into the regular
     requests session for all subsequent JS file downloads.
     Requires: https://github.com/FlareSolverr/FlareSolverr (Docker or pip)
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Config


# ------------------------------------------------------------------ #
# Challenge page signatures (for post-fetch validation)
# ------------------------------------------------------------------ #

_CHALLENGE_INDICATORS: list[str] = [
    "cf-browser-verification",
    "checking your browser",
    "just a moment",
    "cloudflare turnstile",
    "cf_chl_opt",
    "security check",
    "verify you are human",
    "enable javascript and cookies to continue",
    "access denied",
    "ray id",   # CF footer
    "cf-ray",
    "datadome",
    "incapsula",
    "perímeterx",
    "_pxhd",
]


def is_challenge_page(html: str) -> bool:
    """Return True if the HTML appears to still be a bot-challenge page."""
    lower = html.lower()
    return any(sig in lower for sig in _CHALLENGE_INDICATORS)


# ================================================================== #
# Backend 1: Playwright
# ================================================================== #

def fetch_with_playwright(url: str, config: "Config", logger) -> str | None:
    """
    Use Playwright (headless Chromium) to fetch a URL.
    Applies playwright-stealth patches if installed, then waits for
    Cloudflare Turnstile / JS challenges to resolve before returning HTML.
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        logger.error(
            "Browser mode requires Playwright. Install it on Kali with:\n"
            "  pip install playwright playwright-stealth\n"
            "  playwright install chromium"
        )
        return None

    # Stealth patches are optional — degrade gracefully
    stealth_fn = None
    try:
        from playwright_stealth import stealth_sync as _stealth_sync
        stealth_fn = _stealth_sync
        logger.debug("playwright-stealth patches loaded.")
    except ImportError:
        logger.debug("playwright-stealth not installed; running without stealth patches.")

    logger.debug(f"Launching headless Chromium for: {url}")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-gpu",
                    "--window-size=1920,1080",
                    "--disable-infobars",
                    "--lang=en-US,en",
                ],
            )
            context = browser.new_context(
                user_agent=config.user_agent,
                viewport={"width": 1920, "height": 1080},
                locale="en-US",
                timezone_id="America/New_York",
                extra_http_headers={
                    "Accept-Language": "en-US,en;q=0.9",
                    "DNT": "1",
                },
            )
            page = context.new_page()

            if stealth_fn:
                stealth_fn(page)

            try:
                # Navigate; domcontentloaded is faster than networkidle
                page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=config.timeout * 1000,
                )

                # Give Turnstile / JS challenge time to run (first wait)
                page.wait_for_timeout(6_000)

                html = page.content()

                # If still on challenge page, wait longer
                if is_challenge_page(html):
                    logger.debug("Challenge page still active; waiting additional 10s...")
                    page.wait_for_timeout(10_000)
                    html = page.content()

                if is_challenge_page(html):
                    logger.warning(
                        "Browser could not bypass the challenge page for this target.\n"
                        "  This may be an unsolvable Turnstile (human verification required).\n"
                        "  Try --flaresolverr if you have a FlareSolverr instance running."
                    )
                    return None

                logger.debug(f"Browser successfully fetched: {url}")
                return html

            except PWTimeout:
                logger.warning(f"Browser timed out navigating to: {url}")
                try:
                    return page.content() or None
                except Exception:
                    return None
            finally:
                try:
                    browser.close()
                except Exception:
                    pass

    except Exception as exc:
        logger.error(f"Browser fetch error: {exc}")
        return None


# ================================================================== #
# Backend 2: FlareSolverr
# ================================================================== #

def fetch_with_flaresolverr(
    url: str,
    config: "Config",
    logger,
) -> tuple[str | None, dict[str, str]]:
    """
    Delegate the page fetch to a running FlareSolverr v3 instance.

    FlareSolverr handles the full Cloudflare challenge lifecycle using
    a real browser (Puppeteer/Chrome) internally, including Turnstile.

    Returns: (html_content, clearance_cookies)
      - clearance_cookies should be injected into the requests session
        for all subsequent JS file downloads from the same domain.
    """
    import requests as _requests

    endpoint = f"{config.flaresolverr_url.rstrip('/')}/v1"
    payload = {
        "cmd": "request.get",
        "url": url,
        "maxTimeout": max(config.timeout * 1000, 60_000),
    }

    logger.debug(f"Sending request to FlareSolverr at {endpoint}")

    try:
        resp = _requests.post(endpoint, json=payload, timeout=120)
        data = resp.json()

        if data.get("status") != "ok":
            logger.error(
                f"FlareSolverr error: {data.get('message', 'Unknown error')}\n"
                f"  Make sure FlareSolverr is running at {config.flaresolverr_url}"
            )
            return None, {}

        solution = data.get("solution", {})
        html    = solution.get("response", "")
        cookies = {c["name"]: c["value"] for c in solution.get("cookies", [])}

        logger.debug(
            f"FlareSolverr solved challenge. "
            f"Clearance cookies received: {list(cookies.keys())}"
        )
        return html, cookies

    except _requests.exceptions.ConnectionError:
        logger.error(
            f"Cannot connect to FlareSolverr at '{config.flaresolverr_url}'.\n"
            "  Start it with:\n"
            "    docker run -d -p 8191:8191 flaresolverr/flaresolverr:latest\n"
            "  Or install via pip:\n"
            "    pip install flaresolverr && flaresolverr"
        )
        return None, {}
    except Exception as exc:
        logger.error(f"FlareSolverr request failed: {exc}")
        return None, {}
