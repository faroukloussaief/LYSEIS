"""
lyseis.utils
~~~~~~~~~~~~
Shared helpers: logger factory and rate-limit delay.
All log output is directed to stderr to keep stdout clean for data.
"""

import logging
import sys
import time


def get_logger(name: str, verbose: bool = False) -> logging.Logger:
    """Return a named logger that writes to stderr only."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        level = logging.DEBUG if verbose else logging.WARNING
        handler.setLevel(level)
        formatter = logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger


def rate_limit(delay: float) -> None:
    """Sleep for `delay` seconds between HTTP requests to avoid hammering the target."""
    if delay > 0:
        time.sleep(delay)
