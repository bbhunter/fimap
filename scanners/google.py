"""Google scan mode — STUB. Google HTML scraping broken since ~2014.

Prints deprecation warning. Use mass mode with pre-gathered URLs instead.
"""

from __future__ import annotations

from models import ScanResult


async def scan_google(
    query: str,
    pages: int,
    config,
    lang_registry,
    logger,
    results_per_query: int = 100,
    skip_pages: int = 0,
    cooldown: int = 5,
) -> list[ScanResult]:
    """Google scanner stub — always returns empty with deprecation warning."""
    logger.log(
        "Google scanning is no longer supported. "
        "Google HTML scraping has been broken since ~2014 and requires JavaScript. "
        "Use mass mode (-m) with pre-gathered URLs instead.", 99
    )
    return []
