"""Mass URL scan mode — replaces massScan.py."""

from __future__ import annotations

import asyncio

from http_client import HTTPClient
from language import LanguageRegistry
from models import ScanResult
from scanners.single import scan_single
from utils import Logger


async def scan_mass(
    url_list: list[str],
    config,
    lang_registry: LanguageRegistry,
    logger: Logger,
    concurrency: int = 10,
) -> list[ScanResult]:
    """Scan a list of URLs for file inclusion bugs."""
    logger.log("MassScan reading %d URLs..." % len(url_list), 99)

    all_results: list[ScanResult] = []
    semaphore = asyncio.Semaphore(concurrency)

    async def _scan_one(idx: int, url: str) -> list[ScanResult]:
        async with semaphore:
            logger.log("[%d][MASS_SCAN] Scanning: '%s'..." % (idx, url), 99)
            return await scan_single(url, config, lang_registry, logger, concurrency=concurrency, quiet=True)

    tasks = []
    for idx, url in enumerate(url_list):
        url = url.strip()
        if url.startswith("http://") or url.startswith("https://"):
            tasks.append(_scan_one(idx, url))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            all_results.extend(r)

    logger.log("MassScan completed.", 99)
    return all_results
