"""Async URL harvester — replaces crawler.py. BeautifulSoup4, no BS3."""

from __future__ import annotations

import asyncio
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from http_client import HTTPClient
from utils import Logger


async def crawl(
    root_url: str,
    depth: int,
    output_file: str,
    config,
    logger: Logger,
) -> None:
    """BFS crawl same-domain URLs, append to output file."""
    good_types = ("html", "php", "php4", "php5", "jsp", "htm", "py", "pl", "asp", "cgi", "/")
    domain = urlparse(root_url).netloc.lower()

    http = HTTPClient(
        user_agent=config.p_useragent,
        proxy=config.p_proxy,
        timeout=float(config.p_ttl),
        verify=not config.p_insecure,
    )

    urlpool: list[tuple[str, int]] = []

    try:
        # Normalize root URL
        if root_url.count("/") == 2:
            root_url = root_url + "/"

        logger.log("[0] Going to root URL: '%s'..." % root_url, 99)
        await _crawl_url(urlpool, root_url, 0, domain, good_types, depth, http, logger)

        idx = 0
        with open(output_file, "a") as f:
            while idx < len(urlpool):
                url, level = urlpool[idx]
                url = _encode_url(url)
                logger.log("[Done: %d | Todo: %d | Depth: %d] Going for next URL: '%s'..." % (
                    idx, len(urlpool) - idx, level, url), 99)
                f.write(url + "\n")
                f.flush()
                await _crawl_url(urlpool, url, level, domain, good_types, depth, http, logger)
                idx += 1
    finally:
        await http.close()

    logger.log("Harvesting done.", 99)


async def _crawl_url(
    urlpool: list[tuple[str, int]],
    url: str,
    level: int,
    domain: str,
    good_types: tuple,
    max_depth: int,
    http: HTTPClient,
    logger: Logger,
) -> None:
    if url.count("/") == 2:
        url += "/"

    body, _ = await http.get(url)

    if body is None:
        return

    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:
        return

    for tag in soup.find_all("a"):
        new_url = tag.get("href")
        if not new_url or new_url.startswith("#") or new_url.startswith("javascript:"):
            continue

        is_cool = False
        if new_url.startswith("http://") or new_url.startswith("https://"):
            if urlparse(new_url).netloc.lower() == domain:
                is_cool = True
        else:
            if new_url.startswith("/"):
                new_url = urljoin("http://" + domain, new_url)
            else:
                new_url = urljoin(url, new_url)
            is_cool = True

        if is_cool and _is_url_in_pool(urlpool, new_url):
            is_cool = False

        if is_cool:
            tmp = new_url
            if "?" in tmp:
                tmp = tmp[: tmp.find("?")]
            if any(tmp.endswith(s) for s in good_types):
                if level + 1 <= max_depth:
                    urlpool.append((new_url, level + 1))


def _is_url_in_pool(pool: list[tuple[str, int]], url: str) -> bool:
    url_lower = url.lower()
    return any(u.lower() == url_lower for u, _ in pool)


def _encode_url(url: str) -> str:
    """Percent-encode non-ASCII and unsafe chars."""
    ret = ""
    for c in url:
        if c.isalnum() or c in "=?&:/.,_-+#":
            ret += c
        else:
            ret += "%%%02X" % ord(c)
    return ret
