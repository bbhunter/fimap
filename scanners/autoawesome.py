"""AutoAwesome scan mode — replaces autoawesome.py.

Extracts forms, cookies, links from target URL and scans each.
"""

from __future__ import annotations

import asyncio
from copy import deepcopy
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from http_client import HTTPClient
from language import LanguageRegistry
from models import ScanResult
from scanners.single import scan_single
from utils import Logger


async def scan_autoawesome(
    url: str,
    config,
    lang_registry: LanguageRegistry,
    logger: Logger,
    concurrency: int = 10,
) -> list[ScanResult]:
    """AutoAwesome: crawl forms + cookies + links, scan each."""
    logger.log("Requesting '%s'..." % url, 99)

    http = HTTPClient(
        user_agent=config.p_useragent,
        proxy=config.p_proxy,
        timeout=float(config.p_ttl),
        verify=not config.p_insecure,
    )
    try:
        body, headers = await http.get_with_headers(url, additional_headers=config.header)
    finally:
        await http.close()

    if body is None:
        logger.log("Code == None! Does the target exist?! AutoAwesome mode failed.", 99)
        return []

    results: list[ScanResult] = []

    # Extract cookies
    ext_header = ""
    if headers:
        for h in headers:
            if h[0].lower() in ("set-cookie", "set-cookie2"):
                cookie_str = h[1]
                from http.cookies import SimpleCookie
                c = SimpleCookie()
                c.load(cookie_str)
                for k, v in c.items():
                    ext_header += "%s=%s; " % (k, c[k].value)

    if ext_header:
        logger.log("Cookies retrieved. Using them for further requests.", 99)
        ext_header = ext_header.strip()[:-1]  # remove trailing "; "

    if "Cookie" in config.header and ext_header:
        logger.log("WARNING: AutoAwesome mode got some cookies from the server.", 99)
        logger.log("Your defined cookies will be overwritten!", 99)

    if ext_header:
        logger.log("Testing file inclusion against given cookies...", 99)
        mod_config = deepcopy(config)
        mod_config.header = deepcopy(config.header)
        mod_config.header["Cookie"] = ext_header
        r = await scan_single(url, mod_config, lang_registry, logger, concurrency, quiet=True)
        results.extend(r)

    # Parse forms
    soup = BeautifulSoup(body, "html.parser")
    idx = 0
    for form in soup.find_all("form"):
        idx += 1
        caption = form.get("name", "Unnamed Form #%d" % idx)
        desturl = form.get("action", url)
        method_str = (form.get("method") or "post").lower()

        # Resolve relative URLs
        if not desturl.startswith("http"):
            desturl = urljoin(url, desturl)

        method = 0 if method_str == "get" else 1

        params = ""
        for inp in form.find_all("input"):
            input_name = inp.get("name")
            if input_name:
                input_val = inp.get("value", "")
                params += "%s=%s&" % (input_name, input_val)

        if params.endswith("&"):
            params = params[:-1]

        logger.log("Analyzing form '%s' for file inclusion bugs." % caption, 99)

        mod_config = deepcopy(config)
        if method == 0:
            if "?" in desturl:
                desturl = "%s&%s" % (desturl, params)
            else:
                desturl = "%s?%s" % (desturl, params)
        else:
            current_post = mod_config.p_post or ""
            mod_config.p_post = "%s&%s" % (current_post, params) if current_post else params

        r = await scan_single(desturl, mod_config, lang_registry, logger, concurrency, quiet=True)
        results.extend(r)

    # Harvest links at depth 0
    logger.log("Starting harvester engine to get links (Depth: 0)...", 99)
    domain = urlparse(url).netloc
    link_pool: list[tuple[str, int]] = []

    for tag in soup.find_all("a"):
        href = tag.get("href")
        if not href or href.startswith("#") or href.startswith("javascript:"):
            continue
        if not href.startswith("http://") and not href.startswith("https://"):
            href = urljoin(url, href)
        if urlparse(href).netloc.lower() != domain.lower():
            continue

        tmp = href.split("?")[0]
        good_types = ("html", "php", "php4", "php5", "jsp", "htm", "py", "pl", "asp", "cgi", "/")
        if any(tmp.endswith(s) for s in good_types):
            if not any(u.lower() == href.lower() for u, _ in link_pool):
                link_pool.append((href, 0))

    if not link_pool:
        logger.log("No links found.", 99)
    else:
        logger.log("Harvesting done. %d links found. Analyzing links now..." % len(link_pool), 99)
        semaphore = asyncio.Semaphore(concurrency)

        async def _scan_link(u: str) -> list[ScanResult]:
            async with semaphore:
                return await scan_single(str(u), config, lang_registry, logger, concurrency, quiet=True)

        tasks = [_scan_link(u) for u, _ in link_pool]
        link_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in link_results:
            if isinstance(r, list):
                results.extend(r)

    logger.log("AutoAwesome is done.", 99)
    return results
