"""Single URL scan mode — replaces singleScan.py."""

from __future__ import annotations

import asyncio
from copy import deepcopy

from http_client import HTTPClient
from language import LanguageRegistry
from models import ScanResult
from scanner import FileInclusionScanner
from utils import Logger, draw_box


async def scan_single(
    url: str,
    config,
    lang_registry: LanguageRegistry,
    logger: Logger,
    concurrency: int = 10,
    quiet: bool = False,
) -> list[ScanResult]:
    """Scan a single URL for file inclusion bugs."""
    results: list[ScanResult] = []

    http = HTTPClient(
        user_agent=config.p_useragent,
        proxy=config.p_proxy,
        timeout=float(config.p_ttl),
        verify=not config.p_insecure,
    )
    try:
        semaphore = asyncio.Semaphore(concurrency)
        scanner = FileInclusionScanner(config, lang_registry, http, logger, semaphore)
        scanner.monkey_technique = config.p_monkeymode

        if not quiet:
            logger.log("SingleScan is testing URL: '%s'" % url, 99)  # ponytail: LOG_ALWAYS

        if scanner.prepare_target(url):
            res = await scanner.test_target_vuln()
            for rep, files in res:
                results.append(ScanResult(report=rep, readable_files=files))

            if not quiet:
                if not res:
                    logger.log("Target URL isn't affected by any file inclusion bug :(", 99)
                else:
                    _print_results(results, logger)
    finally:
        await http.close()

    return results


def _print_results(results: list[ScanResult], logger: Logger) -> None:
    """Print results in original singleScan box format."""
    for idx, r in enumerate(results, start=1):
        rep = r.report
        files = r.readable_files
        boxarr: list[str] = []

        header = "[%d] Possible File Inclusion" % idx
        if rep.getLanguage():
            header = "[%d] Possible %s-File Inclusion" % (idx, rep.getLanguage())

        boxarr.append("::REQUEST")
        boxarr.append("  [URL]        %s" % rep.getURL())
        if rep.getPostData():
            boxarr.append("  [POST]       %s" % rep.getPostData())
        header_dict = rep.getHeader()
        if header_dict and header_dict.keys():
            modkeys = ",".join(header_dict.keys())
            boxarr.append("  [HEAD SENT]  %s" % modkeys)

        boxarr.append("::VULN INFO")
        if rep.isPost == 0:
            boxarr.append("  [GET PARAM]  %s" % rep.getVulnKey())
        elif rep.isPost == 1:
            boxarr.append("  [POSTPARM]   %s" % rep.getVulnKey())
        elif rep.isPost == 2:
            boxarr.append("  [VULN HEAD]  %s" % rep.getVulnHeader())
            boxarr.append("  [VULN PARA]  %s" % rep.getVulnKey())

        if rep.isBlindDiscovered():
            boxarr.append("  [PATH]       Not received (Blindmode)")
        else:
            boxarr.append("  [PATH]       %s" % rep.getServerPath())

        boxarr.append("  [OS]         %s" % ("Unix" if rep.isUnix() else "Windows"))
        boxarr.append("  [TYPE]       %s" % rep.getType())

        if not rep.isBlindDiscovered():
            if rep.isSuffixBreakable() is None:
                boxarr.append("  [TRUNCATION] No Need. It's clean.")
            else:
                if rep.isSuffixBreakable():
                    boxarr.append("  [TRUNCATION] Works with '%s'. :)" % rep.getSuffixBreakTechName())
                else:
                    boxarr.append("  [TRUNCATION] Doesn't work. :(")
        else:
            if rep.isSuffixBreakable():
                boxarr.append("  [TRUNCATION] Is needed.")
            else:
                boxarr.append("  [TRUNCATION] Not tested.")

        boxarr.append("  [READABLE FILES]")
        if not files:
            boxarr.append("                     No Readable files found :(")
        else:
            for fidx, f in enumerate(files):
                payload = "%s%s%s" % (rep.getPrefix() or "", f, rep.getSurfix())
                if f != payload:
                    display_f = f[3:] if rep.isWindows() and len(f) > 1 and f[1] == ":" else f
                    boxarr.append("                   [%d] %s -> %s" % (fidx, display_f, payload))
                else:
                    boxarr.append("                   [%d] %s" % (fidx, f))

        draw_box(header, boxarr, False)
