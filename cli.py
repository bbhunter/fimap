"""CLI entry point — argparse port of original getopt flags.

Ported from fimap.py __main__ block. Dispatches to scanner or exploit mode.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile

from config import AppConfig
from http_client import HTTPClient
from language import LanguageRegistry
from utils import Logger
from xml_store import XMLResultStore


VERSION = "2.0.0-dev"

HEAD = (
    "fimap v.%s\n"
    ":: Automatic LFI/RFI scanner and exploiter\n"
    ":: by Iman Karim (fimap.dev@gmail.com)\n"
    ":: Python 3 port — https://github.com/fimap\n"
) % VERSION


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fimap",
        description="Automatic LFI/RFI scanner and exploiter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )

    #=== Operating Modes =======================================================
    mode = p.add_argument_group("Operating Modes")
    mode.add_argument("-s", "--single", action="store_const", dest="mode", const=0,
                      help="Scan a single URL for FI errors (default)")
    mode.add_argument("-m", "--mass", action="store_const", dest="mode", const=1,
                      help="Mass scan from a URL list (-l)")
    mode.add_argument("-g", "--google", action="store_const", dest="mode", const=2,
                      help="Google search for URLs (-q)")
    mode.add_argument("-B", "--bing", action="store_const", dest="mode", const=5,
                      help="Bing search for URLs (-q, --bingkey)")
    mode.add_argument("-H", "--harvest", action="store_const", dest="mode", const=3,
                      help="Crawl a URL recursively (-u, -w)")
    mode.add_argument("-4", "--autoawesome", action="store_const", dest="mode", const=4,
                      help="AutoAwesome: scan all forms/headers on a site (-u)")

    #=== Target =================================================================
    target = p.add_argument_group("Target")
    target.add_argument("-u", "--url", help="Target URL")
    target.add_argument("-l", "--list", help="URL list file (mass mode)")
    target.add_argument("-q", "--query", help="Search query (Google/Bing mode)")

    #=== HTTP ===================================================================
    http_g = p.add_argument_group("HTTP")
    http_g.add_argument("-A", "--user-agent", default=None, help="Custom User-Agent")
    http_g.add_argument("--http-proxy", default=None, help="HTTP proxy (host:port)")
    http_g.add_argument("--cookie", default=None, help="Cookie string")
    http_g.add_argument("--header", action="append", default=None,
                        help="Custom header (Name:Value). Repeat for multiple.")
    http_g.add_argument("--ttl", type=int, default=30, help="Request timeout seconds (default: 30)")
    http_g.add_argument("-P", "--post", default="", help="POST data string")

    #=== Scanner ================================================================
    scan = p.add_argument_group("Scanner")
    scan.add_argument("-b", "--enable-blind", action="store_true", help="Enable blind FI testing")
    scan.add_argument("-D", "--dot-truncation", action="store_true", help="Enable dot truncation")
    scan.add_argument("--dot-trunc-min", type=int, default=700,
                      help="Dot truncation min dots (default: 700)")
    scan.add_argument("--dot-trunc-max", type=int, default=2000,
                      help="Dot truncation max dots (default: 2000)")
    scan.add_argument("--dot-trunc-step", type=int, default=50,
                      help="Dot truncation step size (default: 50)")
    scan.add_argument("--dot-trunc-ratio", type=float, default=0.095,
                      help="Dot truncation max ratio (default: 0.095)")
    scan.add_argument("--dot-trunc-also-unix", action="store_true",
                      help="Also try dot truncation on Unix servers")
    scan.add_argument("-M", "--multiply-term", type=int, default=1,
                      help="Multiply terminal symbols (../ → ....//)")
    scan.add_argument("--no-auto-detect", action="store_true",
                      help="Disable auto language detection in blind mode")
    scan.add_argument("--bmin", type=int, default=None, help="Blind min depth override")
    scan.add_argument("--bmax", type=int, default=None, help="Blind max depth override")
    scan.add_argument("--force-os", choices=["linux", "windows", "unix"], default=None,
                      help="Force OS: linux or windows")
    scan.add_argument("--rfi-encoder", choices=["php_b64"], default=None,
                      help="RFI payload encoder")
    scan.add_argument("--encode-chain", default=None,
                      help="Chainable encodings: url,double_url,base64 (comma-separated)")
    scan.add_argument("--oob-domain", default=None,
                      help="DNS callback domain for blind LFI confirmation")

    #=== Google scanner =========================================================
    goog = p.add_argument_group("Google Scanner")
    goog.add_argument("-p", "--pages", type=int, default=10, help="Google search pages (default: 10)")
    goog.add_argument("--results", type=int, default=100,
                      help="Results per page: 10, 25, 50, 100 (default: 100)")
    goog.add_argument("--googlesleep", type=int, default=5,
                      help="Cooldown seconds between Google requests (default: 5)")
    goog.add_argument("--skip-pages", type=int, default=0,
                      help="Skip first N pages from Google scanner")

    #=== Bing scanner ===========================================================
    bing = p.add_argument_group("Bing Scanner")
    bing.add_argument("--bingkey", default=None, help="Bing API key")

    #=== Exploit ================================================================
    exploit = p.add_argument_group("Exploit")
    exploit.add_argument("-x", "--exploit", action="store_true",
                         help="Start interactive exploit shell (exploitable only)")
    exploit.add_argument("-X", action="store_true", dest="exploit_all",
                         help="Start exploit shell (show all domains)")
    exploit.add_argument("-T", "--tab-complete", action="store_true",
                         help="Enable tab completion in exploit shell (needs readline)")
    exploit.add_argument("--x-host", help="Preselect domain in exploit mode")
    exploit.add_argument("--x-vuln", type=int, help="Preselect vulnerability ID")
    exploit.add_argument("--x-cmd", action="append", default=None,
                         help="Command to execute on target (repeat for batch)")

    #=== Crawl ==================================================================
    crawl_g = p.add_argument_group("Crawl / Harvest")
    crawl_g.add_argument("-w", "--write", help="Output file for harvested URLs")
    crawl_g.add_argument("-d", "--depth", type=int, default=1, help="Crawl recurse depth (default: 1)")

    #=== Output =================================================================
    out = p.add_argument_group("Output")
    out.add_argument("-v", "--verbose", type=int, default=2, choices=[0, 1, 2, 3],
                      help="Verbose level: 0=High, 1=Messages, 2=Info(default), 3=Debug")
    out.add_argument("-C", "--enable-color", action="store_true", help="Enable colored output")

    #=== Other ==================================================================
    other = p.add_argument_group("Other")
    other.add_argument("-h", "--help", action="help", help="Show this help and exit")
    other.add_argument("--force-run", action="store_true", help="Ignore instance lockfile")
    other.add_argument("--test-rfi", action="store_true", help="Test RFI configuration")
    other.add_argument("--merge-xml", help="Merge another fimap_result.xml")
    other.add_argument("--show-my-ip", action="store_true", help="Show your IP and user-agent")
    other.add_argument("--credits", action="store_true", help="Show credits")
    other.add_argument("--greetings", action="store_true", help="Show greetings")
    other.add_argument("--plugins", action="store_true", help="List loaded plugins")
    other.add_argument("-I", "--install-plugins", action="store_true",
                        help="Install/upgrade official plugins")
    other.add_argument("--update-def", action="store_true",
                        help="Check for definition file updates")
    other.add_argument("--version", action="version", version="fimap v" + VERSION)

    return p


def _build_config(args: argparse.Namespace) -> AppConfig:
    """Build AppConfig from parsed args."""
    config = AppConfig()

    # Mode
    config.p_mode = args.mode if args.mode is not None else 0

    # Target
    config.p_url = args.url
    config.p_list = args.list
    config.p_query = args.query

    # HTTP
    if args.user_agent is not None:
        config.p_useragent = args.user_agent
    config.p_proxy = args.http_proxy
    config.p_ttl = args.ttl
    config.p_post = args.post or ""

    # Headers
    if args.cookie:
        config.header["Cookie"] = args.cookie
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                config.header[k.strip()] = v.strip()
            else:
                config.header[h] = ""

    # Scanner
    config.p_monkeymode = args.enable_blind
    config.p_doDotTruncation = args.dot_truncation
    config.p_dot_trunc_min = args.dot_trunc_min
    config.p_dot_trunc_max = args.dot_trunc_max
    config.p_dot_trunc_step = args.dot_trunc_step
    config.p_dot_trunc_ratio = args.dot_trunc_ratio
    config.p_dot_trunc_only_win = not args.dot_trunc_also_unix
    config.p_multiply_term = args.multiply_term
    config.p_autolang = not args.no_auto_detect
    config.p_bmin = args.bmin
    config.p_bmax = args.bmax
    if args.force_os == "linux":
        config.force_os = "linux"
    elif args.force_os in ("windows", "unix"):
        config.force_os = args.force_os
    config.p_rfi_encode = args.rfi_encoder
    config.p_encode_chain = args.encode_chain
    config.p_oob_domain = args.oob_domain

    # Google
    config.p_pages = args.pages
    config.p_results_per_query = args.results
    config.p_googlesleep = args.googlesleep
    config.p_skippages = args.skip_pages

    # Bing
    config.p_bingkey = args.bingkey

    # Exploit
    config.p_tabcomplete = args.tab_complete
    config.p_exploit_domain = args.x_host
    config.p_exploit_script_id = args.x_vuln
    config.p_exploit_cmds = args.x_cmd

    # Crawl
    config.p_write = args.write
    config.p_depth = args.depth

    # Output
    config.p_verbose = args.verbose
    config.p_color = args.enable_color

    # Other
    config.force_run = args.force_run
    config.p_mergexml = args.merge_xml
    config.p_plugins = args.plugins

    return config


def _lockfile_check(config: AppConfig) -> None:
    """Check for existing fimap lockfile."""
    lock_found = False
    cur_lockfile = None
    tmpdir = tempfile.gettempdir()
    for f in os.listdir(tmpdir):
        if f.startswith("fimap_") and f.endswith("_lockfile"):
            lock_found = True
            cur_lockfile = f
            break

    if lock_found:
        if config.force_run:
            print("Another fimap instance is running! But you requested to ignore that...")
        else:
            print("Another fimap instance is already running!")
            print("If you think this is not correct please delete:")
            print("-> " + os.path.join(tmpdir, cur_lockfile or ""))
            print("or start fimap with '--force-run' on your own risk.")
            sys.exit(0)
    else:
        # Create lockfile
        lockfile = tempfile.NamedTemporaryFile(prefix="fimap_", suffix="_lockfile", delete=False)
        # pony: lockfile auto-cleaned on process exit via tempfile module


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    config = _build_config(args)

    logger = Logger(verbose=config.p_verbose, use_color=config.p_color)

    #=== Quick mode flags (no scanning needed) ==================================
    if args.credits:
        _show_credits()
    if args.greetings:
        _show_greetings()
    if args.plugins:
        _show_plugins()
    if args.install_plugins:
        _show_install_plugins(config, logger)
    if args.update_def:
        _show_update_def()

    #=== Exploit mode ===========================================================
    if args.exploit or args.exploit_all:
        _lockfile_check(config)

        # Bootstrap exploit shell
        config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")
        lang_reg = LanguageRegistry(config_dir)
        http = HTTPClient(
            user_agent=config.p_useragent,
            proxy=config.p_proxy,
            timeout=config.p_ttl,
            verify=not config.p_insecure,
        )
        xml_store = XMLResultStore(logger)

        # Upgrade old XML if needed
        xml_store.test_if_xml_is_old_school()

        from exploit.shell import FimapShell
        shell = FimapShell(config, lang_reg, http, logger, xml_store)
        only_exploitable = not args.exploit_all
        try:
            shell.start(only_exploitable=only_exploitable)
        except KeyboardInterrupt:
            print("\n\nYou killed me brutally. Wtf!\n\n")
            sys.exit(0)

    #=== RFI test ===============================================================
    if args.test_rfi:
        _test_rfi(config, logger)

    #=== Merge XML ==============================================================
    if args.merge_xml:
        xml_store = XMLResultStore(logger)
        new_vulns, new_domains = xml_store.merge_xml(args.merge_xml)
        print("%d new vulnerabilities added from %d new domains." % (new_vulns, new_domains))
        sys.exit(0)

    #=== Show IP ================================================================
    if args.show_my_ip:
        _show_my_ip(config, logger)

    #=== Scanning modes =========================================================
    if config.p_mode == 0 and config.p_url is None:
        print("Target URL required. (-u)")
        sys.exit(1)
    if config.p_mode == 1 and config.p_list is None:
        print("URLList required. (-l)")
        sys.exit(1)
    if config.p_mode == 2 and config.p_query is None:
        print("Google Query required. (-q)")
        sys.exit(1)
    if config.p_mode == 5 and config.p_query is None:
        print("Bing Query required. (-q)")
        sys.exit(1)
    if config.p_mode == 5 and config.p_bingkey is None:
        print("Bing APIKey required. (--bingkey)")
        sys.exit(1)
    if config.p_mode == 3 and config.p_url is None:
        print("Start URL required for harvesting. (-u)")
        sys.exit(1)
    if config.p_mode == 3 and config.p_write is None:
        print("Output file for harvested URLs required. (-w)")
        sys.exit(1)
    if config.p_mode == 4 and config.p_url is None:
        print("Root URL required for AutoAwesome. (-u)")
        sys.exit(1)

    if config.p_monkeymode:
        print("Blind FI-error checking enabled.")

    if config.force_os and config.force_os not in ("unix", "windows", "linux"):
        print("Invalid parameter for 'force-os'.")
        print("Only 'unix', 'windows', or 'linux' are allowed!")
        sys.exit(1)
    if config.force_os == "linux":
        config.force_os = "unix"

    if config.p_proxy:
        print("Using HTTP-Proxy '%s'." % config.p_proxy)

    #=== Scanner dispatch (deferred to scan phase) ==============================
    print(HEAD)
    print("Scanning not yet integrated with CLI. Use exploit mode (-x) for now.")
    print("Scanner port is in progress.")


#=== Static helpers =============================================================

def _show_credits() -> None:
    print("## Credits:")
    print("## Developer: Iman Karim (ikarim2s@smail.inf.fh-brs.de)")
    print("## Python 3 Port: https://github.com/fimap")
    print("#")
    print("## Project Home: http://fimap.googlecode.com")
    print("#")
    print("## Additional Thanks to:")
    print("   - Peteris Krumins (peter@catonmat.net) for xgoogle python module.")
    print("   - Pentestmonkey from www.pentestmonkey.net for php-reverse-shell.")
    print("   - Crummy from www.crummy.com for BeautifulSoup.")
    print("   - zeth0 from commandline.org.uk for ssh.py.")
    sys.exit(0)


def _show_greetings() -> None:
    print("## Greetings to the Circle of Awesome People:")
    print("(alphabetically)")
    print(" - Alpina, Chicano, Exorzist, IngoWer, Invisible")
    print(" - Maelius, MarcosKhan, Martinius, MorbiusPrime")
    print(" - Ruun, Satyros, Yasmin")
    print(" Special Greetings to the whole Netherlands.")
    sys.exit(0)


def _show_plugins() -> None:
    print("No plugins loaded. Plugin system not yet ported.")
    sys.exit(0)


def _show_install_plugins(config: AppConfig, logger: Logger) -> None:
    print("Plugin installation not yet supported in Python 3 port.")
    sys.exit(0)


def _show_update_def() -> None:
    print("Definition update check not yet ported.")
    sys.exit(0)


def _test_rfi(config: AppConfig, logger: Logger) -> None:
    """Test RFI configuration (port of codeinjector.testRFI)."""
    import asyncio

    from exploit.rfi import RFIHandler
    from http_client import HTTPClient
    from language import LanguageRegistry

    config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")
    lang_reg = LanguageRegistry(config_dir)
    http = HTTPClient(
        user_agent=config.p_useragent,
        proxy=config.p_proxy,
        timeout=config.p_ttl,
    )
    rfi = RFIHandler(config, http, logger)

    mode = config.rfi.mode

    for lang_name, lang_obj in lang_reg.getAllLangSets().items():
        print("Testing language %s..." % lang_name)
        quiz_code, quiz_answer = lang_obj.generateQuiz()
        encoded = rfi.payload_encode(quiz_code)

        if mode == "local":
            print("Testing Local->RFI configuration...")
            local_url = config.rfi.local_http_map or ""
            code = rfi.execute_rfi(local_url, "", "", quiz_code, {})
            if code and encoded.strip() == code.strip():
                print("Dynamic RFI works!")
                for ext in lang_obj.getExtentions():
                    print("Testing %s interpreter..." % ext)
                    code2 = rfi.execute_rfi(local_url + ext, "", ext, quiz_code, {})
                    if code2 and quiz_answer in code2:
                        print("WARNING! Files ending with %s will be interpreted!" % ext)
                    else:
                        pass
            else:
                print("Failed! Something went wrong...")

        elif mode == "ftp":
            print("Testing FTP->RFI configuration...")
            ftp_url = config.rfi.ftp_http_map or ""
            code = rfi.execute_rfi(ftp_url, "", "", quiz_code, {})
            if code and encoded.strip() == code.strip():
                print("Dynamic RFI works!")
                for ext in lang_obj.getExtentions():
                    print("Testing %s interpreter..." % ext)
                    code2 = rfi.execute_rfi(ftp_url + ext, "", ext, quiz_code, {})
                    if code2 and quiz_answer in code2:
                        print("WARNING! Files ending with %s will be interpreted!" % ext)
                    else:
                        pass
            else:
                print("Failed! Something went wrong...")
                if code:
                    print("Code: " + code)
        else:
            print("You haven't enabled and/or configured fimap RFI mode.")
            print("Fix that in config.py")
            sys.exit(0)

    sys.exit(0)


def _show_my_ip(config: AppConfig, logger: Logger) -> None:
    """Show internet IP, country, user-agent."""
    import asyncio

    from http_client import HTTPClient

    print("Heading to 'http://85.214.72.67/show_my_ip'...")
    print("-" * 46)

    http = HTTPClient(
        user_agent=config.p_useragent,
        proxy=config.p_proxy,
        timeout=config.p_ttl,
    )

    async def _fetch():
        body, _ = await http.get("http://85.214.72.67/show_my_ip")
        await http.close()
        return body

    result = asyncio.run(_fetch())
    if result is None:
        print("result = None -> Failed! Maybe you have no connection or bad proxy?")
        sys.exit(1)
    print(result.strip())
    sys.exit(0)


if __name__ == "__main__":
    main()
