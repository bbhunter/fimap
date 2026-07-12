# fimap v2.0 — Automatic LFI/RFI Scanner and Exploiter

fimap is a tool which can find, prepare, audit, exploit and even search automatically for local and remote file inclusion bugs in webapps. fimap aims to be what [sqlmap](https://sqlmap.org) is for SQL injection — but for LFI/RFI bugs.

**Original author:** [Iman Karim](mailto:fimap.dev@gmail.com) (fimap v1.00, 2009–2012, GPLv2)

fimap v2.0 is a full Python 3 rewrite: async I/O, type-safe configuration, zero `exec()` calls, SSL verification on by default, no `pickle`. All original exploit logic preserved and extended with modern LFI→RCE techniques.

Original project home: [fimap.googlecode.com](http://fimap.googlecode.com) (archived)

---

## What fimap Does

### Scanning & Discovery
*   Single URL, mass URL list, or Google search scanning.
*   Identify file inclusion bugs: `include`, `include_once`, `require`, `require_once`.
*   Scans GET parameters, POST parameters, and HTTP headers.
*   Blind mode (`--enable-blind`) for servers with error messages disabled.
*   AutoAwesome mode: auto-discover forms, cookies, and links, then scan them.
*   Harvest mode: crawl a site recursively and collect URLs.

### Exploitation
*   Interactive exploit shell (`-x`) with tab-completion and command execution.
*   Non-interactive exploiting (`--x-cmd`).
*   Reverse shells, payload execution, file read/write.

### LFI→RCE Techniques
*   **Logfile Injection** — 5 vectors across 66 log paths:
    *   `LA` Authorization header (base64-encoded, survives URI mangling)
    *   `LH` Apache User-Agent (with `?`-path fallback)
    *   `LF` vsftpd FTP username injection
    *   `LS` SSH username injection (paramiko)
    *   `LE` Email/SMTP injection
*   **`/proc/self/environ`** — User-Agent reflection in process environment.
*   **PHP_SESSION_UPLOAD_PROGRESS** — Forge PHP sessions via multipart POST.
*   **PHP filter chains** — Generate arbitrary PHP code from `php://filter` without file writes (full 64-char base64 alphabet mapped).
*   **pearcmd.php RCE** — Docker/default PHP image gadget (`+config-create+`).
*   **php://input** — POST body code injection.
*   **phar:// deserialization** — Trigger deserialization via `phar://` wrapper.
*   **zip:// wrapper** — Include PHP from inside uploaded ZIP archives.

### Payload Engineering
*   Relative/absolute path handling with automatic prefix/suffix calculation.
*   Null-Byte poisoning (`%00`) for suffix removal.
*   Dot-Truncation for suffix removal (Windows + Unix).
*   Directory traversal multiplication (`-M`).

### Remote File Inclusion
*   Dynamic RFI with FTP upload/delete (ftplib).
*   Dynamic RFI with local HTTP server.
*   `php_b64` payload encoder for RFI delivery.

### Infrastructure
*   Proxy support (`--http-proxy`).
*   Colored terminal output (`-C`).
*   Full argparse CLI — all 38+ original flags + `--encode-chain`, `--oob-domain`.
*   XML result storage (`~/fimap_result.xml`), JSON headers.
*   Plugin interface for custom exploit modules (stub, planned).

---

## Credits

*   **Original Author & Main Developer:** [Iman Karim](mailto:fimap.dev@gmail.com) — created fimap, designed the scanning engine, exploit logic, language definition system, and plugin architecture.

*   **Python 3 Rewrite & Extensions:** This continuation.

*   **New Techniques (v2.0):**
    *   PHP filter chain generator — based on [loknop's research](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d) and [synacktiv/php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator)
    *   PHP_SESSION_UPLOAD_PROGRESS — technique from [HackTricks](https://hacktricks.wiki/en/pentesting-web/file-inclusion/index.html)
    *   Authorization header log poisoning — technique from [Fredrik Nordberg Almroth](http://h.ackack.net/)
    *   pearcmd.php RCE — technique from [Phith0n](https://www.leavesongs.com/PENETRATION/docker-php-include-getshell.html) and [watchTowr](https://labs.watchtowr.com/form-tools-we-need-to-talk-about-php/)

*   **External Libraries (original):**
    *   Peteris Krumins — [xgoogle](http://www.catonmat.net/blog/python-library-for-google-search/) (removed in rewrite)
    *   Pentestmonkey — [php-reverse-shell](http://pentestmonkey.net/tools/php-reverse-shell/)
    *   Crummy — [BeautifulSoup](http://www.crummy.com/software/BeautifulSoup/) (upgraded to BS4)
    *   Zeth0 — [ssh.py](http://commandline.org.uk/) (SSH client for log injection)

*   **Trusted Plugins (original):**
    *   Metasploit binding — Xavier Garcia
    *   Weevily Injector — Darren "Infodox" Martyn ([insecurety.net](http://insecurety.net/))
    *   AES Reverse Shell — Darren "Infodox" Martyn

---

## Feature Parity

| Feature | Status | Notes |
|---------|:------:|-------|
| Single URL scan (`-s`) | ✅ Python3 | async, concurrent |
| Mass URL scan (`-m`) | ✅ Python3 | async, concurrent with semaphore |
| AutoAwesome mode (`-4`) | ✅ Python3 | form scanning + cookie capture + link harvest |
| Crawler/Harvester (`-H`) | ✅ Python3 | BS4, same-domain BFS |
| Sniper scan (regex-based LFI detection) | ✅ Python3 | all original regex preserved |
| Blind scan (`--enable-blind`) | ✅ Python3 | path traversal + nullbyte |
| Null-Byte poisoning | ✅ Python3 | identical logic |
| Dot-Truncation | ✅ Python3 | `difflib.SequenceMatcher`, Python3 API fix |
| Language definitions (YAML) | ✅ Python3 | PHP: 16 exec methods, 11 include patterns, 5 extensions |
| XML result storage (`~/fimap_result.xml`) | ✅ Python3 | JSON headers (was pickle), `xml.etree.ElementTree` |
| Proxy support (`--http-proxy`) | ✅ Python3 | via httpx |
| Colored output (`--enable-color`) | ✅ Python3 | ANSI terminal colors |
| GET/POST/Header parameter scanning | ✅ Python3 | all three injection vectors |
| SSL verification | ✅ Enabled by default | `--insecure` to disable |
| Interactive exploit shell (`-x`) | ✅ Python3 | domain/vuln menus, exec probing, command loop, tab-complete |
| Dynamic RFI (FTP/local modes) | ✅ Python3 | ftplib FTP upload/delete, local file write/delete, php_b64 encoder |
| Logfile Injection (LA/LH/LF/LS/LE) | ✅ Python3 | 5 vectors, 66 log paths |
| Authorization header injection (LA) | ✅ Python3 | base64-encoded, survives URI mangling |
| php://input wrapper | ✅ Python3 | POST body code injection via wrapper sub-menu |
| data:// wrapper | ✅ Python3 | inline base64 PHP via data:// URI |
| expect:// wrapper | ✅ Python3 | direct command execution (expect extension) |
| file:// wrapper | ✅ Python3 | alternative file access path |
| Slash-Dot (/\.) suffix bypass | ✅ Python3 | bypass substr($file,-4) extension guards |
| Advanced LFI fuzz payloads | ✅ Python3 | 23 payloads: Unicode bypass, double encoding, WAF evasion |
| Log path auto-discovery | ✅ Python3 | canary seeding + wordlist probing across 66 paths |
| Chainable payload encoding | ✅ Python3 | url → double_url → base64 chain for WAF evasion |
| OOB DNS callback | ✅ Python3 | blind LFI confirmation via DNS lookup stub |
| PHP_SESSION_UPLOAD_PROGRESS | ✅ Python3 | multipart POST → forged session → include |
| PHP filter chains (arbitrary code) | ✅ Python3 | convert.iconv chains, 64/64 base64 chars mapped |
| pearcmd.php RCE | ✅ Python3 | Docker/default PHP gadget, +config-create+ |
| phar:// deserialization | ✅ Python3 | wrapper support in config |
| zip:// wrapper | ✅ Python3 | include PHP from uploaded ZIP |
| /proc/self/* entries | ✅ Python3 | fd/{0,1,2}, status, cmdline, environ |
| CLI (`python -m fimap`) | ✅ Python3 | full argparse port of all 38+ original flags |
| Plugin system | ❌ Not ported | planned (importlib-based, no exec) |
| Google scan (`-g`) | ❌ Deprecated | Google HTML scraping broken since ~2014 |
| Bing scan (`-B`) | ❌ Removed | Bing API v2 defunct |
| `--update-def` | ❌ Removed | Google Code URLs dead |
| `--install-plugins` | ❌ Removed | Google Code URLs dead |
| `--show-my-ip` | ❌ Removed | hardcoded endpoint defunct |
| Perl language support | ❌ Removed | non-functional in original (generated PHP code) |

---

## Security Improvements vs Original

| Concern | Original (Python2) | Rewrite (Python3) |
|---------|-------------------|-------------------|
| `exec()` calls | 3 (quiz gen, plugin loading) | **0** |
| Header serialization | `pickle.dumps` + base64 | **JSON** |
| SSL certificate verification | Disabled globally (`ssl.CERT_NONE`) | **Enabled by default** |
| YAML/config loading | N/A (XML + `exec()` quiz code) | `yaml.safe_load()`, pure Python quiz |
| Socket timeout | Global `socket.setdefaulttimeout()` | Per-request `httpx.Timeout` |
| Configuration | Loose `dict` with string keys | Typed `AppConfig` dataclass |
| BeautifulSoup | BS3 (bundled, Python2-only) | BS4 (packaged dependency) |

---

## Project Structure

```
fimap/
├── config/              # YAML language definitions (was: config/*.xml)
│   ├── generic.yaml     #   Global scan config, blind files, shell commands, 66 log paths
│   └── php.yaml         #   PHP exec methods, payloads, detectors
├── scanners/            # Scan modes (single, mass, autoawesome)
├── exploit/             # Interactive exploit shell, RFI, log injection, modern techniques
│   ├── shell.py         #   Domain/vuln selection, injection testing, command loop, wrappers
│   ├── rfi.py           #   Dynamic RFI: FTP/local upload/delete, chainable encoding
│   ├── log_inject.py    #   Logfile injection: 5 vectors (LA/LH/LF/LS/LE), 66 paths, auto-discovery
│   ├── php_session.py   #   PHP_SESSION_UPLOAD_PROGRESS technique
│   ├── php_filters.py   #   PHP filter chain generator (arbitrary code, no files)
│   ├── oob.py           #   Out-of-band DNS callback for blind LFI confirmation
│   └── haxhelper.py     #   Plugin bridge (command execution, file upload)
├── plugins/             # Ported exploit plugins
│   └── msf/             #   Metasploit integration (XML-RPC listener)
├── scanner.py           # Core async scanning engine
├── language.py          # YAML loader, quiz generators, language registry
├── http_client.py       # httpx async wrapper (SSL verify ON by default)
├── models.py            # VulnReport, FileEntry, ExecMethod, Payload dataclasses
├── config.py            # Typed AppConfig + RFIConfig
├── crawler.py           # Async URL harvester (BS4)
├── xml_store.py         # XML result persistence (JSON headers, no pickle)
├── utils.py             # Logger, colored output, box drawing
├── report.py            # Re-exports VulnReport from models
├── cli.py               # Full argparse CLI (all 38+ original flags)
├── __init__.py          # Package metadata
└── __main__.py          # Entry point → cli.main()
```

---

## Installation

```bash
pip install httpx pyyaml beautifulsoup4 paramiko
python cli.py --help
```

**Requirements:** Python 3.10+, httpx, pyyaml, beautifulsoup4, paramiko.

---

## License

GNU General Public License v2.0 — same as original fimap.
