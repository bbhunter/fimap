# fimap — Automatic LFI/RFI Scanner and Exploiter (Python3 Rewrite)

fimap is a tool which can find, prepare, audit, exploit and even search automatically for local and remote file inclusion bugs in webapps. fimap aims to be what [sqlmap](https://sqlmap.org) is for SQL injection — but for LFI/RFI bugs.

## About This Fork

This is a **Python3 rewrite and continuation** of the original fimap project.

**Original author:** [Iman Karim](mailto:fimap.dev@gmail.com) (fimap v1.00, 2009–2012, GPLv2)

The original Python2 codebase was forward-ported to modern Python3 with async I/O, type-safe configuration, and security hardening (zero `exec()`, SSL verify on by default, no `pickle`). All original exploit logic, scanning heuristics, payload generation, and file definitions have been preserved.

Original project home: [fimap.googlecode.com](http://fimap.googlecode.com) (archived)

---

## What fimap Does

*   Check a single URL, a list of URLs, or Google results automatically.
*   Identify and exploit file inclusion bugs (`include`, `include_once`, `require`, `require_once`).
*   Relative/absolute path handling — define absolute paths in config, no redundant `../../etc/passwd` chains.
*   Automatic suffix removal via Null-Byte poisoning and Dot-Truncation.
*   Remote File Inclusion (RFI) with FTP or local HTTP server.
*   Logfile Injection (Apache access logs, SSH auth logs).
*   Blind Mode (`--enable-blind`) for servers with error messages disabled.
*   Interactive exploit shell with tab-completion and command execution.
*   Spawn reverse shells, execute payloads, write files.
*   Harvest mode: crawl a site and collect URLs for later scanning.
*   AutoAwesome mode: auto-discover forms, cookies, and links, then scan them.
*   Scans GET parameters, POST parameters, and HTTP headers.
*   Proxy support.
*   Plugin interface for custom exploit modules.
*   Non-interactive exploiting (`--x-cmd`).

---

## Credits

*   **Original Author & Main Developer:** [Iman Karim](mailto:fimap.dev@gmail.com) — created fimap, designed the scanning engine, exploit logic, language definition system, and plugin architecture.

*   **Python3 Rewrite:** This continuation port.

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
| Interactive exploit shell (`-x`) | ❌ Not ported | next priority |
| Logfile Injection (Apache, SSH) | ❌ Not ported | planned |
| Dynamic RFI (FTP/local modes) | ❌ Not ported | planned |
| Plugin system | ❌ Not ported | planned (importlib-based, no exec) |
| Google scan (`-g`) | ❌ Deprecated | Google HTML scraping broken since ~2014 |
| Bing scan (`-B`) | ❌ Removed | Bing API v2 defunct |
| `--update-def` | ❌ Removed | Google Code URLs dead |
| `--install-plugins` | ❌ Removed | Google Code URLs dead |
| `--show-my-ip` | ❌ Removed | hardcoded endpoint defunct |
| Perl language support | ❌ Removed | non-functional in original (generated PHP code) |
| CLI (`python -m fimap`) | ⚠️ Stub | prints version only |
| Legacy code (`legacy/src/`) | ⚠️ Not deleted | reference-only, pending complete parity |

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
│   ├── generic.yaml     #   Global scan config, blind files, shell commands
│   └── php.yaml         #   PHP exec methods, payloads, detectors
├── scanners/            # Scan modes (single, mass, autoawesome)
├── legacy/              # Original Python2 reference code (will be deleted)
│   ├── src/             #   Core engine, exploit, crawler, plugins
│   └── plugins/         #   External plugins (MSF bindings)
├── plugins/             # Ported exploit plugins
│   └── msf/             #   Metasploit integration (msfpayload/msfencode + XML-RPC listener)
├── scanner.py           # Core async scanning engine
├── language.py          # YAML loader, quiz generators, language registry
├── http_client.py       # httpx async wrapper (SSL verify ON by default)
├── models.py            # VulnReport, FileEntry, ExecMethod, Payload dataclasses
├── config.py            # Typed AppConfig + RFIConfig
├── crawler.py           # Async URL harvester (BS4)
├── xml_store.py         # XML result persistence (JSON headers, no pickle)
├── utils.py             # Logger, colored output, box drawing
├── report.py            # Re-exports VulnReport from models
├── __init__.py           # Package metadata
└── __main__.py           # Entry point (CLI stub)
```

---

## Installation

```bash
pip install httpx pyyaml beautifulsoup4    # core dependencies
pip install paramiko                        # optional: SSH log injection
python __main__.py --help                  # once CLI is built
```

**Requirements:** Python 3.10+, httpx, pyyaml, beautifulsoup4. Optional: paramiko (SSH log injection).

---

## License

GNU General Public License v2.0 — same as original fimap.
