"""Typed AppConfig with all 38 original config keys from fimap.py."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RFIConfig:
    """Dynamic RFI settings (from original config.py)."""
    mode: str = "off"       # "off", "ftp", "local"
    ftp_host: Optional[str] = None
    ftp_user: Optional[str] = None
    ftp_pass: Optional[str] = None
    ftp_path: Optional[str] = None
    ftp_http_map: Optional[str] = None
    local_path: Optional[str] = None
    local_http_map: Optional[str] = None


@dataclass
class AppConfig:
    """All config keys from the original ``config`` dict (fimap.py)."""

    #=== URL / target ==========================================================
    p_url: Optional[str] = None
    p_mode: int = 0           # 0=single, 1=mass, 2=google, 3=crawl, 4=autoawesome
    p_list: Optional[str] = None
    p_query: Optional[str] = None

    #=== HTTP ==================================================================
    p_useragent: str = "fimap.googlecode.com/v2.0.0-dev"
    p_ttl: int = 30                         # per-request timeout seconds
    p_proxy: Optional[str] = None           # "host:port"
    p_post: str = ""

    #=== Scanner engine ========================================================
    p_verbose: int = 2                      # 0-3  (higher = more output)
    p_color: bool = False
    p_monkeymode: bool = False              # enable blind scanning
    p_autolang: bool = True                 # auto-detect language
    p_doDotTruncation: bool = False
    p_dot_trunc_min: int = 700
    p_dot_trunc_max: int = 2000
    p_dot_trunc_step: int = 50
    p_dot_trunc_ratio: float = 0.095
    p_dot_trunc_only_win: bool = True
    p_multiply_term: int = 1
    force_os: Optional[str] = None          # "linux" or "windows"

    #=== Harvest / crawl =======================================================
    p_write: Optional[str] = None
    p_depth: int = 1

    #=== Google scanner ========================================================
    p_pages: int = 10
    p_results_per_query: int = 100
    p_googlesleep: int = 5
    p_skippages: int = 0
    p_maxtries: int = 5

    #=== Exploit ===============================================================
    p_tabcomplete: bool = False
    p_exploit_domain: Optional[str] = None
    p_exploit_script_id: Optional[int] = None
    p_exploit_cmds: Optional[list] = None
    p_rfi_encode: Optional[str] = None

    #=== Misc ==================================================================
    force_run: bool = False
    p_mergexml: Optional[str] = None
    header: dict = field(default_factory=dict)
    p_concurrency: int = 10                 # async semaphore limit
    p_insecure: bool = False                # disable SSL verification
    p_bmin: Optional[int] = None            # blind min depth override
    p_bmax: Optional[int] = None            # blind max depth override

    #=== Plugins (not ported, kept for compat) =================================
    p_plugins: bool = False

    #=== RFI config (from original config.py) ==================================
    rfi: RFIConfig = field(default_factory=RFIConfig)
