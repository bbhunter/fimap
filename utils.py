"""Utility helpers — logging, random strings, colored output, box drawing.

Merged from baseTools.py. No exec(), no Python2 constructs.
"""

from __future__ import annotations

import random
import string
from time import gmtime, strftime
from typing import Optional


# Log levels matching original baseTools
LOG_ERROR  = 99
LOG_WARN   = 98
LOG_DEVEL  = 1
LOG_DEBUG  = 2
LOG_INFO   = 3
LOG_ALWAYS = 4


# ANSI escape helpers — ported from baseTools color hack
_CONST_RST = "\033[0m"
_CONST_COL = "\033[__BOLD__;3__COLOR__m"

BLACK   = 0
RED     = 1
GREEN   = 2
YELLOW  = 3
BLUE    = 4
MAGENTA = 5
CYAN    = 6
WHITE   = 7


BOX_HEADER_STYLE   = (1, 1)
BOX_SPLITTER_STYLE = (3, 0)


def get_random_str(length: int = 8) -> str:
    """Generate random alphanumeric string starting with a letter."""
    chars = string.ascii_letters + string.digits
    return random.choice(string.ascii_letters) + "".join(
        random.choice(chars) for _ in range(length - 1)
    )


class Logger:
    """Minimal logger matching original baseTools logging."""

    def __init__(self, verbose: int = 2, use_color: bool = False):
        self.verbose = verbose
        self.use_color = use_color

        self._levels: dict[int, tuple[str, tuple[int, int]]] = {
            LOG_ERROR:  ("ERROR", (RED, 1)),
            LOG_WARN:   ("WARN",  (RED, 0)),
            LOG_DEVEL:  ("DEVEL", (YELLOW, 0)),
            LOG_DEBUG:  ("DEBUG", (CYAN, 0)),
            LOG_INFO:   ("INFO",  (BLUE, 0)),
            LOG_ALWAYS: ("OUT",   (MAGENTA, 0)),
        }

    def log(self, txt: str, level: int) -> None:
        if 4 - self.verbose <= level:
            label = self._levels.get(level, ("???", (WHITE, 0)))
            logline = "[%s] %s" % (label[0], txt)
            t = strftime("%H:%M:%S", gmtime())
            if self.use_color:
                print("[%s] %s" % (t, self._colorize(logline, label[1])))
            else:
                print("[%s] %s" % (t, logline))

    def _colorize(self, txt: str, style: tuple[int, int]) -> str:
        prefix = _CONST_COL.replace("__COLOR__", str(style[0])).replace("__BOLD__", str(style[1]))
        return prefix + txt + _CONST_RST


def draw_box(
    header: str,
    textarray: list[str],
    use_color: bool = False,
    box_symbol: str = "#",
) -> None:
    """Draw a text box matching original baseTools.drawBox()."""
    max_len = _get_longest_line(textarray, header) + 5
    sym = box_symbol
    if use_color:
        sym = _CONST_COL.replace("__BOLD__", "1").replace("__COLOR__", str(RED)) + "#" + _CONST_RST

    print(sym * (max_len + 1))
    _print_box_line(header, max_len, sym, use_color)
    print(sym * (max_len + 1))

    for ln in textarray:
        _print_box_line(ln, max_len, sym, use_color)

    print(sym * (max_len + 1))


def _print_box_line(txt: str, maxlen: int, symbol: str, use_color: bool, realsize: int = -1) -> None:
    size = len(txt) if realsize == -1 else realsize
    suffix = " " * (maxlen - size - 1)
    if use_color and txt.startswith("::"):
        colored = _CONST_COL.replace("__COLOR__", str(BOX_SPLITTER_STYLE[0])).replace("__BOLD__", str(BOX_SPLITTER_STYLE[1]))
        colored += txt + _CONST_RST
        print(symbol + colored + suffix + symbol)
    else:
        print(symbol + txt + suffix + symbol)


def _get_longest_line(textarray: list[str], header: str) -> int:
    max_len = len(header)
    for ln in textarray:
        if len(ln) > max_len:
            max_len = len(ln)
    return max_len
