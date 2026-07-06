"""Shared pydantic models for fimap.

Maps 1:1 to the original ``report`` class fields and ``config`` dict keys.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class VulnReport:
    """Matches every field and computed property from the original ``report`` class."""

    URL: str
    Params: dict = field(default_factory=dict)
    VulnKey: Optional[str] = None
    VulnKeyVal: Optional[str] = None
    Prefix: Optional[str] = None
    Surfix: str = ""
    Appendix: Optional[str] = None
    SuffixBreakable: Optional[bool] = None
    SuffixBreakTechName: Optional[str] = None
    ServerPath: Optional[str] = None
    ServerScript: Optional[str] = None
    RemoteInjectable: bool = False
    isLinux: bool = True
    BlindDiscovered: bool = False
    PostData: Optional[str] = None
    isPost: int = 0                       # 0=GET, 1=POST, 2=HEADER
    language: Optional[str] = None
    VulnHeaderKey: Optional[str] = None
    HeaderDict: Optional[dict] = None

    def setVulnHeaderKey(self, headerkey: Optional[str]) -> None:
        self.VulnHeaderKey = headerkey

    def setHeader(self, header: Optional[dict]) -> None:
        self.HeaderDict = header

    def setLanguage(self, lang: Optional[str]) -> None:
        self.language = lang

    def getLanguage(self) -> Optional[str]:
        return self.language

    def isLanguageSet(self) -> bool:
        return self.language is not None

    def setPostData(self, p: Optional[str]) -> None:
        self.PostData = p

    def setPost(self, b: int) -> None:
        self.isPost = b

    def getPostData(self) -> Optional[str]:
        return self.PostData

    def getVulnHeader(self) -> str:
        return self.VulnHeaderKey or ""

    def getHeader(self) -> Optional[dict]:
        return self.HeaderDict

    def setWindows(self) -> None:
        self.isLinux = False

    def isWindows(self) -> bool:
        return not self.isLinux

    def setLinux(self) -> None:
        self.isLinux = True

    def isUnix(self) -> bool:
        return self.isLinux

    def setVulnKeyVal(self, val: Optional[str]) -> None:
        self.VulnKeyVal = val

    def getVulnKeyVal(self) -> Optional[str]:
        return self.VulnKeyVal

    def setPrefix(self, path: Optional[str]) -> None:
        self.Prefix = path

    def getPrefix(self) -> Optional[str]:
        return self.Prefix

    def setSurfix(self, txt: str) -> None:
        if self.Appendix is None:
            self.Appendix = txt
        self.Surfix = txt

    def getSurfix(self) -> str:
        return self.Surfix

    def isBlindDiscovered(self) -> bool:
        return self.BlindDiscovered

    def setBlindDiscovered(self, bd: bool) -> None:
        self.BlindDiscovered = bd

    def setServerPath(self, sP: Optional[str]) -> None:
        self.ServerPath = sP

    def getServerPath(self) -> Optional[str]:
        return self.ServerPath

    def setServerScript(self, sP: Optional[str]) -> None:
        self.ServerScript = sP

    def getServerScript(self) -> Optional[str]:
        return self.ServerScript

    def getAppendix(self) -> Optional[str]:
        return self.Appendix

    def isAbsoluteInjection(self) -> bool:
        return self.getPrefix() == ""

    def isRelativeInjection(self) -> bool:
        prefix = self.getPrefix() or ""
        return prefix.startswith("..") or prefix.startswith("/..")

    def getVulnKey(self) -> Optional[str]:
        return self.VulnKey

    def getURL(self) -> str:
        return self.URL

    def isRemoteInjectable(self) -> bool:
        return self.RemoteInjectable

    def setRemoteInjectable(self, ri: bool) -> None:
        self.RemoteInjectable = ri

    def getParams(self) -> dict:
        return self.Params

    def setSuffixBreakable(self, isPossible: Optional[bool]) -> None:
        self.SuffixBreakable = isPossible

    def isSuffixBreakable(self) -> Optional[bool]:
        return self.SuffixBreakable

    def setSuffixBreakTechName(self, name: Optional[str]) -> None:
        self.SuffixBreakTechName = name

    def getSuffixBreakTechName(self) -> Optional[str]:
        return self.SuffixBreakTechName

    def getType(self) -> str:
        if self.isBlindDiscovered():
            return "Blindly Identified"
        if self.getPrefix() is None:
            return "Not checked."
        ret = ""
        if self.isAbsoluteInjection():
            if self.getAppendix() == "":
                ret = "Absolute Clean"
            else:
                ret = "Absolute with appendix '%s'" % (self.getAppendix())
        elif self.isRelativeInjection():
            if self.getAppendix() == "":
                ret = "Relative Clean"
            else:
                ret = "Relative with appendix '%s'" % (self.getAppendix())
        else:
            return "Unknown (%s | %s | %s)" % (
                self.getPrefix(),
                self.isRelativeInjection(),
                self.isAbsoluteInjection(),
            )
        if self.isRemoteInjectable():
            ret += " + Remote injection"
        return ret

    def getDomain(self, url: Optional[str] = None) -> str:
        if url is None:
            url = self.URL
        domain = url[url.find("//") + 2 :]
        domain = domain[: domain.find("/")]
        return domain

    def getPath(self) -> str:
        url = self.getURL()
        url = url[url.find("//") + 2 :]
        url = url[url.find("/") :]
        return url

    def autoDetectLanguageByExtention(self, languageSets: dict) -> bool:
        for Name, langClass in languageSets.items():
            exts = langClass.getExtentions()
            for ext in exts:
                if self.URL.find(ext) != -1:
                    self.setLanguage(Name)
                    return True
        return False


@dataclass
class FileEntry:
    """Equivalent of ``fiFile`` from the original language.py."""

    filepath: str
    postdata: str = ""
    findstr: str = ""
    flags: str = ""
    isunix: bool = True
    iswin: bool = False

    def getFilepath(self) -> str:
        return self.filepath

    def getPostData(self) -> str:
        return self.postdata

    def getFindStr(self) -> str:
        return self.findstr

    def getFlags(self) -> str:
        return self.flags

    def containsFlag(self, flag: str) -> bool:
        return flag in self.flags

    def isInjected(self, content: str) -> bool:
        return content.find(self.findstr) != -1

    def isUnix(self) -> bool:
        return self.isunix

    def isWindows(self) -> bool:
        return self.iswin

    def isBreakable(self) -> bool:
        return self.filepath.find("://") == -1

    def getBackSymbols(self, SeperatorAtFront: bool = True) -> str:
        if SeperatorAtFront:
            return "/.." if self.isUnix() else "\\.."
        return "../" if self.isUnix() else "..\\"

    def getBackSymbol(self) -> str:
        return "/" if self.isUnix() else "\\"


@dataclass
class ExecMethod:
    """Equivalent of ``fiExecMethod`` from the original language.py."""

    name: str
    source: str
    dobase64: bool = False
    unix: bool = True
    win: bool = False

    def getSource(self) -> str:
        return self.source

    def getName(self) -> str:
        return self.name

    def generatePayload(self, command: str) -> str:
        import base64

        cmd = base64.b64encode(command.encode()).decode() if self.dobase64 else command
        return self.getSource().replace("__PAYLOAD__", cmd)

    def isUnix(self) -> bool:
        return self.unix

    def isWindows(self) -> bool:
        return self.win


@dataclass
class Payload:
    """Equivalent of ``fiPayload`` from the original language.py."""

    name: str
    source: str
    dobase64: bool = False
    inshell: bool = False
    unix: bool = True
    win: bool = False
    inputs: list = field(default_factory=list)
    parent_name: str = ""

    def isForWindows(self) -> bool:
        return self.win

    def isForUnix(self) -> bool:
        return self.unix

    def getParentName(self) -> str:
        return self.parent_name

    def doInShell(self) -> bool:
        return self.inshell

    def getName(self) -> str:
        return self.name

    def getSource(self) -> str:
        return self.source


@dataclass
class ScanTarget:
    """Parsed target with GET/POST/Header params for scanning."""

    url: str
    params: dict = field(default_factory=dict)       # GET params
    postparams: dict = field(default_factory=dict)    # POST params
    header: dict = field(default_factory=dict)        # Header params


@dataclass
class ScanResult:
    """Result bundle from a single target scan."""

    report: VulnReport
    readable_files: list[str] = field(default_factory=list)
