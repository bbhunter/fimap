"""Language definition system — replaces XML2Config and baseLanguage from legacy language.py.

Uses PyYAML ``safe_load``. Zero ``exec()`` calls. Quiz generation is pure Python.
"""

from __future__ import annotations

import os
import random
import string
from pathlib import Path
from typing import Optional

import yaml

from models import ExecMethod, FileEntry, Payload


class QuizGenerator:
    """Pure Python quiz generators. No exec()."""

    @staticmethod
    def get_random_str(length: int = 8) -> str:
        chars = string.ascii_letters + string.digits
        return random.choice(string.ascii_letters) + "".join(
            random.choice(chars) for _ in range(length - 1)
        )

    @staticmethod
    def php_chr_quiz() -> tuple[str, str]:
        """Generate PHP echo‑chr quiz. Returns (php_code, answer)."""
        rnd = QuizGenerator.get_random_str()
        phpcode = "echo "
        for c in rnd:
            phpcode += "chr(%d)." % ord(c)
        phpcode = "<?php " + phpcode[:-1] + "; ?>"
        return phpcode, rnd

    @staticmethod
    def shell_math_quiz() -> tuple[str, str]:
        """Generate shell math quiz. Returns (shell_code, answer)."""
        rnd1 = random.randrange(10, 99)
        rnd2 = random.randrange(10, 99)
        result = str(rnd1 * rnd2)
        shellcode = "echo $((%d*%d))" % (rnd1, rnd2)
        return shellcode, result


class ShellCommands:
    """Static shell command builders. No exec()."""

    @staticmethod
    def kernel_version(is_unix: bool = True) -> str:
        return "uname -r -s" if is_unix else "ver"

    @staticmethod
    def current_dir(is_unix: bool = True) -> str:
        return "pwd" if is_unix else "chdir"

    @staticmethod
    def current_user(is_unix: bool = True) -> str:
        return "whoami" if is_unix else "echo %USERNAME%"

    @staticmethod
    def cd(directory: str, is_unix: bool = True) -> str:
        if is_unix:
            return "cd '%s'" % directory
        return 'cd "%s"' % directory


class LanguageDef:
    """Loads a single YAML language definition file (e.g. php.yaml)."""

    def __init__(self, name: str, yaml_path: str):
        self.name = name
        self.yaml_path = yaml_path
        self._data: dict = {}

        self.relative_files: list[FileEntry] = []
        self.absolute_files: list[FileEntry] = []
        self.remote_files: list[FileEntry] = []
        self.log_files: list[FileEntry] = []

        self.exec_methods: list[ExecMethod] = []
        self.payloads: list[Payload] = []

        self.sniper_regex: Optional[str] = None
        self.quiz_type: Optional[str] = None
        self.print_source: Optional[str] = None
        self.eval_kickstarter: Optional[str] = None
        self.write_file_source: Optional[str] = None

        self.detector_include: list[str] = []
        self.detector_readfile: list[str] = []
        self.detector_extentions: list[str] = []

        self.revision: int = 0
        self.autor: str = ""
        self.do_force_inclusion_test: bool = False

        self._load()

    def _load(self) -> None:
        with open(self.yaml_path, "r") as f:
            self._data = yaml.safe_load(f)

        self.revision = self._data.get("revision", 0)
        self.autor = self._data.get("autor", "")
        self.do_force_inclusion_test = self._data.get("force_inclusion_test", False)

        self._load_files("relative_files", self.relative_files)
        self._load_files("absolute_files", self.absolute_files)
        self._load_files("remote_files", self.remote_files)
        self._load_files("log_files", self.log_files)

        self._load_exec_methods()
        self._load_payloads()

        snipe = self._data.get("snipe", {})
        self.sniper_regex = snipe.get("regex", "")

        methods = self._data.get("methods", {})
        quiz = methods.get("quiz", {})
        self.quiz_type = quiz.get("type")
        self.print_source = methods.get("print", {}).get("source")
        self.eval_kickstarter = methods.get("eval_kickstarter", {}).get("source")
        self.write_file_source = methods.get("write_file", {}).get("source")

        detectors = self._data.get("detectors", {})
        for p in detectors.get("include_patterns", []):
            self.detector_include.append(p["regex"])
        for p in detectors.get("readfile_patterns", []):
            self.detector_readfile.append(p["regex"])
        for e in detectors.get("extentions", []):
            self.detector_extentions.append(e["ext"])

    def _load_files(self, key: str, target: list[FileEntry]) -> None:
        for item in self._data.get(key, []) or []:
            target.append(FileEntry(
                filepath=item["path"],
                postdata=item.get("post", ""),
                findstr=item.get("find", ""),
                flags=item.get("flags", ""),
                isunix=item.get("unix", True),
                iswin=item.get("windows", False),
            ))

    def _load_exec_methods(self) -> None:
        for item in self._data.get("exec_methods", []) or []:
            self.exec_methods.append(ExecMethod(
                name=item["name"],
                source=item["source"],
                dobase64=item.get("dobase64", False),
                unix=item.get("unix", True),
                win=item.get("win", False),
            ))

    def _load_payloads(self) -> None:
        for item in self._data.get("payloads", []) or []:
            self.payloads.append(Payload(
                name=item["name"],
                source=item["source"],
                dobase64=item.get("dobase64", False),
                inshell=item.get("inshell", False),
                unix=item.get("unix", True),
                win=item.get("win", False),
                inputs=item.get("inputs", []),
                parent_name=self.name,
            ))

    #=== Accessors matching original baseLanguage interface ======================

    def getName(self) -> str:
        return self.name

    def getVersion(self) -> int:
        return self.revision

    def getRevision(self) -> int:
        return self.revision

    def getAutor(self) -> str:
        return self.autor

    def getSniper(self) -> str:
        return self.sniper_regex or ""

    def doForceInclusionTest(self) -> bool:
        return self.do_force_inclusion_test

    def getExecMethods(self) -> list[ExecMethod]:
        return self.exec_methods

    def getPayloads(self) -> list[Payload]:
        return self.payloads

    def getRelativeFiles(self) -> list[FileEntry]:
        return self.relative_files

    def getAbsoluteFiles(self) -> list[FileEntry]:
        return self.absolute_files

    def getRemoteFiles(self) -> list[FileEntry]:
        return self.remote_files

    def getLogFiles(self) -> list[FileEntry]:
        return self.log_files

    def getIncludeDetectors(self) -> list[str]:
        return self.detector_include

    def getReadfileDetectors(self) -> list[str]:
        return self.detector_readfile

    def getExtentions(self) -> list[str]:
        return self.detector_extentions

    def generateQuiz(self) -> tuple[str, str]:
        """Generate quiz. Returns (code, answer). Pure Python, no exec()."""
        if self.quiz_type == "php_chr":
            return QuizGenerator.php_chr_quiz()
        if self.quiz_type == "shell_math":
            return QuizGenerator.shell_math_quiz()
        raise ValueError("Unknown quiz_type: %s" % self.quiz_type)

    def generatePrint(self, data: str) -> str:
        if not self.print_source:
            return data
        return self.print_source.replace("__PLACEHOLDER__", data)

    def getEvalKickstarter(self) -> Optional[str]:
        return self.eval_kickstarter

    def generateWriteFileCode(self, remotefilepath: str, mode: str, b64data: str) -> str:
        if not self.write_file_source:
            raise ValueError("No write_file method defined")
        code = self.write_file_source
        code = code.replace("__FILE__", remotefilepath)
        code = code.replace("__MODE__", mode)
        code = code.replace("__B64_DATA__", b64data)
        return code


class LanguageRegistry:
    """Loads generic.yaml + all language YAMLs. Provides combined queries."""

    def __init__(self, config_dir: str):
        self.config_dir = config_dir
        self.generic_path = os.path.join(config_dir, "generic.yaml")

        self.relative_files: list[FileEntry] = []
        self.absolute_files: list[FileEntry] = []
        self.remote_files: list[FileEntry] = []
        self.log_files: list[FileEntry] = []
        self.blind_files: list[FileEntry] = []
        self.blind_min: int = 0
        self.blind_max: int = 15

        self.command_concat_unix: str = ";"
        self.command_concat_win: str = "&"
        self.shellquiz_type_unix: str = "shell_math"
        self.shellquiz_type_win: str = "shell_math"
        self.kernelversion_code_unix: str = "uname -r -s"
        self.kernelversion_code_win: str = "ver"
        self.currentdir_code_unix: str = "pwd"
        self.currentdir_code_win: str = "chdir"
        self.currentuser_code_unix: str = "whoami"
        self.currentuser_code_win: str = "echo %USERNAME%"
        self.cd_code_unix: str = "cd '__DIR__'"
        self.cd_code_win: str = 'cd "__DIR__"'

        self.langsets: dict[str, LanguageDef] = {}
        self.version: int = -1

        self._load_generic()

    def _load_generic(self) -> None:
        with open(self.generic_path, "r") as f:
            data = yaml.safe_load(f)

        self.version = data.get("revision", -1)

        self._load_files(data.get("relative_files", []), self.relative_files)
        self._load_files(data.get("absolute_files", []), self.absolute_files)
        self._load_files(data.get("remote_files", []), self.remote_files)
        self._load_files(data.get("log_files", []), self.log_files)

        blind = data.get("blind_files", {})
        self.blind_min = blind.get("mindepth", 0)
        self.blind_max = blind.get("maxdepth", 15)
        self._load_files(blind.get("files", []), self.blind_files)

        methods = data.get("methods", {})
        unix_m = methods.get("unix", {})
        win_m = methods.get("windows", {})

        self.command_concat_unix = unix_m.get("concatcommand", ";")
        self.command_concat_win = win_m.get("concatcommand", "&")

        sq_unix = unix_m.get("shellquiz", {})
        sq_win = win_m.get("shellquiz", {})
        self.shellquiz_type_unix = sq_unix.get("type", "shell_math")
        self.shellquiz_type_win = sq_win.get("type", "shell_math")

        self.kernelversion_code_unix = unix_m.get("kernelversion", {}).get("source", "uname -r -s")
        self.kernelversion_code_win = win_m.get("kernelversion", {}).get("source", "ver")
        self.currentdir_code_unix = unix_m.get("currentdir", {}).get("source", "pwd")
        self.currentdir_code_win = win_m.get("currentdir", {}).get("source", "chdir")
        self.currentuser_code_unix = unix_m.get("currentuser", {}).get("source", "whoami")
        self.currentuser_code_win = win_m.get("currentuser", {}).get("source", "echo %USERNAME%")
        self.cd_code_unix = unix_m.get("cd", {}).get("source", "cd '__DIR__'")
        self.cd_code_win = win_m.get("cd", {}).get("source", 'cd "__DIR__"')

        for lang in data.get("languagesets", []):
            name = lang["name"]
            langfile = lang["langfile"]
            path = os.path.join(self.config_dir, langfile)
            if os.path.exists(path):
                self.langsets[name] = LanguageDef(name, path)

    def _load_files(self, items: list[dict], target: list[FileEntry]) -> None:
        for item in (items or []):
            target.append(FileEntry(
                filepath=item["path"],
                postdata=item.get("post", ""),
                findstr=item.get("find", ""),
                flags=item.get("flags", ""),
                isunix=item.get("unix", True),
                iswin=item.get("windows", False),
            ))

    #=== Query methods matching original XML2Config interface ====================

    def getVersion(self) -> int:
        return self.version

    def generateShellQuiz(self, is_unix: bool = True) -> tuple[str, str]:
        """Pure Python shell quiz — no exec()."""
        return QuizGenerator.shell_math_quiz()

    def getAllLangSets(self) -> dict[str, LanguageDef]:
        return self.langsets

    def getAllReadfileRegex(self) -> list[tuple[str, str]]:
        ret: list[tuple[str, str]] = []
        for k, v in self.langsets.items():
            for reg in v.getReadfileDetectors():
                ret.append((k, reg))
        return ret

    def getAllSniperRegex(self) -> list[tuple[str, str]]:
        ret: list[tuple[str, str]] = []
        for k, v in self.langsets.items():
            sniper = v.getSniper()
            if sniper:
                ret.append((k, sniper))
        return ret

    def getKernelCode(self, is_unix: bool = True) -> str:
        return self.kernelversion_code_unix if is_unix else self.kernelversion_code_win

    def getRelativeFiles(self, lang: Optional[str] = None) -> list[FileEntry]:
        ret = list(self.relative_files)
        if lang and lang in self.langsets:
            ret.extend(self.langsets[lang].getRelativeFiles())
        return ret

    def getAbsoluteFiles(self, lang: Optional[str] = None) -> list[FileEntry]:
        ret = list(self.absolute_files)
        if lang and lang in self.langsets:
            ret.extend(self.langsets[lang].getAbsoluteFiles())
        return ret

    def getLogFiles(self, lang: Optional[str] = None) -> list[FileEntry]:
        ret = list(self.log_files)
        if lang and lang in self.langsets:
            ret.extend(self.langsets[lang].getLogFiles())
        return ret

    def getRemoteFiles(self, lang: Optional[str] = None) -> list[FileEntry]:
        ret = list(self.remote_files)
        if lang and lang in self.langsets:
            ret.extend(self.langsets[lang].getRemoteFiles())
        return ret

    def getBlindFiles(self) -> list[FileEntry]:
        return list(self.blind_files)

    def getBlindMax(self) -> int:
        return self.blind_max

    def getBlindMin(self) -> int:
        return self.blind_min

    def getCurrentDirCode(self, is_unix: bool = True) -> str:
        return self.currentdir_code_unix if is_unix else self.currentdir_code_win

    def getCurrentUserCode(self, is_unix: bool = True) -> str:
        return self.currentuser_code_unix if is_unix else self.currentuser_code_win

    def getConcatSymbol(self, is_unix: bool = True) -> str:
        return self.command_concat_unix if is_unix else self.command_concat_win

    def concatCommands(self, commands: list[str], is_unix: bool = True) -> str:
        symbol = " %s " % self.getConcatSymbol(is_unix)
        return symbol.join(commands)

    def generateChangeDirectoryCommand(self, directory: str, is_unix: bool = True) -> str:
        code = self.cd_code_unix if is_unix else self.cd_code_win
        return code.replace("__DIR__", directory)
