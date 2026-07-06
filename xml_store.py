"""XML result persistence — replaces baseClass XML methods.

* Uses ``xml.etree.ElementTree`` (was ``xml.dom.minidom``).
* Headers stored as **JSON** (was pickle+b64).
* File: ``~/fimap_result.xml``.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import xml.etree.ElementTree as ET
from typing import Optional

from models import VulnReport
from utils import Logger, LOG_DEVEL, LOG_DEBUG, LOG_WARN


class XMLResultStore:
    """Load/save/merge fimap XML results. JSON headers, no pickle."""

    def __init__(self, logger: Logger, xml_path: Optional[str] = None):
        self.log = logger
        self.xml_path = xml_path or os.path.join(os.path.expanduser("~"), "fimap_result.xml")
        self.tree: Optional[ET.ElementTree] = None
        self.root: Optional[ET.Element] = None
        self._init_xml()

    def _init_xml(self) -> None:
        if os.path.exists(self.xml_path):
            self.tree = ET.parse(self.xml_path)
            self.root = self.tree.getroot()
        else:
            self.root = ET.Element("fimap")
            self.tree = ET.ElementTree(self.root)

    def find_domain_node(self, domain: str) -> ET.Element:
        """Find or create a ``<URL hostname="...">`` element."""
        for child in self.root:
            if child.tag != "text":
                if child.get("hostname") == domain:
                    return child
        elem = ET.SubElement(self.root, "URL", hostname=domain)
        return elem

    def exists_domain(self, domain: str) -> bool:
        for child in self.root:
            if child.tag != "text" and child.get("hostname") == domain:
                return True
        return False

    def exists_xml_entry(self, domain: str, file: str, path: str) -> bool:
        elem = self.find_domain_node(domain)
        for child in elem:
            if child.tag == "vuln":
                if child.get("file") == file and child.get("path") == path:
                    return True
        return False

    def add_xml_log(self, rep: VulnReport, flags: str, file: str) -> None:
        """Add a vulnerability entry. Headers stored as JSON (NOT pickle)."""
        domain = rep.getDomain()
        path_ = rep.getPath()

        if self.exists_xml_entry(domain, file, path_):
            return

        domain_node = self.find_domain_node(domain)
        elem = ET.SubElement(domain_node, "vuln")

        elem.set("file", file)
        elem.set("prefix", rep.getPrefix() or "")
        elem.set("suffix", rep.getSurfix() or "")
        elem.set("appendix", rep.getAppendix() or "")
        elem.set("mode", flags)
        elem.set("path", path_)
        elem.set("param", rep.getVulnKey() or "")
        elem.set("paramvalue", rep.getVulnKeyVal() or "")
        elem.set("postdata", rep.getPostData() or "")
        elem.set("kernel", "")
        elem.set("language", rep.getLanguage() or "")

        # Headers as JSON (was pickle + b64)
        headers_json = json.dumps(rep.getHeader() or {})
        elem.set("header_dict", headers_json)

        elem.set("header_vuln_key", rep.getVulnHeader() or "")

        os_ = "win" if rep.isWindows() else "unix"
        elem.set("os", os_)

        elem.set("remote", "1" if rep.isRemoteInjectable() else "0")
        elem.set("blind", "1" if rep.isBlindDiscovered() else "0")
        elem.set("ispost", str(rep.isPost))

    def get_domain_nodes(self) -> list[ET.Element]:
        return self.root.findall("URL")

    def get_nodes_of_domain(self, domain: str) -> list[ET.Element]:
        elem = self.find_domain_node(domain)
        return elem.findall("vuln")

    def update_kernel(self, domain_node: ET.Element, kernel: str) -> None:
        self.log.log("Updating kernel version in XML to '%s'" % kernel, LOG_DEVEL)
        domain_node.set("kernel", kernel)

    def get_kernel_version(self, domain_node: ET.Element) -> Optional[str]:
        ret = domain_node.get("kernel", "")
        return ret if ret else None

    def test_if_xml_is_old_school(self) -> None:
        """Upgrade old XML entries missing 'language'/'os' attrs."""
        already_warned = False

        for child in list(self.root):
            if child.tag == "URL":
                for cc in list(child):
                    toss_warn = False
                    if cc.tag == "vuln":
                        if not cc.get("language"):
                            cc.set("language", "PHP")
                            toss_warn = True
                        if not cc.get("os"):
                            cc.set("os", "unix")
                            toss_warn = True
                    if toss_warn and not already_warned:
                        self.log.log("You have an old fimap_result.xml file!", LOG_WARN)
                        self.log.log("I am going to make it sexy for you now very quickly...", LOG_WARN)
                        already_warned = True

        if already_warned:
            backupfile = os.path.join(os.path.expanduser("~"), "fimap_result.backup")
            if os.path.exists(backupfile):
                self.log.log("WARNING: I wanted to backup your old fimap_result to: %s" % backupfile, LOG_WARN)
                self.log.log("But this file already exists! Please define a backup path:", LOG_WARN)
                backupfile = input("Backup path: ")
            print("Creating backup of your original XML to '%s'..." % backupfile)
            shutil.copy(self.xml_path, backupfile)
            print("Committing changes to orginal XML...")
            self.save_xml()
            print("All done.")
            print("Please rerun fimap.")
            sys.exit(0)

    def merge_xml(self, new_xml_path: str) -> tuple[int, int]:
        """Merge entries from another XML file. Returns (new_vulns, new_domains)."""
        new_vulns = new_domains = 0

        new_tree = ET.parse(new_xml_path)
        new_root = new_tree.getroot()

        for c in list(new_root):
            if c.tag == "URL":
                hostname = c.get("hostname", "")
                for cc in list(c):
                    if cc.tag == "vuln":
                        new_path = cc.get("path", "")
                        new_file = cc.get("file", "")
                        if not self.exists_xml_entry(hostname, new_file, new_path):
                            print("Adding new informations from domain '%s'..." % hostname)
                            domain_node = self.find_domain_node(hostname)
                            domain_node.append(cc)
                            new_vulns += 1
                            if not self.exists_domain(hostname):
                                self.root.append(domain_node)
                                new_domains += 1

        if new_vulns > 0 or new_domains > 0:
            print("Saving XML...")
            self.save_xml()
            print("All done.")

        return new_vulns, new_domains

    def save_xml(self) -> None:
        self.log.log("Saving results to '%s'..." % self.xml_path, LOG_DEBUG)
        raw = ET.tostring(self.root or ET.Element("fimap"), encoding="unicode")
        # Pretty-print — basic indent
        import xml.dom.minidom
        dom = xml.dom.minidom.parseString(raw)
        pretty = dom.toprettyxml(indent="  ")
        # Remove empty lines
        cleaned = "\n".join(line for line in pretty.split("\n") if line.strip())
        with open(self.xml_path, "w") as f:
            f.write(cleaned)
