#!/usr/bin/env python3
"""
tool-installer.py — Pentesting / blue team tool installer.

Detects the system package manager (apt/dnf/pacman/brew) and installs a
given tool. By default it only shows the plan (--dry-run).

Usage:
    python3 tool-installer.py --tool nmap [--yes]
    python3 tool-installer.py --list
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys

# Map: normalized name -> packages per package manager. (Empty = use the same name)
TOOLS: dict[str, dict[str, str]] = {
    "nmap": {"apt": "nmap", "dnf": "nmap", "pacman": "nmap", "brew": "nmap"},
    "gobuster": {"apt": "gobuster", "dnf": "gobuster", "pacman": "gobuster", "brew": "gobuster"},
    "nikto": {"apt": "nikto", "dnf": "nikto", "pacman": "nikto", "brew": "nikto"},
    "sqlmap": {"apt": "sqlmap", "dnf": "sqlmap", "pacman": "sqlmap", "brew": "sqlmap"},
    "john": {"apt": "john", "dnf": "john", "pacman": "john", "brew": "john"},
    "hashcat": {"apt": "hashcat", "dnf": "hashcat", "pacman": "hashcat", "brew": "hashcat"},
    "bloodhound": {"apt": "bloodhound", "dnf": "bloodhound", "pacman": "bloodhound", "brew": "bloodhound"},
    "burpsuite": {"apt": "burpsuite", "dnf": "burpsuite", "pacman": "burpsuite", "brew": "burpsuite"},
    "wireshark": {"apt": "wireshark", "dnf": "wireshark", "pacman": "wireshark", "brew": "wireshark"},
}

INSTALL_CMD = {
    "apt": ["sudo", "apt-get", "install", "-y"],
    "dnf": ["sudo", "dnf", "install", "-y"],
    "pacman": ["sudo", "pacman", "-S", "--noconfirm"],
    "brew": ["brew", "install"],
}


def detect_pkg_manager() -> str:
    for mgr in ("apt-get", "dnf", "pacman", "brew"):
        if shutil.which(mgr):
            return mgr
    return "unknown"


def plan_install(mgr: str, tool: str) -> list[str] | None:
    pkg = TOOLS.get(tool, {}).get(mgr, tool)
    return INSTALL_CMD.get(mgr, []) + [pkg]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tool", help="Tool to install (see --list).")
    ap.add_argument("--list", action="store_true", help="List known tools.")
    ap.add_argument("--dry-run", action="store_true", default=True,
                    help="Show the command without running it (default).")
    ap.add_argument("--yes", action="store_true", help="Run the installation.")
    args = ap.parse_args()

    if args.list:
        print("\n".join(sorted(TOOLS)))
        return 0

    if not args.tool:
        ap.error("--tool is required (or use --list).")

    mgr = detect_pkg_manager()
    if mgr == "unknown":
        print("[!] Could not detect the package manager.", file=sys.stderr)
        return 2

    cmd = plan_install(mgr, args.tool)
    if cmd is None:
        print(f"[!] Unknown tool or no support for '{mgr}'.", file=sys.stderr)
        return 2

    print(f"[*] Package manager: {mgr}")
    print(f"[*] Command: {' '.join(cmd)}")

    if args.yes:
        print("[*] Running ...")
        subprocess.run(cmd, check=True)
        print(f"[+] {args.tool} installed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
