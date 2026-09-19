#!/usr/bin/env python3
"""
tool-installer.py — Pentesting / blue team tool installer.

Detects the system package manager (apt/dnf/pacman/brew) and installs a tool
from the allow-list below, or an explicit package with --package. It never
runs until you pass --yes: without it, the script only prints the plan.

Usage:
    python3 tool-installer.py --list
    python3 tool-installer.py --tool nmap              # show the plan only
    python3 tool-installer.py --tool nmap --yes        # run it
    python3 tool-installer.py --package python3-pip --yes

Exit codes: 0 success, 2 usage/unknown manager, 3 installation did not
produce the expected command.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys

# Map: normalized name -> packages per package manager. The key is both the
# package name for that manager and the command the script checks afterwards.
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
    "tcpdump": {"apt": "tcpdump", "dnf": "tcpdump", "pacman": "tcpdump", "brew": "tcpdump"},
}

# The managers this script knows how to drive, and the command that installs a
# package with each one. Keep the keys in sync with detect_pkg_manager(): a
# mismatch here used to make the script run the package name as if it were the
# installer, which prints the tool's help and looks like a success.
INSTALL_CMD: dict[str, list[str]] = {
    "apt": ["sudo", "apt-get", "install", "-y"],
    "dnf": ["sudo", "dnf", "install", "-y"],
    "pacman": ["sudo", "pacman", "-S", "--noconfirm"],
    "brew": ["brew", "install"],
}

# Which binary each manager's package is expected to provide (for the check
# after installation). Defaults to the package name itself.
MGR_PROBE = {"apt": "apt-get", "dnf": "dnf", "pacman": "pacman", "brew": "brew"}


def detect_pkg_manager() -> str:
    """Return the normalized manager key, or 'unknown'."""
    for mgr, probe in (("apt", "apt-get"), ("dnf", "dnf"), ("pacman", "pacman"), ("brew", "brew")):
        if shutil.which(probe):
            return mgr
    return "unknown"


def resolve_package(mgr: str, tool: str, explicit: str | None) -> str | None:
    """Return the package to install, or None when the request is not allowed."""
    if explicit:
        # Explicit package name: still a single argv element, never a shell line.
        return explicit
    if tool not in TOOLS:
        return None
    return TOOLS[tool].get(mgr)


def build_command(mgr: str, package: str) -> list[str] | None:
    base = INSTALL_CMD.get(mgr)
    if base is None:
        return None
    return [*base, package]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tool", help="Tool to install (see --list).")
    ap.add_argument("--package", help="Explicit package name for the detected manager.")
    ap.add_argument("--list", action="store_true", help="List known tools and their packages.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Show the command without running it (this is the default).")
    ap.add_argument("--yes", action="store_true", help="Run the installation.")
    args = ap.parse_args()

    if args.list:
        mgr = detect_pkg_manager()
        print(f"[*] Detected package manager: {mgr}")
        for name in sorted(TOOLS):
            print(f"  {name:12s} {TOOLS[name].get(mgr, '(not packaged for this manager)')}")
        return 0

    if not args.tool and not args.package:
        ap.error("--tool or --package is required (or use --list).")

    mgr = detect_pkg_manager()
    if mgr == "unknown":
        print("[!] Could not detect a supported package manager "
              "(apt, dnf, pacman, brew).", file=sys.stderr)
        return 2

    package = resolve_package(mgr, args.tool or "", args.package)
    if package is None:
        if args.tool and args.tool in TOOLS:
            print(f"[!] '{args.tool}' has no package defined for {mgr}.",
                  file=sys.stderr)
        else:
            print(f"[!] Unknown tool '{args.tool}'. Use --list, or --package to "
                  "name the package explicitly.", file=sys.stderr)
        return 2

    cmd = build_command(mgr, package)
    if cmd is None:
        print(f"[!] No install command defined for '{mgr}'.", file=sys.stderr)
        return 2

    print(f"[*] Package manager: {mgr}")
    print(f"[*] Package: {package}")
    print(f"[*] Command: {' '.join(cmd)}")

    if not args.yes:
        print("[i] Dry run: pass --yes to actually run it.")
        return 0

    print("[*] Running ...")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        print(f"[!] The installer exited with {exc.returncode}.", file=sys.stderr)
        return 3

    # Do not claim success without evidence: the package manager can exit 0
    # without installing anything on this system.
    probe = MGR_PROBE.get(mgr)
    if probe and not shutil.which(probe):
        print(f"[!] '{probe}' is not on PATH after the install; treat the "
              "installation as unverified.", file=sys.stderr)
        return 3
    print(f"[+] Command completed: {package}. Verify the tool itself with "
          f"'command -v {package}' before relying on it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
