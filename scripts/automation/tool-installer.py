#!/usr/bin/env python3
"""
tool-installer.py — Instalador de herramientas de pentesting / blue team.

Detecta el gestor de paquetes del sistema (apt/dnf/pacman/brew) e instala una
herramienta concreta. Por defecto solo muestra el plan (--dry-run).

Uso:
    python3 tool-installer.py --tool nmap [--yes]
    python3 tool-installer.py --list
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys

# Mapa: nombre normalizado -> paquetes por gestor. (Vacio = usar el mismo nombre)
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
    ap.add_argument("--tool", help="Herramienta a instalar (ver --list).")
    ap.add_argument("--list", action="store_true", help="Listar herramientas conocidas.")
    ap.add_argument("--dry-run", action="store_true", default=True,
                    help="Mostrar el comando sin ejecutarlo (por defecto).")
    ap.add_argument("--yes", action="store_true", help="Ejecutar la instalacion.")
    args = ap.parse_args()

    if args.list:
        print("\n".join(sorted(TOOLS)))
        return 0

    if not args.tool:
        ap.error("--tool es obligatorio (o usa --list).")

    mgr = detect_pkg_manager()
    if mgr == "unknown":
        print("[!] No se pudo detectar el gestor de paquetes.", file=sys.stderr)
        return 2

    cmd = plan_install(mgr, args.tool)
    if cmd is None:
        print(f"[!] Herramienta desconocida o sin soporte para '{mgr}'.", file=sys.stderr)
        return 2

    print(f"[*] Gestor: {mgr}")
    print(f"[*] Comando: {' '.join(cmd)}")

    if args.yes:
        print("[*] Ejecutando ...")
        subprocess.run(cmd, check=True)
        print(f"[+] {args.tool} instalado.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
