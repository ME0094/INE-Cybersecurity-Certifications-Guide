#!/usr/bin/env bash
# env-setup.sh
# Basic lab environment setup (Kali/Parrot/Debian/Ubuntu/macOS).
# Usage: ./env-setup.sh [--install]
#   --install   installs the tools defined in TOOLS (by default it only reports).
set -euo pipefail

TOOLS=(nmap curl wget git jq python3 python3-pip)
LAB_DIR="$HOME/labs"

detect_pkg() {
  if command -v apt-get >/dev/null 2>&1; then echo "apt"
  elif command -v dnf >/dev/null 2>&1; then echo "dnf"
  elif command -v pacman >/dev/null 2>&1; then echo "pacman"
  elif command -v brew >/dev/null 2>&1; then echo "brew"
  else echo "unknown"; fi
}

install_pkg() { # pkg_mgr tool_name
  case "$1" in
    apt)    sudo apt-get update -y && sudo apt-get install -y "$2" ;;
    dnf)    sudo dnf install -y "$2" ;;
    pacman) sudo pacman -Sy --noconfirm "$2" ;;
    brew)   brew install "$2" ;;
    *)      echo "I don't know how to install '$2' with the available package manager." ;;
  esac
}

main() {
  local pkg_mgr
  pkg_mgr="$(detect_pkg)"
  echo "[*] Detected package manager: $pkg_mgr"
  echo "[*] Lab directory: $LAB_DIR"
  mkdir -p "$LAB_DIR"
  echo "[*] Target tools: ${TOOLS[*]}"

  if [[ "${1:-}" == "--install" ]]; then
    for tool in "${TOOLS[@]}"; do
      if command -v "$tool" >/dev/null 2>&1; then
        echo "[+] $tool already available"
      else
        echo "[*] Installing $tool ..."
        install_pkg "$pkg_mgr" "$tool"
      fi
    done
  else
    echo "[i] Run with --install to install any missing tools."
  fi
  echo "[*] Done. Next step: download victim machine images and configure networks."
}

main "$@"
