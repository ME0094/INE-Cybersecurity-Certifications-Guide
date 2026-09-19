#!/usr/bin/env bash
# env-setup.sh
# Basic lab environment setup (Kali/Parrot/Debian/Ubuntu/macOS).
#
# Usage: ./env-setup.sh [--install]
#   (no flag)   report only: what is detected, what is missing
#   --install   install the missing packages with the detected manager
#
# The report is the default on purpose: nothing here is installed behind your
# back, and with an unknown package manager the script stops instead of
# pretending it did the work.
set -euo pipefail

# Commands checked on PATH, and the package that provides them per manager.
# "python3-pip" is a *package* name, not a command: probing for it with
# command -v always fails, which is why the check and the package are separate.
COMMANDS=(nmap curl wget git jq python3 pip3)
PKG_apt=(nmap curl wget git jq python3 python3-pip)
PKG_dnf=(nmap curl wget git jq python3 python3-pip)
PKG_pacman=(nmap curl wget git jq python python-pip)
PKG_brew=(nmap curl wget git jq python python)
LAB_DIR="$HOME/labs"

detect_pkg() {
  if command -v apt-get >/dev/null 2>&1; then echo "apt"
  elif command -v dnf >/dev/null 2>&1; then echo "dnf"
  elif command -v pacman >/dev/null 2>&1; then echo "pacman"
  elif command -v brew >/dev/null 2>&1; then echo "brew"
  else echo "unknown"; fi
}

# install_pkg pkg_mgr package
install_pkg() {
  case "$1" in
    apt)    sudo apt-get install -y "$2" ;;
    dnf)    sudo dnf install -y "$2" ;;
    pacman) sudo pacman -S --noconfirm "$2" ;;
    brew)   brew install "$2" ;;
    *)      echo "I don't know how to install '$2' with the available package manager." >&2
            return 1 ;;
  esac
}

main() {
  local pkg_mgr install_mode
  pkg_mgr="$(detect_pkg)"
  install_mode="${1:-}"

  echo "[*] Detected package manager: $pkg_mgr"
  echo "[*] Lab directory: $LAB_DIR"
  mkdir -p "$LAB_DIR"

  if [[ "$install_mode" == "--install" && "$pkg_mgr" == "unknown" ]]; then
    echo "[!] No supported package manager found; install these by hand:" >&2
    echo "    ${COMMANDS[*]}" >&2
    exit 2
  fi

  # Pick the package list for this manager.
  local -a pkgs=()
  case "$pkg_mgr" in
    apt)    pkgs=("${PKG_apt[@]}") ;;
    dnf)    pkgs=("${PKG_dnf[@]}") ;;
    pacman) pkgs=("${PKG_pacman[@]}") ;;
    brew)   pkgs=("${PKG_brew[@]}") ;;
  esac
  if [[ "$install_mode" == "--install" && "${#pkgs[@]}" -ne "${#COMMANDS[@]}" ]]; then
    echo "[!] Package list for '$pkg_mgr' is incomplete; refusing to guess." >&2
    exit 2
  fi

  local missing=() i
  for i in "${!COMMANDS[@]}"; do
    if command -v "${COMMANDS[$i]}" >/dev/null 2>&1; then
      echo "[+] ${COMMANDS[$i]} already available"
    else
      missing+=("$i")
      echo "[-] ${COMMANDS[$i]} missing (package: ${pkgs[$i]:-unknown})"
    fi
  done

  if [[ "$install_mode" != "--install" ]]; then
    echo "[i] ${#missing[@]} missing. Re-run with --install to install them."
    echo "[*] Done. Next step: download victim machine images and configure networks."
    return 0
  fi

  if [[ "${#missing[@]}" -eq 0 ]]; then
    echo "[i] Nothing to install."
    return 0
  fi

  # Refresh the index once, not once per package.
  if [[ "$pkg_mgr" == "apt" ]]; then
    sudo apt-get update -y
  fi

  local failed=0
  for i in "${missing[@]}"; do
    echo "[*] Installing ${pkgs[$i]} ..."
    if install_pkg "$pkg_mgr" "${pkgs[$i]}"; then
      if command -v "${COMMANDS[$i]}" >/dev/null 2>&1; then
        echo "[+] ${COMMANDS[$i]} is now available"
      else
        echo "[!] ${pkgs[$i]} installed but '${COMMANDS[$i]}' is still not on PATH" >&2
        failed=$((failed + 1))
      fi
    else
      echo "[!] Could not install ${pkgs[$i]}" >&2
      failed=$((failed + 1))
    fi
  done

  if [[ "$failed" -gt 0 ]]; then
    echo "[!] $failed package(s) could not be installed; review the messages above." >&2
    exit 3
  fi
  echo "[*] Done. Next step: download victim machine images and configure networks."
}

main "$@"
