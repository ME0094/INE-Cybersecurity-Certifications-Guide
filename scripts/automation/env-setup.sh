#!/usr/bin/env bash
# env-setup.sh
# Preparacion basica del entorno de laboratorio (Kali/Parrot/Debian/Ubuntu/macOS).
# Uso: ./env-setup.sh [--install]
#   --install   instala las herramientas definidas en TOOLS (por defecto solo informa).
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
    *)      echo "No se como instalar '$2' con el gestor disponible." ;;
  esac
}

main() {
  local pkg_mgr
  pkg_mgr="$(detect_pkg)"
  echo "[*] Gestor de paquetes detectado: $pkg_mgr"
  echo "[*] Directorio de laboratorio: $LAB_DIR"
  mkdir -p "$LAB_DIR"
  echo "[*] Herramientas objetivo: ${TOOLS[*]}"

  if [[ "${1:-}" == "--install" ]]; then
    for tool in "${TOOLS[@]}"; do
      if command -v "$tool" >/dev/null 2>&1; then
        echo "[+] $tool ya disponible"
      else
        echo "[*] Instalando $tool ..."
        install_pkg "$pkg_mgr" "$tool"
      fi
    done
  else
    echo "[i] Ejecuta con --install para instalar las herramientas que falten."
  fi
  echo "[*] Listo. Siguiente paso: descargar imagenes de maquinas victima y configurar redes."
}

main "$@"
