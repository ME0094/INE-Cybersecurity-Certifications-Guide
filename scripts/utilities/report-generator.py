#!/usr/bin/env python3
"""
report-generator.py — Informe de progreso de estudio.

Recorre un arbol de notas Markdown (por defecto el repositorio) contando las
tareas `- [ ]` (pendientes) y `- [x]` (completadas) de cada fichero, agrupadas
por modulo, e imprime un resumen en texto plano o JSON.

Uso:
    python3 report-generator.py [--path .] [--json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CHECK_PENDING = re.compile(r"^\s*-\s*\[\s\]", re.MULTILINE)
CHECK_DONE = re.compile(r"^\s*-\s*\[x\]", re.MULTILINE)


def analyse_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    pending = len(CHECK_PENDING.findall(text))
    done = len(CHECK_DONE.findall(text))
    total = pending + done
    pct = round(100 * done / total, 1) if total else 100.0
    return {"file": str(path), "pending": pending, "done": done,
            "total": total, "pct": pct}


def group_by_module(results: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for r in results:
        module = Path(r["file"]).parts[0] if Path(r["file"]).parts else "?"
        groups.setdefault(module, []).append(r)
    return groups


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--path", default=".", help="Carpeta raiz a analizar.")
    ap.add_argument("--json", action="store_true", help="Salida en JSON.")
    args = ap.parse_args()

    root = Path(args.path)
    if not root.is_dir():
        print(f"[!] No existe la carpeta: {root}", file=sys.stderr)
        return 2

    results = [analyse_file(p) for p in sorted(root.rglob("*.md"))]
    groups = group_by_module(results)

    if args.json:
        print(json.dumps({"root": str(root), "modules": groups}, indent=2,
                         ensure_ascii=False))
        return 0

    grand = {"pending": 0, "done": 0}
    for module in sorted(groups):
        pend = sum(r["pending"] for r in groups[module])
        done = sum(r["done"] for r in groups[module])
        total = pend + done
        pct = round(100 * done / total, 1) if total else 100.0
        grand["pending"] += pend
        grand["done"] += done
        print(f"{module:24s}  {done:4d}/{total:<4d}  {pct:5.1f}%")
        for r in groups[module]:
            print(f"    {Path(r['file']).name:40s} {r['done']:3d}/{r['total']:<3d}")

    gtot = grand["pending"] + grand["done"]
    gpct = round(100 * grand["done"] / gtot, 1) if gtot else 100.0
    print("-" * 46)
    print(f"TOTAL: {grand['done']}/{gtot} tareas ({gpct}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
