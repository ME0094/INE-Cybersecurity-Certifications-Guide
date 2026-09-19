#!/usr/bin/env python3
"""
report-generator.py — Study progress report.

Walks a tree of Markdown notes (by default the repository) counting the
`- [ ]` (pending) and `- [x]` (completed) tasks of each file, grouped by
module, and prints a summary in plain text or JSON.

A file with no checklist has no percentage to report: it is counted as
`n/a` and left out of the averages, instead of being shown as 100% done.

Usage:
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
    pct = round(100 * done / total, 1) if total else None
    return {"file": str(path), "pending": pending, "done": done,
            "total": total, "pct": pct}


def group_key(path: Path, root: Path) -> str:
    """Group by <area>/<module> when the note lives inside one, else by folder.

    The previous version used the first path component verbatim, so a relative
    walk put every file in one group and an absolute walk put them all in "C:".
    """
    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError:
        rel = path
    parts = rel.parts[:-1]  # drop the file name
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    if parts:
        return parts[0]
    return "(root)"


def group_by_module(results: list[dict], root: Path) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for r in results:
        module = group_key(Path(r["file"]), root)
        groups.setdefault(module, []).append(r)
    return groups


def ratio(done: int, total: int) -> str:
    return f"{round(100 * done / total, 1):5.1f}%" if total else "  n/a"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--path", default=".", help="Root folder to analyze.")
    ap.add_argument("--json", action="store_true", help="Output as JSON.")
    args = ap.parse_args()

    root = Path(args.path)
    if not root.is_dir():
        print(f"[!] Folder does not exist: {root}", file=sys.stderr)
        return 2

    results = [analyse_file(p) for p in sorted(root.rglob("*.md"))]
    groups = group_by_module(results, root)

    if args.json:
        print(json.dumps({"root": str(root), "modules": groups}, indent=2,
                         ensure_ascii=False))
        return 0

    grand = {"pending": 0, "done": 0}
    no_checklist = 0
    for module in sorted(groups):
        pend = sum(r["pending"] for r in groups[module])
        done = sum(r["done"] for r in groups[module])
        total = pend + done
        grand["pending"] += pend
        grand["done"] += done
        print(f"{module:34s}  {done:4d}/{total:<4d}  {ratio(done, total)}")
        for r in groups[module]:
            mark = "" if r["total"] else "  (no checklist)"
            if r["total"] == 0:
                no_checklist += 1
            print(f"    {Path(r['file']).name:40s} {r['done']:3d}/{r['total']:<3d}{mark}")

    gtot = grand["pending"] + grand["done"]
    print("-" * 56)
    print(f"TOTAL: {grand['done']}/{gtot} tasks ({ratio(grand['done'], gtot).strip()}) "
          f"across {len(results)} notes; {no_checklist} note(s) have no checklist "
          "and are excluded from the percentage.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
