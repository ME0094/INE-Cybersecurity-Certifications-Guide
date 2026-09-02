#!/usr/bin/env python3
"""
fuzzing.py — Single-parameter HTTP fuzzer (eWPT / eWPTXv2).

Replaces the FUZZ marker in the URL (or in --data) with each wordlist line
and prints status + length. Uses only the standard library.

Usage:
    python3 fuzzing.py -u "http://target/dir/FUZZ" -w payloads.txt
    python3 fuzzing.py -u "http://target/login" -w payloads.txt --data "user=admin&pass=FUZZ"
    python3 fuzzing.py -u "http://target/?id=FUZZ" -w payloads.txt --method POST
"""
from __future__ import annotations

import argparse
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MARKER = "FUZZ"


def build_opener(insecure: bool) -> urllib.request.OpenerDirector:
    handlers: list = []
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def fetch(opener, url: str, method: str, data: str | None, headers: dict,
          timeout: float) -> tuple[int, int]:
    body = data.encode() if data else None
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            content = resp.read()
            return resp.status, len(content)
    except urllib.error.HTTPError as exc:
        return exc.code, len(exc.read())
    except urllib.error.URLError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 0, 0


def load_wordlist(path: str) -> list[str]:
    words: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)
    return words


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-u", "--url", required=True, help=f"URL with the {MARKER} marker.")
    ap.add_argument("-w", "--wordlist", required=True, help="Payload file (wordlist).")
    ap.add_argument("--method", default="GET", choices=["GET", "POST"])
    ap.add_argument("--data", default=None, help="POST body with the FUZZ marker.")
    ap.add_argument("--header", action="append", default=[],
                    help="Extra header (e.g. 'Cookie: session=abc'). Repeatable.")
    ap.add_argument("--delay", type=float, default=0.2, help="Seconds between requests.")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--insecure", action="store_true", help="Ignore TLS.")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if MARKER not in args.url and (not args.data or MARKER not in args.data):
        ap.error(f"The URL or --data must contain the {MARKER} marker.")

    words = load_wordlist(args.wordlist)
    if not words:
        print("[!] Wordlist is empty.", file=sys.stderr)
        return 2

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    opener = build_opener(args.insecure)
    print(f"{'STATUS':>6} {'LEN':>7}  LINE")
    for word in words:
        url = args.url.replace(MARKER, urllib.parse.quote(word, safe=""))
        data = None
        if args.data:
            data = args.data.replace(MARKER, word)
        status, length = fetch(opener, url, args.method, data, headers, args.timeout)
        print(f"{status:>6} {length:>7}  {word}")
        if args.verbose:
            print(f"    -> {url}")
        time.sleep(max(0.0, args.delay))
    return 0


if __name__ == "__main__":
    sys.exit(main())
