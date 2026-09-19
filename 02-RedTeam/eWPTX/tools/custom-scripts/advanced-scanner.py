#!/usr/bin/env python3
"""
advanced-scanner.py — Multi-layer web scanner (eWPTX).

Collects low-cost "frictions" before attacking by hand: security headers,
cookies, robots/sitemap, common paths, CORS and redirects.
Designed as an extensible base: add new checks in CHECKS.

Usage:
    python3 advanced-scanner.py -u https://target.com
    python3 advanced-scanner.py -u http://target:8080 --out report.json
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)

COMMON_PATHS = (
    "robots.txt", "sitemap.xml", ".well-known/security.txt",
    "admin", "api", "login", "upload", ".git/config", "swagger",
)

WEAK_COOKIE_FLAGS = ("secure", "httponly", "samesite")

# Paths whose mere exposure is itself a finding, with the severity it deserves.
# An exposed repository config outranks a robots.txt hit: it hands over source
# and history, not a route list.
SENSITIVE_PATHS = {
    ".git/config": "high",
    "robots.txt": "low",
    "sitemap.xml": "low",
}


@dataclass
class Finding:
    level: str
    check: str
    detail: str
    extra: dict = field(default_factory=dict)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Decline every 3xx so checks observe the raw outcome.

    build_opener() installs HTTPRedirectHandler by default, which silently
    follows 301/302 and would make the redirect branch of
    check_common_paths() unreachable.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Scanner:
    def __init__(self, base: str, insecure: bool = False, timeout: float = 10.0):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.findings: list[Finding] = []
        handlers: list = []
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self.opener = urllib.request.build_opener(NoRedirect, *handlers)

    def request(self, url: str, extra_headers: dict | None = None) -> tuple[int, dict, bytes]:
        headers = {"User-Agent": "advanced-scanner/0.1"}
        headers.update(extra_headers or {})
        req = urllib.request.Request(url, headers=headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Network error reaching {url}: {exc}") from exc

    # ── Checks ──────────────────────────────────────────────────────
    def check_headers(self, status: int, headers: dict) -> None:
        hdr = {k.lower(): v for k, v in headers.items()}
        for name in SECURITY_HEADERS:
            if name.lower() not in hdr:
                self.findings.append(Finding("info", "security-headers",
                                             f"Missing header {name}"))
        server = hdr.get("server") or hdr.get("x-powered-by")
        if server:
            self.findings.append(Finding("info", "banner", f"Exposed banner: {server}"))

    def check_cookies(self, headers: dict) -> None:
        for set_cookie in headers.get("Set-Cookie", "").splitlines():
            parts = [p.strip().lower() for p in set_cookie.split(";")]
            name = parts[0].split("=")[0] if parts else "?"
            missing = [f for f in WEAK_COOKIE_FLAGS if f not in parts]
            if missing:
                self.findings.append(Finding("low", "cookies",
                                             f"Cookie '{name}' missing: {', '.join(missing)}"))

    def check_cors(self) -> None:
        try:
            _, headers, _ = self.request(self.base + "/", {"Origin": "https://evil.example"})
            acao = headers.get("Access-Control-Allow-Origin", "")
            if acao.strip() != "https://evil.example":
                return
            # A reflected origin is only a credential-theft primitive when the
            # browser is also told to send credentials.
            acac = headers.get("Access-Control-Allow-Credentials", "").strip().lower()
            if acac == "true":
                self.findings.append(Finding(
                    "high", "cors",
                    "ACAO reflects the Origin with Access-Control-Allow-Credentials: "
                    "true (credentialed cross-origin read)"))
            else:
                self.findings.append(Finding(
                    "low", "cors",
                    "ACAO reflects the Origin but Access-Control-Allow-Credentials "
                    "is not 'true' (no credentialed read)"))
        except RuntimeError:
            pass

    def check_common_paths(self) -> None:
        for path in COMMON_PATHS:
            url = self.base + "/" + path
            try:
                status, _, body = self.request(url)
            except RuntimeError:
                continue
            level = SENSITIVE_PATHS.get(path)
            if status == 200 and level:
                self.findings.append(Finding(level, "paths",
                                             f"{path} is accessible", {"bytes": len(body)}))
            elif status in (200, 301, 302, 403):
                self.findings.append(Finding("info", "paths",
                                             f"{path} -> HTTP {status}"))

    # ── Orchestration ──────────────────────────────────────────────
    def run(self) -> dict:
        try:
            status, headers, body = self.request(self.base + "/")
        except RuntimeError as exc:
            return {"error": str(exc), "findings": []}
        self.check_headers(status, headers)
        self.check_cookies(headers)
        self.check_common_paths()
        self.check_cors()
        return {
            "target": self.base,
            "status": status,
            "body_bytes": len(body),
            "findings": [vars(f) for f in self.findings],
        }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out", default=None, help="Dump JSON to a file.")
    args = ap.parse_args()

    scanner = Scanner(args.url, insecure=args.insecure)
    report = scanner.run()
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"[+] Report saved to {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
