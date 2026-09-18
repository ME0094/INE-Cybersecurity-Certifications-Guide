# eWPTX — Web Application Penetration Tester eXtreme (Study Module)

> Area: `02-RedTeam` · Repository: `INE-Cybersecurity-Certifications-Guide`
>
> This folder is an **English** study companion for INE Security's eWPTX track. Everything here is written from public, general knowledge and from practice on authorized lab platforms (for example, PortSwigger Web Security Academy). It contains **no actual exam content** and no NDA-protected material — keep it that way.

## Certification version and naming

- **Official title:** *Web Application Penetration Tester eXtreme* — **eWPTX**. INE's
  credential title carries **no version number**.
- **Official page:** <https://ine.com/security/certifications/ewptx-certification>
- **Latest public update:** INE relaunched the certification in the November/December 2024
  window (public announcement dated **4 December 2024**). Notes written after that refresh
  are often labelled "eWPTXv3"; material from the previous generation is labelled
  "eWPTXv2". Both describe the same credential at different points in time, which is why
  this module keeps the folder name `eWPTX` to match INE's title.
- Exam logistics (scope, duration, scoring, price) are published by INE only. Confirm them
  on the official page before booking — nothing in this module should be read as a
  statement about the current exam.

## What eWPTX is about

eWPTX (Web Application Penetration Tester eXtreme) is INE Security's advanced/expert-level web application security certification. It sits above the professional-level web track and targets testers who already know how to find and exploit individual, well-known web vulnerabilities. The theme of this level is **complexity**: real applications rarely fail with a single textbook bug — they fail because an attacker combines several weaknesses and bypasses the controls standing in front of them.

In public, domain-level terms, the module develops expertise in:

- **Advanced and chained exploitation** — turning small primitives (a reflection, an open redirect, a header injection, a logic quirk) into serious impact by chaining them across layers: front end, back end, APIs, authentication, and sessions.
- **Protection bypasses** — evading WAFs, rate limits, input filters, and client-side controls, and understanding *why* each bypass works.
- **Complex authentication and authorization** — modern token formats (JWT), delegated authorization flows (OAuth), session-management edge cases, and flawed access-control logic.
- **HTTP protocol-level attacks** — request smuggling/desync, parameter pollution, cache-poisoning primitives, and how front-end/back-end disagreement gets abused.
- **Server-side exploitation in context** — SSRF reaching internal networks, unsafe deserialization, template injection, and similar classes used as links in a chain rather than as isolated tricks.
- **Professional assessment craft** — scoping, enumeration discipline, evidence-based verification, and clear reporting.

The exact syllabus, prerequisites, and exam brief are published by INE; check the official site (`https://ine.com`) before planning your preparation. This repository is a study aid, not a copy of the syllabus.

## Skills you build by working this module

- Plan an advanced assessment: enumerate broadly, then verify each candidate issue with a **proof of impact**, not just a payload echo.
- Combine separate findings into an attack chain and prove the final impact (account takeover, data access, RCE, ...).
- Read and manipulate modern authentication artifacts (JWTs, OAuth flows, session cookies) fluently.
- Diagnose protocol-level confusion (smuggling, parameter pollution) and explain the root cause of a bypass.
- Automate repetitive steps with your own small scripts — scanner, request builders, report generation (see `tools/custom-scripts/`).
- Document findings with reproducible evidence and write pentest-style reports.

## Prerequisites & recommended background

This is an advanced module: it assumes, rather than teaches, the foundations. Before starting, be comfortable with:

- **HTTP in practice** — methods, status codes, headers, cookies, caching headers, and how proxies terminate and forward traffic.
- **The common vulnerability classes** described in the OWASP Top 10 and the Web Security Testing Guide (SQL injection, XSS, CSRF, IDOR, broken authentication) — enough to exploit each on a basic lab without looking things up.
- **Everyday Burp Suite** — proxy interception, Repeater, Intruder basics, Decoder. The advanced Burp guide builds on these and does not re-teach them.
- **Reading and writing small scripts** — you will extend the Python scanner example and script request builders, so basic Python (functions, dataclasses, `requests`-style HTTP) is expected.
- **Reading application code** — modern labs and real assessments require understanding the JavaScript/Python/Java snippets behind a feature, not just fuzzing its inputs.

If any of these feel shaky, spend a week on the foundations first: this module's value is in the *interplay* of techniques, which is hard to absorb while also learning the basics.

## How the files relate — suggested reading order

```text
methodology/ (01 → 05)              workflow backbone: learn the phases first
        │
        ▼
tools/burp-advanced.md              automation skills (macros, Turbo Intruder, ...)
        │
        ▼
tools/custom-scripts/               script the boring parts (scanner + framework)
        │
        ▼
labs/challenge-solutions.md         apply everything on multi-stage labs/drills
        │
        ▼
cheatsheets/advanced-techniques.md  recall aid during labs and final revision
```

In one sentence: *learn the method, sharpen the tools, script the repetition, practice the chains, then drill recall.* The cheatsheet is deliberately last — it is a memory aid, not a substitute for the other three layers.

## Module layout

```text
eWPTX/
├── README.md                          <- you are here
├── methodology/                       # ordered working procedures
│   ├── 01-advanced-recon.md
│   ├── 02-chaining-exploits.md
│   ├── 03-bypass-techniques.md
│   ├── 04-advanced-authentication.md
│   └── 05-reporting.md
├── tools/                             # tool guides + your own scripts
│   ├── burp-advanced.md
│   └── custom-scripts/
│       ├── advanced-scanner.py        # working example scanner (extend it)
│       └── exploit-framework.md       # how to grow it into a framework
├── labs/
│   └── challenge-solutions.md         # multi-stage lab methodology + drills
└── cheatsheets/
    └── advanced-techniques.md         # compact technique reference
```

How to use each folder:

- **`methodology/`** — Read the numbered files in order (01 → 05) *before* touching a lab. They describe a repeatable workflow: advanced recon, chaining exploits, bypass techniques, advanced authentication, and reporting.
- **`tools/burp-advanced.md`** — Burp Suite skills that pay off at this level: macros, session handling rules, Turbo Intruder, extensions and the BApp Store, match/replace, and integration with the rest of your toolchain.
- **`tools/custom-scripts/`** — `advanced-scanner.py` is a small working scanner (uniform finding model, request layer, pluggable checks, JSON output). `exploit-framework.md` explains when scripting beats point tools and how to extend the scanner into your own framework.
- **`labs/challenge-solutions.md`** — How to attack multi-stage challenges on authorized platforms, record findings, and reconstruct full chains, plus skill drills with objectives and expected outcomes.
- **`cheatsheets/advanced-techniques.md`** — A quick-reference of advanced technique families (JWT, OAuth, WAF bypass, smuggling, SSRF, parameter pollution) to consult while working labs and while revising.

## Suggested study roadmap

1. **Phase 0 — Foundations refresh.** Confirm HTTP semantics, the OWASP Top 10 classes, and everyday Burp usage before starting. You should be comfortable with proxy-based manual testing already.
2. **Phase 1 — Methodology first.** Read `methodology/` files 01 through 05 and take your own notes. Do not jump to payloads yet.
3. **Phase 2 — Tooling.** Read `tools/burp-advanced.md`; then `tools/custom-scripts/exploit-framework.md`. Run `advanced-scanner.py` against an authorized target and add one small check of your own to make the pattern stick.
4. **Phase 3 — Lab practice.** Work through the drills in `labs/challenge-solutions.md` on authorized platforms (PortSwigger Web Security Academy is the canonical free source). Revisit the methodology files whenever a step confuses you.
5. **Phase 4 — Consolidation.** Drill yourself with `cheatsheets/advanced-techniques.md` closed: explain each technique out loud and reproduce a minimal example.
6. **Phase 5 — Full simulation.** Chain techniques end-to-end on self-hosted vulnerable apps or authorized ranges, then write a complete report following `methodology/05-reporting.md`.

Tip: keep a personal notes file with **one worked chain per technique family**. After a few weeks of labs you will have built your own playbook — that is worth more than any single cheatsheet.

## Working rules (ethics & scope)

- Only test systems you own or have **written authorization** to test.
- Prefer authorized lab platforms: PortSwigger Web Security Academy, OWASP Juice Shop, local DVWA/WebGoat-style apps, or INE's own lab environment if you are enrolled.
- Never paste NDA-covered material into this repository. Keep all content generic, public, and in English.

## Common Mistakes & Tips

- **Skipping methodology.** Starting labs before you have a workflow produces scattered, unverifiable results. Learn the phases first; they are the reusable asset.
- **Chasing payloads instead of mechanisms.** If you cannot explain why a payload works, you will not be able to bypass the next filter. Study the parser and the flaw, not just the string.
- **Not recording evidence.** A lab "win" without saved request/response pairs is worthless for report drills and for revision. Record as you go.
- **Practicing on one platform only.** Different platforms use different stacks and show different real-world variation. Rotate between sources.
- **Blaming the payload first.** A "failed" exploit is often a proxy misconfiguration, an expired session, or the wrong `Host` header. Verify your environment before changing the payload.
- **Adding NDA content.** The moment an item describes exam specifics it cannot live in this module. Keep it public and generic.

## Checklist / Self-Test

- [ ] I can explain, in my own words, what eWPTX-level testing adds over basic web testing (chains, bypasses, auth internals).
- [ ] I have read `methodology/` files 01–05 in order and can summarize each phase without looking.
- [ ] I have practiced the Burp advanced features in `tools/burp-advanced.md` (a macro + session rule, one Turbo Intruder script, one extension).
- [ ] I have run `tools/custom-scripts/advanced-scanner.py` against an authorized target and extended it with one new check.
- [ ] I have completed the drills in `labs/challenge-solutions.md` and recorded at least one full chain with evidence.
- [ ] I can reproduce the core entries of `cheatsheets/advanced-techniques.md` with the file closed.
- [ ] I have written at least one end-to-end pentest-style report using the reporting methodology.
- [ ] Everything I added to this module is English, public, and free of NDA content.

## Further Resources

- OWASP Web Security Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
- OWASP Cheat Sheet Series — https://cheatsheetseries.owasp.org/
- PortSwigger Web Security Academy (free, authorized labs) — https://portswigger.net/web-security
- PortSwigger Research (write-ups behind many of these techniques) — https://portswigger.net/research
- INE official site (syllabus, training tracks, labs) — https://ine.com
