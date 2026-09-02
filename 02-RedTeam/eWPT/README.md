# eWPT — Web Application Penetration Tester

> Area: 02-RedTeam · INE-Cybersecurity-Certifications-Guide

## What is eWPT?

**eWPT** (eLearnSecurity Web Application Penetration Tester) is a certification
from INE Security that validates practical skills in **web application
penetration testing**. It is aimed at people who already understand the basics
of web technologies and network security and want to demonstrate a hands-on,
professional approach to assessing the security of web applications.

This module is a public study guide. It covers the *skills domains* that the
certification is built around — reconnaissance, authentication, authorization,
input validation, and business logic — without reproducing any exam content or
material covered by INE's NDA. Everything here is generic, industry-standard
knowledge you can practice on authorized targets such as DVWA, OWASP Juice
Shop, or PortSwigger's Web Security Academy.

## Skills the module builds

Working through this module should give you the following capabilities:

- Map a web application's attack surface: technology fingerprinting, content
  discovery, and analysis of requests and responses.
- Evaluate authentication and session mechanisms for weak passwords, flawed
  login flows, and session handling issues.
- Test authorization boundaries: horizontal and vertical access control,
  object-level references (IDOR), and forced browsing.
- Find and exploit classic input-validation flaws: SQL injection, XSS,
  command injection, path traversal / LFI, SSRF, and unsafe file upload.
- Reason about business logic: abusing workflows, pricing or quota fields,
  race conditions, and trust boundaries.
- Drive professional tooling: Burp Suite as the central proxy and sqlmap for
  automated SQL injection testing.
- Write up findings the way a consultant would: evidence, impact, and
  remediation — no exam specifics, just good professional practice.

## Prerequisites

Before starting, make sure you are comfortable with:

- HTTP fundamentals: methods, status codes, headers, cookies, and sessions.
- HTML/JavaScript basics and how a browser renders a page.
- Relational database concepts and basic SQL (`SELECT`, `JOIN`, `WHERE`).
- Linux command line and light scripting (bash or Python).
- A working Burp Suite proxy setup (see `tools/burp-suite-guide.md`).

If any of these feel shaky, spend a week shoring them up first — every later
phase builds directly on them.

## How to use this module

The module is organized in the order you should attack it:

1. `methodology/` — The **phases** of a web application test, numbered in the
   order you perform them:
   - `01-reconnaissance` — discover and map the application.
   - `02-authentication` — login, sessions, and identity.
   - `03-authorization` — what each identity is allowed to do.
   - `04-input-validation` — injection and parsing flaws.
   - `05-business-logic` — flaws in the application's rules.
   - Read them in sequence; each later phase assumes the earlier ones.
2. `tools/` — **Reference guides** for the tooling you will use while working
   the methodology:
   - `burp-suite-guide.md` — proxy setup, Repeater, Intruder, scanner, extensions.
   - `sqlmap-basics.md` — automated SQL injection testing.
   - `automation-scripts/` — small helper scripts and payload lists (handled
     separately; do not edit them casually).
3. `labs/` — **Practice environments and drills**:
   - `dvwa-setup.md` — install and configure an intentionally vulnerable app.
   - `web-challenges.md` — skill drills mapped to each methodology phase.
4. `cheatsheets/` — **Quick-reference** material:
   - `web-payloads.md` — payload families by vulnerability class.

### Suggested study roadmap

A realistic, self-paced order of study:

1. **Foundations (1–2 weeks).** Be comfortable with HTTP, HTML, JavaScript,
   cookies, sessions, and SQL basics. Refresh Burp Suite fundamentals.
2. **Methodology pass (1 week).** Read all five methodology files and make
   sure you can explain each phase and name its key techniques.
3. **Tooling drills (1 week).** Set up Burp Suite interception and TLS
   interception, then work through the sqlmap basics guide against a local lab.
4. **Lab setup (1 day).** Bring up DVWA (Docker or LAMP) following
   `labs/dvwa-setup.md`; confirm you can log in at each security level.
5. **Phase drills (2–4 weeks).** Complete `labs/web-challenges.md` drills one
   phase at a time, then re-read the matching methodology file.
6. **Consolidation (1 week).** Use the cheatsheets to rehearse payload
   families and review your notes. Redo the drills with write-ups you could
   share professionally.

Reserve dedicated practice time: web testing is a hands-on skill and reading
alone will not make it stick.

## Ethics and scope

- Practice **only** against systems you own or have explicit written
  authorization to test.
- Keep labs isolated: DVWA and similar tools are deliberately vulnerable and
  must never be exposed to untrusted networks.
- This guide intentionally contains **no exam content**. Treat the INE
  certification NDA seriously, just as you would in any professional
  engagement.

## Common mistakes & tips

- **Jumping into labs before the methodology** → you collect exploits without a
  process. Read the five phase files first; the labs assume that order.
- **Reading tool guides without opening the tools** → Burp and sqlmap only
  stick through hands-on use. Pair every guide with its lab drill the same
  week.
- **Practicing only at DVWA's Low level** → Low teaches mechanics, not
  adaptation. Progress to Medium/High and re-run the same drills.
- **Confusing tool output with understanding** → sqlmap can dump a table while
  you still cannot explain the injection. Always prove a finding manually
  before and after automation.
- **No write-ups** → if you cannot summarize a finding (evidence, impact,
  remediation), you have not finished the exercise. Write three lines per lab.
- Tip: keep a personal log of payloads that worked, the *context* they worked
  in, and the defense that stopped them — it compounds faster than re-reading
  guides.
- Tip: revisit earlier files after finishing later ones; you will catch gaps
  now that you have context.

## Checklist / Self-test

- [ ] I can explain what eWPT validates in one sentence, without exam specifics.
- [ ] I can name the five methodology phases in working order.
- [ ] I know which tool guide covers proxy/interception and which covers
      automated SQLi extraction.
- [ ] I installed an authorized lab and logged in at every security level.
- [ ] I completed at least one drill per methodology phase.
- [ ] I rehearsed payload families from the cheatsheet without looking.
- [ ] I produced a short written report for one lab exercise.
- [ ] I reviewed each file's common-mistakes list and re-tested my weak spots.

---

## Further resources

- OWASP Top 10 — <https://owasp.org/www-project-top-ten/>
- OWASP Testing Guide — <https://owasp.org/www-project-web-security-testing-guide/>
- PortSwigger Web Security Academy — <https://portswigger.net/web-security>
- DVWA project — <https://github.com/digininja/DVWA>
- INE Security (certification program information) — <https://security.ine.com/>
