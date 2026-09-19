# Reporting — eWPTX Methodology Phase 5

> eWPTX study guide · Advanced web methodology — INE-Cybersecurity-Certifications-Guide

A pentest is not finished when the exploit works — it is finished when a
reader who was not in the room can **reproduce the finding, understand its
real impact, and act on the fix**. Advanced engagements multiply the
difficulty: chained findings, business-logic nuance, and severity that
depends on context. This phase covers writing findings with reproduction
steps, calibrating severity honestly, describing chained impact, giving
actionable remediation, and defending your conclusions under review.

## Anatomy of one finding

Every finding should stand alone (an executive should understand it without
reading the others):

```text
[ID-07] Server-Side Request Forgery in the PDF export service (High)

Asset / endpoint:  POST /api/v1/export  (export-svc, Node 18, internal LB)
Category:          A10:2021 Server-Side Request Forgery
CVSS 3.1:          7.7 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N)
                   PR:L matches step 1 of the reproduction (the endpoint needs
                   a session); S:C carries the cross-boundary reach.
                   — chained with ID-02 (heapdump key leak) -> 9.1, see §3.4

Summary (2-3 sentences): the export endpoint accepts a url parameter and the
server fetches it without allow-listing destinations...

Reproduction (numbered, copy-paste-able):
   1. Log in as any user (test account t1).
   2. POST /api/v1/export with {"url":"http://127.0.0.1:8080/actuator"}
      (Request A in Appendix).
   3. Observe the internal actuator JSON in the response (Excerpt B).
   4. Repeat with http://169.254.169.254/... on the lab instance to confirm
      cloud-metadata reach (Excerpt C, redacted).

Impact: authenticated internal reach... chained with ID-02 gives cloud keys.
Remediation: allow-list egress destinations... (with code sketch, below).
References: OWASP SSRF; PortSwigger SSRF.
```

## Writing reproduction steps

Reproduction is the part reviewers test first. Rules:

- **Number every step**; each step is one action with its expected result.
- **Attach the raw request** (method, path, headers, body) rather than
  describing it; include the response excerpt that *proves* the bug.
- **Include preconditions**: account type, cookies, tokens, application
  state, and environment (which build/commit was tested).
- **Keep it minimal**: the shortest path from clean state to proof. Extra
  requests make reviewers suspect the bug needs luck.
- **For chains, separate "per-link proof" from "full-chain reproduction"**
  (see phase 2) so a reviewer can validate each link independently.
- **Script long reproductions** and commit the script path in the finding —
  but also keep the manual steps, because reviewers will not always run code.

```http
# What "Request A" should look like in the appendix — exact and replayable
POST /api/v1/export HTTP/1.1
Host: app.example.com
Cookie: session=<test-account-session>
Content-Type: application/json

{"url":"http://127.0.0.1:8080/actuator"}
```

## Severity calibration

Severity answers: **what can an attacker do, with what prerequisites, to what
value?** Calibrate with CVSS, then sanity-check against the business:

- **Scope**: can the bug cross trust boundaries (user→admin, app A→internal
  network)? Scope:Changed pushes severity up.
- **Prerequisites**: authenticated-only bugs drop a point vs. unauthenticated
  ones; a "requires admin" bug is often low unless it chains.
- **Exploitability honesty**: theoretical vs. demonstrated. Do not rate
  "could lead to RCE" as RCE without a PoC — rate what you proved, and note
  the theoretical ceiling separately.
- **Impact quality**: data *exposure* vs. data *modification* vs.
  availability; PII volume and regulatory angle belong in the business
  impact note, not in the CVSS vector.
- **Chained severity**: if finding A alone is Medium but A+B is Critical,
  report **both** ratings and make the chain its own finding or section (see
  below), never silently inflate A's standalone score.

```text
Calibration quick reference
Critical  unauthenticated RCE / full data compromise / chain fully proven
High      auth-bypass or broad data access; SSRF to internal+secrets
Medium    partial data exposure; logic flaw with preconditions
Low       info leak with little impact; defense-in-depth gaps
```

## Describing chained impact

Chains are where advanced reports live or die. Treat the chain as a
first-class object:

```text
§3.4 Chain: export SSRF -> internal debug API -> cloud keys -> config read

Diagram:
  [internet] --SSRF--> export-svc --http--> :8080 actuator
       --heapdump--> AWS key --s3 GetObject--> deploy bucket config
       --db creds + API token--> full application compromise

Why it matters: every link is individually rated Medium/Low, but the
composition is unauthenticated full compromise (Critical). The chain shows
the real risk posture — single controls (egress filtering, debug-API
binding) each break one link, so fixing any link materially reduces risk.
```

Describe for each link: the finding ID it relies on, the proof, and **which
single fix breaks the chain** (defense often needs only one link removed).
Avoid purple prose; let the diagram and the link table carry the impact.

## Remediation guidance

Remediation must be **implementable**, not a slogan:

- Name the **root cause** (missing allow-list vs. weak validation) so the fix
  targets the cause, not the symptom.
- Give **concrete controls** with short code/configuration sketches:

```text
// SSRF remediation sketch — deny by default, allow-list egress
const ALLOWED = ['https://export-static.example.com'];   // explicit list
async function fetchUrl(raw) {
  const u = new URL(raw);
  if (!ALLOWED.some((a) => u.origin === new URL(a).origin)) throw 400;
  const ip = await dnsLookup(u.hostname);                // resolve server-side
  if (!isPublicRoutable(ip)) throw 400;                  // block 127.0.0.0/8 etc.
  return fetch(u, { redirect: 'manual' });               // do not follow to intranet
}
```

- Separate **immediate mitigation** (disable endpoint, firewall egress) from
  **permanent fix** (code change, redesign), and note **verification steps**
  (how the tester will re-test).
- Reference the OWASP cheat sheet relevant to the class of bug.

## Defending your conclusions

Expect pushback: "cannot reproduce", "that is out of scope", "that is by
design". Prepare by having:

- **Raw evidence** preserved: every request/response pair, session tokens at
  each step, timestamps, and environment details. Evidence beats prose.
- **Scope citations**: for each finding, the exact asset and the scope line
  that covers it; if a finding touches something out of scope, say so
  explicitly and stop there.
- **A repro run**: before delivery, replay every finding end-to-end from a
  clean state against the *current* build; findings that no longer reproduce
  get re-tested and re-dated, not shipped stale.
- **Reasoned severity, not ego**: if a client argues a rating, walk through
  the CVSS vector component by component and agree on what changes it —
  concede legitimate points (e.g., "an internal attacker with those rights
  is already trusted").
- **A clear false-positive policy**: state how you distinguish confirmed from
  suspected findings, and keep a "noted, not confirmed" section.

## Executive summary and structure

A full report usually follows this order: executive summary (risk posture in
business language), scope and methodology, findings by severity, chained
impact section, remediation roadmap, appendix (raw requests/responses). The
executive summary must be readable by someone who will never open the
appendix: top 3-5 risks, what they mean for the business, and what to fix
first.

## Common Mistakes & Tips

- **Vague reproductions.** "Send a request to the endpoint" is not
  reproducible; paste the exact request.
- **Severity inflation from unproven chains.** Rate what you demonstrated;
  describe the theoretical ceiling separately.
- **Missing preconditions.** A finding that needs a specific account/state
  must say so on the first line.
- **Full secrets in the report.** Redact credentials and keys everywhere,
  even in internal reports.
- **Stale findings.** Re-run reproductions on the final build before
  delivery; include the tested build/commit in every finding.
- **Remediation without root cause.** "Validate input" does not help; name
  the missing control and show the fix.
- **Not preserving evidence during testing.** Screenshot and store raw
  traffic as you go — you cannot reconstruct it after the lab resets.
- **Defensiveness in review.** Walk the vector, share evidence, and update
  the report when a point is valid.

## Checklist / Self-Test

- [ ] Every finding has a numbered, copy-paste reproduction with the exact
      request, expected result, and response evidence.
- [ ] Preconditions (account, tokens, state, build) are stated in every
      finding.
- [ ] Severity is CVSS-derived and sanity-checked; chained findings carry
      both standalone and chained ratings.
- [ ] Chained impact includes a diagram and states which single fix breaks
      the chain.
- [ ] Remediation names the root cause and gives concrete, verifiable
      controls with code/config sketches.
- [ ] Evidence (raw requests, responses, tokens, timestamps) is preserved
      and attached for every conclusion.
- [ ] I re-ran all reproductions end-to-end against the final build before
      delivery.
- [ ] I can defend each rating by walking through the CVSS vector and scope
      lines without resorting to assertion.

> **Verification:** the base scores were recomputed on 2026-09-19 with the CVSS
> v3.1 formulas as published by FIRST
> (<https://www.first.org/cvss/specification-document>) in a Python 3.12 script,
> cross-checked against four reference vectors (9.8, 6.1, 7.8, 7.5 — all
> reproduced). `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` = **8.6**, not 7.5; 7.5 is
> the `S:U` variant; with `PR:L` — the precondition of step 1 — the same vector
> is **7.7**: ISS 0.5600, Impact (S:C) 3.9928, Exploitability 3.1096,
> Roundup(1.08 × 7.1024) = 7.7.

## Further Resources

- OWASP Web Security Testing Guide — reporting and risk-rating guidance:
  https://owasp.org/www-project-web-security-testing-guide/
- FIRST CVSS specification and calculator: https://www.first.org/cvss/
- OWASP Cheat Sheet Series — vulnerability disclosure and reporting cheat
  sheets: https://cheatsheetseries.owasp.org/
- PortSwigger Research — write-ups of chained vulnerabilities as reporting
  examples: https://portswigger.net/research
- RFC 9116 (security.txt — declaring security contact/process):
  https://www.rfc-editor.org/rfc/rfc9116
