# Challenge Practice — Multi-Stage Labs, Evidence, and Chain Reconstruction

> eWPTX · Labs — INE-Cybersecurity-Certifications-Guide (English)

## Purpose

This guide is a **methodology for advanced web challenges** on authorized platforms (PortSwigger Web Security Academy and similar). Advanced challenges are rarely "one request, one payload": they are multi-stage problems where you must enumerate, identify a weakness, build a working primitive, bypass a filter or two, and chain the pieces into real impact. The drills at the end describe techniques and expected outcomes — they are not copied answers, so work them honestly on the lab platform of your choice.

## How to approach a multi-stage lab

Follow a loop, not a sprint:

1. **Orient.** Read the lab brief for its definition of success (usually a state change: access an admin panel, read a file, become another user). Identify the app's roles (guest/user/admin), its main features, and which ones you control.
2. **Map the surface.** Walk the app and proxy everything through Burp. Note every endpoint, parameter, cookie, upload point, and redirect. Two minutes of listing beats twenty minutes of guessing.
3. **Find a foothold, then prove a primitive.** Pick the most promising input and show a concrete effect — a reflection in the response, a timing change, a different status code, an out-of-band hit. A *primitive* is that minimal, provable effect ("this parameter fetches a URL I control").
4. **Classify and bypass.** Name the weakness class (SSRF, JWT flaw, desync, access control, ...) and identify which protection layer blocks the obvious path (WAF filter, signature check, redirect policy, role check). Now design one bypass at a time and test it with a clear pass/fail criterion.
5. **Ask "so what?".** A reflected header or a reachable internal URL is not the goal. Determine what the primitive *combines with* to reach the brief's success condition.
6. **Chain end-to-end.** Execute the full sequence exactly as a victim or an automated flow would, and verify the final state change.
7. **Record it.** Write the finding and the chain *before* you forget the details (template below).

Time-box yourself: if a stage has no progress after a while, re-read the brief and your notes. The missing link is usually an assumption you made early ("this field is an ID" / "this header is ignored").

## Recording findings — evidence template

Save every meaningful step as request/response pairs (Burp *Save item*, or `curl` commands in your notes). A useful per-finding note:

````markdown
# Finding: <title> — <severity>

- Target URL: <url>
- Class(es): <e.g. SSRF > file read>
- Primitive: <one sentence: "the `url` parameter fetches arbitrary URLs via the server">
- Root cause: <one paragraph: which input, which validator, which assumption failed>

## Reproduction
1. Request A -> response A (note: ...)
2. Request B (built from A) -> response B (note: ...)

## Evidence
- Request:
  ```http
  POST /fetch HTTP/1.1
  Host: ...
  url=http://127.0.0.1/admin
  ```
- Response (excerpt): ...

## Impact chain
  vuln (primitive) --> link 2 (what makes it dangerous) --> final impact

## Suggested fix
  <one paragraph, server-side validation/authorization advice>

- [ ] verified
- [ ] written up
````

The discipline is: **every claim in the write-up must map to a saved request/response pair**. If you cannot reproduce the step from your notes, your notes are wrong.

## Reconstructing chains from notes

When a challenge is solved (or when you are reviewing a friend's write-up), practice reconstructing the chain backwards:

1. Start from the **final impact** and ask *"what made that possible?"* — answer with exactly one prior condition.
2. Repeat for that condition until you reach the **entry primitive**.
3. You now have the chain in reverse: write it forward as impact ← root cause dependencies.
4. Verify each link: replay the requests and confirm every intermediate state change actually happens. A chain with one unverified link is a theory, not a finding.

Keep a per-challenge **chain ledger**:

| # | Step | Proof (evidence id) | Depends on |
|---|------|--------------------|------------|
| 1 | guest login | req/1 | — |
| 2 | IDOR reads user profile | req/4 | 1 |
| 3 | profile leaks JWT for admin | req/6 | 2 |
| 4 | forged admin JWT accepted | req/9 | 3 |

This table is also the skeleton of your final report's *attack narrative* section.

## Skill drills

Each drill names an objective, the techniques it exercises, and the evidence that means success. Work them on authorized labs (Web Security Academy topic areas map to each drill) and record results with the template above.

### Drill 1 — JWT signature bypass by algorithm confusion

- **Objective:** Forge a token that the server accepts with elevated privileges.
- **Techniques:** Inspect the JWT header and signature verification; test `alg` handling (e.g., a server that accepts tokens signed with the public key as an HMAC secret, or one that trusts an attacker-controlled algorithm); craft and sign your own token.
- **Steps you should be able to do:** decode the token; obtain the verification key from public material; produce a forged token; confirm acceptance by calling a privileged endpoint.
- **Expected outcome:** an evidence pair showing a forged token being accepted (HTTP 200 on an admin-only route) plus a one-paragraph root-cause note.

### Drill 2 — Horizontal IDOR that escalates to vertical access

- **Objective:** Turn a user-level object reference flaw into access reserved for another role.
- **Techniques:** Enumerate object IDs; observe that one endpoint authorizes the *object* but not the *action*; abuse a method override or parameter-pollution quirk (e.g., the enforcement layer validates a different value than the data layer uses).
- **Steps you should be able to do:** prove you can read another user's object; then prove you can *modify* or *delete* what you should only read; finally reach a privileged action.
- **Expected outcome:** a three-hop chain ledger and request pairs showing each authorization decision failing.

### Drill 3 — SSRF into an internal-only service

- **Objective:** Use a server-side fetch to reach something the internet cannot see.
- **Techniques:** Find a URL-fetching input; bypass host filters (localhost spellings, IP encodings, redirect following, DNS tricks); enumerate an internal endpoint by status/timing/content-length; read an internal-only response.
- **Steps you should be able to do:** demonstrate a controlled fetch (your own listener), then pivot to the internal host, then extract data that only the internal service holds.
- **Expected outcome:** evidence that internal-only content (e.g., an admin panel page or metadata response) reached you through the vulnerable endpoint, plus the bypass list you tried in order.

### Drill 4 — Request desync detection, then cache poisoning

- **Objective:** First *detect* a front-end/back-end disagreement, then turn it into impact against another user.
- **Techniques:** Probe `Content-Length` vs `Transfer-Encoding` handling (CL.TE, TE.CL, obfuscated TE.TE) with paired requests on one connection; confirm the desync with a timing/orphaned-request signal; use the desync to poison a cached resource.
- **Steps you should be able to do:** produce the two-request probe and explain the differing parser behavior; then demonstrate a poisoned response being served from cache to a following request.
- **Expected outcome:** saved probe pairs showing the desync signature and one cache-poisoning proof with the victim-facing URL.

### Drill 5 — OAuth flow logic: state and redirect handling

- **Objective:** Exploit the *logic* of a delegated-authorization flow, not its cryptography.
- **Techniques:** Inspect the OAuth endpoints (authorize, token, callback); test whether `state` is checked; test `redirect_uri` validation with open-redirect hosts, path tricks, and encoding; leak the authorization code through a controllable redirect target.
- **Steps you should be able to do:** demonstrate login CSRF when `state` is absent or guessable; then demonstrate code theft via a lax `redirect_uri`, and swap it for a victim session.
- **Expected outcome:** an account-takeover chain whose last link is the code/state flaw, with each HTTP hop captured.

### Drill 6 — Race condition in a business-logic step

- **Objective:** Exploit a check-then-act flaw that a single sequential request cannot reach.
- **Techniques:** Identify a state-changing step with a redeem/apply/transfer action; send many concurrent requests through a single connection (Turbo Intruder single-packet style); observe whether server-side validation is atomic.
- **Steps you should be able to do:** show the sequential behavior (one success), then the concurrent behavior (more than one success), and quantify it in the evidence.
- **Expected outcome:** response pairs demonstrating N successes where the business rule allows 1, plus a note on where the check and the act diverged.

## Common Mistakes & Tips

- **Solving forward, recording never.** The chain you reconstruct from memory an hour later is missing links. Record after every successful step.
- **Confusing "the payload ran" with "the impact happened".** A reflected string or an out-of-band ping is a primitive; the brief's success condition is the goal. Chase the latter.
- **One payload at a time, blindly.** Change one variable per test and keep a pass/fail criterion, or you cannot learn which bypass worked.
- **Ignoring the environment.** Session expiry, proxy interference, and wrong `Host` headers masquerade as failed exploits. Re-check tooling first.
- **Copying published answers.** You train recall, not judgment. Struggle, then compare with a write-up, then redo it from scratch.
- **Skipping the "so what" question** on every finding — that question is what builds chains.

## Checklist / Self-Test

- [ ] I have a repeatable loop (orient → map → primitive → bypass → chain → record) and used it on the last three labs I solved.
- [ ] My notes for one full chain include a saved request/response pair for every link.
- [ ] I can reconstruct a solved chain backwards from impact to entry primitive and verify each link.
- [ ] I completed Drill 1–3 on authorized labs and recorded root-cause notes, not just payloads.
- [ ] I completed Drill 4–6 and can explain the detection signal before the impact for each.
- [ ] My chain ledger format (table + evidence ids) is ready to reuse in a report's attack narrative.

> **Verification:** the fence levels were checked on 2026-09-19 with a Python
> 3.12 script implementing the CommonMark fenced-code-block rules. Before the
> fix the outer fence closed at line 45, so `## Impact chain` (line 48) and
> `## Suggested fix` (line 51) rendered as real H2 sections, and the fence
> reopened at line 56 stayed open to the end of the file, swallowing the rest of
> the document as code. With the template fence raised to four backticks the
> block spans lines 27-56 and no section heading leaks out. The repo's own
> `check-links.mjs` and `check-catalog.mjs` were re-run after the change and
> still pass.

## Further Resources

- PortSwigger Web Security Academy (authorized multi-stage labs) — https://portswigger.net/web-security
- PortSwigger Research (smuggling/desync and chain write-ups) — https://portswigger.net/research
- OWASP Web Security Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
- OWASP Cheat Sheet Series — https://cheatsheetseries.owasp.org/
