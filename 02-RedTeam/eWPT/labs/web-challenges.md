# Web Challenges — Skill Drills by Methodology Phase

> eWPT · Labs — INE-Cybersecurity-Certifications-Guide

## Purpose

These drills turn the methodology notes into hands-on practice. Each drill
states an **objective**, the **tools** you should exercise, and the
**expected outcome** — evidence you produced, not a copied answer. The point is
to train the *process*: recon first, then a hypothesis, then a minimal proof,
then a write-up.

Run them against **authorized targets only**: your own DVWA instance
(see `labs/dvwa-setup.md`), OWASP Juice Shop, or the free labs of PortSwigger's
Web Security Academy. If a drill says "victim" or "second user", that means a
second account *you* created in your own lab.

Suggested drill format for every exercise:

1. Write the objective in one sentence.
2. Perform the steps while capturing evidence (Burp history, screenshots,
   request/response pairs).
3. State the finding and its impact in one or two sentences.
4. Write the remediation you would recommend.

## Phase 1 — Reconnaissance

Drills to map the application before touching any input.

- **Drill 1.1 — Fingerprint the stack.** Objective: identify web server,
  framework, and language versions of your lab. Steps: inspect response
  headers, error pages, and HTML comments; note cookies and their flags.
  Expected outcome: a one-line stack summary with the *evidence header* that
  revealed each component.
- **Drill 1.2 — Build the content map.** Objective: enumerate the app's
  pages, parameters, and forms without brute forcing. Steps: walk the site
  normally through Burp, review the site map, and note every distinct
  parameter name seen in requests. Expected outcome: a list of endpoints with
  their input parameters and methods (GET/POST).
- **Drill 1.3 — Directory fuzzing.** Objective: discover unlinked paths using
  a wordlist. Steps: run a small fuzz (Burp Intruder Sniper with a short
  wordlist, or a fuzzing script) against your lab's root; classify results by
  status code and response length. Expected outcome: 3–5 new paths found and a
  note on which HTTP statuses separated hits from misses.

## Phase 2 — Authentication

- **Drill 2.1 — Login as an oracle.** Objective: detect user enumeration.
  Steps: submit two logins — an existing username with a wrong password and a
  non-existent username — and diff the responses with Burp Comparer; repeat at
  two security levels. Expected outcome: a statement of whether the app leaks
  account existence, with the differing response shown as evidence.
- **Drill 2.2 — Password policy & guessing.** Objective: assess credential
  strength against your own accounts. Steps: build a small candidate list of
  common/default passwords in Intruder (Sniper on the password field) and
  throttle it through a resource pool. Expected outcome: a successful login on
  a weak account and a recommendation for password policy.
- **Drill 2.3 — Session handling.** Objective: verify what a session token
  protects and how logout behaves. Steps: log in, note the session cookie
  (flags, whether it changes), log out, and replay an old authenticated
  request in Repeater. Expected outcome: a verdict on session invalidation and
  cookie flags (HttpOnly, Secure, SameSite), with replayed-request responses
  as proof.
- **Drill 2.4 — Brute-force defenses.** Objective: check for rate limiting and
  lockout. Steps: send 20–30 rapid failed logins (throttled, low concurrency)
  and observe status codes and messages. Expected outcome: a note on whether
  the app throttles/locks out, and how you would bypass or respect that in a
  real engagement (hint: you would respect it).

## Phase 3 — Authorization / IDOR

- **Drill 3.1 — Object-level access.** Objective: test whether a resource is
  accessible with another user's identifier. Steps: log in as `alice`, capture
  a request that shows her profile or record by `id`; change the id to an
  object belonging to `bob` in Repeater; repeat at Medium/High. Expected
  outcome: a yes/no answer per level on horizontal access, with the two
  responses compared.
- **Drill 3.2 — Function-level access.** Objective: test whether a privileged
  action is protected. Steps: as a normal user, request an admin-only path
  directly (forced browsing) using a request captured from an admin session,
  but with your session cookie. Expected outcome: a verdict on broken access
  control, with status-code evidence for each role.
- **Drill 3.3 — Mass assignment / hidden fields.** Objective: find trust in
  client-supplied state. Steps: inspect forms for hidden fields (role, price,
  step) and try changing one to a privileged value. Expected outcome: either a
  confirmed privilege change or a note on how the field was validated
  server-side — both are valid findings for your notes.

## Phase 4 — Input validation: SQL injection & friends

- **Drill 4.1 — Manual SQLi proof.** Objective: prove injection with your
  eyes, not a tool. Steps: on the SQLi page at Low, submit `'` and observe the
  error; then craft a payload that changes the response predictably (e.g., a
  boolean condition that alters the row set); finally run the same exercise at
  Medium and note the defense. Expected outcome: a hand-written payload that
  works at each level and a one-line description of *why* it works.
- **Drill 4.2 — Extraction with sqlmap.** Objective: use automation after
  manual proof. Steps: capture the authenticated request in Burp, save it to a
  file, run sqlmap with `-r`; enumerate the database name, then dump one
  table. Expected outcome: the database schema summary and the dumped table
  contents stored under sqlmap's output folder.
- **Drill 4.3 — Reflected & stored XSS.** Objective: distinguish the two XSS
  types. Steps: reflect a payload into a page (Reflected XSS page), then store
  one and view it from a second browser profile/account (Stored XSS page).
  Expected outcome: two proofs — one where the payload executes only in your
  own response, one where it executes when *another* user opens the page —
  and a note on which is more severe and why.
- **Drill 4.4 — Command injection & path traversal.** Objective: reach the OS
  or filesystem through user input. Steps: on the Command Injection page,
  append a benign command (e.g., `whoami`) after the input separator; on a
  file-read style page, traverse with `../` sequences to read a known local
  file. Expected outcome: command output echoed in the response and the
  contents of one file outside the web root, each with the exact payload.

## Phase 5 — Business logic

- **Drill 5.1 — Workflow order.** Objective: test whether the app trusts step
  order. Steps: pick a multi-step flow in your lab (e.g., change password or
  a shopping-like flow) and replay an early step's request *after* the flow
  completed, or skip a step by requesting its URL directly. Expected outcome:
  a note on which state transitions the server enforced versus trusted the
  client for.
- **Drill 5.2 — Replay and tampering of client state.** Objective: change
  values the client controls. Steps: intercept the request that carries a
  price, quantity, or role field and alter it; observe whether the server
  recomputes or trusts it. Expected outcome: a verdict per field on
  server-side validation, with before/after responses as evidence.
- **Drill 5.3 — Race condition check (optional).** Objective: observe whether
  a limited action (coupon, balance transfer, vote) tolerates concurrent use.
  Steps: send two identical requests back-to-back (two Repeater tabs or a
  scripted burst) and inspect whether the resource was consumed once or twice.
  Expected outcome: a careful, load-conscious note on whether a TOCTOU-style
  condition is present.

## Common Mistakes & Tips

- **Skipping recon** → you test endpoints blind and mislabel findings. Map the
  app first; drills get faster, not slower.
- **Not isolating users** → stored XSS and IDOR drills need *two* real
  sessions. Use two browser profiles or an incognito window against your own
  accounts.
- **Dumping whole tables when a row would do** → respect the target: dump
  only what answers the question, especially outside pure labs.
- **No evidence trail** → a finding without a saved request/response is not
  verifiable. Save Burp items and screenshots as you go.
- **Copying walkthroughs** → you train someone else's reflexes. If a payload
  from a blog works, rebuild it from first principles afterwards and explain
  each token.
- **Ignoring the security level's source code** → DVWA shows you the defense;
  reading it is the fastest way to learn why a bypass works.
- Tip: after each drill, write 3–4 lines as if for a client report
  (summary, evidence, impact, remediation) — that writing habit is half the
  value of the lab.
- Tip: repeat each drill at the next DVWA security level once you finish the
  current one; the methodology stays identical, the defenses change.

## Checklist / Self-Test

- [ ] I mapped my lab's endpoints and parameters before exploiting anything.
- [ ] I proved one SQL injection manually and only then used sqlmap.
- [ ] I dumped a single table (not the whole database) as evidence.
- [ ] I demonstrated stored XSS that fired for a second user session.
- [ ] I tested an object-level access issue with two of my own accounts.
- [ ] I tested at least one privileged path with a normal-user session.
- [ ] I attempted one business-logic tamper and recorded the server's response.
- [ ] Every drill above ended with a short written finding + remediation.

---

## Further Resources

- PortSwigger Web Security Academy — free labs for every phase — <https://portswigger.net/web-security>
- OWASP Juice Shop (another authorized practice target) — <https://owasp.org/www-project-juice-shop/>
- OWASP Web Security Testing Guide (drill methodology source) — <https://owasp.org/www-project-web-security-testing-guide/>
- DVWA source walkthroughs and docs — <https://github.com/digininja/DVWA>
