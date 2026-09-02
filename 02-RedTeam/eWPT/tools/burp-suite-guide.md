# Burp Suite Guide

> eWPT · Tools — INE-Cybersecurity-Certifications-Guide

## Purpose

Burp Suite is the de-facto standard **intercepting proxy** for web application
security testing. This guide covers the core workflow every web pentester must
master: proxying browser traffic, intercepting and editing requests, scoping
the target, automating payload delivery with Intruder, decoding data, and
extending Burp with community extensions. Use it alongside the methodology
files whenever a phase needs request manipulation.

Editions at a glance:

- **Community** — free; proxy, Repeater, Intruder (rate-limited), Decoder,
  Comparer, and the BApp extension store. No automated active scanner.
- **Professional** — adds the automated scanner, saved projects, and
  unthrottled Intruder.
- **Enterprise** — CI/CD-oriented scanning platform, not needed for this
  module.

All examples below work in Community Edition unless stated otherwise.

## 1. Proxy setup and TLS interception

Burp runs a local HTTP proxy that sits between your browser and the target.

1. Start Burp and create a **Temporary project** (Community).
2. Go to **Settings → Tools → Proxy → Proxy listeners**; confirm a listener on
   `127.0.0.1:8080`.
3. Point your browser at that proxy. With a browser profile that supports
   proxy configuration (or an extension such as FoxyProxy), set HTTP and HTTPS
   proxy to `127.0.0.1`, port `8080`.
4. Browse to `http://burp` and download the **CA certificate** (`CA
   Certificate` button). Install it in your browser's **trusted root
   authorities** store. This lets Burp decrypt TLS.
5. In Burp's **Proxy → Intercept** tab, toggle **Intercept is on/off**. When
   on, each request pauses for review and editing; when off, traffic flows
   through and is logged in **HTTP history**.

Verification: after installing the CA, load an HTTPS site and confirm Burp's
HTTP history shows decrypted requests with no certificate warnings in the
browser.

```text
Browser ──HTTPS──▶ Burp (127.0.0.1:8080) ──▶ Internet / target
                   ▲ decrypts TLS, logs, lets you edit
```

## 2. Target scope

Scope keeps your testing focused and prevents accidental requests outside the
engagement boundary.

1. Open the **Target → Scope** tab.
2. Add the root of the authorized target, e.g. `http://dvwa.local/`.
3. Optionally configure **Settings → Project → Scope** so out-of-scope
   requests are not logged, or at least enable **"Hide out-of-scope items"** in
   the HTTP history filter.
4. When only in-scope traffic matters, enable **"Use advanced scope
   control"** options that apply to Repeater/Intruder as you prefer.

Keep the scope narrow: an engagement targets a defined host and path set, not
the whole Internet.

## 3. Repeater

Repeater lets you take any captured request, modify it by hand, and send it
repeatedly to observe how the server responds. It is the primary manual
testing workbench.

- Send a request to Repeater from HTTP history (right-click → **Send to
  Repeater**, `Ctrl+R`) or from Proxy intercept.
- Edit any part of the request line, headers, or body. Watch the raw request
  and response panes, plus the rendered view.
- Right-click the request → **Change request method** to flip between GET and
  POST, useful for parameter smuggling checks.
- Use the **\#** tab to number requests and the colored response status to
  tell successful requests apart at a glance.

Typical Repeater tasks: changing a parameter value to probe for SQLi, altering
a cookie or header to test access control, and replaying a request with a
different `User-Agent` to see if the response changes.

## 4. Intruder

Intruder automates sending the same request many times with **payloads**
substituted at marked **positions**.

### Positions

Mark injection points with `§` around the text to fuzz, for example a `id`
parameter:

```http
GET /profile.php?id=§1§ HTTP/1.1
Host: dvwa.local
```

Attack types define how multiple position sets combine:

- **Sniper** — one position, one payload list at a time (most common).
- **Battering ram** — same payload inserted into all positions.
- **Pitchfork** — parallel payload lists, one per position (same row).
- **Cluster bomb** — every combination of all lists (use sparingly; it is
  combinatorially explosive).

### Payload types

- **Simple list** — load a wordlist or paste values.
- **Numbers** — sequential numeric ranges (useful for IDOR scans).
- **Brute forcer** — character-set permutations.
- **Custom iterator** — position-wise combination of character sets.
- **Payload processing rules** — encode, hash, or prefix/suffix values before
  sending (e.g., URL-encode, Base64).

### Resource pool and rate control

Intruder can hammer a server; be a good citizen:

- Create a **Resource pool** (Settings → Resource pools) and cap **maximum
  concurrent requests** (e.g., 1–5).
- Add a **delay between requests** (e.g., 500–1000 ms) when testing against
  rate-sensitive or production-adjacent targets.
- Professional users can throttle to a target requests-per-second; Community
  Edition already rate-limits Intruder.

### Reading results

Sort by status code, length, or a grep match rule you add (e.g.,
`Welcome, admin` vs `Access denied`). Length outliers usually point to a
successful injection; identical lengths usually mean identical outcomes.

## 5. Decoder and Comparer

- **Decoder** converts between encodings (URL, HTML, Base64, hex) and computes
  hashes. Use **Smart decode** to unwrap layered encodings — a common pattern
  in bypassing filters.
- **Comparer** diffs two requests or responses. Classic use: capture the
  response for a *correct* password and an *incorrect* one, then compare —
  differences help you script a login oracle, spot error-based SQLi, or detect
  user enumeration from login messages.

## 6. Scanner basics

The automated scanner is a **Professional** feature; Community users perform
the same checks manually.

- **Crawl** first: follow links and forms to build a site map
  (**Target → Site map**).
- Run **active scans** only on in-scope, authorized hosts. Configure scan
  settings to choose which insertion points and checks run.
- Always **verify scanner findings manually** in Repeater: automated tools
  produce false positives, and a real finding needs a proof-of-concept request
  and a clear impact statement.
- Treat the scanner as a complement to manual testing, never a replacement.
  Business logic and multi-step authorization flaws are invisible to scanners.

## 7. Key extensions

The **BApp Store** (Extensions → BApp store) hosts community extensions.
Examples relevant to web testing:

- **Authorize** — replays every request you proxy with a second session's
  cookies, highlighting responses that differ. Excellent for spotting
  **horizontal/vertical privilege escalation** and forced browsing: capture an
  admin session and a normal-user session, then browse as the normal user and
  watch which admin-only requests succeed.
- **Logger++** — advanced traffic logging with filters, useful for
  correlating requests and responses during complex tests.
- **Copy as requests / Copy as cURL** style helpers — export requests to code
  for scripts.
- **Hackvertor / Hackvertor tags** — nested encoding at runtime inside
  payloads.
- **Turbo Intruder** — high-speed, scriptable brute forcing for specialized
  cases (be very careful with load).

Install only extensions you understand and need; extensions run with your
permissions and can send traffic.

## Common mistakes & tips

- **Forgetting the CA certificate** → HTTPS sites fail or show warnings. Install
  the Burp CA into the browser's trusted store once per browser profile.
- **Proxying all system traffic** → you intercept and log out-of-scope noise.
  Use a dedicated browser profile and strict scope.
- **Intercept left on** → the browser hangs on every request. Toggle intercept
  off for routine browsing.
- **Intruder with no throttle against fragile labs** → resource exhaustion or
  WAF lockout. Use a resource pool with low concurrency.
- **Sniper vs Cluster bomb confusion** → wrong attack type silently tests the
  wrong combinations; re-read section 4 before big runs.
- **Trusting scanner output** → every automated finding must be confirmed
  manually and paired with evidence before it counts.
- Tip: name Repeater tabs and Intruder attacks by test case; after dozens of
  probes you will not remember what tab 47 was for.
- Tip: use the **Search** box in HTTP history to find requests containing a
  parameter or payload string across the whole session.

## Checklist / Self-test

- [ ] Browser traffic flows through Burp and HTTPS is decrypted without
      certificate warnings.
- [ ] I can toggle intercept, edit a request on the fly, and forward it.
- [ ] Scope is configured and out-of-scope items are hidden from history.
- [ ] I replayed a modified request in Repeater and compared responses.
- [ ] I ran a Sniper attack with a numbers payload and explained the results.
- [ ] I decoded a Base64/URL-encoded value with Decoder's smart decode.
- [ ] I used Comparer to spot the difference between two responses.
- [ ] I installed the Authorize extension and described its use case.

---

## Further resources

- PortSwigger Burp Suite documentation — <https://portswigger.net/burp/documentation>
- PortSwigger BApp Store — <https://portswigger.net/bappstore>
- PortSwigger Web Security Academy (free hands-on labs) — <https://portswigger.net/web-security>
- OWASP Web Security Testing Guide — <https://owasp.org/www-project-web-security-testing-guide/>
