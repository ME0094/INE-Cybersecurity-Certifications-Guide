# Advanced Web Techniques — Quick Reference

> eWPTX · Cheatsheets — INE-Cybersecurity-Certifications-Guide (English)
>
> Compact recall aid for technique families. Test only authorized targets. "→" means *then try*.

## JWT attack vectors

Attacks target the **header**, the **signature verification**, or the **claims**:

- `alg: none` — some libraries accept unsigned tokens. Remove the signature or set signature to empty.
- **Algorithm confusion (RS256 → HS256)** — if the server verifies with a public key but you can force HMAC, sign with the public key bytes as the HMAC secret.
- **Weak HMAC secret** — brute-force with `hashcat -m 16500` or `jwt_tool`.
- **Header injection (`kid`, `jku`, `x5u`)** — attacker-controlled key location: `kid` pointing at a file (e.g., `../../dev/null` → empty secret), or `jku`/`x5u` hosting your JWKS. Also test `kid` for SQLi/path traversal.
- **Inline `jwk`** — some verifiers accept a key embedded in the token header.
- **Claim tampering** — flip `role`/`admin`/`sub` when the server forgets to verify the signature.
- **Signature stripping / trailing data** — malformed signatures or duplicate headers can bypass naive parsing.
- **Algorithm downgrade** — reject strong algorithms, accept weaker ones (HS256 after RS256 was expected).
- **Oracle via error/timing** — different messages for expired vs invalid signature reveal verification order.

```text
header: {"alg":"none","typ":"JWT"}  + empty signature (remove trailing dot segment content)
confusion: header {"alg":"HS256"}   + sign(header.payload, public_key_pem_bytes, "HS256")
kid trick: {"kid":"../../dev/null"} + HS256 with empty secret
```

Check order: is the signature verified at all? → which algorithms are accepted? → where does the key come from? → are claims trusted after verification?

## OAuth misconfigurations

Logic flaws in delegated authorization (RFC 6749 / OIDC), in rough order of likelihood:

- **Missing or guessable `state`** → login CSRF (attacker initiates, victim authenticates, attacker reuses the code).
- **`redirect_uri` validation bypass** — open-redirect hosts, subdomain takeover targets, path/dir tricks (`/callback/..`), whitespace/encoding, wildcard or prefix matching.
- **Public client without `client_secret`** or a secret the server never checks at the token endpoint.
- **Authorization code leakage** — code in the URL, forwarded via `Referer`, or logged by an open redirect at the callback.
- **Scope escalation** — request a higher scope than granted; swap a low-scope code into a high-scope token request (confused deputy).
- **Implicit grant abuse** — token in the fragment leaks via redirect chains; `token` in query → lands in logs.
- **Missing `iss`/audience checks** → mix-up between authorization servers.

```text
test checklist per endpoint:
[ ] state present + bound to the session?   [ ] redirect_uri strictly validated?
[ ] client_secret enforced?                 [ ] scope fixed per client?
[ ] code single-use + bound to client?      [ ] iss/aud verified?
```

Flow to test: browser authorization → callback capture → token exchange → protected resource, verifying each transition's checks.

## WAF bypass — encoding families

Bypasses exploit the difference between what the **WAF parses** and what the **backend parses**. Families to cycle through (test each against a live oracle):

- **URL encoding** — single, double, overlong UTF-8 (`%2527`, `%c0%ae`).
- **Case & comments** — mixed case; SQL comments `/**/`, `/*!50000*/`; `sel/**/ect`, `<scr<script>ipt>`.
- **Whitespace variants** — tab, newline, vertical tab, form feed instead of space.
- **Unicode & normalization** — full-width characters, homoglyphs, unicode escapes (`\u002f` in JSON contexts).
- **HTML entities** — for reflected/JS contexts: `&#x27;`, `&#39;`, `&Tab;`.
- **Null byte & charset confusion** — legacy stacks truncate at `%00`.
- **Alternate syntax** — JSON/XML bodies, multipart, gzip bodies; unicode escapes inside JSON keys.
- **Protocol-level splitting** — chunked encoding, CL/TE confusion (see smuggling) to hide payloads from the WAF.
- **Parameter pollution** — split the payload so the WAF sees one value and the backend another (see below).

```text
?q=1' OR '1'='1        → baseline
?q=1%27%20OR%201%3D1   → encoding
?q=1'/**/OR/**/'1'='1  → comments
?q=1'%09OR%09'1'='1    → whitespace
```

For each family, ask: does the backend decode more than once? Which parser (WAF/backend) sees the final value?

## Request smuggling — detection hints

Smuggling/desync happens when a **front-end proxy** and a **back-end server** disagree about a request's boundaries. Classes: **CL.TE** (front end uses Content-Length, back end uses Transfer-Encoding), **TE.CL** (the reverse), **TE.TE** (obfuscated Transfer-Encoding defeats one parser).

Detection hints:

- Responses you never asked for; a valid path returns a 404/400 that belongs to a *previous* request.
- Two requests sent on one connection where the second gets the answer to the first (desync signature).
- Cache poisoning of static pages with attacker content (front-end request swallowed and replayed).
- Timing differences: a request with a body that is valid to one parser and "extra" to the other produces a delay or an orphaned error.
- Headers to inspect: both `Content-Length` **and** `Transfer-Encoding` present; `Transfer-Encoding` with odd casing/spacing (`Transfer-Encoding : chunked`, `Transfer-Encoding: xchunked`).

```text
CL.TE probe (one TCP connection, send back-to-back):
POST / HTTP/1.1
Host: target
Content-Length: 4
Transfer-Encoding: chunked

1
A
X

If the second response is odd/404, parsers disagreed — investigate further.
```

Hints: work on HTTP/1.1 keep-alive connections only; test each front-end path; confirm with a benign marker (`X`) before any malicious body. Authorized labs only — smuggling probes are easy to misfire against shared infrastructure.

## SSRF → internal patterns

Turning a URL-fetch input into internal reach, in escalation order:

- **Localhost filter bypasses** — IP notations: decimal/hex/octal (`2130706433`, `0x7f000001`), IPv6 (`::1`, `[::ffff:127.0.0.1]`), short forms, trailing dots, embedded credentials, `localhost` variants with encodings.
- **Redirect-based bypass** — allowlist passes `https://trusted.example/` but the server follows a 302 to `http://169.254.169.254/...`; chain an open redirect you control.
- **DNS tricks** — your own domain resolving to `127.0.0.1`; DNS rebinding against allowlists.
- **Cloud metadata** — `http://169.254.169.254/latest/meta-data/` (AWS) and equivalents; note IMDSv2 requires a token header — some fetchers let you set it.
- **Internal discovery** — once internal fetches work: brute common ports (`127.0.0.1:8080`, admin panels), read timing/content-length as a port oracle, use `file://` for local files when the fetcher supports it.
- **Protocol smuggling** — `gopher://`/`dict://` to speak raw protocols to internal services (Redis, SMTP, memcached) when the fetcher allows non-HTTP schemes.
- **Blind SSRF** — no response body: confirm with an out-of-band listener (Collaborator/interactsh) and pivot by timing.

```text
bypass ladder for http://127.0.0.1/admin
  127.0.0.1 → 2130706433 → 0x7f000001 → ::1 → [::ffff:7f00:1]
  + URL-encode/redirect-following variants → DNS rebinding
```

Always ask: does the response come back to me (visible) or only reach the server (blind)? That decides the technique set.

## Parameter pollution (HPP / HPF)

Duplicate or crafted parameter names exploit **parser disagreement about the same name**.

- **Duplicate parameters** — WAF checks the first, backend uses the last (or vice versa), or the backend joins all values.
- **Array syntax** — `?id[]=1&id[]=2`; some stacks treat `id` as a list.
- **Semicolon separators** — ASP.NET-style `?id=1;id=2` or `?debug=false;debug=true`.
- **Name truncation/overlong keys** — parser cuts the key at a byte, changing which value wins.
- **Nested/JSON coercion** — a param interpreted as JSON on one layer, scalar on another.

```text
?role=user&role=admin          → WAF sees user, backend may see admin (last-wins)
?file=/etc/passwd&file=img.png → split across validation and use
?debug=false;debug=true        → ; as separator on ASP.NET stacks
```

Detect it: send duplicates, reflect both, and observe *which* value drives the decision; then test whether validation and use read different positions.

## Common Mistakes & Tips

- **Testing encoding bypasses without an oracle.** You need a visible difference (response, timing, out-of-band) to know a bypass worked; build the oracle first.
- **Stopping at the first primitive.** A JWT with `alg:none` or a reflected header is a start — chain it to the goal (see `labs/challenge-solutions.md`).
- **Forgetting request ordering in smuggling.** Desync tests are meaningless unless requests share one connection and arrive back-to-back.
- **Copying payloads without the class logic.** Know *which parser disagreement* each payload exploits; filters change, classes do not.
- **Testing SSRF against real cloud metadata** of systems you do not own. Authorized labs only.
- **Ignoring `state`/`iss`/single-use** when reading OAuth flows — the crypto is rarely the bug; the state machine is.

## Checklist / Self-Test

- [ ] I can enumerate six JWT vectors and explain the verification step each one attacks.
- [ ] I can list the OAuth `redirect_uri`/`state`/`client_secret` checks and the flaw each prevents.
- [ ] I can produce an encoding ladder (URL → double-encode → comments → whitespace) for one payload class.
- [ ] I can explain CL.TE vs TE.CL vs TE.TE and the two-request detection signal for each.
- [ ] I can name five localhost-filter bypasses and when redirect-following SSRF applies.
- [ ] I can explain last-wins vs first-wins parameter pollution with one example per parser behavior.
- [ ] I can reproduce this entire sheet's structure from memory (topic → vectors → detection → bypass).

## Further Resources

- OWASP Cheat Sheet Series — https://cheatsheetseries.owasp.org/
- PortSwigger Web Security Academy (JWT, OAuth, SSRF, smuggling topics with labs) — https://portswigger.net/web-security
- PortSwigger Research (HTTP desync/smuggling write-ups) — https://portswigger.net/research
- jwt.io (token debugging) — https://jwt.io
- OWASP Web Security Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
