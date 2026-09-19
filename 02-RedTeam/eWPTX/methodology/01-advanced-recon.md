# Advanced Recon — eWPTX Methodology Phase 1

> eWPTX study guide · Advanced web methodology — INE-Cybersecurity-Certifications-Guide

At eWPTX level, "recon" is no longer "which ports are open." The target is a
modern web stack: a JavaScript single-page application (SPA) talking to REST
or GraphQL APIs, fronted by a CDN and a WAF, with several subdomains and
virtual hosts. This phase is about **reconstructing the application from the
outside** — client-side code, API contracts, host routing, and protective
layers — until you can describe every reachable attack surface and rank where
to dig first.

## Phase goals

- Enumerate **subdomains and virtual hosts** to expand the attack surface.
- Map the **SPA** and its **API** (routes, parameters, auth requirements).
- Analyze **client-side JavaScript** for endpoints, secrets, and logic clues.
- Fingerprint **WAF/CDN** layers so you know what you will have to bypass.
- Hunt **exposed files**: source maps, `.git`, backups, Swagger/OpenAPI docs.
- Produce an **attack-surface document** that drives the remaining phases.

Work from an **authorized target only** (scope you own, a lab, or a signed
engagement) and respect rate limits while scanning.

## Subdomain and virtual-host discovery

```bash
# Passive: certificate transparency — great first source
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Brute force with a quality wordlist (tune -t for politeness)
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

# Resolve what you found and confirm which are in scope
for h in $(cat subs.txt); do host "$h.example.com" | grep "has address"; done
```

Then check **virtual hosts**: many targets answer with different apps on the
same IP depending on the `Host` header. `gobuster vhost` fuzzes this:

```bash
# Compare every Host to the default; flag responses that differ in size/status
gobuster vhost -u http://example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

When a vhost answers, add it to `/etc/hosts` (or use Burp's Host-header
rewrite) so cookies, redirects, and TLS SNI behave correctly. Correlate: two
subdomains may be the **same app** (deduplicate) or distinct apps with
different security postures (each needs its own mapping).

## Mapping SPAs and their APIs

Modern apps are thin clients: almost all functionality lives behind JSON
endpoints. Watch the network waterfall while you click, then extend it:

1. Browse with Burp (or your proxy) and let the SPA load; capture XHR/fetch
   traffic. Every request is a documented API call.
2. Use the app's **JavaScript** as a route map (see next section).
3. Crawl the API by hand: change IDs, HTTP methods, and content types on
   observed endpoints; follow `Link` headers and pagination fields.
4. For GraphQL, probe the schema (see exposed files below) and enumerate
   queries/mutations from the introspection response.

Capture the contract per endpoint in notes:

```text
POST /api/v2/orders            JSON {user_id, items[]}   auth: Bearer JWT
GET  /api/v2/orders/{id}       returns order + PII        auth: JWT (IDOR test)
GET  /api/v2/internal/health   no auth observed           -> SSRF/ACL test
POST /graphql                  introspection: ON          -> schema dump
```

Look for **parallel APIs** (an old `/v1` left alive, an internal admin API on
a different host) — they are classic sources of high-severity findings.

## Client-side JavaScript analysis

The SPA ships its routing, endpoints, and often hard-coded values to you.
Collect JS, beautify it, and grep for signals:

```bash
# Grab all <script src> targets from the page (also do this inside the browser
# after dynamic modules load)
curl -s https://app.example.com/ | grep -oE 'src="[^"]+\.js[^"]*"' | cut -d'"' -f2

# Download and search each bundle
mkdir -p js && for u in $(cat js_urls.txt); do curl -s "$u" -o "js/$(basename $u)"; done
grep -rniE 'api[_-]?key|secret|token|password|aws|firebase|Authorization' js/

# Pretty-print minified bundles before reading them
npx js-beautify js/main.*.js > js/main.pretty.js
```

Things that matter in JS review:

- **API base URLs** and relative paths (`/api/`, `/graphql`, `/internal/`).
- **Hard-coded secrets** (API keys, Firebase config, OAuth client secrets,
  Stripe publishable vs. secret keys) — publishable keys are normal; private
  keys and service accounts are findings.
- **Client-side role/flag checks** (`if (user.role === 'admin')`) that reveal
  what the server must actually enforce.
- **Source maps**: if `//# sourceMappingURL=app.js.map` is present you can
  often download the original, unobfuscated source.

```bash
# Source map recovery (great payoff, low effort)
curl -s https://app.example.com/js/app.js.map -o app.js.map
npx source-map-visualizer 2>/dev/null || python3 - <<'EOF'
import json
m = json.load(open('app.js.map'))
for s in m.get('sources', []): print(s)
EOF
```

If the source map is blocked, use a deobfuscator and **runtime inspection**
(breakpoints, console) instead — the code still runs in your browser.

## WAF and CDN fingerprinting

Know what sits in front of the origin before you attack: it changes how you
send payloads and whether you need bypasses (see methodology phase 3).

```bash
# Inspect headers and TLS
curl -sI https://example.com/
# Typical fingerprints:
#   Cloudflare:  server: cloudflare, cf-ray, cf-cache-status
#   AWS WAF/CloudFront: x-cache, x-amz-cf-id, Via
#   Akamai:      server: AkamaiGHost, x-akamai-*
#   Incapsula/Imperva: x-iinfo, X-CDN: Incapsula
#   ModSecurity: no banner, but 403 body may mention "ModSecurity"

# Find the real origin behind the CDN (for research/lab targets; be careful:
# bypassing the CDN is often out of scope in real engagements)
dig +short example.com A
dig +short example.com CNAME
# Look for direct IPs: subdomain A-records, MX/SPF records, old DNS history
```

Test WAF behavior safely with a single benign-but-suspicious request, e.g.
`curl 'https://example.com/?q=<script>'` and observe status/body differences
versus a clean request. Record: blocked patterns, response codes used for
blocks (403 vs 406 vs 200-with-captcha), and whether blocks are IP-based or
header-based. This becomes your bypass planning input.

## Exposed files and metadata

Automated scanners miss most of these; check them deliberately:

```bash
# Common exposed paths (respect scope and rate limits)
for p in .git/config .git/HEAD .env .env.bak backup.zip db.sql config.php.bak
         swagger.json openapi.json api-docs graphql .well-known/security.txt
         server-status server-info wp-config.php.bak; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://example.com/$p")
  echo "$code  /$p"
done
```

Interpretation and follow-ups:

- **`.git/` exposed**: `git-dumper` the repository and run `git log -p` —
  commits often contain credentials and older, vulnerable code. Rate it
  **high** — the same level `tools/custom-scripts/advanced-scanner.py` assigns to
  an accessible `.git/config`.
- **Backups** (`.bak`, `~`, `.zip`, `.sql`, `.tar.gz`, `%7e` dotfiles):
  download and grep for secrets; a DB dump is a critical finding.
- **Swagger/OpenAPI** (`/swagger-ui.html`, `/v2/api-docs`, `/openapi.json`):
  gives you a full endpoint + parameter catalogue. For GraphQL, try
  `?query={__typename}` and introspection:

```http
POST /graphql HTTP/1.1
Host: example.com
Content-Type: application/json

{"query":"query{__schema{types{name fields{name}}}}"}
```

- **`.well-known/`**: `security.txt`, `openid-configuration`, `jwks.json`,
  `assetlinks.json` — reveals federation and OAuth endpoints (feeds phase 4).
- **robots.txt / sitemap.xml**: still useful; compare with what the crawler
  found to spot disallowed admin paths. Their Exposure alone is **low** (the
  scanner's `paths` check rates them there) — a route list, not a leak.

## Documenting the attack surface

Before exploitation, consolidate into a living document (one per host/app):

```text
App:         store.example.com (vhost confirmed; origin IP known)
Stack:       React SPA -> API Gateway -> Node/Express; GraphQL present
Front line:  Cloudflare (WAF on, rate limit 10 req/min per IP)
Auth:        OIDC via /auth (PKCE), JWT in localStorage, 2FA optional
Endpoints:   23 REST + GraphQL; /api/v1 legacy still reachable
Exposed:     /api/v1/swagger.json (readable, info), .git on admin.store.* (high)
Secrets:     Firebase config w/ public keys only (low)
Candidate issues: legacy v1 ACL, GraphQL introspection, IDOR on orders
Next:        phase 2 chaining — v1 IDOR -> admin token in .git history
```

Rules that keep the document honest: record **evidence** (status codes,
response excerpts, request IDs) next to every claim; mark hosts **in scope /
out of scope**; and update the surface map whenever a new endpoint or vhost
appears — exploitation phases are only as good as this map.

## Common Mistakes & Tips

- **Trusting a single DNS source.** Cross crt.sh, brute force, and search
  engines; each misses different subdomains. Also check IPv6 (`AAAA`) — many
  labs only filter IPv4.
- **Skipping vhost fuzzing.** Two different apps on one IP is the norm in
  shared hosting and labs; a Host-header check takes seconds.
- **Only crawling rendered HTML.** SPA functionality lives in JS and XHR —
  crawl with a real browser and watch the network tab.
- **Reading minified JS raw.** Beautify first; and remember dynamic
  `import()` loads more modules only after user actions.
- **Treating CDN/WAF fingerprints as facts.** Headers can be spoofed; confirm
  behavior (blocking) before planning bypasses.
- **Ignoring low-hanging exposed files.** `.git` and Swagger often unlock
  more than any 0-day; check them before deep exploitation.
- **Polluting notes.** One host per block, evidence attached, scope marked.
  Recon without notes does not feed the report.

## Checklist / Self-Test

- [ ] I enumerated subdomains (passive + brute force) and virtual hosts on
      every discovered IP.
- [ ] I mapped SPA endpoints from real XHR/fetch traffic and from JS analysis,
      not only from rendered HTML.
- [ ] I downloaded and beautified the app's JS bundles and searched them for
      endpoints, secrets, and auth logic.
- [ ] I checked for source maps and attempted original-source recovery.
- [ ] I fingerprinted the WAF/CDN (headers, TLS, block behavior) and noted it
      in the surface document.
- [ ] I probed exposed files: `.git`, backups, `.env`, Swagger/OpenAPI, and
      GraphQL introspection.
- [ ] I can explain the difference between a CDN edge and the origin, and why
      the origin matters.
- [ ] I maintain one up-to-date attack-surface document per host with
      evidence, scope markings, and candidate next steps.

> **Verification:** the severity levels quoted here were taken from a run of
> `02-RedTeam/eWPTX/tools/custom-scripts/advanced-scanner.py` on 2026-09-19
> (Python 3.12.3) against a local server exposing `/.git/config` (200),
> `robots.txt` (200) and a reflected `Access-Control-Allow-Origin`: `.git/config`
> is reported `high`, `robots.txt`/`sitemap.xml` `low`, and everything else
> `info`. The recon commands in this file were not run — no authorized target was
> available in this lab, so they remain documentation-primary.

## Further Resources

- OWASP Web Security Testing Guide — information gathering and configuration
  testing: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Research — client-side and API research blog:
  https://portswigger.net/research
- PortSwigger Web Security Academy — API testing and client-side labs:
  https://portswigger.net/web-security
- OWASP SecLists wordlists (DNS, discovery): https://github.com/danielmiessler/SecLists
- crt.sh certificate transparency search: https://crt.sh/
- RFC 9110 (HTTP semantics, incl. Host header): https://www.rfc-editor.org/rfc/rfc9110
