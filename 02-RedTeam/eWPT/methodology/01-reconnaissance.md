# eWPT Methodology — Phase 01: Reconnaissance

> Web Application Penetration Testing · INE-Cybersecurity-Certifications-Guide

Reconnaissance is the foundation of every web application test. Before touching a single parameter, you must understand **what** the application is, **where** its attack surface sits, and **how** it is built. Only work against applications you are explicitly authorized to test (your own lab, a client with a signed scope document, or a training platform such as PortSwigger Web Security Academy).

## Scope Review

Start by writing down exactly what you may and may not test. Scope errors are the fastest way to turn a pentest into an incident.

- Record the in-scope root URLs (for example `https://app.example.com` and `https://api.example.com`), plus explicit out-of-scope items (third parties, payment gateways, admin panels owned by another team).
- Note authorization levels: are you allowed to register accounts, create content, upload files, or trigger destructive actions? If not, plan read-only checks.
- Identify legal and safe limits: rate, volume, and timing constraints for brute force or fuzzing.
- Keep an engagement file with: client, dates, scope list, rules of engagement, and credentials provided.

```bash
# Save the scope to a file that every later tool reads from
cat > scope.txt <<'EOF'
https://app.example.com
https://api.example.com
https://old.app.example.com
EOF
```

> Golden rule: if a host is not in scope, do not touch it. Redirects, CDNs, and third-party trackers often leave the scope without you noticing.

## Mapping the Application

Mapping answers the question "what pages and functions exist?" The goal is a complete inventory of endpoints, not just the homepage.

### Crawling and spidering

Start passive and stay gentle, then move to active crawling:

- **Passive:** browse with a proxy (Burp Suite, OWASP ZAP) and record everything you click plus everything the server sends.
- **Active:** let a crawler/spider follow links, parse forms, and read JavaScript to discover additional routes.

```bash
# ZAP quick scan-style crawl (authorized target only)
zap-cli spider -r https://app.example.com

# Burp Suite: right-click the target > Engagement tools > "Discover content"
# or use the built-in Spider/Crawler from the Site Map tab
```

### Sitemaps and robots.txt

These files exist to help search engines, but they leak paths to testers too.

```bash
curl -s https://app.example.com/robots.txt        # look for Disallow entries
curl -s https://app.example.com/sitemap.xml        # often lists deep, linked URLs
curl -s https://app.example.com/sitemap_index.xml  # aggregated sitemap (common in CMS)
```

Check the security-relevant side of these files:

- `robots.txt` may reference admin, backup, staging, or hidden upload paths.
- `sitemap.xml` may expose pages that are not linked from the UI (orphan pages).
- A `sitemap.xml` listing a `search` or `download` endpoint is a hint to test parameters there.

### Client-side mapping

Modern single-page applications (React, Vue, Angular) build the route map in JavaScript. Look at the bundles:

- In Burp, review the "JS files" scope tab and hunt for API endpoints, `/api/...` strings, and hardcoded keys.
- Use browser DevTools: **Sources** panel, or **Network** tab while exercising the UI.

```bash
# Download and grep every JavaScript file for interesting strings
curl -s https://app.example.com/assets/app.js -o app.js
grep -oE '"/api/[a-zA-Z0-9/_-]+"' app.js | sort -u
grep -oE '(api[_-]?key|token|secret)["'"'"']?\s*[:=]' app.js
```

## Technology Fingerprinting

Knowing the stack tells you which vulnerabilities to prioritize and which payloads will work. Fingerprint at several layers:

### HTTP headers and server banner

```bash
curl -sI https://app.example.com
# Look at: Server, X-Powered-By, Set-Cookie, Strict-Transport-Security,
# Content-Security-Policy, X-Frame-Options, X-AspNet-Version
```

- `Server: nginx`, `Server: Apache/2.4.41` → web server and possible version.
- `X-Powered-By: PHP/7.4` or `X-AspNet-Version: 4.0.30319` → runtime language.
- `Set-Cookie: JSESSIONID`, `PHPSESSID`, `ASP.NET_SessionId` → session mechanism.
- Missing security headers is itself a finding worth noting (not a critical one).

### Framework and CMS detection

```bash
# WhatWeb combines many signatures into one pass
whatweb https://app.example.com

# Wappalyzer (browser extension) also fingerprints while you browse
nmap --script http-headers -p 80,443 app.example.com   # optional, from an authorized host
```

Check typical fingerprints by hand too:

- WordPress: `/wp-login.php`, `/wp-content/`, `generator` meta tag.
- Joomla, Drupal, Laravel, Rails, Django, Spring: distinctive cookie names, headers (`X-Frame-Options` default values), and default paths (`/administration`, `/admin`, `/console`).
- Versioned assets (`/static/js/main.a1b2c3.js`) can reveal a framework build.

## Content Discovery

Crawling finds what is linked; content discovery finds what is **not** linked: admin panels, backup files, source archives, `.git` folders, developer endpoints.

### Pick a good wordlist

- `/usr/share/seclists/Discovery/Web-Content/` from SecLists is the standard source.
- Use `raft-large-directories.txt` or `raft-medium-directories.txt` for general paths.
- For technology-specific discovery, use
  `Programming-Language-Specific/CommonBackdoors-PHP.fuzz.txt` (the other languages ship their
  own file in that same subfolder) or CMS lists such as `CMS/wp-themes.fuzz.txt` and
  `CMS/Drupal.txt`.

### Fuzzing with ffuf or gobuster

```bash
# ffuf: fast, flexible, matches on status codes or content length
ffuf -u https://app.example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -mc 200,204,301,302,307,401,403 -c -t 50

# ffuf with extension fuzzing (catches file backups)
ffuf -u https://app.example.com/FUZZ -w raft-medium-files.txt \
     -mc 200 -e .bak,.old,.txt,.php,.zip,.tar.gz

# gobuster: simple directory brute force
gobuster dir -u https://app.example.com -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -t 40 -x php,txt,bak,zip
```

Interpret results carefully:

- `301`/`302` redirects can point to login pages or dead ends — follow them before reporting.
- A wall of `403` responses often means a WAF blocks everything; try a different user-agent or lower rate first.
- Filter noise by content length with `-fs` (ffuf) or `--exclude-length` (gobuster) when the site returns a common "not found" body with HTTP 200.

### Common high-value hits

```
/admin            /administrator     /api              /swagger
/.git/HEAD        /.env             /backup/          /config.php.bak
/server-status    /phpinfo.php      /actuator         /graphql
/console          /debug            /uploads/         /vendor/
```

## API Discovery

Many tests fail because the tester only exercises the HTML UI while the real logic lives behind an API. Find and map APIs early.

- Search JavaScript bundles for `/api/`, `/v1/`, `/graphql`, `/swagger`, `/openapi.json`.
- Try documented endpoints: `/swagger-ui.html`, `/swagger/index.html`, `/api-docs`, `/openapi.json`, `/v2/api-docs` (Springfox), `/graphql` with an introspection query.
- Look for versioned APIs (`/api/v1/users`, `/api/v2/users`) — old versions often lack the security fixes of new ones.
- Once you see an API response, replay requests and inspect JSON fields for object IDs, roles, or tokens (material for Phases 03–04).

```bash
# Probe common API documentation paths
for p in swagger-ui.html openapi.json api-docs v2/api-docs graphql; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://app.example.com/$p")
  echo "$p -> $code"
done

# GraphQL introspection (authorized targets only)
curl -s https://app.example.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name}}}"}'
```

## Note-Taking

Reconnaissance produces hundreds of small facts; the difference between a good and a great report is whether those facts survive until the exploitation phase.

- Keep a per-application notebook: base URLs, discovered paths, technologies with versions, cookies, user roles, and interesting parameters.
- Record **evidence as you find it**: raw requests/responses, screenshots, and timestamps. Recreating a finding days later without evidence is painful.
- Use tools that centralize state: Burp Suite project files, ZAP sessions, or a plain Markdown tree such as `notes/00-scope.md`, `notes/01-endpoints.md`, `notes/02-tech.md`.
- Tag every finding with severity and the phase that will validate it (auth, authz, input validation, business logic).

## Common Mistakes & Tips

- **Brute-forcing out of scope.** Redirects and canonical hosts (`www.` vs apex, HTTP vs HTTPS) can move requests outside the agreement. Always resolve and confirm the final host.
- **Stopping at the homepage.** If you never crawl behind authentication, you miss the majority of the attack surface. Map the authenticated area too (register a test account if authorized).
- **Ignoring the WAF.** Unusual response patterns (all `403`, CAPTCHA walls, connection resets) usually mean filtering. Slow down, rotate user-agents, and check whether only some extensions are blocked.
- **Blind fuzzing without filters.** Default wordlists return thousands of hits; learn to filter with `-fs`, `-mc`, `-fc` (ffuf) before drawing conclusions.
- **Treating every `403` as "access denied".** A `403` can still leak the existence of a path worth checking with different methods (`POST`, `OPTIONS`, `TRACE`) or headers (`X-Original-URL`).
- **Skipping the API layer.** If the site is a SPA, the API is the application. Always enumerate API endpoints before exploitation.
- **Poor evidence hygiene.** Store requests, not just conclusions; a finding without a reproducible request is hard to report and hard to retest.

## Checklist / Self-Test

- [ ] I can state the exact in-scope URLs, out-of-scope items, and rules of engagement from memory.
- [ ] I crawled both the public and (where authorized) the authenticated parts of the application.
- [ ] I reviewed `robots.txt` and `sitemap.xml` and recorded non-linked paths.
- [ ] I fingerprinted the web server, runtime, framework/CMS, and session mechanism with evidence.
- [ ] I ran content discovery with a tuned wordlist and documented hits with status codes and sizes.
- [ ] I searched JavaScript bundles and common documentation paths for API endpoints.
- [ ] I recorded every finding in notes with the raw request/response or screenshot attached.
- [ ] My note file lists candidate areas for authentication, authorization, and input validation testing.

> **Verification:** executed against ffuf 2.1.0-dev, Gobuster 3.6 and WhatWeb 0.5.5 on 2026-09-19
> against a local listener: ffuf returned the test wordlist's three entries, WhatWeb fingerprinted
> `HTTPServer[BaseHTTP/0.6 Python/3.12.3]` and `gobuster dir` refused to run because the lab
> answered 200 for a non-existent path. The SecLists paths were re-checked upstream on the same
> date: `CMS/wp-themes.fuzz.txt`, `CMS/Drupal.txt` and
> `Programming-Language-Specific/CommonBackdoors-PHP.fuzz.txt` all answer HTTP 200, while
> `directory-list-2.3-medium.txt` 404s. One correction in this pass: the backdoor wordlist was
> cited without its `Programming-Language-Specific/` subfolder, and the bare name 404s — the
> sentence above now carries the full path, because a wordlist path that does not resolve is a
> command the reader cannot run.

## Further Resources

- OWASP Top 10 — A01/Broken Access Control context and general methodology framing: https://owasp.org/www-project-top-ten/
- OWASP Web Security Testing Guide — WSTG-INFO and WSTG-CONF chapters for recon-specific tests: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy — "Information disclosure" and "Business logic" learning materials with labs: https://portswigger.net/web-security
