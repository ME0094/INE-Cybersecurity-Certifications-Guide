# Burp Suite Advanced — Macros, Session Handling, Turbo Intruder, Extensions & Integration

> eWPTX · Tools — INE-Cybersecurity-Certifications-Guide (English)

## Purpose

This guide covers Burp Suite features that matter at the advanced web-testing level. At this level you rarely click one request at a time: you automate session maintenance, replay sequences, brute-force with tight timing control, extend Burp with plugins, and feed Burp from — or into — other tools. Most content assumes **Burp Suite Professional**; Community Edition differences are flagged inline. Work only against targets you are authorized to test.

## Macros: replay a sequence and capture dynamic values

A **macro** is a recorded sequence of requests that Burp can replay automatically *before* (or around) your actual request. You add **response extraction rules** to pull dynamic values out of the macro responses, then substitute those values into your main request via **macro substitution points**.

Typical uses:

- Refresh a CSRF token before every request in a state-changing flow.
- Re-authenticate (re-login or refresh a session cookie) when a scan or intruder run lasts longer than the session.
- Fetch a signed value, nonce, or timestamp the application requires.
- Keep a multi-step flow consistent when testing one step in isolation.

Workflow to create one:

1. In **Settings → Sessions → Macros**, click *Add* and record the requests that produce the dynamic value (e.g., a `GET /csrf` that returns a token).
2. Add a **response extraction rule** with a regex that isolates the value, for example:

```text
name="csrf" value="([a-zA-Z0-9]{32})"
```

3. In the **Session Handling Rules** editor, add a rule whose action is *Run a macro*, choose your macro, and enable substitution.
4. Back in the request editor, use the context menu to **insert a macro substitution point** at the exact position the value must go (header, cookie, or body parameter).
5. Scope the rule to the relevant tool and URL prefix, then test with manual sends in the *session handling rule tester* (replay the request twice and confirm the token changes each time).

Macros are stateful: they replay real requests, so they consume server-side state and can trip rate limits. Keep the macro as short as possible (only the requests needed to produce the value).

## Session handling rules: automated context

Session handling rules tell Burp *what to do around a request* and *when to do it*. A rule has a **scope** (tools and URL prefix it applies to) and a list of **actions**. Order matters: Burp evaluates matching rules in order, so put the most specific rule first and keep the rule set small.

Common action combinations:

- **401/302 detector + re-login macro**: if a response indicates the session expired, run the login macro, then retry the original request with the fresh cookie. This keeps long scans alive.
- **CSRF refresh macro**: run a one-request macro that fetches a fresh token and substitutes it into each state-changing request.
- **Header injection on the fly**: add or rewrite headers (for example an internal `X-API-Key` or a custom `Host`) only for requests inside a given scope.

Debugging tips: disable rules while you manually explore (a mis-scoped rule will rewrite your manual requests too), and always confirm the rule applies to the intended tool — scanner, intruder, and repeater can each be included or excluded independently.

## Turbo Intruder: brute force and race conditions with Python

Turbo Intruder is a Burp extension that drives an HTTP engine from a short Python script you write. Instead of a GUI grid you get full control over timing, connection reuse, and response handling — the classic use cases are **large wordlists** and **race conditions** (including the *single-packet attack* that fires many requests within one TCP segment).

Conceptual template:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=20,
                           requestsPerConnection=100,
                           pipeline=False)

    for word in open(wordlists['wordlist']):
        word = word.rstrip()
        engine.queue(target.req, word)          # word appears in a %s placeholder

def handleResponse(req, interesting):
    if req.status == 200 and 'Welcome' in req.response:
        table.add(req)                           # flag interesting responses
```

Race-condition pattern (single-packet attack): queue several requests, hold them behind a gate, then release them in one burst:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False)
    for _ in range(30):
        engine.queue(target.req)
    engine.openGate()                            # release all at once
```

Rules of thumb: start with a small run and watch response codes before scaling up; respect the lab or target's rate expectations; use `handleResponse` to filter noise instead of dumping everything; remember that Turbo Intruder reuses connections, so server-side rate limiters keyed per connection behave differently than they do per request.

## Extensions and the BApp Store

The **BApp Store** is Burp's official extension catalog. Extensions roughly fall into families: request/response **modifiers**, **scanner/active-check** helpers, **token & auth** manipulators (JWT signing/verification tools), **authorization testing** helpers that re-send requests under different sessions, **UI/dashboard** helpers, and **integration** bridges to other frameworks.

Working with extensions in general terms:

- Install from **Extensions → BApp Store** with one click; watch the *Output/Errors* tabs after install — an extension that misbehaves shows up there.
- Prefer extensions that are actively maintained and match your Burp version; API drift breaks old plugins.
- **Community and third-party extensions execute code with your privileges.** Only install from sources you trust, and review what an extension does before running it against sensitive targets.
- The primary way to *write* your own is Java against the **Montoya API** (the current extension API): you get typed access to HTTP requests, the project's data model, and UI registration. Keep extensions small and focused: one capability, clean logging, no global side effects.
- Remember the BApp Store is convenience, not a requirement: a 20-line custom extension or a Python script (see `tools/custom-scripts/exploit-framework.md`) is often a better fit for a specific task than a heavyweight plugin.

## Match and replace rules

Match and replace rules perform automatic, find-and-replace edits on requests and responses as they pass through the proxy. Uses: rewriting a `User-Agent`, forcing a header value, removing a noisy header, or simulating a different client during testing.

Example configuration (conceptual):

```text
Match:    ^User-Agent: .*$
Replace:  User-Agent: eWPTX-lab-agent/1.0
Apply to: Request header        Scope: *.example-lab.com only
```

Warnings:

- Rules apply **globally** by default. Always scope them to the target host prefix; an unscoped rule silently corrupts traffic to every host you proxy.
- Match/replace is blind text surgery. If the value is *dynamic* (a CSRF token, a session cookie that rotates), use a macro + session handling rule instead of a static replace.
- Response-side rules can hide the truth: rewriting responses to make an exploit "work" only trains you to fool yourself. Use response rules sparingly and consciously.

## Integrating Burp with other tooling

Burp is strongest when it is the central proxy your other tools share, so all traffic lands in one history for correlation.

Route external tools through Burp (default proxy listener is `127.0.0.1:8080`):

```bash
# curl
curl -k -x http://127.0.0.1:8080 https://target.example/api/v1/users

# ffuf / gobuster / nuclei-style tools that accept a proxy flag
ffuf -u https://target.example/FUZZ -w wordlist.txt -x http://127.0.0.1:8080

# python requests
python3 - <<'PY'
import requests
proxies = {"http": "http://127.0.0.1:8080",
           "https": "http://127.0.0.1:8080"}
r = requests.get("https://target.example/", proxies=proxies, verify=False)
print(r.status_code)
PY
```

Browsers and other GUI tools need Burp's **CA certificate** installed and trusted (Proxy settings → import/export CA certificate; export in DER and convert for tools that need PEM, or accept the cert once per tool).

Other integration patterns:

- **Copy as curl / save items** — right-click any request to copy it as a `curl` command for a lab notebook or to feed a custom script; *Save item* exports full request/response pairs as evidence files.
- **Comparer** — diff two responses to isolate the effect of one header or parameter change.
- **Collaborator** (Professional) — out-of-band detection for blind SSRF, blind XXE, and similar; watch for DNS and HTTP interactions.
- **REST API / headless automation** — recent Professional releases ship an automation API; check your version's release notes before scripting around it.
- **Project state files** — save/load `.burp` project state to keep an assessment reproducible across sessions.

## Common Mistakes & Tips

- **Unscoped session rules and match/replace** rewrite traffic to unrelated hosts. Scope everything to the target prefix.
- **Macro loops**: a macro that itself triggers a session rule can recurse. Test the macro standalone first.
- **Order blindness**: session handling rules are evaluated in order; a broad rule before a specific one shadows it.
- **Turbo Intruder without a plan**: firing thousands of requests before checking a small sample wastes time and gets you blocked. Sample first, scale second.
- **Installing BApp extensions blindly**: extensions run with your privileges and can break your workflow. Review and test them on throwaway targets.
- **Forgetting to disable convenience rules** when you switch from lab work to real engagements; a leftover rewrite rule is a classic way to corrupt production testing.
- **Not exporting evidence**: interactive tool wins that are never saved as request/response pairs vanish when the project closes.

## Checklist / Self-Test

- [ ] I can create a macro that extracts a dynamic token and substitutes it into a request via a session handling rule.
- [ ] I can scope a session handling rule to one tool and one URL prefix and verify it does not fire elsewhere.
- [ ] I can write a Turbo Intruder script that queues a wordlist and filters responses in `handleResponse`.
- [ ] I can explain the single-packet attack concept and when race-condition testing needs it.
- [ ] I have installed one BApp extension and checked its Output/Errors tabs; I can describe what family it belongs to.
- [ ] I can configure a scoped match/replace rule and explain why static replaces are wrong for dynamic values.
- [ ] I can route `curl` and a Python script through Burp's proxy and locate their traffic in HTTP history.

## Further Resources

- PortSwigger Web Security Academy (proxy, macros, session handling, Turbo Intruder topics) — https://portswigger.net/web-security
- BApp Store (official extension catalog) — https://portswigger.net/bappstore
- PortSwigger Research (desync/smuggling and other technique write-ups) — https://portswigger.net/research
- PortSwigger docs on extensions and the Montoya API — https://portswigger.net/burp/documentation
- OWASP Web Security Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
