# Advanced Authentication & Sessions — eWPTX Methodology Phase 4

> eWPTX study guide · Advanced web methodology — INE-Cybersecurity-Certifications-Guide

Modern apps rarely run a simple username/password form anymore: they front
with JWT-bearing APIs, delegate identity to OAuth/OIDC providers, federate
through SAML SSO, and add 2FA on top. Each of those layers has its own
failure modes, and the bugs live in the **transitions** — how tokens are
issued, validated, stored, and invalidated. This phase covers the attacks you
must be able to test (in authorized environments) and the logic you must be
able to reason about.

## JWT issues

A JSON Web Token is a signed/encrypted claim set (`header.payload.signature`).
The security rests entirely on *which algorithm the server accepts* and *what
it trusts as the verification key*.

**Decode first, always:**

```bash
# header.payload.signature — decode without verifying
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null   # add padding if needed
# or use a decoder: https://jwt.io (paste only test/lab tokens there)
```

**`alg: none` and algorithm confusion.** If the server accepts unsigned
tokens, or verifies with the public key but lets you choose `RS256`→`HS256`
(symmetric), you can forge tokens:

```text
# none attack — header says "no signature"; some libraries accept it
header:  {"alg":"none","typ":"JWT"}
payload: {"sub":"admin","role":"admin","exp":<future>}
signature: (empty)

# confusion attack — server verifies RS256 with the PUBLIC key; if it also
# accepts HS256, sign with that same public key bytes as the HMAC secret
# (jwt_tool / pyjwt can do this; the prerequisite is obtaining the public key)
```

**Weak HMAC secret.** HS256 tokens are forgeable when the secret is weak —
brute force offline (never against the server):

```bash
# Crack a JWT HMAC secret with hashcat (wordlist attack, offline)
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
# Once cracked: forge new tokens with the recovered secret
```

**Other JWT checks:** `kid` header injection (point at a file/URL you
control), missing `exp`/`iat` validation, algorithm confusion through `jku`
/`x5u` header URL fetching, and accepting tokens signed for a *different
audience/issuer* than the app. Test in this order: does the app accept
`alg:none`? does it validate the signature at all (change payload only)? does
it validate `exp`? which algorithms are whitelisted?

## OAuth 2.0 / OIDC flows and misconfigurations

OAuth delegates *authorization*, OIDC adds *authentication* (an `id_token`).
The standard flows you must know: **authorization code (with PKCE)**, the
implicit flow (legacy, token in URL fragment), and the client-credentials
flow. The vulnerabilities concentrate in:

- **`redirect_uri` validation**: open redirectors, path confusion
  (`/callback` vs `/callback/extra`), subdomain wildcards, and
  `redirect_uri` that equals a page the attacker controls on the same origin.
  If you can steer the code/token to your URI, you can steal it.
- **State parameter**: missing `state` lets an attacker **login CSRF** — bind
  a victim's account to the attacker's provider account.
- **Code/token leakage**: codes in logs, referrer headers, or URL fragments.
- **Token scope/audience confusion**: an `access_token` for API A accepted
  by API B because audience is not checked.
- **IdP confusion / token substitution**: app trusts tokens from any IdP, or
  does not bind the token to the login it requested.

Test with a browser + proxy and your own OAuth client:

```text
1. Start the normal SSO login; capture the /authorize request.
2. Mutate redirect_uri (add /path, change host, drop to http) and observe
   whether the provider redirects with a code (bad) or errors.
3. Remove state and replay; if the callback still binds, login CSRF exists.
4. Replay an authorization code twice — second use should fail (codes are
   one-time); if it succeeds, you have a replay bug.
5. Swap the id_token/access_token between two of your accounts and see
   whether the app maps identity by token or by session cookie.
```

## SSO and SAML basics

SAML is XML-based SSO: the **IdP** authenticates and issues a signed
`Assertion` (with `Subject`, conditions, attributes) that the **SP** trusts.
The classic flaws:

- **XML signature wrapping**: the SP validates the signature on one node but
  consumes a different, unsigned node — craft a validly-signed document whose
  *used* assertion contains your identity.
- **Comment injection** in `NameID`: the comment sits *after* the identity being
  impersonated (`victim@target.com<!--x-->`). A conformant XML parser
  **discards** comments, so the element's text content — the value the SP must
  use — is `victim@target.com`. The flaw lives in libraries whose DOM-traversal
  and canonicalization APIs handle comments inconsistently, so inner text
  *after* the comment is dropped before the message is signed and ends up
  outside the signature; the SP must parse conformantly and verify the
  signature over the whole element (CERT VU#475445).
- **Missing signature / signature only on part of the assertion**.
- **`Recipient`/`Audience`/`Conditions` not enforced** — assertions issued
  for one SP accepted by another.

```xml
<!-- Comment injection: the comment trails the impersonated identity. A
     conformant parser discards comments, so the text content the SP must use
     is victim@target.com — but a library that drops text *after* the comment
     signs less than the element holds (CERT VU#475445). -->
<saml:NameID>victim@target.com<!--x--></saml:NameID>

<!-- Signature wrapping: the SP validates the signature on one node but
     consumes another. The signed node is the attacker's own legitimate
     assertion (the decoy); the consumed, unsigned node carries the victim. -->
<saml:Subject>
  <saml:NameID>attacker@evil.com</saml:NameID>   <!-- signed decoy -->
</saml:Subject>
<saml:Subject>
  <saml:NameID>victim@target.com</saml:NameID>   <!-- consumed, unsigned -->
</saml:Subject>
```

Practical path: obtain a legitimate assertion from the IdP with your own
account, then mutate the identity fields and replay it to the SP; if the SP
accepts unsigned/forged attributes, that is your finding. (SAML testing needs
a lab IdP/SP pair — use one you control.)

## Session fixation and invalidation flaws

- **Fixation**: if the app accepts a session id chosen by the attacker
  (via URL, cookie pre-set, or `session` parameter) and does not rotate it on
  login, an attacker can fixate then wait for the victim to authenticate.
- **Missing rotation on privilege change**: logging in, changing roles, or
  completing 2FA must issue a *new* session id; check that the pre-login
  cookie value dies after login.
- **Invalidation gaps**: logout must invalidate server-side; the *old*
  session and any parallel sessions (other devices) must not keep working.
  Test: login, logout, replay the old cookie. Change password, replay the
  pre-change session.

```bash
# Fixation probe (lab): supply a session id YOU chose, log in, compare what
# comes back. `-b` sends the fixed cookie — without it the probe sends nothing;
# `-c` saves the cookie the app hands back.
FIXED=attacker-chosen-session-id
curl -s -b "session=$FIXED" -c jar.txt http://lab/login -d 'user=x&pass=y'
grep session jar.txt                       # cookie the app gave you
# If it still equals $FIXED after a successful login -> fixation candidate
# (a correct app rotates the session id on login; see the notes above)
```

## 2FA logic gaps

2FA is only as strong as the logic around it:

- **Bypass by not finishing the flow**: some apps set an authenticated
  session *before* the OTP step and only check the flag client-side, or
  leave the post-login endpoint reachable when 2FA is "pending".
- **OTP not bound to the session/request**: replay the same OTP, or use an
  OTP generated for one login on another (no binding to device/account).
- **Response/status oracles**: endpoints leak whether an OTP was *correct*
  (vs. expired/invalid) through different status codes or messages.
- **Rate-limit gaps**: no attempt limit on the OTP check (see phase 3) lets
  you brute force a 6-digit code.
- **Backup codes / remember-device weaknesses**: unlimited tries, or backup
  codes that bypass rather than replace 2FA.
- **Enrollment flaws**: adding a second device or disabling 2FA requires
  only the (phishable) password, or the confirmation step is skippable.

```http
# Concept: some apps mark 2FA "verified" with a cookie the client sets
POST /api/verify-otp HTTP/1.1
Cookie: session=abc; step=otp-pending
# try removing the step cookie / calling /api/account directly before OTP
```

## Cross-cutting test plan

1. Map every auth entry point: login, SSO callback, password reset, API token
   issuance, 2FA enrollment, session refresh.
2. For each, note what token/cookie is issued and **when it rotates**.
3. Attack the token formats (JWT alg/key issues, SAML signature handling).
4. Attack the flows (redirect_uri, state, code replay, fixation).
5. Attack invalidation (logout, password change, 2FA disable).
6. Record evidence per issue: before/after tokens, full requests, and the
   exact logic that failed (missing check vs. wrong check).

## Common Mistakes & Tips

- **Treating JWT as opaque.** Decode every token before testing; most bugs
  are visible in the header (`alg`, `kid`, `jku`).
- **Only attacking the signature.** `exp`, audience, issuer, and scope
  validation are equally common failure points.
- **Forgetting `state` in OAuth.** Login CSRF via missing state is frequent
  and easy to demonstrate with two browser profiles.
- **Skipping session-rotation checks.** Fixation and post-login rotation are
  quick to verify and often missed.
- **Confusing client-side 2FA UI with server enforcement.** Prove the server
  enforces the step; a UI that hides a reachable endpoint is a finding.
- **Testing SAML/OAuth against production IdPs.** Always build/use a lab IdP
  (e.g., a local Keycloak or similar) for mutation testing.
- **Not checking multi-device sessions.** Logout that only kills one session
  is a real invalidation flaw — test from two sessions.

## Checklist / Self-Test

- [ ] I can decode a JWT and test `alg:none`, algorithm confusion, weak-HMAC
      secret, and missing `exp`/audience validation.
- [ ] I can explain OAuth authorization-code, implicit, and client-credentials
      flows and where each is dangerous.
- [ ] I can test OAuth `redirect_uri` validation, missing `state` (login
      CSRF), and authorization-code replay.
- [ ] I understand SAML assertion structure and can describe signature-
      wrapping and unsigned-assertion attacks.
- [ ] I test session fixation, rotation on login, and server-side logout
      invalidation across devices.
- [ ] I can identify 2FA logic gaps: skipped steps, OTP replay, weak attempt
      limits, and enrollment flaws.
- [ ] I verify that auth failures are real server-side issues with before/
      after token evidence.
- [ ] I keep an auth entry-point map with the tokens/cookies issued at each
      step.

> **Verification:** the SAML comment handling was checked against CERT/CC
> VU#475445 on 2026-09-19
> (<https://www.kb.cert.org/vuls/id/475445>), which states that inconsistent
> comment handling makes inner text after the comment fall outside the signature
> (CVE-2017-11427 … CVE-2018-5387) — primary documentation, no SAML lab was run
> here. The fixation probe was executed: against a local login endpoint, the old
> `curl -s -c jar.txt` reached the server with `Cookie: <none>`, while
> `curl -s -b "session=$FIXED" -c jar.txt` sent
> `Cookie: session=attacker-chosen-session-id` (curl in WSL Ubuntu 24.04,
> 2026-09-19).

## Further Resources

- IETF RFC 7519 (JWT) summary and ecosystem: https://jwt.io/introduction
- IETF RFC 6749 (OAuth 2.0) and RFC 7519/7517 (JOSE) at the RFC editor:
  https://www.rfc-editor.org/rfc/rfc6749
- OAuth 2.0 security best practices (BCP, RFC 9700): https://www.rfc-editor.org/rfc/rfc9700
- PortSwigger Web Security Academy — JWT, OAuth, and authentication labs:
  https://portswigger.net/web-security
- OWASP Cheat Sheet Series — JWT, OAuth, and session-management cheat
  sheets: https://cheatsheetseries.owasp.org/
- OWASP Web Security Testing Guide — identity management testing:
  https://owasp.org/www-project-web-security-testing-guide/
