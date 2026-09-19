# Authentication — eIAMA Methodology Phase 02

> eIAMA · Methodology · INE Cybersecurity Certifications Guide (public-knowledge study notes; no exam/NDA material)

## Overview

Authentication (AuthN) answers **"Who are you, and can you prove it?"** — distinct from authorization (AuthZ), which answers "What may you do?" (Phase 03). An IAM architect must select authenticators, design multi-factor authentication (MFA), decide when to demand more assurance, and manage the sessions that follow a successful sign-in. In a zero-trust world (Phase 04), authentication is also the moment where risk signals are collected and assurance levels are chosen per request.

By the end of this phase you should be able to:

- Classify authentication factors and their attack surfaces.
- Design MFA that resists phishing and MFA-fatigue, with sane recovery paths.
- Explain passwordless options: FIDO2/WebAuthn and the passkey concept.
- Describe adaptive and step-up authentication and when to apply them.
- Manage session lifetime, revocation, and logout.
- Map controls to NIST authentication assurance levels (AAL1–AAL3).

## Authentication Factors

Factors are traditionally grouped into three categories; NIST SP 800-63B notes that multi-factor authentication requires **at least two different factors**, and two instances of the same category (two passwords) do not count.

| Factor | Examples | Representative attacks |
|---|---|---|
| **Knowledge** (something you know) | Password, PIN, security questions | Phishing, password spraying, credential stuffing, shoulder surfing, guessable answers |
| **Possession** (something you have) | Authenticator app (TOTP), push, SMS OTP, hardware security key, smart card | SIM swap, SMS interception, push notification fatigue, token theft, malware relay |
| **Inherence** (something you are) | Fingerprint, face, iris, voice | Presentation attacks (photos/masks), biometric replay; poor fallback handling |

Beyond the three factors, signals such as device posture, location, and behavioral risk are **not factors** — they are *risk context* used by adaptive authentication. Never let a "secure location" replace a factor; context can be spoofed or shared.

## Designing MFA

Design principles:

- **Combine independent factors**, so that compromising one channel is not enough. Password + TOTP on the *same device* is weaker than password + a separate authenticator or hardware key.
- **Prefer phishing-resistant MFA** (FIDO2/WebAuthn, smart cards, PKI certificates) for administrators and high-value roles: they bind the assertion to the exact origin, so a fake login page cannot harvest a reusable secret.
- **Mitigate MFA-fatigue:** push prompts that a user can accidentally approve are being spammed until the victim accepts. Use number-matching challenges, or switch that population to FIDO2.
- **Plan enrollment and recovery before rollout:** backup codes, recovery flow, help-desk verification. A lost authenticator that locks users out drives shadow workarounds — but a weak recovery path (e.g., "send a code to any email") undoes the MFA.

```text
User                Application            Identity Provider        Authenticator
 │  username + password  │                        │                      │
 │──────────────────────►│ step 1 verify          │                      │
 │                       │───────────────────────►│                      │
 │◄──── challenge (step 2)────────────────────────│                      │
 │  approve push / TOTP / FIDO2 assertion         │                      │
 │────────────────────────────────────────────────│─────────────────────►│
 │                       │                        │◄─── verify step 2 ────│
 │◄────────── session established ────────────────│                      │
```

| MFA method | Phishing resistant? | Replay resistant? | Notes |
|---|---|---|---|
| TOTP (authenticator app) | No (OTP can be typed into a fake site) | Short-lived but phishable in real time | Cheap, wide compatibility |
| Push + number matching | Partially (resists fatigue) | Better than bare push | Still relies on the phone |
| SMS OTP | No | Weak (SS7/SIM swap) | Use only as a last resort |
| FIDO2 security key / passkey | Yes (origin-bound public key) | Yes | Best resistance; recovery planning needed |
| Smart card / PKI certificate | Yes | Yes | Strongest; heavier logistics |

**Common MFA bypasses to design against:** phishing the OTP in real time, session/cookie theft after MFA (protect sessions, see below), recovery-flow abuse, backup-code theft, and malware that runs inside an already-authenticated session.

## Passwordless Options

Passwordless means the user does not type a shared secret (password); instead, proof is a cryptographic response tied to something they have/are.

### FIDO2 / WebAuthn

- During **registration (attestation)**, the authenticator generates a key pair and stores the *private key* on the device; the public key is registered with the relying party.
- During **sign-in (assertion)**, the server sends a challenge; the authenticator signs it. The signature is scoped to the **origin** (scheme + host + port) it was registered with — a phishing site under a different origin cannot replay it.
- **CTAP2** lets a roaming authenticator (phone, USB key) talk to the browser; **platform authenticators** (Windows Hello, Touch ID, Android biometrics) are built into the device.

### The passkey concept

A **passkey** is the user-facing productization of WebAuthn: a *discoverable* (resident) credential that lets the user pick an account without typing a username. Two flavors matter architecturally:

- **Synced passkeys** are backed up and synced across a vendor's ecosystem (Apple/Google/Microsoft). Convenient and recoverable, but the credential's private key material lives with the cloud provider — assess trust and phishing-resistance claims per platform.
- **Device-bound passkeys** never leave one device (e.g., tied to a TPM-backed key). Stronger containment, weaker portability; requires a recovery path.

Other passwordless options: one-time codes by email ("magic links" — convenient but phishable at click time), certificate-based authentication (CBA), and PIN-plus-TPM schemes such as Windows Hello for Business.

| Option | Phishing resistant | Portable | Offline capable | Recovery story |
|---|---|---|---|---|
| Synced passkey | Yes (origin-bound) | Yes (via vendor sync) | Usually | Via ecosystem recovery |
| Device-bound passkey / security key | Yes | No (or carry key) | Yes | Backup key or recovery codes |
| Magic link / email OTP | No | Yes | No | Email access is the recovery |
| Smart card / CBA | Yes | Yes (physical card) | Yes | Card issuance process |

## Adaptive and Step-Up Authentication

**Adaptive (risk-based) authentication** varies the required assurance with the risk of the request. Signals include:

- Sign-in risk (impossible travel, anonymous IP, new device, leaked-credential match).
- Device compliance (managed, patched, jailbroken?).
- Location/network reputation, user behavior anomalies, sensitivity of the target resource.

**Step-up authentication** demands a *higher* assurance level for sensitive actions *after* the session is established (viewing a payment card, changing MFA settings, admin console, bulk export). A conceptual policy:

```json
// Conditional-access-style rule (conceptual)
{
  "name": "Step-up for admin actions",
  "applyTo": ["Admin Portal", "Tenant Settings API"],
  "require": "phishingResistantMfa",           // AAL2+ with FIDO2
  "when": {
    "any": [
      { "signInRisk": "high" },
      { "deviceCompliance": false },
      { "location": "untrusted" },
      { "action": ["directory.write", "mfa.reset", "user.delete"] }
    ]
  },
  "session": { "reauthenticateAfter": "4h", "disablePersistence": true }
}
```

Design notes: step-up should be **contextual and rare** (constant challenges train users to click through), it must itself survive replay (use the same strong MFA), and after step-up you usually want a *separate, elevated session* rather than silently upgrading the existing one.

## Session Management

After authentication, the user holds a **session** (opaque cookie server-side, or a signed/JWT token). Session design is where many breaches actually happen, because an attacker who steals a session never needs the password or the MFA.

| Control | What it does | Watch out for |
|---|---|---|
| Idle timeout | Ends session after inactivity | Too short = friction; too long = theft window |
| Absolute timeout | Forces full re-authentication periodically | Balance with step-up instead of blunt re-auth |
| Re-authentication on privilege change | New sign-in before elevated action | Should use step-up, not just fresh password |
| Session revocation | Server-side kill of tokens | Stateless JWTs are hard to revoke — keep exp short + denylist |
| Logout | Invalidates session at IdP **and** apps | Single sign-out needs propagation (OIDC RP-Initiated Logout / SAML Logout) |

Implementation tips: mark cookies `HttpOnly; Secure; SameSite`; bind sessions to a device identifier; rotate the session token after login and after privilege changes; **never trust the client's "logout"** — revocation must be enforced server-side. Remember: MFA protects sign-in, but a stolen post-MFA session bypasses it — which is why phishing-resistant sign-in must be paired with short-lived, revocable sessions.

## Authentication Assurance Levels (NIST SP 800-63B)

NIST defines three **authenticator assurance levels (AAL)** describing the confidence in the authentication event (note: separate from IAL — identity *proofing* — and FAL — federation, Phase 05).

> **Which revision these come from.** The current edition is **SP 800-63B-4 (revision 4)**, which
> states that it *supersedes* SP 800-63B — that is, revision 3. The requirements below are
> quoted from **revision 4**; where revision 3 said something materially different it is noted,
> because a study note that mixes the two silently changes what "AAL2" means. The reference
> text is published as HTML at
> <https://pages.nist.gov/800-63-4/sp800-63b.html> (revision 3 remains at
> <https://pages.nist.gov/800-63-3/sp800-63b.html>).

| Level | Minimum authenticator requirements (rev. 4) | Example posture |
|---|---|---|
| **AAL1** | "Only single-factor authentication using a wide range of available authentication technologies"; approved cryptography; authenticated protected channels. Rev. 4 *recommends* offering multi-factor options here but does not require them — and it does **not** require a replay-resistant session at AAL1 | Password or any single factor; low-risk internal tools |
| **AAL2** | Two distinct authentication factors, approved cryptography — and two normative requirements that are easy to collapse into one: *"At least one authenticator used at AAL2 SHALL be replay-resistant"*, and the verifier *"SHALL offer at least one phishing-resistant authentication option at AAL2"*. **Offering** it is required; the user's actual second factor need not be phishing-resistant | Password + TOTP or push does satisfy AAL2 — neither of those is phishing-resistant, which is exactly why the standard only requires the option to exist. A passkey or a FIDO2 key is the phishing-resistant option; standard enterprise access |
| **AAL3** | Two distinct factors, where authentication "is based on the proof of possession of a key through the use of a public-key cryptographic protocol" and "requires a phishing-resistant authenticator with a non-exportable authentication key" | FIDO2 security key + PIN, PIV/smart card; admins, high-value roles |

**Two corrections this table exists to make.** First, **replay resistance is an AAL2
requirement, not an AAL1 one** — at AAL1 the standard asks for single factor and approved
cryptography, and nothing about replay. Second, **"verifier-impersonation resistance" is not an
AAL2 property, and it is not even the current name.** Revision 4 says plainly: *"Phishing
attacks, previously referred to in SP 800-63B as 'verifier impersonation,' …"* — the concept was
renamed to **phishing resistance**, and in revision 3 it was an **AAL3** requirement ("AAL3
authentication requires a hardware-based authenticator and an authenticator that provides
verifier impersonation resistance"). Revision 4 kept it at the top: an AAL3 authenticator must be
phishing-resistant with a non-exportable key. TOTP and push are not phishing-resistant at
either revision, so an AAL2 posture built on them is correct *and* phishable at the same time —
which is the whole reason rev. 4 pushes phishing resistance into the AAL2 requirement as an
option the verifier must offer.

AAL is about the **whole protocol**, not just the factor count: replay resistance, session
binding, authentication intent, and (at AAL3) a non-exportable key all count. When the
exam-style scenario asks "what should a privileged admin use?", the answer profile is
*phishing-resistant, hardware-backed, MFA — AAL3-style* for the most sensitive roles and AAL2
for general staff — and if you want the general staff to be phishing-resistant too, that is a
policy choice above the minimum, not a requirement you can quote.

## Common Mistakes & Tips

- **Mistake:** SMS OTP as the sole second factor for admins. **Tip:** reserve SMS for low-risk recovery; use FIDO2/TOTP for privileged access.
- **Mistake:** MFA-fatigue-exposed push without number matching. **Tip:** enable number matching or migrate that group to phishing-resistant keys.
- **Mistake:** treating MFA as protection against session theft. **Tip:** pair strong AuthN with short-lived, revocable, HttpOnly sessions.
- **Mistake:** a recovery path weaker than the primary factor (e.g., password reset via a single email link). **Tip:** design recovery with the same assurance as sign-in.
- **Mistake:** static "MFA for everyone" with no step-up — high-risk actions get the same assurance as email reading. **Tip:** layer adaptive and step-up policies.
- **Mistake:** no absolute session timeout; stolen tokens live forever. **Tip:** enforce idle + absolute limits and re-auth on privilege change.
- **Mistake:** passkeys rolled out without a recovery/backup story, then users locked out. **Tip:** plan device-bound vs. synced per population and test recovery.

## Checklist / Self-Test

- [ ] I can classify factors (knowledge/possession/inherence) and name realistic attacks on each.
- [ ] I can explain why two factors from the same category do not make MFA.
- [ ] I can describe FIDO2/WebAuthn registration vs. assertion and why origin binding resists phishing.
- [ ] I can contrast synced and device-bound passkeys, including recovery implications.
- [ ] I can write a step-up rule that raises assurance only for genuinely risky actions.
- [ ] I can choose idle/absolute timeouts and session revocation for a given threat model.
- [ ] I can map controls to AAL1/AAL2/AAL3 and justify a privileged-access posture.

## Further Resources

- NIST SP 800-63B-4 (revision 4, current), *Digital Identity Guidelines: Authentication and Authenticator Management* — official reference HTML at <https://pages.nist.gov/800-63-4/sp800-63b.html>; revision 3 remains at <https://pages.nist.gov/800-63-3/sp800-63b.html> for comparison
- NIST SP 800-63-4, *Digital Identity Guidelines* (the umbrella volume; IAL and FAL live in 63A and 63C): <https://pages.nist.gov/800-63-4/>
- FIDO Alliance — passkeys: https://fidoalliance.org/passkeys/
- W3C WebAuthn specification: https://www.w3.org/TR/webauthn-3/
- OpenID Foundation (OIDC session/logout concepts): https://openid.net/developers/specs/
- Microsoft Entra ID documentation (MFA and Conditional Access concepts): https://learn.microsoft.com/en-us/entra/identity/

> **Verification:** the three AAL summaries and the normative AAL1/AAL2 requirement sentences
> quoted above were read from the official reference HTML of **SP 800-63B-4** on **2026-09-19**
> (`https://pages.nist.gov/800-63-4/sp800-63b.html`, HTTP 200; revision 3 at
> `https://pages.nist.gov/800-63-3/sp800-63b.html`, HTTP 200). The revision-4 text read:
> *"At least one authenticator used at AAL2 SHALL be replay-resistant"*, *"Verifiers SHALL offer
> at least one phishing-resistant authentication option at AAL2"*, and *"Phishing attacks,
> previously referred to in SP 800-63B as 'verifier impersonation,' …"*. The revision-3 text
> read: *"AAL3 authentication requires a hardware-based authenticator and an authenticator that
> provides verifier impersonation resistance."* Neither revision states a replay-resistance
> requirement at AAL1.
