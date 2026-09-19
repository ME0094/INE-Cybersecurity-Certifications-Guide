# Federation and SSO — eIAMA Methodology Phase 05

> eIAMA · Methodology · INE Cybersecurity Certifications Guide (public-knowledge study notes; no exam/NDA material)

## Overview

Federation lets one organization (or one IdP) **assert identity to applications and organizations it does not control**, so users get single sign-on (SSO) without duplicated accounts and passwords. The dominant standards are **SAML 2.0** (XML-based, still the norm for enterprise/B2B) and **OpenID Connect (OIDC)** (JSON/JWT-based, built on OAuth 2.0, the default for modern apps and B2C). Federation is the mechanism that turns the identity lifecycle (Phase 01), authentication (Phase 02), and authorization (Phase 03) into a cross-boundary service.

By the end of this phase you should be able to:

- Explain SSO and federation concepts and when each applies.
- Describe SAML 2.0 flows, assertions, and the role of the ACS endpoint.
- Describe OIDC flows, the ID token, discovery, and JWKS.
- Explain trust relationships and the validations both sides must perform.
- Map and transform claims safely between IdP and applications.
- Identify the classic federation failure modes and design against them.
- Choose an identity provider strategy (single IdP, hubs, B2B/B2C).

## SSO Fundamentals

- **Local (same-domain) SSO:** one session in a shared directory covers many apps (e.g., Kerberos/AD or an IdP session across registered apps). One authentication, many applications.
- **Federated SSO:** authentication happens at an **identity provider (IdP)** you may not own, and each **service provider / relying party (SP/RP)** accepts the IdP's assertion through a trust relationship. No password ever travels to the application.

```text
 User ──► wants app at SP-A and SP-B
          │
          ▼
       IdP (single sign-on session) ──► asserts identity to SP-A (SAML/OIDC)
                │                        ──► asserts identity to SP-B (no re-login)
                ▼
        Central control: lifecycle, MFA, policy, revocation
```

Benefits: fewer credentials to phish, centralized MFA and lifecycle, faster onboarding/offboarding. Costs/risks: the IdP becomes a single control plane, and protocol mistakes (bad ACS/audience/signature handling) become critical vulnerabilities.

## SAML 2.0 in Concept

Actors and terms: **principal** (user), **identity provider (IdP)**, **service provider (SP)**. Key artifacts: **assertions** (authentication statements, attribute statements), **AuthnRequest** and **Response** messages, **bindings** (HTTP-Redirect, HTTP-POST), **RelayState**, and metadata. Endpoints: the SP's **Assertion Consumer Service (ACS) URL** receives the signed response; the IdP's **SSO service** receives the request.

SP-initiated flow:

```text
1. User → SP:         requests /sales
2. SP → browser:      HTTP 302 to IdP SSO service with AuthnRequest (+ RelayState)
3. browser → IdP:     user authenticates (password + MFA)
4. IdP → browser:     HTML form auto-POST to SP ACS URL containing signed Response
5. SP (ACS):          validate signature, issuer, audience, conditions;
                      create local session → redirect to /sales
```

Conceptual (abridged) assertion:

```xml
<samlp:Response ...>
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <ds:Signature>…</ds:Signature>   <!-- SP MUST validate against IdP cert -->
  <saml:Assertion ID="_a1b2" IssueInstant="...">
    <saml:Conditions NotBefore="..." NotOnOrAfter="...">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com/sales</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement .../>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">…
      <saml:Attribute Name="groups">…
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

The ACS URL is the SP's *trusted mailbox*: if the SP accepts responses at any URL an attacker chooses, the attacker can exfiltrate a valid assertion to their own endpoint (see risks below).

## OpenID Connect in Concept

OIDC layers identity on OAuth 2.0: the client obtains an **ID token** (a JWT asserting who the user is) plus an access token for APIs, and can fetch more attributes from the **UserInfo** endpoint. Critical endpoints are discovered via the **discovery document** at `/.well-known/openid-configuration`, and public keys via **JWKS** (JSON Web Key Set).

```jsonc
// Conceptual ID token (JWT payload)
{
  "iss": "https://idp.example.com",       // must match configured issuer
  "sub": "a4b2c3...",                     // stable, immutable subject id
  "aud": ["sales-app"],                   // must include THIS client
  "exp": 1730000000,
  "iat": 1729996400,
  "nonce": "S8x9K2...",                   // binds token to the login session (CSRF)
  "email": "ana@example.com",
  "email_verified": true,
  "groups": ["finance", "sales-readers"]
}
```

```text
App (RP) → IdP: /authorize (response_type=code, PKCE, scope=openid profile email)
IdP → App:     authorization code (after user authenticates + consents)
App → IdP:     /token (code + PKCE verifier) → ID token + access token
App:           validate signature (JWKS), iss, aud, exp, nonce → local session
App → IdP:     optional /userinfo for additional claims
```

Recommended for native/mobile/SPA clients: **authorization code + PKCE**; never put client secrets in browsers. RP-initiated logout and (optional) back-channel logout keep sessions aligned.

## Trust Relationships and Metadata

Federation trust is established out-of-band and then verified in-band on every request:

- **SAML:** both sides exchange **metadata** (entity IDs, endpoints, signing certificates). The SP keeps an allowlist of trusted IdPs (and vice versa); trust anchors are the exchanged certificates.
- **OIDC:** the RP trusts the IdP's issuer, fetches its discovery document and JWKS over HTTPS, and registers its client (`client_id`, allowed `redirect_uris`).

| What must be validated | IdP side | SP/RP side |
|---|---|---|
| Who is talking | `client_id` exists; `redirect_uri` exact-match allowlist | Issuer (`iss`) matches a trusted IdP |
| Who the assertion is for | — | Audience (`aud`) includes this SP/client |
| Authenticity | — | Signature over XML/JWT with the IdP's key |
| Freshness | — | `NotBefore`/`NotOnOrAfter`, `exp`, tolerated clock skew |
| Anti-replay / CSRF | `state` binding | `nonce` (OIDC) / `InResponseTo` (SAML) |

Design guidance: use exact-match validation, tolerate only small clock skew, plan **key rotation** (multiple active certs/JWKS), and log every rejected assertion for detection.

## Claims and Attribute Mapping

Assertions carry claims (SAML attributes / OIDC claims) that the SP maps into its own identity and authorization model: `email` → login name, `groups` → roles, `department` → attribute used by ABAC policies (Phase 03). Mapping decisions that matter:

- **Use the immutable `sub`/`NameID`, not the email, as the correlation key.** Emails change and can be repurposed; matching on email means a recycled address can map onto another person's account.
- **Map, don't echo.** The SP decides what a claim means locally; the IdP's group names must not silently become SP roles without transformation and review.
- **Just-in-time (JIT) provisioning:** create/update the local account from claims at first sign-in — but know that the *source* of attributes is the IdP's directory quality (Phase 01).

| Concept | SAML 2.0 | OpenID Connect |
|---|---|---|
| Identifier | `NameID` in Subject | `sub` claim |
| Attributes | `AttributeStatement` (XML) | Claims in ID token / UserInfo (JSON) |
| Assertion format | Signed XML | Signed JWT (JWKS) |
| Browser binding | HTTP-Redirect / HTTP-POST | HTTP redirects + HTTPS APIs |
| Logout | SAML Logout (front/back channel) | RP-Initiated / Back-Channel Logout |

## Federation Risks

Every one of these is a real, documented class of failure — and an architect's checklist:

- **Misconfigured / overly permissive ACS (SAML) or `redirect_uri` (OIDC):** attackers redirect the assertion to their own endpoint. *Fix:* exact-match allowlist; never wildcard; validate before processing.
- **Audience confusion:** an assertion issued for tenant A is accepted by tenant B (multi-tenant IdP mix-ups). *Fix:* validate `aud`/Audience against *your* exact entity; per-tenant allowlists.
- **Signature validation gaps:** disabled signature checks, `alg: none`, algorithm confusion (HS256 with the RSA public key), XML signature wrapping. *Fix:* enforce strong, pinned algorithms; reject unsigned/unverified content; keep libraries current.
- **Replay and freshness:** replayed assertions/tokens; missing `InResponseTo`/`nonce` checks; excessive clock-skew tolerance. *Fix:* one-time use, state/nonce binding, tight time windows.
- **Session/logout gaps:** IdP session killed but SP sessions alive (no logout propagation); session fixation on return. *Fix:* implement logout agreements; rotate local session on login.
- **Metadata and discovery abuse:** importing untrusted metadata (SSRF via metadata URLs), tampered discovery. *Fix:* fetch metadata over HTTPS from pinned sources; cache and verify.
- **IdP compromise blast radius:** one weak IdP credential or policy misconfiguration exposes every federated app. *Fix:* strong AuthN at the IdP (Phases 02), per-app audiences, minimal claims, monitoring.

## Identity Provider Strategy

Choose the topology that matches the user populations and governance model:

| Pattern | When to use | Example |
|---|---|---|
| **Single corporate IdP** | One organization, one directory | Employees SSO into SaaS and internal apps |
| **Hub-and-spoke / broker** | Acquisitions, subsidiaries, multi-cloud | A broker IdP trusts each subsidiary's IdP and presents one face to apps |
| **B2B federation** | Partners/customers keep their own identity | Each partner federates its IdP to your apps (or yours to theirs) |
| **B2C / CIAM** | External consumers, no directory of your own | OIDC social or self-registered identities for a product |

Strategic considerations: protocol support (SAML for legacy/B2B, OIDC for modern), attribute availability and quality, residency/compliance, lifecycle integration with the source of truth (Phase 01), conditional access and risk engines at the IdP (Phases 02/04), **outage planning** (secondary IdP, cached sessions, break-glass), and migration/coexistence from legacy federation (e.g., AD FS to cloud IdP) with staged rollout per application.

## Common Mistakes & Tips

- **Mistake:** wildcard ACS/redirect allowlists "to avoid breaking apps." **Tip:** exact-match registration; log and review every new URI.
- **Mistake:** trusting the assertion because "it came over HTTPS from the IdP." **Tip:** verify signature, issuer, audience, and time on every single request — TLS only protects transport.
- **Mistake:** correlation on email addresses. **Tip:** use immutable `sub`/`NameID`; treat email as a mutable attribute.
- **Mistake:** claims become roles verbatim (IdP group `everyone` → app admin). **Tip:** map and transform claims; default deny at the SP.
- **Mistake:** no logout propagation — deprovisioning at the IdP leaves live SP sessions. **Tip:** implement logout agreements and short session lifetimes.
- **Mistake:** accepting SAML metadata from arbitrary URLs or untrusted sources. **Tip:** pin metadata sources; validate entities and certificates.
- **Mistake:** no monitoring of failed assertions/validation. **Tip:** log rejections; alert on spikes — attacks show up there first.

## Checklist / Self-Test

- [ ] I can distinguish local SSO from federated SSO and describe the trust model.
- [ ] I can draw the SAML SP-initiated flow and explain the ACS endpoint's role.
- [ ] I can list the OIDC artifacts (ID token, access token, discovery, JWKS, UserInfo).
- [ ] I can state the five validations both sides must perform (signature, issuer, audience, time, replay).
- [ ] I can map SAML↔OIDC concepts (NameID↔sub, attributes↔claims, logout differences).
- [ ] I can explain at least five federation failure modes and their fixes.
- [ ] I can recommend an IdP topology (single, broker, B2B, CIAM) for a given scenario.

> **Verification:** the protocol facts above were checked on **2026-09-19** against the primary
> specifications, all HTTP 200 unless noted. **OpenID Connect Core 1.0**: `sub` is *"A locally
> unique and never reassigned identifier within the Issuer for the End-User"*, `nonce` is a
> *"String value used to associate a Client session with an ID Token, and to mitigate replay
> attacks"*, and `aud` *"MUST contain the OAuth 2.0 client_id of the Relying Party as an
> audience value"*. **OpenID Connect Discovery 1.0**: the metadata document is served at the
> path formed by concatenating `/.well-known/openid-configuration` to the Issuer, and
> `jwks_uri` is *"REQUIRED"*. **SAML V2.0 core**
> (`docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf`) contains `AuthnRequest`,
> `InResponseTo`, `AudienceRestriction`, `NotOnOrAfter` and `NameID`; the HTML rendering under
> that same path answers **HTTP 404**, as the note in Further Resources says. The XML and JSON
> blocks are abridged illustrations rather than captured traffic: no IdP, realm or federation
> partner was available in this pass, so no assertion or token shown above was produced or
> validated live. `groups`, used in the ID token example, is not one of the standard claims
> registered by OIDC Core — the spec permits additional claims and its own example of one is
> `http://example.info/claims/groups`.

## Further Resources

- NIST SP 800-63C, *Digital Identity Guidelines: Federation and Assertions*: https://doi.org/10.6028/NIST.SP.800-63c
- OASIS SAML V2.0 core specification: https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf (the HTML rendering under the same path is gone; the PDF is the published form)
- OpenID Connect Core 1.0 specification: https://openid.net/specs/openid-connect-core-1_0.html
- OAuth.net — OAuth 2.0 overview: https://oauth.net/2/
- Microsoft Entra ID documentation (federation and SSO concepts): https://learn.microsoft.com/en-us/entra/identity/
