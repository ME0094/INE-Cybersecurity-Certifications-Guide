# IAM Protocols — Quick Reference Cheatsheet

> eIAMA · cheatsheets — INE-Cybersecurity-Certifications-Guide
> Compact reference for the standards an IAM architect works with daily: OAuth 2.0, OIDC, SAML 2.0, LDAP, Kerberos, and SCIM.

## OAuth 2.0 — Delegated Authorization

OAuth 2.0 (RFC 6749) lets a client obtain **access tokens** that represent permission to act **on behalf of a resource owner** (usually a user) — or on its own behalf — without sharing the password. It is an *authorization* framework, not an authentication protocol.

### Roles

| Role | Meaning |
| --- | --- |
| Resource owner | Entity that can grant access (usually the user) |
| Resource server | API that protects resources; validates access tokens |
| Client | Application requesting access on the owner's behalf |
| Authorization server | Issues tokens after authenticating owner/client |

### Grant types (how a client obtains a token)

| Grant | Who | Typical use | Notes |
| --- | --- | --- | --- |
| Authorization code | User + confidential client | Web apps, mobile, SPAs | Most common; **use PKCE** (RFC 7636), mandatory for public clients |
| Implicit | User, in-browser | Legacy SPAs | Deprecated by **RFC 9700 §2.1.2**: "*clients SHOULD NOT use the implicit grant (response type `token`) or other response types issuing access tokens in the authorization response*". Tokens in the URL fragment; avoid — use code + PKCE |
| Resource owner password (ROPC) | User gives username/password to client | Legacy/migration only | Deprecated by **RFC 9700 §2.4**, in the strongest wording the document uses: "*the resource owner password credentials grant MUST NOT be used* … this grant type insecurely exposes the credentials of the resource owner to the client". Migration only, never for new clients |
| Client credentials | No user (machine) | Server-to-server, cron jobs, APIs | Client authenticates itself; no refresh token for user context |
| Refresh token | Previously authenticated user | Getting new access tokens | Not for client-credentials flow |
| Device authorization | User on limited-input device | Smart TVs, CLI logins | User approves on another device (RFC 8628) |

> **Where "deprecated" comes from, and what OAuth 2.1 is.** The two "avoid" entries above are
> not folklore: **RFC 9700, *Best Current Practice for OAuth 2.0 Security* (January 2025)** is
> the document that says so — it "deprecates some modes of operation that are deemed less secure
> or even insecure", and §§2.1.2 and 2.4 are the clauses quoted in the table. **OAuth 2.1** is
> the other name you will hear: it is
> [*The OAuth 2.1 Authorization Framework*](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/),
> still an **Internet-Draft** (`draft-ietf-oauth-v2-1`) rather than a published RFC, which folds
> RFC 9700's best practice and PKCE into the core specification and drops the two grants above
> from it. Cite it as a draft with its number, not as a standard — "required by OAuth 2.1" is
> not yet a sentence you can write.

### Endpoints and token response

| Item | Value |
| --- | --- |
| Authorization endpoint | Interactive: `GET /authorize?response_type=code&client_id=...&redirect_uri=...&scope=...&state=...` |
| Token endpoint | `POST /token` with `grant_type`, code/credentials, and client auth |
| Token response fields | `access_token`, `token_type` (usually `Bearer`), `expires_in`, optional `refresh_token`, `scope` |
| Errors | `invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope` |

```bash
# Concept-level token request (client credentials), e.g. Keycloak:
curl -X POST https://idp.example/realms/lab-realm/protocol/openid-connect/token \
  -u client-id:client-secret \
  -d "grant_type=client_credentials"
```

## OIDC — OpenID Connect (Authentication on top of OAuth 2.0)

OIDC adds an **ID token** (a JWT proving *who the user is*) and a **UserInfo endpoint**. Built on OAuth 2.0; it is the modern replacement for SAML in most web scenarios.

### Flows

| Flow | response_type | Best for |
| --- | --- | --- |
| Authorization code (+ PKCE) | `code` | Server-side and native apps, SPAs (with PKCE) — recommended default |
| Implicit | `id_token token` | Legacy; tokens in URL fragment — avoid |
| Hybrid | `code id_token`, `code token`, etc. | Special cases needing early id_token |

### ID token claims (JWT payload)

| Claim | Meaning |
| --- | --- |
| `iss` | Issuer URL (must match the IdP's discovery issuer) |
| `sub` | Stable, unique subject identifier of the user |
| `aud` | Audience — the client ID that must accept this token |
| `exp`, `iat` | Expiry and issued-at times (validate `exp`!) |
| `nonce` | Binds token to the login request; replay protection |
| `auth_time` | When the user last authenticated (for step-up checks) |
| `azp` | Authorized party (when `aud` has multiple values) |
| `at_hash`, `c_hash` | Hashes binding ID token to access token / code |
| Standard profile | `name`, `given_name`, `family_name`, `preferred_username`, `email`, `email_verified`, `phone_number`, `address` |

### Key endpoints and scopes

| Item | Value |
| --- | --- |
| Discovery | `GET /.well-known/openid-configuration` (list issuer, auth/token/userinfo/jwks endpoints) |
| Required scope | `openid` (plus `profile`, `email`, `address`, `phone` as needed) |
| UserInfo | `GET /userinfo` with the access token → profile claims |
| JWKS | *not an endpoint of its own*: the discovery document's `jwks_uri` field names the URL that serves the public keys used to verify token signatures (Keycloak's happens to be `/…/protocol/openid-connect/certs`) |

### OIDC vs. OAuth in one line

OAuth 2.0 grants **API access**; OIDC tells the client **who the user is**. OIDC *uses* OAuth; the reverse is not true.

## SAML 2.0 — Security Assertion Markup Language

XML-based standard for **federation** (web SSO across organizations). Predates OIDC; still dominant for enterprise SaaS and government.

### Vocabulary

| Term | Meaning |
| --- | --- |
| IdP (Identity Provider) | Authenticates users and issues assertions |
| SP (Service Provider) | Trusts the IdP; grants access to its app |
| Assertion | XML document: statements about a subject (user) |
| AuthnStatement | "This subject authenticated this way at this time" |
| AttributeStatement | Name/value attributes about the subject (email, groups) |
| AuthnRequest / Response | The SSO request / response messages |
| ACS (Assertion Consumer Service) URL | SP endpoint that **receives the SAML response**. It is the *destination*, not the trust anchor: what the SP actually trusts is the IdP's **signing certificate**, pinned from its metadata (Phase 05). Confusing the two is how an SP ends up validating a response against whatever key the response itself carries |
| Binding | How messages travel: HTTP-Redirect (request), HTTP-POST (response, common), Artifact |
| Metadata | XML describing an entity: endpoints, certificates, entityID |
| EntityID | Global name of an IdP or SP |

### SSO flow (SP-initiated, the common case)

1. User hits SP; the SP sends an `AuthnRequest` to the IdP's SSO endpoint over **HTTP-Redirect** (SAML's own *Redirect* binding). Signing is **optional and behaviour-dependent** here: if the SP signs it, the signature travels as URL query parameters (`SigAlg`, `Signature`) over the *redirect* query string, not as XML-DSig inside the message, so the two parties must agree on the exact canonicalisation in advance. Many SP-initiated deployments sign nothing at all and rely on the signed *response* instead — so "signed AuthnRequest" is a configuration fact to verify, not a property of the binding.
2. IdP authenticates the user (password, MFA, etc.).
3. IdP builds a signed `<samlp:Response>` with an assertion and POSTs it to the SP's **ACS URL**.
4. SP validates signature, assertion conditions (`NotBefore`/`NotOnOrAfter`), and audience; creates a session.

### One-liner differences vs. OIDC

| | SAML 2.0 | OIDC |
| --- | --- | --- |
| Format | XML | JSON/JWT |
| Transport | Browser redirects/POSTs | HTTP + redirects |
| Typical users | Enterprise, government | Web/mobile/cloud apps, consumer |

## LDAP — Directory Access

LDAP (Lightweight Directory Access Protocol) reads/writes **directory** data — the identity store (OpenLDAP, Active Directory, 389 DS).

| Term | Example / meaning |
| --- | --- |
| Entry | One record in the tree |
| DN (distinguished name) | Full path: `cn=alice,ou=people,dc=example,dc=com` |
| RDN | Relative name within parent: `cn=alice` |
| Base DN | Search starting point: `dc=example,dc=com` |
| Object class | Schema rule for an entry: `inetOrgPerson`, `organizationalUnit` |
| Attribute | Field: `uid`, `cn`, `mail`, `memberOf` |
| Bind | Authenticate with DN + password (or SASL) |
| Ports | 389 (LDAP), 636 (LDAPS), 3268/3269 (AD Global Catalog) |

### Core operations

`bind` (authenticate) · `search` · `add` · `modify` · `delete` · `compare`

### Filter examples

| Filter | Matches |
| --- | --- |
| `(objectClass=person)` | All person entries |
| `(&(objectClass=person)(mail=alice@example.com))` | AND |
| `(\|(uid=alice)(uid=bob))` | OR |
| `(!(memberOf=cn=admins,...))` | NOT |

```bash
ldapsearch -x -H ldap://localhost:389 -b "dc=example,dc=com" \
  "(uid=alice)" mail memberOf
```

Note: LDAP **authenticates** (bind) and stores identity, but web SSO needs an IdP layer (Keycloak, AD FS/Entra) on top — LDAP is not OIDC/SAML.

## Kerberos — Network Authentication

Symmetric-key, ticket-based authentication (RFC 4120); the authentication engine inside Active Directory. Password never crosses the network; instead the KDC issues tickets encrypted with keys derived from passwords.

| Term | Meaning |
| --- | --- |
| KDC | Key Distribution Center (AS + TGS in AD: the DC) |
| AS | Authentication Service — issues the TGT after password check |
| TGS | Ticket-Granting Service — issues service tickets |
| TGT | Ticket-Granting Ticket: proves you authenticated |
| Service ticket (ST) | Lets you access one service (SPN) |
| Principal | Identity: `user@REALM`, `host/server@REALM`, `service/spn@REALM` |
| Realm | Kerberos domain (uppercase): `EXAMPLE.COM` |
| SPN | Service principal name bound to the service account |
| Keytab | File with service keys (machine auth, services) |
| Authenticator | Timestamp proof the ticket owner is present |
| Ports | KDC 88 (TCP/UDP), kpasswd 464, Kerberos change 749 |

### Flow

1. **AS-REQ/AS-REP:** client → AS: "I am alice@EXAMPLE.COM"; AS returns TGT (encrypted with KDC key).
2. **TGS-REQ/TGS-REP:** client → TGS with TGT + SPN; gets service ticket for that SPN.
3. **AP-REQ/AP-REP:** client presents service ticket + authenticator to the service; service verifies and (optionally) replies.

Clock skew tolerance (~5 min) is required — tickets carry timestamps. **Security context (AD attacks):** forged TGTs ("golden ticket") or service tickets ("silver ticket") abuse a stolen KRBTGT/service key. **Kerberoasting** is narrower than it is usually stated: it requests a TGS for a service that has an **SPN**, then cracks the service account's key *offline* — and it only works where that key is derived from a **password a human chose**. Three qualifications matter in practice: an account with no SPN has no ticket to roast; an account whose key is machine-generated and rotated (a **gMSA**, or a machine account with a 120-character random password) is not crackable this way, which is exactly why gMSAs are a common remediation; and RC4-encrypted tickets (etype 23) crack far faster than AES, so disabling RC4 and requiring AES reduces the exposure even before you rotate the password. A finding that says "Kerberoasting exposes our service accounts" without naming the SPN-bearing, password-keyed accounts is a finding nobody can act on.

## SCIM — Provisioning (System for Cross-domain Identity Management)

SCIM 2.0 (RFC 7643/7644) is a REST API for **creating, updating, and deprovisioning** identities between systems — the IdP pushes accounts to SaaS apps, or directories sync.

| Item | Value |
| --- | --- |
| Resources | `/Users`, `/Groups`, plus `/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes`, `/Bulk` |
| Methods | `GET` (list/retrieve), `POST` (create), `PUT` (replace), `PATCH` (partial), `DELETE` |
| Auth | Bearer token (or OAuth 2.0) over HTTPS |
| Pagination/filter | `filter`, `startIndex`, `count`, `sortBy` |
| Core schema | `urn:ietf:params:scim:schemas:core:2.0:User` (plus `...:User:enterprise` extension) |
| Core attributes | `userName`, `name`, `emails`, `active`, `groups`, `meta` |

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "alice",
  "active": true,
  "emails": [{"value": "alice@example.com", "primary": true}],
  "name": {"givenName": "Alice", "familyName": "Example"}
}
```

Provisioning pattern: IdP detects a new user → `POST /Users` on the target → target returns the SCIM user with `id`; updates use `PATCH`/`PUT`; deactivation sets `"active": false` (or `DELETE`) — this is how deprovisioning (leaver) is automated.

> **`"active": false` is not the whole of deprovisioning.** RFC 7643 §4.1.1 defines `active` as a boolean on the *account* — "specifying `false` … indicates that the user should be prevented from accessing any resource". That is a strong statement about future access and a weak one about the present: the target app is entitled to honour it, but nothing in SCIM revokes sessions, closes refresh tokens, or expires an access token that has already been issued. Deprovisioning is therefore **three** operations, and the phase that owns lifecycle (Phase 01) says the same: set `active: false`, **revoke the principal's sessions and tokens at every connected app**, and confirm the account is no longer able to authenticate. A runbook that does only the first produces the most common leaver incident there is — an account that is "disabled" while a live session keeps working.

## Common Mistakes & Tips

- **Mistake:** using OAuth 2.0 alone and treating the access token as "logged in". **Tip:** use OIDC when you need identity; check the ID token, not just the access token.
- **Mistake:** skipping `state`/`nonce` validation. **Tip:** both are anti-replay/CSRF controls; a callback that ignores them is vulnerable.
- **Mistake:** trusting a JWT without validating signature, issuer, audience, and expiry. **Tip:** verify against the IdP's `jwks_uri` keys; never trust `alg: none`, and pin the algorithm you accept rather than reading it from the token. Be precise about what you are validating: an ID token or access token is a **JWS** (RFC 7515) carrying JWT claims (RFC 7519), and "decoding the payload" is not validation — the signature check is. A **JWE** (RFC 7516) is a different animal: five segments, encrypted payload, unreadable without the key, so code that expects to base64-decode the middle segment will simply fail rather than silently trust it.
- **Mistake:** confusing token *types*: access token vs. refresh token vs. ID token. **Tip:** ID = who, access = what you may do, refresh = get a new access token.
- **Mistake:** assuming SAML and OIDC assertions/tokens are interchangeable. **Tip:** know which your target apps support; hybrid estates run both.
- **Mistake:** mixing up the roles: LDAP *stores* and *binds*; Kerberos *authenticates* in the domain; OIDC/SAML *federate to web apps*; SCIM *provisions*. Choose per problem, not by fashion.
- **Mistake:** in Kerberos deployments, forgetting clock sync. **Tip:** keep hosts within the tolerated skew or tickets silently fail.

## Checklist / Self-Test

- [ ] I can name the four OAuth 2.0 roles and the main grant types with a use case each.
- [ ] I can explain why PKCE is required for public clients.
- [ ] I can list five ID token claims and what each validates.
- [ ] I can describe the SAML SSO flow and the role of the ACS URL.
- [ ] I can decode an LDAP DN and write a simple search filter.
- [ ] I can walk through AS → TGS → service ticket and name the AD attacks on tickets.
- [ ] I can describe a SCIM create/update/deactivate sequence.
- [ ] I can choose between SAML 2.0 and OIDC for a given integration scenario.

---

## Further Resources

- OAuth 2.0: https://oauth.net/2/
- RFC 6749 (OAuth 2.0): https://www.rfc-editor.org/rfc/rfc6749
- RFC 9700 (Best Current Practice for OAuth 2.0 Security, January 2025 — the source of the deprecations above): https://www.rfc-editor.org/rfc/rfc9700
- OAuth 2.1 (still an Internet-Draft, `draft-ietf-oauth-v2-1` — cite it as a draft): https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/
- RFC 7636 (PKCE): https://www.rfc-editor.org/rfc/rfc7636
- OpenID Foundation / OIDC spec: https://openid.net/connect/
- **JWT is a container, not a signature.** Three different RFCs, and every validation this sheet teaches is the *signature* one:
  - RFC 7519 (JWT) — the claims container and its claim semantics: https://www.rfc-editor.org/rfc/rfc7519
  - RFC 7515 (JWS, JSON Web Signature) — the compact three-segment `header.payload.signature` form an ID token or access token uses: https://www.rfc-editor.org/rfc/rfc7515
  - RFC 7516 (JWE, JSON Web Encryption) — the **five**-segment encrypted form, whose payload is ciphertext and therefore not readable at all without the key: https://www.rfc-editor.org/rfc/rfc7516
  - Practical test: count the dots. Three segments and you can base64-read the middle one → JWS, and signature verification is the check that matters. Five segments → JWE, and "decoding the payload to look at the claims" is not something you can do without the decryption key; an encrypted token is opaque to the client on purpose.
- OASIS SAML 2.0: https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=security
- RFC 7644 (SCIM 2.0 protocol; RFC 7643 is the schema, and §4.1.1 defines `active`): https://www.rfc-editor.org/rfc/rfc7644
- RFC 4120 (Kerberos): https://www.rfc-editor.org/rfc/rfc4120
- Keycloak documentation: https://www.keycloak.org/documentation
- NIST SP 800-207 (Zero Trust Architecture): https://csrc.nist.gov/pubs/sp/800/207/final

> **Verification:** the RFC facts above were checked on **2026-09-19** by fetching the texts
> from `rfc-editor.org` (all HTTP 200): RFC 9700, *Best Current Practice for OAuth 2.0
> Security*, dated **January 2025**, whose §2.4 reads *"The resource owner password credentials
> grant [RFC6749] MUST NOT be used"* and whose §2.1.2 reads *"clients SHOULD NOT use the
> implicit grant (response type token) …"*; RFC 7515, 7516 and 7519 (JWS, JWE, JWT); RFC 7643
> (SCIM schema); and `draft-ietf-oauth-v2-1-13` (28 May 2025), *The OAuth 2.1 Authorization
> Framework*, status **Internet-Draft**, Standards Track — **not** an RFC. The SCIM `active`
> semantics used in the note about deprovisioning are taken from RFC 7643 §4.1.1.
