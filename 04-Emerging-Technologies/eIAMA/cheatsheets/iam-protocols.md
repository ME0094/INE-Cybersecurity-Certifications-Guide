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
| Implicit | User, in-browser | Legacy SPAs | Deprecated; tokens in URL; avoid — use code + PKCE |
| Resource owner password (ROPC) | User gives username/password to client | Legacy/migration only | Discouraged; client sees the password |
| Client credentials | No user (machine) | Server-to-server, cron jobs, APIs | Client authenticates itself; no refresh token for user context |
| Refresh token | Previously authenticated user | Getting new access tokens | Not for client-credentials flow |
| Device authorization | User on limited-input device | Smart TVs, CLI logins | User approves on another device (RFC 8628) |

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
| JWKS | `GET /jwks` → public keys to verify token signatures |

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
| ACS (Assertion Consumer Service) URL | SP endpoint that **receives the SAML response** — the trust anchor of the SP |
| Binding | How messages travel: HTTP-Redirect (request), HTTP-POST (response, common), Artifact |
| Metadata | XML describing an entity: endpoints, certificates, entityID |
| EntityID | Global name of an IdP or SP |

### SSO flow (SP-initiated, the common case)

1. User hits SP; SP sends signed `AuthnRequest` (HTTP-Redirect) to IdP.
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
| `(|(uid=alice)(uid=bob))` | OR |
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

Clock skew tolerance (~5 min) is required — tickets carry timestamps. **Security context (AD attacks):** forged TGTs ("golden ticket") or service tickets ("silver ticket") abuse a stolen KRBTGT/service key; Kerberoasting cracks service account passwords from TGS-REP data. Architects must protect service accounts and monitor Kerberos.

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

## Common Mistakes & Tips

- **Mistake:** using OAuth 2.0 alone and treating the access token as "logged in". **Tip:** use OIDC when you need identity; check the ID token, not just the access token.
- **Mistake:** skipping `state`/`nonce` validation. **Tip:** both are anti-replay/CSRF controls; a callback that ignores them is vulnerable.
- **Mistake:** trusting a JWT without validating signature, issuer, audience, and expiry. **Tip:** verify against the IdP's JWKS; never trust `alg: none`.
- **Mistake:** confusing token *types*: access token vs. refresh token vs. ID token. **Tip:** ID = who, access = what you may do, refresh = get a new access token.
- **Mistake:** assuming SAML and OIDC assertions/tokens are interchangeable. **Tip:** know which your target apps support; hybrid estates run both.
- **Mistake:** mixing up the roles: LDAP *stores* and *binds*; Kerberos *authenticates* in the domain; OIDC/SAML *federate to web apps*; SCIM *provisions*. Choose per problem, not by fashion.
- **Mistake:** in Kerberos deployments, forgetting clock sync. **Tip:** keep hosts within the tolerated skew or tickets silently fail.

## Checklist / Self-test

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
- RFC 7636 (PKCE): https://www.rfc-editor.org/rfc/rfc7636
- OpenID Foundation / OIDC spec: https://openid.net/connect/
- RFC 7519 (JWT): https://www.rfc-editor.org/rfc/rfc7519
- OASIS SAML 2.0: https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=security
- RFC 7644 (SCIM 2.0): https://www.rfc-editor.org/rfc/rfc7644
- RFC 4120 (Kerberos): https://www.rfc-editor.org/rfc/rfc4120
- Keycloak documentation: https://www.keycloak.org/documentation
- NIST SP 800-207 (Zero Trust Architecture): https://csrc.nist.gov/pubs/sp/800/207/final
