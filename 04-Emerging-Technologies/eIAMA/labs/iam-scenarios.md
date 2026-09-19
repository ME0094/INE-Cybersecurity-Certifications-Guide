# IAM Hands-on Scenarios — A Local Identity Lab with Keycloak

> eIAMA · labs — INE-Cybersecurity-Certifications-Guide
> Everything runs locally in Docker. Authorized lab context only — use throwaway credentials and do not connect this lab to any production system.

## Purpose

Theory becomes durable knowledge when you watch the protocol messages with your own eyes. This lab builds a small, disposable identity environment with **Keycloak** (open-source identity and access management) in Docker and then walks through the scenarios an IAM architect must be able to demonstrate:

1. Realm and user setup (identity store basics).
2. SSO with **OIDC** for a small test application (authorization code flow).
3. **MFA** with a TOTP authenticator.
4. **Roles and clients** and how they surface in tokens.
5. **Federation** between two realms through identity brokering.

### Objectives

- Run a standards-compliant IdP locally without external accounts.
- Explain each step in terms of OAuth 2.0 / OIDC concepts (realm, client, grant, scope, claim).
- See real authorization codes, tokens, and token payloads.
- Recreate each scenario from memory after finishing (the real test of learning).

### Expected outcomes

- You can log into a test app with SSO and explain where the session lives.
- You can enroll and verify TOTP MFA and explain the second-factor step in the flow.
- You can map a role to a user and see it appear in a token.
- You can federate a user from realm A into realm B and explain what the broker does.

## Prerequisites

- Docker (or Podman) with a working local engine.
- A web browser, a terminal, and (for MFA) an authenticator app on your phone or a TOTP-capable tool.
- Python 3 with `flask` and `requests` installed only for the SSO test app (`pip install flask requests`).

## Step 0 — Start the identity server

Run Keycloak in development mode (uses an embedded database — fine for a lab, never for production):

```bash
docker run -d --name eiama-keycloak -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.1 start-dev
```

> **Version note — the two environment variables in that block are the current names, not the
> historical ones.** Keycloak **26.0** deprecated `KEYCLOAK_ADMIN` and
> `KEYCLOAK_ADMIN_PASSWORD` in favour of **`KC_BOOTSTRAP_ADMIN_USERNAME`** and
> **`KC_BOOTSTRAP_ADMIN_PASSWORD`**, and the new pair is the supported form from 26.0 onward;
> this lab uses it.
>
> What actually happens if you paste a command from a Keycloak ≤25 guide was measured rather
> than assumed (see the verification note at the end of this file). On **26.1.0** the old names
> still work: the server logs two deprecation warnings —
> `KC-SERVICES0110: Environment variable 'KEYCLOAK_ADMIN' is deprecated, use 'KC_BOOTSTRAP_ADMIN_USERNAME' instead`
> — and then bootstraps the admin anyway, so `admin`/`admin` logs in successfully. They are an
> alias on their way out, not a broken flag. The failure you will actually meet is the other
> one: with **neither** pair set, there is no usable admin at all and the token endpoint
> answers `401 invalid_grant / Invalid user credentials` — which is why the note in the console
> step below tells you to read the log instead of assuming a networking problem. Write the new
> names, treat the warning as the deadline, and do not build a lab that depends on the alias.

Verify it is up (wait a few seconds on first boot):

```bash
curl -s http://localhost:8080/realms/master/.well-known/openid-configuration | head -c 300
```

**Expected:** a JSON document listing `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, and more. This `.well-known` document is the machine-readable contract every OIDC client uses — remember it.

Open the admin console at http://localhost:8080/admin and sign in with the username and password you passed in `KC_BOOTSTRAP_ADMIN_USERNAME` / `KC_BOOTSTRAP_ADMIN_PASSWORD` — `admin` / `admin` if you used the block above. If that pair is rejected, read the container log first (`docker logs eiama-keycloak | grep -iE 'admin|bootstrap'`): on 26.1.0 a rejected login means the bootstrap variables were not the ones the server read, and the log says which names it recognised and whether it created an admin at all.

## Scenario 1 — Realm and test user

A **realm** is an isolated identity domain: its own users, clients, roles, and policies. Think of it as a tenant.

1. In the admin console, create a realm named `lab-realm` (top-left dropdown → *Create realm*).
2. Under *Users → Add user*, create `alice` (do not set a password yet).
3. In the *Credentials* tab of the user, set a temporary password (e.g., `ChangeMe!2024`) and clear "Temporary".
4. Visit the account console: http://localhost:8080/realms/lab-realm/account/ and sign in as `alice`.

**Expected:** you can sign in and see Alice's profile. You just authenticated against a realm — the account console is itself an OIDC client of that realm.

## Scenario 2 — SSO with OIDC (authorization code flow)

Register a confidential client that represents a test application, then run a tiny OIDC client app against it.

**Keycloak client config** (Realm `lab-realm` → *Clients → Create client*):

- Client ID: `test-app`, Client authentication: **On** (confidential), Standard flow: **On**, others off.
- Valid redirect URIs: `http://localhost:5001/callback`
- After creation, copy the client secret (Clients → `test-app` → *Credentials*).

**Minimal OIDC test app** (`oidc-app.py`) that performs the authorization code flow with the realm:

```python
import json, os, secrets
from flask import Flask, redirect, request, session
import jwt                                   # PyJWT
import requests
from jwt import PyJWKClient

CLIENT_ID = "test-app"
CLIENT_SECRET = os.environ["OIDC_CLIENT_SECRET"]     # never hard-code it in the file
REDIRECT_URI = "http://localhost:5001/callback"
ISSUER = "http://localhost:8080/realms/lab-realm"

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET"]          # lab only, but from the environment

# The realm's public keys, fetched from the discovery document rather than assumed.
DISCOVERY = requests.get(f"{ISSUER}/.well-known/openid-configuration", timeout=10).json()
JWKS_CLIENT = PyJWKClient(DISCOVERY["jwks_uri"])     # caches keys, refetches on kid miss
ALGORITHMS = ["RS256"]                               # pin it: never accept the token's `alg`

@app.route("/")
def home():
    if "claims" not in session:
        state = secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(16)            # binds the ID token to THIS request
        session["state"] = state
        session["nonce"] = nonce
        url = requests.Request("GET", DISCOVERY["authorization_endpoint"], params={
            "response_type": "code", "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI, "scope": "openid profile email",
            "state": state, "nonce": nonce}).prepare().url
        return redirect(url)
    return "<pre>" + json.dumps(session["claims"], indent=2) + "</pre>"

@app.route("/callback")
def callback():
    if request.args.get("state") != session.pop("state", None):
        return "state mismatch (possible CSRF)", 400
    r = requests.post(DISCOVERY["token_endpoint"], data={
        "grant_type": "authorization_code", "code": request.args.get("code"),
        "redirect_uri": REDIRECT_URI, "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET}, timeout=10)
    id_token = r.json()["id_token"]

    # Verify — do not decode. The signature is checked against the realm's JWKS, and the
    # claims that make the token *mean* something are checked explicitly:
    #   signature   proves the realm issued this token and nobody edited it
    #   iss          proves it came from THIS realm and not another one you also trust
    #   aud          proves it was issued for THIS client, not replayed from another app
    #   exp / iat    prove it is current (PyJWT enforces these by default)
    #   nonce        proves it answers the login request this session started
    # Skipping any of the five turns a login into an assertion by whoever holds the token.
    signing_key = JWKS_CLIENT.get_signing_key_from_jwt(id_token)
    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=ALGORITHMS,
        issuer=ISSUER,
        audience=CLIENT_ID,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )
    # `or ""` rather than a default: a token that carries an explicit `"nonce": null` must
    # produce a clean mismatch, not a TypeError that turns into a 500.
    if not secrets.compare_digest(claims.get("nonce") or "", session.pop("nonce", "") or ""):
        return "nonce mismatch (token replay or wrong login request)", 400
    session["claims"] = claims
    return redirect("/")

if __name__ == "__main__":
    app.run(port=5001)
```

**What the earlier version of this fragment did, and why it is worth naming.** It decoded the
ID token with `base64.urlsafe_b64decode` on the middle segment and put the result straight
into the session — no signature check, no `iss`, no `aud`, no `exp`, no `nonce`. Everything it
displayed was attacker-controlled: anyone could hand that callback a token of their own
construction and the app would show whatever claims they chose. It also contradicted the rest
of this lab, which asks for `nonce` in the checklist below and points at the "never trust a
JWT without validating signature, issuer, audience and expiry" rule in
[../cheatsheets/iam-protocols.md](../cheatsheets/iam-protocols.md). Decoding is not verifying,
and a token you decoded is a claim someone else wrote.

Run it, open http://localhost:5001, and sign in as `alice`.

**Expected:** the app redirects to the Keycloak login page (note the `/realms/lab-realm/protocol/openid-connect/auth?...` URL), and after login it shows the decoded ID token claims: `sub` (Alice's stable subject), `preferred_username`, `email`, and an `aud` of `test-app`.

**Watch in the browser address bar:**

- Before login: `/auth?response_type=code&client_id=test-app&redirect_uri=...&scope=openid%20profile%20email&state=...`
- After login: `/callback?code=...&state=...` — the *authorization code*, exchanged server-side by the app at the token endpoint.

**SSO check:** open the account console in a second tab (same browser). You should *not* be asked to log in again — the Keycloak SSO session covers both clients.

## Scenario 3 — MFA with TOTP

1. In the admin console (Realm `lab-realm`), edit user `alice`.
2. Under *Required actions*, add **Configure OTP** and update the user.
3. Log out everywhere (account console → sign out, or clear cookies) and sign in again as `alice`.
4. The login flow now forces enrollment: scan the QR code with an authenticator app, enter a code, and confirm.
5. Sign out and sign in once more.

**Expected:** after the password step, Keycloak asks for the one-time code — authentication now requires *something you know* plus *something you have*. Without the second factor the login fails.

## Scenario 4 — Roles and clients in tokens

Roles group permissions; Keycloak distinguishes **realm roles** (apply across the realm) and **client roles** (scoped to one client). Mappers decide which roles appear in which token.

1. *Realm roles → Create role*: `lab-admin`.
2. *Clients → test-app → Client scopes* is where role mappers live; the default `roles` scope usually already maps realm roles into the access token.
3. Assign the role: *Users → alice → Role mapping → Assign role* → pick `lab-admin` (realm role) and assign.
4. Log in to the test app again and inspect the **access token** payload as well as the ID token. For inspection only, decoding without verifying is fine — you are reading your own token in your own lab, and `python3 -c "import base64,json,sys; p=sys.argv[1].split('.')[1]; p+='='*(-len(p)%4); print(json.dumps(json.loads(base64.urlsafe_b64decode(p)), indent=2))" <token>` does it. Note the difference from the callback above: **reading** a token for a look is debug output; **acting** on the claims it carries is authentication, and that path verifies the signature and the claims first.

**Expected:** the access token contains a `realm_access` claim like `{"roles": ["lab-admin", "default-roles-lab-realm", "offline_access", "uma_authorization"]}`. The application authorizes Alice because the token says so — that is token-based authorization in action.

## Scenario 5 — Client credentials (machine-to-machine)

Not every actor is a human. Test the flow a service uses to get a token for itself:

```bash
curl -s -X POST http://localhost:8080/realms/lab-realm/protocol/openid-connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=test-app" \
  -d "client_secret=REPLACE_WITH_REALM_CLIENT_SECRET"
```

**Expected:** a JSON response with `access_token`, `expires_in`, and `token_type` — but **no** `id_token` and no `refresh_token`. There is no user in this exchange; the token represents the client itself (check `azp`/`aud` when decoded).

## Scenario 6 — Federation between two realms

Simulate two organizations trusting each other: realm `org-a` hosts the users; realm `org-b` (the "broker") lets them in through an OIDC Identity Provider.

1. In `org-a`, create client `broker-b` (confidential, standard flow) with redirect URI `http://localhost:8080/realms/org-b/broker/org-a/endpoint` and note its secret.
2. In `org-a`, create user `bob`.
3. In `org-b`, go to *Identity Providers → Add provider → OpenID Connect v1.0*. Set alias `org-a`, and paste the discovery URL: `http://localhost:8080/realms/org-a/.well-known/openid-configuration`. Keycloak auto-fills the endpoints. Provide the client ID/secret of `broker-b`.
4. Open the org-b account console (http://localhost:8080/realms/org-b/account/) and click *Sign in with org-a*.

**Expected:** you are redirected to the org-a login page (cross-realm!), authenticate as `bob`, and land back in org-b authenticated as a **federated** identity — org-b never stored Bob's password, only a trust relationship and (optionally) a linked local user.

**Watch-outs:** the broker redirect URI must match exactly; if the alias changes, so does the endpoint path.

## Cleanup

```bash
docker stop eiama-keycloak && docker rm eiama-keycloak
```

Remove the container when finished so no throwaway credentials linger.

## Common Mistakes & Tips

- **Mistake:** using `start-dev` for anything real. **Tip:** development mode is for labs only; production deployments need a database and a hostname config (`start` with `--db` options).
- **Mistake:** mismatched redirect URIs. **Tip:** OIDC validates `redirect_uri` byte-for-byte; `http://localhost:5001/callback` is not `http://localhost:5001/callback/`.
- **Mistake:** skipping `state` (or nonce) in your own client. **Tip:** `state` binds the callback to the login request and blocks login CSRF.
- **Mistake:** confusing the ID token with the access token. **Tip:** the ID token tells *the client who the user is* (`aud` = client); the access token is what the client presents to an API/resource server.
- **Mistake:** treating client secrets as safe in browsers. **Tip:** a confidential client must never run in a SPA; public clients use PKCE instead.
- **Mistake:** expecting a realm role to appear in a client's token automatically in every configuration. **Tip:** check the client's role mappers/scopes; token content is configurable, so verify, don't assume.
- **Mistake:** reusing the master realm for real users. **Tip:** the master realm exists to administer the server; create dedicated realms for actual identities.

## Checklist / Self-Test

- [ ] I started Keycloak in Docker and reached the admin console without errors.
- [ ] I created a realm and a user and authenticated at the account console.
- [ ] I registered an OIDC client and ran the authorization code flow end to end.
- [ ] I can point to the `state` parameter in my app's callback handling and explain it.
- [ ] I decoded an ID token and identified `iss`, `sub`, `aud`, and `exp` claims.
- [ ] I enforced TOTP as a required action and verified a second-factor login.
- [ ] I assigned a realm role and saw it appear in the access token.
- [ ] I obtained a client-credentials token and explained how it differs from a user token.
- [ ] I federated a user between two realms via an OIDC Identity Provider.
- [ ] I cleaned up the lab container afterward.

---

## Further Resources

- Keycloak documentation: https://www.keycloak.org/documentation
- Keycloak getting started (Docker): https://www.keycloak.org/getting-started/getting-started-docker
- Keycloak Docker image (quay.io): https://quay.io/repository/keycloak/keycloak
- OIDC specification: https://openid.net/connect/
- RFC 6749 (OAuth 2.0): https://www.rfc-editor.org/rfc/rfc6749
- RFC 7636 (PKCE): https://www.rfc-editor.org/rfc/rfc7636
- NIST SP 800-207 (Zero Trust Architecture): https://csrc.nist.gov/pubs/sp/800/207/final

> **Verification.** Both corrections in this file were executed, on **2026-09-19**, under
> Ubuntu 24.04 with **Java 21.0.12** and **Keycloak 26.1.0** (the release zip, extracted in
> `/tmp`, `kc.sh start-dev --http-port=8180`).
>
> **Step 0 / the admin variables.** Three runs, each against a wiped `data/`, authenticated with
> a real `admin-cli` password grant at the realm's token endpoint:
>
> | Variables set | Log | `admin`/`admin` token | `GET /admin/realms` |
> | --- | --- | --- | --- |
> | `KEYCLOAK_ADMIN` + `KEYCLOAK_ADMIN_PASSWORD` | `WARN KC-SERVICES0110: Environment variable 'KEYCLOAK_ADMIN' is deprecated, use 'KC_BOOTSTRAP_ADMIN_USERNAME' instead` (and the password equivalent), then `INFO KC-SERVICES0077: Created temporary admin user with username admin` | **HTTP 200** | **HTTP 200** |
> | `KC_BOOTSTRAP_ADMIN_USERNAME` + `KC_BOOTSTRAP_ADMIN_PASSWORD` | `INFO KC-SERVICES0077: Created temporary admin user with username admin`, and *no* deprecation warning | **HTTP 200** | **HTTP 200** |
> | *neither* (control) | no admin-creation line | **HTTP 401**, `{"error":"invalid_grant","error_description":"Invalid user credentials"}` | — |
>
> So on **26.1.0 the old names are deprecated but still honoured**, which is why the version note
> above is worded as "an alias on its way out" rather than "no longer works": the audit that
> prompted this change asserted the latter, and the measurement does not support it. The
> server banner was `Keycloak 26.1.0 on JVM (powered by Quarkus 3.15.2) started in 24.676s.
> Listening on: http://localhost:8180`, and the discovery document returned
> `"issuer":"http://localhost:8180/realms/master"` with
> `"jwks_uri":"http://localhost:8180/realms/master/protocol/openid-connect/certs"`.
>
> **Scenario 2 / the callback.** PyJWT was exercised against a locally generated RSA key
> standing in for the realm's JWKS (no Keycloak needed for this half), with the corrected
> callback logic run against eight tokens — on **both** PyJWT 2.7.0 and PyJWT 2.14.0, with
> identical results. Accepted: the valid token
> (`ACCEPTED: alice / sub=a1b2c3-alice`). Rejected with a named error: forged signature
> (`InvalidSignatureError`), wrong issuer (`InvalidIssuerError`), wrong audience
> (`InvalidAudienceError`), expired (`ExpiredSignatureError`), `alg: none`
> (`InvalidAlgorithmError: The specified alg value is not allowed`), and both nonce cases
> (`nonce mismatch (token replay or wrong login request)`). The pre-fix code — base64-decode
> the middle segment and trust it — accepted **all eight**, including the forged token
> (`'mallory'`) and the unsigned `alg: none` token. The route itself was not served over HTTP
> with Flask; the verification is of the validation logic the callback runs, from the token
> onwards.
