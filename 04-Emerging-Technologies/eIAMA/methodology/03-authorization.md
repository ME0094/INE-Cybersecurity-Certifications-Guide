# Authorization — eIAMA Methodology Phase 03

> eIAMA · Methodology · INE Cybersecurity Certifications Guide (public-knowledge study notes; no exam/NDA material)

## Overview

Authorization (AuthZ) answers **"What may this authenticated identity do?"** Authentication (Phase 02) establishes *who*; authorization decides *whether* — for every action, on every resource, through every channel. The architect's job is to choose authorization models, centralize decision-making, and make enforcement auditable. Authorization flaws are among the most exploited vulnerability classes precisely because checks are often duplicated ad hoc in every application.

By the end of this phase you should be able to:

- Contrast RBAC, ABAC, and ReBAC and pick a model for a scenario.
- Explain the PDP/PEP pattern and where policy engines belong.
- Read and design OAuth 2.0 scope/consent flows with least privilege in mind.
- Identify privilege-escalation risks and the mitigations that stop them.
- Design access certifications that close the governance loop.

## Authorization Foundations

| Term | Meaning |
|---|---|
| Subject / principal | The identity requesting access (user, workload, service) |
| Resource / object | What is being accessed (file, API, VM, database row) |
| Action / operation | read, write, delete, execute, assume |
| Permission | An allowed (action, resource) pair |
| Role | A named collection of permissions (RBAC) |
| Policy | Rules that map subject/resource/context to allow/deny |
| Entitlement | A granted permission or role held by a specific identity |

Authorization is enforced at multiple layers — network, application, API, data, and cloud IAM — and they must tell a consistent story. A common failure is a strict API gateway but no object-level checks behind it (leading to IDOR/BOLA), or vice versa.

## RBAC vs. ABAC vs. ReBAC

- **RBAC** — permissions attach to *roles*; subjects get roles. Predictable and auditable, but static and prone to role explosion and accumulation.
- **ABAC** — allow/deny is computed from *attributes* of subject, resource, action, and environment (time, location, risk) via policies. Flexible and dynamic (NIST SP 800-162); complexity lives in attribute quality and policy management.
- **ReBAC (relationship-based access control)** — access follows *relationships* in a graph: "Ana is a *viewer* of folder X because she belongs to team Y, and folder X is *shared with* team Y." Popularized by Google's Zanzibar paper and implemented by systems like OpenFGA and Cedar; ideal for collaborative, resource-hierarchy, and multi-tenant sharing models.

| Dimension | RBAC | ABAC | ReBAC |
|---|---|---|---|
| Authorization primitive | Role ↔ permission | Policy over attributes | Relationship edges between entities |
| Change dynamics | Role assignment updates | Policy/attribute updates | Membership changes propagate through graph |
| Best suited for | Stable org structure, employee access at scale | Attribute-rich, classification-driven, cross-org | Sharing/collaboration, hierarchies, multi-tenant SaaS |
| Administration burden | Role explosion, assignment churn | Attribute governance, complex condition logic | Graph growth, indexing, permission fan-out |
| Audit story | Simple (role → user) | Attribute sprawl complicates | Rich: query "who can reach this object" |
| Typical examples | AD/Entra groups, cloud IAM roles | Cloud resource policies, data classification | Google Drive/Docs, GitHub teams, SaaS workspaces |

A conceptual ReBAC-style tuple set (OpenFGA-like):

```text
document:2024-report#viewer@team:finance          # team sees the doc
document:2024-report#viewer@user:ana              # Ana additionally
folder:fy2024#parent@document:2024-report         # doc lives in folder
team:finance#member@user:ana                      # Ana is in finance
# ReBAC answer: Ana can view 2024-report via team membership and folder traversal
```

Real deployments are **hybrid**: RBAC for broad organizational access, ABAC rules for sensitive data and dynamic conditions, ReBAC where the product is built around sharing.

## Policy Engines and the PDP/PEP Pattern

Authorization logic should be **centralized** rather than copy-pasted into every app. The classic pattern (from the XACML vocabulary, reused in NIST SP 800-162 and modern policy engines) separates:

- **PAP — Policy Administration Point:** where policies are authored and versioned (policy-as-code repos).
- **PDP — Policy Decision Point:** the engine that evaluates a request against policy and returns allow/deny.
- **PEP — Policy Enforcement Point:** the component in front of the resource that intercepts requests and enforces the decision.
- **PIP — Policy Information Point:** sources of attributes the PDP needs (directory, device DB, external context).

```text
 Client ──(1) request──► PEP ──(2) authorization request + context──► PDP
   ▲                        │                                            │
   │                        │                                            │ (3) fetch attrs
   │                        │                                            ▼
   │                        │                                          PIP (directory,
   │                        │                                           device, context)
   │                        │◄──────── (4) allow/deny ─────────────────┘
   │◄─── (5) enforce: allow (forward to resource) / deny ────│
```

Policies as code — a conceptual ABAC rule:

```json
{
  "name": "Finance team reads internal reports in business hours",
  "effect": "allow",
  "action": ["read", "list"],
  "resource": { "type": "report", "sensitivity": "internal" },
  "condition": {
    "all": [
      "subject.group == 'finance'",
      "subject.clearance >= resource.classification",
      { "time": { "gte": "08:00", "lte": "18:00", "tz": "Europe/Madrid" } }
    ]
  },
  "denyByDefault": true
}
```

Design notes: the PEP must be **trustworthy and ubiquitous** — every enforcement point you cannot control is a bypass; log every decision (allow *and* deny) for audit; and prefer fail-closed defaults.

## OAuth 2.0 Scopes and Consent

OAuth 2.0 is a *delegation* protocol: the resource owner authorizes a **client** to act on their behalf within limits. Roles: resource owner (user), client (app), authorization server, resource server.

- **Scopes** are the granular permissions a client requests — the token carries only the granted scopes.
- **Consent** is the resource owner's approval of the scoped delegation. First-party apps often rely on implicit admin consent; third-party apps get a consent screen.

```text
GET https://auth.example.com/authorize?
  response_type=code&                  # authorization code flow
  client_id=webapp-42&
  redirect_uri=https://app.example.com/callback&
  scope=openid%20profile%20email%20orders%3Aread&   # minimal, explicit
  state=random-csrf-token&             # binds the response to this login
  code_challenge=...&code_challenge_method=S256     # PKCE (recommended always)
```

Least privilege applies to clients too: request `orders:read`, not `orders:write` or `admin`; never `scope=*`. **Over-scoping** plus long-lived refresh tokens is how a stolen token becomes full account takeover. Treat the consent screen as a security boundary: mislabeled, combined, or "required" scopes train users to approve anything.

## Least Privilege

- **Principle:** every subject gets the *minimum* permissions needed for the current job, for the *minimum* time.
- **Standing vs. just-in-time (JIT):** permanent admin grants are the exception; privileged access should be requested, approved, time-boxed, and monitored (privileged access management / PIM concepts), with a tightly controlled break-glass path for emergencies.
- Least privilege spans users, **service accounts/workloads**, clients (scopes), and data (column/row level), not just "don't be domain admin."
- Enforce it with roles plus constraints: ABAC/ReBAC conditions, session restrictions, and revocation when context changes (device compliance lost → rights shrink).

## Privilege Escalation Risks

Two directions:

- **Vertical (privilege) escalation:** reaching a higher privilege than granted — e.g., a user toggles their own role to admin, exploits a misconfigured group inheritance, or abuses an over-privileged service account.
- **Horizontal (access) escalation:** reaching *other* users' data at the same privilege — classic IDOR/BOLA where the API trusts a client-supplied object id (`GET /api/orders/1001`) without an ownership check.

Contributing causes an architect must design against:

- Over-provisioned roles and default-everyone-admin cultures.
- Stale memberships from lifecycle gaps (Phase 01): leavers still in admin groups.
- Enforcement only in the UI, not in the API/data layer.
- Fail-open policies and deny-by-default violations.
- OAuth misconfiguration: over-broad scopes, missing `aud` validation, tokens exposed to the browser, permissive `redirect_uri`.
- Delegation chains where one over-privileged identity (service account, sync account) becomes a universal pass.

Mitigations: SoD matrices, JIT elevation with approval and recording, per-object authorization checks, centralized PDP with deny-by-default, and continuous access reviews (below).

## Access Certifications

Access certification is authorization's governance loop — the mechanism that forces periodic, accountable review of who holds what:

- **Campaign design:** define scope (app, role, group, or user), the *certifier* (manager, data owner, role owner), the evidence shown, and the cadence (privileged: quarterly; general: annual; plus event-triggered reviews on mover/leaver).
- **Reviewer decisions:** certify (keep), revoke, modify, or escalate; decisions must trigger automated remediation and leave an audit trail.
- **Fight rubber-stamping:** sample audits, risk-weighted review queues (privileged first), and automated attestation for low-risk entitlements.
- SoD conflicts are surfaced *during* the review, not just at request time.

Access reviews are the same engine as the lifecycle reviews in Phase 01 — certification is where "the role no longer matches the job" is finally detected.

## Common Mistakes & Tips

- **Mistake:** authorization checks scattered through code with no central policy. **Tip:** adopt a PDP/PEP pattern; keep the policy in one versioned place.
- **Mistake:** building everything with RBAC until role explosion, or ABAC until nobody can explain a decision. **Tip:** start with RBAC for org access, add ABAC/ReBAC only where the scenario demands it.
- **Mistake:** object-level access unprotected ("the gateway authenticated, so it's fine") → IDOR/BOLA. **Tip:** authorize the *resource*, not just the endpoint.
- **Mistake:** OAuth clients requesting far more scope than needed. **Tip:** enforce scope allowlists per client and audit granted scopes.
- **Mistake:** standing admin for everyone "just in case." **Tip:** JIT elevation, approvals, break-glass with monitoring.
- **Mistake:** reviews that produce reports but no remediation. **Tip:** wire revocation outcomes into the lifecycle engine automatically.

## Checklist / Self-test

- [ ] I can define subject, resource, action, permission, role, and policy.
- [ ] I can compare RBAC/ABAC/ReBAC across a scenario and justify the choice.
- [ ] I can draw the PAP/PDP/PEP/PIP flow and explain what each component does.
- [ ] I can parse an OAuth authorize URL and explain scope, consent, state, and PKCE.
- [ ] I can describe vertical and horizontal privilege escalation with realistic examples.
- [ ] I can design least-privilege/JIT controls and a break-glass exception path.
- [ ] I can design an access certification campaign with remediation hooks.

## Further resources

- NIST SP 800-162, *Guide to Attribute Based Access Control (ABAC)*: https://doi.org/10.6028/NIST.SP.800-162
- OAuth 2.0 Authorization Framework, RFC 6749: https://datatracker.ietf.org/doc/html/rfc6749
- OAuth.net — OAuth 2.0 overview and best practices: https://oauth.net/2/
- OpenFGA documentation (ReBAC): https://openfga.dev/docs
- Microsoft Entra ID documentation (role-based access and governance): https://learn.microsoft.com/en-us/entra/identity/
