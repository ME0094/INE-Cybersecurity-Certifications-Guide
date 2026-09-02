# Identity Lifecycle — eIAMA Methodology Phase 01

> eIAMA · Methodology · INE Cybersecurity Certifications Guide (public-knowledge study notes; no exam/NDA material)

## Overview

Identity lifecycle management (ILM) treats a digital identity as a governed asset that is created, changed, and eventually retired in step with the person, device, or workload it represents. An identity and access management (IAM) architect designs the state machine that connects **business events** (hire, transfer, termination) to **access outcomes** (account exists, has the right roles, no longer exists). This phase is the foundation for every other eIAMA phase: authentication, authorization, zero trust, and federation all assume that identities are accurate, timely, and minimal.

By the end of this phase you should be able to:

- Model the joiner / mover / leaver (JML) lifecycle and state what must happen at each event.
- Identify systems of record vs. authoritative attribute sources vs. enforcement points.
- Explain provisioning and deprovisioning patterns, including SCIM-based API provisioning.
- Contrast role-based (RBAC) and attribute-based (ABAC) authorization concepts.
- Design access reviews/certifications and defend identity hygiene practices.

## The Joiner–Mover–Leaver (JML) Model

JML is the classic lifecycle: an identity **joins** an organization, **moves** between roles or business units, and eventually **leaves**. Every event is a change in access that must be planned, executed, reviewed, and audited.

| Event | Typical trigger | Core actions |
|---|---|---|
| Joiner | New hire or contractor offer accepted (HR event) | Proof identity, provision account, assign minimal roles, enroll MFA, communicate credentials securely |
| Mover | Transfer, promotion, project change, re-org | Review and *adjust* entitlements — remove old-org access, add new-org access, re-run segregation-of-duties checks |
| Leaver | Resignation, dismissal, contract end, retirement | Disable access first, transfer owned data, revoke sessions/tokens, keep record for retention, then delete |

A useful mental picture of the lifecycle loop:

```text
HR event (Joiner / Mover / Leaver)
        │
        ▼
Identity store / directory ──provision/deprovision──► Target systems
        │                                                (accounts, groups,
        │                                                 roles, SaaS apps)
        │                                                      │
        └────── access reviews & certifications ◄──────────────┘
                     (governance loop)
```

### Joiner (onboarding)

- **Proof before provision.** The HR system is the authoritative source: an identity should be proofed and approved before any account is created, not after.
- **Start minimal.** New joiners get a default, minimal role plus role-specific entitlements selected from rules — never a blind "copy of a similar colleague," which silently imports their accumulated privileges.
- **Security enrollment is part of onboarding.** MFA registration and a documented recovery path should happen before (or at the same moment as) first interactive sign-in. Delaying MFA creates a period of weak authentication.
- **Contractors and temporaries** should have explicit end dates; their accounts should be governed by the same lifecycle with automatic expiry.

### Mover (change)

- A move is **not** "keep everything and add more." Access should be recalculated against the destination role, then the *delta* applied: add what is new, remove what is no longer needed.
- Re-run **segregation of duties (SoD)** checks: a promotion may create a conflict (e.g., someone who approves purchase orders now also creates vendors).
- Reassign owned resources (shared mailboxes, project repos, key vaults) to the new role or manager.
- A mover event is a natural **trigger for a targeted access review** rather than waiting for the annual campaign.

### Leaver (offboarding)

- **Order matters:** disable interactive sign-in *before* telling anyone, revoke active sessions and tokens, then handle data and cleanup. Reversible "disable" beats "delete" for the first hours after termination.
- Transfer ownership of documents, mail, code, and cloud resources to a manager or successor so no work is orphaned.
- Mind **service-account and delegation dependencies**: an admin's personal account may be embedded in scripts, scheduled jobs, or break-glass procedures.
- Compliance may require keeping records (mail holds, legal holds) after access is gone. Use **disable → hold → delete** rather than instant deletion.
- Involuntary terminations should disable access at the moment of notice — even mid-session — because the risk window starts at separation, not at the end of the day.

| Account state | Access | Data retained | Typical use |
|---|---|---|---|
| **Disabled** | Blocked | Yes (full) | Immediate termination, investigation, legal hold |
| **Deleted** | — | No (or archive) | After retention window expires, cleanup |

## Sources of Truth and Provisioning / Deprovisioning

**Source-of-truth vocabulary** is essential for architecture discussions:

- **System of record (SoR):** the authoritative system for an identity's existence — normally HR/payroll. If HR says the person left, the identity lifecycle must react.
- **Authoritative attribute source:** the system that owns a specific attribute (e.g., HR owns `costCenter`, the phone system owns `telephoneNumber`).
- **Authoritative directory / IdP store:** the directory that applications trust for authentication (e.g., Active Directory, Microsoft Entra ID, LDAP).
- **Enforcement points:** the applications, cloud IAM, and data systems where access is actually granted.

**Provisioning** flows identity and attribute changes outward to every system that needs them; **deprovisioning** flows removals. A typical topology:

```text
HR (SoR) ──► Identity Governance / Provisioning hub ──► Authoritative directory (AD/Entra)
                 │   rules, approvals, SoD checks            │
                 │                                           │  sync + federation
                 ▼                                           ▼
           Target apps ── SCIM/connectors ──────────►  SaaS, on-prem apps, cloud IAM
```

Modern SaaS systems are provisioned over **SCIM 2.0** (System for Cross-domain Identity Management), a standard REST/JSON API. A conceptual user creation, then a deprovisioning update:

```json
// SCIM 2.0 create user (conceptual)
POST /scim/v2/Users
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "ana.garcia",
  "name": { "givenName": "Ana", "familyName": "Garcia" },
  "emails": [{ "value": "ana.garcia@example.com", "primary": true }],
  "active": true
}

// Deprovisioning: PATCH "active": false — keeps the identity and audit
// record but blocks access everywhere the app is connected.
```

| Provisioning pattern | Strengths | Weaknesses |
|---|---|---|
| Direct connector per app (IGA hub) | Central policy, audit, SoD checks | Hub becomes critical; connector maintenance |
| Directory-first (provision into AD/Entra, apps join) | Reuses existing directory trust | Only works for directory-connected apps |
| SCIM to each SaaS | Standard, no per-vendor agents | Requires the app to implement SCIM |

**Deprovisioning pitfalls:** accounts in "shadow IT" apps no connector reaches; nested-group memberships that survive the account disable; still-valid session tokens after the account is disabled (must revoke sessions, not just block new logins); and deactivation order across interdependent systems (e.g., email before the HR portal that sends notifications).

## Role-Based and Attribute-Based Access Control (Concepts)

Authorization models are covered deeply in Phase 03; here you need working definitions because they drive lifecycle design.

- **RBAC (role-based access control):** permissions are grouped into roles and identities are assigned roles. The lifecycle question becomes "which roles does this person hold, and do they still match their job?" RBAC is easy to audit (`user → role → permission`) but suffers from **role explosion** when every fine-grained need becomes a new role, and from **role accumulation** when roles are only ever added.
- **ABAC (attribute-based access control):** access decisions are computed from attributes of the subject, resource, action, and environment against policies (NIST SP 800-162 is the reference model). The lifecycle focus shifts to *keeping attributes correct and current*: department, employment status, clearance, cost center, location.

A conceptual ABAC policy:

```json
{
  "name": "HR analysts read HR records of their own department",
  "effect": "allow",
  "action": "read",
  "resource": { "type": "hr-record" },
  "condition": {
    "all": [
      "subject.department == resource.ownerDepartment",
      "subject.employmentStatus == \"active\"",
      "environment.riskScore <= 40"
    ]
  }
}
```

| Dimension | RBAC | ABAC |
|---|---|---|
| Decision basis | Role membership | Attributes + policy |
| Administration | Create roles, assign/revoke memberships | Manage attribute sources and policies |
| Dynamic decisions (time, risk, location) | Limited | Natural fit |
| Auditing | Simple: role → user | Harder: many attributes in play |
| Best fit | Stable org structures, employee access at scale | Fine-grained data control, external users, classification |

In practice most enterprises are **hybrid**: RBAC for broad access (group membership ⇒ role) with ABAC-style rules and device/data-classification conditions layered on top for sensitive resources.

## Governance and Access Reviews

Governance is the feedback loop that keeps the lifecycle honest:

- **Certification/attestation campaigns:** periodically every account+entitlement pairing is presented to a reviewer (manager, data owner, or role owner) who must certify, revoke, or modify it. Typical cadence: privileged access quarterly, general access annually.
- **Who reviews what:** managers certify their direct reports' access; application/data owners certify access to their systems. Untrusted reviewers and rubber-stamping are a governance failure.
- **Segregation-of-duties (SoD) matrices:** pre-defined conflicting pairs (create-vendor vs. approve-PO) checked both at request time and continuously.
- **Role mining:** analyze existing entitlements to discover roles worth creating, consolidating, or cleaning up.
- **Event-driven reviews:** Mover/leaver/role-change events trigger targeted reviews so problems do not wait a year to surface.
- Review outcomes (certify / revoke / modify) must feed **remediation**, not just reports, or the review is decorative.

## Identity Hygiene

Identity hygiene is the collection of practices that keep the identity store free of risky residue:

- **Orphan accounts:** enabled accounts with no live owner (leaver missed by a broken connector, contractor never removed).
- **Dormant accounts:** active but unused for 60–90+ days; prime targets for password-spray and takeover.
- **Shared/generic accounts:** no individual accountability; ban by policy, except narrowly scoped break-glass accounts that are sealed, monitored, and checked out.
- **Service-account sprawl:** non-human identities with standing privileges and secrets that never rotate; treat them as first-class identities with their own lifecycle.
- **Stale privileged memberships:** domain/tenant admin groups that keep former admins after role changes.
- **Hygiene metrics** worth tracking: number of orphan/dormant accounts, privileged members vs. privileged users active, % of entitlements certified, accounts past their end date.

Good hygiene is what makes a zero-trust architecture (Phase 04) believable: you cannot enforce least privilege on identities you do not know about.

## Common Mistakes & Tips

- **Mistake:** disabling accounts but not revoking sessions/tokens — the "leaver" can keep using already-authenticated sessions. **Tip:** make session revocation part of the offboarding playbook.
- **Mistake:** copying a colleague's access to onboard faster. **Tip:** provision from roles and rules; the few minutes saved now become years of entitlement creep.
- **Mistake:** only provisioning at join; moves accumulate access forever. **Tip:** treat every move as access *recalculation* with removal.
- **Mistake:** deleting accounts immediately on termination, destroying audit and legal-hold data. **Tip:** disable first, hold, then delete after the retention window.
- **Mistake:** forgetting service accounts, break-glass, and delegated/shared mailboxes in the leaver process. **Tip:** enumerate non-human dependencies before offboarding admins.
- **Mistake:** letting the app be the source of truth ("we create users in the app"). **Tip:** centralize provisioning; apps consume identities via SCIM/directory.
- **Mistake:** annual reviews that everyone rubber-stamps. **Tip:** sample-verify certifications, use event-driven reviews, and enforce remediation.

## Checklist / Self-Test

- [ ] I can draw the JML lifecycle and state the required actions and ideal timings for each event.
- [ ] I can explain the difference between system of record, authoritative attribute source, directory, and enforcement point.
- [ ] I can sketch a SCIM 2.0 create and deactivate (active=false) and argue disable-vs-delete.
- [ ] I can contrast RBAC and ABAC, including role explosion and attribute drift, and describe a hybrid pattern.
- [ ] I can design an access review campaign: scope, reviewer, frequency, SoD checks, and remediation path.
- [ ] I can list at least five identity-hygiene problems and a mitigation for each.
- [ ] I can explain why session revocation matters for offboarding, not just account disabling.

## Further Resources

- NIST SP 800-162, *Guide to Attribute Based Access Control (ABAC)*: https://doi.org/10.6028/NIST.SP.800-162
- NIST SP 800-63-3, *Digital Identity Guidelines* (IAL/AAL suite): https://doi.org/10.6028/NIST.SP.800-63-3
- SCIM 2.0 protocol, RFC 7644: https://datatracker.ietf.org/doc/html/rfc7644
- NIST Computer Security Resource Center (CSRC): https://csrc.nist.gov/
- Microsoft Entra ID documentation (identity lifecycle and governance concepts): https://learn.microsoft.com/en-us/entra/identity/
