# eIAMA — Identity & Access Management Associate

> Area: 04-Emerging-Technologies · INE-Cybersecurity-Certifications-Guide
> Status: Study module for the eIAMA certification track. Public study material only — no exam content or NDA-protected material is included.

> **Nomenclature note:** This module was first published as "Identity and Access Management
> Architect". That name was incorrect — the credential is **Identity & Access Management
> Associate**, which is what the acronym IAMA stands for. Official certification page:
> [eIAMA — Identity & Access Management Associate](https://ine.com/security/certifications/eiama-certification).

## What This Module Covers

The **eIAMA (Identity & Access Management Associate)** certification covers the discipline of designing and operating identity and access management systems — from day-to-day IAM administration through to the architecture concepts that discipline rests on. IAM is the set of processes, policies, and technologies that answer two questions for every user, device, or workload: *who are you?* (identity and authentication) and *what may you do?* (authorization).

An IAM architect plans how identities are born, change, and retire across an organization; selects and integrates identity providers; designs authentication and single sign-on (SSO) experiences; decides how access decisions are made and enforced; and aligns all of it with modern security models such as zero trust.

This module organizes the domain into five pillars:

| Pillar | Core question | Typical artifacts |
| --- | --- | --- |
| Identity lifecycle | How are accounts created, changed, and removed? | Joiner/mover/leaver processes, provisioning |
| Authentication | How does the system verify a claimed identity? | Passwords, MFA, SSO, passwordless, federation |
| Authorization | How are permissions granted and enforced? | RBAC, ABAC, policies, least privilege |
| Zero trust | How is trust established per request? | Policy decision/enforcement points, microsegmentation |
| Federation | How do trust relationships span organizations? | SAML/OIDC trust, cross-realm identity |

### What the eIAMA Certification Covers (Public Framing)

INE launched eIAMA on **26 August 2026** as a **vendor-neutral** certification. It validates the practical skills of an associate who can work with IAM solutions in real-world and cloud environments, and it assumes familiarity with the architecture concepts those solutions rest on. At a high level, the body of knowledge spans:

- **Identity architecture:** directories, identity stores, and how identities are represented (users, groups, service accounts, workloads).
- **Authentication architecture:** credential types, MFA and risk-based authentication, SSO standards, and passwordless approaches.
- **Authorization architecture:** role-based and attribute-based access control, policy management, and least-privilege design.
- **Access control models for modern infrastructure:** cloud IAM, privileged access, and API/machine identity.
- **Zero trust principles** applied to identity: continuous verification, policy-based access, and minimizing implicit trust.
- **Federation and standards:** trusting external identities through SAML, OIDC/OAuth, and directory synchronization.
- **IAM governance:** access reviews, segregation of duties, auditing, and compliance considerations.

This guide deliberately describes the *discipline* — the concepts, protocols, and hands-on skills an architect needs — not the specific questions, labs, or answers of the INE exam. Prepare by building genuine fluency in the topics below.

### Skills You Build

After working through this module you should be able to:

- Explain the full identity lifecycle and design provisioning/deprovisioning workflows.
- Compare authentication mechanisms and design an MFA strategy (knowledge, possession, inherence factors).
- Read and reason about OAuth 2.0, OIDC, and SAML 2.0 exchanges at the message level.
- Translate a business requirement into roles, policies, or attributes (RBAC/ABAC thinking).
- Articulate zero trust in IAM terms: every request authenticated, authorized, and encrypted.
- Stand up a small identity lab (e.g., Keycloak in Docker) and demonstrate SSO, MFA, and federation.
- Choose the right IAM platform family for a given scenario: cloud IdP, open-source IdP, or cloud-provider-native IAM.

## How to Use the Module Folders

The module follows a consistent layout. Work top-down the first time, then treat it as reference material.

```
eIAMA/
├── README.md                  <- This overview: roadmap, checklist, navigation
├── methodology/               <- Concepts, organized pillar by pillar
│   ├── 01-identity-lifecycle.md
│   ├── 02-authentication.md
│   ├── 03-authorization.md
│   ├── 04-zero-trust.md
│   └── 05-federation.md
├── tools/                     <- Platform guides and tooling references
│   └── iam-platforms.md       <- Comparing IAM platform families
├── labs/                      <- Hands-on, reproducible lab work
│   └── iam-scenarios.md       <- Keycloak lab: SSO, MFA, roles, federation
└── cheatsheets/               <- Quick reference for protocols and terms
    └── iam-protocols.md       <- OAuth 2.0, OIDC, SAML, LDAP, Kerberos, SCIM
```

- **methodology/** — Read in order (01 → 05). Each file states its purpose, the key concepts, and a checklist of the ideas you should be able to explain afterward.
- **tools/** — Reference for the platform families an architect meets in practice. Use it when choosing or discussing technologies.
- **labs/** — Follow after you understand authentication and federation. Everything runs locally in Docker; no external accounts required.
- **cheatsheets/** — Print-friendly quick reference. Revisit before and during practice to decode protocol traces.

## Study Roadmap

Suggested path for a new learner (roughly 2–4 weeks at a few hours per week):

1. **Foundations (methodology 01–02).** Learn identity lifecycle and authentication first; every other pillar builds on them.
2. **Authorization (methodology 03).** Roles, attributes, policies; revisit least privilege constantly.
3. **Zero trust (methodology 04).** Frame everything so far in the "never trust, always verify" model; read the NIST definition (see Further Resources).
4. **Federation (methodology 05).** Learn SAML and OIDC conceptually before touching a lab.
5. **Platforms (tools/iam-platforms.md).** Understand the families and when each fits.
6. **Hands-on (labs/iam-scenarios.md).** Build the Keycloak lab and run every guided scenario. Seeing real protocol messages makes the theory stick.
7. **Consolidate (cheatsheets/iam-protocols.md).** Drill the grants, flows, and terms until they are instant recall.

### Tips for Effective Study

- **Draw the flows.** For OIDC and SAML, sketch sequence diagrams from memory until they are automatic.
- **Read real messages.** The lab shows actual redirects, tokens, and assertions; decode them instead of only clicking through.
- **Explain out loud.** If you cannot explain client credentials vs. authorization code to a colleague, re-read that section.
- **Pair concepts with a platform.** Every abstract idea (scope, realm, claim) is concrete in at least one tool; find it in the lab.
- **Use the checklists.** Each module file ends with a self-test; treat un-checked boxes as review triggers, not trivia.

### Concept ↔ Protocol ↔ Platform Map

An IAM concept rarely stands alone — every pillar maps to concrete protocols and platform features. Use this table to navigate between the theory (methodology), the standards (cheatsheet), and the hands-on work (labs):

| Concept (methodology) | Standards involved (cheatsheets) | Where you see it in practice (labs/tools) |
| --- | --- | --- |
| Identity lifecycle | SCIM, LDAP | User provisioning/deactivation; SCIM connectors in cloud IdPs |
| Authentication | OIDC, SAML, LDAP bind, Kerberos | Login page, TOTP enrollment, domain logon |
| SSO | OIDC/OAuth 2.0, SAML | Logging into several apps with one session |
| Authorization | OAuth 2.0 scopes, SAML attributes | Roles and claims inside tokens |
| Zero trust | OIDC step-up, token validation | Conditional access, per-request policy checks |
| Federation | SAML 2.0, OIDC identity brokering | Cross-realm login between two Keycloak realms |

A good exercise: pick any row, read the methodology file, find the terms in the cheatsheet, then reproduce the behavior in the lab.

## How the Files Relate

The module is meant to be read as a loop, not a stack:

1. **methodology/** gives you the vocabulary and the mental model.
2. **cheatsheets/** pins the vocabulary to the exact protocol artifacts (grants, flows, claims, assertions).
3. **tools/** shows where those protocols live in real product families.
4. **labs/** makes you *operate* all of the above against a real identity server.

If you get stuck on a term in any file, search for it in the cheatsheet first — it was written to be the shared glossary of this module.

## Progress Checklist

Use this to track your overall preparation:

- [ ] I can explain the five pillars of IAM architecture in my own words.
- [ ] I can describe the joiner/mover/leaver lifecycle and why deprovisioning matters.
- [ ] I can compare knowledge, possession, and inherence factors and design a basic MFA strategy.
- [ ] I can explain RBAC vs. ABAC and give an example policy for each.
- [ ] I can summarize zero trust (NIST SP 800-207) in IAM terms.
- [ ] I can explain when to federate with SAML vs. OIDC.
- [ ] I completed the Keycloak lab scenarios (SSO, MFA, roles, federation).
- [ ] I can recall the OAuth 2.0 grant types and OIDC flows from the cheatsheet without looking.
- [ ] I can compare cloud IdP, open-source IdP, and cloud-provider-native IAM use cases.

---

> ⚠️ Personal study notes. No exam content protected by NDA is included; when in doubt about a source, rely on the public standards listed under "Further Resources" in each file.
