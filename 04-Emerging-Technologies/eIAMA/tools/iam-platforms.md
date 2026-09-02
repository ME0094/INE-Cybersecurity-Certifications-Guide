# IAM Platforms — A Conceptual Comparison

> eIAMA · tools — INE-Cybersecurity-Certifications-Guide

## Purpose

This guide helps you reason about IAM platforms as an architect: what they provide, how the major families differ, and how to choose among them. It compares **capability families** using well-known, publicly documented behaviors — not vendor-specific configuration manuals. Product facts here are limited to common knowledge (product existence, positioning, and headline features); always confirm details in the vendor's current documentation.

## What an IAM Platform Provides

Nearly every IAM platform is a bundle of the same logical capabilities, even when the names differ:

| Capability | What it does | Example artifacts |
| --- | --- | --- |
| **Directory / identity store** | Authoritative record of users, groups, devices, and their attributes | Users and groups, schema, attributes |
| **Authentication** | Verifies identity: passwords, MFA, passwordless, step-up | Login page, MFA challenges, session |
| **Single sign-on (SSO)** | One authentication grants access to many applications | Sessions, SSO cookies/tokens |
| **Authorization** | Decides what an authenticated identity may do | Roles, groups, policies, claims |
| **Provisioning** | Creates, updates, and removes accounts in target systems | SCIM connectors, job workflows |
| **Governance** | Reviews and certifies who has access | Access reviews, audit logs, attestation |

A useful mental model: the platform is the **policy decision point (PDP)** and, when it hosts the login experience, part of the **policy enforcement point (PEP)**. Applications ask it "who is this user, and what are they allowed to do?" instead of implementing identity themselves.

### Why organizations centralize IAM

- **Consistent policy:** one MFA rule, one password policy, one session policy everywhere.
- **Fewer credentials to manage:** users get SSO instead of per-app passwords; admins stop resetting them.
- **Faster joiner/mover/leaver:** provisioning is automated instead of manual per app.
- **Auditability:** a single place to review who had access to what, when.
- **Security:** orphaned and shared accounts shrink; suspicious sign-ins are caught centrally.

## The Platform Families

### 1. Cloud identity providers (IdP) — Microsoft Entra ID, Okta, Google Workspace, Ping, Auth0

Cloud IdPs host the identity store and authentication in the vendor's cloud and speak open standards (OIDC/OAuth 2.0, SAML, SCIM) to applications.

- **Core strengths:** mature SSO catalogs; broad MFA and conditional-access rules; lifecycle automation to thousands of SaaS apps via SCIM; self-service and directory sync (e.g., from on-prem AD); strong audit and compliance reporting.
- **Common use:** the "front door" for employee and sometimes customer identities across a SaaS-heavy organization.
- **When to choose them:** you need fast coverage of many cloud apps, managed resilience, conditional access (risk-based policies), and you accept a per-user subscription cost and a cloud dependency.
- **Watch-outs:** identity lives with a third party; outages affect all sign-ins; directory sync introduces its own consistency problems; per-user licensing shapes how broadly you can deploy.

> Example positioning: *Microsoft Entra ID* is the identity layer of the Microsoft ecosystem and integrates deeply with Microsoft 365/Azure. *Okta* is a cloud-neutral IdP with a large independent app network. Both are general-purpose workforce IdPs that natively support OIDC, SAML, and SCIM.

### 2. On-premises directories and self-hosted/open-source IdPs — Active Directory, OpenLDAP, Keycloak, FreeIPA

This family splits into two roles:

- **Directories** (Active Directory Domain Services, OpenLDAP) are identity *stores* speaking LDAP/Kerberos. They authenticate (bind) and answer attribute lookups but do not themselves do modern web SSO.
- **IdP servers** (Keycloak, FreeIPA, Shibboleth IdP) sit in front of or beside directories and translate directory identity into web standards (OIDC/SAML). Keycloak is the most common open-source example and can use an LDAP directory as its user federation backend.

- **Core strengths:** full control over data and code; no per-user SaaS fees; strong for legacy/on-prem estates (AD is the identity backbone of most Windows environments); Kerberos/LDAP native.
- **Common use:** government/regulated/air-gapped environments, hybrid estates bridging AD to modern SSO, cost-sensitive or lab deployments.
- **When to choose them:** you must keep identity data in-house, you need deep AD integration, or you want to learn IAM hands-on (Keycloak in Docker is the basis of the module lab).
- **Watch-outs:** you run the availability and patching burden; modern SSO features (conditional access, risk signals) require more assembly than a cloud IdP; LDAP and Kerberos are complex to operate well.

### 3. Cloud-provider-native IAM — AWS IAM, Azure RBAC/Entra, GCP IAM

The hyperscalers ship identity services for their *own* platforms. AWS IAM is the canonical example: it manages **principals** (users, groups, roles) and **policies** (JSON documents) that grant or deny API actions on AWS resources.

- **Core strengths:** purpose-built for the cloud provider's API surface; role-based, short-lived credentials via STS; fine-grained, auditable policy evaluation; enables workload identity (EC2 instance roles, container roles, OIDC federation for Kubernetes).
- **Common use:** controlling human and *machine* access to cloud APIs — the "who can call which API on which resource" problem.
- **When to choose them:** you are architecting inside one cloud and need cloud-native access control and temporary credentials. They do **not** replace a workforce IdP for SaaS SSO; the two layers interoperate (e.g., the IdP federates into the cloud account via SAML/OIDC, and AWS IAM then enforces what the federated user may do).
- **Watch-outs:** IAM policies are cloud-specific and do not port; misconfigured policies are a leading cause of cloud breaches, so least privilege and policy review matter; human identities and cloud identities must be mapped deliberately.

## Comparing the Families Honestly

| Question | Cloud IdP (Entra ID, Okta) | On-prem dir + open-source IdP (AD/LDAP + Keycloak) | Cloud-native IAM (AWS IAM) |
| --- | --- | --- | --- |
| Where does identity live? | Vendor cloud | Your infrastructure | Cloud account |
| Primary purpose | Workforce/customer SSO + lifecycle | Directory + standards-based SSO | API/resource access control |
| Native protocols | OIDC, SAML, SCIM, LDAP (sync) | LDAP, Kerberos, OIDC, SAML | Proprietary policies + federated roles |
| Best at | Fast SaaS coverage, conditional access | Control, AD integration, low marginal cost | Cloud API security, workload identity |
| Not a fit for | Air-gapped/identity-residency needs | Huge SaaS catalogs with minimal ops staff | SaaS user SSO, cross-cloud estates |
| You operate | Little (SaaS) | Everything | Policies within one cloud |

### Key architectural rule

The families are **complementary**, not competing. A common enterprise architecture is:

1. **Workforce IdP** (cloud IdP or self-hosted Keycloak) handles user SSO and lifecycle.
2. **Authoritative directory** (AD or cloud directory) holds the master user record; the IdP syncs or federates to it.
3. **Cloud IAM** (AWS IAM and friends) governs the cloud APIs those users and their workloads touch, often consuming federated identity from step 1.

A clean architecture names one **source of truth** per identity attribute and every other system consumes it via sync (SCIM) or federation (SAML/OIDC) — never by maintaining its own duplicate truth.

## Choosing the Right Platform for a Scenario

Work through these questions:

1. **Who are the users?** Employees, customers, partners, machines, or all of the above? (Machines need workload identity; customers may need a separate, self-service IdP experience.)
2. **Where must data live?** Residency, regulatory, or air-gap constraints may rule out cloud IdPs.
3. **What apps are in scope?** A SaaS-heavy estate rewards a cloud IdP's catalog; an on-prem estate rewards AD + an on-prem IdP.
4. **What is your operating budget?** Per-user SaaS fees vs. the salary/ops cost of running your own.
5. **What does your cloud strategy look like?** Cloud-native IAM is mandatory inside each hyperscaler regardless of the other choices.
6. **What risk does a directory outage create?** Centralize identity only where you can afford the single point of failure; plan fallback and break-glass access.

## Common Mistakes & Tips

- **Mistake:** treating AWS IAM (or any cloud IAM) as a workforce SSO product. **Tip:** use it for cloud APIs; federate humans in from the workforce IdP.
- **Mistake:** multiple teams each keeping their own copy of the user directory. **Tip:** designate one source of truth and sync/federate outward.
- **Mistake:** skipping deprovisioning design "because it is just an account". **Tip:** orphaned accounts are a top insider-risk vector; lifecycle is a first-class requirement.
- **Mistake:** picking a platform by brand instead of by integration reality. **Tip:** check the actual connector list for the apps you run, and whether it speaks OIDC/SAML/SCIM natively.
- **Mistake:** assuming "the cloud IdP syncs from AD" makes the two stores identical. **Tip:** expect attribute conflicts and soft/hard match issues; define the sync direction and conflict rules.
- **Mistake:** over-centralizing — every user in one giant realm, every app trusting everything. **Tip:** separate workforce, customer, and machine identity into realms/tenants with distinct policies.

## Checklist / Self-Test

- [ ] I can list the six core capabilities every IAM platform provides.
- [ ] I can explain the difference between an identity *store* (LDAP/AD) and an *IdP* (Keycloak, Entra ID, Okta).
- [ ] I can name when a cloud IdP is the right choice and when it is not.
- [ ] I can describe what AWS IAM governs and how it differs from a workforce SSO IdP.
- [ ] I can draw a reference architecture with one source of truth, an IdP, and cloud IAM.
- [ ] I can state the role of SCIM and of SAML/OIDC in connecting platforms.
- [ ] I can argue why cloud-provider-native IAM does not replace a workforce IdP (and vice versa).

---

## Further Resources

- Microsoft Entra ID documentation: https://learn.microsoft.com/entra/
- Okta documentation: https://developer.okta.com/docs/
- Keycloak documentation: https://www.keycloak.org/documentation
- AWS IAM documentation: https://docs.aws.amazon.com/iam/
- OpenLDAP documentation: https://www.openldap.org/doc/
- NIST SP 800-207 (Zero Trust Architecture): https://csrc.nist.gov/pubs/sp/800/207/final
- RFC 7644 (SCIM 2.0 protocol): https://www.rfc-editor.org/rfc/rfc7644
