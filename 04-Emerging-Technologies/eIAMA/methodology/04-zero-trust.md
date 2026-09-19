# Zero Trust — eIAMA Methodology Phase 04

> eIAMA · Methodology · INE Cybersecurity Certifications Guide (public-knowledge study notes; no exam/NDA material)

## Overview

Zero trust is a security model that **removes implicit trust from network location**: being "inside the office" or "on the VPN" no longer earns access. The canonical public reference is **NIST SP 800-207, *Zero Trust Architecture***, which describes the principles and the policy-engine/policy-administrator/PEP pattern used throughout this phase. For an IAM architect, zero trust is where identity becomes the *control plane*: every request is authenticated, authorized, and continuously re-verified against identity, device, and context signals.

By the end of this phase you should be able to:

- State the zero-trust principles and why "trust but verify" fails.
- Explain the NIST SP 800-207 components: policy engine (PE), policy administrator (PA), policy enforcement point (PEP).
- Explain microsegmentation and how it limits lateral movement.
- Describe continuous verification as a loop, not a login event.
- Argue why identity-centric architecture is the practical realization of zero trust.

## Principles — the seven tenets, and the slogans that are not tenets

NIST SP 800-207 §2.1 states that **"a zero trust architecture is designed and deployed with
adherence to the following zero trust basic tenets"**, and then lists exactly seven. They are
reproduced below in the standard's own words, because the list is short, it is quotable, and a
paraphrase loses the parts that constrain an architecture. Read the full text in the
publication before quoting one in a design document.

1. **All data sources and computing services are considered resources.** A network may be
   composed of multiple classes of devices; an enterprise may also classify personally owned
   devices as resources if they can access enterprise-owned resources.
2. **All communication is secured regardless of network location.** Network location alone does
   not imply trust; access requests from inside a legacy perimeter must meet the same
   requirements as any other. Communication should protect confidentiality and integrity and
   provide source authentication.
3. **Access to individual enterprise resources is granted on a per-session basis.** Trust in
   the requester is evaluated before access is granted, and *"access should also be granted
   with the least privileges needed to complete the task"*. Crucially: *"authentication and
   authorization to one resource will not automatically grant access to a different resource"* —
   that sentence is the whole reason a shared SSO session is not a zero-trust session.
4. **Access to resources is determined by dynamic policy** — including the observable state of
   client identity, application/service, and the requesting asset — and may include other
   behavioral and environmental attributes.
5. **The enterprise monitors and measures the integrity and security posture of all owned and
   associated assets.** No asset is inherently trusted.
6. **All resource authentication and authorization are dynamic and strictly enforced before
   access is allowed** — a constant cycle of obtaining access, scanning and assessing threats,
   adapting, and continually re-evaluating trust in ongoing communication.
7. **The enterprise collects as much information as possible about the current state of assets,
   network infrastructure and communications and uses it to improve its security posture.**
   That data feeds policy creation and enforcement, not only incident response.

> **What is *not* on that list.** SP 800-207 does not contain the phrases *"never trust, always
> verify"* or *"assume breach"*; neither is a tenet. They are the industry's shorthand — useful
> in a briefing, and a frequent source of exam-style errors when they are presented as the
> standard's own list. *Assume breach* in particular is a design posture from vendor and
> government guidance (it assumes the network is already compromised), and it overlaps with
> tenet 5's "no asset is inherently trusted" without being the same statement. **Least
> privilege** is likewise not a separate tenet: it appears *inside* tenets 3 and 4, as the rule
> that a grant is scoped to the task and that visibility is restricted alongside accessibility.

**The operational principles this phase actually applies**, stated separately so they are not
mistaken for the standard: *never trust, always verify* as a working posture; *assume breach*
as a planning assumption; *least privilege, just-in-time* as the shape of a grant; and
*identity as the control plane* — which is this module's own framing, not a quotation from
anyone. The phase's job is to show how each of those maps onto one of the seven tenets above
and onto architecture you can point at.

## NIST SP 800-207 Architecture: PE / PA / PEP

NIST separates *decision* from *execution* into three collaborating components:

- **Policy Engine (PE):** the brain. Evaluates every access request against enterprise policy using inputs from the identity provider, device-management (CDM) systems, threat intelligence, activity logs, and data-access policies. Returns **allow/deny**.
- **Policy Administrator (PA):** executes the PE's decision — creating, managing, or terminating the session/credentials and instructing the PEP on what to do. (In some designs the PA also issues per-session tokens.)
- **Policy Enforcement Point (PEP):** the muscle. Sits in front of the resource and *enables, monitors, and terminates* connections according to the PE/PA decisions.

```text
                     +---------------------------------------------+
                     |             Policy Engine (PE)              |
                     |  decides allow/deny using enterprise policy |
                     +---------------------+-----------------------+
                     ▲                     | decision
   inputs: identity, |                     ▼
   device posture,   |     +-------------------------------+
   CDM, threat       |     |     Policy Administrator (PA) |  creates/revokes session,
   intel, logs       |     +---------------+---------------+  configures PEP
                                          | instruction
                                          ▼
 Subject  ──(request)──► +----------------+----------------+────► Resource
 (user / device /        | Policy Enforcement Point (PEP) |    (app, data, workload)
  workload identity)     |  allows, monitors, terminates  |
                         +--------------------------------+
```

Conceptual sequence:

```text
1. Subject requests access to resource → PEP intercepts.
2. PEP/PA gather context → PE evaluates policy + signals (IdP claims, device compliance, risk).
3. PE returns allow/deny → PA operationalizes it (issue session, update PEP).
4. PEP enforces: permits/denies the connection; activity is logged back to the enterprise.
5. Signals keep flowing — if posture or risk degrades, PE→PA→PEP revokes the session.
```

Notes: the PEP is frequently an identity-aware proxy/gateway or an agent embedded next to the resource; PE+PA are usually centralized (cloud or on-prem) so policy is consistent; the **trust algorithm** must weigh identity assurance (Phase 02) and device posture, not just "who" but "is this device trustworthy right now".

## Identity-Centric Architecture

In practice, zero trust is realized by making **identity the new perimeter** and centralizing the decisions that used to be delegated to the network:

- **One control plane:** a central IdP/directory (Phase 01 lifecycle) plus an authorization service; the network is demoted to a transport, not a trust boundary.
- **Strong, phishing-resistant authentication** (Phase 02) for every identity — user, device, and **workload/service identities** for machine-to-machine calls.
- **Conditional access as authorization-at-entry:** sign-in is granted only when identity + device compliance + risk + resource sensitivity all satisfy policy; step-up is demanded when risk rises.
- **ZTNA-style access:** users reach specific applications through an identity-aware proxy that authenticates and authorizes per app, instead of a broad VPN into the whole network.

| Aspect | Traditional perimeter (VPN + firewall) | Identity-centric zero trust |
|---|---|---|
| Trust anchor | Network location ("inside") | Identity + device + context, per request |
| Access scope | Broad after VPN entry | Per-resource, per-session, least privilege |
| Revocation latency | Slow (VPN teardown, ACL pushes) | Immediate (session kill via PE→PA→PEP) |
| East–west movement | Flat and open | Microsegmented, policy-controlled |
| Verification | Login time | Continuous |

## Microsegmentation

Microsegmentation splits the network/data center into fine-grained segments so a compromised workload cannot roam. Where legacy segmentation was "subnet per tier," microsegmentation is **policy per workload or application** — enforced by software-defined overlays, host agents, or cloud security groups.

```json
// Workload-to-workload segmentation policy (conceptual)
{
  "from": { "workload": "web-tier",   "env": "prod" },
  "to":   { "workload": "api-tier",   "env": "prod" },
  "allow": ["443/tcp"],
  "deny":  "all else",
  "notes": "web-tier cannot reach db-tier directly; api-tier is its only path"
}
```

Why it matters to IAM: microsegmentation complements identity controls — identity decides *who* may talk to *what*, and segmentation stops an attacker who already has valid credentials from treating the network as a trampoline. Both enforce least privilege, one at the identity layer and one at the flow layer.

## Continuous Verification

Verification is a **loop, not an event**. After the session is created, the PE keeps receiving signals: device compliance checks, sign-in risk, impossible travel, anomalous data access, threat-intel hits. Consequences are enforced dynamically: prompt for step-up, restrict scope, or terminate the session.

```text
 request ──► verify identity+device ──► authorize (PE) ──► enforce (PEP) ──► log activity
    ▲                                                                          │
    └──────── continuous signals: risk, posture, behavior ◄─────────────────────┘
                 (risk ↑ ⇒ step-up or session revocation)
```

Architecture implications: comprehensive **activity logging** (authn, authz, data access) feeding SIEM/UEBA; telemetry must reach the PE in near-real time; policies must include *revocation triggers*, not just entry conditions. "Always verify" therefore means the authorization decision has a **half-life** — it decays unless refreshed by evidence.

## Common Mistakes & Tips

- **Mistake:** zero trust = "MFA for everyone." **Tip:** MFA is entry; the model also needs per-resource authorization, device posture, and continuous re-evaluation.
- **Mistake:** keeping the flat network and bolting on a gateway. **Tip:** segment east–west traffic and close direct workload paths.
- **Mistake:** one PE but enforcement points that are not all under policy control. **Tip:** inventory every PEP (gateway, agents, cloud policies) — unmanaged enforcement is a bypass.
- **Mistake:** static policies that ignore device/risk signals. **Tip:** wire CDM/device-compliance and risk feeds into the PE.
- **Mistake:** confusing "verify once at login" with continuous verification. **Tip:** define revocation triggers and monitor the loop.
- **Mistake:** treating identities as only human. **Tip:** give workloads/service identities the same lifecycle (Phase 01) and least privilege.
- **Mistake:** assume-breach but no blast-radius reduction. **Tip:** least privilege + segmentation + short sessions make a compromised credential cheap to contain.

## Checklist / Self-Test

- [ ] I can state the zero-trust principles and explain why location-based trust fails.
- [ ] I can describe PE, PA, and PEP and draw how a request flows through them.
- [ ] I can list the signal sources a policy engine consumes (identity, CDM, threat intel, logs).
- [ ] I can explain microsegmentation and give a workload-to-workload policy example.
- [ ] I can describe continuous verification as a loop with revocation triggers.
- [ ] I can argue why identity-centric architecture implements zero trust in practice.
- [ ] I can map eIAMA Phases 01–03 (lifecycle, AuthN, AuthZ) into a zero-trust design.

## Further Resources

- NIST SP 800-207, *Zero Trust Architecture*: https://doi.org/10.6028/NIST.SP.800-207
- NIST Computer Security Resource Center (CSRC): https://csrc.nist.gov/
- CISA Zero Trust Maturity Model: https://www.cisa.gov/zero-trust-maturity-model
- Microsoft Entra ID documentation (Conditional Access and identity-driven access control): https://learn.microsoft.com/en-us/entra/identity/
