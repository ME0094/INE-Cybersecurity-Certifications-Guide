# Compliance Basics

> eEDA · Methodology — Enterprise Defense Administrator

## Purpose

Compliance is the set of obligations — laws, regulations, contracts, and industry frameworks — that an organization must satisfy, plus the evidence that proves it does. For a defender, compliance work is a constant companion: scoping audits, proving controls, responding to regulators, and keeping obligations from becoming security debt. This guide covers the purpose of compliance, the key regimes you will meet (GDPR, ISO/IEC 27001, PCI DSS, SOC 2, HIPAA), the difference between compliance and security, audit basics, and continuous monitoring.

## Why Compliance Exists

Compliance obligations exist for several overlapping reasons:

- **Legal/regulatory**: the law demands it (data protection, financial services, healthcare, critical infrastructure).
- **Contractual**: customers and partners require it (many enterprise contracts demand SOC 2 or ISO 27001).
- **Market/trust**: certifications are a competitive signal and often a gate to sell (PCI DSS for card acceptance, SOC 2 for SaaS).
- **Risk management**: compliance regimes encode years of lessons learned — following them genuinely reduces risk when done with intent.

Consequences of non-compliance are not theoretical: fines, loss of the right to operate (e.g., card processing), contract termination, and regulator-imposed corrective action.

## Key Regimes Overview

### GDPR (General Data Protection Regulation) — EU/EEA

- Applies to any organization processing personal data of people in the EU/EEA, regardless of where the organization sits.
- Core concepts: **personal data**, **data controller** (decides why/how), **data processor** (acts on controller's behalf), **data subject rights** (access, erasure, portability…).
- Principles: lawfulness/fairness/transparency, purpose limitation, data minimization, accuracy, storage limitation, integrity & confidentiality, accountability.
- Key operational duties: records of processing activities (RoPA), DPIAs for high-risk processing, breach notification to the supervisory authority **within 72 hours** (when risk to individuals), privacy by design/default.
- Fines: up to €20M or 4% of global annual turnover, whichever is higher.

### ISO/IEC 27001

- Not a law but the de facto **certifiable** information-security management system (ISMS) standard (see the governance guide for clauses).
- Compliance here means: implement an ISMS per the standard's requirements, pass an accredited certification audit, and maintain it through surveillance audits (typically annual) and recertification (typically every 3 years).
- The certification is awarded to the *management system*, not to "the company" in the abstract — scope statements matter (which sites, systems, services).

### PCI DSS (Payment Card Industry Data Security Standard)

- Applies to any entity that stores, processes, or transmits cardholder data — from the smallest merchant to global acquirers.
- 12 requirements grouped into 6 objectives: build/maintain a secure network; protect cardholder data; maintain a vulnerability management program; implement strong access control; regularly monitor and test; maintain an information security policy.
- Compensating controls must be reviewed and approved by the assessor; SAQs apply to smaller merchants, full ROC + QSA assessment to larger ones.
- Data minimization is the heart of compliance: the fewer card numbers you store, the smaller your attack surface and your scope.

### SOC 2 (Service Organization Control 2) — AICPA

- An attestation report over a service organization's controls, built on the **Trust Services Criteria**: Security (mandatory), plus optional Availability, Confidentiality, Processing Integrity, and Privacy.
- Two report types: **Type I** (controls designed as of a point in time) and **Type II** (controls operated over a period, usually 6–12 months, with testing).
- Produced by an independent CPA firm; not a "certification" with a pass/fail, though a qualified opinion is commercially damaging.
- In practice, SOC 2 has become the default ask for SaaS and cloud vendors.

### HIPAA (Health Insurance Portability and Accountability Act) — US healthcare

- Applies to **covered entities** (providers, plans, clearinghouses) and their **business associates**.
- Protects **PHI** (protected health information); the **Security Rule** mandates administrative, physical, and technical safeguards; the **Privacy Rule** governs use/disclosure.
- Requires risk analysis, workforce training, breach notification (HHS and media in large breaches, generally within 60 days), and business associate agreements (BAAs).

```text
Regime    | Trigger                                | Typical evidence
GDPR      | Processing EU personal data            | RoPA, DPIAs, breach log
ISO 27001 | Chosen certification / customer demand | Audit reports, SoA
PCI DSS   | Storing/processing card data           | SAQ/ROC, scans, ASV report
SOC 2     | Service organization, customer demand | Type I/II report
HIPAA     | PHI in US healthcare context           | Risk analysis, BAAs, training
```

## Compliance vs Security

Compliance and security overlap but are not the same:

| Dimension | Compliance | Security |
|---|---|---|
| Driver | External obligations | Risk and business need |
| Question | "Can we prove X is done?" | "Are we actually safe?" |
| Time horizon | Audit cycles | Continuous |
| Failure | Fine, loss of certification | Incident, breach, harm |
| Mindset | Minimum bar, checklists | Defense in depth, adaptation |

Key insight: **compliance is a floor, not a ceiling.** A checklist-perfect environment can still be breached (e.g., MFA deployed but misconfigured, logs collected but never analyzed). Conversely, strong security can exist without a certification. Professionals aim for controls that are both compliant *and* genuinely effective, and they flag the gap when "meeting the letter" creates a false sense of safety.

## Audit Basics

An audit is an independent examination of evidence against criteria. Two main flavors relevant here:

- **Internal audit** — performed by the organization's own auditors (or outsourced) to check controls and readiness; reports to the audit committee.
- **External audit** — performed by an accredited certification body (ISO 27001), a CPA firm (SOC 2), or a regulator; results are relied upon by third parties.

Typical audit lifecycle:

1. **Scoping** — agree which systems, locations, and processes are in scope and which standard/criteria apply.
2. **Readiness / pre-assessment** — internal gap analysis against the criteria.
3. **Evidence collection** — the auditor requests documents, configurations, logs, and interviews (the "walk-through").
4. **Testing** — sampling: e.g., pick 20 user terminations and verify access was removed; pick 10 firewall changes and verify approval workflow.
5. **Findings & report** — nonconformities (major/minor), observations, and improvement opportunities.
6. **Corrective actions** — the organization fixes findings within agreed deadlines; evidence of closure is re-reviewed.

How to survive (and use) an audit:

```text
Keep an evidence index: control -> where the proof lives (config export,
policy doc, ticket, log query). If you can produce evidence in minutes,
the audit is cheap. If you scramble, the audit is expensive and stressful.
```

Auditors love: consistent naming, versioned policies with owners, complete and retained logs, and staff who can explain *why* a control exists. They dislike: one-off exceptions, empty "procedure documents" that nobody follows, and last-minute evidence hunts.

## Continuous Compliance Monitoring

Annual audits are point-in-time; modern programs monitor compliance continuously so that the next audit is a formality and drift is caught early. Techniques:

- **Automated policy checks**: infrastructure-as-code scans (e.g., Open Policy Agent, Cloud Custodian, AWS Config, Azure Policy) that flag non-compliant resources in real time.
- **CIS benchmark / compliance scanning** against systems (e.g., OpenSCAP on Linux, security baselines in Intune/Group Policy).
- **Evidence pipelines**: configuration exports and reports collected on a schedule into a GRC tool, timestamped and immutable.
- **Control self-assessments** on a rolling quarterly cycle rather than one annual push.
- **Alerting on control failures** — a cloud key rotation that failed should page someone, not wait for the audit.

```text
Example: "no public read access on storage buckets"
Continuous check: Cloud Custodian / Azure Policy / AWS Config rule
-> on violation: auto-remediate (block public ACL) + open a ticket
-> evidence: policy evaluation history exported monthly to the GRC tool
```

The goal: the annual audit becomes a sample of a process that is already proven daily, and control failures become incidents with owners, not audit surprises.

## Common Mistakes & Tips

- **Treating compliance as the goal of security** — you can pass an audit and still be breached. Use the regime as a floor and keep going.
- **Scope creep in reverse** — claiming compliance for the whole company when only one system is in scope, or keeping cardholder data "just in case." Minimize scope by minimizing data.
- **Evidence collected at audit time** — rebuildable evidence is the difference between a smooth audit and a fire drill. Automate collection.
- **Ignoring sub-processor / vendor obligations** — GDPR and HIPAA flow through contracts; a non-compliant vendor can breach *your* obligations. Manage third parties actively.
- **Fixating on fines** — GDPR fines dominate headlines, but the more common business impact is losing customers/contracts that require SOC 2 or ISO 27001.
- **Tip**: maintain a single **obligations register** mapping each requirement to its owner control and evidence — it is the backbone of any compliance program.
- **Tip**: when a control fails in production, ask "what would the auditor say?" — that framing forces both remediation *and* documentation.

## Checklist / Self-Test

- [ ] I can explain the difference between compliance and security, with an example of compliant-but-insecure.
- [ ] I can state GDPR's applicability trigger, the 72-hour breach rule, and controller vs processor.
- [ ] I can outline the six PCI DSS objectives and explain why data minimization shrinks scope.
- [ ] I can distinguish SOC 2 Type I vs Type II and name the Trust Services Criteria.
- [ ] I can describe HIPAA's covered entity / business associate model and the Security Rule's safeguard categories.
- [ ] I can list the steps of an audit lifecycle and name typical evidence auditors sample.
- [ ] I can design a continuous compliance check for one control (tool, trigger, remediation, evidence).
- [ ] I can build an obligations register structure mapping requirement → control → evidence → owner.

## Further Resources

- European Commission — GDPR text and guidance: https://commission.europa.eu/law/law-topic/data-protection_en
- ISO/IEC 27001 information: https://www.iso.org/standard/27001
- PCI Security Standards Council — PCI DSS: https://www.pcisecuritystandards.org
- AICPA — SOC 2 and Trust Services Criteria: https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2
- HHS — HIPAA Security Rule guidance: https://www.hhs.gov/hipaa/for-professionals/security/index.html
- ENISA — data protection and breach notification resources: https://www.enisa.europa.eu
- NIST — SP 800-53 controls (used in audit/assessment): https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
