# Compliance Basics

> eEDA · Methodology — Enterprise Defense Administrator
>
> Phase 03 of nine. Compliance is where the other phases are asked to prove themselves: the inventory counts from [05](05-asset-inventory-and-configuration.md), the access reviews from [06](06-identity-and-privileged-access.md), the patch records from [07](07-vulnerability-and-patch-management.md), and the restore tests from [08](08-continuity-and-recovery.md) become audit evidence here.

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

## The Obligations Register

An obligations register is the map from "what binds us" to "what we do about it, and how we prove it". Without it, compliance lives in the heads of two people and in whichever framework tab happens to be open.

| Field | What goes in it | Example |
|---|---|---|
| Obligation ID | Stable reference used by findings and tickets | `OBL-GDPR-07` |
| Source | Law, regulation, contract, or standard clause | GDPR Art. 33 (breach notification) |
| Requirement | One sentence, in plain language | "Notify the supervisory authority within 72 hours of becoming aware of a personal-data breach" |
| Applicability trigger | Why it applies to us | "We process EU customer personal data" |
| Internal control | The control that satisfies it | `IR-04` breach assessment and notification procedure |
| Owner | The accountable person | Data Protection Officer |
| Evidence | The artifact that proves it operated | Breach log, notification copies, decision records |
| Test method | How an assessor checks it | Sample 3 incidents from the period; verify assessment timestamps |
| Frequency | How often it is tested internally | Twice a year, plus after every incident |
| Status and next review | Live state | In place / partial / gap; review 2026-09-01 |

Worked rows from a fictional mid-size company:

| ID | Source | Requirement (short) | Internal control | Evidence | Owner |
|---|---|---|---|---|---|
| OBL-GDPR-03 | GDPR Art. 30 | Maintain records of processing activities | `PRIV-01` RoPA | Current RoPA document, version history | DPO |
| OBL-GDPR-07 | GDPR Art. 33 | Breach notification within 72 hours | `IR-04` notification procedure | Incident records with timestamps and decisions | DPO |
| OBL-PCI-08 | PCI DSS — access control objective | Restrict access to cardholder data by business need to know | `AC-02` role-based access, `AC-05` review | Access review exports and removal tickets | Head of Payments |
| OBL-ISO-A89 | ISO/IEC 27001:2022 A.8.9 | Configuration management | `CM-01` baseline and drift process | Baseline documents and scan reports | Platform lead |
| OBL-HIPAA-05 | HIPAA Security Rule | Risk analysis and documented safeguards | `RM-02` annual risk assessment | Signed risk assessment and treatment plan | Compliance manager |

The register's payoff is proportionality: before an audit, you can see which obligations have weak evidence, and fix those rather than re-polishing the ones that were already strong.

## The Evidence Index: Making Proof Cheap

The difference between a quiet audit and a fire drill is whether evidence can be produced in minutes. Build an index that answers, for every control, *what proves it, where it lives, and how it is generated*.

| Control | Evidence artifact | Where it lives | How it is generated | Freshness |
|---|---|---|---|---|
| `AC-02` Role-based access | Group membership export per system | `\\evidence\access\` | Scheduled report from the directory | Monthly |
| `AC-06` Leaver deprovisioning | Leaver ticket with disable timestamp and group removal | ITSM project `OFFBOARD` | Ticket workflow, exported quarterly | Quarterly |
| `CM-01` Configuration baseline | Baseline document (version) plus OpenSCAP scan report | `\\evidence\config\` | `oscap xccdf eval` against the data stream, saved with results | Monthly |
| `VM-03` Patch compliance | Compliance report by tier with coverage figure | `\\evidence\patching\` | Inventory tool report, exported per cycle | Monthly |
| `LOG-01` Auditing enabled | Audit policy export per host class plus sample query results | `\\evidence\logging\` | Policy export plus a saved search executed during the audit | On request |
| `BC-02` Restore testing | Restore test record with measured RTO/RPO and deviations | `\\evidence\recovery\` | Test record template, signed by operator and owner | Quarterly |

Prefer **rebuildable** evidence (a report you can regenerate for the audit window) over **static** evidence (a screenshot from eight months ago that no longer matches the system). Static evidence is faster to file and much weaker in an interview, because the auditor's next question is always "show me it is still true".

> If producing the evidence for a control takes more than ten minutes, automate the production or admit the control is not monitored. Both answers are useful; "it is complicated" is the answer that turns into a finding.

## How Auditors Actually Sample

Auditors rarely test a whole population; they sample and then judge whether the *process* exists. Knowing this changes what you prepare.

| What is sampled | Typical approach | What the auditor is really testing |
|---|---|---|
| User terminations | Pick a period, then a set of leavers; compare HR record to access state | Whether deprovisioning is a process or an occasional favour |
| Access reviews | Read the review record, then trace two removals to closure | Whether reviews produce change or only sign-off |
| Changes to production | Sample change tickets; check approval, testing, and rollback | Whether change control is followed under pressure |
| Incidents | Sample incidents; check timeline, notification decision, and lessons | Whether the response process is documented and consistent |
| Vulnerability management | Sample findings; check SLA, remediation, and exceptions | Whether timing promises are kept or explained |
| Restore tests | Read test records; ask for the follow-up actions | Whether recovery is verified or assumed |

Findings come in three severities, and the distinction matters when you are negotiating remediation timelines:

- **Major nonconformity** — the control is absent or ineffective for the whole scope (for example: no leaver process exists at all). Blocks certification.
- **Minor nonconformity** — the control exists but failed for a sample item, or documentation is incomplete (for example: two of twenty leavers were disabled late).
- **Observation / opportunity for improvement** — not a failure; a risk of future failure (for example: leaver tickets have no automated SLA clock).

## Audit Readiness Timeline

A workable plan for a scheduled external audit:

```text
T-30 days   Close all open nonconformities from the last audit; confirm evidence owners are still
            in their roles. Confirm the scope statement and the systems it names still exist.
T-21 days   Generate every scheduled evidence artifact for the audit period in one pass.
            Check each one covers the full window (a report that stops two months short is a finding).
T-14 days   Dry-run: pick one control per framework theme and interview the owner as the auditor will.
            Record where the answer was "let me check" -- that is a missing index entry.
T-7 days    Fix the index gaps, confirm the evidence folder is readable by the audit team,
            and brief interviewees on scope (what is in, what is out) not on answers.
T-1 day     Freeze the evidence folder snapshot and note its location. Confirm room, access, and
            that the people who own the sampled processes are available.
During      Every request gets a ticket, an owner, and a promised time. Answer with the artifact,
            not with a narrative. Log anything you could not produce: that is tomorrow's index entry.
T+14 days   Respond to the draft report with corrective actions, owners, and dates.
T+30 days   Close corrective actions with evidence; update the obligations register and the index.
```

> The most expensive audit question is "can you show me that again for a different period?" Prepare evidence as a *repeatable query*, and the follow-up costs a minute instead of a day.

## Cloud and Vendor Boundaries in Compliance

In any cloud or outsourced service, the evidence is split. Be explicit about which half is yours, because auditors will still ask for the whole chain.

| Layer | Who proves it | Typical evidence you keep |
|---|---|---|
| Physical, hypervisor, provider network | The provider | Their independent attestation report (for example a SOC 2 report) and its scope statement |
| Service configuration you control (identity, storage permissions, logging, network rules) | **You** | Configuration exports, policy evaluation history, log pipeline evidence |
| Data classification, retention, and lawful basis | **You** | Data inventory, retention schedule, processing records |
| Contractual flow-down to sub-processors | You, via the contract | Contract clauses, vendor register, review records |

Two practical traps: an attestation report that covers a service you are not using, and a provider finding that you cannot distinguish from your own misconfiguration because you never documented which layer you own. Write the split into the obligations register per service.

## Common Mistakes & Tips

- **Treating compliance as the goal of security** — you can pass an audit and still be breached. Use the regime as a floor and keep going.
- **Scope creep in reverse** — claiming compliance for the whole company when only one system is in scope, or keeping cardholder data "just in case." Minimize scope by minimizing data.
- **Evidence collected at audit time** — rebuildable evidence is the difference between a smooth audit and a fire drill. Automate collection.
- **Ignoring sub-processor / vendor obligations** — GDPR and HIPAA flow through contracts; a non-compliant vendor can breach *your* obligations. Manage third parties actively.
- **Fixating on fines** — GDPR fines dominate headlines, but the more common business impact is losing customers/contracts that require SOC 2 or ISO 27001.
- **Tip**: maintain a single **obligations register** mapping each requirement to its owner control and evidence — it is the backbone of any compliance program.
- **Tip**: when a control fails in production, ask "what would the auditor say?" — that framing forces both remediation *and* documentation.
- **Evidence that only covers part of the audit period.** A monthly report that stops two months before the audit window is a finding, not a gap in the auditor's understanding. Check the date range before you hand anything over.
- **Screenshots as primary evidence.** They cannot be re-verified, they date instantly, and they invite the follow-up question you cannot answer. Prefer exports and saved queries.
- **Treating "we have a tool" as "we have a control".** Tooling that is deployed but not monitored, tuned, or reviewed is an activity, not a control. Say what the tool produces and who reads it.
- **Ignoring the observations.** Observations are free advice from someone who audits comparable organisations. Convert them into backlog items or record why you accepted them.
- **Assuming the provider's certification covers you.** A vendor's attestation covers their layer and their scope statement. Your configuration of their service is your evidence to produce.
- **Tip**: keep one "audit ready" folder structure per framework theme, refreshed on a schedule, so that readiness is a state rather than an event.

## Checklist / Self-Test

- [ ] I can explain the difference between compliance and security, with an example of compliant-but-insecure.
- [ ] I can state GDPR's applicability trigger, the 72-hour breach rule, and controller vs processor.
- [ ] I can outline the six PCI DSS objectives and explain why data minimization shrinks scope.
- [ ] I can distinguish SOC 2 Type I vs Type II and name the Trust Services Criteria.
- [ ] I can describe HIPAA's covered entity / business associate model and the Security Rule's safeguard categories.
- [ ] I can list the steps of an audit lifecycle and name typical evidence auditors sample.
- [ ] I can design a continuous compliance check for one control (tool, trigger, remediation, evidence).
- [ ] I can build an obligations register structure mapping requirement → control → evidence → owner.
- [ ] I can populate an obligations register with one row per regime (GDPR, PCI DSS, ISO/IEC 27001, HIPAA) including a test method.
- [ ] I can build an evidence index that states, for each control, what proves it, where it lives, how it is generated, and how fresh it is.
- [ ] I can explain the difference between rebuildable and static evidence, and why auditors prefer the first.
- [ ] I can describe how auditors sample leavers, changes, and restore tests, and what each sample is really testing.
- [ ] I can distinguish a major nonconformity, a minor nonconformity, and an observation, with an example of each.
- [ ] I can run the audit readiness timeline from T-30 to T+30 and say what happens at each stage.
- [ ] I can split cloud compliance evidence between the provider's layer and mine, and name the artifact for each.

## Further Resources

- European Commission — GDPR text and guidance: https://commission.europa.eu/law/law-topic/data-protection_en
- ISO/IEC 27001 information: https://www.iso.org/standard/27001
- PCI Security Standards Council — PCI DSS: https://www.pcisecuritystandards.org
- AICPA — SOC 2 and Trust Services Criteria: https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2
- HHS — HIPAA Security Rule guidance: https://www.hhs.gov/hipaa/for-professionals/security/index.html
- ENISA — data protection and breach notification resources: https://www.enisa.europa.eu
- NIST — SP 800-53 controls (used in audit/assessment): https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
