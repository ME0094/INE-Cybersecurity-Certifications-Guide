# Security Frameworks for eEDA

> eEDA · Tools — INE-Cybersecurity-Certifications-Guide

## Purpose

Frameworks are the shared language of enterprise defense. An administrator who cannot map a control, a finding, or a requirement onto a recognized framework cannot communicate with auditors, executives, or regulators. This guide explains the frameworks defenders use most — **NIST CSF**, **NIST RMF**, **ISO/IEC 27001**, **CIS Controls**, and **COBIT** — and shows how to compare and map them. Read this guide together with the methodology notes on governance, risk, and compliance.

## Why Defenders Use Frameworks

- **Consistency** — everyone evaluates the same categories the same way.
- **Credibility** — auditors and customers recognize NIST, ISO, and CIS language.
- **Gap analysis** — a framework gives you a checklist of *what should exist* so you can find what is missing.
- **Prioritization** — CIS Controls, for example, exist specifically to tell you what to do first with limited budget.

## NIST Cybersecurity Framework (CSF)

The CSF (version 2.0, published 2024) is the most widely used voluntary framework in the United States and beyond. It is **risk- and outcome-oriented**, not control-prescriptive: it describes *what outcomes you want*, leaving *how* to you.

### The Six CSF 2.0 Functions

| Function | Plain-language meaning | Example outcomes |
|---|---|---|
| **Govern (GV)** | Set the direction, roles, and risk appetite | Security policy exists; risk is part of decision-making |
| **Identify (ID)** | Know your assets, data, and risks | Asset inventory; risk assessment completed |
| **Protect (PR)** | Put safeguards in place | Access control; training; data protection |
| **Detect (DE)** | Find problems in time | Monitoring; anomaly detection; continuous visibility |
| **Respond (RS)** | Act during an incident | Incident response plan executed; analysis done |
| **Recover (RC)** | Restore and improve after an incident | Backups restored; lessons learned recorded |

CSF 2.0 organizes these functions into 22 categories (for example, asset management and risk assessment sit under Identify).

### Profiles and Implementation Tiers

- **Profiles** — a *Current Profile* describes where you are; a *Target Profile* describes where you want to be. Comparing them drives your roadmap.
- **Implementation Tiers** — describe how formally an organization manages cyber risk, from **Tier 1 (Partial)** to **Tier 4 (Adaptive)**. Tiers describe maturity, not "good vs. bad": a small company can legitimately target Tier 2.

```text
Profile gap = Target Profile − Current Profile
             (each gap becomes a prioritized work item)
```

## NIST Risk Management Framework (RMF)

Where CSF says *what outcomes*, the RMF says *what process to follow* to authorize and operate systems under risk. Defined in **NIST SP 800-37 Rev. 2**, it is mandatory for US federal systems and widely borrowed by industry. Its seven steps:

| # | Step | What happens | Key output |
|---|---|---|---|
| 1 | **Prepare** | Set context, roles, risk strategy | Preparedness tasks done org-wide and per system |
| 2 | **Categorize** | Classify the system and its data (impact: low/moderate/high) | Categorization / impact analysis |
| 3 | **Select** | Pick baseline controls (e.g., NIST SP 800-53) | Control set |
| 4 | **Implement** | Put controls in place and document them | Control implementations |
| 5 | **Assess** | Test/evaluate that controls work | Assessment findings |
| 6 | **Authorize** | A senior official accepts the residual risk | Authorization decision (ATO) |
| 7 | **Monitor** | Continuously watch controls and re-assess on change | Updated risk posture |

## ISO/IEC 27001 and Annex A

ISO/IEC 27001 is the international standard for an **Information Security Management System (ISMS)** — a management system, not just a set of technical controls. It uses the Plan-Do-Check-Act (PDCA) cycle and is **certifiable**: an independent body can certify your ISMS against it.

Annex A of ISO/IEC 27001:2022 lists **93 controls grouped into four themes** (the 2022 revision replaced the old 14 domains / 114 controls):

| Annex A theme | # of controls | Examples |
|---|---|---|
| **Organizational** (A.5) | 37 | Policies, roles & responsibilities, supplier security, threat intelligence |
| **People** (A.6) | 8 | Screening, terms of employment, security awareness training |
| **Physical** (A.7) | 14 | Physical entry, secure areas, equipment maintenance & disposal |
| **Technological** (A.8) | 34 | Access control, malware protection, logging, cryptography, backup |

Each control has an identifier (e.g., **A.8.9 Configuration management**, **A.8.15 Logging**) and a control description plus implementation guidance in ISO/IEC 27002.

## CIS Controls

The **CIS Critical Security Controls v8** are 18 prioritized, prescriptive controls built by practitioners from real incident data. Unlike CSF, they tell you *specifically what to do*.

**Implementation Groups (IGs)** scale the controls to your resources:

- **IG1** — essential hygiene every organization should do (the baseline).
- **IG2** — adds safeguards for organizations with more resources/complexity.
- **IG3** — full set for security-focused, regulated, or high-value organizations.

The 18 v8 controls (v7 had 20; v8 consolidated them in 2021):

```text
1  Inventory and Control of Enterprise Assets
2  Inventory and Control of Software Assets
3  Data Protection
4  Secure Configuration of Enterprise Assets and Software
5  Account Management
6  Access Control Management
7  Continuous Vulnerability Management
8  Audit Log Management
9  Email and Web Browser Protections
10 Malware Defenses
11 Data Recovery
12 Network Infrastructure Management
13 Network Monitoring and Defense
14 Security Awareness and Skills Training
15 Service Provider Management
16 Application Software Security
17 Incident Response Management
18 Penetration Testing
```

## COBIT (Brief)

COBIT (ISACA, current edition 2019) is a **governance framework for information and technology** aimed at executives and management. It separates **governance** ("are we doing the right things?") from **management** ("are we doing things right?") and defines 40 core objectives across five domains:

| Domain | Meaning |
|---|---|
| **EDM** — Evaluate, Direct, Monitor | Governance objectives |
| **APO** — Align, Plan, Organize | Strategy and planning |
| **BAI** — Build, Acquire, Implement | Solution delivery |
| **DSS** — Deliver, Service, Support | Operations |
| **MEA** — Monitor, Evaluate, Assess | Performance and conformance |

You will rarely configure COBIT as an administrator, but you should recognize it when executives use it to steer the security program.

## Comparison Table

| Aspect | NIST CSF 2.0 | NIST RMF | ISO/IEC 27001 | CIS Controls v8 | COBIT 2019 |
|---|---|---|---|---|---|
| Publisher | NIST | NIST | ISO/IEC | Center for Internet Security | ISACA |
| Type | Outcome framework | Risk/authorization process | Manageable ISMS standard | Prioritized technical controls | IT governance framework |
| Structure | 6 functions, 22 categories | 7 steps | 93 Annex A controls (4 themes) | 18 controls, 3 IGs | 40 objectives, 5 domains |
| Prescriptiveness | Low (what/why) | Medium (process) | Medium (what + process) | High (how) | High-level (direction) |
| Certifiable? | No | No (authorization instead) | **Yes** (by accredited bodies) | No (self-assess/attest) | No |
| Best used for | Strategy, gap analysis | System authorization | Management system certification | Daily hardening priorities | Board-level governance |

## Mapping Example

Frameworks overlap heavily, so defenders map between them (auditors love this). Example: a fictional requirement expressed in CIS, ISO, and CSF language at once.

| Requirement you want to prove | CIS Controls v8 | ISO/IEC 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|
| Logs exist and are protected | 8 Audit Log Management | A.8.15 Logging | DE.CM (Detect) |
| Systems are hardened to a baseline | 4 Secure Configuration | A.8.9 Configuration management | PR.PS (Protect) |
| Patches are tracked and applied | 7 Continuous Vulnerability Management | A.8.8 Management of technical vulnerabilities | ID.RA / PR.PS |
| Malware defenses are active | 10 Malware Defenses | A.8.7 Protection against malware | PR.PS / DE.CM |
| Suppliers are vetted | 15 Service Provider Management | A.5.19/A.5.20 Supply chain | GV.SC (Govern) |

**Mapping workflow:** pick one framework as your home base (often CIS or CSF), then for each of your findings or planned controls ask "which category in the other frameworks does this serve?" and record it in a mapping spreadsheet — that spreadsheet becomes evidence for audits.

## Common Mistakes & Tips

- **Confusing CSF with RMF.** CSF = what outcomes you want (voluntary, strategic). RMF = the seven-step process to authorize a system (process, mandatory in US federal). You cannot "implement RMF controls"; you *follow* RMF and *implement* controls from catalogs like SP 800-53.
- **Quoting outdated versions.** CIS v8 has 18 controls (not 20, that was v7) and ISO 27001:2022 has 93 controls (not the old 114). Say the version when you talk: "CIS v8", "27001:2022".
- **Treating Tier/IG as scores.** CSF tiers and CIS Implementation Groups are about *matching effort to risk and resources*, not about being "better". A Tier 2 small business can be perfectly appropriate.
- **Memorizing control IDs without meaning.** You will be asked "what does this *do*?" more often than "what number is it?". Learn each control's outcome first.
- **Forgetting the mapping artifact.** In real engagements, the mapping table *is* the deliverable that ties policy to framework to evidence. Start one early.

## Checklist / Self-Test

- [ ] I can name the six CSF 2.0 functions and give one outcome example for each.
- [ ] I can list the seven RMF steps in order and say what an ATO is.
- [ ] I know the four Annex A themes of ISO/IEC 27001:2022 and roughly how many controls each contains.
- [ ] I can explain the difference between CIS v7 (20) and v8 (18) and what IG1/IG2/IG3 mean.
- [ ] I can state in one sentence what COBIT is for, and name its five domains.
- [ ] I can map one concrete requirement across CIS, ISO 27001, and CSF without looking anything up.
- [ ] I can explain the difference between a CSF profile and an implementation tier.

## Further Resources

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) — CSF 2.0, quick-start guides, and informative references.
- [NIST SP 800-37 Rev. 2 (RMF)](https://csrc.nist.gov/publications/detail/sp/800-37/rev-2/final) — the authoritative RMF publication.
- [NIST SP 800-53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) — the control catalog RMF selects from.
- [ISO/IEC 27001](https://www.iso.org/standard/27001.html) — official standard page.
- [CIS Controls](https://www.cisecurity.org/controls) — the 18 controls, IGs, and companion guides.
- [ISACA — COBIT](https://www.isaca.org/resources/cobit) — governance framework resources.
