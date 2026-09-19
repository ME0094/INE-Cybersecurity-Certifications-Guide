# Terminology Reference — GRC & Defense Cheatsheet

> eEDA · Cheatsheets — INE-Cybersecurity-Certifications-Guide

## Purpose

A compact lookup for the vocabulary of governance, risk, compliance, and enterprise defense. Use it while reading the methodology notes, writing policies, or preparing summaries. Terms are grouped in small tables; the acronym list at the end covers the abbreviations you will meet most often.

## Core Risk Terms

| Term | Quick definition | Example / note |
|---|---|---|
| **Asset** | Anything of value to the organization (data, systems, people, reputation) | Customer database, AD domain, backup tapes |
| **Threat** | Anything that can cause harm (actor or event) | Ransomware gang, power outage, insider |
| **Vulnerability** | A weakness a threat could exploit | Unpatched CMS, open S3 bucket, weak password |
| **Exploit** | Code or technique that takes advantage of a vulnerability | Public exploit for CVE-2024-XXXX |
| **Risk** | The *potential* for loss when a threat meets a vulnerability | Risk = f(threat, vulnerability, impact) |
| **Likelihood** | How probable a risk event is (given controls) | Rated 1–5 in most registers |
| **Impact** | The damage if the event happens | Financial, operational, reputational, legal |
| **Inherent risk** | Risk before any controls are applied | What you would face with no defenses |
| **Residual risk** | Risk that remains after controls | The part you accept or transfer |
| **Exposure** | Degree to which an asset is open to a threat | Public vs. internal system |
| **Risk appetite** | How much risk leadership is willing to take | "No critical data outside company devices" |
| **Risk tolerance** | Acceptable deviation from the appetite | Specific thresholds per risk type |
| **Risk treatment** | Decision on what to do with risk | Accept / Mitigate / Transfer / Avoid |
| **Risk register** | The living list of identified risks | Columns: ID, asset, score, owner, treatment |

## Threat Actors & Events

| Term | Quick definition |
|---|---|
| **Threat actor** | Individual/group behind an attack (nation-state, cybercriminal, insider, hacktivist) |
| **Insider threat** | Risk originating from someone inside (malicious or accidental) |
| **APT** | Advanced Persistent Threat: well-resourced, long-dwell attacker |
| **Malware** | Malicious software (virus, worm, trojan, ransomware, spyware) |
| **Phishing / social engineering** | Tricking people into acting against their interests |
| **DDoS** | Distributed denial of service — overwhelming a service to take it down |
| **Data breach** | Unauthorized access/exfiltration of data |
| **Incident** | An event that harms (or risks harming) confidentiality, integrity, or availability |
| **IoC** | Indicator of Compromise: evidence an intrusion happened (hash, IP, log pattern) |
| **Zero-day** | Vulnerability or exploit unknown to the vendor |

## Controls & Safeguards

| Term | Quick definition | Example |
|---|---|---|
| **Control / safeguard / countermeasure** | Anything that reduces risk | Firewall, policy, training, backup |
| **Preventive** | Stops the bad thing | Access control, patching, MFA |
| **Detective** | Finds the bad thing in progress/after | Alerts, IDS, log review |
| **Corrective** | Repairs after the bad thing | Restore from backup, reimage |
| **Deterrent** | Discourages the actor | Warning banners, cameras |
| **Compensating** | Alternative control when the primary one can't be used | Manual review instead of automated tool |
| **Administrative (procedural)** | Policies, procedures, training | AUP, background checks |
| **Technical (logical)** | Technology-based | Firewalls, EDR, encryption |
| **Physical** | Tangible protections | Locks, badges, server-room access |
| **Defense in depth** | Layered, independent controls | Perimeter + host + app + data layers |
| **Least privilege** | Users get the minimum access needed | No local admin on workstations |
| **Separation of duties** | No single person controls a critical process alone | Approver ≠ requester for payments |
| **Baseline** | An agreed minimum security configuration | CIS Benchmark profile |
| **Hardening** | Reducing attack surface by configuration | Disable services, patch, restrict |

## Governance, Compliance & Audit Terms

| Term | Quick definition |
|---|---|
| **Governance** | Direction, accountability, and oversight of security ("who decides and who is responsible") |
| **Policy** | High-level mandatory statement of intent ("Users must use MFA") |
| **Standard** | Mandatory specific requirements supporting a policy ("MFA via TOTP or hardware key") |
| **Procedure** | Step-by-step how-to ("how to enroll a new device") |
| **Guideline** | Recommended, not mandatory, practice |
| **Compliance** | Conforming to laws, regulations, standards, or internal policy |
| **Regulation** | Binding rule from an authority (GDPR, HIPAA, SOX) |
| **Audit** | Independent, evidence-based examination against criteria |
| **Internal audit** | Run by the organization itself |
| **External audit / assessment** | Run by an independent third party |
| **Audit evidence** | Records proving a control operated (logs, reports, tickets) |
| **Attestation** | A formal statement/assurance about controls (e.g., SOC 2 report) |
| **Certification** | Third-party confirmation you meet a standard (ISO/IEC 27001) |
| **Accreditation** | Formal authorization to operate (US federal RMF context: ATO) |
| **Due diligence** | Reasonable investigation before a decision (e.g., vetting a vendor) |
| **Due care** | Acting the way a prudent organization would (implementing reasonable controls) |
| **FISMA / FedRAMP** | US federal compliance/cloud authorization programs (context for RMF) |
| **CIA triad** | Confidentiality, Integrity, Availability — the core security objectives |
| **Non-repudiation** | A party cannot deny an action (guaranteed by logs/signatures) |
| **ISMS** | Information Security Management System (ISO/IEC 27001's managed framework) |

## Control-Effectiveness Language

| Term | Quick definition |
|---|---|
| **In place** | The control exists |
| **Operating effectively** | The control works as designed (proven by evidence) |
| **Finding** | A gap or weakness an assessment discovered |
| **Remediation** | Fixing a finding |
| **POA&M** | Plan of Action and Milestones: documented plan to fix findings |
| **Material weakness** | Serious control gap (audit language) |

## Quick Acronym List

```text
AUP    Acceptable Use Policy
ATO    Authority To Operate
BCP    Business Continuity Planning
CIA    Confidentiality, Integrity, Availability
CIS    Center for Internet Security
COBIT Control Objectives for Information and Related Technologies (ISACA)
CSF    Cybersecurity Framework (NIST)
CVE    Common Vulnerabilities and Exposures
CVSS   Common Vulnerability Scoring System
DDoS   Distributed Denial of Service
DR     Disaster Recovery
EDR    Endpoint Detection and Response
FIM    File Integrity Monitoring
FISMA  Federal Information Security Modernization Act
GDPR   General Data Protection Regulation (EU)
GRC    Governance, Risk, and Compliance
HIPAA  Health Insurance Portability and Accountability Act (US)
HIPS/HIDS Host Intrusion Prevention/Detection System
IDS/IPS Intrusion Detection/Prevention System
IG     Implementation Group (CIS Controls)
IoC    Indicator of Compromise
IR     Incident Response
ISMS   Information Security Management System
ISO    International Organization for Standardization
MFA    Multi-Factor Authentication
NDA    Non-Disclosure Agreement
NIST   National Institute of Standards and Technology
OSCAL  Open Security Controls Assessment Language
PCI DSS Payment Card Industry Data Security Standard
PDCA   Plan-Do-Check-Act
PII    Personally Identifiable Information
PHI    Protected Health Information
POA&M  Plan of Action and Milestones
RMF    Risk Management Framework (NIST)
SIEM   Security Information and Event Management
SOAR   Security Orchestration, Automation, and Response
SOC    System and Organization Controls (AICPA reports); also Security Operations Center
SOX    Sarbanes-Oxley Act (US)
SSG    SCAP Security Guide
TTP    Tactics, Techniques, and Procedures
VPN    Virtual Private Network
```

## Common Mistakes & Tips

- **Risk ≠ vulnerability ≠ threat.** "We have a risk of unpatched servers" is sloppy; the unpatched server is the *vulnerability*, the exploit attempt is the *threat*, and the resulting business damage is the *risk*. Examiners and auditors test this distinction constantly.
- **Policy vs. standard vs. procedure.** Saying "our password policy is 14 characters" conflates them: the *policy* says strong authentication is required, the *standard* says 14+ characters, the *procedure* says where to change it. Keep the layers straight.
- **Audit ≠ penetration test.** An audit checks conformance against criteria with evidence; a pentest actively tries to break in. Different goals, methods, and reports.
- **Certification vs. attestation vs. accreditation.** A *certificate* (ISO 27001) is against a public standard; an *attestation* (SOC 2) is a report by a CPA firm over your controls; *accreditation/ATO* is an owner's formal acceptance of risk (US federal RMF).
- **SOC the report vs. SOC the team.** "SOC 2" is an AICPA attestation report; "the SOC" is the Security Operations Center. Context disambiguates — use the full phrase when writing.
- **Don't memorize definitions cold.** Practice by classifying real examples: "failed login alerts" → detective technical control; "MFA" → preventive technical; "AUP" → administrative preventive.

## Checklist / Self-Test

- [ ] I can define asset, threat, vulnerability, and risk with a real example of each.
- [ ] I can distinguish inherent risk, residual risk, risk appetite, and risk tolerance.
- [ ] I can classify any control as preventive/detective/corrective and as administrative/technical/physical.
- [ ] I can tell a policy, standard, procedure, and guideline apart and give one example of each.
- [ ] I can explain the difference between audit, attestation, certification, and accreditation.
- [ ] I can expand every acronym in the list above and say which domain it belongs to.
- [ ] I can write one sentence using GRC terminology correctly to describe a real security task.

## Further Resources

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) — glossary of cybersecurity terms in NIST context.
- [NIST Computer Security Resource Center (CSRC)](https://csrc.nist.gov/glossary) — authoritative glossary of security terms.
- [CIS Controls](https://www.cisecurity.org/controls) — terminology used with the 18 controls.
- [ISO/IEC 27001](https://www.iso.org/standard/27001.html) — official ISMS standard page.
- [OWASP community pages](https://owasp.org/www-community/) — project and initiative index for application-security terminology (the standalone Glossary of Terms page this list used before is gone).
