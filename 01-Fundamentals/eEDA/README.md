# eEDA — Enterprise Defense Administrator

> Module: 01-Fundamentals · INE-Cybersecurity-Certifications-Guide
> Official program: [INE Security — eEDA Certification](https://ine.com/security/certifications/eeda-certification)

## What Is the eEDA?

The **Enterprise Defense Administrator (eEDA)** is INE Security's certification for the *defender* side of cybersecurity. While offensive certifications (like eJPT) teach you to break systems, eEDA focuses on how an enterprise **administers and defends** them. The name says it: you are expected to act as a security administrator inside an organization who understands why controls exist, how to operate them, and how to prove they work.

This module covers the four knowledge pillars the eEDA program is built around:

1. **Security governance** — how security is directed, organized, and accountable inside a company.
2. **Risk management** — identifying, analyzing, and treating risk in a structured way.
3. **Compliance** — understanding regulatory and framework obligations (and how tools verify them).
4. **Security engineering & defense** — hardening systems, auditing configuration, and monitoring for trouble.

> **Study-note policy.** These are public study notes written from general, publicly available knowledge. They deliberately contain **no actual exam questions, item pools, or NDA-protected material**. Use them to build durable skills, not to memorize answers.

### What Each Pillar Looks Like in Practice

| Pillar | Defender-side questions it answers | Where covered in this module |
|---|---|---|
| Security governance | Who owns security? What do our policies say? How are decisions made and overseen? | [methodology/01-security-governance](methodology/01-security-governance.md) |
| Risk management | What can hurt us? How big is it? What do we do about it and who decides? | [methodology/02-risk-management](methodology/02-risk-management.md) |
| Compliance | What rules bind us (GDPR, PCI DSS, HIPAA, internal standards)? How do we prove we meet them? | [methodology/03-compliance-basics](methodology/03-compliance-basics.md) |
| Security engineering & defense | How do we harden systems, audit configuration, and keep visibility? | [methodology/04-security-engineering](methodology/04-security-engineering.md) |

The distinction matters throughout your study: **governance decides, risk management prioritizes, compliance proves, and engineering builds.** A single activity usually touches several pillars — for example, running a hardening scan is *engineering*, but choosing which baseline to scan against is *compliance*, and deciding which findings to fix first is *risk management*.

## Target Audience

The eEDA is aimed at people who want to **start or formalize a career on the blue team**, including:

- **Entry-level security administrators** (SOC analyst, security admin, GRC junior roles).
- **IT professionals moving into security** (sysadmins, network admins) who already touch systems and now need a security lens.
- **Students or career-changers** who want a structured path into defense, governance, risk, and compliance.
- **Team members of compliance/audit engagements** who must understand frameworks such as NIST CSF, NIST RMF, ISO/IEC 27001, and CIS Controls.

A working knowledge of Linux, Windows, and basic networking (the kind eJPT or general IT experience provides) is a strong foundation before this module.

## Skills You Build

By working through this module you build practical, job-relevant abilities:

- Explain the difference between a **threat, vulnerability, risk, and control** and use the terms correctly in reports.
- Map enterprise requirements onto **NIST CSF, NIST RMF, ISO/IEC 27001 Annex A, CIS Controls, and COBIT**.
- Write and critique **security policies, standards, baselines, and an Acceptable Use Policy**.
- Build and maintain a **risk register** and propose treatment strategies (accept, mitigate, transfer, avoid).
- Run **compliance and hardening tools** — OpenSCAP, Lynis, osquery, auditd — and interpret their findings.
- Understand what **SIEM and GRC platforms** do in real enterprises and where they fit in a defense workflow.
- Speak the language of **audits, attestations, and evidence** so you can support an assessor or auditor.

## How to Use This Module's Folders

The module is organized the way you will actually *work* — first understand the phases, then learn the tooling, then practice:

```text
eEDA/
├── README.md                  <- this overview + study checklist
├── methodology/               <- the "why": numbered defense phases, read in order
│   ├── 01-security-governance.md
│   ├── 02-risk-management.md
│   ├── 03-compliance-basics.md
│   └── 04-security-engineering.md
├── tools/                     <- the "how": guides for the tools defenders use
│   ├── security-frameworks.md
│   └── compliance-tools.md
├── labs/                      <- the "practice": hands-on exercises
│   └── security-policy-exercises.md
└── cheatsheets/               <- the "reference": quick lookup tables
    └── terminology-reference.md
```

Suggested workflow:

1. **Read the methodology in order** — [01-security-governance](methodology/01-security-governance.md), [02-risk-management](methodology/02-risk-management.md), [03-compliance-basics](methodology/03-compliance-basics.md), [04-security-engineering](methodology/04-security-engineering.md). These give you the conceptual spine of the whole program.
2. **Study the two tool guides** — [security-frameworks](tools/security-frameworks.md) and [compliance-tools](tools/compliance-tools.md) — and run the commands yourself on a Linux VM.
3. **Do the lab** — [security-policy-exercises](labs/security-policy-exercises.md) — where you draft a policy, build a risk register, map CIS Controls, and interpret real scan output.
4. **Keep the cheatsheet open** — [terminology-reference](cheatsheets/terminology-reference.md) — and use it while writing any summary, report, or self-test answer.
5. Finish each file with its **Checklist / Self-test**; only move on when every box is honest to check.

### Suggested Study Plan

| Week | Focus | Concrete output |
|---|---|---|
| 1 | Governance + risk methodology notes | One-page summary of each note |
| 2 | Compliance + engineering methodology notes; read both tool guides | Terminology quiz using the cheatsheet |
| 3 | Run the lab exercises (policy, risk register, CIS mapping, scans) | AUP draft, 6-row risk register, CIS mapping table, saved scan reports |
| 4 | Re-run every file's Checklist / Self-test; fill your gaps | All checkboxes checked with evidence |

Spacing matters more than cramming: this material is vocabulary-and-frameworks heavy, and it sticks when you *apply* each concept in the lab within a day or two of reading it.

## Common Mistakes & Tips

- **Confusing the four pillars.** Governance is *direction and accountability*; compliance is *meeting obligations*; risk management is *the decision process*; engineering is *the controls themselves*. If you cannot classify a task into one of these, re-read the methodology notes before going further.
- **Learning tool commands without learning interpretation.** `oscap` and `lynis` produce output that means nothing if you cannot explain *why* a finding matters and *what* to do about it. Always practice "scan → read → remediate → re-scan".
- **Treating frameworks as checklists to memorize.** Exams and interviews reward the ability to *map* a scenario to a framework, not to recite control IDs. Practice mapping repeatedly.
- **Writing policies that cannot be enforced or measured.** A good policy names the audience, the requirement, and who owns enforcement. Avoid vague sentences like "systems must be secure".
- **Forgetting residual risk.** After you implement a control, the risk that remains is still yours to document and accept.

## Checklist / Self-test

- [ ] I can explain, in one paragraph each, what the eEDA certifies and who it is for.
- [ ] I can list the four methodology pillars and give one concrete task per pillar.
- [ ] I have read the four methodology notes in order and can summarize each in three sentences.
- [ ] I have run at least one scan with Lynis or OpenSCAP on a Linux VM and written down what the output means.
- [ ] I have drafted one security policy and one risk register entry using the lab guide.
- [ ] I can look up any GRC term in the terminology cheatsheet without opening a browser.
- [ ] I have completed the Checklist / Self-test section of every file in this module.

## Further Resources

- [NIST Cybersecurity Framework (CSF 2.0)](https://www.nist.gov/cyberframework) — the CSF itself, quick start guides, and mapping resources.
- [NIST SP 800-37 Rev. 2 — Risk Management Framework](https://csrc.nist.gov/publications/detail/sp/800-37/rev-2/final) — the authoritative RMF process.
- [ISO/IEC 27001 — Information security management systems](https://www.iso.org/standard/27001.html) — official standard page and control overview.
- [CIS Controls](https://www.cisecurity.org/controls) — the 18 prioritized controls and implementation groups.
- [ISACA — COBIT](https://www.isaca.org/resources/cobit) — governance framework background.
- [OWASP](https://owasp.org/) — application-security references used when engineering defensive requirements.

---

> ⚠️ Personal study notes. No NDA-protected or actual exam content is included.
