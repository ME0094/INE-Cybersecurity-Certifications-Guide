# eEDA — Enterprise Defense Administrator

> Module: 03-BlueTeam · INE-Cybersecurity-Certifications-Guide
> Official program: [INE Security — eEDA Certification](https://ine.com/security/certifications/eeda-certification)
>
> Official classification: INE Security lists the eEDA as a **defense (Blue Team)**
> credential — [eEDA Certification](https://ine.com/security/certifications/eeda-certification).

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

The `methodology/` folder carries those pillars into **nine numbered phases**: 01–04 are the conceptual notes above, and 05–09 are the operating phases an administrator owns — asset inventory and configuration, identity and privileged access, vulnerability and patch management, continuity and recovery, and the SOC / incident-response interface.

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
- Keep **evidence defensible**: know which auditing source answers a given question, and how long each one actually retains what it records.
- Keep an **asset and software inventory** honest, tier assets by criticality, and hold systems to **configuration baselines** while measuring drift.
- Review **access and privileged accounts** on a schedule, and keep service credentials out of scripts and repositories.
- Run a **vulnerability and patch cycle** with defensible SLAs, and **prove recovery** with restore tests against agreed RTO and RPO.
- Work the **SOC / incident-response interface**: supply the log and asset context analysts need, and hand over cleanly under time pressure.
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
│   ├── 04-security-engineering.md
│   ├── 05-asset-inventory-and-configuration.md
│   ├── 06-identity-and-privileged-access.md
│   ├── 07-vulnerability-and-patch-management.md
│   ├── 08-continuity-and-recovery.md
│   └── 09-soc-and-incident-response-interface.md
├── tools/                     <- the "how": guides for the tools defenders use
│   ├── security-frameworks.md
│   ├── compliance-tools.md
│   ├── hardening-and-configuration-scanning.md
│   ├── endpoint-inventory-and-query.md
│   └── system-auditing-and-log-integrity.md
├── labs/                      <- the "practice": hands-on exercises
│   ├── security-policy-exercises.md
│   ├── inventory-and-unauthorized-software.md
│   └── risk-exception-writeup.md
└── cheatsheets/               <- the "reference": quick lookup tables
    └── terminology-reference.md
```

Suggested workflow:

1. **Read the methodology in order.** Phases [01-security-governance](methodology/01-security-governance.md), [02-risk-management](methodology/02-risk-management.md), [03-compliance-basics](methodology/03-compliance-basics.md), and [04-security-engineering](methodology/04-security-engineering.md) give you the conceptual spine of the whole program; phases 05–09 turn it into administrator work:
   - [05-asset-inventory-and-configuration](methodology/05-asset-inventory-and-configuration.md) — what you own, what is installed on it, and the configuration baselines it is held to.
   - [06-identity-and-privileged-access](methodology/06-identity-and-privileged-access.md) — joiner/mover/leaver, access reviews, privileged access patterns, and service accounts and secrets.
   - [07-vulnerability-and-patch-management](methodology/07-vulnerability-and-patch-management.md) — the discovery-to-verification cycle, patch SLAs, and what to do with what you cannot patch.
   - [08-continuity-and-recovery](methodology/08-continuity-and-recovery.md) — RTO/RPO inputs, backup design rules, restore testing, and recovery ordering.
   - [09-soc-and-incident-response-interface](methodology/09-soc-and-incident-response-interface.md) — what the administrator owes the SOC, what comes back, the handover packet, and containment authorization.
2. **Study the five tool guides**, and run the commands yourself on a Linux VM:
   - [security-frameworks](tools/security-frameworks.md) — NIST CSF, NIST RMF, ISO/IEC 27001, CIS Controls, and COBIT, and how to compare and map them.
   - [compliance-tools](tools/compliance-tools.md) — OpenSCAP, Lynis, osquery, and auditd for scan-and-evidence work on Linux, plus what SIEM and GRC platforms add.
   - [hardening-and-configuration-scanning](tools/hardening-and-configuration-scanning.md) — assessing a host against a benchmark, turning scan output into evidence, and Windows checks that work without WMI.
   - [endpoint-inventory-and-query](tools/endpoint-inventory-and-query.md) — osquery queries plus agentless inventory on Windows and Linux, and how to detect unauthorized software.
   - [system-auditing-and-log-integrity](tools/system-auditing-and-log-integrity.md) — auditd rules, journald persistence, Windows channel configuration, and what makes a log survive as evidence.
3. **Do the labs**, in this order:
   - [security-policy-exercises](labs/security-policy-exercises.md) — draft a policy, build a risk register, map CIS Controls, and interpret real scan output.
   - [inventory-and-unauthorized-software](labs/inventory-and-unauthorized-software.md) — build an inventory, publish an allowlist, diff two snapshots, and detect configuration drift.
   - [risk-exception-writeup](labs/risk-exception-writeup.md) — write and defend a risk exception with a compensating control, a named owner, and an expiry date.
4. **Keep the cheatsheet open** — [terminology-reference](cheatsheets/terminology-reference.md) — and use it while writing any summary, report, or self-test answer.
5. Finish each file with its **Checklist / Self-Test**; only move on when every box is honest to check.

### Suggested Study Plan

| Week | Focus | Concrete output |
|---|---|---|
| 1 | Methodology 01–05: governance, risk, compliance, engineering, asset inventory | One-page summary of each note |
| 2 | Methodology 06–09: identity, patching, recovery, SOC/IR interface; read the five tool guides | Terminology quiz using the cheatsheet |
| 3 | Run the lab exercises (policy, risk register, CIS mapping, scans, inventory diff, exception memo) | AUP draft, 6-row risk register, CIS mapping table, saved scan reports, classified inventory diff, one signed risk exception |
| 4 | Re-run every file's Checklist / Self-Test; fill your gaps | All checkboxes checked with evidence |

Spacing matters more than cramming: this material is vocabulary-and-frameworks heavy, and it sticks when you *apply* each concept in the lab within a day or two of reading it.

## Common Mistakes & Tips

- **Confusing the four pillars.** Governance is *direction and accountability*; compliance is *meeting obligations*; risk management is *the decision process*; engineering is *the controls themselves*. If you cannot classify a task into one of these, re-read the methodology notes before going further.
- **Learning tool commands without learning interpretation.** `oscap` and `lynis` produce output that means nothing if you cannot explain *why* a finding matters and *what* to do about it. Always practice "scan → read → remediate → re-scan".
- **Treating frameworks as checklists to memorize.** Exams and interviews reward the ability to *map* a scenario to a framework, not to recite control IDs. Practice mapping repeatedly.
- **Writing policies that cannot be enforced or measured.** A good policy names the audience, the requirement, and who owns enforcement. Avoid vague sentences like "systems must be secure".
- **Forgetting residual risk.** After you implement a control, the risk that remains is still yours to document and accept.

## Checklist / Self-Test

- [ ] I can explain, in one paragraph each, what the eEDA certifies and who it is for.
- [ ] I can list the four knowledge pillars and give one concrete task per pillar.
- [ ] I have read the nine methodology notes in order and can summarize each in three sentences.
- [ ] I can explain why an asset inventory is the precondition for vulnerability, access, backup, and incident work.
- [ ] I have written one risk exception with a named owner, a compensating control, and an expiry date.
- [ ] I have restored from a backup and can state the RTO and RPO that restore actually proved.
- [ ] I have run at least one scan with Lynis or OpenSCAP on a Linux VM and written down what the output means.
- [ ] I have drafted one security policy and one risk register entry using the lab guides.
- [ ] I have produced an inventory diff, classified its dispositions, and written one finding from it.
- [ ] I can name which auditing source answers a given question, and what my hosts' log retention actually is.
- [ ] I can look up any GRC term in the terminology cheatsheet without opening a browser.
- [ ] I have completed the Checklist / Self-Test section of every file in this module.

> **Verification:** checked against the module tree on disk on 2026-09-19: the nine `methodology/` phases, the five `tools/` guides, the three `labs/` and the single `cheatsheets/` file listed above all exist, and every relative link in this README resolves — the repository-wide `node scripts/utilities/check-links.mjs .` run is clean (887 relative links, 0 broken).

## Further Resources

- [NIST Cybersecurity Framework (CSF 2.0)](https://www.nist.gov/cyberframework) — the CSF itself, quick start guides, and mapping resources.
- [NIST SP 800-37 Rev. 2 — Risk Management Framework](https://csrc.nist.gov/publications/detail/sp/800-37/rev-2/final) — the authoritative RMF process.
- [ISO/IEC 27001 — Information security management systems](https://www.iso.org/standard/27001.html) — official standard page and control overview.
- [CIS Controls](https://www.cisecurity.org/controls) — the 18 prioritized controls and implementation groups.
- [ISACA — COBIT](https://www.isaca.org/resources/cobit) — governance framework background.
- [OWASP](https://owasp.org/) — application-security references used when engineering defensive requirements.

---

> ⚠️ Personal study notes. No NDA-protected or actual exam content is included.
