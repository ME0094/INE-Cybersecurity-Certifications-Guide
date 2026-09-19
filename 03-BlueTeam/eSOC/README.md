# eSOC — SOC Analyst Study Module

> Blue team · 03-BlueTeam · INE-Cybersecurity-Certifications-Guide

This module is a self-paced, hands-on study companion for the INE Security **eSOC (Security Operations Center Analyst)** certification. It is written from general public knowledge about the role of a tier-1 SOC analyst — monitoring, detection, investigation, and response — and about the tools and techniques SOC teams use every day.

> ⚠️ **Important framing.** This repository contains personal study notes only. It does **not** reproduce exam questions, lab walkthroughs, or any material protected by INE's NDA. Always practice in environments you own or are authorized to test, and read the official INE course material for authoritative guidance.

## What the eSOC Certification Covers

eSOC targets people who want to start a career as an entry-level (tier-1) Security Operations Center analyst. In general terms, the certification validates the practical skills a SOC analyst needs on duty:

- **Monitoring** — understanding what a SOC is, how alert queues work, and how to keep eyes on telemetry coming from endpoints, servers, and network devices.
- **Detection** — knowing how detection tools (SIEM, EDR, and detection-as-code rule formats such as Sigma and YARA) turn raw events into meaningful alerts.
- **Investigation** — triaging alerts, hunting for context, correlating events across time and sources, and asking the right questions before deciding anything.
- **Response** — knowing what to do when an alert is confirmed: containment steps, escalation paths, evidence handling, and clear written documentation.

Think of the exam as testing "would you survive a real first shift at a SOC?" rather than "can you recite theory?" — which is exactly why this module emphasizes a lab you can click around in.

## Skills You Will Build

Working through this module (and the official INE lab environment) develops the following analyst habits:

| Skill | Why it matters |
|---|---|
| Log literacy | Read Windows Event Logs (4625 failed logon, 4688 process creation, 4104 PowerShell script block) and Linux/auth logs without panic. |
| SIEM fluency | Query the Elastic Stack or Wazuh dashboards, filter by time and host, and pivot from one event to the full timeline. |
| Rule literacy | Read and write basic Sigma rules and YARA rules, and understand how they plug into a detection pipeline. |
| Triage discipline | Classify alerts quickly: benign, suspicious, or malicious — with a documented reason. |
| Communication | Write shift notes and escalation summaries that a tier-2 analyst or incident responder can act on. |
| Safe experimentation | Generate and detect sample events in a disposable lab, never in production or against systems you do not own. |

## Before You Start: Prerequisites & Mindset

You do not need a security background to begin, but a few foundations make the whole module smoother:

- **Comfort with the command line.** You should be able to run commands in PowerShell and a Linux shell and read their output without fear. The labs assume you can copy, adapt, and troubleshoot a command.
- **Networking basics.** IP addresses, ports, DNS, and what a firewall does. You will read `source.ip`, `destination.port`, and DNS queries constantly.
- **Windows fundamentals.** Users and groups, processes and services, and the Event Viewer. The SOC world speaks Windows Event IDs before anything else.
- **Your own isolated lab machines.** VirtualBox or VMware VMs (or cloud VMs you control) where you are free to break things and reset with snapshots.
- **A documentation habit.** Take notes as you go: what you installed, what you generated, what fired, and why. That habit *is* the job.

Mindset matters more than tooling: be comfortable saying "I don't know yet", be systematic instead of fast, and treat every false positive as a tuning lesson rather than an annoyance.

## How to Use This Module

The folder structure mirrors how a SOC analyst actually works: methodology first, then tools, then practice.

```text
eSOC/
├── README.md                  <- You are here: overview + roadmap
├── methodology/               <- Core skills, one file per discipline
│   ├── 01-monitoring.md
│   ├── 02-detection.md
│   ├── 03-investigation.md
│   ├── 04-response.md
│   ├── 05-use-cases-and-tuning.md
│   ├── 06-threat-intel-and-enrichment.md
│   ├── 07-soc-metrics.md
│   └── 08-shift-handover-and-case-notes.md
├── tools/                     <- Tooling you will operate
│   ├── siem-tools.md
│   ├── query-languages.md
│   ├── edr-and-endpoint-telemetry.md
│   ├── enrichment-and-ti-tools.md
│   ├── case-management.md
│   ├── automation-and-soar.md
│   └── detection-rules/
│       ├── sigma-rules/
│       │   ├── .gitkeep
│       │   └── sigma-example.yml
│       └── yara-rules/
│           ├── .gitkeep
│           └── yara-example.yar
├── labs/                      <- Build it, break it, detect it
│   ├── soc-scenarios.md
│   ├── sigma-rule-tuning.md
│   └── anomalous-logon-investigation.md
└── cheatsheets/               <- Quick reference for the desk
    └── alert-triage-guide.md
```

Suggested order of attack:

1. **Read the methodology files** (`methodology/01` → `08`) to learn the vocabulary and the analyst's mental model. Take notes as you go. Phases 5–8 carry on past the day-one loop: [05-use-cases-and-tuning](methodology/05-use-cases-and-tuning.md) is about keeping a rule alive — its lifecycle, the tuning backlog, the quarterly review; [06-threat-intel-and-enrichment](methodology/06-threat-intel-and-enrichment.md) is using threat intelligence in triage honestly — confidence, freshness, provenance; [07-soc-metrics](methodology/07-soc-metrics.md) defines the measures that describe SOC performance and how the same numbers get misread; [08-shift-handover-and-case-notes](methodology/08-shift-handover-and-case-notes.md) covers the handover note, the case note, and the open action register.
2. **Study the tooling files**, starting with [siem-tools](tools/siem-tools.md) (install a platform, query it, diagnose it), then [query-languages](tools/query-languages.md) (KQL, SPL, EQL and ES|QL side by side, and the syntax traps that quietly return nothing), [edr-and-endpoint-telemetry](tools/edr-and-endpoint-telemetry.md) (reading a process tree, what the console can act on, where EDR coverage ends), [enrichment-and-ti-tools](tools/enrichment-and-ti-tools.md) (MISP, VirusTotal, Shodan, reputation and ownership lookups), [case-management](tools/case-management.md) (TheHive and Cortex: cases, tasks, observables, templates) and [automation-and-soar](tools/automation-and-soar.md) (what to automate, what must stay human, and how a playbook is structured) — with the example Sigma and YARA rules and the official docs open in another tab.
3. **Build the lab** described in [soc-scenarios](labs/soc-scenarios.md) and run every drill until the expected outcomes match reality, then work the two deeper labs: [sigma-rule-tuning](labs/sigma-rule-tuning.md) follows one case from the triage observation to a tuned, validated Sigma rule, and [anomalous-logon-investigation](labs/anomalous-logon-investigation.md) works an impossible-travel alert and a valid-credential logon across `4624`/`4625`/`4648`/`4672`.
4. **Print or keep open** the `cheatsheets/alert-triage-guide.md` and use it to triage every alert you generate in the lab — practice the template until it is reflex.
5. Return to the official INE course to fill any gaps; treat these notes as revision, not as the source of truth.

## Study Roadmap

A realistic rhythm for a motivated part-time learner (adjust to your own schedule):

- **Week 1 — Foundations.** Read `methodology/01-monitoring.md` and `02-detection.md`. Install VirtualBox/VMware and either Docker Desktop or WSL2 if you do not have them yet. Write down the acronyms you meet (SIEM, EDR, SOC, IoC, FP/TP) in your own words.
- **Week 2 — Build.** Stand up the lab from `labs/soc-scenarios.md`. Do not rush: a working Elastic Stack or Wazuh install is the single biggest enabler for everything after this.
- **Week 3 — Tooling.** Work through `tools/siem-tools.md`: collect logs, run queries, watch alerts fire. Read `sigma-example.yml` and `yara-example.yar` line by line; modify and re-test them.
- **Week 4 — Scenarios.** Run the scenario drills in `labs/soc-scenarios.md`. For each alert you generate, fill in the triage template from `cheatsheets/alert-triage-guide.md` and write a mini report.
- **Week 5 — Hardening.** Re-read `methodology/03-investigation.md` and `04-response.md`. Re-run your favourite drill end to end, but now with a "colleague" (or a second window) asking you to explain every decision aloud.
- **Week 6 — Mock day.** Recreate a full "shift": generate several sample events in a row, triage them all, escalate the ones that deserve it, and write shift notes. Review the official INE practice material, then book your exam.

Repeat the drill week whenever you feel rusty — this is a skill certification, and skills decay without practice.

## Common Mistakes & Tips

- **Skipping the lab setup.** Reading about the Elastic Stack is not the same as running it. If you stall, still build *a* lab: even Wazuh alone, or a plain `grep` over Windows event exports, teaches the underlying concepts.
- **Memorizing instead of reasoning.** Exams of this style reward the ability to look at an alert and decide what to do. Practice the reasoning loop: *what happened → is it anomalous → how confident am I → what next?*
- **Ignoring the "why".** When an alert is a false positive, write down *why* it fired. That habit is what makes you a good rule tuner later.
- **Not touching the actual tools.** At minimum, run a Kibana query and a `yara` scan before exam week. Twenty minutes of clicking beats two hours of flashcards.
- **Confusing open source with "free cloud".** Elastic Stack and Wazuh are free to self-host but you still pay with RAM and patience. Give your lab VM 6–8 GB of RAM and be patient with first-time downloads.

## Module Checklist

- [ ] Read all eight methodology files and summarize each in my own words.
- [ ] Understand the tier-1 SOC analyst role across monitoring, detection, investigation, and response — and can explain the difference between a SIEM, an EDR, and a SOAR out loud.
- [ ] Can name at least five Windows Event IDs relevant to SOC work and what each means.
- [ ] Have a working lab (Elastic Stack or Wazuh) with logs flowing from at least one endpoint.
- [ ] Can write and run a Kibana/OpenSearch query plus a simple Sigma rule and a YARA rule.
- [ ] Completed all scenario drills in `labs/soc-scenarios.md` and verified the expected outcomes.
- [ ] Filled in the alert triage template from the cheatsheet for every alert I generated in the lab.
- [ ] Re-read the methodology files after the lab drills, then reviewed the official INE material and practice environment before attempting the exam.

> **Verification:** checked against the module tree on disk on 2026-09-19: the eight `methodology/` files, the six `tools/` guides, the two rule files under `tools/detection-rules/`, the three `labs/` and the single `cheatsheets/` file listed above all exist, and every relative link in this README resolves — the repository-wide `node scripts/utilities/check-links.mjs .` run is clean (887 relative links, 0 broken).

## Further Resources

- INE Security eSOC official course page (enrollment and authoritative syllabus): <https://ine.com/security/certifications/esoc-certification>
- MITRE ATT&CK — https://attack.mitre.org/ (technique IDs used across these notes)
- SigmaHQ rule repository — https://github.com/SigmaHQ/sigma
- Sigma documentation — https://sigmahq.io/
- YARA documentation — https://yara.readthedocs.io/
- Elastic Security / SIEM docs — https://www.elastic.co/guide/index.html
- Wazuh documentation — https://documentation.wazuh.com/
- TryHackMe & Hack The Box SOC-oriented free/beginner paths (practice, not exam dumps)
