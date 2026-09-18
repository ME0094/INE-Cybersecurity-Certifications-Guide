# eCTHP — Certified Threat Hunting Professional

> Blue Team · eCTHP module — INE Cybersecurity Certifications Study Guide
>
> Companion study material for the eCTHP certification. This is **general public study content**: it explains threat hunting concepts, methodology, and hands-on tooling in an authorized lab context. It does not reproduce exam content, questions, or anything covered by NDA.

## What eCTHP covers

eCTHP (**Certified Threat Hunting Professional**) is INE Security's Blue Team credential for **threat hunting**: the proactive, hypothesis-driven search for adversary activity that your existing detections did not catch. INE Security published an updated version of the certification on 24 July 2025 ([launch announcement](https://ine.com/newsroom/ine-security-launches-updated-certified-threat-hunting-professional-ecthp-cybersecurity-certification), [background on the update](https://ine.com/newsroom/ine-updates-threat-hunting-certification-as-adversaries-evolve-beyond-malware)).

The discipline in this module rests on five pillars:

1. **Hunting program** — running hunting as a repeatable capability rather than as heroics: roles, rituals, target selection, and metrics.
2. **Hypothesis generation** — deciding *what* to hunt for, from threat intelligence, MITRE ATT&CK, adversary emulation, and detection gaps.
3. **Telemetry and data sources** — knowing what your endpoint, network, identity, and cloud data can actually answer, and where the blind spots are.
4. **Hunting tradecraft** — executing the loop: hypothesis → query → triage → pivot → conclusion, by ATT&CK tactic, across hosts and over time.
5. **Detection engineering** — converting a confirmed finding into a maintained detection, and feeding the result back to the SOC and to IR.

**The core idea: a hunt starts with a hypothesis, not an alert.** An alert answers a question somebody already wrote down; a hunt asks a new one. If you begin by opening your SIEM and scrolling, you are not hunting — you are reading a queue with extra steps. Writing the hypothesis first is what makes the result falsifiable, reviewable, and worth the analyst hours it costs.

> Framing note: exam logistics (domains, question mix, passing criteria, lab environment) are published by INE and change over time — always check the [official eCTHP page](https://ine.com/security/certifications/ecthp-certification) for current, authoritative details before you book the exam.

## Skills you build

Working through this module develops the abilities that separate a hunter from an alert triager:

- Writing a **falsifiable hunting hypothesis** with a subject, a behaviour, a data source, and confirmation criteria.
- Knowing which **telemetry** answers which question — and when the data you need simply does not exist yet.
- Querying endpoint, network, identity, and cloud data fluently (KQL, SPL, VQL, Zeek logs, osquery, auditd).
- Hunting by **ATT&CK tactic**: execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, C2, and exfiltration — with the artifacts and event IDs that betray each one.
- Correlating **across hosts** and reconstructing a timeline instead of staring at one machine.
- Turning a finding into a **maintained detection rule** (Sigma plus SIEM logic), then validating it with adversary emulation.
- Documenting a hunt so that a colleague can **re-run it from your notes** and a decision-maker can act on it.
- Measuring improvement: coverage gained, false positives introduced, and telemetry gaps closed.

## Module layout

This folder is your study workspace. Each subfolder has a specific role:

| Path | Purpose |
| --- | --- |
| [README.md](README.md) | This overview: what to learn, in what order, and how to self-check. |
| [methodology/](methodology/) | Phase-by-phase notes in working order: [01-hunting-program](methodology/01-hunting-program.md), [02-hypothesis-generation](methodology/02-hypothesis-generation.md), [03-telemetry-and-data-sources](methodology/03-telemetry-and-data-sources.md), [04-hunting-tradecraft](methodology/04-hunting-tradecraft.md), [05-detection-engineering](methodology/05-detection-engineering.md). |
| [tools/](tools/) | Platform and tool references: [hunting-platforms](tools/hunting-platforms.md) (SIEM and storage, endpoint platforms, notebook workflow, case tracking), [endpoint-tools](tools/endpoint-tools.md) (Sysmon, Windows Event Log, PowerShell logging, auditd, osquery, Autoruns, Hayabusa, Chainsaw, YARA), and [network-tools](tools/network-tools.md) (Zeek, NetFlow, DNS, proxy). |
| [labs/](labs/) | Build-your-own range and drills: [hunting-range-setup](labs/hunting-range-setup.md), then guided work in [hunting-exercises](labs/hunting-exercises.md). |
| [cheatsheets/](cheatsheets/) | Desk references: [hunting-queries](cheatsheets/hunting-queries.md) (KQL, SPL, VQL, Zeek, osquery, auditd) and [windows-artifacts](cheatsheets/windows-artifacts.md). |

> Every query in this module is a **syntax reference for you to run in your own lab**. This repository ships no captured command output: the examples were written from the documented syntax of each tool, not executed against a live SIEM or endpoint. Treat them as starting points to adapt, and confirm tool flags against the documentation for the version you have installed.

## Prerequisites and suggested environment

You will get the most from this module if you already have:

- **Command-line comfort** on Windows (PowerShell) and Linux — most hunting starts with a shell, not a dashboard.
- **Operating-system literacy** — processes and parent processes, services, scheduled tasks, registry autostarts, systemd units, cron, SSH keys.
- **Networking basics** — TCP/IP, DNS, TLS, HTTP, and what a forward proxy does. You will read `id.orig_h`, `RemoteIP`, and `query` fields constantly.
- **One query language** — basic KQL (Microsoft Sentinel / Defender) or SPL (Splunk). You can learn the other one as you go.
- **MITRE ATT&CK fluency** — tactics, techniques, and sub-technique IDs (T1059.001, T1547.001, and friends).

Recommended practice range — build it once, snapshot it, and hunt in it repeatedly:

- **One Windows VM** with **Sysmon** installed and a configuration that logs process creation with command lines, network connections, and image loads. Add PowerShell script block logging and command-line audit policy.
- **One Linux VM** with `auditd` running a small rule set, plus `journald`, `sshd`, and a shell history you can read.
- **One collector** — a SIEM or log platform (Elastic Stack, Wazuh, Splunk free, or a Velociraptor server) that ships and stores events from both VMs. Hunting needs retained, searchable data; a dashboard you cannot query is not telemetry.
- **One emulation toolkit** — Atomic Red Team and, optionally, MITRE Caldera, to generate the activity you are going to hunt for.

> Snapshot the range before each exercise. Hunting practice means generating suspicious behaviour on purpose, and you want a one-click reset after you have wrecked it.

## Key terms you will meet

| Term | Meaning in one line |
| --- | --- |
| Threat hunting | Proactive, hypothesis-driven search for adversary activity that detections missed. |
| Hypothesis | A falsifiable statement of expected attacker behaviour plus the data that would confirm or refute it. |
| IOC | Indicator of compromise — a hash, IP, domain, or filename. Cheap to change, cheap to detect. |
| TTP | Tactics, techniques, and procedures — *how* the adversary operates. Expensive to change, hard to detect. |
| Telemetry | The raw events your environment records: process creates, network flows, logons, file writes. |
| Data source | A specific store of telemetry (Sysmon, Security event log, Zeek, CloudTrail) with known coverage. |
| Detection engineering | Turning observed behaviour into a tested, versioned, tuned detection rule. |
| Coverage gap | A technique you cannot see, either because the rule is missing or the telemetry never existed. |
| False negative | Malicious activity that occurred and produced no alert. The thing hunting exists to fix. |
| False positive | An alert raised by benign activity; a tuning problem, not a failure. |
| Pivot | Moving from one artifact (user, host, hash, IP, pipe) to every other place it appears. |
| Beaconing | Regular, periodic outbound connections from an implant — visible as a rhythm, not a payload. |
| Pyramid of Pain | The idea that detection value rises as you move from hashes to TTPs, because TTPs cost the adversary more to change. |
| Hunt journal | The dated record of hypothesis, queries, data used, findings, and verdict for each hunt. |
| Purple teaming | Hunters, detection engineers, and red teamers working the same technique together to fix coverage. |

## What makes a hunt defensible

These principles run through every phase in `methodology/` — internalize them before you write your first query:

1. **Write the hypothesis before the query.** A conclusion reached first and justified afterwards is not a hunt.
2. **Prove your telemetry before you trust an absence.** "No results" means either the adversary was not there *or* the data never arrived. Validate the source with a known-good event first.
3. **Record queries verbatim.** A hunt that cannot be re-run is an anecdote.
4. **Corroborate.** One artifact is a lead; two independent sources agreeing are a finding.
5. **Separate fact from inference.** "A process created a scheduled task" is a fact; "an attacker established persistence" is an interpretation, and it must be labelled as one.
6. **Know your gaps.** Document what you could not see and why. An honest gap becomes a collection request; a hidden one becomes a future breach.
7. **Timebox and stop.** A hunt that runs forever produces nothing and starves the next one. Decide the end condition when you write the hypothesis.
8. **Do no harm.** Read-only collection, no tipping off the adversary, and no touching production hosts without authorization and an IR liaison.

## How to use this module

Treat the folders as concentric practice rings — read, then do, then compress into memory:

1. **Read the methodology files in order.** Program → hypotheses → telemetry → tradecraft → detection engineering mirrors how a hunt is planned, run, and closed out.
2. **Build the range** from `labs/hunting-range-setup.md` before reading the tradecraft file; you will understand the artifacts far faster once you can generate them yourself.
3. **Write hypotheses before you touch a tool.** Use `methodology/02-hypothesis-generation.md` and keep a hunt journal from the first day.
4. **Run the drills** in `labs/hunting-exercises.md` — emulation first, hunt second, detection third. Never read the answer before you have written your queries.
5. **Convert every confirmed finding into a rule** and validate it with the same emulation that produced it.
6. **Self-check** with each file's "Checklist / Self-Test" and the module checklist below before moving on.

## Study roadmap

A realistic self-paced plan for someone with basic Windows/Linux and query-language comfort (adjust weeks to your schedule):

| Stage | Focus | Output |
| --- | --- | --- |
| Week 1 | Fundamentals + program: vocabulary, roles, the hunting loop | Written notes on hunting vs. monitoring vs. detection, plus your own one-page hunt process. |
| Week 2 | Telemetry + range | A Windows VM with Sysmon, a Linux VM with auditd, and a collector where you can find an event you generated on purpose. |
| Week 3 | Hypothesis generation | A hunt journal containing three falsifiable hypotheses with data sources and confirmation criteria. |
| Week 4 | Tradecraft I — endpoint | One completed hunt on execution and persistence: queries, triage, pivots, written verdict. |
| Week 5 | Tradecraft II — network and correlation | One hunt across at least two hosts using network telemetry, with a timeline of what you found. |
| Week 6 | Detection engineering + report | One Sigma rule validated by emulation, deployed and tuned, plus one full hunt report. |

## Lab ethics & authorization

- Hunt **only** in environments you own or are explicitly authorized to investigate. `labs/hunting-range-setup.md` builds a range precisely so you never need to improvise on production.
- **Get written authorization** before hunting on any real network — hunting reads user activity, and in many jurisdictions that means personal data.
- Treat emulation tools (Atomic Red Team, Caldera) as live malware: run them in a disposable, isolated VM with snapshots and no shared folders.
- **Read-only by default** in a real environment: collect copies, do not delete attacker files, do not "clean up" while a hunt is open, and coordinate with IR before touching a host.
- **Minimize data.** Collect what the hypothesis needs, not what the platform happens to hold. Hunting is not a licence to browse everyone's mailbox.
- When a hunt finds real malicious activity, **stop hunting and start responding** — hand it to the incident response process with your evidence intact.

## Common misconceptions

- **"Hunting is just threat intelligence."** Intelligence tells you what is possible; hunting verifies whether it is happening *in your environment*. An IOC feed is an input, not a hunt.
- **"The SIEM will tell me."** A SIEM answers the questions someone already wrote rules for. Hunting exists exactly for the activity that has no rule yet.
- **"No alerts means no compromise."** It usually means no coverage. Absence of evidence is only meaningful once you have proven the data source works.
- **"Only TTPs matter, IOCs are worthless."** Hashes and domains are cheap and perishable, but they are still excellent *starting points* for a pivot. Use them to open a hunt, not to close one.
- **"Hunting is a one-off project."** A hunt that finds nothing still produced value if it exercised a data source and closed a gap. A programme that stops after the first quiet month stops learning.
- **"I need an EDR and a data lake first."** You need the telemetry your hypothesis requires. Start with Sysmon and Zeek; add platforms when a gap justifies them.
- **"Finding nothing means the hunt failed."** A refuted hypothesis, documented with the queries that refuted it, is a result. An unfalsifiable hunt that "looked around" is not.

## Where this fits the Blue Team path

Hunting sits between detection and response: the SOC runs the alerts, the hunter looks for what the alerts miss, IR takes over when something is real, and forensics explains it afterwards. The material here pairs directly with the other Blue Team modules:

- [eSOC](../eSOC/README.md) — monitoring, triage, and detection rule formats. Hunting starts where SOC coverage ends and feeds new rules back into it.
- [eCIR](../eCIR/README.md) — incident response lifecycle. Hunting hands a confirmed intrusion to IR with scope and evidence already gathered.
- [eCDFP](../eCDFP/README.md) — forensics, acquisition, and timeline discipline. When a hunt escalates, forensic methods make the findings stand up.

In short: **the SOC watches what you know, the hunter looks for what you do not, IR handles what is found, and forensics proves it.**

## Checklist / Self-Test

Run through this module checklist — each item maps to a concrete artifact you should be able to produce:

- [ ] I can explain the difference between monitoring, detection, and hunting, and where each one stops.
- [ ] I can state the hunting loop (hypothesis → query → triage → pivot → conclusion) and where detection engineering closes it.
- [ ] I wrote three falsifiable hypotheses with subject, behaviour, data source, and confirmation criteria.
- [ ] My range produces endpoint, network, and authentication telemetry I can query end to end.
- [ ] I can name the Sysmon event IDs for process creation, network connection, registry value set, image load, and driver load.
- [ ] I completed at least one hunt per major tactic (execution, persistence, lateral movement, C2) with queries recorded verbatim.
- [ ] I turned one confirmed finding into a Sigma rule and validated it by running the emulation that produced it.
- [ ] I documented at least one telemetry gap and what it would take to close it.
- [ ] I wrote one hunt report that another analyst could re-run from the document alone.
- [ ] I know when a hunt must stop and become an incident.

## Further Resources

- **Official eCTHP product page** (current syllabus, logistics, and FAQ) — https://ine.com/security/certifications/ecthp-certification
- **INE Security — updated eCTHP launch announcement** — https://ine.com/newsroom/ine-security-launches-updated-certified-threat-hunting-professional-ecthp-cybersecurity-certification
- **INE Security — why the threat hunting certification was updated** — https://ine.com/newsroom/ine-updates-threat-hunting-certification-as-adversaries-evolve-beyond-malware
- **MITRE ATT&CK** (tactics, techniques, and data source mappings) — https://attack.mitre.org/
- **MITRE Cyber Analytics Repository (CAR)** (analytic pseudocode and coverage) — https://car.mitre.org/
- **Sigma** (vendor-neutral detection rule format) — https://sigmahq.io/
- **NIST SP 800-61 Rev. 2**, *Computer Security Incident Handling Guide* — https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
