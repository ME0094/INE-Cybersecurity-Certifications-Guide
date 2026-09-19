# eCIR — Certified Incident Responder (Study Module)

> Area: 03-BlueTeam · INE-Cybersecurity-Certifications-Guide · English study companion

This folder is an English study guide for **INE Security's eCIR (Certified Incident
Responder)** certification track. It is written from public information only and is
meant to build the real-world skills the certification domain represents. It contains
**no actual exam content or NDA-protected material** — always treat INE's official
syllabus and exam guide as the authoritative source for what is tested.

## Certification version note

INE Security published the **next generation of the eCIR** certification on
**3 September 2025** (the accompanying press release is dated 8 September 2025); the
official blog post is
<https://ine.com/blog/new-ecir-certification-advanced-incident-response-training>.

> **Scope note.** The five phase files in [`methodology/`](methodology/)
> (01-preparation through 05-lessons-learned) are **this repository's own study
> organization** of the incident-response lifecycle. They are **not** an official list
> of eCIR exam domains, and this guide makes no claim about how many domains the exam
> has. Treat INE's official syllabus as the authoritative source.

## What the eCIR Domain Covers (Public Framing)

The eCIR sits in INE's blue-team / defensive track and centers on **incident response
and handling**: what an organization does before, during, and after a security
incident to limit damage, recover, and improve. The publicly described domain spans:

- The **incident response lifecycle** — SP 800-61 **Rev. 2** defines four phases
  (Preparation; Detection and Analysis; Containment, Eradication and Recovery;
  Post-Incident Activity). This module splits the third phase into separate
  containment and eradication files, which is where its **five** phase files come
  from. Rev. 3 (April 2025) drops the phase model and frames response around CSF 2.0
  functions instead; the familiar **six**-step PICERL sequence is the SANS teaching
  model. Quote the model you are using — the numbers are not interchangeable.
- **Evidence handling fundamentals** — identifying, preserving, collecting, and
  documenting digital evidence without destroying it.
- **Host and artifact triage** — quickly examining endpoints (Windows/Linux) for
  signs of compromise and answering *when, how, and what*.
- **Investigation support skills** — timelines, log review, memory basics, and
  malware handling concepts needed to scope an intrusion.
- **Coordination and communication** — working with internal teams (SOC, IT,
  legal, leadership) and external parties (law enforcement, vendors, ISPs, CERTs).

## Skills You Build

Studying this module should make you able to:

- Run an incident from first alert to post-incident review using a structured process.
- Preserve and document evidence with hashes, write blockers, and chain-of-custody notes.
- Perform fast host triage with CLI tools and purpose-built collectors (KAPE-style,
  Velociraptor, Sysinternals).
- Build timelines from logs and filesystem metadata (plaso/log2timeline, Autopsy).
- Perform introductory memory analysis with Volatility to find injected or hidden processes.
- Apply containment, eradication, and recovery decisions for common incident types.
- Write clear case notes, executive summaries, and communication templates.

## Where eCIR Fits in the Blue-Team Track

The repository groups blue-team certifications that overlap but emphasize different
moments of the defense lifecycle. eCIR sits in the middle: after detection, before and
during recovery. As public framing:

| Module | Public domain emphasis | Relationship to eCIR |
| ------ | ---------------------- | -------------------- |
| [eSOC](../eSOC/README.md)   | Monitoring, alert triage, Tier-1 analysis | Feeds incidents to the responder; eCIR assumes you can read the alert and the logs behind it. |
| eCIR   | Handling incidents end to end: preserve, contain, eradicate, recover, communicate | This module. |
| [eCTHP](../eCTHP/README.md)  | Proactive, hypothesis-driven hunting for what detection missed | Turns "we were never alerted" into named techniques and new detections; an incident often becomes the next hunt. |
| [eCDFP](../eCDFP/README.md)  | Deep digital forensics: acquisition, analysis, reporting | Supplies the rigorous evidence method eCIR uses in scoped investigations; eCIR stays response-oriented. |

In practice, incident responders borrow SOC detection context, hunting leads and forensic
evidence discipline. This module emphasizes the *response process*: fast, correct
decisions under time pressure, with evidence preserved well enough for anyone (including
eCDFP-style forensics or law enforcement) to rely on later.

## How This Module Is Organized

The module mirrors the working order of an incident:

- [methodology/](methodology/) — the numbered incident-response phases, in working order
  - [01-preparation](methodology/01-preparation.md)
  - [02-detection](methodology/02-detection.md)
  - [03-containment](methodology/03-containment.md)
  - [04-eradication](methodology/04-eradication.md)
  - [05-lessons-learned](methodology/05-lessons-learned.md)
- [tools/](tools/) — responder tooling reference guides
  - [forensic-tools](tools/forensic-tools.md) — acquisition, triage, timeline, and memory tools
  - [incident-management](tools/incident-management.md) — ticketing, case documentation, comms
- [labs/](labs/) — hands-on practice
  - [incident-scenarios](labs/incident-scenarios.md) — build a home IR lab and run scenario drills
- [cheatsheets/](cheatsheets/) — quick reference
  - [ir-playbook](cheatsheets/ir-playbook.md) — decision trees, quick actions, evidence commands

### Suggested Reading Order

1. **Methodology 01–03** first: learn the process before the tools.
2. **Tools** guides, practicing each tool as you read it.
3. **Labs**: build the lab, then run scenario drills end to end.
4. **Cheatsheet** as a running reference; drill with it until the actions are automatic.

## Study Roadmap

A suggested 4–6 week plan (adjust to your pace):

| Weeks | Focus | Output |
| ----- | ----- | ------ |
| 1 | Preparation + detection phases | Written notes on IR process, team roles, KPIs |
| 2 | Forensic tools: acquisition, hashing, triage | Working VM with KAPE/Velociraptor collection |
| 3 | Timeline + memory analysis | Timeline of a practice image; Volatility reports |
| 4 | Containment / eradication / lessons learned | Decision tree cheat sheet drafted |
| 5 | Labs: scenario drills 1–3 | Completed scenario checklists |
| 6 | Labs: scenario drills 4–5 + full mock incident | One end-to-end written case file |

## Common Mistakes & Tips

- **Skipping the process to play with tools.** Tools support a method; state your
  hypothesis, then pick the tool that answers it.
- **Practicing only detection.** Containment, eradication, and communication are
  half the job — rehearse them in the labs.
- **Writing notes after the fact.** Document contemporaneously: timestamps, commands,
  findings, and decisions as they happen.
- **Ignoring legal/regulatory context.** Know reporting obligations (for example,
  breach-notification rules) at a conceptual level before you need them.
- **Trusting one source.** Cross-check public claims about the cert domain against
  INE's official syllabus page and NIST/MITRE references listed below.

## Checklist / Self-Test

- [ ] I can explain the five IR lifecycle phases this module uses and what each one produces —
      and name the model whenever I quote a different count (NIST Rev. 2: four phases;
      SANS/PICERL: six steps).
- [ ] I can name the ordering rule of evidence work: preserve first, analyze copies.
- [ ] I can list at least five Windows and five Linux artifacts useful for triage.
- [ ] I can build a timeline from a disk image and explain its key events.
- [ ] I can run a basic Volatility 3 memory scan and interpret its output.
- [ ] I can draft a containment plan for a compromised workstation in under 10 minutes.
- [ ] I have completed at least three scenario drills and written a case file for one.
- [ ] I can explain to a non-technical audience what happened and what we are doing.

> **Verification:** the phase counts were **checked against the NIST SP 800-61 Rev. 3 publication
> page** (`https://csrc.nist.gov/pubs/sp/800/61/r3/final`, HTTP 200 via `curl` on 2026-09-19) and
> against this module's own file list. The Rev. 2 four-phase structure and the SANS/PICERL
> six-step attribution are **documentation references, not executed checks**.

## Further Resources

- INE Security — eCIR certification page and official syllabus: <https://ine.com/security/certifications/ecir-certification>
- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide* — https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- NIST SP 800-61 Rev. 3, *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile* (April 2025) — https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-86, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- MITRE ATT&CK — https://attack.mitre.org/
- CISA Incident Response resources — https://www.cisa.gov/resources-tools/resources/incident-response

---

> Self-authored public study notes. No NDA-protected or actual exam content is included.
