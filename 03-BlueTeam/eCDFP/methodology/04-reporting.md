# Forensic Reporting (eCDFP Methodology — Phase 04)

> Companion study guide for the eCDFP (Certified Digital Forensics Professional) Blue Team methodology track. This phase converts analysis into a clear, defensible, decision-ready report — the artifact of the entire investigation that others will actually read and challenge.

## Overview

Reporting is the final phase of NIST SP 800-86's process model and the phase that makes all prior work useful. A forensic report must satisfy two audiences at once:

- **Technical reviewers and opposing experts**, who will check methodology, evidence handling, and reasoning.
- **Decision-makers** (management, legal counsel, HR, law enforcement), who need the bottom line in plain language.

A useful test for any report: *could another examiner follow your documented steps, reach the same findings, and defend them in front of a skeptical audience?* If not, the report is not finished.

## Anatomy of a Forensic Report

A defensible report typically contains:

1. **Case metadata** — case number, examiner(s), date(s), requested-by, classification.
2. **Executive summary** — the incident, key findings, and conclusion in one page or less.
3. **Scope and objectives** — what was asked, what systems/data were in scope, and any limits.
4. **Methodology** — tools (name + version), techniques, and the order of the phases followed.
5. **Evidence examined** — exhibits list with hashes, acquisition and chain-of-custody records.
6. **Findings** — each finding stated plainly, with supporting evidence references.
7. **Analysis and reconstruction** — how the findings fit together (often the timeline narrative).
8. **Conclusions** — what you can and cannot say, with confidence levels.
9. **Recommendations** — remediation, detection improvements, or next investigative steps.
10. **Appendices** — full tool logs, command outputs, hash manifests, exhibit photos, glossary.

Write findings first, then build the report around them; the executive summary is written last, from the conclusions.

## Documenting Methodology and Evidence

The methodology section is your shield. It must show the work was **repeatable** and **complete**:

- **Contemporaneous notes**: record actions as you take them — never reconstruct notes after the fact. Note date/time (UTC), tool, version, command, and result.
- **Tool and version for every step**: `dd (coreutils 9.1)`, `fls 4.11.1`, `plaso 20240101` — not just "Sleuth Kit".
- **Evidence identifiers**: refer to exhibits by number (e.g., "Exhibit 3") everywhere in the report.
- **Hash values**: include SHA-256 of every image and working copy so reviewers can verify integrity.
- **Assumptions and limitations**: state what you could not do (no memory image, encrypted volume not analyzed, clock skew) and why. Honest limitations increase credibility; hiding them destroys it.

```text
# Example methodology note style (captured at the time of the action)
2024-11-03 14:12 UTC — Examiner J. Doe
Tool: mmls (Sleuth Kit 4.11.1)
Cmd:  mmls /evidence/case-001/image.dd
Res:  NTFS partition at sector 2048 (offset 1048576 bytes)
```

## Presenting Conclusions Defensibly

Defensible reporting separates three levels of statement and never confuses them:

- **Fact** — directly observed: "The image contains file `payload.exe` at path X with SHA-256 Y."
- **Inference** — reasoned from facts: "The Run key referencing `payload.exe` indicates a persistence mechanism was configured."
- **Opinion/recommendation** — judgment: "This is consistent with an attacker-controlled backdoor."

For each significant conclusion:

- State the **confidence** and what would raise or lower it (corroborating source, missing log).
- Offer and address the **main alternative explanation** (counter-hypothesis).
- **Stay in scope** — do not speculate about intent or identity without evidence.
- Avoid absolutes ("the attacker definitely did X", "the user intentionally deleted...") unless the evidence is unambiguous.
- Watch for **confirmation bias**: report evidence that contradicts your working theory, not only what supports it.

A finding is only as strong as its weakest support. One screenshot of a registry key is a lead; the key plus a matching Prefetch entry plus an event-log entry is a finding.

## Exhibits and Chain-of-Custody Records

Every piece of evidence needs a defensible paper trail:

- **Exhibit numbering**: consistent scheme, e.g., `CASE-001-E01` (image), `CASE-001-E02` (memory dump), and exhibits referenced by number in the narrative.
- **Chain-of-custody log**: who handled each exhibit, when, why, and where it was stored. Every transfer (seizure → lab → analyst → storage → court) is a row.

| Date (UTC) | Exhibit | Action | Handler | Location / Notes |
| --- | --- | --- | --- | --- |
| 2024-11-03 09:00 | CASE-001-E01 | Seized and imaged | J. Doe | On-scene, write blocker used |
| 2024-11-03 13:30 | CASE-001-E01 | Stored | J. Doe | Evidence locker #4, sealed |
| 2024-11-05 10:00 | CASE-001-E01 | Checked out for analysis | A. Smith | Hash verified before/after |

- **Hash manifests** in an appendix tie each exhibit to its integrity value; re-verify the hash at each checkout and note the result.
- Secure the originals (sealed, access-controlled); the report should clearly distinguish the original from working copies.

## Communicating to Non-Technical Stakeholders

Management, counsel, and HR rarely want your tool output — they want answers to *their* questions: Was there a breach? Is the data compromised? Who did what? What do we do now?

Guidelines for the non-technical audience:

- Lead with the **executive summary**: plain-language incident, impact, and conclusion.
- **Define every term** on first use ("prefetch — a Windows record of programs that ran") or include a glossary.
- Use **impact-oriented language**: "An attacker had administrative access to the file server for 6 days" beats "Sysmon event 4624 logon type 3 observed."
- Use **visuals**: a chronological attack diagram or timeline chart communicates sequence faster than prose.
- Separate **"so what"** from the technical detail — put the detail in findings/appendices, not the summary.
- Be careful with **causation and intent**: report what the evidence supports ("the account was used from IP X") rather than unproven claims ("the employee stole data").

```text
# Executive-summary style example (non-technical, defensible)
Between 02:00 and 03:30 UTC on 3 November 2024, an attacker used a
stolen password to log into the file server and copied 40 documents
marked confidential to an external address. The copy activity is
supported by log and file evidence described in Sections 4-6.
```

## Common Mistakes & Tips

- **Writing the report from memory.** Contemporaneous notes are the raw material; never reconstruct methodology after the fact.
- **Unverifiable statements.** Every claim needs an exhibit number or tool output reference.
- **Undocumented tools.** "Used forensic software" is indefensible; tool name + version + configuration is not optional.
- **Skipping limitations.** Reviewers find gaps anyway — documenting them is strength, not weakness.
- **Conflating fact and inference.** "The file was deleted" (fact) versus "the user deleted the file" (inference) is a distinction that decides cases.
- **Jargon-drowning the executive summary.** Technical detail belongs in findings and appendices.
- **Forgetting the chain of custody.** An otherwise perfect report collapses if the evidence's handling history has holes.
- **Tip:** have a second examiner read the draft with fresh eyes — if they cannot reproduce your reasoning, neither can a court.
- **Tip:** number sections and exhibits consistently; cross-references make the report audit-proof.

## Checklist / Self-Test

- [ ] Does my report contain case metadata, executive summary, scope, methodology, evidence list, findings, analysis, conclusions, and recommendations?
- [ ] Is the executive summary understandable without any technical background?
- [ ] Is every finding tied to a specific exhibit and supporting tool output?
- [ ] Are all tools documented with name, version, and the commands/configuration used?
- [ ] Does the report clearly separate facts from inferences from opinions, with confidence levels?
- [ ] Are SHA-256 hashes and a chain-of-custody log included for every exhibit?
- [ ] Have I stated assumptions and limitations honestly?
- [ ] Could another examiner reproduce my analysis from the report alone?

## Further Resources

- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* (see its reporting guidance) — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **SANS reading room** (white papers on forensic report writing and expert testimony) — https://www.sans.org/reading-room/
- **Forensics Wiki** (reporting and documentation conventions) — https://forensics.wiki/
- **The Sleuth Kit / Autopsy documentation** (case management and report generation) — https://www.sleuthkit.org/
