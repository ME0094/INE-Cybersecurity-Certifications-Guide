# Forensic Reporting (eCDFP Methodology — Phase 04)

> Companion study guide for the eCDFP (Certified Digital Forensics Professional) Blue Team methodology track. This phase converts analysis into a clear, defensible, decision-ready report — the artifact of the entire investigation that others will actually read and challenge.
>
> Every template and example below is **illustrative structure**, not captured output from a real case, and this repository ships no such output. Templates are marked as such where they appear. Where a statement is a convention rather than a rule, the text says so — legal and organisational requirements vary, and the authority on them is your legal counsel, not this file.

## Overview

Reporting is the final phase of NIST SP 800-86's process model and the phase that makes all prior work useful. A forensic report must satisfy two audiences at once:

- **Technical reviewers and opposing experts**, who will check methodology, evidence handling, and reasoning.
- **Decision-makers** (management, legal counsel, HR, law enforcement), who need the bottom line in plain language.

A useful test for any report: *could another examiner follow your documented steps, reach the same findings, and defend them in front of a skeptical audience?* If not, the report is not finished.

Two further tests worth running before you call a draft complete:

- **The re-derivation test.** Could a competent examiner, given only your report and the sealed exhibits, reproduce your conclusions? If a step exists only in your head, it is missing from the report.
- **The cross-examination test.** Read your own findings as if you were paid to destroy them. Which sentence would you attack first? Fix that one.

## Know which report you are writing

Different deliverables have different structures, audiences and standards of language. Deciding which one you are producing — often more than one from the same investigation — prevents the most common structural failure: a document that is too technical for its reader and too vague for a reviewer.

| Deliverable | Audience | Length guide | Optimised for |
| --- | --- | --- | --- |
| **Full technical report** | Examiners, opposing experts, counsel | Long; appendices unbounded | Reproducibility and completeness |
| **Executive summary / briefing** | Management, legal, HR, the client | One page | Decisions and impact |
| **Incident handover note** | The IR or SOC team taking over | A few pages | What to do next, and what has already been done |
| **Expert statement or affidavit** | A court or tribunal | Varies with jurisdiction and instruction | Fact, method and opinion, strictly separated |
| **Verbal briefing** | Whoever asked for the work | Minutes | The answer to the question asked, and its limits |
| **Detection / control recommendation** | Engineering and security teams | A page per recommendation | Actionable change with an owner |

Most investigations produce the full report plus at least one summary. Write the full report first; every shorter deliverable is derived from it, never the reverse.

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

What each section must actually accomplish, beyond being present:

| Section | It fails if… |
| --- | --- |
| Scope and objectives | It does not say what was **excluded** and why |
| Methodology | It names tools without versions, or omits the order and the reasoning |
| Evidence examined | It lists exhibits without hashes or without the acquisition record |
| Findings | A finding has no evidence reference, or mixes fact with inference |
| Analysis | The reconstruction asserts causation without arguing it |
| Conclusions | It does not distinguish "I found X" from "X means Y" |
| Recommendations | They are generic ("improve logging") rather than specific and owned |
| Appendices | They are missing the raw output a reviewer would need to check a claim |

## A report skeleton you can adapt

```text
CASE REPORT — <case number>

1. CASE INFORMATION
   Case number, exhibit numbers, examiner(s) and role, dates of work, date of report,
   requested by, authority/scope of the examination, classification and handling.
2. EXECUTIVE SUMMARY           (one page; written last; no unexplained jargon)
   What was asked · what was found · what it means · what happens next.
3. SCOPE, OBJECTIVES AND LIMITATIONS
   Questions posed. Systems, accounts and time windows in scope. What was excluded,
   by whose instruction, and what effect that has. Known limitations from the outset.
4. METHODOLOGY
   Phase order followed. For every tool: name, version, and what it was used for.
   Acquisition method and write protection. Time handling (UTC, clock offsets measured).
   Anything non-standard, and why.
5. EVIDENCE EXAMINED
   Exhibits table: exhibit id, description, source, acquisition date/time, SHA-256,
   where the sealed original is stored, working copies derived from it.
   Chain-of-custody summary, with the full log in an appendix.
6. FINDINGS
   Numbered. Each one: statement · evidence reference(s) · method · confidence ·
   alternative explanation considered · significance.
7. ANALYSIS AND RECONSTRUCTION
   The narrative — typically the timeline — that connects the findings. Every step
   cites the finding or exhibit that supports it. Gaps named where they matter.
8. CONCLUSIONS
   What the evidence supports, at the level it supports it. What it does not support.
   Confidence per conclusion.
9. RECOMMENDATIONS
   Each one specific, with an owner-shaped action, and separated from the findings.
10. APPENDICES
   A: hash manifests.  B: chain-of-custody log.  C: tool and version inventory.
   D: command and query log.  E: exported evidence samples.  F: glossary.
   G: any addenda issued after the original report.
```

Adapt it to the requirements of whoever commissioned the work — many organisations and courts have a mandated structure, and theirs wins over yours.

## Writing a finding that survives review

A finding is the unit of a report, and there is a shape that works:

```text
FINDING <n> — <one-line statement of what the evidence shows>

Statement ....... The user account 'labuser' executed <binary> from <path> at
                  <time> UTC.  [fact, no interpretation]
Evidence ........ Exhibit 03 (<image name>, SHA-256 <value>): Prefetch entry for the
                  binary, run count 1, last-run time <value>. Exhibit 03: Amcache
                  entry for the same path with a matching first-observed window.
                  Exhibit 05 (exported event logs): process-creation event at <time>.
Method .......... <tool> <version>, command and arguments as recorded in appendix D.
Confidence ...... High. Three independent artefacts agree within <window>.
Alternative ..... Considered and not supported: an artefact-inventory entry without
                  execution (excluded because the Prefetch run count is non-zero and
                  the process-creation event exists).
Significance .... Establishes execution; does not, by itself, establish who was at
                  the keyboard (see Finding <n+1> and Conclusion <n>).
```

Five rules for findings:

1. **One claim per finding.** Compound findings hide weak components.
2. **Every finding cites evidence by exhibit and by artefact**, not by "the analysis showed".
3. **State the evidence grade or a confidence level**, and be consistent about what the words mean (§ next).
4. **Name the alternative you rejected**, and why. This is the single most credibility-building sentence in most reports.
5. **Separate the establishment of the fact from its significance.** "The file was created" and "this indicates staging" are two sentences, and only one of them is a fact.

## Confidence, in words that mean something

Vague confidence language is where reports quietly overclaim. Fix the vocabulary in advance and use it consistently.

| Phrase | Use it when |
| --- | --- |
| **Established** | Independently corroborated by at least two artefacts that would each have to be wrong in the same direction to mislead |
| **Supported / consistent with** | One strong artefact, or several weak ones agreeing, with no plausible alternative identified |
| **Possible / cannot be excluded** | The evidence permits the explanation but does not distinguish it from alternatives |
| **Not supported** | The evidence is insufficient; say so plainly rather than implying the opposite |
| **Contradicted** | Evidence exists that is inconsistent with the claim, and you have described it |

And a discipline about words that carry legal weight: *deleted*, *copied*, *accessed*, *transmitted*, *the user*, *the attacker*. Each of these is stronger than the artefact usually supports. Prefer "a delete record exists for this file at T" over "the user deleted the file"; prefer "the account was used to authenticate from X" over "X logged in". Precision here is not pedantry — it is the difference between a finding a reviewer accepts and one they dismantle.

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

Three additions that make a methodology section materially stronger:

- **Time handling.** State the time zone convention, the clock offset you measured for each source, and what you did about it. See `03-timeline.md` for how to measure it; a methodology section that omits this is vulnerable to a single question about skew.
- **Deviations, with their effect.** If a step went differently — a tool failed and you used another, an image was re-acquired, a rule was broken and recorded — put it here, with an honest statement of which findings could be affected.
- **Negative results.** The artefacts and sources you checked and found nothing in. This is what demonstrates the examination was thorough, and it is what stops a reviewer arguing that you simply did not look.

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

### What the report must not do

- **It must not name a person as culpable.** Report what the evidence supports about accounts, sessions and devices; conclusions about who a person is and what they intended belong to a process with legal authority, and should be flagged as requiring it.
- **It must not slide from "an artefact exists" to "this is malware".** Maliciousness is a judgement supported by behaviour, provenance and context. Where you can only say "unsigned binary, executed from a temporary path, with an outbound connection to an address with no business relationship to the organisation", say that.
- **It must not attribute causation from ordering.** §Phase 03's discipline applies here: sequence is evidence, causation is an argument.
- **It must not include unrelated personal data.** Minimization continues into the report: quote the minimum needed to support the finding, and keep the rest in the unredacted working material.
- **It must not contain unexplained jargon** in the executive summary, and it must not contain vague generalities in the technical sections. Each section has one job.

## Exhibits, Redaction and Chain-of-Custody Records

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

Referencing evidence inside the narrative — conventions that make a report reviewable:

| Instead of | Write |
| --- | --- |
| "I saw a suspicious file" | "Exhibit 03 contains `<path>` (SHA-256 `<value>`, MFT record `<n>`)" |
| "The logs show a logon" | "Exhibit 05, Security channel, event `<id>` at `<time>` UTC, LogonType `<n>`, account `<account>`" |
| "The timeline shows the attack" | "Appendix E, filtered with `<exact filter>`; the sequence is described in §7, steps 1–6" |
| A screenshot of a tool window | An exported artefact, plus the command that produced it, plus the screenshot if it aids the reader |

**Redaction.** Where a report must be shared beyond the investigation, redact the personal data and sensitive values — but keep an unredacted master, record what was redacted and by whose instruction, and make sure the redaction cannot be mistaken for the original evidence. A redacted exhibit that is presented as the exhibit is a credibility problem waiting to happen; a redacted *copy* with the master referenced is not.

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

A structure that works for almost any executive summary, in five sentences:

```text
1. What was asked.        "We were asked whether data left the network."
2. What the evidence shows. "It did: 40 documents, between 02:00 and 03:30 UTC."
3. How confident, and why. "High confidence: two independent sources agree."
4. What it does not show.  "We cannot say who was at the keyboard; that requires..."
5. What happens next.      "Recommended actions are in Section 9."
```

Sentence 4 is the one people omit, and the one that protects both the report and the reader.

## Reviewing your own report before it goes out

Treat this as a procedure, not a feeling. Read the draft three times, with a different question each time.

| Pass | Read it as | Looking for |
| --- | --- | --- |
| **1. The reviewer** | Someone who will reproduce your work | Every claim has an exhibit reference; every tool has a version; every filter and command is recorded; the methodology section is complete enough to re-run |
| **2. The adversary** | An opposing expert paid to find holes | Unsupported inferences; overclaimed confidence; ignored alternative explanations; timestamps cited without a clock-skew statement; findings that depend on a single weak artefact |
| **3. The decision-maker** | Someone with five minutes and no technical background | The summary answers their question; jargon is defined or absent; the recommendation is actionable and has an owner |

Then a mechanical check, because these are the errors that actually reach the reader:

- [ ] Do the finding numbers in the narrative match the findings section?
- [ ] Does every exhibit cited exist in the evidence table, with a hash?
- [ ] Do the dates in the summary match the dates in the findings?
- [ ] Do all timestamps state a time zone, and is the convention consistent?
- [ ] Are the tool versions in the appendix the ones you actually used?
- [ ] Does the report contain any personal data that is not necessary?
- [ ] Are the limitations in the summary consistent with the limitations in the technical sections?

> **Changes after issue are addenda, not edits.** Once a report has been delivered, corrections go in a dated addendum that says what changed and why. Silently editing a delivered report destroys the audit trail that made it defensible in the first place.

## Testimony and expert statements

Most examiners eventually have to explain their work in person. Four rules cover the common ground; your jurisdiction's rules and your counsel's advice govern the details.

1. **Answer the question that was asked.** Not the one you prepared for, and not a longer one that makes your point. If the question is unclear, say so.
2. **Distinguish fact, inference and opinion out loud**, exactly as the report does. "The artefact shows X" and "in my opinion X indicates Y" are different answers.
3. **Say "I do not know" when you do not know.** One honest gap costs less than one overreach.
4. **Bring the material that supports your method**: the report, the appendices, the hash manifests, the tool versions. Reviewers ask about procedure more often than about findings.

Admissibility requirements differ between jurisdictions and forums — some weigh the reliability of the method, others the qualifications of the examiner, and most consider both. Ask counsel which standard applies to your matter rather than assuming one; and in every case, the habits in this file (versions, hashes, contemporaneous notes, stated limitations) are what make any standard satisfiable.

## Common Mistakes & Tips

- **Writing the report from memory.** Contemporaneous notes are the raw material; never reconstruct methodology after the fact.
- **Unverifiable statements.** Every claim needs an exhibit number or tool output reference.
- **Undocumented tools.** "Used forensic software" is indefensible; tool name + version + configuration is not optional.
- **Skipping limitations.** Reviewers find gaps anyway — documenting them is strength, not weakness.
- **Conflating fact and inference.** "The file was deleted" (fact) versus "the user deleted the file" (inference) is a distinction that decides cases.
- **Using confidence words loosely.** "Possibly" and "established" cannot both mean "I think so". Fix the vocabulary and keep it.
- **Not stating how time was handled.** Omitting clock skew and time-zone conventions invites the one question that undermines a sequence.
- **Leaving out negative results.** The artefacts you checked and found empty are part of the evidence of a thorough examination.
- **Naming a person as culpable.** Report what the evidence supports about accounts and sessions; leave culpability to the process that is entitled to determine it.
- **Jargon-drowning the executive summary.** Technical detail belongs in findings and appendices.
- **Forgetting the chain of custody.** An otherwise perfect report collapses if the evidence's handling history has holes.
- **Editing a delivered report.** Corrections are addenda. Silent edits destroy the audit trail.
- **Over-redacting or under-redacting.** Redact in the copy you distribute, keep an unredacted master, and record the instruction.
- **Tip:** have a second examiner read the draft with fresh eyes — if they cannot reproduce your reasoning, neither can a court.
- **Tip:** number sections and exhibits consistently; cross-references make the report audit-proof.
- **Tip:** before you send it, read your findings as if you were paid to destroy them. The sentence you would attack first is the one to rewrite.
- **Tip:** keep a "lessons for next time" note for your own method (not for the client report) — the process improvements that made this case hard belong in your next examination, not in this deliverable.

## Checklist / Self-Test

- [ ] Have I decided which deliverables this investigation needs, and written the full report before deriving the summaries?
- [ ] Does my report contain case metadata, executive summary, scope, methodology, evidence list, findings, analysis, conclusions, and recommendations?
- [ ] Does the scope section state what was excluded and why, in addition to what was included?
- [ ] Is the executive summary understandable without any technical background, and does it include what the evidence does *not* show?
- [ ] Is every finding tied to a specific exhibit and supporting tool output, with the artefact named?
- [ ] Are all tools documented with name, version, and the commands/configuration used?
- [ ] Does the methodology section state how time was handled, including any measured clock offsets?
- [ ] Does the report clearly separate facts from inferences from opinions, with confidence levels that use a consistent vocabulary?
- [ ] Does every significant conclusion name the alternative explanation I considered?
- [ ] Are SHA-256 hashes and a chain-of-custody log included for every exhibit?
- [ ] Have I stated assumptions and limitations honestly, including negative results?
- [ ] Have I avoided naming individuals as culpable, and labelled anything about intent as requiring a process with legal authority?
- [ ] Have I minimized personal data in the report, and kept an unredacted master where redaction was applied?
- [ ] Have I run the three review passes — reviewer, adversary, decision-maker — and the mechanical cross-reference check?
- [ ] Could another examiner reproduce my analysis from the report alone?
- [ ] Do I know that post-issue corrections go in a dated addendum, and that I would not edit a delivered report?

> **Verification:** executed against **The Sleuth Kit 4.12.1** and **GNU coreutils 9.4** on
> **2026-09-19** (Ubuntu 24.04 WSL): on an image built in `/tmp`, `mmls` printed the partition
> table with the start sector and `fsstat -o 2048` the file-system type and volume serial — the
> shape the methodology-note example uses, and the two values it tells you to record. `mmls -V`
> prints `The Sleuth Kit ver 4.12.1` and `sha256sum --version` prints
> `sha256sum (GNU coreutils) 9.4`, so the `<tool> <version>` notation asked for is the one these
> tools report; the versions in the templates are illustrative and belong to no particular host.
> **Not executed:** the report itself — there is no case, no exhibit and no opposing expert here —
> so every template above remains structure, not a captured document.

## Further Resources

- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* (see its reporting guidance) — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **ISO/IEC 27037**, *Guidelines for identification, collection, acquisition and preservation of digital evidence* (the handling records the report must reference) — https://www.iso.org/standard/44381.html
- **RFC 3227**, *Guidelines for Evidence Collection and Archiving* — https://www.rfc-editor.org/rfc/rfc3227
- **SANS reading room** (white papers on forensic report writing and expert testimony) — https://www.sans.org/reading-room/
- **Forensics Wiki** (reporting and documentation conventions) — https://forensics.wiki/
- **The Sleuth Kit / Autopsy documentation** (case management and report generation) — https://www.sleuthkit.org/
