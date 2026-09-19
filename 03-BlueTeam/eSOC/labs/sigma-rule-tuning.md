# Lab — From a Case to a Tuned Sigma Rule

> eSOC · Labs — INE-Cybersecurity-Certifications-Guide
>
> This lab walks the whole path a detection takes after a real triage: the observation, the behaviour written down as a hypothesis, the Sigma rule, validation in both directions, the noise measured over a quiet period, and the tuning change that removes noise without removing the detection. It is the laboratory that the worked example in `../methodology/02-detection.md` refers to, and it uses the same case: a user reported a document that asked them to "enable content", Word spawned a script host, and that script host pulled a file down with `certutil`.
>
> **Nothing below is captured output.** The case, the log excerpts and the arithmetic are constructed illustrations of the *shape* to expect — no SIEM, endpoint or event log was consulted while writing this note, and no command in it was executed. Build the lab, run the drills, and let your own output replace the illustration. The two Sigma rules are the study rules from `../methodology/02-detection.md`; validate them with the Sigma CLI in your own environment before trusting them.

## What This Lab Covers, Stage by Stage

The point of the lab is the *order*, which is the same order any detection follows in production.

| Stage | The question you are answering | Artifact you end up with |
|---|---|---|
| 1. Observation | What did the analyst actually see, and in which sources? | A triage note with facts separated from assumptions |
| 2. Hypothesis | Which behaviour, stated so it survives a change of sample? | One sentence naming behaviour, asset class and data source |
| 3. Data mapping | Do the fields the rule needs exist and are they populated? | A raw event that shows the fields, not a promise that they exist |
| 4. Rule authoring | What is the narrowest logic that matches the behaviour? | A Sigma file that another analyst can read |
| 5. Positive validation | Does it fire on the behaviour, with the right fields? | Recorded evidence of a true positive |
| 6. Negative validation | How often does it fire when nothing is happening? | A measured false-positive rate over a defined window |
| 7. Tuning | What is the narrowest change that removes the noise? | A dated exclusion plus a re-run of the positive case |
| 8. Record | What does the next analyst need to know? | Use case document, backlog item, changelog entry |

Stages 1–4 are covered by `../methodology/02-detection.md`, stages 5–8 by `../methodology/05-use-cases-and-tuning.md`. This lab is where you do all eight on one case.

## Before You Start

The lab needs a place to generate events and a place to see them.

- **An isolated Windows VM** you own, with a snapshot taken before each drill. Command-line auditing enabled so Event `4688` carries the command line, PowerShell script block logging (`4104`) enabled, and optionally Sysmon for richer process telemetry. `../methodology/01-monitoring.md` has the verification steps that prove each channel is really switched on; skip them and you will debug your rule when the real problem is your collection.
- **A SIEM ingesting those channels.** Any stack will do — `../labs/soc-scenarios.md` covers the blueprint and sizing, and `../tools/siem-tools.md` covers the platform choice.
- **A web listener you control** on the lab network, for the download half of the case. A plain HTTP server serving one harmless text file is enough: the lab reproduces the *shape* of a download, never real malware.
- **The rule file.** Save the first rule from Part 3 as `office-spawns-script-host.yml`; the conversion commands below use that file name.

> ⚠️ **Lab rules.** Only run this against machines you own, on an isolated network, with disposable credentials. The macro and download steps below are harmless stand-ins, but they look exactly like the real thing to every security control you have — including any EDR or email gateway you forgot was watching.

## Part 1 — The Case, as It Reached the Analyst

A user reported a document that asked them to "enable content". They enabled it. The alert that followed was a process-creation detection on the endpoint, and the triage note looked like this:

```text
SUMMARY:    User reported a document prompting "enable content". Shortly after,
            WIN-FIN-07 shows winword.exe creating a script host, which ran
            certutil to retrieve a file from an external address.
SOURCES:    4688 process creation (with command line), 4104 PowerShell script
            block, Sysmon 3 network connection [if installed]
SCOPE:      one host, one user (confirmed); file hash and remote address (to verify)
OPEN:       was the file executed? is the address shared by other hosts?
```

Three things are worth noticing before a single rule is written, because each one changes what you do next:

| What you observed | What it does not tell you |
|---|---|
| Word spawned a script host | Where the document came from, or who else received it |
| The script host ran `certutil` against an external address | What was downloaded — the file content is a separate question |
| The chain happened on one host | Whether the same chain ran on other hosts whose alerts were never triaged |

The behaviour, written as a hypothesis rather than as a sample: **"A Microsoft Office application creating a child process that is a scripting host or a download utility, on any Windows endpoint."** That sentence is deliberately built out of the parent–child relationship and not the file hash, because the hash changes with every campaign and the relationship does not. This is the step analysts skip: a rule written around one sample's hash is a rule that expires.

## Part 2 — Confirm the Data Before Writing Logic

A rule is a hypothesis about your data. Prove the data first.

1. **Search for one raw process-creation event from the alert window.** Expand it and read the actual field names your pipeline produces — `process.parent.name`, `process.parent.executable`, `process.name`, `process.command_line` in ECS-style pipelines; `ParentImage`, `Image`, `CommandLine` in the Sigma `windows/process_creation` vocabulary this rule uses.
2. **Check the fields the rule depends on are populated**, not merely present in the schema. In this case the rule is worthless without the parent image and the command line, so "is `ParentImage` empty on my collector?" is the question that decides whether the rule can work as written.
3. **Generate nothing yet.** If a field is empty across all hosts, the fix is upstream in the pipeline, and a rule that compensates with regex is a rule that hides the defect.

```text
# Kibana KQL - the parent-child pair as a filter, before any rule exists.
# What to look for: the fields your rule will use, populated with real values.
process.parent.name : "winword.exe" and process.name : *

# Splunk SPL - the same question against the Windows add-on's field names.
index=windows EventCode=4688
| stats count by Parent_Process_Name, New_Process_Name
| sort - count
```

## Part 3 — The First Rule

Here is the rule **before tuning** — the honest first version. It matches the behaviour and nothing else.

```yaml
title: Office Application Spawning a Script or Download Utility
id: 2f2a5c31-9a7e-4b0d-8c15-7d3f1b9e4a62
status: experimental
description: |
  Detects a Microsoft Office process creating a child process that is a
  scripting host or a download utility. Typical of a malicious macro that
  survives the "enable content" prompt.
references:
  - https://attack.mitre.org/techniques/T1204/002/
  - https://attack.mitre.org/techniques/T1218/
author: SOC detection engineering (study example)
date: 2025/06/01
tags:
  - attack.execution
  - attack.t1204.002
  - attack.t1218
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\msaccess.exe'
  selection_child:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\cmd.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
      - '\certutil.exe'
      - '\bitsadmin.exe'
      - '\curl.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Document-management or ERP add-ins that shell out to a helper process
  - Software installers launched from a document viewer
level: high
```

Why it is written this way, and what each choice costs:

- **`endswith` on the image path, not a location.** Matching a signed binary by its full path is a statement about an identity; matching `\Temp\` or `\ProgramData\` is a statement about a folder where macros legitimately stage files. The first can be defended in a review; the second cannot.
- **A list of children rather than one.** The behaviour is "Office spawns something that can execute or download", and the list is what makes the rule survive the attacker switching from `powershell.exe` to `mshta.exe`.
- **`level: high` with an honest `falsepositives` block.** If you cannot name the benign cases, you have not finished writing the rule.
- **`status: experimental`.** The rule has not been through negative validation yet. That is what the next two parts are for.

The `id` stays fixed for the life of the detection, including through the tuning in Part 5. A stable id is how a change to the logic stays traceable as *the same rule*, and how the tuning backlog, the changelog and the queue can all refer to it.

## Part 4 — Validate in Both Directions

A rule that has only been tested positively has an unknown error rate, and an unknown rate becomes someone else's night shift.

### Positive validation: make the behaviour happen

Reproduce the shape, not the malware. Two options, in order of fidelity:

1. **The faithful shape, with a macro.** In the lab VM only, enable macros for a trusted location and put a three-line VBA macro in a document that shells out — `Shell "cmd.exe /c whoami"` is enough. Saving the document as `.docm`, opening it and clicking through the prompt produces a genuine `winword.exe` → `cmd.exe` process-creation pair, which is exactly what the rule keys on.
2. **The substitute shape, if you will not touch Office macro settings.** Accept a different parent and adapt `selection_parent` to it for the drill — for example a script that starts a script host, or `explorer.exe` launching `cmd.exe`. The lab's point is the method (observe → hypothesise → map → write → validate), not the sample, and a rule whose parent list you edited in the lab is a rule you understand.

Then reproduce the **download** half against your own listener, using the same command shape the case showed:

```text
# On the lab endpoint. The address is your own lab HTTP server, serving a
# harmless text file - never a live host.
certutil -urlcache -split -f http://<lab-listener-ip>/sample.txt %TEMP%\sample.txt

# What to look for afterwards, in the raw event and in the alert:
#   - the 4688/Sysmon 1 event for certutil.exe with the URL in the command line
#   - the parent of that process (the script host from the macro step)
#   - whether your rule's selection_child list actually contains certutil.exe
```

Record the positives as evidence, not as a feeling: the exact field values that matched, the rule version, the timestamps in UTC, and the queries you ran. "It fired when I tested it" is half a validation; the other half is the next drill.

### Negative validation: measure the noise

Now leave the rule running (or run the equivalent search on a schedule) over a **quiet period** and count what it produces when you are not generating anything.

| What to record | Why |
|---|---|
| The window, with dates | "Two weeks" means nothing if the window contained a deployment |
| Alerts per day from this rule | The number that decides whether it can stay in the queue |
| Every host and parent–child pair behind those alerts | The distribution is the diagnosis: one add-in on 200 hosts is one exclusion, not 200 false positives |
| The distinguishing feature of each hit | This is what the tuning change in Part 5 will filter on |
| Analyst minutes per alert | High cost with low value is a retirement argument, not a tuning one |

Choose a window that includes both a weekday and a weekend, and one that contains no change window if you can. Then write the numbers down with the date, because the next review will ask what they were.

## Part 5 — Measure the Noise, Then Tune Narrowly

Four figures are enough to make a defensible decision — alert volume, fidelity (confirmed TP ÷ confirmed TP + FP), queue share, and median triage minutes. `../methodology/05-use-cases-and-tuning.md` defines each one and shows where it comes from in the queue.

What that looks like in practice is arithmetic you do on your own numbers. This paper example — **no live data, no SIEM was queried to produce it** — shows the shape of the decision:

```text
Rule: Office spawning script host / download utility
Window: 14 days (10 working days, 4 quiet days)

Alerts:              96        -> ~6.9 per day
Confirmed TP:         1        -> the drill you generated, plus any real hit
Confirmed FP:        95        -> all from one document-management add-in
Fidelity:           ~1 %       -> the logic does not match how this environment behaves
Queue share:         ~4 %      -> tolerable in isolation, but flag it in the review
Median triage:       4 min     -> ~6.4 analyst hours per 14 days for 1 true positive

Decision: the behaviour is worth detecting; the noise is one identity, not the logic.
```

Two candidate fixes, and what each one costs:

| Candidate fix | What it removes | What else it removes | Verdict |
|---|---|---|---|
| Raise the threshold from 1 occurrence to 5 | Most of the noise from the add-in | The original case: one macro, one download, one event. The behaviour you built the rule for stops alerting | Wrong |
| Exclude `*\\Temp\\*` or `*\\AppData\\*` | Some of the noise | Execution from exactly the directories macros stage payloads in — the blind spot the rule exists to close | Wrong |
| Exclude one signed binary path, in one asset group, with a dated comment | The add-in's noise | Nothing that matters, and the exclusion is reviewable | Right |

The tuned rule — the version the worked example in `../methodology/02-detection.md` ends up with:

```yaml
title: Office Application Spawning a Script or Download Utility
id: 2f2a5c31-9a7e-4b0d-8c15-7d3f1b9e4a62
status: experimental
description: |
  Detects a Microsoft Office process creating a child process that is a
  scripting host or a download utility. Typical of a malicious macro that
  survives the "enable content" prompt.
references:
  - https://attack.mitre.org/techniques/T1204/002/
  - https://attack.mitre.org/techniques/T1218/
author: SOC detection engineering (study example)
date: 2025/06/01
tags:
  - attack.execution
  - attack.t1204.002
  - attack.t1218
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\msaccess.exe'
  selection_child:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\cmd.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
      - '\certutil.exe'
      - '\bitsadmin.exe'
      - '\curl.exe'
  filter_known_addin:
    ParentImage|endswith: '\ACME-DocTools.exe'   # signed document add-in, confirmed benign 2025-06-01
    Image|endswith: '\cmd.exe'
  condition: selection_parent and selection_child and not filter_known_addin
falsepositives:
  - Document-management or ERP add-ins that shell out to a helper process
  - Software installers launched from a document viewer
level: high
```

Two properties make that filter defensible, and both are easy to get wrong. It names a **specific known-good binary path** rather than a location, so it cannot swallow the macro case. And it carries **a comment with the date and the reason**, so the next analyst can re-review it instead of guessing what it was for. If the exclusions keep growing, the real defect is upstream — an untagged add-in, an asset group nobody owns — and the fix belongs there.

Then run the regression test, in both directions, before the tuned rule goes back into service:

```text
# Syntax check and conversion.
sigma check office-spawns-script-host.yml
sigma convert -t es-qs   office-spawns-script-host.yml
sigma convert -t splunk  office-spawns-script-host.yml
sigma convert -t kusto   office-spawns-script-host.yml
```

`sigma check` was run against these two rules with **sigma-cli 3.1.0** (see the verification note at the end of this lab); `sigma convert` was **not**, because a conversion backend is a separately installed plugin rather than part of the CLI.

- **Positive case re-run:** repeat the macro drill and confirm the alert still fires. An exclusion that swallows your positive case has turned a detection into a placebo.
- **Negative case re-run:** confirm the volume dropped to what the arithmetic predicted, and that the drop came from the add-in and not from the rule being broken.
- **Record:** update the use case document with the numbers and the date, add the backlog item for the untagged add-in, and put a re-review date on the exclusion. A suppression nobody owns is a permanent blind spot wearing a temporary label.

## Part 6 — The Artifact Side: Where YARA Takes Over

The process rule answers "did this happen?". It says nothing about the file that `certutil` pulled down. That is a different question with a different tool.

```text
# Scan the file you collected in the lab, using the study rules in
# ../tools/detection-rules/yara-rules/yara-example.yar
yara ../tools/detection-rules/yara-rules/yara-example.yar <collected-file>

# Then scan an ordinary file for contrast.
yara ../tools/detection-rules/yara-rules/yara-example.yar <some-benign-file>
```

Two rules live in that file, and which one fires *is* the measurement: `Suspicious_CredDump_Strings_AnyFile` fires on any artifact carrying the strings (a text note included), while `Suspicious_CredDump_Strings_PE` additionally requires a real PE. A `.txt` printing only the first name is the expected result, not a near-miss.

What to look for, and the distinction that matters more than the match:

| Result | What it means | What it does not mean |
|---|---|---|
| A plain text file matches `Suspicious_CredDump_Strings_AnyFile` | The strings exist in a file someone wrote or downloaded. Low severity on its own | That the file is malicious, or that anything executed |
| A real PE matches `Suspicious_CredDump_Strings_PE`, **and** the host shows network activity to the same address | Strings, a compiled artifact and behaviour line up | Still not proof of intent — but it is no longer a coincidence |
| Nothing matches | This rule set does not see this sample | That the artifact is clean: YARA only finds what its strings describe |

That is the whole point of the pair: **a match is a lead, not a verdict.** The same strings inside a note someone saved and inside a signed-looking executable that also calls home are two different conversations. `../labs/soc-scenarios.md` runs the same reasoning as a standalone YARA drill with a harmless text file, and `../tools/detection-rules/` holds both study rules.

## What This Lab Does Not Prove

Be precise about the boundary, because the temptation is to claim more than a lab can deliver.

- **It does not give you a production false-positive rate.** Lab activity is generated on purpose; real environments generate noise you have not imagined. The negative validation in Part 4 is a *first* measurement, and the honest reading of it is "no worse than N per day in this lab".
- **It does not validate the Sigma CLI output.** The conversion commands are shown as the shape to run; the generated backend query still has to be tested against your own field names, because conversion is a translation, not a proof.
- **It does not prove the case is real.** The case in Part 1 is a construction built to have the right shape. The reasoning transfers; the numbers do not.
- **It does not cover what happens after escalation.** Containment, evidence handling and the IR handoff are in `../methodology/04-response.md`; this lab stops at a validated, tuned, documented rule.

## Common Mistakes & Tips

- **Mistake:** writing the rule from the sample's hash. *Tip:* write the behaviour — parent, child, command-line shape — and let the hash be an observable in the case instead of the detection.
- **Mistake:** validating only against the activity that inspired the rule. *Tip:* a positive test proves it can fire; only a run over quiet data tells you how often it will.
- **Mistake:** tuning by raising the threshold. *Tip:* a threshold trades detection for quiet. Use it only when the low-and-slow variant of the technique does not matter to you.
- **Mistake:** excluding a directory instead of an identity. *Tip:* filter on a specific signed binary path and scope, with a dated comment and a re-review date.
- **Mistake:** skipping the regression test after the exclusion. *Tip:* re-run the positive case; if it no longer fires, you have removed the detection, not the noise.
- **Mistake:** leaving the tuned rule undocumented. *Tip:* the numbers, the diff and the reason go in the use case document, or the next review starts from zero.
- **Mistake:** treating a YARA match as a verdict. *Tip:* a match says "these strings are here". Whether that matters is the analyst's judgement, and it depends on the artifact type and the behaviour around it.

## Checklist / Self-Test

- [ ] I can state the behaviour of my rule in one sentence, without naming a file hash.
- [ ] I found one raw event and confirmed every field my rule uses is populated.
- [ ] I wrote a Sigma rule with `selection_*` blocks, an `id`, tags, and an honest `falsepositives` list.
- [ ] I reproduced the behaviour in the lab and captured the fields that matched, in UTC.
- [ ] I ran the rule over a defined quiet window and recorded alerts per day and per host.
- [ ] I can classify the false positives I found (parser, admin tooling, business process, threshold, context, environment, logic) and name the correct fix for each.
- [ ] My tuning change is the narrowest one that removes the noise, with a dated comment and a re-review date.
- [ ] I re-ran the positive case after tuning and confirmed the rule still fires.
- [ ] I scanned an artifact with a YARA rule and can explain why a match in a text file is a weaker finding than a match in a PE with network activity.
- [ ] I recorded the numbers, the diff and the reason where the next analyst will find them.

> **Verification:** the two Sigma rules in Parts 3 and 5 were extracted to `/tmp` and checked with **sigma-cli 3.1.0** on **2026-09-19**: both returned `Found 0 errors, 0 condition errors and 0 issues`, and their YAML also parsed under PyYAML 6.0.1. `sigma convert` was not exercised — sigma-cli 3.1.0 reports *"No backends installed"*, so the conversion lines above remain a shape to run where a backend plugin exists. The YARA rules used in Part 6 were run with **yara 4.5.0** on the same date against files created under `/tmp`, never inside the repository: a `.txt` with three of the strings matches `Suspicious_CredDump_Strings_AnyFile` only, the same strings appended to a real PE match `Suspicious_CredDump_Strings_PE` too, and a clean text file matches neither.

## Further Resources

- SigmaHQ rule repository — community rules to compare your logic against: https://github.com/SigmaHQ/sigma
- Sigma documentation — specification, modifiers and the conversion pipeline: https://sigmahq.io/
- MITRE ATT&CK — T1204.002 (malicious file) and T1218 (system binary proxy execution): https://attack.mitre.org/
- YARA documentation — string modifiers, the `pe` module and conditions: https://yara.readthedocs.io/
- Elastic — detection rule management and rule tuning concepts: https://www.elastic.co/guide/index.html
- Microsoft Learn — event 4688 and command-line process auditing: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
