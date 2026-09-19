# Detection Engineering (eCTHP Methodology — Phase 05)

> Companion study guide for the eCTHP (Certified Threat Hunting Professional) Blue Team methodology track. This phase closes the loop: turning a confirmed hunting finding into a detection that survives contact with production, proving it works, and reporting the result so the next hunt starts from a better place.

## Overview

A hunt that finds something and produces no detection has bought you one afternoon of safety. The adversary keeps the technique; you keep the memory. Detection engineering is how hunting compounds.

The pipeline is short and unforgiving:

| Stage | Question | Output |
| --- | --- | --- |
| 1. Finding | What did the hunt actually observe? | A behaviour statement, in observable terms |
| 2. Logic | What condition distinguishes it from normal? | Rule draft: selection, filters, condition |
| 3. Test | Does it fire on the malicious case, and stay quiet on the benign one? | Positive and negative test evidence |
| 4. Tune | What does production traffic do to it? | Narrowed filters, documented exceptions |
| 5. Deploy | Who is expected to act on it, and how? | Rule in version control, triage guidance for the SOC |
| 6. Monitor | Is it still working and still useful? | Volume and accuracy tracking, periodic review |
| 7. Retire or keep | Does it still earn its alert volume? | A decision, recorded |

Skipping stage 3 is the most expensive shortcut in security operations: you get a rule that looks right, never fires, and quietly becomes a false sense of coverage.

## What makes a detection maintainable

Detections are code with an operational cost. Judge each one against explicit criteria:

| Criterion | Good looks like | Bad looks like |
| --- | --- | --- |
| Specificity | Condition combines behaviour and context | Matches a filename or a single keyword |
| Data availability | Every field is collected, on the scope claimed | Relies on a source deployed on half the estate |
| Actionability | An analyst knows what to do within a minute | "Investigate further" with no starting point |
| Documented false positives | Known benign causes are listed | Silence until the queue floods |
| Technique mapping | `tags` reference the ATT&CK technique | No mapping, so coverage cannot be measured |
| Test evidence | Positive and negative tests recorded | "Tested in the lab" with no artefacts |
| Ownership | A named owner and a review date | Nobody knows who wrote it or why |
| Versioning | Lives in Git with review history | Edited live in a console nobody can audit |

The last row is worth stating plainly: **a rule that exists only in a console is not an engineering artefact.** Put rules in version control, review changes, and deploy from the repository. If your platform cannot deploy from Git, keep the repository as the source of truth and record deployments in it.

## Writing the rule: Sigma first

Write the logic vendor-neutrally, then convert. Sigma is the de facto format for that, and it keeps the reasoning readable to anyone who does not share your SIEM.

```yaml
title: Encoded PowerShell Command Line
id: 3f2d1c40-6a51-4d2e-9c17-6b0a4f9a1e01
status: experimental
description: Detects PowerShell executed with an encoded command argument, a common way to hide script content.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: Hunt team
date: 2026/09/18
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    - Image|endswith: '\powershell.exe'
    - Image|endswith: '\pwsh.exe'
  selection_encoded:
    # Sigma `contains` is case-insensitive, and the surrounding spaces stop the rule matching
    # unrelated switches such as `-Encoding`. All three translations below match this same set.
    CommandLine|contains:
      - ' -enc '
      - ' -encodedcommand '
  filter_deployment:
    ParentImage|endswith: '\deploy-agent.exe'   # known-good automation, narrow by parent, not by directory
  condition: selection_image and selection_encoded and not filter_deployment
fields:
  - CommandLine
  - ParentImage
  - ParentCommandLine
falsepositives:
  - Software deployment tooling that encodes commands (covered by filter_deployment).
  - Administrative scripts run by hand during maintenance windows.
level: medium
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
```

Reading the anatomy:

- **`logsource`** declares which data the rule needs: `product` plus `category` (process creation, file event, network connection) or a `service` such as `security`, `sysmon`, or `powershell`. A rule whose logsource fields match nothing in your pipeline will never fire — verify the category exists in your collected data.
- **Modifiers** (`|endswith`, `|contains`, `|startswith`, `|re`, `|all`) shape field matching. Use the narrowest modifier that expresses the behaviour: `|endswith` on a full executable name beats `|contains` on a fragment.
- **Selection blocks** are ORed within a list and ANDed between different keys. That structure *is* the logic — keep it readable instead of compressing everything into one condition line.
- **Filters** suppress known-good activity. Name them for what they suppress, not for what they allow.
- **`tags`** carry the ATT&CK mapping, which is what makes coverage measurable later.
- **`falsepositives`** is documentation for the analyst who gets paged at 03:00, not decoration.

Validation and conversion, with the caveat that converter and pipeline names differ between releases — check `sigma convert --help` and `sigma check --help` for your installation:

```bash
# Validate rule syntax before it reaches the pipeline
sigma check rules/

# Convert to a backend query language
sigma convert -t splunk rules/susp_encoded_powershell.yml
sigma convert -t elasticsearch rules/susp_encoded_powershell.yml
```

Conversion gives you a starting query, not a finished detection: field names, index selection, and pipeline transformations are environment-specific. Review the output, then test it.

## The same logic in the SIEM

The rule above, as native queries. All three assume the supporting telemetry exists and is healthy.

```kql
// KQL: encoded PowerShell, excluding known-good deployment parents.
// Same term set as the Sigma rule: `tolower()` plus `contains_any` reproduces Sigma's
// case-insensitive substring match on ' -enc ' and ' -encodedcommand '.
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where NewProcessName endswith_cs "\\powershell.exe" or NewProcessName endswith_cs "\\pwsh.exe"
| where tolower(CommandLine) contains_any (" -enc ", " -encodedcommand ")
| where ParentProcessName !endswith_cs "\\deploy-agent.exe"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
```

```
# SPL: same behaviour, with the deployment parent excluded
index=sysmon EventCode=1
  (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
  (CommandLine="*-enc *" OR CommandLine="*-EncodedCommand *")
  NOT ParentImage="*\\deploy-agent.exe"
| table _time, Computer, User, Image, CommandLine, ParentImage
```

> **The three versions now detect the same set — they did not before.** The KQL added a
> `FromBase64String` term that the Sigma rule and the SPL did not have, and that term is a
> *wider* rule: `[Convert]::FromBase64String` appears in plenty of legitimate administrative
> scripts and fires on command lines where `-enc` was never used. If you want it, it is a
> separate detection with its own baseline, its own false-positive review and its own validation
> run — do not bolt it onto this one and assume the existing numbers carry over. Whenever you
> change a term or a modifier in one translation, change it in all three, and re-validate in each
> backend rather than only in the Sigma source.

Threshold and correlation logic, for behaviours that are only suspicious in aggregate:

```kql
// Account discovery burst: many discovery commands from one account in a short window
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where NewProcessName endswith_cs "\\net.exe" or NewProcessName endswith_cs "\\nltest.exe"
| summarize Commands = dcount(CommandLine) by Computer, Account, bin(TimeGenerated, 10m)
| where Commands >= 5
```

```
# SPL equivalent, using bin and stats instead of a join
index=sysmon EventCode=1 (Image="*\\net.exe" OR Image="*\\nltest.exe")
| bin _time span=10m
| stats dc(CommandLine) as commands values(CommandLine) as details by _time, Computer, User
| where commands >= 5
```

Notes on shape:

- **Aggregate before you alert.** Single events cause fatigue; bursts, sequences, and rare combinations carry more signal.
- **Prefer `stats`/`summarize` over joins** on high-volume tables. Joins are the most common reason a rule times out under production volume.
- **Thresholds need baselines.** "Five discovery commands in ten minutes" is a guess until you measure what your automation does every day.
- **Cap the result.** Suppression windows and deduplication settings belong in the rule design, documented, not applied ad hoc by the analyst.
- **Sigma correlation rules** (`correlation:` blocks with `type`, `group-by`, and `timespan`) exist for sequence logic, but backend support varies — verify whether your converter and platform implement them before designing around them.

## False positives and tuning

A false positive is a cost, and the cost is paid by whoever is on shift at 03:00. Treat tuning as part of building the rule.

**Where false positives come from:**

- Legitimate administration: deployment tooling, backup software, vulnerability scanners, patch management, monitoring agents.
- Developer and power-user behaviour that looks like tradecraft: encoded commands, `certutil` usage, archive creation in temp directories.
- Your own security tooling: scanners, audit scripts, and the emulation you ran in the lab.
- Bad rule logic: matching a filename fragment, a generic keyword, or a directory instead of a behaviour.

**How to tune without gutting the rule:**

1. **Backtest first.** Run the candidate query over 30 to 90 days of retained data and count what it would have alerted on. This is free and it is the single most valuable step in the pipeline.
2. **Classify before filtering.** Group the hits by parent process, account, and command line pattern; the benign cluster is usually obvious and sharply defined.
3. **Filter at the most specific field available.** A parent-process path, a signer, or an exact command-line prefix is a narrow filter. A directory or a username is a broad one that will hide the next intrusion.
4. **Combine conditions rather than allowing single indicators.** Require the suspicious behaviour *and* a context signal (unsigned binary, unexpected parent, off-hours account).
5. **Keep exceptions documented and owned.** Each filter gets a reason, an owner, and a date. An undocumented filter is tomorrow's blind spot.
6. **Re-test after every change.** Retune with the emulation that produced the finding, so you know the rule still catches the malicious case.

**Measure it.** Track alerts per rule per week, the share marked false positive, and the time analysts spend per alert. A rule with a 95% false-positive rate is not a detection; it is a queue tax. Report it and either fix it or retire it.

## Validation with emulation

A detection is a claim about the world. Emulation is how you test the claim end to end.

**Positive test — the rule must fire.**

```powershell
# Re-run the atomic that produced the original finding, in the lab or with approval in production
Invoke-AtomicTest T1059.001 -ShowDetails
Invoke-AtomicTest T1059.001 -TestNumbers <n>
# Then: confirm the alert appears, with the expected fields populated and the right severity
Invoke-AtomicTest T1059.001 -TestNumbers <n> -Cleanup
```

**Negative test — the rule must stay quiet.** Run the legitimate equivalent: your deployment tool performing the same action, your approved admin script with the same arguments. A rule that fires on both has not been validated, only observed.

**Regression test — the rule must survive edits.** Every change to a rule re-runs the positive and negative tests, and records the result in the rule's repository entry. This is the entire reason rules live in version control.

Checks that catch most broken detections:

- **Data present?** Confirm the logsource category is actually collected, and that the fields the rule references are populated (not empty strings) in the events.
- **Field names right?** A single typo in a field name produces a rule that never fires and never errors.
- **Timing right?** Some sources ingest with minutes of latency; an alert that depends on two sources correlating within one minute may be structurally unreliable.
- **Alert delivered?** Confirm the rule reaches a destination a human reads — not a folder, not a disabled search, not a notepad dashboard.
- **Documented?** The triage note tells the analyst what to check first and what a benign instance looks like.

Then measure coverage honestly. Counting rules flatters you; counting *validated* rules against prioritized techniques does not. Build an ATT&CK Navigator layer from your rule `tags` and track it quarter over quarter — and record which techniques were validated by emulation rather than merely covered on paper.

## Closing the loop with the SOC and IR

The detection is only half the handoff. Package it so the SOC can use it on the first shift it exists.

**Rule handoff package:**

- Rule ID, name, owner, and repository link.
- Behaviour in one sentence, and the technique mapping.
- Expected volume (alerts per week) and severity.
- Triage steps: the first three things to check, with the exact queries.
- Known benign causes, with the filter that already covers them.
- Escalation trigger: what turns this alert into an incident.
- Test evidence: the emulation used, and the date.

**Other directions the loop runs:**

- **To IR:** the TTPs the hunt confirmed, the artefacts and hashes observed, and the queries that found them — so a future incident starts with scope instead of a blank page.
- **To threat intelligence:** what was actually seen in this environment, which is more actionable than what was reported elsewhere.
- **To platform engineering:** the collection and retention requests that came out of the hunt's telemetry gaps. These are the changes that make the *next* hunt possible.
- **To the hunting backlog:** every hunt generates follow-up hypotheses; the journal is where they live.

## The hunt report

The report is the artefact that outlives the hunt. Write it for two readers: the analyst who will re-run the hunt, and the decision-maker who will fund the fix.

```text
1. Header         Hunt ID, title, dates, hunters, status (confirmed / refuted / inconclusive).
2. Scope          Hosts, accounts, environments, time window, data sources used, and what was excluded.
3. Hypothesis     The hypothesis as written before the hunt, with subject, behaviour, data, criteria.
4. Data           Sources queried, health check performed, retention window, known limitations.
5. Method         How the hunt ran: queries verbatim, pivots taken, baselines used, what was dismissed
                  and why.
6. Findings       What was observed, stated as facts with evidence references (host, time UTC, event,
                  hash, path). Clearly separated from interpretation.
7. Coverage gap   What could not be seen, quantified, with the change that would close it.
8. Detections     Rules created or modified, with their IDs, test evidence, and expected volume.
9. Recommendations Ordered by effort and impact: collection, detection, hardening, process.
10. Appendix      Exported result sets, artefact hashes, timestamps, and the emulation used.
```

Writing rules that keep a report useful:

- **Facts and interpretations are labelled separately.** "A scheduled task was created by `powershell.exe` at 02:14 UTC" is a fact. "An attacker established persistence" is an interpretation and belongs in a different column or sentence.
- **Negative results are reported as results.** "Refuted after triaging 42 candidates across 180 hosts" is a coverage statement you can defend in an audit.
- **Every finding carries its evidence**: host, UTC time, event or artefact, and where the export lives.
- **Limitations are stated, not omitted.** An honest gap becomes a funded collection request; a hidden one becomes the next incident.
- **Recommendations are ordered.** Five equal-priority recommendations produce no action.

## Measuring the improvement

Report the delta, not the activity. A compact set of metrics, measured per cycle:

| Metric | How to measure | What good looks like |
| --- | --- | --- |
| Techniques covered by validated rules | Count ATT&CK techniques with a rule that passed positive and negative tests | Rising against a prioritized target list |
| Coverage delta this cycle | New validated techniques minus retired ones | Positive, and explained |
| False-positive rate of new rules | Alerts marked benign ÷ total alerts, per rule, per week | Falling after tuning; documented for the rest |
| Alert volume per rule | Alerts per week, tracked after deployment | Predictable; no rule dominating the queue |
| Time from finding to deployed rule | Journal date of the finding to deployment date | Weeks, not quarters |
| Telemetry gaps closed | Collection changes implemented and validated | Each one re-tested with the hunt that found it |
| Repeat-hunt success | Re-running an old hunt for a now-covered behaviour, and getting an alert instead of manual work | Automatic detection replaces the manual hunt |
| Effect on triage load | Analyst minutes per alert on the new rules | Bounded, and known to the SOC before deployment |

Two habits keep this honest:

- **Re-hunt old hypotheses.** The definitive test of a detection is whether the next hunt for the same behaviour finds it automatically. If it does not, the rule is documentation, not detection.
- **Retire rules deliberately.** Rules that no longer map to a technique, a data source that vanished, or a behaviour that changed should be removed with a dated note — otherwise coverage numbers drift away from reality.

> Every command, query, and rule in this file is a syntax reference. None of it was executed while writing: this repository contains no SIEM, no endpoint telemetry, and no rule deployment pipeline. Validate in your own lab before you trust it in production.

## Common Mistakes & Tips

- **Deploying without a test.** The most common and most expensive error. A rule that has never fired on purpose has never been validated.
- **Alerting on single events.** One `net.exe` is nothing. A burst, a rare parent, or an unexpected account is a detection.
- **Tuning with broad filters.** Excluding a whole directory or username to silence noise hides the next attacker in the same place. Filter on the most specific field that explains the benign cluster.
- **Coverage theatre.** Counting rules instead of validated techniques produces green dashboards and no defence.
- **No owner, no review date.** Rules rot silently: data sources change, field names move, behaviour shifts.
- **Forgetting the analyst.** A rule without triage guidance is a puzzle delivered at random hours.
- **Letting the report become a status update.** Findings, evidence, gaps, and ordered recommendations — or it will not change anything.
- **Tip:** keep the emulation that produced each rule next to the rule. It is the regression test, and it stops arguments about whether a change broke coverage.
- **Tip:** review the noisiest ten rules quarterly and decide explicitly: tune, keep, or retire.

## Checklist / Self-Test

- [ ] Can I name the seven pipeline stages from finding to retirement, and the exit criterion for each?
- [ ] Can I write a Sigma rule with logsource, selections, a filter, a condition, mapped tags, and documented false positives?
- [ ] Can I convert a rule to my SIEM's query language and then review the output rather than trusting it?
- [ ] Can I express the same detection in KQL and SPL, with a threshold or aggregation where the behaviour requires it?
- [ ] Can I backtest a candidate rule against history and classify its hits before deploying?
- [ ] Can I run a positive test, a negative test, and a post-edit regression test for one rule?
- [ ] Can I state the false-positive causes of a rule I own, and when each filter was added and why?
- [ ] Can I produce a rule handoff package a tier-1 analyst could act on during their first shift?
- [ ] Can I write a hunt report with facts separated from interpretation, quantified gaps, and ordered recommendations?
- [ ] Can I measure coverage as validated techniques rather than as a count of rules?

## Further Resources

- **Sigma** (rule format, modifiers, and specification) — https://sigmahq.io/
- **SigmaHQ rule repository** (community rules to compare against your own) — https://github.com/SigmaHQ/sigma
- **MITRE ATT&CK** (technique mapping for rule tags and coverage measurement) — https://attack.mitre.org/
- **ATT&CK Navigator** (coverage layers from validated rules) — https://mitre-attack.github.io/attack-navigator/
- **MITRE Cyber Analytics Repository (CAR)** (analytic logic to borrow from) — https://car.mitre.org/
- **Atomic Red Team** (positive and negative test material) — https://github.com/redcanaryco/atomic-red-team
- **NIST SP 800-61 Rev. 2**, *Computer Security Incident Handling Guide* (handoff to incident response) — https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- **Official eCTHP product page** (authoritative syllabus and logistics) — https://ine.com/security/certifications/ecthp-certification
