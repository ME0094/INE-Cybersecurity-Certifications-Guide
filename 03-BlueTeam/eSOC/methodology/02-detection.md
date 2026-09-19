# eSOC Methodology — Phase 2: Detection

> Tier-1 SOC Analyst focus · INE-Cybersecurity-Certifications-Guide

Detection is the practice of turning monitoring data into alerts that mean something. This guide contrasts signature and anomaly approaches, introduces detection engineering fundamentals, explains the Sigma and YARA concepts an analyst must read fluently, walks common detection use cases (authentication anomalies, beaconing, LOLBins), and covers the discipline of false-positive tuning.

## Signature vs Anomaly Detection

- **Signature (rule-based) detection** matches events against known patterns: an IOC hash, a specific command line, a known bad domain. It is precise, fast, easy to explain, and nearly useless against novel activity. Signature quality decays as attackers change one byte or one argument.
- **Anomaly (behavioral/statistical) detection** flags events that deviate from a learned or declared baseline: unusual login time, abnormal data egress, unexpected parent–child process pairs. It finds novel attacks but produces more noise and needs good baselines to stay sane.
- **In practice you use both.** A strong detection program layers them: signatures catch the known and the commodity; anomalies catch the weird; correlation rules connect separate signals into one story. Never let one layer be your whole strategy.

| Aspect | Signature | Anomaly |
|---|---|---|
| Basis | Known pattern/IOC | Deviation from baseline |
| False positives | Low if pattern is specific | Higher, needs tuning |
| Novel attacks | Blind | Can surface them |
| Explainability | High | Lower |
| Maintenance | Update as IOCs change | Re-baseline over time |

## Detection Engineering Fundamentals

Detection engineering is the craft of creating, testing, and maintaining detection content. Core concepts:

- **Use case lifecycle:** hypothesis → data mapping → rule write → test against real + known-bad data → tune → monitor → retire. A detection that is never exercised is a guess.
- **ATT&CK as the map:** write coverage per technique, not per tool. When a new threat report appears, ask "which of our ATT&CK detections would catch this technique?" and fill the gap.
- **Atomic tests beat theory:** validate a rule by replaying the behavior (e.g., run the command, force the failed logon) and confirming the alert fires with the right fields.
- **Field hygiene:** rules should depend on normalized fields (`event.code`, `process.name`), never on raw message strings, or they break when a parser changes.
- **Precision first:** prefer several narrow rules over one broad rule. A specific alert that fires rarely but correctly is easier to trust than a broad one nobody reads.
- **Version and track content:** rules live in version control; every change is a diff with an owner, a date, and a rationale.

Rule-writing mental model:

```text
HYPOTHESIS: An attacker who steals a service account will use it
            outside its normal workstation set and hours.
DATA MAPPED: security events (4624), fields: user, src_ip, host, hour
RULE LOGIC:  success logon AND user is service account AND
             src_ip NOT IN [known good list]   -> alert (medium)
VALIDATION:  run atomic test -> alert fires with correct fields?
TUNING:      suppress the known maintenance window, re-test
```

## Sigma — Detection Rules as Code

Sigma is an open, generic signature format for log events. Instead of writing one rule per SIEM, you write Sigma once and convert it to Elasticsearch, Splunk, QRadar, and others (via tools like `sigmac` or Sigma converters in Elastic/Splunk).

Anatomy of a Sigma rule (read these fields fluently):

```yaml
title: Rundll32 Executing a URL Handler (Possible Download Cradle)
id: 8d4b4f0a-2b3f-4a1e-9c3a-1234567890ab
status: experimental            # experimental -> stable -> deprecated
description: Detects rundll32.exe launched with a URL-handling DLL export, a way to load remote content without a browser
logsource:
  # process_creation sees launches only: this category carries no network
  # fields, so it can never prove a connection happened. Detecting the
  # connection itself needs a separate rule on network_connection telemetry
  # (Sysmon 3 / EDR), where CommandLine does not exist.
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains:
      - 'url.dll,OpenURL'
      - 'url.dll,FileProtocolHandler'
  condition: selection
falsepositives:
  - Administrative use of rundll32 to open URLs
level: medium                    # informational/low/medium/high/critical
tags:
  - attack.t1218               # System Binary Proxy Execution
```

When you read a Sigma rule, decode it in four steps: (1) which log source does it expect, (2) which selection fields matter, (3) what does the condition combine, (4) how confident and how critical. Step 1 is the one that bounds everything else: a `process_creation` rule cannot observe a network connection, and a `network_connection` rule has no command line, so a title promising the wrong one is a title the logic can never satisfy. A tier-1 analyst also converts or re-implements Sigma rules in their SIEM when the detection team needs coverage fast.

## YARA — Malware Pattern Matching

YARA identifies malware by pattern-matching on files or memory, not logs. Rules describe binary or text characteristics: strings, byte sequences, file metadata. Understand the syntax well enough to read and lightly modify rules.

```yara
rule Suspicious_Powershell_DownloadCradle
{
    meta:
        author = "SOC Detection"
        description = "Detects common download-cradle strings in a script or binary"
    strings:
        $a = "System.Net.WebClient" ascii wide
        $b = "DownloadString" ascii wide
        $c = "IEX(" ascii
        $d = { 6A 00 6A 00 E8 }                 // raw hex bytes
    condition:
        2 of ($a,$b,$c) or $d
}
```

Condition reading: this fires when at least two of the first three strings appear, or the hex sequence appears. YARA shines on file collections, memory dumps (via YARA-enabled tools), and email attachments; it is useless on plain log text unless you scan extracted artifacts. Practice concepts: string modifiers (`ascii`, `wide`, `nocase`), the `condition` logic, and `meta` for attribution.

## Common Detection Use Cases

### Authentication Anomalies

Detect when an identity behaves out of character. Classic patterns:

- Failed logons across many users from one source IP (spray) — correlate with a later success (the spray landed).
- Successful logon from a geolocation or ASN the user has never used.
- Service accounts logging on interactively (type 2/10) or at 3 a.m. from a workstation.
- Kerberoasting indicators: many TGS requests (Event 4769) with RC4 encryption from one account.

Rule logic snippet — again pseudocode for a backend correlation, not a valid Sigma rule (no `timeframe`, no `count()` in Sigma; and the field names below are ECS-style `event.code`, which only exist if your pipeline defines them):

```yaml
# NOT VALID SIGMA — the backend does the aggregation
detection:
  selection_fail:
    event.code: 4625
  selection_success:
    event.code: 4624
  timeframe: 30m
  condition: selection_fail | count() by user.name > 10 and selection_success by user.name
```

The honest version of this detection is a **threshold rule in the platform**: group failed logons by account and source over a window, alert when the count crosses the baseline, and add the success event as correlated context rather than as a second condition. In Splunk that is a `stats`/`where` pair; in Sentinel it is `summarize ... by Account, IpAddress`; in Elastic Security it is a threshold rule on the same fields.

### Beaconing

C2 malware "beacons" home at regular intervals. Look for:

- A host contacting one external IP/domain repeatedly with similar request sizes.
- Low jitter: intervals tightly clustered around a mean (e.g., every ~60 seconds ± small variance) — measured on **raw event timestamps**, never on rounded time buckets, which force every interval to a multiple of the bucket and manufacture the regularity you are trying to test for.
- Unusual protocols or ports for the traffic (HTTP POST to a site the host never visited).

Elasticsearch-style shape — count first, then measure intervals. KQL filters and does not aggregate, so the counting is an ES|QL step:

```text
# Kibana KQL - the filter half only (no pipe, no aggregation)
event.category:network AND direction:egress AND destination.ip:*
```

```esql
// ES|QL - connections per source/destination pair, the set worth measuring
FROM logs-*
| WHERE event.category == "network" AND direction == "egress"
| STATS connections = COUNT(*) BY source.ip, destination.ip
| SORT connections DESC
```

Investigate regularity on that shortlist by taking the raw timestamps for one destination and computing the deltas between them — regular gaps plus small payloads are the classic beacon signature. Do the arithmetic on the event times themselves; binning the timestamps first destroys the measurement (see `../tools/query-languages.md` for the SPL form of the inter-arrival calculation).

### LOLBins

Living-off-the-land binaries are signed Microsoft/OS tools abused for malicious work: `powershell`, `cmd`, `rundll32`, `mshta`, `regsvr32`, `wmic`, `certutil`, `bitsadmin`. Because they are legitimate, detection depends on *context*: unusual parents, unexpected arguments, and combinations.

Examples to hunt:

- `certutil -urlcache -split -f http://...` (download) or `certutil -decode` (decode base64 payload).
- `mshta http://...` — script host pulling remote content.
- PowerShell with `-enc`, `-e`, `DownloadString`, or executing from suspicious parents.
- `regsvr32 /s /u /i:http://... scrobj.dll` — classic Squiblydoo.

Sigma selection for an encoded PowerShell launch:

```yaml
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-e '
  filter_known:
    CommandLine|contains: 'approved-automation-tool'   # allowlist your known use
  condition: selection and not filter_known
level: high
tags:
  - attack.t1059.001
```

## False-Positive Tuning

Every alert stream decays into noise without deliberate tuning. Discipline:

1. **Track why alerts fire.** Log each confirmed false positive with its cause: bad parser field, legit app behavior, missing allowlist, threshold too low.
2. **Fix at the right layer.** Root-cause first: fix the parser, then the allowlist, then the threshold — in that order. Patching a bad field with regex inside a rule just moves the problem.
3. **Use allowlists and filters, not threshold inflation.** A specific exclusion ("patch-management tool runs powershell nightly on these 5 hosts") keeps detection power for the other 1,000 hosts.
4. **Measure, don't guess.** Watch alert volume per rule, false-positive rate, and confirmed-true rate over 30 days. Retire rules that never fire or never confirm.
5. **Document every change.** Tuning that is not documented is a future mystery: next shift will not know why the rule looks the way it does.
6. **Prefer rules that scale.** A rule that needs daily whitelist edits is a process problem, not a tuning problem.

Tuning decision table:

```text
High true positives, high volume -> keep, add correlation/prioritization
High false positives, low value  -> filter root cause, or disable
Low volume, never confirms       -> investigate data source, then retire
High volume, never confirms      -> likely bad threshold or broken parse
```

## The Detection Lifecycle, Stage by Stage

A detection is a small product with a lifecycle. Each stage has an entry condition, a concrete artifact, and an exit condition — without the artifact, the stage did not happen.

| Stage | Entry condition | Artifact you must be able to show | Exit condition |
|---|---|---|---|
| 1. Hypothesis | A behaviour worth detecting, from threat intel, an incident, a hunt, or an ATT&CK gap | One sentence: *"An adversary doing X on asset class Y produces Z in source S"* | The behaviour is observable in data you actually collect |
| 2. Data mapping | The hypothesis names a source | Field list and a sample raw event proving the fields exist and are populated | Every field the logic needs is present, with a known type and case |
| 3. Rule authoring | Fields confirmed | The rule file (Sigma preferred), with MITRE tag, level, and reference | Rule is syntactically valid and readable by another analyst |
| 4. Validation (positive) | Rule exists | Evidence that the behaviour was reproduced and the rule fired with the expected fields | True positive confirmed against generated activity |
| 5. Validation (negative) | Positive case passes | Evidence of a run over a normal period with the alert count recorded | False-positive rate is known and acceptable — not "zero because nobody looked" |
| 6. Tuning | Known false positives | Each exclusion with a reason, a scope, and an expiry or review date | The rule survives a busy week without owning the queue |
| 7. Operation | Rule deployed | Owner, severity, playbook link, and expected volume | Alerts are acknowledged and triaged like everything else |
| 8. Review / retire | Recurring calendar trigger, or a data-source change | Decision recorded: keep, change, or retire — with the numbers behind it | The rule set stays smaller than or equal to the useful set |

> The stage analysts skip is **5**. A rule validated only against the activity that inspired it has an unknown false-positive rate, and an unknown rate becomes someone else's night shift. "It fired when I tested it" is half a validation.

## From a Case to a Rule (Worked Example)

This is the path a detection follows after a real triage, and it is the exact path the laboratory in `../labs/sigma-rule-tuning.md` walks through. The case: a user reported a document that asked them to "enable content"; the endpoint showed Word spawning a script host, which downloaded a file with `certutil`.

**Step 1 — Write the behaviour, not the sample.** The malware hash will change; the parent–child relationship is the durable part. *"An Office application spawning a scripting or download utility as a child process"* — that is the hypothesis, and it covers the whole family rather than one sample.

**Step 2 — Confirm the data.** Process creation with command lines is required. Check one raw event for the fields the rule will use: the child image path, the parent image path, the command line, the user. Both image fields come from the *same* record — `ParentImage` and `Image` are attributes of one process-creation event — so the parent–child relationship is read from a single event, the rule stays a single-event Sigma rule, and the false-positive rate measured at step 5 is the rate of that rule's matches, not of the whole Word → script host → `certutil` chain. If `ParentImage` is empty on your collector, the rule cannot work as written and the real fix is upstream.

**Step 3 — Write the rule.** Narrow on the parent (Office products), narrow on the child (script hosts and download utilities), and keep the exclusions explicit:

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

Two properties make that filter defensible, and both are easy to get wrong. It names **a specific known-good binary path**, not a location: an exclusion such as `CommandLine|contains: '\AppData\Local\Temp\'` would remove the detection exactly where macros stage their payloads, which is the blind spot the rule exists to close. And it carries **a comment with the date and the reason**, so the next analyst can re-review it instead of guessing. A rule that needs weekly allowlist edits is a process problem, not a tuning problem — if the exclusions keep growing, the real defect is upstream (an unsigned add-in, an untagged asset class, or a missing field).

**Step 4 — Convert and deploy.** Getting the rule into your back end is a conversion step, not a rewrite:

```bash
# Syntax check and conversion.
sigma check office-spawns-script-host.yml
sigma convert -t es-qs  office-spawns-script-host.yml
sigma convert -t splunk office-spawns-script-host.yml
sigma convert -t kusto  office-spawns-script-host.yml
```

`sigma check` was run against the rules in this file with **sigma-cli 3.1.0** (see the verification note at the end); `sigma convert` was **not**, because a conversion backend is a separately installed plugin. The conversion lines are the shape to run in an environment that has one.

**Step 5 — Validate both directions.** Reproduce the positive case in the lab (the drill in `../labs/sigma-rule-tuning.md` does exactly this) and record the alert count over a quiet period. Only then does the rule have a known error rate.

**Step 6 — Hand it over.** A rule without an owner, a severity, and a line in the triage playbook is an orphan. Write the one-paragraph playbook into the rule's PR description: what the analyst should check first, what a benign explanation looks like, and when to escalate.

## Suppression Without Blind Spots

Noise reduction is where good detections go to die quietly. Order the techniques from least to most dangerous, and always know which one you are applying.

| Technique | What it does | Blind spot it creates | Guardrail |
|---|---|---|---|
| **Threshold** (N events in T minutes) | Turns a flood into one alert | A single, deliberate event no longer alerts | Keep a second, low-volume rule for the *rare* variant of the same behaviour |
| **Deduplication** (one alert per key per window) | Collapses 5 000 alerts into one with a count | The count must be read: "one alert, 4 812 events" is not the same as one event | Always surface the event count in the alert body |
| **Field-scoped exclusion** (this binary, this signer, this account) | Removes a known-benign actor precisely | The excluded identity can later be abused (allowlisted binary as a LOLBin) | Narrow by *path plus signer*, never by name alone; review quarterly |
| **Time-scoped suppression** (this host, this change window) | Silences planned activity | Everything else on that host is silenced too, including the attack | Expiry timestamp in the suppression itself, and a case reference explaining it |
| **Global suppression** (this rule, everywhere) | Makes the queue clean | Total loss of detection, usually permanent, usually undocumented | Only as a temporary measure with an owner and a date; prefer disabling the rule, which is at least visible |
| **Disable** | Removes the rule | Total loss, but *visible* in the rule list and in coverage reporting | Legitimate outcome for a rule that never confirms; record it as a coverage decision |

Three habits keep suppression honest:

1. **Every exclusion gets a reason, an owner, and an expiry.** A comment in the rule file is the minimum: `# excluded 2025-06-01 by A.Tier1 - ACME backup agent signs its binaries; re-review 2025-09-01`.
2. **Test the exclusion, not just the rule.** After narrowing, re-run the original true-positive case and confirm it still fires. An exclusion that swallows your positive case has converted a detection into a placebo.
3. **Prefer fixing upstream.** If the noise comes from a parser field, a missing asset tag, or a deployment, fix that. A rule that needs weekly allowlist edits is a process defect wearing a detection costume.

## False-Positive Classification and the Right Fix

"False positive" is a category, not a diagnosis. Classify before you patch, because the correct fix depends on the class.

| Class | Typical example | Correct fix | Wrong fix |
|---|---|---|---|
| **Parser artifact** | `process.name` empty or truncated, so the rule matches nothing or everything | Fix the pipeline mapping, then re-test | Regex inside the rule to compensate |
| **Legitimate administrative tooling** | Your patch-management product runs encoded PowerShell nightly | Narrow exclusion on path **and** signer, documented and dated | Raising the threshold until the abuse case also stops alerting |
| **Business process** | Finance runs a bulk account-provisioning script each month-end | Scheduled suppression tied to the change calendar, with a case reference | Disabling the rule |
| **Threshold too tight** | 3 failed logons in 5 minutes alerts on ordinary typos | Widen the window or raise the count using real baseline data | Excluding the user who complained |
| **Missing context** | The rule cannot tell a service account from a human, so it alerts on both | Add the context (account type, asset tag) as an enrichment field, then filter on it | Telling analysts to "just close it with a reason" |
| **Environmental change** | A new application introduced, or a subnet was re-IP'd | Re-baseline and update the exclusions as part of the change | Treating each new alert as a one-off |
| **Genuine detection gap in the rule's logic** | It fires on the benign variant of a technique but not the malicious one | Rewrite the logic around the behaviour | Declaring the technique undetectable |

> A false positive that is closed without a class and a reason is a wasted detection improvement. The reason text *is* the tuning input; without it, the next analyst re-derives the same conclusion from nothing.

## YARA in the SOC: Where It Earns Its Place

YARA matches patterns in *files and memory*, not in log streams, so it answers a different question from Sigma: not "did this event happen?" but "does this artifact exist here?".

| Use in a SOC | What it gives you | What it costs |
|---|---|---|
| Scanning files collected from an investigation | Rapid family attribution and a way to name what you are looking at | Only as good as the rule; strings cannot see intent |
| Memory scanning (through a tool that supports it) | Catches decoded payloads and injected content that never hit disk | Requires a memory acquisition path and analyst time to triage hits |
| Retro-hunting an artifact store | Applies today's intelligence to yesterday's evidence — the main reason to keep samples and quarantine archives | Storage and a scanning budget |
| Triage of email attachments and downloads | Fast pre-filtering before deeper dynamic analysis | Attachments must be extracted to a scannable form first |

Rules of thumb that keep YARA useful instead of noisy:

- **Tighten the condition, not the strings.** Removing a distinctive string to reduce hits removes the detection. Counting how many strings must match (`3 of ($s*)`), requiring the file type (`pe.is_pe`, `uint16(0) == 0x5A4D`), or requiring a size or offset constraint are the correct tightening moves.
- **Test both directions every time you change a condition:** the sample that should match, and a folder of ordinary files that should not. "No match on `notepad.exe`" is a weak negative test — use dozens of real documents and binaries from your own environment.
- **Version your rules and say who verified them.** A community rule copied without testing is a hypothesis about someone else's environment.
- **Scan cost is real.** Wide-open string sets over a large file share produce both false positives and hours of I/O. Scope by path and by file type before you scope by string.
- **A match is a lead, not a verdict.** A text file containing credential-tool strings is a note someone saved; the same strings inside a signed-looking PE that also makes network connections is a different conversation. The laboratory in `../labs/sigma-rule-tuning.md` and the examples in `../tools/detection-rules/` both walk this distinction.

## Common Mistakes & Tips

- **Mistake:** writing a rule against raw log text and celebrating when it fires once. *Tip:* build on normalized fields; re-test after any parser change.
- **Mistake:** one giant regex rule trying to catch "all malware." *Tip:* small, specific rules; compose with correlation.
- **Mistake:** ignoring false positives because "analysts will triage." *Tip:* an overwhelmed triage queue is where real alerts get missed; tune to keep it survivable.
- **Mistake:** trusting Sigma/YARA rules copied from the internet without testing them against your own environment's noise. *Tip:* treat community rules as candidates, then validate and tune.
- **Mistake:** detecting only the endpoint layer. *Tip:* the same technique (e.g., credential dumping) should produce detections from multiple layers: endpoint, network, and auth.
- **Mistake:** never retiring rules. *Tip:* schedule a quarterly detection review — coverage grows by pruning, not only by adding.
- **Mistake:** shipping a rule that was only validated against the activity that inspired it. *Tip:* a positive test proves it can fire; only a run over normal data tells you how often it will.
- **Mistake:** excluding a *location* instead of an *identity*. *Tip:* filter on a specific signed binary path with a dated comment, never on `\Temp\`, `\ProgramData\`, or another directory attackers favour.
- **Mistake:** adding suppressions with no owner and no expiry. *Tip:* every exclusion carries "who, when, why, re-review date"; a suppression nobody owns is a permanent blind spot.
- **Mistake:** tightening a YARA rule by deleting strings. *Tip:* tighten the condition (count required strings, require the file type) and keep the distinctive strings.
- **Mistake:** writing aggregation logic inside a Sigma rule. *Tip:* Sigma describes one event; counting, thresholds, and sequences are backend features — put the correlation in the platform and keep the Sigma rule as the unit of detection content.

## Checklist / Self-Test

- [ ] I can explain signature vs anomaly detection and give one strength and one weakness of each.
- [ ] I can read a Sigma rule and state its log source, selection fields, condition, and level.
- [ ] I can read a YARA rule condition and explain when it fires.
- [ ] I can describe the beaconing pattern (regular intervals, low jitter) and the query shape to find it.
- [ ] I can list at least five LOLBins and the suspicious argument pattern for each.
- [ ] I can name the correct fix order when a rule is noisy (parser → allowlist → threshold).
- [ ] I can describe the lifecycle of one detection from hypothesis to retirement.
- [ ] I can map one of my organization's detection rules to its MITRE ATT&CK technique(s).
- [ ] I can write a rule that uses `selection_*` blocks plus one documented `filter_*`, and explain why the filter names an identity rather than a directory.
- [ ] I can say which stages of the detection lifecycle have an artifact in my repo, and which ones I have skipped.
- [ ] I can name the correct fix for a parser artifact, a noisy threshold, and a scheduled business process.
- [ ] I can list five noise-reduction techniques and the blind spot each one creates.
- [ ] I have run a YARA rule against both a positive sample and a folder of ordinary files, and I know why `notepad.exe` alone is a weak negative test.
- [ ] I can explain why `timeframe` and `count()` do not belong in a Sigma rule, and where that logic goes instead.

> **Verification:** every Sigma rule shown in this file was extracted to `/tmp` (nothing was written inside the repository) and checked with **sigma-cli 3.1.0** on **2026-09-19**: the rundll32 rule above, the encoded-PowerShell selection fragment and the Office-spawns rule from the worked example. All returned `Found 0 errors, 0 condition errors and 0 issues`. Two limits are worth stating: (1) `sigma check` also returned **0 errors for the pre-fix version** of the rundll32 rule — it validates syntax, not the claim a title makes about its logsource, which is why that defect needed a human to find; (2) `sigma convert` could not be exercised, because sigma-cli ships with no backend plugin installed (`sigma list targets` → *"No backends installed"*, and `-t splunk` → *"'splunk' is not one of ."*). The YAML of each rule was additionally parsed with PyYAML 6.0.1.

## Further Resources

- SigmaHQ — the open Sigma rule repository and format documentation: https://github.com/SigmaHQ/sigma
- Sigma specification (how to write and convert rules): https://github.com/SigmaHQ/sigma-specification
- YARA documentation — rule syntax and best practices: https://yara.readthedocs.io
- YARA rule repository (community): https://github.com/YARAHQ/yara-forge
- MITRE ATT&CK — techniques, tactics, and detection guidance: https://attack.mitre.org
- MITRE ATT&CK detection & analytics documentation: https://attack.mitre.org/resources/faq/
