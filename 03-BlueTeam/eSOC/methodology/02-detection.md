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
title: Rundll32 Internet Connection (Possible C2 or Download Cradle)
id: 8d4b4f0a-2b3f-4a1e-9c3a-1234567890ab
status: experimental            # experimental -> stable -> deprecated
description: Detects rundll32 making an outbound network connection
logsource:
  category: process_creation     # which log stream this rule expects
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
  - attack.t1218               # Signed Binary Proxy Execution
```

When you read a Sigma rule, decode it in four steps: (1) which log source does it expect, (2) which selection fields matter, (3) what does the condition combine, (4) how confident and how critical. A tier-1 analyst also converts or re-implements Sigma rules in their SIEM when the detection team needs coverage fast.

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

Rule logic snippet (single user, many source IPs + success later = possible brute force):

```yaml
detection:
  selection_fail:
    event.code: 4625
  selection_success:
    event.code: 4624
  timeframe: 30m
  condition: selection_fail | count() by user.name > 10 and selection_success by user.name
```

### Beaconing

C2 malware "beacons" home at regular intervals. Look for:

- A host contacting one external IP/domain repeatedly with similar request sizes.
- Low jitter: intervals tightly clustered around a mean (e.g., every ~60 seconds ± small variance).
- Unusual protocols or ports for the traffic (HTTP POST to a site the host never visited).

Elasticsearch-style shape (outbound connections per hour per destination):

```lucene
event.category:network AND direction:egress AND destination.ip:*
| stats count by source.ip, destination.ip
```

Investigate regularity with a table of connection timestamps for one destination and compute the deltas — regular gaps plus small payloads are the classic beacon signature.

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

## Common Mistakes & Tips

- **Mistake:** writing a rule against raw log text and celebrating when it fires once. *Tip:* build on normalized fields; re-test after any parser change.
- **Mistake:** one giant regex rule trying to catch "all malware." *Tip:* small, specific rules; compose with correlation.
- **Mistake:** ignoring false positives because "analysts will triage." *Tip:* an overwhelmed triage queue is where real alerts get missed; tune to keep it survivable.
- **Mistake:** trusting Sigma/YARA rules copied from the internet without testing them against your own environment's noise. *Tip:* treat community rules as candidates, then validate and tune.
- **Mistake:** detecting only the endpoint layer. *Tip:* the same technique (e.g., credential dumping) should produce detections from multiple layers: endpoint, network, and auth.
- **Mistake:** never retiring rules. *Tip:* schedule a quarterly detection review — coverage grows by pruning, not only by adding.

## Checklist / Self-Test

- [ ] I can explain signature vs anomaly detection and give one strength and one weakness of each.
- [ ] I can read a Sigma rule and state its log source, selection fields, condition, and level.
- [ ] I can read a YARA rule condition and explain when it fires.
- [ ] I can describe the beaconing pattern (regular intervals, low jitter) and the query shape to find it.
- [ ] I can list at least five LOLBins and the suspicious argument pattern for each.
- [ ] I can name the correct fix order when a rule is noisy (parser → allowlist → threshold).
- [ ] I can describe the lifecycle of one detection from hypothesis to retirement.
- [ ] I can map one of my organization's detection rules to its MITRE ATT&CK technique(s).

## Further Resources

- SigmaHQ — the open Sigma rule repository and format documentation: https://github.com/SigmaHQ/sigma
- Sigma specification (how to write and convert rules): https://github.com/SigmaHQ/sigma-specification
- YARA documentation — rule syntax and best practices: https://yara.readthedocs.io
- YARA rule repository (community): https://github.com/YARAHQ/yara-forge
- MITRE ATT&CK — techniques, tactics, and detection guidance: https://attack.mitre.org
- MITRE ATT&CK detection & analytics documentation: https://attack.mitre.org/resources/faq/
