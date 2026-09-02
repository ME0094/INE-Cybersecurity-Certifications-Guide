# eSOC Methodology — Phase 3: Investigation

> Tier-1 SOC Analyst focus · INE-Cybersecurity-Certifications-Guide

Investigation is where an alert becomes a verdict: True positive, False positive, or Needs escalation. This guide covers the alert triage workflow, enrichment (reputation, context, asset owner), building an event timeline, correlating indicators, documenting findings, and the decision to escalate or close.

## The Tier-1 Triage Mindset

Your goal is not "solve the entire intrusion." It is to **make a correct, documented, timely decision** about whether the alert is real and dangerous enough to escalate — and to leave the next analyst everything they need if it is.

Work from a checklist, not from memory. Under time pressure, analysts skip steps; a written triage flow prevents that. Verify, don't assume: an alert is a *claim* about events, and your job is to confirm it against the raw data.

Triage flow in one picture:

```text
Alert arrives (ACK within SLA)
   |
   +-- 1. Validate the alert (raw events, fields, timing)
   |        |
   +-- 2. Enrich (reputation, context, asset owner)
   |        |
   +-- 3. Scope (build timeline, correlate indicators)
   |        |
   +-- 4. Decide
            +-- False positive  -> document reason, tune
            +-- True positive, contained scope -> document, track as case
            +-- True positive, spreading/unknown -> escalate to IR
```

## Alert Triage Workflow

A repeatable sequence for nearly every tier-1 alert:

1. **Acknowledge within SLA.** Claim the alert in the queue/ticketing tool so others do not double-work it.
2. **Read the alert metadata.** What rule fired, severity, host(s), user(s), time window, MITRE ATT&CK tags.
3. **Open the raw events.** Confirm the rule's conditions actually occurred — same event code, same fields, correct timestamps. Parsing or clock bugs create ghost alerts.
4. **Ask the five W's:** Who (user/host), What (action/process), When (first and last seen), Where (source and destination), Why (does it fit a known pattern, or is it unexplained?).
5. **Form a preliminary hypothesis.** Example: "host X ran PowerShell with an encoded command at 03:00; is this admin maintenance or malware?"
6. **Investigate enough to confirm or refute it** (enrichment + timeline below), with a time box — e.g., 30 minutes for tier-1 before escalation guidance is needed.
7. **Record the verdict and reasoning**, then close or escalate.

A triage worksheet template:

```text
Alert ID / Rule name:        ____________________
Severity / Status:           ____________________
Hosts / Users / IPs:         ____________________
First seen / Last seen:      ____________________
Raw events confirm alert?    [ ] Yes  [ ] No — explain: ______
Enrichment summary:          ____________________
Other hosts/users affected?  [ ] No  [ ] Yes — list: ______
Verdict:                     [ ] FP  [ ] TP (contained)  [ ] TP (escalate)
Reasoning + next steps:      ____________________
```

## Enrichment

Enrichment adds outside and internal context that raw events lack.

- **Reputation lookups:** IPs, domains, hashes against threat intel (AlienVault OTX, VirusTotal, AbuseIPDB, MISP instance). Interpret carefully: intel is probabilistic, not truth — one VirusTotal hit from an unknown vendor is weak; an IP on an active C2 feed is strong.
- **Passive DNS / WHOIS:** has the domain been seen before? When was it registered (brand-new domains are suspicious)? Who hosts it?
- **Asset context:** what does this host do (DC, file server, developer workstation)? Is it internet-facing? What is its criticality tier?
- **Asset owner:** who to call when the host must be contained or taken offline. Lookup from CMDB/AD, not guesswork.
- **User context:** department, role, travel history, VPN usage, whether the account is a service account. A developer logging on from a hotel in another country reads differently than a service account doing the same.
- **Historical sighting:** has this hash/IP/user triggered anything else in the last 90 days? One-off vs repeat pattern changes the verdict.

Enrichment lookup flow for an unknown source IP:

```text
Alert shows src_ip 203.0.113.77
   |-> Reputation feed  : no hits (fresh/unknown)  [weak signal]
   |-> WHOIS / passiveDNS: domain registered 2 days ago [strong signal]
   |-> Internal history : same IP brute-forced VPN 3 weeks ago [strong signal]
   |-> Asset/geo        : country never used by this org [medium signal]
   V
Verdict leans TRUE POSITIVE -> widen scope, escalate
```

## Building an Event Timeline

A timeline is the investigation's spine: every relevant event ordered by time, from the *earliest suspicious activity* forward. Reconstructing when an attacker first acted is often more valuable than the alert moment itself.

How to build one:

1. **Anchor** at the alert event's timestamp.
2. **Go backward** to find the first sign: initial access (phishing link click, RDP brute force success, new scheduled task) — the "patient zero" event.
3. **Go forward** to the present: what happened after — lateral movement, persistence, data access.
4. **Pull each layer** of logs for the same host/user/indicators: auth, process execution, network, file/system changes.
5. **Represent time consistently** (UTC in the log, local in the write-up) and note the gaps — missing data is itself a finding.

Timeline fragment (Windows-oriented):

```text
2025-06-01 02:11:14Z  4625  failed logon x6, user: j.doe, src: 198.51.100.9
2025-06-01 02:12:01Z  4624  SUCCESS logon, user: j.doe, type 3, src: 198.51.100.9
2025-06-01 02:12:40Z  4688  powershell.exe -enc <base64>  (parent: svchost.exe)
2025-06-01 02:13:05Z  sysmon 3  powershell.exe -> TCP 203.0.113.77:443  [C2?]
2025-06-01 02:14:22Z  4698  scheduled task "UpdaterSvc" created by j.doe  [persistence]
```

Build it in the SIEM (timeline view / time-boxed search) and paste the ordered result into your case notes — the artifact *is* the deliverable.

## Correlating Indicators

An indicator alone is weak; correlated indicators are evidence. Treat this as hypothesis testing:

- **IP + user + process + persistence** seen together across layers is an attack story; the same IP alone is a lead.
- Correlate by **time proximity** (events within minutes), by **shared entity** (same host/user/domain), and by **parent–child relationships** (which process launched what).
- Check **other entities** that share an indicator: other hosts that logged on from the same IP, other users who received the same phishing subject, other machines that executed the same hash.
- **Look for the kill chain direction:** is the activity consistent with initial access → execution → persistence → C2? If you can name the stages you observed, escalation notes write themselves.

Scoping query concept (everything touching one user in 48 hours):

```lucene
user.name:"j.doe" AND @timestamp:[now-2d TO now]
| stats count by event.category, host.name, source.ip
```

If the same indicator touches a second host, your scope just doubled — update the case and the escalation threshold immediately.

## Documenting Findings

If it is not documented, it did not happen. Your notes are the input to the case ticket, the shift handover, the IR handoff, and possibly legal or compliance review.

Write for the next reader: precise, chronological, evidence-linked (alert IDs, event IDs, timestamps, raw log excerpts), and separated into *facts* and *assessment*.

Case note skeleton:

```text
SUMMARY:        One-paragraph plain-language description of the activity.
ALERT(S):       Rule names + IDs + severity + timestamps.
SCOPE:          Hosts, users, IPs, domains involved (confirmed vs suspected).
TIMELINE:       Chronological list of key events with evidence references.
ENRICHMENT:     Intel/context consulted and what it added.
ASSESSMENT:     Analyst interpretation — confidence, phase of attack reached.
VERDICT:        False positive / True positive (contained) / Escalate.
ACTIONS TAKEN:  ACK time, queries run, owner notified, containment steps (if any).
RECOMMENDATION: Close, monitor, or escalate; suggested next steps.
```

Good documentation is boring and complete. Avoid: vague phrases ("weird traffic"), undocumented opinions, and copying raw logs without a stated conclusion.

## Escalate vs Close

Apply a consistent decision rule so the outcome does not depend on who is on shift.

**Close as false positive (with reason)** when the alert condition is met but the activity is explained and benign — scheduled scan, admin change window, parser artifact, allowlisted application. Always write the reason: a closed FP with no explanation is a tuning opportunity lost.

**Escalate (and escalate early)** when any of these hold:

- Confirmed malicious behavior (known C2, malware hash, credential theft pattern).
- Scope is unclear or expanding (indicator touches multiple hosts/users).
- Accounts with high privilege or critical assets (DC, domain admin, payment systems) are involved.
- Persistence or lateral movement is present or suspected.
- Data exfiltration or destruction is plausible.
- The activity cannot be explained within your time box.

Escalation trigger, table form:

```text
Single host, single user, explained activity  -> close (FP) + tune
Single host, suspicious but unknown           -> contain guidance, monitor
Multiple hosts / admin account / persistence -> ESCALATE to IR now
Exfiltration / DC compromise                  -> ESCALATE immediately (break glass)
```

Know the difference between **monitor-and-continue** (true positive, contained, wait for more data) and **escalate** (needs a higher authority: IR team, manager, or on-call). When in doubt, escalate — the cost of a false escalation is a meeting; the cost of a missed one is an incident.

## Common Mistakes & Tips

- **Mistake:** trusting the alert summary and never opening raw events. *Tip:* ghost alerts (parser/clock/rule bugs) are common; verify before believing.
- **Mistake:** jumping to the conclusion before gathering the timeline. *Tip:* always identify the *first* event; the alert time is rarely the start of the story.
- **Mistake:** enrichment paralysis — checking 12 intel sources and still unsure. *Tip:* weigh signals by source quality and recency; two strong signals beat ten weak ones.
- **Mistake:** scoping to the alerting host only. *Tip:* always ask what else shares the user, IP, or hash.
- **Mistake:** undocumented reasoning, then a colleague re-does the whole investigation. *Tip:* fill the case notes as you go, not at the end.
- **Mistake:** closing a true positive as "monitored" with no owner and no deadline. *Tip:* every open verdict needs a next action and a time to re-check.

## Checklist / Self-Test

- [ ] I ACK alerts within the SLA and work from a written triage checklist.
- [ ] I validate every alert against raw events before forming a verdict.
- [ ] I enrich hosts, IPs, users, and hashes and weigh intel by quality, not count.
- [ ] I can identify the asset owner and criticality of any host in an alert.
- [ ] I can build a chronological timeline from first suspicious event forward.
- [ ] I correlate indicators across hosts/users and re-scope when new entities appear.
- [ ] My case notes contain summary, scope, timeline, assessment, verdict, and recommendation.
- [ ] I apply a documented rule for escalate-vs-close and escalate early when scope is unclear.

## Further Resources

- MITRE ATT&CK — kill-chain framing and technique context for analysis: https://attack.mitre.org
- NIST SP 800-61 — Computer Security Incident Handling Guide (triage & escalation context): https://csrc.nist.gov/pubs/sp/800/61/r3/final
- AlienVault OTX (open threat intelligence): https://otx.alienvault.com
- VirusTotal (file/IP/domain reputation): https://www.virustotal.com
- MISP (open-source threat intelligence platform): https://www.misp-project.org
- CISA — incident response and analysis guidance: https://www.cisa.gov/resources-tools/resources/incident-response-guidelines
