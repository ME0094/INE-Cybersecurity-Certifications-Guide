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

Timeline fragment (Windows-oriented). This is a *constructed illustration of the shape* a timeline takes, not captured output from a real system — no SIEM or event log was consulted to produce it, and your own lab will give you the real thing:

```text
2025-06-01 02:11:14Z  4625  failed logon x6, user: j.doe, src: 198.51.100.9
2025-06-01 02:12:01Z  4624  SUCCESS logon, user: j.doe, type 3, src: 198.51.100.9
2025-06-01 02:12:40Z  4688  powershell.exe -enc <base64>  (parent: svchost.exe)
2025-06-01 02:13:05Z  sysmon 3  powershell.exe -> TCP 203.0.113.77:443  [C2?]
2025-06-01 02:14:22Z  4698  scheduled task "UpdaterSvc" created by j.doe  [persistence]
```

Build it in the SIEM (timeline view / time-boxed search) and paste the ordered result into your case notes — the artifact *is* the deliverable.

Note where the illustration is already misleading, because that is the skill: a `4688` whose parent is `svchost.exe` is *itself* a finding (service-hosted execution), and a logon at 02:11 with `type 3` after six failures from a public address is not routine. A timeline is not a list of events; it is a list of events **you have annotated with what each one implies**.

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

## Worked Example: One Alert, End to End

The alert: *"Suspicious PowerShell – Encoded Command Execution"* on `WIN-FIN-07`, user `CORP\m.lopez`, severity high, 21:47 local. Everything below is a **reasoning walkthrough**, written as decision gates rather than reproduced tool output: the point is the order of the questions, and each gate names what would change your mind.

**Gate 1 — Does the raw event exist?** Search for the process-creation event the rule claims to have matched. Two outcomes matter:

- The event is there with `-EncodedCommand` in the command line → continue to gate 2.
- There is no such event → the alert is a parser artifact or a stale index. Do **not** keep investigating a ghost; fix the rule and document that you did. Ghost alerts are the cheapest false positive to eliminate and the most expensive to inherit.

**Gate 2 — Who, and does the account belong there?** Look up the user: department, role, whether it is a service account, and whether the host is the one that user normally uses. Ask the question that decides the rest of the investigation: *would this account legitimately run an encoded PowerShell command on this machine at this hour?* A service account on a file server at 02:00 and a developer on their own workstation at 11:00 lead to different next steps, not because the technique differs but because the baseline does.

**Gate 3 — What is the parent, and what is the command line?** The parent process is usually the fastest discriminator: an encoded command from a management agent, a monitoring probe, or a signed deployment tool has a plausible parent; one whose parent is `winword.exe`, `outlook.exe`, `wscript.exe`, or an application that should never spawn a shell does not. Then read the command line itself — flag names, paths, and anything written to a user-writable directory.

**Gate 4 — Decode the payload.** Base64 is encoding, not malice, and decoding it is a read-only action that costs seconds. What you are looking for:

| What the decoded payload contains | What it suggests | Next step |
|---|---|---|
| Your own tooling's imports and a known module path | Legitimate automation | Confirm with the owner, then add a narrow exclusion |
| Download primitives (`DownloadString`, `Invoke-WebRequest`), `IEX`, `FromBase64String` chains | Stager or download cradle | Continue to scope; treat as malicious until proven otherwise |
| Credential material, `lsass`, key material, or token manipulation | Credential theft | Escalate immediately; check `T1003` indicators on the host |
| Reconnaissance (`net view`, `whoami /all`, AD queries) | Discovery, possibly manual operator | Look for what happened next on the same host and others |
| Nothing readable (garbage, or a second encoded layer) | Deliberate obfuscation | Escalate; obfuscation depth is itself evidence of intent |

**Gate 5 — Scope it.** Continue the timeline forward and sideways: what did that process do next (child processes, network connections, file writes, registry writes), and what else in the environment shows the same indicators in the last 24–72 hours? Two questions decide the verdict here — *is the host alone*, and *is the account alone*.

**Gate 6 — Decide and write it down.** If the command decodes to approved automation from a signed parent and the same pattern runs across the fleet nightly, this is a false positive with a tuning action (narrow exclusion, dated). If it decodes to a download cradle, the host contacted an external address, and no ticket explains it, this is a true positive and it escalates — with the timeline, the decoded payload, and the scope as you know it. If it decodes to something readable that you still cannot explain, it is a true positive of unknown intent: escalate and say exactly that, rather than picking a label you cannot support.

> The recurring error in this walkthrough is stopping at gate 3. A verdict built on the parent process and the alert title alone is a guess with a timestamp on it.

## Correlation: Entity, Pivot, Question

An indicator is weak because it is *single*. Correlation means turning one artifact into a query that asks what else shares it. Keep this table next to the escalation decision.

| Entity in the alert | Pivot question | Query shape (Kibana KQL / SPL) |
|---|---|---|
| `host.name` | What else did this host do, before and after? | `host.name : "win-fin-07" and event.category : (process or network or file)` |
| `user.name` | Where else did this account authenticate? | `user.name : "m.lopez" and event.category : authentication` |
| `source.ip` | Who else authenticated from this address? | `source.ip : "198.51.100.9" and event.category : authentication` |
| `process.name` / `process.parent.name` | Is this parent–child pair normal in this environment? | `process.parent.name : "winword.exe" and process.name : *` |
| File hash | Where else has this file been seen — on disk and in the SIEM? | `file.hash.sha256 : "<hash>"` and a YARA scan over collected samples |
| Domain / URL | Who else resolved or requested it? | `dns.question.name : "<domain>" or url.full : *<domain>*` |
| Scheduled task / service name | What created it, and does it exist elsewhere? | `event.code : ("4698" or "7045") and winlog.event_data.TaskName : *UpdaterSvc*` |

```spl
# Splunk equivalent of "scope one user across every source class"
index=* user="m.lopez" earliest=-72h
| stats count values(sourcetype) as sources by host
| sort - count
```

Two habits make correlation trustworthy. First, **always state which entity names the scope** — "the IP is the same but the account is different" is a materially different finding from "the same account used two IPs". Second, **update the scope when it widens**: the moment a second host appears, the verdict and the escalation threshold change, and the case note has to say so before you continue.

## Time-Boxing the Investigation

Tier 1 does not own an investigation forever. Decide the box when the alert arrives, and treat reaching the end of it as information rather than failure.

| Alert severity | Reasonable tier-1 box | If the box expires without a verdict |
|---|---|---|
| Low / informational | Finish in the same pass, minutes | Close with a reason, or park it with a monitoring note and a re-check time |
| Medium | Under an hour | Ask for guidance; do not let it absorb the shift |
| High | Immediate attention; scope within the hour | Escalate with what you have — an unresolved high-severity alert *is* the escalation trigger |
| Critical | Drop everything, notify first, investigate in parallel | Escalation is already underway; keep documenting while others act |

The box is about *attention*, not curiosity. Productive reasons to extend it: a scope that is actively widening, a containment action in progress, or an IR request. Unproductive reasons: "I want to understand the malware", "I almost have it", or "I do not want to escalate something I cannot explain" — that last one is the exact opposite of the rule.

## What a Good Triage Note Looks Like

The note is the product. Two versions of the same finding, one usable and one not:

| Weak | Why it fails | Strong |
|---|---|---|
| "Looks like a false positive, closed." | No evidence, no reason, no tuning input | "Encoded PowerShell from `CORP\m.lopez` on `WIN-FIN-07` at 21:47 UTC. Command line matches the nightly inventory agent (`signed by <vendor>`, parent `AcmeAgent.exe`). Same pattern on 214 hosts in 24 h. Closed FP; proposed exclusion on parent path — case SOC-2025-001, re-review 2025-09-01." |
| "Suspicious traffic to an unknown IP." | Unactionable for the next reader | "`powershell.exe` on `WIN-FIN-07` opened three TCP connections to `203.0.113.77:443` at 02:13, 02:14, 02:15 UTC (regular ~60 s interval). Process parent `svchost.exe`; no signed-binary path in file telemetry. Escalated as suspected C2 beacon, host isolated at 02:21 UTC; scope currently one host, one user." |
| "Escalated to tier 2." | No content for tier 2 to act on | "Escalated: summary, hosts/users/IPs, UTC timeline with event IDs, queries run, actions taken (isolation, account disabled), open questions (how the credential was obtained; whether the C2 address is shared). Case SOC-2025-001." |

The pattern in every strong note: **what you observed, how you know, what you did, what is still open**. Confidence language is explicit ("confirmed", "probable", "unexplained") and never implies a certainty you do not have.

## The Handoff Boundary: What Tier 1 Owns

Escalating is not handing over the problem; it is handing over *a documented state*. Knowing where your ownership ends prevents both paralysis and overreach.

| Phase | Tier 1 owns | Tier 2 / IR owns |
|---|---|---|
| Alert validation | Confirming the raw events, fixing ghost alerts | Rule logic changes, data-source corrections |
| Initial enrichment | Reputation, asset owner, historical sightings | Deep malware analysis, adversary attribution |
| Scoping | Timeline for the alerting entities, first sweep for shared indicators | Enterprise-wide scope, all affected identities and assets |
| Verdict | FP / TP-contained / escalate, with evidence | Root-cause analysis, blast-radius confirmation |
| Containment | Pre-approved reversible actions in the playbook | Destructive or irreversible actions, eradication, recovery |
| Documentation | Case notes and the escalation package | Incident record, regulator or customer communication |

> "I do not know" is a legitimate answer at this boundary — but only with the query you ran, the sources you checked, and the question you are handing over. An unexplained escalation with a written question is a professional handoff; an unexplained escalation with nothing in it is a restart for someone else.

## Common Mistakes & Tips

- **Mistake:** trusting the alert summary and never opening raw events. *Tip:* ghost alerts (parser/clock/rule bugs) are common; verify before believing.
- **Mistake:** jumping to the conclusion before gathering the timeline. *Tip:* always identify the *first* event; the alert time is rarely the start of the story.
- **Mistake:** enrichment paralysis — checking 12 intel sources and still unsure. *Tip:* weigh signals by source quality and recency; two strong signals beat ten weak ones.
- **Mistake:** scoping to the alerting host only. *Tip:* always ask what else shares the user, IP, or hash.
- **Mistake:** undocumented reasoning, then a colleague re-does the whole investigation. *Tip:* fill the case notes as you go, not at the end.
- **Mistake:** closing a true positive as "monitored" with no owner and no deadline. *Tip:* every open verdict needs a next action and a time to re-check.
- **Mistake:** stopping at the parent process. *Tip:* the parent narrows the hypothesis; the child behaviour, the network destination, and the scope confirm or refute it.
- **Mistake:** extending the time box because you want to understand the whole attack. *Tip:* tier 1's deliverable is a documented state, not a finished analysis — write the question you are handing over.
- **Mistake:** writing a note that describes feelings rather than evidence ("looks weird", "seems fine"). *Tip:* every sentence should be checkable by the next reader: what you ran, what it showed, what you concluded.
- **Mistake:** chasing an alert that has no underlying event. *Tip:* validate first; a ghost alert is a rule/data defect, and the fix belongs upstream, not in your investigation.

## Checklist / Self-Test

- [ ] I ACK alerts within the SLA and work from a written triage checklist.
- [ ] I validate every alert against raw events before forming a verdict.
- [ ] I enrich hosts, IPs, users, and hashes and weigh intel by quality, not count.
- [ ] I can identify the asset owner and criticality of any host in an alert.
- [ ] I can build a chronological timeline from first suspicious event forward.
- [ ] I correlate indicators across hosts/users and re-scope when new entities appear.
- [ ] My case notes contain summary, scope, timeline, assessment, verdict, and recommendation.
- [ ] I apply a documented rule for escalate-vs-close and escalate early when scope is unclear.
- [ ] I can walk the six gates of a suspicious-execution alert and say what would change my verdict at each one.
- [ ] I decode an encoded command before judging it, and I can say what the payload tells me about intent.
- [ ] I can turn any entity in an alert into a pivot query and state which entity defines the current scope.
- [ ] I know my time box for each severity and what I do when it expires.
- [ ] My notes name the owner and the boundary of my part of the investigation, and state open questions explicitly.

## Further Resources

- MITRE ATT&CK — kill-chain framing and technique context for analysis: https://attack.mitre.org
- NIST SP 800-61 — Computer Security Incident Handling Guide (triage & escalation context): https://csrc.nist.gov/pubs/sp/800/61/r3/final
- AlienVault OTX (open threat intelligence): https://otx.alienvault.com
- VirusTotal (file/IP/domain reputation): https://www.virustotal.com
- MISP (open-source threat intelligence platform): https://www.misp-project.org
- CISA — incident response and analysis guidance: https://www.cisa.gov/resources-tools/resources/incident-response-guidelines
