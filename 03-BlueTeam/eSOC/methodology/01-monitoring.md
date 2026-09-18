# eSOC Methodology — Phase 1: Monitoring

> Tier-1 SOC Analyst focus · INE-Cybersecurity-Certifications-Guide

Monitoring is the foundation of every SOC workflow. You cannot detect, investigate, or respond to what you never see. This guide covers the log sources a tier-1 analyst must understand, how logs travel into a SIEM, how they are normalized and searched, and how baselines, alerts, and dashboards turn raw telemetry into decision-ready signals.

## Why Monitoring Matters

Monitoring answers one question continuously: **what is happening across the environment?** A tier-1 analyst uses monitoring to:

- Detect security events (failed logons, malware callbacks, data exfiltration patterns).
- Support investigations by finding the "first seen" and "last seen" of an activity.
- Measure operational health (agents down, gaps in coverage) so blind spots get fixed.

A monitoring gap is equivalent to a security control failure. If an endpoint never sends logs, an alert on that endpoint is fiction. Always ask: *"Do we have the data to see this attack if it happened right now?"*

## Log Sources and Their Value

Different log sources answer different questions. Learn what each one proves and what it misses.

### Endpoint Logs

- **Sources:** Windows Event Log (Security 4624/4625 logons, 4688 process creation, 4698 scheduled tasks, Sysmon event IDs 1/3/11/22), Linux `auditd`/`journald`, EDR telemetry, PowerShell operational logs (Event ID 4104).
- **Value:** Highest-fidelity view of what actually executed — processes, command lines, file activity, persistence. Critical for detecting malware execution, LOLBins, and credential access attempts.
- **Limit:** Only covers endpoints with the agent installed; command lines can be truncated or blocked by policy.

### Network Logs

- **Sources:** Firewall logs (allow/deny), proxy logs (HTTP/S CONNECT, domains, user agent), DNS logs, NetFlow/IPFIX, IDS/IPS alerts (Suricata, Snort).
- **Value:** Shows communication between hosts and the outside world — beaconing to a C2, DNS tunneling, data leaving via the proxy.
- **Limit:** Encrypted traffic hides content; without TLS inspection you see metadata only (IPs, domains, sizes, timing).

### Authentication Logs

- **Sources:** Active Directory domain controller Security logs (4624/4625/4768/4769/4771), VPN logs, SSO/IdP logs (Okta, Azure AD sign-ins), RADIUS.
- **Value:** The story of *who* got access and *when*. Essential for detecting brute force, password spraying, and account takeover.
- **Limit:** Successful-but-anomalous logons look identical to normal logons without baselines and correlation.

### Cloud Logs

- **Sources:** AWS CloudTrail, CloudWatch, GuardDuty findings; Azure Activity Log and Microsoft 365 audit (Exchange Online, SharePoint); Google Cloud audit logs.
- **Value:** Visibility into control-plane actions (console logins, IAM changes, new keys, storage exfiltration) that never touch on-prem sensors.
- **Limit:** Massive volume and API-only events; requires separate parsers and retention decisions (e.g., S3 buckets with lifecycle policies).

| Log source | Typical questions it answers | Priority tier |
|---|---|---|
| Endpoint | What executed? On which host? With which user? | Critical |
| Authentication | Who authenticated, from where, when, with what result? | Critical |
| Network/DNS/Proxy | What talked to what? Any known-bad destination? | High |
| Cloud/IdP | What changed in the control plane or identity provider? | High |
| Vulnerability scanner | Which systems are exposed to which weaknesses? | Medium (context) |

## Log Collection Architecture

Centralized collection follows a small number of patterns; know them well enough to draw the data flow.

- **Agents / forwarders:** A lightweight process on each host reads local logs and ships them (Winlogbeat, Auditbeat, osquery, Splunk Universal Forwarder, syslog-ng). Preferred for endpoints because it captures local event detail and encrypts in transit.
- **Syslog relay:** Network devices, Linux hosts, and many appliances push RFC 3164/5424 syslog over UDP/TCP/TLS to a collector (rsyslog, syslog-ng). Use TCP or TLS, never raw UDP, in production.
- **API/collector pulls:** Cloud providers and SaaS (M365, AWS) are polled via API by a collector service running in or near that tenant.
- **Storage tiers:** Hot (searchable, days–weeks), warm, cold/archive (object storage, months–years for compliance). Decide retention per log type before the SIEM fills up.

A reference flow:

```text
Endpoints  --agent/TLS-->  Collector pool  --load balancer-->  SIEM indexers
Network/fw --syslog/TLS--> Collector pool         |                 |
Cloud/IdP  ---API pull---> Collector service      |                 v
                                                 Parsing / normalizing / enrichment
                                                         |
                                         Search + detection engine + dashboards
```

Key architecture principles:

1. **No single point of failure:** run collectors in pairs; queue logs locally when the SIEM is down (agent disk buffering, syslog with local spool).
2. **Clock discipline:** synchronize every host to NTP. A 5-minute clock skew makes timeline correlation unreliable.
3. **Coverage beats volume:** 100% of critical sources beats 40% of everything.
4. **Tag at the edge:** attach environment, role, and asset-criticality fields at collection time so searches and dashboards can filter.

## SIEM Ingestion and Parsing

Raw logs are lines of text; a SIEM turns them into structured, searchable events.

- **Parsing:** Splitting a raw message into fields (`src_ip`, `user`, `event.code`). Regex-based parsing or vendor parsing pipelines (Logstash, Cribl, Splunk sourcetypes).
- **Normalization:** Mapping vendor-specific fields to a common schema so Windows, firewall, and cloud events can be correlated with one query language. The **Elastic Common Schema (ECS)** and OCSF are widely used open schemas; Splunk uses CIM (Common Information Model).
- **Timestamps:** Set the correct timestamp *source* and **timezone**. Events logged in UTC but parsed as local time silently break every time-based search.
- **Index/partition strategy:** Separate indexes per data class (endpoint, network, auth) improve search speed and let you tune retention per class.
- **Enrichment at ingestion (optional):** GeoIP lookup on source IPs, adding asset owner or hostname from CMDB. Cheap at ingest, hugely useful during triage.

A parsed Windows 4624 event, normalized to ECS-style fields:

```json
{
  "event":     { "code": "4624", "kind": "event", "category": "authentication", "outcome": "success" },
  "@timestamp": "2025-06-01T03:14:00.000Z",
  "user":      { "name": "svc_backup", "domain": "CORP" },
  "source":    { "ip": "10.20.30.40", "geo": { "country_iso_code": "US" } },
  "host":      { "name": "dc01.corp.local" },
  "logon":     { "type": 3, "type_name": "network" },
  "related":   { "ip": ["10.20.30.40"] }
}
```

If `event.code` is blank or `user.name` is missing for most events, parsing is broken — fix it at the pipeline, not with regexes inside every search.

## Baselining

A baseline is the *normal* profile of a metric — the thing you compare current activity against.

- **What to baseline:** logon volume and hours, data egress volume per host, DNS query rates, admin command frequency, outbound connection timing (regularity = possible beacon).
- **How to build it:** aggregate per host/user/asset over 30–90 days, sliced by hour-of-day and day-of-week. Weekends differ from weekdays; month-end differs from mid-month.
- **Use in detection:** alert on deviation from baseline rather than a fixed threshold. A service account that logs on 3×/week suddenly logging on 300×/day is far more meaningful than "100 logons" alone.
- **Keep it current:** re-baseline after major changes (new application rollout, org restructuring). Stale baselines create false positives or false negatives.

Baseline query concept (per-hour logon count by user, Elasticsearch):

```lucene
event.category:authentication AND event.outcome:success
| stats count by user.name, hour
```

Anomaly example — outbound connections from a single process to a fixed remote IP at suspiciously regular intervals:

```lucene
event.category:network AND destination.ip:*
| stats count, values(destination.ip) by process.name, source.ip
```

## Alert Design

An alert is a *use case*: a detection condition plus the metadata an analyst needs to act. Design for actionability, not volume.

- **Map to MITRE ATT&CK:** tag each use case with technique IDs (e.g., T1078 Valid Accounts, T1071.001 Web Protocols). This turns alerts into attack-story fragments and makes coverage reviewable.
- **Prefer behavior over IOCs:** "new service account logged on from a non-standard workstation" survives longer than a hash that changes with every build.
- **Suppression and deduplication:** do not alert 5,000 times for one brute force; alert once per source IP → target, with a rolling window.
- **Thresholds with time windows:** "5+ failed logons for one user within 15 minutes" beats "failed logon = true" noise.
- **Every alert carries context:** who/what/where plus links to the raw events, assigned priority, and the playbook reference.

Password-spray correlation is *pseudocode* below, not Sigma. Sigma has no `timeframe` or `count()` operator: a single rule describes the condition on one event, and correlation across events belongs to the backend (an Elastic Security threshold rule, a Splunk `stats` search, a Sentinel `summarize`). Read the block as the logic you are implementing, then write it in your platform — the valid, copyable syntax lives in `../tools/detection-rules/sigma-rules/`.

```yaml
# NOT VALID SIGMA — pseudocode for the correlation to implement in the backend
title: Failed Logons Followed by Success — Possible Password Spray
logsource:
  product: windows
  service: security
detection:
  selection_fail:
    EventID: 4625        # note: the Windows Security schema names the source field
    IpAddress: '*'       # "IpAddress", not "src_ip"; check the real schema before writing
  selection_success:
    EventID: 4624
  timeframe: 15m         # backend concept, not a Sigma key
  condition: count(selection_fail by IpAddress) > 5 and selection_success
level: medium
```

Backend forms of that same correlation, all valid syntax for their own language:

```spl
# Splunk SPL: spray from one source, then a success for any of the targeted users
index=windows (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as fails, count(eval(EventCode=4624)) as oks by IpAddress, Account
| where fails > 5 and oks > 0
```

```kusto
// Microsoft Sentinel KQL
SecurityEvent
| where EventID in (4625, 4624)
| summarize Fails = countif(EventID == 4625), Oks = countif(EventID == 4624) by IpAddress, Account
| where Fails > 5 and Oks > 0
```

Alert metrics to watch: **false positive rate**, **time-to-acknowledge**, **time-to-detect (MTTD)**, and **coverage** (ATT&CK techniques with at least one detection). If an alert has never fired or never been confirmed, tune or retire it.

## Dashboards

Dashboards turn searches into glanceable status. Tier-1 useful boards:

1. **SOC overview:** alerts by severity/status today, open cases, mean time to acknowledge.
2. **Authentication health:** failed logon spikes, logons outside business hours, new account creation.
3. **Endpoint posture:** hosts without recent heartbeat/check-in, agent versions, OS coverage.
4. **Network egress:** top talkers, blocked vs allowed, DNS queries to newly registered domains.
5. **Per-entity view:** one host's or user's full event stream during an investigation.

Dashboard query example (open high-severity alerts by technique):

```lucene
alert.severity:high AND alert.status:open
| top 10 by rule.name, threat.technique.id
```

Rules of thumb: keep fewer than a dozen well-curated panels per board; every panel must answer an operational question; add a "last updated" timestamp panel so stale data is obvious.

## Coverage: What You Can and Cannot See

Detection coverage is a property of *data* before it is a property of rules. The table below is the one to keep in mind when you wonder why a rule never fires: for each tactic, it names the source that has to be collected for the behaviour to be visible at all.

| ATT&CK tactic | What the analyst must be able to see | Sources that carry it | Blind spot when the source is missing |
|---|---|---|---|
| Initial Access | A logon made with explicit credentials; the delivery channel | Security 4648; proxy and mail-gateway logs | Delivery is invisible, so the first visible event becomes *execution* and you lose the "how did they get in" answer |
| Execution | Which process started, with which command line | 4688 **with command-line auditing enabled**, Sysmon 1 | You learn that something ran but never how it was invoked |
| Persistence | Service installs, scheduled-task creation, autostart registry writes | 4697 / System 7045, 4698, Sysmon 13 | Persistence becomes visible only when it acts, usually much later |
| Privilege Escalation | Special privileges assigned, token and process access | 4672, Sysmon 10 | Escalation is inferred from later behaviour instead of observed |
| Defense Evasion | Log clearing, AV/AMSI/ETW tampering, config changes | Security 1102, System 104, Defender 5001/5007, Sysmon 12/13 | You cannot distinguish *the attacker removed the data* from *we never had it* |
| Credential Access | Access to LSASS, Kerberos ticket requests | Sysmon 10, Security 4768/4769/4771 | Theft stays invisible until the stolen account is used somewhere else |
| Discovery | Enumeration commands and their targets | Sysmon 1, 4688 with command line, `auditd` execve | Reconnaissance becomes indistinguishable from routine administration |
| Lateral Movement | Remote service creation, remote logons, admin-share access | 7045, 4624 type 10 and 3, 5140/5145 | Movement surfaces only as a fresh alert on the destination host |
| Command and Control | Outbound connections attributed to a **process** | Sysmon 3, EDR network telemetry, proxy and DNS logs | You see traffic with no owner process, which is a lead, not a finding |
| Exfiltration | Volume per host, destination and process | Flow records (NetFlow/IPFIX), proxy logs, Sysmon 3 | Volume baselines are the most commonly missing exfiltration control |

> The gap that hurts most is rarely a missing tool; it is a collected channel that is *half* collected. `4688` without command-line auditing, Sysmon installed with a narrow configuration, or PowerShell script-block logging enabled only on some hosts all produce a source that looks present in the dashboard and answers nothing.

**Validate coverage by generating the event, not by reading the dashboard.** The procedure below is written for a lab you own; it runs the same way in production, with authorization, and it is the only way to tell "no activity" from "no data". None of these commands was executed while writing this note — there is no SIEM or event log on the machine that produced this document, so the outputs are what you should go and confirm for yourself.

```powershell
# 1. Confirm the channel exists and is switched on (Windows endpoint, elevated)
Get-WinEvent -ListLog Security, System, "Microsoft-Windows-Sysmon/Operational" |
    Select-Object LogName, IsEnabled, RecordCount, MaximumSizeInBytes

# 2. Confirm the audit subcategory that feeds 4688 is actually enabled
#    (command-line inclusion is a PolicyChange/ProcessCreation setting, not a default)
auditpol /get /subcategory:"Process Creation"

# 3. Generate one known-good event and note the exact UTC time
cmd /c whoami        # produces a process-creation event with a recognisable command line

# 4. Prove the pipeline, not just the host: search for it in the SIEM
#    (Kibana KQL example - the host must be the one from step 3)
#    process.command_line : "*whoami*" and host.name : "win-lab-01"
```

Read the result in two directions: the endpoint must show the event *and* the SIEM must show the same event with the same timestamp and a parsed `user.name` / `process.name`. If the endpoint has it and the SIEM does not, the problem is collection, not detection. If both have it but the fields are empty, the problem is parsing. Record the outcome as a dated coverage note — "4688 with command line: verified 2025-06-01" is a fact you can rely on next quarter.

## Choosing What to Collect (and What Not To)

"Collect everything" is not a strategy; it is a storage bill with a search problem attached. Decide per channel, and write the decision down so the next analyst knows what was deliberate.

| Channel | Collect? | Why |
|---|---|---|
| Security log, process creation, logons, account changes, Kerberos | Yes, full | Highest-value triage evidence per stored byte |
| Sysmon 1/3/11/13/22 at minimum | Yes, tuned by config | Turns process creation into a story with parents, paths, network and DNS |
| PowerShell 4104 script block | Yes | The only record of script content that never touched disk |
| System log (7045, 104, 1074) | Yes | Service persistence and log clearing live here |
| Defender/AV operational log | Yes | Detection *and* tampering (5001, 5007) both matter |
| Firewall allow logs on internal east–west links | Yes if volume allows | Lateral movement and C2 egress are found here |
| DNS query logs | Yes, with retention | Fastest cheap indicator of beaconing and tunnelling |
| Object-access auditing (4663) on all file servers | Usually no, by default | Enormous volume; enable per-share for a defined investigation window instead |
| Verbose/debug informational channels, print spoolers, legacy app logs | No | Cost without triage value; document the exclusion |
| Full packet capture everywhere | Only at chokepoints | PCAP is the most expensive byte you can store; keep it where the hypothesis needs it |

Three rules that keep this decision defensible:

1. **Volume is a coverage decision too.** A channel that pushes the indexer past capacity will be dropped by someone at 3 a.m. during an incident, and that is how blind spots appear. Size retention deliberately.
2. **Record the exclusions.** A documented "we do not collect object access except on demand" is a known gap; an undocumented one is a surprise during an audit.
3. **Separate "collect" from "alert".** Collecting a channel costs storage; alerting on it costs analyst attention. High-volume channels are worth *storing* long before they are worth *alerting* on — you cannot retro-hunt what you never stored.

## Worked Example: Diagnosing a Silent Detection

A rule that has never fired in 90 days is either an excellent rule in a quiet environment or a broken pipeline. Work the chain in order, and stop at the first break.

| Symptom | Most likely cause | Where to check first |
|---|---|---|
| Endpoint has the event; SIEM has nothing for that host | Agent stopped, buffering, or the host is in no collection policy | Agent service state and its log, then the collector's ingest rate for that host |
| SIEM has events from the host, but not this event code | Channel not in the collection configuration | The agent/pipeline configuration for that channel |
| Events arrive, but the fields the rule uses are empty | Parsing or normalization break (field renamed, message format changed) | Expand one raw event; compare actual field names to the names in the rule |
| Fields are populated, but the rule still does not match | Rule logic wrong for the data (case sensitivity, field type, path separators) | Re-run the rule's condition by hand as a plain search |
| Rule matches in the search bar but no alert appears | Detection engine not enabled for that rule, wrong index pattern, or a suppression filter swallowing it | Rule status, index pattern, and any active suppression/exception list |
| Alert appears but with the wrong timestamp | Timezone or timestamp-source misconfiguration | Compare `@timestamp` with the event's own `TimeCreated` field |
| Everything works, the rule is correct, nobody has done this | Genuinely quiet | Check the rule's ATT&CK technique against the environment's exposure, then decide whether to keep it |

The general principle: **a silent rule is a hypothesis about your data, not a conclusion about your adversary.** Prove the data first, then the rule, then the behaviour — in that order.

```text
Silent rule
   |-> Does the endpoint produce the event?            no -> collection problem
   |-> Does the SIEM receive it for that host?         no -> ingestion problem
   |-> Are the rule's fields populated?                no -> parsing problem
   |-> Does the raw search match the logic?            no -> rule problem
   |-> Is the rule enabled on the right index?         no -> engine problem
   V
Rule is fine: the technique is either not present or not exposed
```

## Time Discipline in Practice

Every event carries more than one timestamp, and confusing them is the most common cause of a timeline that does not add up.

| Timestamp | Meaning | Trust it for |
|---|---|---|
| Event time (`TimeCreated`, `@timestamp` after parsing) | When the host says it happened | Ordering events on one host |
| Host clock vs NTP | Whether the host's idea of now is correct | Cross-host correlation — a skewed host silently reorders your timeline |
| Ingest time (`event.ingested`, `_index_time`) | When the platform received it | Diagnosing lag and backfill, never for the story |
| Display time | The analyst's local rendering | Nothing. Convert to UTC before you write a note |

Practical consequences:

- **Always reason in UTC and state the offset when you write the timeline.** "02:14" is ambiguous; "02:14 UTC (04:14 local)" is evidence.
- **A burst of events with one ingest timestamp is a backfill, not an attack.** When agents reconnect after an outage, hundreds of old events arrive at once. Check `event.ingested` before you get excited about the spike.
- **Clock skew is a coverage gap.** If two hosts disagree by minutes, every sequence-based detection (failed logon *then* success) can fail silently on that pair. NTP is a security control, not housekeeping.
- **Missing events inside a window you expected traffic in are themselves findings.** A gap in a normally chatty channel is evidence of collection failure or of log tampering; note it either way.

## Alert Queue Health

The queue is the analyst's actual working surface, and its shape predicts whether real alerts get missed. Watch for these signals rather than waiting for them to be reported:

| Signal | What it usually means | Reasonable response |
|---|---|---|
| One rule is more than ~30 % of the queue | Threshold or exclusion is wrong | Take the rule out of the queue and fix it at the source |
| Queue depth grows faster than analysts can clear it for a week | Detection volume exceeds staffing | Prioritize aggressively and escalate the tuning backlog as a work item, not a complaint |
| Many alerts share one host, one user, or one subnet | A local condition (broken app, new deployment, scanner) | One investigation, one suppression with an expiry, not N separate closures |
| Alerts with no owner for hours | Acknowledge SLA is not being respected | Escalation path problem; fix the rotation, not the queue |
| Alerts closed as false positive with no reason text | Tuning signal being thrown away | Treat as a quality defect; the reason is the input to the next fix |
| Rules that have never fired or never confirmed | Either bad logic or the technique is not exposed | Quarterly review: fix, retire, or document why it stays |

Prioritization discipline for a full queue: work **severity × blast radius × time-sensitivity**, not arrival order. A medium-severity alert on a domain controller outranks a high-severity alert on an isolated lab subnet; an alert that is still ongoing outranks one that finished six hours ago.

## Common Mistakes & Tips

- **Mistake:** trusting alert content without validating the underlying events. *Tip:* always open the raw events; alert logic and parsers drift.
- **Mistake:** ignoring timezone/clock issues, then wondering why events are "missing" from a timeline. *Tip:* standardize on UTC ingestion and convert only at display time.
- **Mistake:** collecting everything at full verbosity and drowning in storage costs and noise. *Tip:* collect security-relevant channels fully, tune verbose non-security channels down, and record what is deliberately not collected.
- **Mistake:** treating dashboards as decoration. *Tip:* define the one question per panel and review the board in every shift handover.
- **Mistake:** fixed thresholds that never change. *Tip:* review baseline windows regularly and document why a threshold is what it is.
- **Mistake:** no test of the pipeline. *Tip:* periodically generate known events (failed logon, `whoami` execution) and confirm they arrive parsed and searchable — a "canary log" test.
- **Mistake:** treating "collect everything" as a strategy. *Tip:* decide per channel, write down the exclusions, and remember that an indexer pushed past capacity will have channels dropped during the incident, not before it.
- **Mistake:** reading a dashboard as proof of coverage. *Tip:* dashboards show what arrived; only a generated-and-found event proves the path works end to end.
- **Mistake:** reasoning about a spike without checking ingest time. *Tip:* a burst with one `event.ingested` value is a backfill after an agent outage, not an attack.
- **Mistake:** letting one noisy rule own the queue. *Tip:* measure alert share per rule; a rule at a third of the queue is a tuning defect that hides everything behind it.

## Checklist / Self-Test

- [ ] I can name the five log classes above and state one high-value question each answers.
- [ ] I can trace one endpoint event from host to SIEM index and identify where parsing happens.
- [ ] I can explain why timestamp source, timezone, and NTP discipline matter for correlation.
- [ ] I can write a Lucene-style query that counts successful logons per user per hour.
- [ ] I understand the difference between hot/warm/cold storage and why retention varies by log type.
- [ ] I can list three metrics that indicate a detection rule is unhealthy (noise or silence).
- [ ] I know which of my organization's critical assets are NOT currently sending logs to the SIEM.
- [ ] I can map one monitoring gap in my environment to the MITRE ATT&CK techniques it would hide.
- [ ] I can fill the coverage table for execution, credential access, and C2 from memory and name the source that carries each one.
- [ ] I have generated a known event and confirmed it arrived in the SIEM parsed, with the host clock within seconds of NTP.
- [ ] I can walk the silent-detection chain (endpoint → ingest → parse → rule → engine) and name the check for each step.
- [ ] I can explain the difference between event time, ingest time, and display time, and which one belongs in my notes.
- [ ] I can name the channels I deliberately do not collect, and why.

## Further Resources

- MITRE ATT&CK — technique and data-source catalog for detection coverage thinking: https://attack.mitre.org
- Elastic Common Schema (ECS) — field normalization reference: https://www.elastic.co/guide/en/ecs/current/index.html
- OCSF (Open Cybersecurity Schema Framework): https://schema.ocsf.io
- NIST SP 800-92 — Guide to Computer Security Log Management: https://csrc.nist.gov/pubs/sp/800/92/upd1/final
- Windows Event Log / Sysmon reference (Microsoft Learn, Sysinternals): https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
