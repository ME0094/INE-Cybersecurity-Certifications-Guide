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

Pseudo-detection-rule for a password-spray pattern (Sigma-style logic):

```yaml
title: Suspicious Failed Logons Followed by Success — Possible Password Spray
logsource:
  product: windows
  service: security
detection:
  selection_fail:
    EventID: 4625
  selection_success:
    EventID: 4624
  timeframe: 15m
  condition: selection_fail | count() by src_ip > 5 and selection_success by same user
level: medium
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

## Common Mistakes & Tips

- **Mistake:** trusting alert content without validating the underlying events. *Tip:* always open the raw events; alert logic and parsers drift.
- **Mistake:** ignoring timezone/clock issues, then wondering why events are "missing" from a timeline. *Tip:* standardize on UTC ingestion and convert only at display time.
- **Mistake:** collecting everything at full verbosity and drowning in storage costs and noise. *Tip:* collect security-relevant channels fully, tune verbose non-security channels down, and record what is deliberately not collected.
- **Mistake:** treating dashboards as decoration. *Tip:* define the one question per panel and review the board in every shift handover.
- **Mistake:** fixed thresholds that never change. *Tip:* review baseline windows regularly and document why a threshold is what it is.
- **Mistake:** no test of the pipeline. *Tip:* periodically generate known events (failed logon, `whoami` execution) and confirm they arrive parsed and searchable — a "canary log" test.

## Checklist / Self-Test

- [ ] I can name the five log classes above and state one high-value question each answers.
- [ ] I can trace one endpoint event from host to SIEM index and identify where parsing happens.
- [ ] I can explain why timestamp source, timezone, and NTP discipline matter for correlation.
- [ ] I can write a Lucene-style query that counts successful logons per user per hour.
- [ ] I understand the difference between hot/warm/cold storage and why retention varies by log type.
- [ ] I can list three metrics that indicate a detection rule is unhealthy (noise or silence).
- [ ] I know which of my organization's critical assets are NOT currently sending logs to the SIEM.
- [ ] I can map one monitoring gap in my environment to the MITRE ATT&CK techniques it would hide.

## Further Resources

- MITRE ATT&CK — technique and data-source catalog for detection coverage thinking: https://attack.mitre.org
- Elastic Common Schema (ECS) — field normalization reference: https://www.elastic.co/guide/en/ecs/current/index.html
- OCSF (Open Cybersecurity Schema Framework): https://schema.ocsf.io
- NIST SP 800-92 — Guide to Computer Security Log Management: https://csrc.nist.gov/pubs/sp/800/92/upd1/final
- Windows Event Log / Sysmon reference (Microsoft Learn, Sysinternals): https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
