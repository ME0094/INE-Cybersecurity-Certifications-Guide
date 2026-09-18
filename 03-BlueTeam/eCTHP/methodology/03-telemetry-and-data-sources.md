# Telemetry and Data Sources (eCTHP Methodology — Phase 03)

> Companion study guide for the eCTHP (Certified Threat Hunting Professional) Blue Team methodology track. This phase is about the raw material of every hunt: what each source records, which question it can answer, how to tell whether it is healthy, and what to do when the data you need does not exist.

## Overview

Hunting is a data problem before it is a query problem. The most common reason a hunt ends inconclusive is not a bad hypothesis — it is that the telemetry needed to test it was never collected, was not retained long enough, or silently stopped flowing weeks ago.

Three ideas drive this phase:

- **Question first, source second.** Decide what you need to see, then check which source can show it. Starting from a dashboard is how hunts become unfocused.
- **A source is only real if you have proven it.** "Sysmon is deployed" is a claim. "I generated this event at 14:02 UTC and found it in the platform" is evidence.
- **A gap is a finding.** When the data does not exist, that is a deliverable of the hunt, not a failure of it.

## Endpoint telemetry

### Sysmon

Sysmon is the highest-value single source on Windows: it records process creation with command lines and hashes, network connections, image loads, registry writes, and file creation — far beyond the default Security log. Its weakness is that **the configuration decides everything**: a default install with a minimal config sees almost nothing useful.

```powershell
# Install with a configuration file (a curated community config is a reasonable start)
sysmon64.exe -accepteula -i sysmonconfig.xml

# Update the configuration later without reinstalling
sysmon64.exe -c sysmonconfig.xml

# Print the configuration schema for the installed version — the authoritative list of
# event IDs and fields this build can emit
sysmon64.exe -s
```

Event IDs you will use constantly:

| ID | Event | What it gives a hunter |
| --- | --- | --- |
| 1 | Process Create | Image, CommandLine, ParentImage, ParentCommandLine, User, Hashes, OriginalFileName, IntegrityLevel — the backbone of most hunts |
| 2 | File creation time changed | Timestomping (T1070.006) |
| 3 | Network connection detected | Per-process outbound/inbound connections: Image, SourceIp, DestinationIp, DestinationPort |
| 4 | Sysmon service state changed | Someone stopped or reconfigured Sysmon |
| 5 | Process terminated | Process lifetime; pairs with ID 1 to spot short-lived processes |
| 6 | Driver loaded | Suspicious or unsigned kernel drivers |
| 7 | Image loaded | DLLs loaded into a process, including unsigned ones |
| 8 | CreateRemoteThread | Classic injection and process-injection frameworks |
| 9 | RawAccessRead | Direct disk access, e.g. raw volume readers |
| 10 | Process accessed | LSASS access and credential dumping (watch GrantedAccess and the target image) |
| 11 | File created | Dropped files, staged payloads, file writes in unusual paths |
| 12 | Registry object added or deleted | Persistence keys appearing or disappearing |
| 13 | Registry value set | The actual autorun value being written — the persistence payload |
| 14 | Registry key and value rename | Renaming to hide from baselines |
| 15 | File create stream hash | Alternate data streams |
| 16 | Sysmon config change | Detection evasion by changing logging |
| 17 | Pipe created | Named pipes used by C2 frameworks and lateral tooling |
| 18 | Pipe connected | Which process connected to which pipe |
| 19 | WMI filter registered | WMI persistence |
| 20 | WMI consumer registered | WMI persistence |
| 21 | WMI consumer-to-filter binding | WMI persistence, the piece that makes it run |
| 22 | DNS query | Query name and the process that asked — a workhorse for C2 and tunnelling hunts |
| 23 | File delete (archived) | Moved to the Sysmon archive instead of vanishing (if archive directory is configured) |

Newer Sysmon releases continue past ID 23 — clipboard change, process tampering, and file delete detection among them. Run `sysmon64.exe -s` against the build you deploy and enable what your hunts need; do not assume a community configuration turns on everything.

Hunting notes:

- **Command lines are the point.** A configuration that logs process creation without `CommandLine` removes most of the value.
- **Parent-child relationships are the point.** `ParentImage` plus `CommandLine` turns a process list into a behavioural story.
- **Hashes are the pivot.** They let you search the same binary across every host, and compare against intelligence.

### Windows Event Log

The Security log complements Sysmon with authentication, account, and audit events — but many are off by default. Enable the audit subcategories your hypotheses need:

```powershell
# Check current audit policy, then enable the subcategories you need
auditpol /get /category:*
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

Command-line capture in event 4688 requires a separate policy setting, stored under:

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
  ProcessCreationIncludeCmdLine_Enabled = 1   (DWORD)
```

PowerShell script block logging (event 4104) is worth as much as Sysmon for script-based attacks, and it is likewise a policy setting:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
  EnableScriptBlockLogging = 1   (DWORD)
```

High-value Windows events:

| Event | Log | Meaning |
| --- | --- | --- |
| 4624 | Security | Successful logon; LogonType 2 (interactive), 3 (network), 10 (RDP) matter most |
| 4625 | Security | Failed logon — brute force, spraying, or a misconfigured service account |
| 4634 | Security | Logoff |
| 4648 | Security | Logon using explicit credentials — a classic lateral-movement artifact |
| 4672 | Security | Special privileges assigned to a new logon (admin-equivalent session) |
| 4688 | Security | Process creation, with command line only if the policy above is enabled |
| 4689 | Security | Process exit |
| 4697 | Security | Service installed |
| 4698 / 4699 / 4700 / 4702 | Security | Scheduled task created / deleted / enabled / updated (requires object-access auditing) |
| 4720 / 4722 / 4724 / 4726 | Security | User account created / enabled / password reset / deleted |
| 4728 / 4732 | Security | Account added to a global / local privileged group |
| 4768 / 4769 / 4771 | Security | Kerberos TGT requested / service ticket requested / pre-authentication failed (domain controllers) |
| 4776 | Security | NTLM credential validation |
| 4657 | Security | Registry value modified (requires registry auditing) |
| 4663 | Security | Object access attempt (requires a SACL on the object) |
| 5140 / 5145 | Security | Network share accessed / detailed file share access |
| 5156 / 5157 | Security | Windows Filtering Platform allowed / blocked a connection |
| 1102 | Security | Audit log cleared — high-signal defence evasion |
| 104 | System | System log cleared |
| 6416 | Security | A new external device was recognized (needs PnP audit policy) — USB hunts |
| 7045 | System | Service installed (the System-log twin of 4697) |

Default-deny reality check: on a stock system you will see 4624, 4625, 4688 (without command lines), and little else. Most of the table above requires an explicit audit policy or SACL. Enable it in the lab first, then measure the volume it costs you.

### Linux: auditd and friends

On Linux the equivalent backbone is **auditd**, plus journald, shell history, and file permissions.

```bash
# Watch key identity and persistence files for writes and attribute changes
sudo auditctl -w /etc/passwd -p wa -k identity
sudo auditctl -w /etc/shadow -p wa -k identity
sudo auditctl -w /etc/ssh/sshd_config -p wa -k ssh_config

# Verify the rules are loaded
sudo auditctl -l

# Persist rules across reboots by writing them to a file in the rules directory
# (/etc/audit/rules.d/*.rules) and reloading
sudo augenrules --load
```

Searching what auditd recorded:

```bash
# Everything tagged with a key, interpreted into readable form
sudo ausearch -k identity -i

# Executed programs today, interpreted (execve records with the calling user and command)
sudo ausearch -m EXECVE -ts today -i

# Summary views: which executables ran, counts by user and program
sudo aureport -x
sudo aureport --summary
```

Also worth collecting: `journalctl -u ssh --since "24 hours ago"` for service context, `/var/log/auth.log` on Debian-family systems, cron and systemd timer definitions, `authorized_keys` files, SUID binaries, and `/home/*/.*_history`. Shell history is attacker-editable and must never be treated as authoritative — corroborate it with auditd or process accounting.

### EDR

An EDR adds process lineage, in-memory detections, and live response collection. Two hunting caveats:

- **It reduces as well as enriches.** Many products store their own normalized, sampled view of an event. If the raw event never reached your SIEM, you cannot re-query it with a different hypothesis later.
- **Its telemetry is not yours to configure freely.** Know what is retained, for how long, and whether you can query it programmatically before you build a hunt around it.

Prefer keeping raw endpoint events (Sysmon or the OS log) in a queryable store as well as the EDR's alerts. Hunting needs the full event, not the verdict.

## Network telemetry

### Zeek

Zeek turns packets into structured, queryable logs. It answers questions that endpoint data cannot: what left the network, what a protocol actually looked like, and which hosts never had an agent.

| Log | Question it answers | Fields to know |
| --- | --- | --- |
| `conn.log` | Who talked to whom, how long, how much data? | `ts`, `uid`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state` |
| `dns.log` | What did hosts resolve, and what came back? | `id.orig_h`, `query`, `qtype_name`, `rcode_name`, `answers` |
| `http.log` | What HTTP requests and user agents crossed the wire? | `host`, `uri`, `method`, `user_agent`, `status_code`, `resp_mime_types`, `orig_bytes` |
| `ssl.log` | TLS sessions: SNI, certificate, fingerprints | `server_name`, `ja3`, `ja3s`, `version`, `cipher`, `subject`, `issuer` |
| `files.log` | File transfers observed on the wire | `source`, `mime_type`, `filename`, `md5`, `sha1`, `sha256` |
| `notice.log` | Zeek's own policy alerts | `note`, `msg`, `src`, `dst` |
| `smb_mapping.log`, `smb_files.log`, `ntlm.log` | Lateral movement over SMB and NTLM authentication | shares, filenames, usernames, hostnames |
| `kerberos.log` | Kerberos authentication attempts and service names | `client`, `service`, `success`, `error_msg` |

Typical use:

```bash
# Replay a capture into logs (only on captures you are authorised to analyse)
zeek -C -r capture.pcap

# Pull just the fields you need out of a log
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p proto service duration orig_bytes resp_bytes

# What did this host talk to?
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service | grep 10.0.4.17

# DNS activity, one line per query
cat dns.log | zeek-cut id.orig_h query qtype_name rcode_name answers
```

For beaconing, sort `conn.log` by time and look for **repeated (origin, destination, port) tuples at near-constant intervals with small, similar byte counts**. For tunnelling, look at DNS query length, label count, and answer patterns in `dns.log`. Confirm which fields your Zeek version emits before relying on them: fingerprint fields such as `ja3`/`ja3s` are present in modern Zeek's `ssl.log`, while newer fingerprint schemes need extra packages.

### Flow data (NetFlow / IPFIX)

Flows are the cheap, long-retention alternative to full packets: no payload, but months of "who talked to whom". They are ideal for scope questions ("did any other host contact this address?") and useless for payload questions.

```bash
# Top talkers by bytes from a flow capture file (nfdump format)
nfdump -r nfcapd.202609180000 -s ip/bytes -n 20
```

Flow visibility depends on where you collect it. External interfaces give you egress hunts; internal collection gives you lateral-movement hunts. Aggregation and sampling settings decide whether you can see short, low-volume C2 at all — check them against your hypothesis before concluding "not present".

### Proxy and DNS

- **Forward proxy logs** show the URL, method, user, user agent, bytes sent, and response code for web traffic that went through the proxy. This is where you catch exfiltration over HTTP POST and downloads that never touched the endpoint's disk.
- **DNS logs** (resolver or Zeek) show which host asked for which name. Encrypted DNS and hardcoded resolvers on endpoints create blind spots — know how much of your estate bypasses your resolver.
- Neither source sees encrypted traffic contents. They give you metadata: destinations, volumes, timings, and certificate names.

## Identity and cloud telemetry

Authentication is where most intrusions become visible, and cloud control planes are where they become expensive.

| Source | What it records | Fields and events to watch |
| --- | --- | --- |
| Windows Security log (DCs) | Kerberos and NTLM authentication | 4768, 4769, 4771, 4776; account names, source workstation, encryption type |
| Microsoft Entra ID sign-in logs | Cloud identity authentication | `UserPrincipalName`, `IPAddress`, `ResultType`, `AppDisplayName`, `ConditionalAccessStatus`, `Location` |
| Microsoft 365 unified audit log | Mailbox, file, and admin activity | `Operation`, `Workload`, `UserId`, `ClientIP`, `ObjectId` |
| AWS CloudTrail | AWS API activity | `eventName`, `userIdentity`, `sourceIPAddress`, `requestParameters`, `errorCode`, `userAgent` |
| Other cloud audit logs | Provider control-plane actions | Console logins, key creation, role or policy changes, storage access |

Hunt in identity data for: impossible travel and unusual source addresses, sign-ins from unfamiliar user agents or legacy protocols, privilege grants outside a change window, new access keys or service principals, mailbox rule creation, and mass file sharing. In cloud control planes, look for enumeration, policy modification, and log-tampering API calls — the same behaviours as on-premises, with different field names.

## Matching questions to sources

Use a mapping like this when you write a hypothesis, so the data column is filled in before the query column:

| Question | Primary source | Supporting source |
| --- | --- | --- |
| What process ran, with which arguments? | Sysmon 1 / 4688 | EDR process tree, Prefetch, Amcache |
| What did a process connect to? | Sysmon 3 | Zeek `conn.log`, firewall or flow data |
| Was a file dropped or written? | Sysmon 11 | MFT and USN journal, EDR file events |
| Did persistence get configured? | Sysmon 13 (registry), 4698 | Service install events, TaskCache, autoruns |
| Was a credential accessed or abused? | Sysmon 10, 4656/4663 | 4624/4648, DC authentication events |
| Where did authentication come from? | 4624, 4768/4769 | VPN and identity provider logs |
| What left the network, and how much? | Zeek `conn.log` | Proxy logs, flow data, `files.log` |
| What name was resolved, by which host? | Zeek `dns.log` | Resolver logs, Sysmon 22 |
| Who changed cloud configuration? | CloudTrail / audit logs | Identity provider sign-in logs |

## Data quality, retention, and normalization

Telemetry you cannot trust is worse than no telemetry, because it produces confident false negatives.

- **Time.** Everything must be synchronized (NTP) and stored in UTC. One host with a skewed clock ruins cross-host correlation, and the error is invisible until you compare sources.
- **Normalization.** Field names differ per platform: Elastic Common Schema (`process.command_line`, `source.ip`, `destination.port`, `event.code`, `dns.question.name`, `user.name`) versus raw vendor names versus OCSF. Normalize at ingest, or write your queries twice and get one of them wrong.
- **Retention.** Decide per source, and know the number. Endpoint events are high volume and often kept for weeks; flows and identity logs are smaller and often kept for months. A hypothesis whose window exceeds your retention cannot be tested — re-scope it or say so.
- **Sampling and aggregation.** Flow sampling, Sysmon config trimming, and EDR-side filtering all drop events. Document what is dropped, and prefer dropping at the query layer over dropping at the collection layer.
- **Agent and pipeline health.** Ingestion gaps are normal: agents update, certificates expire, forwarders buffer and drop. Track ingest volume per source per day so a silent source is visible.

A health check you can run before every hunt:

```powershell
# 1. Generate one known event on a host in scope
New-Item -Path "$env:TEMP\hunt-healthcheck.txt" -ItemType File -Force

# 2. Search for it in the platform, narrowing to the last 30 minutes
```

```kql
// KQL (Sentinel-style Event table) — expect at least one row; zero rows means the pipeline is broken, not that the event is absent
Event
| where TimeGenerated > ago(30m)
| where RenderedDescription has "hunt-healthcheck"
| project TimeGenerated, Computer, RenderedDescription
```

```
# SPL (Splunk) — same idea, grouped by sourcetype to show which pipeline delivered it
index=* "hunt-healthcheck" earliest=-30m
| stats count by host, sourcetype
```

Run the equivalent check for **every** source in the hypothesis before you conclude anything from an empty result. This single habit prevents the most expensive class of hunting error.

## When the data does not exist

Sooner or later — usually during a promising hunt — you will need an event nobody collects. Handle it as a first-class outcome:

1. **Stop and name the gap precisely.** Not "we lack visibility into lateral movement" but "Sysmon is deployed on servers only, not workstations; workstations have no 4688 command-line auditing; flow data is sampled 1:1000 on the internal segment."
2. **Quantify it.** Which fraction of assets, which time period, and which techniques are affected. This is what turns a complaint into a funded request.
3. **Look for compensating sources.** A missing endpoint event is sometimes visible in network or identity data — an SMB write may appear in `smb_files.log`, a logon in the DC's Kerberos events.
4. **Hunt around the gap.** If you cannot see the technique, hunt the technique's consequences: the file it drops, the service it creates, the connection it makes.
5. **Propose the smallest collection change** that closes it — one Sysmon configuration block, one audit subcategory, one log source enabled — with its expected volume and cost.
6. **Validate after the change.** Re-run the health check, then re-run the original hunt. Do not mark a gap closed until the same query returns data.

Closing gaps is slow, unglamorous, and the single most durable thing a hunting programme does.

> Example validation: every command and query in this file is a syntax reference. None of them was executed here — this repository has no SIEM, no endpoint telemetry, and no logs. Run the health check in your own range before trusting any hunt result.

## Common Mistakes & Tips

- **Hunting on an unvalidated source.** Generate a known event and find it first. Otherwise "no results" is an unknown, not an answer.
- **Assuming default logging is enough.** Stock Windows gives you 4688 without command lines and almost none of the registry, service, or handle events. Configure deliberately.
- **Forgetting time zones.** Store UTC, display local. Mixing them creates phantom sequences.
- **Treating the EDR console as your data lake.** If you cannot re-query the raw event with a new hypothesis, you do not own the data.
- **Ignoring ingest gaps.** A source that stopped three weeks ago looks exactly like an environment with no activity.
- **Chasing payload you cannot see.** Most traffic is encrypted. Hunt metadata: destinations, timing, volume, certificate names, and process lineage.
- **Letting retention expire mid-hunt.** Check the window before you write the hypothesis, not after the query returns nothing.
- **Tip:** keep a one-page inventory of sources, fields, owners, and retention — it saves days over a year of hunting.
- **Tip:** when a hunt ends "unknown", the deliverable is the gap description, not an apology.

## Checklist / Self-Test

- [ ] Can I state the Sysmon event IDs for process creation, network connection, image load, registry value set, file creation, DNS query, and process access?
- [ ] Do I know which audit policy and registry settings are required for 4688 command lines and PowerShell script block logging?
- [ ] Can I write an auditd watch rule, load it, and search for it with `ausearch`?
- [ ] Can I name the Zeek logs for connections, DNS, HTTP, TLS, and file transfers, and one field from each?
- [ ] Can I explain what flow data can and cannot answer compared with full packet capture or Zeek logs?
- [ ] Can I list the identity and cloud sources available in my environment and one hunting question for each?
- [ ] Can I describe my retention per source, and pick a hypothesis whose window fits inside it?
- [ ] Can I run a telemetry health check that proves a source is working before I trust an empty result?
- [ ] Can I write a precise, quantified telemetry gap statement and the smallest collection change that closes it?

## Further Resources

- **Sysmon** (documentation, configuration schema, and event IDs) — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- **MITRE ATT&CK** (data source and detection mappings; naming has changed across versions, check the current site) — https://attack.mitre.org/
- **Zeek documentation** (log formats and field reference) — https://docs.zeek.org/
- **osquery documentation** (SQL over endpoint state) — https://osquery.readthedocs.io/
- **auditd / Linux Audit documentation** — https://github.com/linux-audit/audit-documentation/wiki
- **Elastic Common Schema (ECS)** — https://www.elastic.co/guide/en/ecs/current/index.html
- **Open Cybersecurity Schema Framework (OCSF)** — https://ocsf.io/
- **NIST SP 800-61 Rev. 2**, *Computer Security Incident Handling Guide* (evidence and logging expectations) — https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- **Official eCTHP product page** (authoritative syllabus and logistics) — https://ine.com/security/certifications/ecthp-certification
