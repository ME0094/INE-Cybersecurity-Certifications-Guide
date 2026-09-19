# Hunting Tradecraft (eCTHP Methodology — Phase 04)

> Companion study guide for the eCTHP (Certified Threat Hunting Professional) Blue Team methodology track. This phase is the work itself: running the hunt loop, knowing which artifacts betray which technique, pivoting across hosts, and documenting what you found well enough to defend it.

## Overview

Tradecraft is the difference between a hunter and someone with SIEM access. It has three parts:

- **A disciplined loop** — hypothesis, data readiness, query, triage, pivot, conclusion, handoff. Always the same order, always recorded.
- **Technique knowledge** — for any behaviour you hypothesise, knowing which event, artifact, or field it produces, and therefore where to look.
- **Restraint** — read-only collection, timeboxing, and stopping when a hunt becomes an incident.

Technique IDs below follow MITRE ATT&CK. MITRE renumbers, merges, and splits techniques between releases, so treat the IDs as navigational aids and confirm the current mapping on the ATT&CK site.

## The hunt loop

| Stage | What you do | Exit criterion |
| --- | --- | --- |
| 1. Hypothesis | Write subject, behaviour, data, confirmation and refutation criteria, scope, and end condition | A one-sentence hypothesis you could hand to a colleague |
| 2. Data readiness | Confirm each source in the hypothesis is healthy for the whole scope and window | A known event generated and found, per source |
| 3. Query | Write the narrowest query that returns the behaviour, not everything adjacent to it | Query runs, returns a triageable candidate set |
| 4. Triage | Classify candidates: expected, suspicious, malicious. Record the reason for each dismissal | Every candidate has a disposition |
| 5. Pivot | Follow each surviving artifact to every other place it appears — other hosts, users, times, sources | The blast radius is known, or the lead is closed |
| 6. Conclusion | State the verdict: confirmed, refuted, or inconclusive with the reason | Verdict written with the evidence behind it |
| 7. Handoff | Detection rule, telemetry gap, or incident escalation — plus journal entry | Someone else can act on the result |

Rules that keep the loop honest:

- **Timebox in advance.** When the box expires, write down where you stopped and why. An unfinished hunt with a written stopping point is still a result.
- **Never widen scope to keep a hunt alive.** If the lead is dead, close it and start the next hypothesis.
- **One question per query.** Combined queries hide their own logic and cannot be handed over.
- **Keep raw results.** Export the candidate set before you filter it; your triage reasoning is part of the evidence.

## Query patterns by platform

These are syntax references, not recipes: adapt field names to your environment and confirm flags against the version you run.

**KQL (Microsoft Sentinel / Defender)** — filter early, summarize before joining, and project only what you need.

```kql
// Off-hours PowerShell with encoded commands, grouped by host
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where NewProcessName endswith_cs "\\powershell.exe"
| where CommandLine has_any ("-enc", "-EncodedCommand", "FromBase64String")
| summarize Hits = count(), Samples = take_any(CommandLine) by Computer, Account
| order by Hits desc
```

```kql
// Cross-host pivot: hosts taking network logons and also running admin tooling
let window = 7d;
SecurityEvent
| where TimeGenerated > ago(window)
| where EventID == 4624 and LogonType == 3
| summarize NetworkLogons = count() by Computer
| join kind=inner (
    SecurityEvent
    | where TimeGenerated > ago(window)
    | where EventID == 4688
    | where NewProcessName endswith_cs "\\net.exe" or NewProcessName endswith_cs "\\nltest.exe"
    | summarize AdminTools = count() by Computer
  ) on Computer
| project Computer, NetworkLogons, AdminTools
```

In Defender XDR advanced hunting, the equivalent tables are event-specific — `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceLogonEvents`, `DeviceFileEvents` — with fields such as `Timestamp`, `DeviceName`, `AccountName`, `FileName`, `ProcessCommandLine`, `InitiatingProcessFileName`, `RemoteIP`, `RemotePort`, and `SHA256`.

**SPL (Splunk)** — use `stats` rather than `join` wherever you can; it is cheaper and easier to read later.

```
index=sysmon EventCode=1
| where match(Image, "(?i)powershell(\.exe)?$")
| stats count values(CommandLine) as commands by Computer, User, ParentImage
| sort - count
```

```
index=sysmon EventCode=3
| stats count values(Image) as processes dc(DestinationIp) as destinations by Computer
| where count > 100
| sort - count
```

Field names differ by add-on: the Sysmon add-on provides `Image`, `CommandLine`, `ParentImage`, `DestinationIp`, while the Windows add-on provides its own extraction for Security events. Confirm the extraction for your version rather than assuming a field exists.

**Velociraptor VQL** — endpoint truth, at scale. Artifacts are callable as plugins in a query.

```powershell
velociraptor.exe query "SELECT Pid, Ppid, Name, Exe, CommandLine FROM pslist() WHERE Name =~ 'powershell'"
# `OSPath` is the canonical field name for a glob() result in current releases; pre-rename
# builds expose the same value as `FullPath`. Confirm on your own build with `velociraptor vql
# list` before copying a query between versions — an unknown field name yields an empty column,
# not an error, so the mistake is silent.
velociraptor.exe query "SELECT OSPath, Size, Mtime FROM glob(globs='C:/Windows/System32/Tasks/**')"
velociraptor.exe query "SELECT * FROM Artifact.Windows.System.Pslist()"
```

Useful artifacts to know by name (list what your server actually ships before relying on one): `Windows.System.Pslist`, `Windows.Network.Netstat`, `Windows.NTFS.MFT`, `Windows.Detection.Yara.Process`, and the registry and event-log artifacts in the same namespace.

**osquery** — point-in-time state across a fleet, with SQL you already know.

```sql
SELECT pid, name, path, cmdline FROM processes WHERE name LIKE 'powershell%';
SELECT * FROM startup_items;
SELECT name, path, status, start_type FROM services;
SELECT * FROM scheduled_tasks;
SELECT * FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';
SELECT * FROM listening_ports WHERE port != 0;
SELECT * FROM hash WHERE path = 'C:\Windows\Temp\update.exe';
```

Run one-off queries with `osqueryi "<SQL>"` and confirm table and column names against the schema bundled with your version.

**Windows event logs from the shell** — two equally valid approaches.

```powershell
# Native PowerShell: filter in the log service, not after loading everything
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=(Get-Date).AddHours(-24)} |
  Where-Object { $_.Message -match 'powershell|pwsh' } |
  Select-Object TimeCreated, Id, Message -First 20
```

```powershell
# XPath query via wevtutil (renders text; useful for exporting to a file)
wevtutil qe Microsoft-Windows-Sysmon/Operational /q:"*[System[(EventID=1)]]" /c:20 /rd:true /f:text
```

Exporting a log for offline hunt and analysis is a supported operation on a running system:

```powershell
wevtutil epl Security C:\case\Security-export.evtx
```

Supporting tools worth having on hand, with current flags confirmed from their own help output: **Chainsaw** and **Hayabusa** (Sigma-based EVTX hunting and timelines — check `chainsaw hunt --help` for the exact `--sigma` and `--mapping` arguments in your release), **YARA** (`yara -r rules.yar <path>` for recursive scanning of collected files), and **autorunsc** from Sysinternals for a comprehensive autostart inventory with signatures and hashes.

## Hunting by tactic

For each tactic, the left column is what you are looking for and the right column is where it shows up. The artifacts are the pivot points — a hunt rarely ends at the first event.

### Execution

| Behaviour | Artifacts and events |
| --- | --- |
| Command-shell and scripting execution (T1059.001, T1059.003, T1059.005) | Sysmon 1 with `CommandLine`; 4688 with command-line auditing; PowerShell 4104 script blocks; `Hashes` to pivot on the binary |
| Execution from user-writable paths | Sysmon 1 where `Image` is under `\AppData\`, `\Temp\`, `\ProgramData\`, or `\Users\Public\` — and the same binary's Sysmon 11 file creation |
| System-binary proxy execution (T1218, T1218.011, T1218.005) | Sysmon 1 for `rundll32.exe`, `mshta.exe`, `regsvr32.exe`, `installutil.exe`, `certutil.exe`, `bitsadmin.exe`, with the arguments that make them suspicious |
| Deobfuscation and decoding (T1140, T1027) | `certutil -decode`, base64 arguments, long single-line command lines, mismatched `OriginalFileName` versus `Image` |
| Scheduled or service-based execution (T1053.005, T1569.002) | 4698 scheduled task created; 7045 / 4697 service installed; Sysmon 13 registry write; the child process appearing later in Sysmon 1 |
| WMI execution (T1047, T1546.003) | Sysmon 19/20/21 for WMI subscriptions; `WmiPrvSE.exe` as a parent process in Sysmon 1; `wmiprvse.exe` spawning a shell |

Corroboration on the endpoint side: Prefetch tells you a program *ran* even if logging was trimmed; Amcache and ShimCache record execution history; the USN journal shows file activity on NTFS.

### Persistence

| Behaviour | Artifacts and events |
| --- | --- |
| Registry autoruns (T1547.001) | Sysmon 13 with the target key containing `\CurrentVersion\Run`, `RunOnce`, or `Explorer\Shell Folders`; compare against a baseline of known values |
| Services (T1543.003) | 7045 (System), 4697 (Security), `HKLM\SYSTEM\CurrentControlSet\Services` writes, service binary paths outside `System32` |
| Scheduled tasks (T1053.005) | 4698, files under `C:\Windows\System32\Tasks\`, registry writes to `TaskCache`; tasks referencing user-writable binaries |
| WMI event subscription (T1546.003) | Sysmon 19/20/21; WMI repository changes under `C:\Windows\System32\wbem\Repository` |
| Startup folder and logon scripts | Sysmon 11 in the Startup folder; group policy script writes |
| Account creation for persistence (T1136) | 4720 user created, 4732/4728 privileged group membership, 4722 account enabled |
| Linux persistence | `authorized_keys` writes, cron entries, systemd units, `auditd` rules for `-w /etc/cron.d -p wa -k cron` style watches, SUID changes |

The pivot that turns a persistence hit into scope: take the persisted binary's **path and hash** and search every host, plus the account that created it, plus the logon that preceded it.

### Privilege escalation and credential access

| Behaviour | Artifacts and events |
| --- | --- |
| LSASS access (T1003.001) | Sysmon 10 with a non-security process accessing `lsass.exe`; Sysmon 8 for remote thread creation; 4656/4663 handle requests where auditing is on |
| Token manipulation (T1134) | 4672 special privileges on unexpected accounts; sudden SYSTEM-context process creation from a user session |
| UAC bypass (T1548.002) | Auto-elevating binaries invoked with unusual arguments; registry writes under `Software\Classes\ms-settings\shell\open\command` style hijack paths |
| Exploitation (T1068) | Crash followed by a privileged child process; anomalous image loads (Sysmon 7); service or driver installation |
| Domain credential theft (T1003.003) | DC-side 4662 and replication events, `ntdsutil` or volume shadow access, unusual service account logons |

Credential access hunts are noisy by nature. Anchor on the *target* (`lsass.exe`, `NTDS.dit`) and the *requestor* being unexpected, not on the syscall.

### Defence evasion

| Behaviour | Artifacts and events |
| --- | --- |
| Log clearing (T1070.001) | 1102 (Security log cleared), 104 (System log cleared) — treat any occurrence as high signal |
| Logging tampering (T1562.001) | Sysmon 4 (service state changed), Sysmon 16 (config change), service stop events, EDR agent removal |
| Timestomping (T1070.006) | Sysmon 2 for file creation time changes; mismatched `$STANDARD_INFORMATION` versus `$FILE_NAME` times in forensics |
| Masquerading (T1036) | `OriginalFileName` or `Product` not matching the executable name; signed binaries in unusual directories |
| Process injection and hollowing (T1055, T1055.012) | Sysmon 8, Sysmon 10, Sysmon 7 with unsigned modules; process-tampering events (confirm the event ID for your Sysmon build with `sysmon64.exe -s`) |
| Indicator removal (T1070.004) | Sysmon 23 (file delete archived) when the archive is configured; mass deletion patterns in a short window |

### Discovery, lateral movement, and command and control

| Behaviour | Artifacts and events |
| --- | --- |
| Host and account discovery (T1082, T1087, T1018, T1057) | Sysmon 1 for `whoami`, `net user`, `net group`, `systeminfo`, `ipconfig`, `tasklist`, `nltest`, `quser` — especially clustered in one session |
| Remote service execution (T1569.002, T1021.002) | 7045 on the target, `PSEXESVC` style service names, 4624 LogonType 3, 5140/5145 share access |
| RDP and SSH movement (T1021.001, T1021.004) | 4624 LogonType 10 with a source address; Terminal Services operational logs; SSH authentication and `authorized_keys` activity on Linux |
| Valid-account abuse (T1078) | Successful logons with no preceding failure, from new source addresses or at unusual hours; 4648 explicit-credential logons |
| C2 over web protocols (T1071.001, T1090, T1572) | Sysmon 3 and `conn.log` showing regular intervals, small symmetric byte counts, consistent destination; proxy logs with unusual user agents; `ssl.log` SNI and fingerprints |
| C2 over DNS (T1071.004) | Zeek `dns.log` with long, high-entropy labels, high query volume from one host, or consistent query sizes; Sysmon 22 per-process DNS |
| Named pipes and tool transfer (T1105) | Sysmon 17/18 pipe names associated with known frameworks; inbound transfers visible in `files.log` or proxy logs |

### Exfiltration and impact

| Behaviour | Artifacts and events |
| --- | --- |
| Exfiltration over C2 (T1041) | Sustained outbound volume from one host in `conn.log`; large POST bodies in proxy or `http.log`; asymmetry between `orig_bytes` and `resp_bytes` |
| Exfiltration to cloud storage (T1567.002) | Browsing or API traffic to file-sharing and storage domains from servers that never used them; cloud audit events for uploads and link sharing |
| Alternative channels (T1048) | Unusual protocols on unusual ports; DNS or ICMP volume anomalies in flow data |
| Staging before exfiltration (T1074) | Archive utilities (`rar`, `7z`, `tar`) in Sysmon 1; large file creation (Sysmon 11) in temp directories |
| Impact and destruction (T1486, T1490) | Mass file writes and renames in a short window; `vssadmin delete shadows` style commands in Sysmon 1; backup deletion; service stops across many hosts |

## Hunting in memory and on disk

The two views answer different questions. Disk artifacts tell you what **persisted**; memory tells you what was **running**.

**On disk (or in collected artifacts):**

- Prefetch, Amcache, and ShimCache for execution history — cheap and surprisingly durable.
- MFT and USN journal for file creation, deletion, and renaming, including files that no longer exist.
- Registry hives for autoruns, services, task configuration, and USB history.
- Event logs exported with `wevtutil epl`, then searched offline with Sigmaless queries or a hunting tool.
- Hashes for every collected binary, so findings transfer between hosts and to intelligence.

**In memory** (Volatility 3 syntax; acquire a full memory image with a documented tool before you touch disk):

```bash
vol -f memory.raw windows.info          # image profile and basic facts
vol -f memory.raw windows.pslist        # processes as the OS lists them
vol -f memory.raw windows.psscan        # processes found by scanning — catches hidden or unlinked ones
vol -f memory.raw windows.pstree        # parent-child relationships
vol -f memory.raw windows.cmdline --pid 4242
vol -f memory.raw windows.netscan       # connections, including closed ones
vol -f memory.raw windows.malfind --pid 4242   # memory regions with executable, non-image-backed content
vol -f memory.raw windows.dlllist --pid 4242
vol -f memory.raw windows.handles --pid 4242
```

Compare `pslist` with `psscan`: a process present in one and not the other is a lead, not a conclusion. The same caution applies to `netscan` (includes stale connections) and to `malfind` (flags legitimate JIT and packed code as well as injected code). Corroborate before you write it up.

**Live triage** on a host you are authorised to inspect: `Get-CimInstance Win32_Process` for process detail, autorunsc for autostarts, osquery for point-in-time state, and Velociraptor for broad collection. Prefer tools that copy artifacts out over tools that modify the host.

## Correlating across hosts

Single-host hunting finds infections. Cross-host correlation finds campaigns. Pivot on **entities**, not on feelings:

| Entity | Where to look next |
| --- | --- |
| File hash | Every endpoint's process and file telemetry for the same binary |
| File path or filename | Network shares, SMB logs, and cloud storage access |
| Account or SID | Authentication events on every domain controller and identity provider |
| Source address | `conn.log`, proxy, VPN, and cloud audit logs |
| Destination address or domain | All hosts that ever contacted it, and the DNS queries that resolved it |
| Parent-child process pair | Other hosts showing the same lineage |
| Named pipe, mutex, or service name | Endpoint telemetry on every host, and framework signatures |
| Scheduled task name or registry key | The same artefact elsewhere — attackers reuse their own naming |

Practical correlation patterns:

- **Union then summarize.** Combine sources into one result set with a common schema, then `summarize` or `stats` by the shared field. This is almost always cheaper and clearer than a join.
- **Join when you must.** KQL `join kind=inner (...) on Computer` and SPL `| join type=inner` both work, but a large join on high-volume event tables will time out before it returns an answer. Reduce both sides first.
- **Look for the second host.** If a technique appears on exactly one host, ask what makes that host special — and check whether the *precursor* behaviour appears on others.
- **Anchor on time when entities are weak.** Clock discipline matters: everything in UTC, and be suspicious of hosts whose clock drifts.

## Timeline analysis for hunters

A hunt timeline is narrower than a forensic supertimeline: it covers the entities in scope and the window of the hypothesis, and it exists to show sequence and causality.

- **Pick an anchor.** A known event — the alert that started the hunt, a suspicious logon, a file creation — and place everything else relative to it.
- **Normalize to UTC** before you merge anything.
- **Merge the smallest useful set of sources**: process creation, network connections, authentication, and file writes answer most sequence questions.
- **Sort, then read for cause.** "Process A created B; B connected to C; C's address appears in D's logon" is a story. A sorted dump is not.
- **Mark provenance.** Every row keeps its source and its platform-specific identifiers, so another analyst can re-derive it.

In the SIEM, this is typically `sort by TimeGenerated asc` over a unioned projection in KQL, or `| sort + _time` over merged results in SPL. For disk-side timelines, plaso (covered in the eCDFP module) remains the tool of choice.

## Evidence and light chain of custody

A hunt is not a forensic examination, but its output may become evidence in an incident — so treat collection as if it will be reviewed.

- **Read-only.** Copy artifacts; never open, run, or delete attacker files. Do not "clean up" during a hunt.
- **Hash what you collect.** `Get-FileHash -Algorithm SHA256 <path>` on Windows, `sha256sum <file>` on Linux, and record the hash with the artifact's path and collection time.
- **Export logs properly.** On a running system, `wevtutil epl` for event logs is preferable to copying the `.evtx` file, and memory acquisition is always a separate, documented step.
- **Record the query.** Platform, query text, time range, and run time. Without it, the finding is unrepeatable.
- **Keep the light custody record.**

| Field | Example |
| --- | --- |
| Hunt ID | H-2026-014 |
| Artifact | `C:\Windows\System32\Tasks\Updater` |
| Collected by / at (UTC) | A. Analyst / 2026-09-18 14:22 |
| Method | Read-only copy to case share |
| SHA-256 | recorded in the case manifest |
| Storage | Case share, restricted access |
| Handed to | IR at 14:40 UTC (incident INC-2026-081) |

- **Respect privacy and scope.** Hunting touches user data. Collect what the hypothesis needs, store it in the authorised location, and do not widen the window "just in case".
- **Coordinates with IR, not around it.** When a hunt confirms live malicious activity, escalate with your queries, result sets, hashes, and timeline — then let IR run the response.

> No command in this file was executed while writing it. This repository has no SIEM, no endpoint telemetry, and no memory images, so every query is a syntax reference to be adapted and run in your own authorised range.

## Common Mistakes & Tips

- **Querying before proving the data.** Generate the behaviour in the lab first; it tells you both that the source works and what the event actually looks like.
- **Treating a lead as a conclusion.** `malfind` output, one registry key, or one unusual logon is a lead. Two independent corroborating sources make it a finding.
- **Filtering too early.** Aggressive filters feel efficient and hide the pattern you were looking for. Start broad, narrow deliberately, and record what you excluded.
- **Pivoting on one entity only.** The hash matters, but so do the path, the parent process, the account, and the destination.
- **Ignoring the "boring" hosts.** An attack path often runs through a workstation nobody watches.
- **Hunting without a baseline.** Whatever your environment does all day is not an anomaly, even when it looks alarming.
- **Widening scope to keep a dead lead alive.** Close it, journal it, move on.
- **Tip:** for each tactic, ask "what would this look like if the attacker did it *lazily*?" — the simplest implementation usually leaves the clearest artifact.
- **Tip:** when a hunt stalls, switch evidence class: if endpoint data is exhausted, go to network, then identity, then cloud.

## Checklist / Self-Test

- [ ] Can I list the hunt loop stages and the exit criterion for each?
- [ ] Can I write a KQL query and an SPL query that produce a triageable candidate set without returning the whole environment?
- [ ] Can I run a VQL query in Velociraptor and an osquery query for the same endpoint fact?
- [ ] For execution, persistence, lateral movement, and C2, can I name three artifacts or events that would reveal each?
- [ ] Can I explain what `pslist` versus `psscan`, and `malfind` alone, do and do not prove?
- [ ] Can I pivot from a file hash, an account, and an IP to every other place each appears in my data?
- [ ] Can I build a UTC timeline from at least three sources and narrate the sequence?
- [ ] Can I hash, store, and hand over a collected artifact with a custody record?
- [ ] Do I know the exact point at which I stop hunting and escalate to incident response?

> **Verification:** executed on **2026-09-19** against **Volatility 3 Framework 2.28.2** and
> **Velociraptor 0.77.2** (Ubuntu 24.04 WSL) and **PowerShell 7.6.6** (Windows 11). All nine
> plugins named in "Hunting in memory and on disk" exist in the Volatility build —
> `windows.info`, `windows.pslist`, `windows.psscan`, `windows.pstree`, `windows.cmdline`,
> `windows.netscan`, `windows.malfind`, `windows.dlllist`, `windows.handles` — though no memory
> image was available to run them against. The `glob()` query of the VQL block returned rows for
> `OSPath`, and a query selecting `FullPath` returned the same values, so on this build the rename
> is a version cut rather than a live defect; `velociraptor vql list` exists as the note says.
> `Get-FileHash -Algorithm SHA256` printed algorithm, hash and path as the custody section
> describes. **Not executed:** the KQL, SPL, osquery and `wevtutil` examples — no SIEM, no osquery
> and no event-log export exists here — and the memory image itself.

## Further Resources

- **MITRE ATT&CK** (technique details, procedure examples, and detection notes) — https://attack.mitre.org/
- **ATT&CK Navigator** (coverage layers for the techniques you have exercised) — https://mitre-attack.github.io/attack-navigator/
- **MITRE Cyber Analytics Repository (CAR)** — https://car.mitre.org/
- **Sysmon** (event IDs and configuration schema) — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- **Zeek documentation** (logs and fields for network hunting) — https://docs.zeek.org/
- **Velociraptor documentation** (VQL and artifacts) — https://docs.velociraptor.app/
- **osquery documentation** (schema and tables) — https://osquery.readthedocs.io/
- **Volatility 3** (memory analysis plugins) — https://volatility3.readthedocs.io/
- **NIST SP 800-61 Rev. 2**, *Computer Security Incident Handling Guide* (when a hunt becomes an incident) — https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- **Official eCTHP product page** (authoritative syllabus and logistics) — https://ine.com/security/certifications/ecthp-certification
