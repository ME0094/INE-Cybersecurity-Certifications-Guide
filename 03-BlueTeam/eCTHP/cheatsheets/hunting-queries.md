# Hunting Queries — Quick Reference

> eCTHP · Cheatsheet — INE Cybersecurity Certifications Study Guide
>
> Compact query and command reference organised by **hunting question**, covering KQL, SPL, EQL, VQL, osquery SQL, Zeek, `auditd`, and the EVTX triage tools. Run everything against telemetry from systems you own or are authorized to monitor. `HOST` = a host name, `WIN` = a Windows endpoint, `DC` = a domain controller, `SRC`/`DST` = source/destination address.

**Conventions used below**

- **Field names are environment-specific.** `process.name`, `Account_Name`, and `event_data.Image` all describe "the process" in different backends. Confirm against a real event before trusting a query copied from anywhere — including this sheet.
- **Every threshold is a starting point, not a truth.** `count > 20`, `jitter < 5`, `orig_bytes > 1000000` are placeholders. Baseline your own environment and set them from data.
- A query returning nothing is a statement about your telemetry until you prove otherwise.

---

## 1. "What executed?"

### Sysmon process creation (Windows PowerShell, live)

```powershell
# Full field access by name — read the XML rather than guessing property indexes
function Get-SysmonEvent {
  param([int]$Id, [int]$Hours = 2)
  Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = $Id; StartTime = (Get-Date).AddHours(-$Hours)
  } | ForEach-Object {
    [xml]$x = $_.ToXml(); $h = @{ TimeCreated = $_.TimeCreated; EventId = $Id }
    foreach ($d in $x.Event.EventData.Data) { $h[$d.Name] = $d.'#text' }
    [pscustomobject]$h
  }
}

Get-SysmonEvent -Id 1 | Select-Object TimeCreated, User, ParentImage, Image, CommandLine
```

```powershell
# Masquerading: image name does not match the binary's embedded original name
Get-SysmonEvent -Id 1 | Where-Object { $_.OriginalFileName -and ($_.Image -notlike "*$($_.OriginalFileName)") } |
  Select-Object TimeCreated, User, Image, OriginalFileName, ParentImage, CommandLine

# Encoded / hidden / no-profile PowerShell
Get-SysmonEvent -Id 1 | Where-Object { $_.CommandLine -match '(?i)-enc(odedcommand)?\s|-w(indowstyle)?\s+hidden|-nop' } |
  Select-Object TimeCreated, User, ParentImage, Image, CommandLine

# Execution from user-writable staging paths
Get-SysmonEvent -Id 1 | Where-Object { $_.Image -match '(?i)\\Temp\\|\\AppData\\|\\Public\\|\\ProgramData\\' } |
  Select-Object TimeCreated, User, ParentImage, Image, CommandLine
```

### Legacy 4688 and account context

```powershell
# 4688 requires Audit Process Creation; the command line needs it enabled explicitly
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = (Get-Date).AddHours(-4) } |
  Select-Object TimeCreated, Message

# 4688 without a command line is a coverage gap, not a quiet host
auditpol /get /subcategory:"Process Creation"
```

### KQL / SPL / EQL / VQL

```kusto
// Sentinel: Office application spawning a scripting host
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by Timestamp desc
```

```text
# Kibana
event.category : "process" and process.name : "powershell.exe" and process.command_line : *-enc*
```

```spl
index=sysmon EventCode=1
| stats count by Computer, User, ParentImage, Image
| sort - count
```

```eql
/* Elastic Security: process lineage as a sequence */
sequence by host.name with maxspan=2m
  [ process where process.name == "winword.exe" ]
  [ process where process.name in ("powershell.exe","cmd.exe","mshta.exe") ]
```

```sql
-- Velociraptor VQL
SELECT Name, Pid, Ppid, CommandLine, CreateTime
FROM pslist()
WHERE CommandLine =~ "(?i)-enc(odedcommand)?\\s"
```

```bash
# Linux: execution records by audit key (auid survives sudo; uid does not)
sudo ausearch -k exec -ts recent -i
sudo ausearch -k exec -ts today -x /usr/bin/curl        # -x matches the executable
sudo aureport -x --summary                              # executables seen, summarised
```

```sql
-- osquery: execution from odd paths, and the process's parent
SELECT pid, parent, name, path, cmdline, uid FROM processes WHERE path LIKE '%\Temp\%';
SELECT pid, name, cmdline FROM processes WHERE name IN ('powershell.exe','cmd.exe','mshta.exe');
```

---

## 2. "What persisted?"

```powershell
# Registry writes to autostart locations (Sysmon 13) — note WHO wrote it
Get-SysmonEvent -Id 13 | Where-Object { $_.TargetObject -match 'CurrentVersion\\(Run|RunOnce)|Winlogon|Image File Execution Options' } |
  Select-Object TimeCreated, User, Image, TargetObject, Details

# Service installation: System 7045 is the SCM's own record; Security 4697 is the audited view
Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = (Get-Date).AddHours(-4) } | Select-Object TimeCreated, Message
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4697 } -MaxEvents 20 | Select-Object TimeCreated, Message

# Scheduled tasks: creation events AND the on-disk definition
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4698 } -MaxEvents 20 | Select-Object TimeCreated, Message
Get-ChildItem C:\Windows\System32\Tasks -Recurse -File | Sort-Object LastWriteTime -Descending | Select-Object -First 10 LastWriteTime, FullName

# WMI event-subscription persistence (Sysmon 19/20/21 = filter / consumer / binding)
Get-SysmonEvent -Id 19 | Select-Object TimeCreated, User, EventNamespace, Name, Query
Get-SysmonEvent -Id 20 | Select-Object TimeCreated, User, EventNamespace, Name, Destination
Get-SysmonEvent -Id 21 | Select-Object TimeCreated, User, EventNamespace, Filter, Consumer

# Autoruns: the diff between two snapshots is the hunt
# autorunsc64.exe -accepteula -a * -s -h -c -o autoruns-current.csv
$base = Import-Csv C:\lab\exports\autoruns-baseline.csv
$now  = Import-Csv C:\lab\exports\autoruns-current.csv
Compare-Object $base $now -Property 'Entry Location','Entry','Image Path' | Where-Object SideIndicator -eq '=>'
```

```sql
-- osquery: persistence state on Windows
SELECT name, action, path, enabled, hidden, last_run_time FROM scheduled_tasks;
SELECT name, path, args, type, source, status FROM startup_items;
SELECT name, display_name, status, start_type, path FROM services;
```

```bash
# Linux persistence surfaces
sudo ausearch -k identity -ts recent -i          # /etc/passwd writes (rule-dependent)
sudo ausearch -k cron_persist -ts recent -i      # needs: auditctl -w /etc/cron.d -p wa -k cron_persist
crontab -l
systemctl list-unit-files --state=enabled
cat ~/.ssh/authorized_keys
```

```eql
/* A new service created shortly after a suspicious process — sequence view */
sequence by host.name with maxspan=10m
  [ process where process.name : ("cmd.exe","powershell.exe") ]
  [ registry where registry.path : "*\\Services\\*" ]
```

---

## 3. "Who authenticated, and how?"

```powershell
# Logon-type distribution per account: the fastest way to spot an account used wrongly
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = (Get-Date).AddDays(-1) } |
  ForEach-Object {
    [xml]$x = $_.ToXml(); $d = @{}
    foreach ($f in $x.Event.EventData.Data) { $d[$f.Name] = $f.'#text' }
    [pscustomobject]@{ Time = $_.TimeCreated; User = $d['TargetUserName']; Type = $d['LogonType']
                       Src = $d['IpAddress']; LogonId = $d['TargetLogonId'] }
  } | Group-Object User, Type | Select-Object Count, Name | Sort-Object Count -Descending

# Explicit credentials (4648) — recorded whether or not the credential worked
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4648; StartTime = (Get-Date).AddHours(-4) } | Select-Object TimeCreated, Message

# Special privileges (4672): correlate LogonId with the 4624 that opened the session
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4672 } -MaxEvents 20 | Select-Object TimeCreated, Message

# Account and group changes: created, enabled, password reset, added to a privileged group
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4720,4722,4724,4726,4728,4732,4756) } -MaxEvents 20 |
  Select-Object TimeCreated, Id, Message

# Failed authentication bursts, and NTLM validation (a fallback worth watching)
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625 } -MaxEvents 50 | Select-Object TimeCreated, Message
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4776 } -MaxEvents 20 | Select-Object TimeCreated, Message
```

```kusto
// Sentinel: failed logons per account and source, above a threshold
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 1h)
| where FailedAttempts > 10
```

```spl
index=windows EventCode=4625
| bin _time span=1h
| stats count by _time, Account_Name, Source_Network_Address
| where count > 10
```

```bash
# Linux: authentication records from two independent sources
sudo ausearch -m USER_AUTH,USER_ACCT,CRED_ACQ -ts recent -i
sudo aureport --auth --summary
sudo grep -E 'sudo|su:|Accepted|Failed' /var/log/auth.log | tail -30
last -n 20
```

---

## 4. "Is anything beaconing?"

```bash
# Zeek: connections per conversation, ranked
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes \
  | sort | uniq -c | sort -nr | head -20

# Zeek: inter-arrival deltas — low stddev relative to mean means machine-like timing.
# Requires the #fields header, so feed zeek-cut whole log files.
cat conn.log \
  | zeek-cut id.orig_h id.resp_h id.resp_p ts \
  | sort -k1,1 -k2,2 -k3,3n -k4,4n \
  | awk '{ key=$1" "$2" "$3; if (key==prev) { d=$4-last;
             if (key in n) { n[key]++; s[key]+=d; ss[key]+=d*d } else { n[key]=1; s[key]=d; ss[key]=d*d } }
           prev=key; last=$4 }
         END { for (k in n) if (n[k]>=10) { m=s[k]/n[k]; v=ss[k]/n[k]-m*m; if (v<0) v=0;
                 printf "%d conns  mean_sec %.1f  stddev_sec %.1f  %s\n", n[k]+1, m, sqrt(v), k } }' \
  | sort -k6,6n | head -20

# Zeek: attempted-and-unanswered connections (dead C2, blocked egress, scanning)
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p conn_state | awk '$4=="S0"' | sort | uniq -c | sort -nr | head
```

```spl
// Splunk: beaconing candidates from proxy logs
index=proxy
| sort 0 + _time
| streamstats current=f last(_time) as prev by src_ip, dest_host
| eval delta = _time - prev
| stats count avg(delta) as avg_delta stdev(delta) as jitter sum(bytes_out) as uploaded by src_ip, dest_host
| where count > 20 and jitter < 5
```

```bash
# RITA: import Zeek logs and rank candidates (v3 and v4 differ — check rita import --help)
rita import --logs /lab/zeek/logs --database beacon-drill
rita view beacon-drill
rita list
```

```powershell
# Attribute the connection to a process (Sysmon 3) — a beacon without a process is a lead, not a finding
Get-SysmonEvent -Id 3 | Where-Object { $_.DestinationPort -in 443,80,8080,4444 } |
  Select-Object TimeCreated, User, Image, DestinationIp, DestinationHostname, DestinationPort, Initiated
```

```bash
# tshark: 60-second volume buckets, for the shape of a periodic conversation
tshark -r /lab/pcaps/hunt-01.pcap -q -z io,stat,60

# tshark: SNI is visible even under TLS
tshark -r /lab/pcaps/hunt-01.pcap -Y 'tls.handshake.extensions_server_name' \
  -T fields -e ip.dst -e tls.handshake.extensions_server_name
```

---

## 5. "Is data leaving?"

```bash
# Flow records: top talkers by bytes — the cheapest exfiltration triage there is
nfdump -R /var/flows -s srcip/bytes -n 20
nfdump -R /var/flows -s dstip/bytes -n 20
nfdump -R /var/flows -o csv > /lab/exports/flows.csv

# Zeek: strongly asymmetric conversations (outbound far exceeding inbound)
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes duration \
  | awk '$4 > 1000000 && $4 > ($5 * 10) { print }' | sort -k4 -nr | head -20
```

```spl
// Proxy: large uploads by client and destination
index=proxy method=POST
| stats sum(bytes_out) as uploaded count by src_ip, dest_host, username
| where uploaded > 10000000
| sort - uploaded
```

```bash
# DNS as an egress channel: long query names and unique-subdomain counts
cat dns.log | zeek-cut query | awk '{ print length($0), $0 }' | sort -nr | head -20
cat dns.log | zeek-cut query | awk -F. 'NF>=2 { d=$(NF-1)"."$NF; c[d]++ } END { for (k in c) print c[k], k }' | sort -nr | head -20
```

```powershell
# Endpoint staging: archive creation shortly before a transfer window
Get-SysmonEvent -Id 11 | Where-Object { $_.TargetFilename -match '\.(zip|7z|rar|tar|gz)$' } |
  Select-Object TimeCreated, User, Image, TargetFilename
```

---

## 6. "What moved laterally?"

```bash
# Zeek: internal-to-internal traffic on administrative ports
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p conn_state service \
  | awk '$3==445 || $3==3389 || $3==5985 || $3==22 || $3==135' | sort | uniq -c | sort -nr | head -30

# Zeek: one source touching many destinations (fan-out)
cat conn.log | zeek-cut id.orig_h id.resp_h | sort -u | awk '{ c[$1]++ } END { for (k in c) print c[k], k }' | sort -nr | head -10

# Zeek: SMB and NTLM detail — who authenticated where
cat smb_files.log | zeek-cut id.orig_h id.resp_h name action | sort | uniq -c | sort -nr | head
cat ntlm.log     | zeek-cut id.orig_h id.resp_h username hostname success | sort | uniq -c | sort -nr | head
```

```powershell
# Destination-side view: network logons with their source
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = (Get-Date).AddHours(-4) } |
  ForEach-Object {
    [xml]$x = $_.ToXml(); $d = @{}
    foreach ($f in $x.Event.EventData.Data) { $d[$f.Name] = $f.'#text' }
    if ($d['LogonType'] -eq '3') {
      [pscustomobject]@{ Time = $_.TimeCreated; User = $d['TargetUserName']; From = $d['IpAddress']; Process = $d['ProcessName'] }
    }
  } | Sort-Object Time -Descending

# Share access (object-access auditing) and network connections with a process owner
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(5140,5145) } -MaxEvents 20 | Select-Object TimeCreated, Id, Message
Get-SysmonEvent -Id 3 | Where-Object { $_.DestinationPort -in 445,3389,5985,135 } |
  Select-Object TimeCreated, User, Image, DestinationIp, DestinationPort, Initiated
```

```kusto
// Sentinel: internal fan-out on administrative ports
DeviceNetworkEvents
| where Timestamp > ago(4h)
| where RemotePort in (445, 3389, 5985, 135) and ActionType == "ConnectionSuccess"
| summarize Attempts = count(), Targets = dcount(RemoteIP) by DeviceName, InitiatingProcessFileName
| where Targets > 3
| sort by Targets desc
```

---

## 7. "What names were resolved?"

```bash
# Zeek DNS: queries per client, and the longest names (encoded data)
cat dns.log | zeek-cut id.orig_h query qtype rcode | sort | uniq -c | sort -nr | head -40
cat dns.log | zeek-cut query | awk '{ print length($0), $0 }' | sort -nr | head -20
```

```powershell
# Endpoint-side resolution attempts — logged even when the lookup fails
Get-SysmonEvent -Id 22 | Select-Object TimeCreated, Image, QueryName, QueryStatus, QueryResults
```

```kusto
// Sentinel: burst of unique names from one client
DnsEvents
| where TimeGenerated > ago(24h)
| summarize Queries = count(), UniqueNames = dcount(Name) by ClientIP, bin(TimeGenerated, 10m)
| where UniqueNames > 100
```

---

## 8. "What changed on disk?"

```powershell
# File creation and deletion with the owning process
Get-SysmonEvent -Id 11 | Select-Object TimeCreated, User, Image, TargetFilename, CreationUtcTime
Get-SysmonEvent -Id 23 | Select-Object TimeCreated, User, Image, TargetFilename, Hashes, IsExecutable

# Timestomping: creation time changed after the file already existed (Sysmon 2)
Get-SysmonEvent -Id 2 | Select-Object TimeCreated, Image, TargetFilename, CreationUtcTime, PreviousCreationUtcTime

# Alternate data streams (Sysmon 15)
Get-SysmonEvent -Id 15 | Select-Object TimeCreated, Image, TargetFilename, Hash
```

```sql
-- osquery: hash a suspicious file, and check its on-disk metadata
SELECT * FROM hash WHERE path = 'C:\Users\labuser\AppData\Local\Temp\lab.exe';
SELECT * FROM file WHERE path = 'C:\Windows\System32\drivers\etc\hosts';
```

```bash
# Linux: file metadata changes, and the audit trail for a watched path
stat /etc/passwd /etc/sudoers
sudo ausearch -k identity -ts recent -i
```

---

## 9. "What matches known-bad patterns?"

```bash
# YARA over files, a directory tree, or a memory image
yara -r -s rule.yar C:/lab/samples/
yara -r -t apt_lab rule.yar C:/lab/samples/       # only rules with a given tag
yara -r -s rule.yar C:/lab/dumps/memory.raw

# Volatility 3 + YARA, so matches are attributed to a process
vol -f mem.raw windows.vadyarascan --yara-file rule.yar
vol -f mem.raw windows.yarascan --yara-file rule.yar --pid 2468
```

```text
# Velociraptor: browse the catalogue rather than trusting a remembered artifact name
velociraptor artifacts list
```

---

## 10. EVTX triage at speed

```cmd
:: Hayabusa: update rules first, then build a timeline (profile and switch names
:: change between releases — check `hayabusa.exe help` on your build)
hayabusa.exe update-rules
hayabusa.exe csv-timeline  -d C:\lab\evtx\ -o C:\lab\out\timeline.csv
hayabusa.exe json-timeline -d C:\lab\evtx\ -o C:\lab\out\timeline.json
hayabusa.exe logon-summary -d C:\lab\evtx\
hayabusa.exe eid-metrics   -d C:\lab\evtx\
hayabusa.exe search -k "mimikatz" -d C:\lab\evtx\
```

```bash
# Chainsaw: Sigma hunts (needs the mapping file) and raw dumps for your own queries
chainsaw hunt C:/lab/evtx/ -s C:/lab/sigma-rules/ \
  --mapping C:/lab/chainsaw/mappings/sigma-event-logs-all.yml -o C:/lab/out/
chainsaw dump C:/lab/evtx/
chainsaw search "powershell" C:/lab/evtx/
```

```powershell
# Native queries still matter: they show the raw event the tools summarised
Get-WinEvent -Path C:\lab\evtx\Security.evtx -FilterXPath "*[System[EventID=4688]]" -MaxEvents 20
wevtutil qe Security "/q:*[System[(EventID=4688)]]" /c:20 /rd:true /f:text
wevtutil epl Security C:\lab\exports\Security.evtx
```

```bash
# Velociraptor: fleet-scale questions and raw artefact collection
# (artifact names are versioned — list yours first)
velociraptor artifacts list
velociraptor artifacts collect Windows.System.Pslist
velociraptor query "SELECT Name, Pid, Ppid, CommandLine FROM pslist()"
```

```sql
-- VQL: failed logons straight from a collected EVTX file
SELECT System.TimeCreated.SystemTime AS Time, System.Computer AS Host,
       EventData.TargetUserName AS User, EventData.IpAddress AS Source
FROM parse_evtx(filename="C:/Windows/System32/winevt/Logs/Security.evtx")
WHERE System.EventID.Value == 4625
```

---

## 11. Cross-language map

| Intent | KQL | SPL | EQL | VQL |
| --- | --- | --- | --- | --- |
| Filter by field | `where EventID == 1` | `EventCode=1` | `process where process.name == "cmd.exe"` | `WHERE Name = "cmd.exe"` |
| Case-insensitive match | `in~ ("a","b")` | `Image IN ("a","b")` | `process.name in ("a","b")` | `Name =~ "(?i)a\|b"` |
| Substring | `has "abc"` / `contains` | `Image="*abc*"` | `process.command_line : "*abc*"` | `CommandLine =~ "abc"` |
| Count per entity | `summarize count() by User` | `stats count by User` | — (use a rule query) | `GROUP BY` is done in the source, not the query |
| Time bucket | `bin(TimeGenerated, 1h)` | `bin _time span=1h` | — | `GROUP BY` on a formatted time field |
| Sequence | — (use `join`/`summarize`) | `transaction` / `streamstats` | `sequence by host with maxspan=…` | `chain()` / ordered collection |
| Time bound | `where TimeGenerated > ago(7d)` | time picker or `earliest=-7d` | timeline selector | `StartTime`/`EndTime` args on collection |

---

## Common Mistakes & Tips

- **Wrong time window.** Most "my query is broken" moments are a time-range problem. Set the window explicitly before debugging syntax.
- **Field names copied from another environment.** `process.name` in one backend is `event_data.Image` in another and `New_Process_Name` in a third. Expand a sample event and read the real names.
- **Leading-wildcard searches at scale.** `*foo*` on a large index is slow and often truncated; filter on a cheaper field first.
- **Calling a pattern a finding.** "Beaconing detected" is not a finding. Name the host, the pair, the count, the interval statistics, the time window, and the process that owned it.
- **Ignoring variance.** A mean interval of 60 s means nothing without the standard deviation. The ratio of the two is the beacon signal.
- **Trusting a threshold from a cheatsheet.** Every numeric threshold here is a placeholder. Derive yours from a baseline you can point at.
- **Forgetting that `zeek-cut` needs the header.** Piping a pre-stripped log into `zeek-cut` gives you silent nonsense.
- **Interpreting an empty result as an all-clear.** State the coverage: which sources, which window, which gaps. A negative without coverage is an apology, not a result.
- **Skipping the endpoint check.** Network behaviour without a process and process behaviour without an account both leave the hunt unfinished.
- **Hunting outside your authorization.** Every one of these queries is surveillance. Run them on your own systems, or on systems covered by written authorization.

## Checklist / Self-Test

- [ ] I can name the hunting question I am answering before I write a query.
- [ ] I can write a process-creation hunt in KQL, SPL, and VQL without looking them up.
- [ ] I can extract any Sysmon field by name in PowerShell instead of guessing property indexes.
- [ ] I can build a logon-type distribution for an account and explain what an anomaly means.
- [ ] I can compute beacon interval mean and standard deviation from `conn.log` by hand.
- [ ] I can find an exfiltration candidate in flow data without packet capture.
- [ ] I can produce a lateral-movement fan-out view and attach a process to one connection.
- [ ] I can turn an EVTX directory into a timeline with Hayabusa and a Sigma hunt with Chainsaw.
- [ ] I can validate a Sigma hunt pipeline against a known-bad test event before trusting a clean result.
- [ ] I state the telemetry coverage next to every negative result.
- [ ] I re-derived my thresholds from my own baseline rather than using the numbers on this page.

## Further Resources

- Elastic Security (KQL, EQL, timeline) — elastic.co/guide/en/security/current/index.html.
- Splunk Search Reference (SPL) — docs.splunk.com.
- Microsoft Sentinel and KQL — learn.microsoft.com/azure/sentinel, learn.microsoft.com/kusto/query.
- Velociraptor VQL and artifact catalogue — docs.velociraptor.app.
- osquery schema browser — osquery.io/schema.
- Zeek log reference — docs.zeek.org/en/current/script-reference/log-files.html.
- `auditd` man pages — `auditctl`, `ausearch`, `aureport`.
- Hayabusa — github.com/Yamato-Security/hayabusa; Chainsaw — github.com/WithSecureLabs/chainsaw.
- Official eCTHP page on the INE website for current, authoritative details about the certification.
