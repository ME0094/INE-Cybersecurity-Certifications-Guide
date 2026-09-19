# Endpoint Tools — Telemetry, EVTX Triage & Scanning

> eCTHP · Tools — INE Cybersecurity Certifications Study Guide
>
> The endpoint-side hunting kit: Sysmon and the Windows Event Log as the primary behaviour record, PowerShell logging for script visibility, `auditd` for Linux execution, `osquery` for fleet-wide questions, Autoruns for persistence, Hayabusa and Chainsaw for EVTX timeline triage, and YARA for file and memory scanning. Every example targets hosts you own or are explicitly authorized to monitor.

## 1. The endpoint is where behaviour becomes visible

Network telemetry tells you *that* two hosts talked. Only endpoint telemetry tells you **which process did it, spawned by what, under which account, from which path**. That causality is what turns a suspicious connection into a finding (see `../methodology/03-telemetry-and-data-sources.md`).

Five questions account for most endpoint hunts, and each maps to a different source:

| Hunting question | Primary source |
| --- | --- |
| What executed, and what spawned it? | Sysmon Event ID 1, Windows 4688, `auditd` execve, osquery `processes` |
| What persisted? | Registry Run keys, services, scheduled tasks, WMI repository, Autoruns |
| What ran as a script that never touched disk? | PowerShell 4104 script block logging |
| What did the process touch — files, registry, other processes? | Sysmon 11/12/13, Sysmon 8/10, Sysmon 3 |
| What is true on *every* host right now? | osquery (fleet), or a Velociraptor artifact |

> Coverage first, questions second. A hunt on a host without Sysmon and without command-line auditing is a hunt with no data — confirm the source exists and is actually collecting before you interpret an empty result as "nothing happened".

## 2. Sysmon (System Monitor)

**What it is.** A Sysinternals driver-plus-service that writes rich, structured Windows telemetry into the event log channel `Microsoft-Windows-Sysmon/Operational`. It is not built into Windows: you install it, and its value is entirely determined by the configuration file you feed it.

**What it produces.** One XML event per observed behaviour, with a stable template per event ID. The table below is the hunting-relevant subset.

| Event ID | Behaviour | Fields a hunter pivots on |
| --- | --- | --- |
| 1 | Process Create | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `IntegrityLevel`, `Hashes`, `OriginalFileName`, `CurrentDirectory` |
| 2 | File creation time changed (timestomping) | `Image`, `TargetFilename`, `CreationUtcTime`, `PreviousCreationUtcTime` |
| 3 | Network connection | `Image`, `User`, `Protocol`, `SourceIp`, `DestinationIp`, `DestinationHostname`, `DestinationPort`, `Initiated` |
| 5 | Process terminated | `Image`, `ProcessGuid` (pair with ID 1 for duration) |
| 6 | Driver loaded | `ImageLoaded`, `Hashes`, `Signed`, `Signature` |
| 7 | Image (DLL) loaded | `Image`, `ImageLoaded`, `Hashes`, `Signed` |
| 8 | CreateRemoteThread | `SourceImage`, `TargetImage`, `StartAddress`, `StartModule` |
| 9 | RawAccessRead (raw disk access) | `Image`, `Device` |
| 10 | ProcessAccess | `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace` |
| 11 | FileCreate (file created or overwritten) | `Image`, `TargetFilename`, `CreationUtcTime` |
| 12 / 13 / 14 | Registry key create-delete / value set / key-value rename | `Image`, `EventType`, `TargetObject`, `Details` |
| 15 | FileCreateStreamHash (alternate data stream) | `Image`, `TargetFilename`, `Hash` |
| 16 | Sysmon config change | `Configuration`, `ConfigurationFileHash` |
| 17 / 18 | Named pipe created / connected | `Image`, `PipeName` |
| 19 / 20 / 21 | WMI event filter / consumer / filter-to-consumer binding | `EventNamespace`, `Name`, `Query`, `Consumer`, `Destination`, `Filter` |
| 22 | DNS query | `Image`, `QueryName`, `QueryStatus`, `QueryResults` |
| 23 | FileDelete (archived) | `Image`, `TargetFilename`, `Hashes`, `Archived`, `IsExecutable` |
| 24 | ClipboardChange | `Image`, `Session`, `ClientInfo` |
| 25 | ProcessTampering (process hollowing / herpaderping) | `Image`, `Type` |
| 26 | FileDeleteDetected | `Image`, `TargetFilename`, `Hashes`, `IsExecutable` |
| 27 / 28 / 29 | File block executable / block shredding / executable detected | `Image`, `TargetFilename`, `Hashes` |

> **The introduction version differs per event ID**, and the current Sysinternals documentation no
> longer carries the per-version changelog. Events 23 and 26 arrived in the Sysmon 11.x line, 24
> in 12.0, 25 in 13.0, 27 and 28 in 14.x, and 29 in 15.0 — so do not build a hunt on a remembered
> number. Ask the binary that is actually installed: `sysmon64.exe -s` prints the configuration
> schema that build accepts, and
> `Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | Select-Object -ExpandProperty Id -Unique`
> shows which IDs are genuinely reaching the channel. A rule for an ID that never appears looks
> exactly like a clean environment.

**How to use it.**

```powershell
# Install (elevated). Config decides what you get: start from a public baseline
# configuration (e.g. the SwiftOnSecurity or sysmon-modular distributions) and tune it.
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml

# Update the configuration in place — no reinstall, no reboot
.\Sysmon64.exe -c .\sysmonconfig.xml

# Show the configuration currently in force
.\Sysmon64.exe -c

# Confirm the channel is producing events at all
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

Hunt the process-creation stream with PowerShell when you have no SIEM:

```powershell
# Last day of process creations; export the XML so you can see every field
Get-WinEvent -FilterHashtable @{
  LogName   = 'Microsoft-Windows-Sysmon/Operational'
  Id        = 1
  StartTime = (Get-Date).AddDays(-1)
} | ForEach-Object { $_.ToXml() } | Set-Content .\hunt-exports\sysmon-eid1.xml

# Read one event's fields as an object instead of guessing property indexes
# (index order follows the event template: dump the XML once, then map it)
$e = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1
$e.Properties | ForEach-Object { $_.Value }
```

**Limitations.**

- **Configuration decides coverage.** A default or narrow config silently omits whole event classes. Sysmon only answers questions its config was written to capture.
- **No built-in retention policy** beyond the channel's own log size — the channel wraps and old events are lost. Ship them somewhere.
- **High volume.** Event ID 1 plus 3 plus 7 on a busy workstation is a lot of data; unfiltered Sysmon is a storage problem.
- **Not tamper-proof.** Anyone with administrative access can stop the service, load a permissive config (Event ID 16 records this — hunt it), or clear the channel (Event ID 1102 in Security, plus the Sysmon channel's own cleared event).
- **Command lines can be truncated** by the OS in legacy `4688` (not Sysmon) unless command-line auditing is enabled; Sysmon captures them fully.

## 3. Windows Event Log

**What it is.** The native logging subsystem: channels organised under `C:\Windows\System32\winevt\Logs\` as `.evtx` files, readable live through the Event Log API or offline as files.

**What it produces.** `Security.evtx` (auditing — which is off by default for most event types), `System.evtx` (services, drivers, shutdowns), `Application.evtx`, and per-component Operational channels such as `Microsoft-Windows-PowerShell/Operational`, `Microsoft-Windows-TaskScheduler/Operational`, `Microsoft-Windows-WMI-Activity/Operational`, and `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`. See `../cheatsheets/windows-artifacts.md` for the event-ID map and what each one answers.

**How to use it.**

```powershell
# Live channel query with a server-side filter (fast — it runs in the log service)
Get-WinEvent -FilterHashtable @{
  LogName   = 'Security'
  Id        = 4688
  StartTime = (Get-Date).AddDays(-2)
} -MaxEvents 50

# Same thing from cmd, without PowerShell
wevtutil qe Security "/q:*[System[(EventID=4688)]]" /c:20 /rd:true /f:text

# Export a channel to a file for offline analysis in a lab VM
wevtutil epl Security C:\lab\exports\Security.evtx
```

**Limitations.**

- **Audit policy is the whole game.** `4688` requires *Audit Process Creation*; command lines inside it additionally require *Include command line in process creation events*; `4657` needs registry auditing; object-access events need SACLs. Reading 4688 in an environment where process-creation auditing is off will show you nothing, forever.
- **Security log wraps.** Default sizes are small; a noisy week can push out the window you care about.
- **Offline analysis is where the speed is.** Analysing `.evtx` copies (Chainsaw, Hayabusa, `EvtxECmd`) is far faster than live `Get-WinEvent` over a long window, and it preserves the evidence.
- **One channel tells part of the story.** Process creation lives in Security/Sysmon; service installs in System (`7045`) and Security (`4697`); task changes in TaskScheduler Operational. A hunt that reads one channel will miss the corroborating event.

## 4. PowerShell logging

**What it is.** Three independent logging facilities, each answering a different question. This is the single highest-value telemetry upgrade on a Windows estate, because so much real-world activity happens in script that never becomes an `.exe`.

| Facility | Event | Channel | Answers |
| --- | --- | --- | --- |
| **Script Block Logging** | 4104 | `Microsoft-Windows-PowerShell/Operational` | What code actually executed, including de-obfuscated and in-memory script |
| **Module Logging** | 4103 | `Microsoft-Windows-PowerShell/Operational` | Which cmdlets and parameters were invoked |
| **Transcription** | — | `.txt` files in the configured output directory | A plaintext record of a session, useful for human-readable replay |

Enable them by Group Policy or registry (elevated, applies to new sessions):

```powershell
# Script Block Logging
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
  -Name EnableScriptBlockLogging -Value 1 -Type DWord

# Module Logging (needs the module list to be useful)
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
  -Name EnableModuleLogging -Value 1 -Type DWord
```

Hunt it:

```powershell
# Script blocks containing classic download-and-execute primitives
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-PowerShell/Operational'
  Id      = 4104
} -MaxEvents 200 |
  Where-Object { $_.Message -match 'FromBase64String|DownloadString|IEX|Invoke-Expression|Reflection.Assembly' } |
  Select-Object TimeCreated, @{n='Snippet';e={ $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length)) }}
```

Also check the interactive command history, which script block logging does **not** capture:

```powershell
# Commands typed at an interactive prompt (per user, user-deletable)
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

**Limitations.**

- **Not enabled by default.** On a host without these policies, the log is empty and the absence of a hit proves nothing.
- **4104 logs script blocks, not keystrokes.** Commands typed interactively at the prompt do not appear; PSReadLine history covers some of that gap but is user-writable and truncated by default — a hunter treats it as a lead, not proof.
- **The log grows fast** and wraps. Collect 4104 centrally or lose it.
- **Encoded input is logged decoded, but obfuscation survives** in the logged text; expect to read de-obfuscation work into a hunt rather than a clean indicator.
- **PowerShell is not the only scripting host.** `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, and `msbuild.exe` deliver script behaviour with none of this logging. Hunt those through process creation instead.

## 5. auditd (Linux)

**What it is.** The Linux kernel audit subsystem: syscall-level recording driven by rules you load, with a userspace daemon writing to disk. It is the Linux equivalent of "process creation with command line", plus far more.

**What it produces.** Records in `/var/log/audit/audit.log`, correlated by an event ID. The types that matter for hunting:

| Record type | What it holds |
| --- | --- |
| `SYSCALL` | `auid` (login UID — survives `sudo`), `uid`, `gid`, `pid`, `ppid`, `comm`, `exe`, `key` |
| `EXECVE` | `argc` plus `a0`, `a1`, … — the actual arguments of the executed binary |
| `PATH` | File paths involved in the syscall, with inode and mode |
| `USER_AUTH` / `USER_ACCT` | Authentication and account events (from PAM) |
| `CONFIG_CHANGE` | Someone changed the audit rules — a hunt lead in itself |

**How to use it.**

```bash
# Minimal, high-value hunting rules (one rule per line, in /etc/audit/rules.d/hunt.rules)
# -k sets the key you search by later
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k exec
-w /etc/passwd -p wa -k identity
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/ssh/sshd_config -p wa -k ssh_config

# Load the rules and confirm they are active
sudo augenrules --load
sudo auditctl -l

# Query: who executed what, recently
sudo ausearch -k exec -ts recent
sudo ausearch -k exec -ts today -x /usr/bin/curl      # -x matches the executable

# Summaries that reveal shape rather than individual events
sudo aureport -x --summary       # executables seen
sudo aureport --auth --summary   # authentication summary
sudo aureport -k                 # activity per key
```

**Limitations.**

- **Rules must be loaded before the activity.** auditd is not retrospective; a hunt over last week's data needs those rules loaded last week.
- **`auid` versus `uid`** is the classic trap: `uid` becomes `0` under `sudo`, while `auid` still names the human who logged in. Hunting on `uid` alone loses the attribution that makes the event useful.
- **Volume and cost.** An `execve` rule on a busy server produces a lot of records; unkeyed rules are hard to search later.
- **Container and namespace blind spots.** Host auditd may not attribute activity inside containers the way you expect.
- **It records syscalls, not intent.** You still have to explain why the behaviour mattered.

## 6. osquery

**What it is.** SQL over the operating system. osquery exposes OS state as virtual tables, so you can ask "which hosts have X" in SQL instead of writing per-platform parsing code. `osqueryi` is the ad-hoc/interactive shell; `osqueryd` is the daemon that runs scheduled queries and (with an event publisher) evented tables.

**What it produces.** Query results, plus scheduled-query logs and evented-table records from `osqueryd`.

**How to use it.**

```sql
-- Interactive shell: discover the schema instead of guessing column names
-- osqueryi
.tables
.schema scheduled_tasks

-- Processes, with the command line — the core execution question
SELECT pid, parent, name, path, cmdline, uid FROM processes WHERE path LIKE '%\Temp\%';

-- Network state per process
SELECT pid, family, protocol, local_address, local_port, remote_address, remote_port, path
FROM process_open_sockets WHERE remote_address != '';

-- Listening services (unexpected listeners are a classic lead)
SELECT * FROM listening_ports;

-- Linux persistence surfaces
SELECT * FROM crontab;
SELECT * FROM systemd_units WHERE active_state = 'active';

-- Windows persistence and services
SELECT name, action, path, enabled, hidden, last_run_time FROM scheduled_tasks;
SELECT name, path, args, type, source, status FROM startup_items;
SELECT name, display_name, status, start_type, path FROM services;
```

```bash
# Non-interactive, machine-readable — the form you use in a fleet query
osqueryi --json "SELECT pid, name, cmdline FROM processes WHERE name = 'sshd';"

# The daemon form: scheduled queries come from the config
osqueryd --config_path=/etc/osquery/osquery.conf --verbose
```

**Limitations.**

- **Snapshot versus history.** Most tables show *now*. The classic hunting limitation: if you did not ask the question while the process was running, the answer is gone. Only evented tables (`process_events`, `socket_events`, `file_events`) give history, and they need an event publisher (Linux audit/BT-F, or Windows eventing) plus the daemon — check which your build supports with `.tables`.
- **Schema drift between versions.** Table and column names change across releases. Confirm with `.schema <table>` on the build you are querying rather than trusting a query copied from a blog post.
- **Performance.** Broad `LIKE` scans over `file` or `hash` tables can hammer a host. Scope by path.
- **Windows fidelity is lower than Sysmon.** osquery is excellent for state ("what exists"), weaker for behaviour ("what happened in what order").

## 7. Autoruns

**What it is.** A Sysinternals tool that enumerates **everything Windows starts automatically** — the canonical persistence survey. The GUI is `autoruns64.exe`; the scriptable form is `autorunsc64.exe`.

**What it produces.** A complete list of autostart locations with the executable path, publisher, signature status, and optionally file hashes — in a form you can diff between two points in time.

**How to use it.**

```cmd
:: Full inventory, signatures verified, hashes included, CSV for diffing
autorunsc64.exe -accepteula -a * -s -h -c -o C:\lab\exports\autoruns-baseline.csv

:: Later, on the same host, take a second snapshot and compare
autorunsc64.exe -accepteula -a * -s -h -c -o C:\lab\exports\autoruns-current.csv
```

```powershell
# The hunt is the diff: new entries since the baseline are what matter
$base = Import-Csv C:\lab\exports\autoruns-baseline.csv
$now  = Import-Csv C:\lab\exports\autoruns-current.csv
Compare-Object -ReferenceObject $base -DifferenceObject $now `
  -Property 'Entry Location','Entry','Image Path' |
  Where-Object SideIndicator -eq '=>'
```

Signature verification turns the survey into triage: an unsigned or invalid-signature entry in a location that normally holds signed Microsoft binaries is the lead.

```cmd
:: Ask the full switch list of your own binary rather than trusting memory
autorunsc64.exe /?
```

**Limitations.**

- **Elevation required.** Run unelevated and you will silently miss entries; an incomplete persistence survey is worse than none.
- **It is a snapshot.** Autoruns answers "what persists *now*". Persistence that was removed before you looked is invisible — that is what the registry, task files, and `$MFT`/USN timeline are for.
- **Microsoft entries are noise.** A large fraction of the output is legitimate. Suppress Microsoft entries in the GUI to hunt, but do not blind yourself permanently: attackers masquerade as legitimate entries.
- **No historical view and no correlation.** Autoruns does not tell you when an entry was created, or what it did. Pair it with file timestamps and process creation.

## 8. Hayabusa

**What it is.** A fast Windows event log **timeline generator and threat-hunting tool**, built around Sigma-derived detection rules. One binary, a rules directory, a directory of `.evtx` files.

**What it produces.** A CSV or JSON timeline of rule matches across the analysed EVTX set, with command lines, counts, severity levels, and channel context — plus summary reports (logon summary, event-ID metrics).

**How to use it.**

```cmd
:: Keep the rules current first — the findings depend entirely on them
hayabusa.exe update-rules

:: Full timeline of a collected EVTX set, with the default profile
hayabusa.exe csv-timeline -d C:\lab\evtx\ -o C:\lab\out\timeline.csv

:: Machine-readable output for a notebook or a diff between two collections
hayabusa.exe json-timeline -d C:\lab\evtx\ -o C:\lab\out\timeline.json

:: Summary views that answer "what shape is this log set?"
hayabusa.exe logon-summary -d C:\lab\evtx\
hayabusa.exe eid-metrics  -d C:\lab\evtx\

:: Keyword pivot inside the logs
hayabusa.exe search -k "mimikatz" -d C:\lab\evtx\
```

> Profiles and switches change between releases (`-p` selects a detection profile, outputs and severity filtering have grown over time). Run `hayabusa.exe help` on the version you download rather than assuming the flags above are current.

**Limitations.**

- **EVTX only.** Hayabusa cannot see network, EDR, or Linux telemetry. It is a triage accelerator for Windows logs, not a hunting platform.
- **Rule-driven.** Everything it reports comes from someone else's rule. A behaviour nobody wrote a rule for produces no timeline entry — which is exactly when you drop to raw queries (Sysmon ID 1, 4688) or Chainsaw's `dump`.
- **Noisy defaults on a real estate.** Expect false positives and tune.
- **Timeline, not narrative.** It gives ordered hits; the causality still has to be reasoned out by you.

## 9. Chainsaw

**What it is.** A WithSecure tool for rapid search and hunting through Windows forensic artefacts, with Sigma rule support. Where Hayabusa optimises for a fast timeline, Chainsaw is the general-purpose "search and dump EVTX at speed" tool — including a raw dump mode for when no rule covers your hypothesis.

**What it produces.** Sigma-rule hit reports (stdout, or written to an output directory), and raw/structured dumps of events from `.evtx` files.

**How to use it.**

```bash
# Hunt: run Sigma rules over a directory of EVTX files with the mapping file
# that translates Sigma field names onto the Windows event schema
chainsaw hunt C:/lab/evtx/ \
  -s C:/lab/sigma-rules/ \
  --mapping C:/lab/chainsaw/mappings/sigma-event-logs-all.yml \
  -o C:/lab/out/

# Dump: no rules, no interpretation — every event, structured, for your own queries
chainsaw dump C:/lab/evtx/

# Search: a plain pattern across the EVTX set
chainsaw search "powershell" C:/lab/evtx/
```

```powershell
# Chainsaw and Hayabusa are the fast path; for a single file the native tool is enough
# and keeps you honest about what the raw event actually contains
Get-WinEvent -Path C:\lab\evtx\Security.evtx -FilterXPath "*[System[EventID=4688]]" -MaxEvents 20
```

**Limitations.**

- **The mapping file is load-bearing.** Sigma rules describe generic fields; the Windows schema names them differently. A wrong or stale mapping produces either misses or garbage — validate that known-bad test events are detected before you trust a clean result.
- **Rules and tool versions move together.** Rules written for a newer schema may not fire on your version. Check the tool's docs for the matching rule release.
- **EVTX only**, and it needs the log to have been collected in the first place.
- **A dump is not an analysis.** `dump` gives you everything, which means it gives you no prioritisation — you still need a hypothesis.

## 10. YARA

**What it is.** A pattern-matching engine for files and memory. Rules describe strings and byte patterns plus a condition; YARA reports which rules matched which target. It is how you turn a known-bad indicator into something you can sweep across a file system, a memory image, or a set of process dumps.

**What it produces.** Match reports: rule name, target, and (with `-s`) the matching strings and offsets.

A minimal, valid rule:

```yara
rule Lab_Hunt_Marker
{
    meta:
        description = "Example lab rule: a marker string in a file or memory image"
        author      = "lab"
        date        = "2026-09-18"
    strings:
        $marker = "LAB-HUNT-MARKER" ascii wide
        $pe     = { 4D 5A }                    // 'MZ' — DOS/PE header
    condition:
        $marker and $pe
}
```

**How to use it.**

```bash
# Scan files or a directory tree
yara -r -s Lab_Hunt_Marker.yar C:/lab/samples/
# -r recursive, -s print the matching strings and offsets, -w suppress warnings

# Filter to rules carrying a tag, useful when you keep a library of rules
yara -r -t apt_lab Lab_Hunt_Marker.yar C:/lab/samples/

# Memory: a raw memory image is just a file, so the same rule applies
yara -r -s Lab_Hunt_Marker.yar C:/lab/dumps/memory.raw
```

For process memory inside a dump, let Volatility drive YARA so matches are attributed to a process rather than to a flat blob:

```bash
# `windows.vadyarascan` walks process address space and accepts `--pid`, which is what makes a
# hit attributable to a process. The root-level `yarascan` plugin scans kernel memory only and
# has NO `--pid` option, and `windows.yarascan` does not exist in Volatility 3 at all.
vol -f C:/lab/dumps/memory.raw windows.vadyarascan --yara-file C:/lab/rules/Lab_Hunt_Marker.yar
vol -f C:/lab/dumps/memory.raw windows.vadyarascan --yara-file C:/lab/rules/Lab_Hunt_Marker.yar --pid 2468
```

> Both plugin names come from `vol --help`. `windows.vadyarascan` and the root-level
> `yarascan.YaraScan` are loaded **only** when the `yara-x` or `yara-python` module is importable:
> without it Volatility lists them under "The following plugins could not be loaded …" and they
> disappear from the CLI — so confirm on the machine that will run the scan, which is often a
> container with a slimmer Python environment than your workstation. Note also that the short name
> `yarascan` becomes ambiguous once several YARA plugins are installed (`vol yarascan` answers
> "matches multiple plugins"); spell out `windows.vadyarascan` or `yarascan.YaraScan`.

**Limitations.**

- **String matching is evadable.** Packing, encryption, obfuscation, and a single changed byte defeat naive rules. YARA finds what you already described, so it complements a behavioural hunt rather than replacing it.
- **Memory is not the same as a file.** Use `ascii wide` where appropriate: Windows strings are frequently UTF-16LE, and an ASCII-only rule will miss them.
- **False positives are guaranteed** on any large corpus; a rule must be tuned against clean samples before its hits mean anything.
- **Performance.** Scanning full disks or multi-gigabyte memory images is slow; scope the target.
- **YARA is not a verdict.** A match is a lead that still needs process attribution, timestamp, and context.

## 11. How the endpoint tools fit together

| Tool | Artefact produced | Question it answers | Best paired with |
| --- | --- | --- | --- |
| Sysmon | Structured behaviour events in `Microsoft-Windows-Sysmon/Operational` | What executed, what it touched, what it connected to | Event Log, Chainsaw, Hayabusa |
| Windows Event Log | `.evtx` channels | Native security, service, task, and session events | Sysmon (for command lines), Autoruns |
| PowerShell logging | `4104` / `4103` in the PowerShell Operational channel, transcripts | What script code ran, including fileless | Sysmon ID 1, DNS logs |
| auditd | Syscall, execve, and path records on Linux | Which binary ran with which arguments, as which login user | osquery, Zeek |
| osquery | SQL result sets from live OS state | What is true now, across the fleet | SIEM, Velociraptor |
| Autoruns | Autostart inventory (CSV diffable) | What persists and would survive a reboot | Registry, scheduled tasks, `$MFT` |
| Hayabusa | EVTX rule-match timeline (CSV/JSON) | What in this log set matches known-bad behaviour | Chainsaw, raw queries |
| Chainsaw | Sigma hit reports and raw EVTX dumps | Fast search across many EVTX files | Hayabusa, Sysmon |
| YARA | Rule matches in files and memory | Does this known pattern appear here? | Volatility, file-system timeline |

## Common Mistakes & Tips

- **Interpreting an empty log as proof of absence.** The most common endpoint hunting error. Before concluding "nothing happened", confirm the telemetry existed: is Sysmon installed, is the config capturing this event ID, is 4104 enabled, did the channel wrap?
- **Reading `uid` where you meant `auid`** on Linux, or reading `4624` without the logon type. Logon type `3` (network) and type `10` (RDP) mean very different things from type `2` (interactive).
- **Hunting only event IDs.** Event IDs tell you the shape of the record, not whether it is malicious. `4688` with `cmd.exe` is normal; `4688` with `cmd.exe` whose parent is `winword.exe` is not.
- **Ignoring the parent.** Process creation without parentage loses most of its value. Sysmon ID 1 gives you `ParentImage` and `ParentCommandLine` — always capture and pivot on them.
- **Scanning without scope.** A YARA rule over an entire disk or an unbounded osquery `LIKE` on a production fleet is a self-inflicted outage. Scope the target, test on one host first.
- **Trusting a tool's clean result after a rules/mapping mismatch.** Chainsaw with a stale mapping and Hayabusa with outdated rules both fail *silently*. Validate the pipeline against a known-bad test event before you rely on it.
- **Forgetting the diff.** Persistence hunting is far more powerful as a comparison between two snapshots (Autoruns baseline versus now) than as a single list review.
- **Not preserving the raw artefact.** Chainsaw's `dump` and the exported `.evtx`/XML are your evidence. Keep them; a CSV of rule hits is a summary, not a record.
- **Practising on production.** Every tool here can hammer or alter a host. Learn them in the lab described in `../labs/hunting-range-setup.md`, on systems you own or are authorized to query.

## Checklist / Self-Test

- [ ] I can explain why Sysmon's value depends on its configuration file, and name one event class a narrow config omits.
- [ ] I can list the Sysmon event IDs for process creation, network connection, file creation, and registry value set, with their key fields.
- [ ] I confirmed which Sysmon event IDs my installed version actually writes to the channel.
- [ ] I can state which audit policy settings are required for `4688` to carry a command line — and whether they are enabled in my environment.
- [ ] I enabled PowerShell script block logging and found a `4104` event containing a download-and-execute primitive.
- [ ] I know what script block logging does *not* capture, and where to look for it instead.
- [ ] I wrote an `auditd` rule with a key, loaded it, and queried the resulting events with `ausearch -k`.
- [ ] I can explain the difference between `auid` and `uid` in an audit record.
- [ ] I ran at least three osquery tables and confirmed their real column names with `.schema`.
- [ ] I produced two Autoruns snapshots and identified the entries added between them.
- [ ] I generated a Hayabusa timeline and a Chainsaw hunt output from the same EVTX set and compared the findings.
- [ ] I wrote a valid YARA rule, ran it against a file and a memory image, and can name one way to evade it.
- [ ] Every artefact I analysed came from a host I own or am authorized to monitor.

> **Verification:** executed against Volatility 3 Framework 2.28.2 on 2026-09-19 in WSL Ubuntu
> 24.04.4 LTS (yara-python 4.5.4, `yara` 4.5.0). `vol windows.vadyarascan --help` prints
> `[--pid [PID ...]]`, so the process attribution in this section is real; `vol yarascan.YaraScan
> --help` lists only `--insensitive/--wide/--yara-string/--yara-file/--yara-compiled-file/--max-size`
> and contains **no** `--pid`; `vol windows.yarascan --help` fails with <!-- check-commands: ignore -->
> `invalid choice windows.yarascan`; and `vol yarascan` alone fails as ambiguous, matching <!-- check-commands: ignore -->
> `linux.vmayarascan`, `windows.vadyarascan` and `yarascan`. The Sysmon per-event introduction
> versions were **checked against the Sysinternals Sysmon documentation** on 2026-09-19, which
> lists the events but no longer publishes the per-version changelog; `sysmon64.exe -s` and the
> PowerShell examples are **unverified syntax references — not run**, since no Windows host was
> available.

## Further Resources

- Sysmon documentation and configuration guidance — learn.microsoft.com/sysinternals/downloads/sysmon; baseline configurations at github.com/SwiftOnSecurity/sysmon-config and github.com/olafhartong/sysmon-modular.
- Windows security auditing and event reference — learn.microsoft.com/windows/security/threat-protection/auditing.
- PowerShell about_Logging_Windows — learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows.
- `auditd` documentation — man pages for `auditd`, `auditctl`, `ausearch`, `aureport`, and the Linux Audit project at github.com/linux-audit.
- osquery documentation and schema browser — osquery.io/docs and osquery.io/schema.
- Autoruns — learn.microsoft.com/sysinternals/downloads/autoruns.
- Hayabusa — github.com/Yamato-Security/hayabusa.
- Chainsaw — github.com/WithSecureLabs/chainsaw.
- YARA documentation — yara.readthedocs.io.
- Official eCTHP page on the INE website for current, authoritative details about the certification.
