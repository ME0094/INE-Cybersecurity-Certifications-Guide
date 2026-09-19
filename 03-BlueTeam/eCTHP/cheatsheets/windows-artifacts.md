# Windows Artifacts — Event IDs, Paths & What They Answer

> eCTHP · Cheatsheet — INE Cybersecurity Certifications Study Guide
>
> The two things you reach for constantly during a Windows hunt: the event IDs that record behaviour, and the file-system and registry artefacts that survive after the events have wrapped. Both tables are organised by **the question they answer**. Analyse copies of artefacts from hosts you own or are authorized to examine.

**Conventions used below**

- **An event ID is a shape, not a verdict.** `4688` with `cmd.exe` is normal; `4688` with `cmd.exe` whose parent is `winword.exe` is not. Always read the parent, the account, and the command line.
- **Channel matters as much as ID.** The same numeric ID appears in different channels with different meanings. Read the ID *with* its channel.
- **Auditing is opt-in.** Many Security events exist only if the matching audit policy or SACL is configured. Check coverage before trusting an absence.
- **Timestamps are UTC** in the artefacts below; registry timestamps are FILETIME. State your time zone before building a timeline.
- **Event logs wrap.** Collect or export them before they rotate, or the window you need is gone.

---

## 1. Process execution and termination

| ID | Channel | What it records | What it answers |
| --- | --- | --- | --- |
| 1 | `Microsoft-Windows-Sysmon/Operational` | Process Create, with full command line, parent image and command line, user, integrity level, hashes, `OriginalFileName` | What ran, from where, spawned by what, as whom — the primary endpoint hunting event |
| 5 | Sysmon | Process Terminated | How long it ran (pair with the matching ID 1 `ProcessGuid`) |
| 2 | Sysmon | File creation time changed | Timestomping — a creation time adjusted after the file existed |
| 4688 | `Security` | Process creation (requires *Audit Process Creation*) | Native process creation; the command line appears only if *Include command line in process creation events* is enabled |
| 4689 | `Security` | Process termination | Native counterpart to 4688 |
| 800 | `Windows PowerShell` | Pipeline execution details (requires the matching policy) | Which commands ran through the PowerShell engine |
| 4104 | `Microsoft-Windows-PowerShell/Operational` | Script Block Logging | What script code actually executed, including encoded and in-memory |

---

## 2. Logon, authentication, and accounts

| ID | Channel | What it records | What it answers |
| --- | --- | --- | --- |
| 4624 | `Security` | Successful logon, with **LogonType**, source address, and `TargetLogonId` | Who logged on, how, and from where — the LogonType table below is the analytical key |
| 4625 | `Security` | Failed logon, with a status/sub-status code | Password guessing, invalid accounts, failed remote authentication |
| 4634 / 4647 | `Security` | Logoff (system-initiated / user-initiated) | Session duration; pair with the 4624 `LogonId` |
| 4648 | `Security` | A process used **explicit credentials** different from the current session's | `runas`, scheduled tasks with stored credentials, lateral movement tooling — recorded whether or not the credential worked |
| 4672 | `Security` | Special privileges assigned to a new logon | Which sessions hold administrative rights, tied to a `LogonId` |
| 4720 / 4722 / 4724 / 4725 / 4726 | `Security` | Account created / enabled / password reset attempted / disabled / deleted | Account lifecycle, and how quickly an account is used after creation |
| 4728 / 4732 / 4756 | `Security` | Member added to a global / local / universal security group | Privilege escalation through group membership |
| 4740 | `Security` | Account locked out | Guess-until-lockout behaviour, or a misconfigured service account |
| 4768 | `Security` | Kerberos TGT requested | Interactive domain authentication, and the encryption type requested |
| 4769 | `Security` | Kerberos service ticket requested | Service access; RC4 (`0x17`) requests for service accounts are a kerberoasting *heuristic*, not proof |
| 4771 | `Security` | Kerberos pre-authentication failed | Credential failures at the domain level |
| 4776 | `Security` | NTLM credential validation | The fallback authentication path — useful precisely because modern estates should rarely use it |
| 4798 / 4799 | `Security` | User's groups / security-enabled group membership enumerated | Reconnaissance in volume |
| 5140 / 5145 | `Security` | Network share object accessed (detailed access requires object-access auditing) | Which share, which file, by whom |
| 1149 | `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | RDP user authentication succeeded | Remote interactive access |
| 21 / 22 / 23 / 24 / 25 | `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | Session logon / shell start / logoff / disconnect / reconnect | The RDP session lifecycle, including reconnections worth explaining |

### Logon types (the field that makes 4624 readable)

| Type | Meaning | Hunting relevance |
| --- | --- | --- |
| 2 | Interactive (at the console) | Normal for a workstation; anomalous for a service account |
| 3 | Network (e.g. SMB, WinRM) | Lateral movement, share access, remote service use |
| 4 | Batch | Scheduled work |
| 5 | Service | What a service account *should* produce — its absence in favour of type 2 or 10 is the anomaly |
| 7 | Unlock | Workstation returning from lock |
| 8 | Network cleartext | Credentials sent in the clear — worth investigating on its own |
| 9 | New credentials (`runas /netonly`) | Explicit alternate-identity use |
| 10 | RemoteInteractive (RDP) | Remote desktop access |
| 11 | Cached interactive | Logon with cached domain credentials — works offline, notable on a laptop that should be online |

---

## 3. Services and drivers

| ID | Channel | What it records | What it answers |
| --- | --- | --- | --- |
| 7045 | `System` | A service was installed | New persistence or remote-execution service — with image path, type, start type, and the account it runs as |
| 4697 | `Security` | A service was installed in the system (requires the matching audit policy) | The same install as an audited event; useful when you want it in the security stream |
| 7040 | `System` | Service start type changed | A dormant service re-armed to auto-start |
| 7036 | `System` | Service entered running/stopped state | Confirming that a newly installed service actually started |
| 7034 | `System` | Service terminated unexpectedly | Crash-looping or killed service |
| 6 | Sysmon | Driver loaded | Kernel-level persistence and BYOVD-style driver loading |
| 4 | Sysmon | Sysmon service state changed | **Tampering**: Sysmon was stopped or reconfigured |
| 16 | Sysmon | Sysmon configuration changed | The agent was told to collect less — an anti-forensic move |

---

## 4. Scheduled tasks

| ID | Channel | What it records | What it answers |
| --- | --- | --- | --- |
| 4698 | `Security` | A scheduled task was created | New persistence, with the task's action and trigger in the event |
| 4699 / 4700 / 4701 / 4702 | `Security` | Task deleted / enabled / disabled / updated | Modification of existing tasks — often quieter than creation |
| 106 | `Microsoft-Windows-TaskScheduler/Operational` | A task was registered | The scheduler's own record of creation, independent of the Security log |
| 140 / 141 / 142 | TaskScheduler Operational | Task updated / deleted / disabled | Lifecycle as seen by the scheduler |
| 200 / 201 | TaskScheduler Operational | Task action started / completed | **Execution** — the event that proves the persistence actually fired, and when |
| 11 | Sysmon | File created (`C:\Windows\System32\Tasks\…`) | The on-disk task definition — an artefact that outlives the events |

> The on-disk definition under `C:\Windows\System32\Tasks\` is the corroborating artefact for any task-based finding: it keeps the action and trigger even after the creating events have wrapped.

---

## 5. PowerShell

| ID | Channel | What it records | What it answers |
| --- | --- | --- | --- |
| 400 | `Windows PowerShell` | Engine state changed to Available | A PowerShell session started (the classic log) |
| 403 | `Windows PowerShell` | Engine state changed to Stopped | Session ended |
| 600 | `Windows PowerShell` | Provider started | Which providers a session used (registry, file system) |
| 800 | `Windows PowerShell` | Pipeline execution details (opt-in policy) | Command-level execution inside the pipeline |
| 4103 | `Microsoft-Windows-PowerShell/Operational` | Module logging | Which cmdlets and parameters were invoked |
| 4104 | `Microsoft-Windows-PowerShell/Operational` | Script block logging | The actual script text — decoded even when the command line was base64 |

**Paths that complement the events:**

```text
%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    Commands typed at an interactive prompt. Per user, user-deletable, truncated by default.
    Treat as a lead, never as proof.

%USERPROFILE%\Documents\PowerShell_transcript.*.txt   (or the configured output directory)
    Session transcripts, when transcription policy is enabled.
```

---

## 6. WMI

| ID | Channel | What it records | What it answers |
| --- | --- | --- | --- |
| 19 / 20 / 21 | Sysmon | WMI event filter / consumer / consumer-to-filter binding | WMI event-subscription persistence — all three together are diagnostic |
| 5857 | `Microsoft-Windows-WMI-Activity/Operational` | WMI provider started | Which provider was loaded, and by which process |
| 5858 | WMI-Activity Operational | A WMI operation failed | Failed reconnaissance or blocked execution |
| 5860 | WMI-Activity Operational | Temporary event consumer registration | Transient WMI subscription |
| 5861 | WMI-Activity Operational | Permanent event consumer registration | **The persistence variant** — a consumer that survives reboot |

```powershell
# Live view of WMI subscriptions (needs elevation). Sysmon 19/20/21 record the same
# objects being created, which is how you know when it happened.
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding
```

---

## 7. DNS

| ID | Channel | What it records | What it answers |
| --- | --- | --- | --- |
| 22 | Sysmon | DNS query from a process, with `QueryName`, `QueryStatus`, `QueryResults` | Which **process** resolved which name — the attribution that resolver logs cannot give you |
| 3006 / 3008 | `Microsoft-Windows-DNS-Client/Operational` | Client DNS query / response events | Client-side resolution history; confirm the IDs on your build, and note the channel is often disabled by default |
| — | DNS Server debug logging | A text log written per the server's configured log file | Server-side query history; configuring it is a deliberate act, so check whether it exists before assuming it |

---

## 8. Object access, defence tampering, and endpoint protection

| ID | Channel | What it records | What it answers |
| --- | --- | --- | --- |
| 4657 | `Security` | A registry value was modified (requires a SACL on the key) | Who changed which registry value — the audited alternative to Sysmon 13 |
| 4656 / 4663 | `Security` | A handle was requested / an object access was attempted | File, key, and share access when SACLs are configured |
| 1102 | `Security` | The audit log was cleared | Anti-forensic action against the Security log |
| 4719 | `Security` | System audit policy was changed | Someone reduced visibility — hunt this, not just the events it hid |
| 104 | `System` | The System log was cleared | The same tampering against a non-Security channel |
| 1116 / 1117 | `Microsoft-Windows-Windows Defender/Operational` | Malware detected / action taken | What the endpoint protection saw, and whether it acted |
| 5001 | Windows Defender Operational | Real-time protection disabled | Protection turned off — often a precursor, always worth explaining |
| 5007 | Windows Defender Operational | Defender configuration changed | Exclusions added, features disabled |

---

## 9. File-system and registry artefacts

Events tell you what happened while the log was collecting. These artefacts tell you what happened before it — and they often survive both a wrap and a reboot. Collect them from a copy or image, never modify the original.

| Artefact | Path | Question it answers | Read it with |
| --- | --- | --- | --- |
| **Prefetch** | `C:\Windows\Prefetch\*.pf` | Did this executable run, how many times, when (last run and up to several prior run times), and which files/DLLs it loaded in the first seconds | `PECmd` (Zimmerman tools), or a hex/text inspection for the embedded path strings |
| **Amcache** | `C:\Windows\AppCompat\Programs\Amcache.hve` | What programs were present on this system, first-seen evidence, and SHA-1 hashes for files | `AmcacheParser` |
| **ShimCache (AppCompatCache)** | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` → `AppCompatCache` value | Was this binary ever present (and, depending on version, executed) on this host? | `AppCompatCacheParser` |
| **SRUM** | `C:\Windows\System32\sru\SRUDB.dat` (ESE database) | Which **application** sent or received how much network data, and when — per hour | `SrumECmd` |
| **MFT** | `$MFT` at the volume root | What files exist and existed, with timestamps, size, and full path — including entries for deleted files whose records still survive | `MFTECmd`, or an image parser |
| **USN Journal** | `$Extend\$UsnJrnl:$J` | What changed on this volume, **in order**: create, delete, rename, with reasons | `MFTECmd`; live reads with `fsutil usn readjournal C:` |
| **Registry hives** | `C:\Windows\System32\config\{SYSTEM,SOFTWARE,SAM,SECURITY}`, `C:\Users\<user>\NTUSER.DAT`, `…\AppData\Local\Microsoft\Windows\UsrClass.dat` | Persistence, configuration, accounts, execution history, USB history, MRU lists | `RECmd`, `Registry Explorer`, `reg save` + offline parsing |
| **`$Recycle.Bin`** | `C:\$Recycle.Bin\<SID>\` — `$I*` (metadata) and `$R*` (content) | What was deleted, by which user (from the SID folder), the original full path, and the deletion time | `$I` parsing tools, or manual `$I` structure parsing |
| **WMI repository** | `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` (with `INDEX.BTR`, `MAPPING*.MAP`) | WMI classes, instances, and event subscriptions that persist across reboot | Live `Get-CimInstance -Namespace root/subscription`, or offline repository parsers |
| **Event logs** | `C:\Windows\System32\winevt\Logs\*.evtx` | The event records in section 1–8 | `Get-WinEvent`, `wevtutil`, Chainsaw, Hayabusa |
| **Task definitions** | `C:\Windows\System32\Tasks\*` | Scheduled-task actions and triggers, including tasks whose creation events have wrapped | Text/XML inspection (`schtasks /query /xml`) |
| **BITS jobs** | `C:\ProgramData\Microsoft\Network\Downloader\qmgr*.dat` | Background transfers — a download mechanism that survives reboots | `bitsadmin /list /allusers /verbose`, or offline parsing |
| **Jump lists / LNK / Recent** | `%APPDATA%\Microsoft\Windows\Recent\`, `…\Recent\AutomaticDestinations\`, `…\Recent\CustomDestinations\` | What files were opened, from where, and when | `JLECmd`, `LECmd` |
| **PowerShell history** | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Commands typed interactively (user-writable, truncated) | Plain text |
| **Activity/Timeline DB** | `C:\Users\<user>\AppData\Local\ConnectedDevicesPlatform\L.<user>\ActivitiesCache.db` | User activity history across applications | SQLite tools |
| **Hibernation / page files** | `C:\hiberfil.sys`, `C:\pagefile.sys`, `C:\swapfile.sys` | Memory-resident data persisted to disk — analysable as a memory image | Memory forensics tooling (Volatility) |
| **Crash dumps** | `C:\Windows\Minidump\*.dmp`, `%LOCALAPPDATA%\CrashDumps\` | Process memory at the moment of a crash — sometimes the only copy of a payload | Debuggers, `strings` |

### Registry locations worth knowing by heart

```text
Autostart (per user)     NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
                         NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce
Autostart (machine)      SOFTWARE\Microsoft\Windows\CurrentVersion\Run
                         SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
Winlogon shell / helper  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
Services                 SYSTEM\CurrentControlSet\Services\<name>
Scheduled tasks          SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree
ShimCache                SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
Execution history (BAM)  SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>
UserAssist               NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\
                         (entry names are ROT13-obfuscated)
Run dialog history       NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
Typed paths              NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
Recent documents         NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
MUICache (app names)     NTUSER.DAT\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
USB storage history      SYSTEM\CurrentControlSet\Enum\USBSTOR
Network history          SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList
Installed software       SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
```

Collect hives from a live system without touching the originals:

```powershell
# Copy a live hive out for offline analysis (elevated)
reg save HKLM\SYSTEM   C:\lab\exports\SYSTEM.hive
reg save HKLM\SOFTWARE C:\lab\exports\SOFTWARE.hive
reg save HKCU          C:\lab\exports\NTUSER.DAT

# Or export a subtree as readable text for a quick review
reg export "HKLM\SYSTEM\CurrentControlSet\Services" C:\lab\exports\services.reg

# Export the event logs you intend to analyse offline
wevtutil epl Security C:\lab\exports\Security.evtx
```

---

## 10. Question → artefact map

| Hunting question | First artefact(s) to reach for |
| --- | --- |
| What executed, and what spawned it? | Sysmon 1, 4688, Prefetch, Amcache, BAM |
| Did this specific binary ever run here? | Prefetch, Amcache, ShimCache, BAM/DAM, USN Journal |
| What was deleted, and when? | `$Recycle.Bin` (`$I` files), Sysmon 23/26, USN Journal, MFT (unallocated records) |
| What persists across a reboot? | Run keys, Services, `TaskCache\Tree` + `System32\Tasks`, WMI repository, Autoruns |
| Which process sent how much data? | SRUM (per-application network usage), Sysmon 3 (the connection itself) |
| Which process resolved which name? | Sysmon 22 |
| Who authenticated, how, and from where? | 4624 (+ LogonType), 4625, 4648, 4672, 4768/4769/4776 |
| Was this account used outside its purpose? | 4624 LogonType compared against a baseline, 4720/4732, 4648 |
| Did the network move data after a file appeared? | Sysmon 11 → SRUM network entries → Zeek `conn.log` |
| Was logging tampered with? | 1102, 4719, 104, Sysmon 4 and 16 |
| What did this user do, in order? | Timeline DB, Recent/Jump lists, PSReadLine history, UserAssist, MFT/USN timeline |
| Was this file timestomped? | Sysmon 2, MFT `$STANDARD_INFORMATION` vs `$FILE_NAME` timestamps, USN Journal |

---

## 11. Artefact caveats you must state in a report

- **Prefetch is not a complete execution history.** Entries roll over, some configurations disable it, and it exists only on the system volume by default. "Not in Prefetch" ≠ "never ran".
- **ShimCache is presence-oriented.** Timestamp availability and update behaviour vary across Windows versions. Use it to support a claim, not to date one.
- **Amcache is first-seen evidence, not a run counter.** Reading it as a reliable execution count is a classic overclaim.
- **USN Journal wraps and can be deleted.** Its absence on a host where everything else is intact is itself worth a line in the report.
- **`$Recycle.Bin` proves deletion, not the actor's intent** — and its `$I`/`$R` pairing can be broken by cleanup tools.
- **WMI repository parsing is heavy.** Prefer the live `Get-CimInstance` view when the host is running; treat the on-disk repository as the fallback for a past state.
- **Event log absence has two meanings.** Either it did not happen, or auditing was off / the channel wrapped / the attacker cleared it. Distinguish the cases in writing.
- **Registry timestamps and event timestamps are different clocks of evidence.** A key's `LastWriteTime` says the key changed, not that the value you are looking at was written then.

---

## Common Mistakes & Tips

- **Treating a missing artefact as a negative finding.** Before concluding "this never happened", confirm the artefact is collected and enabled on that host — Prefetch, auditing, and Defender logging are all optional in practice.
- **Reading 4624 without LogonType.** The type is the analysis; the ID is only the container.
- **Ignoring `LogonId`.** It is the field that ties a logon to the 4672 and 4688 events produced inside that session.
- **Analysing live hives in place.** You will hit locks and, worse, you risk altering evidence. Copy with `reg save`, work on the copy.
- **Building a timeline from one artefact.** Prefetch plus MFT plus USN plus event logs is a timeline; any one of them alone is a hint.
- **Forgetting the on-disk counterpart.** Task events describe creation; the task XML describes what will run. Collect both.
- **Assuming the `Security.evtx` on disk is complete.** Channel size limits truncate history long before the incident you are hunting.
- **Mixing local time and UTC.** Normalise before you order events, and say which convention you used.
- **Hunting artefacts from hosts you do not control.** Analysis of someone else's system requires authorization, in writing, before you copy anything.

## Checklist / Self-Test

- [ ] I can name the Sysmon event ID for process creation, network connection, registry value set, and DNS query, with their key fields.
- [ ] I can state both audit policy prerequisites for a useful `4688` event.
- [ ] I can read a `4624` and say what the logon type and source address mean, and why 4648 is different.
- [ ] I can explain why a service account logging on with type 2 or 10 is more interesting than its privileges.
- [ ] I can name the two independent event sources for a service install and for a scheduled-task creation.
- [ ] I can list the WMI persistence triple and where the persistent form lives on disk.
- [ ] I can name five artefacts that answer "did this binary ever run here?" and one limitation of each.
- [ ] I can say which artefact answers "which application sent how much data, and when".
- [ ] I can explain how `$I` and `$R` files in `$Recycle.Bin` combine to give a path, a user, and a deletion time.
- [ ] I can find the persistence-relevant registry locations without looking them up.
- [ ] For every negative finding, I stated whether the artefact or the audit policy was actually present.
- [ ] Every artefact I collected came from a host I own or am authorized to examine.

> **Verification:** executed against **PowerShell 7.6.6 / `Get-WinEvent`** on Windows 11
> (10.0.26200) on **2026-09-19**, elevated. Every non-Sysmon channel named in the tables exists on
> this host with its `.evtx` file under `C:\Windows\System32\winevt\Logs` — `Security`, `System`,
> `Windows PowerShell`, `Microsoft-Windows-PowerShell/Operational`,
> `TaskScheduler/Operational`, `WMI-Activity/Operational`, both TerminalServices channels,
> `Windows Defender/Operational` and `DNS-Client/Operational` — and the cited IDs are declared by
> their providers' own manifests: TaskScheduler 106/140/141/142/200/201, WMI-Activity
> 5857/5858/5860/5861, Defender 1116/1117/5001/5007, PowerShell 4103/4104, DNS-Client
> 3006/3008, TerminalServices 21–25 and 1149, and the Security IDs including 4688, 4624, 4648,
> 4672, 4698 and 6416. Two rows deserve the precision: **1102** and **104** are declared by
> `Microsoft-Windows-Eventlog`, not by the auditing provider, and the legacy `400`/`403`/`600`/`800`
> IDs come from the `Windows PowerShell` channel, which no installed manifest describes.
> **Not verified:** the Sysmon rows — Sysmon is not installed on this host, and `Get-WinEvent
> -LogName 'Microsoft-Windows-Sysmon/Operational'` fails accordingly — and the logon-type table,
> which is documentation rather than a manifest entry.

## Further Resources

- Windows Security auditing and event reference — learn.microsoft.com/windows/security/threat-protection/auditing.
- Sysmon events and configuration — learn.microsoft.com/sysinternals/downloads/sysmon.
- Eric Zimmerman's tools (PECmd, AmcacheParser, AppCompatCacheParser, SrumECmd, MFTECmd, RECmd, JLECmd, LECmd) — ericzimmerman.github.io.
- Registry Explorer and the Registry reference material on hive structures — ericzimmerman.github.io.
- `wevtutil` and `Get-WinEvent` documentation — learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent.
- Windows Event Forwarding — learn.microsoft.com/windows/win32/wec/windows-event-collector.
- MITRE ATT&CK — attack.mitre.org (technique context for what each artefact is evidence of).
- Official eCTHP page on the INE website for current, authoritative details about the certification.
