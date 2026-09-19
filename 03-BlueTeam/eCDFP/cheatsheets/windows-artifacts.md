# Windows Artefacts — Ordered by the Question They Answer

> eCDFP · Cheatsheet — INE Cybersecurity Certifications Study Guide
>
> The Windows artefacts that carry evidential weight, organised by the question you are trying to answer rather than by where they live on disk. Every artefact has two columns that matter more than its path: what it **proves**, and what it **does not**.
>
> Analysing copies of media you own or are authorized to examine. This sheet is a lookup table; the analytical method is in `../methodology/05-windows-artifact-forensics.md`, the tooling in `../tools/windows-artifact-tools.md`, and the per-source ceilings in `evidence-validity.md`. The event-ID-oriented view of the same territory, from a hunting angle, is in `../../eCTHP/cheatsheets/windows-artifacts.md`.

**Conventions used below**

- **An artefact proves a category of claim, not a verdict.** Prefetch proves execution. ShimCache proves presence. A LNK file proves someone touched a file through the shell. Confusing the three is the classic analytical error.
- **Every artefact has a lifecycle.** The last section tells you what destroys each one; "no entry" means nothing until you have shown the artefact was capable of recording the event.
- **Timestamps are claims by the host's clock.** Validate the clock before you build a sequence (`evidence-validity.md` §3).
- **Parse hives with their transaction logs.** A hive extracted from a dirty shutdown can be stale on disk until `.LOG1`/`.LOG2` are replayed.
- **Parser names below are pointers, not invocations.** Confirm names and switches on your install; see `../tools/windows-artifact-tools.md`.

---

## 1. "What executed?"

| Artefact | Where | Proves | Does **not** prove | Parser | Notes |
| --- | --- | --- | --- | --- | --- |
| Prefetch | `C:\Windows\Prefetch\<NAME>-<HASH>.pf` | That the program ran, with run count and last-run times; files/volumes touched in its first seconds | The path it ran from (use the referenced-paths list) | `PECmd` | Client editions with prefetch enabled; bounded cache — absence is weak |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | That a binary was inventoried, with path, file metadata and often a SHA-1 | Execution | `AmcacheParser` | Compatibility inventory, not an execution log; structure varies by Windows version |
| ShimCache / AppCompatCache | `SYSTEM` hive, `...\Control\Session Manager\AppCompatCache` | That a binary was known to the compatibility infrastructure; can survive after the file is gone | Execution, on any version | `AppCompatCacheParser` | Older versions record files that were merely *seen*; treat the execution flag as a hint |
| UserAssist | `NTUSER.DAT`, `...\Explorer\UserAssist\{GUID}\Count` | That a **user profile** launched a GUI program via the shell, with counts and times (names ROT13-encoded) | Console tools, services, scheduled tasks, prompt-started scripts | `RECmd`, `RegRipper` | User-writable; corroborate before relying on it alone |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | Per-application resource use, including network bytes, keyed to a user SID | Who was at the keyboard; that bytes moved = exfiltration | `SrumECmd` | Roughly a month of retention by default |
| Process creation events | `Security` (`4688`), Sysmon channel | That a process started, with command line (policy-dependent), parent and account | Anything on a host where auditing/Sysmon was not configured before the event | `EvtxECmd`, Hayabusa, Chainsaw | The most legible execution evidence and the easiest to lose |
| PowerShell script block log | `Microsoft-Windows-PowerShell/Operational` | The script code that executed, including decoded and in-memory | Interactive keystrokes; other script hosts | `EvtxECmd` | Requires the policy to have been enabled |
| MFT / USN journal | `$MFT`, `$UsnJrnl:$J` | That a binary **existed**, was created or renamed, and when | That it ran | `MFTECmd`, Sleuth Kit | The pair that survives when caches were cleared |
| LNK / jump list | `...\Recent\`, `AutomaticDestinations` | That a file was opened through the shell / per-application recency | Execution of a program | `LECmd`, `JLECmd` | User interaction, not execution |

**The ranking that matters:** Prefetch and process-creation events > Amcache > ShimCache. Prefetch and a process-creation event are the two that prove execution; Amcache is an inventory and ShimCache is the weakest of the three. Use them in that order of weight, and prefer two of them agreeing over one of them alone.

## 2. "What would run again?" — persistence

| Mechanism | Configuration artefact | Log evidence of setup | Parser | Removal leaves |
| --- | --- | --- | --- | --- |
| Run / RunOnce | `SOFTWARE` and per-user `NTUSER.DAT`, `...\CurrentVersion\Run*` | Sysmon registry events (12/13/14); no native Security event by default | `RECmd`, `RegRipper` | Key last-write time; deleted-key remnants in hive slack |
| Services | `SYSTEM` hive, `Services\<name>` | `7045` (System), `4697` (Security, with auditing) | `RECmd`, `RegRipper` | Service key timestamps; the stored binary path even if the file is gone |
| Scheduled tasks | `C:\Windows\System32\Tasks\*.xml` + TaskCache registry | `106` (TaskScheduler/Operational), `4698` (Security, with auditing) | `RECmd`, `EvtxECmd` | XML file timestamps; one of the pair surviving without the other is a tampering signal |
| WMI event subscription | WMI repository | Sysmon 19/20/21; WMI-Activity/Operational | — (collect the repository) | Repository entries; not plain text — collect, do not hand-edit |
| Startup folder / logon scripts | Startup directories; Group Policy scripts | File creation events; Group Policy operational logs | Sleuth Kit, `LECmd` | Shortcut metadata; the LNK's own target |
| Image File Execution Options | `SOFTWARE`, `...\Image File Execution Options\<exe>` | Sysmon registry events | `RECmd` | Key last-write time; a `Debugger` value pointing elsewhere |
| Winlogon / AppInit_DLLs | `SOFTWARE` / `SYSTEM` autostart values | Sysmon registry events | `RECmd`, `RegRipper` | Key last-write time; value content |
| COM hijacking | `Classes\CLSID\{...}\InprocServer32` | Sysmon registry events | `RECmd` | The rewritten path and its timestamp |
| Accessibility binaries (e.g. `sethc.exe`) | The file in `System32` | File write events; `$MFT` | Sleuth Kit, `MFTECmd` | File timestamps versus the OS build's expected values |
| BITS jobs | The `qmgr` database | BITS-Client operational log | — | Job database, which records the remote URL and local file |
| Netsh helpers / port monitors / print processors | Respective registry keys | Sysmon registry events | `RECmd` | Key last-write times; the referenced DLL path |

Method reminders: survey **mechanisms** (a checklist of locations), not a filename; timestamp the configuration and compare it with the first suspicious execution; look for the configuration *and* the file-system record of the executable being written; and check the alternate control sets before declaring a survey complete.

## 3. "What did a user do?"

| Artefact | Where | Proves | Does **not** prove | Parser |
| --- | --- | --- | --- | --- |
| Shellbags | Per-user `UsrClass.dat`, `...\Shell\BagMRU` | That a user browsed a folder through Explorer — **including folders and volumes that no longer exist** | That they opened a file in it; that a program ran | `SBECmd` |
| LNK files | `...\Recent\` and friends | That a file was opened via the shell; the target's path and the target's timestamps | The user's action time (read the LNK's *own* file timestamps for that) | `LECmd` |
| Jump lists | `...\Recent\AutomaticDestinations\` | Recently opened items per application, with access times and counts | That the file still exists | `JLECmd` |
| RecentDocs / MRU / TypedPaths | `NTUSER.DAT` | Interactive use of files and typed paths | Execution; intent | `RECmd` |
| Browser databases | Profile `History`, `places.sqlite`, `Cookies` | Visits, downloads with source URL **and target path**, searches, form data | That the person at the keyboard was the account owner; private-browsing activity | `sqlite3`, Autopsy |
| Recycle Bin | `$Recycle.Bin\<SID>\$I…` (metadata) and `$R…` (data) | That a file was deleted through the shell, with its **original path and deletion time** | Deletion by other means (`Shift`+`Delete`, applications, network shares); that the user did it | `RBCmd`, Sleuth Kit |
| Timeline activities | Per-user ActivitiesCache database | Application and document activity recorded by the Timeline feature | Anything on a build where the feature was disabled | `WxTCmd` |
| Focus / usage counters | UserAssist values | That a GUI program was launched repeatedly, with focus time | The person involved | `RECmd` |

Separating a person from automation: logon type 2/10 (interactive/RDP) supports a human session; scheduled tasks, services and logon scripts support automation. UserAssist entries and shell-created LNK files point at the shell; task XML and service keys point at the machine. State the action you can prove, and label any statement about intent.

## 4. "What happened to files?"

| Question | Artefact | Proves | Caveat |
| --- | --- | --- | --- |
| Did the file exist? | `$MFT` record, directory entry | Existence, size, attributes, timestamps | A deleted record can be reused |
| When was it created? | `$STANDARD_INFORMATION` and `$FILE_NAME` created times | Two claims, which may disagree | Forged or copied times; disagreement = investigate |
| Was it renamed or moved? | `$UsnJrnl` reason codes, `$LogFile` | A rename/move operation with a time | Journal is finite, and can be deleted |
| Was it written or deleted? | `$UsnJrnl` reason codes | A write/delete operation with a time | Not *who*, only what |
| What was in it? | Cluster content, resident data, slack | Bytes existed at a location | Fragmentation; reuse; compression/encryption hide content |
| What did it look like before? | Volume shadow copies / snapshots | A previous version of the file | Snapshot intervals; tool support varies |
| Was it deleted through the shell? | Recycle Bin `$I` file | Deletion with original path and time | Absence proves nothing — many deletions bypass the bin |
| Was it copied out? | `$UsnJrnl` + destination-side evidence + logs | That a file operation occurred here; where it went requires the other side | The source host does not record the destination by itself |
| Is there hidden content? | Alternate data streams (a `:` in the name field) | Data attached to a file | Ordinary copies and most GUIs silently drop streams |

## 5. "What was installed or used?"

| Artefact | Where | Proves | Caveat |
| --- | --- | --- | --- |
| Uninstall entries | `SOFTWARE`, `...\Uninstall\*` | Product name, publisher, install location, sometimes an install date | The date field is frequently absent or approximate |
| MSI installer data | `SOFTWARE` installer keys | Installation records for MSI packages, with an owning SID | Only MSI-installed software |
| MUICache / AppCompat PCA | `NTUSER.DAT` | That a program has been interacted with by a profile | Weak on its own; corroborate |
| Prefetch referenced paths | `.pf` contents | Files, DLLs and volumes touched in the program's first seconds | Only the first seconds |
| SRUM | `SRUDB.dat` | Per-application CPU/network/energy use with a user SID | Short retention; dense output |
| ShimCache / Amcache | See §1 | Presence and identity of binaries | Not execution |
| Services and drivers | `SYSTEM` hive; `7045`/`4697`; Sysmon driver-load events | What was installed as a service or driver, and its path | Driver loads require Sysmon or driver-verification logging |

## 6. "Who was logged on, and what did they connect to?"

| Question | Artefact | Proves | Caveat |
| --- | --- | --- | --- |
| Who authenticated, how, from where? | `Security` `4624`/`4625`/`4634`, `4648`, `4672` | A logon attempt or success with a logon type and source address | Requires the audit policy; logon type distinguishes interactive from network from service |
| Which sessions held privileges? | `4672` | That a new logon carried special privileges | Tied to a `LogonId`, not to a person |
| Remote interactive access? | Terminal Services operational channels | RDP session lifecycle, including reconnects | Does not say what was done in the session |
| Which USB devices were attached? | `SYSTEM` hive `USBSTOR`, `MountedDevices` | Device connection history with serial numbers | Does not show file copies (look to the file system and the USN journal) |
| Which network shares were accessed? | `5140`/`5145` (with object-access auditing), Sysmon network events | Share and file access by an account | Requires auditing; payload content is not recorded |
| What did a process connect to? | Memory (`netscan`), Sysmon network events, host firewall logs | That a process had a connection, with the owning PID | Untrusted-address ≠ malicious; confirm intent elsewhere |

## 7. Where the artefacts live — path and hive quick reference

```text
SYSTEM HIVES (C:\Windows\System32\config\)
  SYSTEM     services, drivers, USB device history, control sets, ShimCache
  SOFTWARE   installed programs, autoruns for the machine, network configuration
  SAM        local accounts
  SECURITY   policy, cached domain credentials
  (each may have .LOG1/.LOG2 transaction logs beside it — parse with them)

PER-USER HIVES
  C:\Users\<user>\NTUSER.DAT                     UserAssist, RecentDocs, TypedPaths, Run (per user)
  C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat   Shellbags, file associations

FILE SYSTEM ARTEFACTS
  C:\Windows\Prefetch\                            execution (client editions)
  C:\Windows\AppCompat\Programs\Amcache.hve       program inventory with hashes
  C:\Windows\System32\sru\SRUDB.dat               resource usage
  C:\Windows\System32\Tasks\                      scheduled task XML definitions
  C:\Windows\System32\winevt\Logs\                event channels (.evtx)
  C:\Windows\System32\config\                     system hives (as above)
  C:\Windows\INF\setupapi.dev.log                 device installation history
  C:\Windows\System32\LogFiles\                   per-service logs (IIS, WMI, firewall, etc.)
  C:\$Recycle.Bin\<SID>\                          $I metadata and $R data
  C:\System Volume Information\                   volume shadow copies and restore points
  C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\      LNK files, jump lists
  C:\Users\<user>\AppData\Local\ConnectedDevicesPlatform\       Timeline activities database
  C:\Users\<user>\AppData\Local\Microsoft\Windows\WebCache\     browser/OS web cache
```

> Confirm the exact subdirectory on your target build. Microsoft moves per-user paths between Windows versions, and a path copied from a blog post is a common source of an empty result. When a path is wrong, `fls -r -p` piped into a case-insensitive filter finds the artefact by name.

## 8. What destroys each artefact

| Artefact | Lifetime | Destroyed by | Absence therefore means |
| --- | --- | --- | --- |
| Prefetch entries | Weeks to months, bounded by cache size | Cache rollover, cleanup tools, deliberate deletion, feature updates | Little, unless the cache is otherwise populated |
| Amcache | Long-lived | Hive deletion, OS reinstall | Weak — a cleaned machine resembles a fresh one |
| ShimCache | Persists in the hive, capped | Clearing; hive replacement | Weak to moderate |
| `$UsnJrnl` | Days to weeks on a busy volume | Journal deletion, rollover | Moderate — cite its earliest retained record |
| `$LogFile` | Small, short window | Rollover | Weak for anything but very recent activity |
| SRUM | ~1 month | Rollover | Moderate for that window |
| Event channels | Bounded by configured size | Wrapping, `wevtutil cl`, policy change | Weak — always check the oldest retained record |
| Recycle Bin `$I` | Until emptied or overwritten | Emptying, cleanup, `Shift`+`Delete` bypass | Weak |
| Shellbags | Lives with the profile hive | Profile deletion, hive cleanup | Moderate |
| LNK / jump lists | Until cleanup or profile deletion | Recent-items cleanup, "clear history" | Weak |
| Registry deleted keys | Until the hive cell is reused | Further writes to the hive | Moderate when the slack cell survives |
| Volume shadow copies | Until deleted or space pressure | Deletion of the snapshot set | Weak — but say you could not check |
| Memory artefacts | Seconds to hours | Power-off, process exit, paging | Very weak: a snapshot is biased |

## 9. Common Mistakes & Tips

- **Treating ShimCache as an execution log** or Amcache as proof of execution. Use them for presence and identity (paths, hashes), and find execution in Prefetch or process-creation events.
- **Citing a LNK file's embedded timestamps as the access time.** They describe the target file; the LNK's own file-system timestamps are when the shortcut was created.
- **Reading a registry key's last-write time as a value's write time.** Values carry no timestamps of their own.
- **Parsing a hive without its `.LOG1`/`.LOG2`.** A dirty hive on disk can be stale; you may report a key state that never existed.
- **Concluding "no Prefetch, so it did not run".** Prefetch is a bounded cache on client editions with an on/off switch. Show the cache is otherwise healthy, or qualify.
- **Forgetting per-user hives.** Most user-activity artefacts live in `NTUSER.DAT` and `UsrClass.dat`, one per profile. A `SOFTWARE`-only survey misses them.
- **Ignoring the control sets.** Check `Select` and the alternate control sets before declaring a persistence survey complete.
- **Attributing a dropped file to a process.** The file system does not record the creator; attribute through a process event, a Prefetch referenced path, or an application log.
- **Assuming a path from documentation is correct on your build.** Per-user paths move between versions; find the artefact by name when a path comes up empty.
- **Sliding from action to intent.** "Files were deleted during a session owned by this account" is supported; "the user deleted them to destroy evidence" is an inference and must be labelled.
- **Tip:** keep a per-case matrix — artefact, available?, checked?, result, corroborates what. It becomes the methodology section of the report with no extra work.
- **Tip:** hash every artefact you extract and record the extraction command. An extracted hive with no provenance is an unattributable file.

## Checklist / Self-Test

- [ ] For a claim of *execution*, can I name three artefacts that support it and rank them by weight?
- [ ] Can I state which artefacts prove *presence* rather than execution, and why the distinction decides conclusions?
- [ ] Can I explain why shellbags can show a folder that no longer exists anywhere on the volume?
- [ ] Can I state what a Recycle Bin `$I` file adds that an `$MFT` delete record does not?
- [ ] Can I name the persistence mechanism behind a given registry key or task file, and the log event that records its installation?
- [ ] Do I check alternate control sets and all per-user hives in a persistence survey?
- [ ] Can I explain the two NTFS timestamp sets and which operations update each?
- [ ] Can I state, for five artefacts, what destroys them and what their absence therefore means?
- [ ] Do I parse hives together with their transaction logs, and know why that changes conclusions?
- [ ] Can I separate a human session from automation using logon type and launch channel?
- [ ] Do I record which artefacts I checked and found empty?
- [ ] For every finding, can I name the primary artefact and one independent corroborating artefact?

## Further Resources

- **Eric Zimmerman's forensic tools** (parsers named throughout: `PECmd`, `AmcacheParser`, `AppCompatCacheParser`, `MFTECmd`, `LECmd`, `JLECmd`, `RECmd`, `SBECmd`, `SrumECmd`, `RBCmd`, `WxTCmd`, `EvtxECmd`) — https://ericzimmerman.github.io/
- **RegRipper** (offline registry parsing and plugin set) — https://github.com/keydet89/RegRipper3.0
- **The Sleuth Kit** (`fls`, `istat`, `icat`, `ils`, `blkls`) — https://www.sleuthkit.org/sleuthkit/
- **Microsoft — Windows security auditing and event reference** (the authority for the events referenced here) — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings
- **Forensics Wiki** (per-artefact references, version differences, and known limitations) — https://forensics.wiki/
- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- The eCTHP module's own artefact sheet, from a hunting perspective — `../../eCTHP/cheatsheets/windows-artifacts.md`

> **Verification:** checked against primary sources in this repository, not executed — **no command
> in this sheet was run**. The ranking in section 1 was corrected on **2026-09-19** against the
> artefact table immediately above it (Prefetch "proves: that the program ran"; Amcache "proves:
> that a binary was inventoried — does not prove: execution"; ShimCache "proves: that a binary was
> known to the compatibility infrastructure — does not prove: execution") and against
> `../methodology/05-windows-artifact-forensics.md` §1, whose evidential ladder names Prefetch and
> process creation as the strongest evidence for "the program executed" and ShimCache as not
> sufficient on its own. The operator in the previous wording was inverted relative to both.
