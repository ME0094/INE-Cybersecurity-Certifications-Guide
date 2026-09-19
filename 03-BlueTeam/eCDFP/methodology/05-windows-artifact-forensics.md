# Windows Artifact Forensics — Execution, Persistence, Resource Use & User Activity (eCDFP Methodology — Phase 05)

> Companion study guide for the eCDFP (Certified Digital Forensics Professional) Blue Team methodology track. Phase 02 walks the file system; this deep-dive phase covers the Windows-specific artefacts that live *on top of* it, organised by the question they answer, so you can move from "this file exists" to "this program ran, under this account, at this time, and something made it start again."
>
> Where this phase sits: it is a companion to Phase 02 (analysis) and a feeder for Phase 03 (timeline). Read Phase 02 first — an interpreter of Windows artefacts who cannot read an MFT entry will misattribute half of what they find.
>
> Every command in this file is a **syntax reference**. This repository ships no captured command output: there is no Windows image, no hive and no parser on the machine that wrote it. Where a command would print a result, the text says what to look for. Confirm flags against `--help` or the manual page for the version you install.

## Overview

The file system tells you what is *there*. Windows artefacts tell you what *happened*. They are the difference between an inventory and an investigation, and they are the reason a Windows case is won or lost on interpretation rather than on tooling.

Four question domains organise everything in this phase:

| Domain | The question | Representative artefacts |
| --- | --- | --- |
| **Execution** | What ran? | Prefetch, Amcache, ShimCache/AppCompatCache, UserAssist, SRUM, process-creation events |
| **Persistence** | What makes it run again? | Run keys, services, scheduled tasks, WMI subscriptions, startup folder, logon scripts |
| **Resource use** | What did it touch, consume, and connect to? | SRUM, Prefetch referenced files, Amcache, `$UsnJrnl` for file operations |
| **User activity** | What did a *person* do? | Shellbags, LNK files, jump lists, RecentDocs/MRU, browser databases, Recycle Bin, Timeline |

Three principles govern the whole phase:

1. **Every artefact has a ceiling on what it can prove.** Prefetch proves execution. ShimCache proves presence. A LNK file proves somebody touched a file through the shell. Confusing these three is the most common analytical error in Windows forensics, and it is the error that turns a lead into a false conclusion.
2. **Corroborate or qualify.** One artefact is a lead; two independent artefacts that would each have to be wrong in the same direction are a finding. Where you have one, say so.
3. **Prove the source before you trust an absence.** "No prefetch entry" is meaningless until you know prefetch was enabled, not cleared, and not reset by a feature update. Absence is a conclusion you are allowed to draw only after you have demonstrated the artefact's lifecycle.

## 1. The evidential ladder

Before you open a parser, decide which claim you are trying to support. The artefacts available to you depend on it.

| Claim | Strongest evidence | Supporting evidence | Does **not** prove it |
| --- | --- | --- | --- |
| The file was present on disk | `$MFT` record; `$UsnJrnl` entry | ShimCache entry; an Amcache file entry | Nothing about execution |
| The program executed | Prefetch entry (with run count); Sysmon/4688 process creation; Amcache execution entry | UserAssist; SRUM | LNK files, jump lists, ShimCache alone |
| The program executed repeatedly | Prefetch run count + several last-run timestamps; repeated process-creation events | SRUM per-application data | A single event |
| A user launched it interactively | UserAssist (Explorer-launched GUI) + logon type 2/10 at that time | LNK file created at launch; jump-list entry | Prefetch (services and tasks execute too) |
| A user interacted with a *file* | LNK file plus jump-list entry plus an MRU/recent entry | Shellbag node timestamp for the containing folder | `$MFT` access times (unreliable) |
| Persistence was configured | The configuration artefact itself (registry value, task XML, service key) | Installation event (`7045`/`4697`), Sysmon registry event | That it ever executed |
| Persistence executed | Process creation for the persisted binary, with the parent being the persistence mechanism | Prefetch for that binary | The bare existence of a Run key |
| A file was deleted | `$MFT` record marked unallocated; `$UsnJrnl` delete record; Recycle Bin `$I` file | Directory entry in slack | That the *user* deleted it (as opposed to a program, a cleanup tool, or an installer) |

> Notice how many rows end in "does not prove". That column is the point of the table. Write your conclusion at the level your strongest artefact supports, then state what would be needed to raise it.

## 2. Establish the baseline before you interpret anything

An artefact is only interesting relative to what the machine normally looks like. Before you chase a finding, answer four questions about the *system*, not the suspect:

1. **Which Windows edition and build?** Artefact availability depends on it. Prefetch is present on client editions and typically disabled on servers. ShimCache entry semantics and the presence of an execution flag differ across Windows 8, 10 and 11. The Windows 10 Timeline database only exists where the feature was enabled.
2. **Was the artefact's subsystem collecting?** Prefetch can be disabled by policy or by the SysMain service being off. Process-creation auditing (`4688`, with command lines) must have been enabled *before* the activity. PowerShell script block logging likewise. If the policy was off, the evidence does not exist and never did.
3. **Was the artefact cleared, reset, or rolled over?** Prefetch entries are deleted by cleanup utilities and by some "optimisers"; ShimCache can be cleared; the `$UsnJrnl` can be deleted (`fsutil usn deletejournal`) or overwritten as it grows; SRUM's ESE database retains roughly a month by default; the Security log wraps at its configured size. Each of these has a signature — see `../labs/anti-forensics-lab.md`.
4. **What is the machine's clock story?** Time zone, offset from real time, and whether it is synchronised. Without this, every timestamp in this phase is a guess with decimal places.

A practical order that answers all four cheaply:

```bash
# From an image, first establish geometry and file system (Phase 02)
mmls /evidence/case-01/evidence/disk.dd          # partition offsets
fsstat -o 2048 /evidence/case-01/evidence/disk.dd # file system type, label, cluster size
# What to look for: the NTFS partition's start sector, and the volume serial number —
# record both, because the volume serial appears inside several artefacts later.

# Then extract the artefact corpus you need — do NOT mount the image.
# List candidate paths, then pull the files out by meta address.
fls -o 2048 -r -p /evidence/case-01/evidence/disk.dd | grep -iE 'prefetch|AppCompat|sru|winevt|config/SYSTEM|NTUSER'
# What to look for: the meta (inode/MFT) address in the first column for each path
# you want. That address is what icat takes next.

icat -o 2048 /evidence/case-01/evidence/disk.dd <meta-address> > /evidence/case-01/exports/SYSTEM
```

> A hive, a `.pf` file or an `SRUDB.dat` extracted this way is a **copy**. The image remains the exhibit. Record the `icat` command, the meta address and the hash of what you extracted, so another examiner can reproduce the extraction exactly.

## 3. Execution evidence

Work these in descending order of reliability, and note the ceiling of each.

### 3.1 Prefetch — the strongest execution artefact on a client

**What it is.** A per-program record kept by the prefetcher (SysMain) to speed up subsequent launches: `C:\Windows\Prefetch\<NAME>-<HASH>.pf`. The hash is derived from the executable's full path, which is why the same binary in two locations produces two files — a useful pivot.

**What it gives you.** The executable name, the run count, several last-run timestamps, the paths of files and libraries loaded during the first seconds of execution (including volumes and devices touched), and the file's own creation time.

**Limits — state these in the report, not in your head:**

- **Client editions only, and only if enabled.** Servers normally have prefetch off. A missing entry on a server tells you nothing.
- **The file name is not the run path.** `NAME-HASH.pf` gives you the executable name and a path-derived hash; to claim a path you need the referenced-paths list or a corroborating artefact.
- **Absence is weak evidence.** Prefetch is a cache, not a log. Entries are deleted by the OS when the cache is full, by cleanup tools, by some feature updates, and by hand (see `../labs/anti-forensics-lab.md`). An old program with no prefetch entry has simply aged out.
- **Volume-referenced paths.** On a system where the executable ran from removable media, the referenced paths may point at a volume that is no longer attached; interpret them as device-relative, not as a current path.

```powershell
# Parse a directory of .pf files extracted from the image
PECmd.exe -d "C:\case\exports\Prefetch" --csv "C:\case\reports" --csvf prefetch.csv
# What to look for: one row per .pf with a run count and last-run timestamps; a
# run count greater than one means repeated execution, not a single accidental launch.
# Confirm the exact switch names with PECmd.exe --help on your build.

# A single file is often enough for triage
PECmd.exe -f "C:\case\exports\Prefetch\SOMEPROG.EXE-1234ABCD.pf"
```

### 3.2 Amcache — program inventory with hashes

**What it is.** A registry hive at `C:\Windows\AppCompat\Programs\Amcache.hve`, maintained by the application-compatibility infrastructure. It records information about programs the system has inventoried, including executable paths, file metadata, and (on modern Windows) SHA-1 hashes.

**What it gives you.** A hash for a binary you may no longer have, a path, and first/last modification times. The hash is the single most valuable thing here: it lets you pivot to other hosts, to intelligence, and to a disk-wide search for the same content under a different name.

**Limits.** Amcache is a compatibility inventory, **not an execution log**; entries can exist for programs the system inspected but never ran. It is not created for everything, and its structure differs across Windows versions, which is why the parser version matters as much as the hive.

```powershell
# Parse the hive out of the image-exported copy
AmcacheParser.exe -f "C:\case\exports\Amcache.hve" --csv "C:\case\reports"
# What to look for: SHA-1 values and full paths for binaries of interest. A hash lets
# you prove identity across renames; a path alone does not.
```

### 3.3 ShimCache / AppCompatCache — presence, not execution

**What it is.** A cache inside the `SYSTEM` hive (under `ControlSet00X\Control\Session Manager\AppCompatCache`) recording executables the compatibility infrastructure has seen, with a last-modified timestamp.

**What it gives you.** Corroboration that a binary was present on the volume, and — on Windows 8 and later — a flag that the entry was recorded by an execution path. It is valuable precisely because it can survive when the file itself is gone, and because its timestamps are sometimes the only remaining trace of a binary that was deleted.

**Limits — the one to be strictest about.** On older Windows versions, entries were added when a file was *seen* (for example during directory enumeration), not when it ran. **Presence in the ShimCache is not proof of execution** on any version, and you should treat the execution flag as a hint to corroborate rather than as a finding. The cache can also be cleared, and a cleared cache is indistinguishable from a machine with nothing to record.

```powershell
AppCompatCacheParser.exe -f "C:\case\exports\SYSTEM" --csv "C:\case\reports"
# What to look for: paths and last-modified times, plus whatever execution-indicating
# field the parser exposes for that hive version. Read the parser's own documentation
# for how it labels that field rather than assuming a column name.
```

### 3.4 UserAssist — GUI launches, attributed to a user

**What it is.** Per-user data in `NTUSER.DAT` under `...\Explorer\UserAssist\{GUID}\Count`, with names ROT13-encoded. It records programs launched through the Explorer shell, with a run count and a last-execution time.

**What it gives you.** The rare combination of *execution* plus *attribution to a user profile* — and, because the encoder is trivial, it is also one of the artefacts easiest to spot by hand.

**Limits.** Explorer-launched GUI programs only: console tools, services, scheduled tasks and scripts started from a command line frequently leave nothing here. The data is user-writable, so it can be forged; treat it as strong when it agrees with an independent artefact and as a lead when it stands alone.

### 3.5 SRUM — resource usage over time

**What it is.** The System Resource Usage Monitor database, an ESE database (typically `C:\Windows\System32\sru\SRUDB.dat`) recording per-application resource consumption: network bytes sent and received, energy usage, and application activity, keyed to user SIDs.

**What it gives you.** A behavioural fingerprint for two questions nothing else answers well: *how much data did this process actually move*, and *which user account owned the process*. Byte counts per application over time are how you distinguish a program that opened a socket from one that exfiltrated gigabytes.

**Limits.** Retention is short (roughly a month by default) and the database is written incrementally, so the start of an older incident may simply have aged out. Records are dense and easy to over-read: a large byte count is not by itself exfiltration, and the SID tells you whose session hosted the process, not who was at the keyboard.

```powershell
SrumECmd.exe -f "C:\case\exports\SRUDB.dat" --csv "C:\case\reports"
# What to look for: per-application network totals with a user SID, ordered by time.
```

### 3.6 Process-creation events — the most legible evidence, if you have it

Sysmon process creation (Event ID 1) or the Security log's `4688` give you the image path, the command line, the parent image, and the account — usually in one record. They are the easiest artefacts to read and the easiest to lose, because both require a policy that had to be enabled before the event:

- `4688` requires *Audit Process Creation*; the command line inside it requires *Include command line in process creation events*.
- Sysmon requires that it was installed, running, and configured to record the event.

If neither was in place, do not conclude the program did not run — conclude that you cannot see process creation on this host, and fall back to Prefetch, Amcache and UserAssist.

### 3.7 File system artefacts: existence and file operations

`$MFT` and `$UsnJrnl` answer a different question — what the file system did — and they are the backbone of Phase 02 and Phase 03:

- **`$MFT`**: file records, including unallocated ones; resident data may survive after content is gone.
- **`$UsnJrnl`**: change records with reason codes (create, write, delete, rename, data overwrite) and timestamps. This is where you find a `rename` that would otherwise leave no trace, and it is often the artefact that survives when higher-level caches were cleared.
- **`$LogFile`**: the transaction journal, useful for a narrow window and for reconstructing metadata changes.

None of these prove execution. They prove that a file existed, moved, changed or was removed — and that is frequently the more valuable claim.

## 4. Persistence evidence

Persistence answers "what makes this run again", and it leaves a *configuration* artefact even when the payload is gone. That asymmetry is the examiner's advantage: deleting a binary is easy, deniable removal of the mechanism that referenced it is not.

| Mechanism | Where the configuration lives | Log evidence of it being set up | What removal leaves |
| --- | --- | --- | --- |
| Run / RunOnce keys | `SOFTWARE` hive (`...\CurrentVersion\Run`), `NTUSER.DAT` equivalent per user | Sysmon registry events (key/value create/rename); no native Security event by default | Key last-write time; deleted-key remnants in hive slack |
| Services | `SYSTEM` hive `Services\<name>` | `7045` (System), `4697` (Security, with auditing) | Service key timestamps; the installed binary path even if the file is gone |
| Scheduled tasks | Task XML files under `C:\Windows\System32\Tasks\` plus the TaskCache in the registry | `4698` (Security, with auditing), `106` (TaskScheduler/Operational) | The XML file's own timestamps; a task whose XML was deleted but whose TaskCache entry remains, or vice versa |
| WMI event subscription | The WMI repository (`OBJECTS.DATA`) | Sysmon `19`/`20`/`21`; WMI-Activity/Operational | Repository entries, which are not plain text — collect the repository, do not hand-edit it |
| Startup folder | The user's and the all-users Startup directory | File creation events; `$MFT` for the shortcut | The shortcut's own metadata and the LNK it contains |
| Logon / logoff scripts | Group Policy or `...\Group Policy\...\Scripts` | Group Policy operational logs | Policy file timestamps, script contents |
| Image File Execution Options | `SOFTWARE` hive `...\Image File Execution Options\<exe>` | Sysmon registry events | Key last-write time; a `Debugger` value pointing at another binary |
| Winlogon shell/userinit, AppInit_DLLs | `SOFTWARE`/`SYSTEM` hive autostart values | Sysmon registry events | Key last-write time; the value content itself |
| COM hijacking | `HKCU`/`HKLM` `Classes\CLSID\{...}\InprocServer32` | Sysmon registry events | The rewritten `InprocServer32` path and its timestamp |
| Accessibility binaries (e.g. `sethc.exe` replaced) | The file itself in `System32` | File creation/write events; `$MFT` | The file's timestamps versus the OS build's expected values |
| BITS jobs | `qmgr` database files | BITS-Client operational log | The job database, which records the remote URL and local file |
| Netsh helper DLLs, port monitors, print processors | Registry under the respective subsystem keys | Sysmon registry events | Key last-write times; the referenced DLL path |

Method, in order:

1. **Survey the mechanisms, not the binaries.** A complete persistence survey is a checklist of locations, not a search for a filename. A scan for a known-bad name finds only what you already knew about.
2. **Timestamp the configuration.** A Run key whose last-write time sits two minutes before the first suspicious process creation is a different artefact from one written three years ago by an installer.
3. **Look for the pair.** Persistence mechanisms appear in at least two places: the configuration, and the file system's record of the executable being written. Find both, or explain which one is missing and why.
4. **Handle deleted mechanisms deliberately.** A deleted task XML with a surviving TaskCache entry (or the reverse) is a strong tampering signal. Recovering deleted registry keys requires parsing hive slack, not the live key tree — see §7.

Cross-reference: `../cheatsheets/windows-artifacts.md` maps each mechanism to its artefact and its caveat; `../tools/windows-artifact-tools.md` covers the parsers.

## 5. Resource use, program inventory and what a binary touched

These artefacts answer capacity and behaviour questions rather than existence questions, and they are under-used.

| Question | Artefact | What it can tell you | Caveat |
| --- | --- | --- | --- |
| Which programs were installed, and when? | `SOFTWARE` hive uninstall entries; MSI installer data | Product name, publisher, install location, and an install date for many products | The install date field is often absent or a rounded value; an installer's own date is not the date the program first ran |
| What did a program load when it started? | Prefetch referenced files | DLLs, data files, and volumes touched in the first seconds | Only the first seconds; only the recorded subset |
| How much network traffic did a process generate? | SRUM per-application network data | Bytes sent/received per application per hour | Roughly a month of retention |
| What user session owned a process? | SRUM records with a SID | Attribution of resource use to an account | The session owner, not the person at the keyboard |
| Which files were created, written, renamed or deleted? | `$UsnJrnl` reason codes | File operations with timestamps, including renames | The journal is finite and can be deleted or overwritten |
| What did a program leave behind as a side effect? | `$MFT` for created files; `$UsnJrnl` for the sequence | Drop locations, staging directories, log files | Creation proves a file appeared, not which process made it |

That last row deserves a warning: **the file system does not record which process created a file.** Attribution of a dropped file to a process requires a process-creation event, a Prefetch referenced-path entry, an application log, or a memory artefact. Where you cannot attribute, say "a file was created at T" rather than "the malware created it at T".

## 6. User activity and intent

This domain is where a technical finding becomes a defensible statement about people, and therefore where the standard of proof is highest.

### 6.1 Shellbags — folders a user browsed

Shellbags live in the per-user `UsrClass.dat` hive (`...\Shell\BagMRU` and `...\Shell\Bags`) and record the shell items a user opened through Explorer, with timestamps on the BagMRU nodes.

Their distinctive value: **shellbags retain entries for paths that no longer exist.** A folder that was deleted, a USB volume that was unplugged, a network share that is gone — the shellbag record can outlive all of them. That makes shellbags one of the best artefacts for questions about *browsing behaviour* rather than file content.

Limits: they record Explorer navigation, not file opens; the volume-relative shell items need their GUIDs resolving to become readable paths; and a roaming or newly created profile has almost nothing in it.

### 6.2 LNK files and jump lists — what a user touched

- **LNK files** (`%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\`, plus other locations such as the Office recent folder) are created when a file is opened through the shell. They embed the target's path, its size, and timestamps copied from the *target* — which is a well-known source of confusion, because a LNK's embedded timestamps describe the file it points at, not the moment the shortcut was made. The LNK file's own `$MFT` timestamps are what tell you when it was created.
- **Jump lists** (`...\Recent\AutomaticDestinations\<AppID>.automaticDestinations-ms` and the `CustomDestinations` equivalent) record recently opened items per application, keyed by an application ID. The destination list carries its own access times and, in AutomaticDestinations, an access count.

Both prove **user interaction with a file**, not execution of a program. They are frequently the artefact that shows a document was opened when the application's own logs are gone.

### 6.3 Recent documents, typed paths and MRU lists

`RecentDocs`, the `ComDlg32` open/save MRU lists, `TypedPaths` (paths a user typed into Explorer's address bar), and the per-application `RunMRU` entries (including `cmd.exe`'s or PowerShell's typed history where it is preserved) all corroborate interactive use. Treat them as supporting evidence: they are numerous, individually weak, and easy to over-read.

### 6.4 Browser and application databases

Chromium-family browsers keep `History` (with `urls`, `visits`, `downloads`), `Cookies`, and `Login Data`; Firefox keeps `places.sqlite` (`moz_places`, `moz_historyvisits`), `cookies.sqlite`, and `formhistory.sqlite`. These databases record downloads with the source URL and the *target* path, which is often the cleanest link between a browsing action and a file that later appeared on the disk.

Two rules: **copy the database out of the image and query the copy**, never a live one, and **search for the deleted rows too** — the SQLite freelist may still hold pages for history the user cleared.

### 6.5 Recycle Bin — deletion, with the user's original path

On Windows Vista and later, `$Recycle.Bin\<SID>\` holds `$R…` files (the original data) and `$I…` files (metadata: the original full path, the deletion time, and the size). The `$I` file is the artefact that matters: it gives you a *deletion* event with a *path* and a *time*, which is exactly what a "what happened to this file" question needs.

Limits: `Shift`+`Delete`, deletions by applications, and deletions on network shares bypass the Recycle Bin entirely — so the absence of a `$I` file is not evidence that nothing was deleted. Each user SID has its own bin; enumerate all of them.

### 6.6 Separating a person from a program

This is the question that most often decides whether a report accuses someone, so answer it with evidence rather than inference:

| Signal | Supports "a person did this" | Supports "automation did this" |
| --- | --- | --- |
| Logon type at the time (`4624`) | 2 (interactive) or 10 (RDP) | 4 (batch) or 5 (service) |
| Launch channel | UserAssist entry; Explorer-created LNK; jump-list entry | Scheduled task, service, Run key, logon script |
| Timing pattern | Irregular, clustered around working hours, with idle gaps | Precise intervals; activity while no session is interactive |
| Corroborating artefacts | Browser history, typed paths, recent documents, shellbags | Task XML, service key, WMI subscription |
| Focus/usage counters | UserAssist focus time and count | Absent |

And the discipline: state the *action* you can prove ("the account was used interactively at 14:02 UTC and 40 files were deleted from this folder"), and label any statement about intent or identity as an inference with its confidence. "The user deleted the files" is a different claim from "the files were deleted during a session owned by that account", and only one of them is supported by the artefacts above.

## 7. The registry as an evidence source

Registry artefacts earn their own section because examiners lose cases by parsing hives naively.

**Where the hives live on disk.** System hives sit under `C:\Windows\System32\config\` (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`); per-user hives are `NTUSER.DAT` in each profile and `UsrClass.dat` under the user's `AppData\Local\Microsoft\Windows\`. Extract them with `icat` from the image; never parse a hive from a live system when the evidence is a dead image.

**Parse the hive with its transaction logs.** Hives are accompanied by `.LOG1` and `.LOG2` files. If the hive was not shut down cleanly, the current tree on disk may be *stale*: the newest writes can still be sitting in the transaction logs. A parser that ignores the logs can report a key state that never existed at acquisition time. Use a parser with explicit dirty-hive recovery, and extract the log files alongside the hive.

**Understand what a timestamp means.** A registry key carries a last-write time; individual values do **not** carry their own timestamps. Therefore "the Run value was written at T" is shorthand for "some write to that key happened at T", and the value's *content* may predate it. Wherever an artefact needs value-level precision, look for a second source.

**Deleted keys and slack.** Removing a key frees its cell inside the hive without erasing the bytes. Parsers that expose hive slack and unallocated cells can recover deleted key names and partial value data — which is how you demonstrate that a persistence key was *removed* rather than never present. This is one of the clearest tampering signals available offline, and it is invisible to any tool that only reads the live key tree.

**Know the alternate control sets.** The `SYSTEM` hive contains `ControlSet001`, `ControlSet002`, and a `Select` key naming which one is current and which is the last-known-good. A persistence mechanism present only in a non-current control set is a different finding from one in the active set, and the difference matters.

## 8. Proving a negative without fooling yourself

Every artefact in this phase has a lifecycle. Before you write "there is no evidence that X happened", walk the lifecycle for each artefact you checked:

| Artefact | Typical lifetime | What destroys it | What its absence therefore means |
| --- | --- | --- | --- |
| Prefetch entries | Weeks to months, bounded by cache size | Cache rollover, cleanup tools, deliberate deletion, feature updates | Little, unless you have shown the cache is otherwise populated |
| Amcache | Long-lived; survives many cleanups | Deliberate deletion of the hive; OS reinstall | Weak; a cleaned machine looks identical to a fresh one |
| ShimCache | Persists in the hive, capped in size | Clearing; hive replacement | Weak to moderate |
| `$UsnJrnl` | Days to weeks on a busy volume, bounded by size | Journal deletion; rollover; rollback | Moderate; note the journal's *earliest* retained record and cite it |
| SRUM | Roughly a month | Rollover | Moderate for that window |
| Security log | Bounded by configured size | Wrapping; `wevtutil cl`; clearing events | Weak; always check the log's oldest retained timestamp |
| Recycle Bin `$I` files | Until emptied or overwritten | Emptying; manual cleanup; `Shift`+`Delete` bypasses it | Weak |
| Registry deleted keys | Until the cell is reused | Further writes to the hive | Moderate when the slack cell is intact |

Then apply the test that matters: **was this artefact capable of recording the thing I am asking about?** A prefetch check on a server, a `4688` check where auditing was never enabled, a browser-history check on a machine with no browser profile — all three produce an empty result that means nothing at all.

## 9. Choosing the order of examination

A repeatable decision procedure, so your artefact work is driven by the question rather than by the tool you happen to like:

1. **Write the question as a claim you could falsify.** "The user opened the payroll spreadsheet" is testable; "the user exfiltrated data" is a conclusion looking for support.
2. **Classify the claim** using the ladder in §1, and pick the strongest artefact class that answers it.
3. **Check the artefact's preconditions** (§2): was it collecting, on this edition, with these policies, in this window?
4. **Take the cheapest sufficient artefact first.** A prefetch parse before a full super-timeline; a `$I` file before carving unallocated space.
5. **Require corroboration for anything that will become a finding**, and record which artefact is primary and which is supporting.
6. **When the strongest artefact is missing, move one step down the ladder and say so** — "prefetch is unavailable on this server, so execution is inferred from the service start event and the binary's MFT record" is a complete, defensible sentence.
7. **Write the artefacts you checked and found nothing in.** The list of negative checks is what proves your examination was thorough, and it is what stops the next examiner repeating your work.

## Common Mistakes & Tips

- **Treating ShimCache as an execution log.** It is a presence cache. On older Windows versions entries appear without execution, and even on modern versions the flag is a hint to corroborate.
- **Treating an Amcache entry as proof of execution.** It is a compatibility inventory. Use it for paths and hashes, then find the execution elsewhere.
- **Citing a LNK file's embedded timestamps as the time of access.** Those timestamps describe the *target* file. The LNK's own file-system timestamps are when the shortcut was created.
- **Parsing a hive without its `.LOG1`/`.LOG2`.** A dirty hive on disk can be stale; you may report a key state that never existed at the moment of acquisition.
- **Reading a key's last-write time as the value's write time.** Values do not carry timestamps of their own.
- **Concluding "no prefetch entry, so it did not run".** Prefetch is a bounded cache on client editions with an on/off switch. Show the cache is otherwise healthy, or qualify the conclusion.
- **Reading the current control set as the whole story.** Check `Select` and the other control sets before declaring a persistence survey complete.
- **Forgetting the per-user hives.** `NTUSER.DAT` and `UsrClass.dat` per profile hold most user-activity artefacts. A survey of `SOFTWARE` alone misses them entirely.
- **Attributing a dropped file to a process.** The file system does not record the creator. Attribute through a process event, a Prefetch referenced path, or an application log — or do not attribute.
- **Sliding from action to intent.** "Files were deleted during a session owned by this account" is supported. "The user deleted the files to destroy evidence" is an inference, and it needs to be labelled as one.
- **Tip:** build a per-case artefact matrix (artefact → available? → checked? → result → corroborates what) and keep it in `notes/`. It becomes the methodology section of your report with almost no extra work.
- **Tip:** hash every extracted artefact and record the extraction command. An extracted hive with no provenance is an unattributable file.
- **Tip:** before you interpret anything, write down the machine's edition, build, time zone and clock offset. Four lines that prevent a category of errors.

## Checklist / Self-Test

- [ ] Can I state, for at least six artefacts, what each one proves and what it does *not* prove?
- [ ] Can I explain why a ShimCache entry and a Prefetch entry have different evidential weight?
- [ ] Can I name the four question domains and give two artefacts for each?
- [ ] Can I extract a hive, `$MFT`, a Prefetch folder and `SRUDB.dat` from an image with `fls` + `icat`, and record the provenance of each?
- [ ] Do I know which hives hold the persistence mechanisms I surveyed, and which per-user hives I still need to check?
- [ ] Can I explain why a hive must be parsed together with its `.LOG1`/`.LOG2` transaction logs?
- [ ] Can I explain what a registry key's last-write time does and does not tell me about a value?
- [ ] Do I know how deleted registry keys can still be recovered, and what that proves?
- [ ] Can I state the retention and destruction behaviour of Prefetch, `$UsnJrnl`, SRUM and the Security log, and does my report cite the earliest retained record of each?
- [ ] Have I written down which artefacts I checked and found empty, so the examination is demonstrably complete?
- [ ] For every finding in my notes, can I name the primary artefact and the independent corroborating one?
- [ ] Am I keeping action claims and intent claims in separate sentences, with the intent claims labelled as inference?

## Further Resources

- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **Eric Zimmerman's forensic tools** (PECmd, AmcacheParser, AppCompatCacheParser, MFTECmd, LECmd, JLECmd, RECmd, SBECmd, SrumECmd) — https://ericzimmerman.github.io/
- **RegRipper** (offline registry parsing) — https://github.com/keydet89/RegRipper3.0
- **The Sleuth Kit** (`fls`, `icat`, `istat`, `mmls`, `fsstat`) — https://www.sleuthkit.org/sleuthkit/
- **Autopsy** (GUI case work over the same engine) — https://www.sleuthkit.org/autopsy/
- **Forensics Wiki** (artefact encyclopedia and per-artefact references) — https://forensics.wiki/
- **Microsoft — Windows security auditing and event reference** (the authoritative source for the events cited above) — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings
- **DFRWS challenge archives** (authorized practice images containing these artefacts) — https://dfrws.org/
