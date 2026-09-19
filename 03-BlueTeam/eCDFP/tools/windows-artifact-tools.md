# Windows Artifact Tools — Parsers, KAPE & Offline Triage

> eCDFP · Tools — INE Cybersecurity Certifications Study Guide
>
> The parsing suite an examiner runs over evidence from a host: Eric Zimmerman's artefact parsers (Prefetch, Amcache, ShimCache, NTFS metadata, LNK, jump lists, registry, EVTX, shellbags, Timeline, SRUM, Recycle Bin) plus KAPE for collecting artefacts and driving those parsers over what was collected.
>
> Every command here is a **syntax reference**: this repository ships no captured command output, no sample artefacts and no parser binaries, and the switch set of every tool below must be confirmed against the installed build's own help. All collection and analysis described here applies only to media you own or are explicitly authorised to examine.

## 1. How this tool family works

Most of the parsers below are **portable .NET executables maintained by Eric Zimmerman**: `PECmd`, `AmcacheParser`, `AppCompatCacheParser`, `MFTECmd`, `LECmd`, `JLECmd`, `RECmd`, `EvtxECmd`, `SBECmd`, `WxTCmd`, `SrumECmd`, `RBCmd`. No installer, no service, no agent: you unpack a release, run the executable, and get a CSV (some also emit JSON). Three properties shape how you use them:

1. **They are offline tools.** The normal mode is to point them at artefacts you already extracted from an image. Running one against a live host is triage, not examination — the source keeps changing and no defensible copy exists afterwards.
2. **They target artefacts, not images.** No parser here opens a disk image. Extracting the file is your job (section 2), and how you extracted it belongs in the case record.
3. **They ride a moving release train.** Artefact formats change with Windows versions, and the parsers chase them.

**The runtime requirement differs per release.** These tools have been built against different .NET generations, and distributions differ too (framework-dependent builds need a runtime present, single-file builds carry it). **Do not trust a runtime version number written here or in a blog post** — read the release notes for the build you downloaded, then let the tool tell you: a missing runtime fails immediately with a message naming what it wants.

**Scope boundaries in this module.** Four sibling files carry the rest: [windows-artifact-forensics](../methodology/05-windows-artifact-forensics.md) holds the analytical method — which question each artefact family answers, the corroboration requirement, and how to state confidence; `../cheatsheets/windows-artifacts.md` is the module's lookup table of artefact path → question → parser → caveat; [forensic-toolkit](forensic-toolkit.md) covers acquisition with `dd`/`dc3dd`/`ewfacquire`, write blockers, integrity hashing and Sleuth Kit; [memory-analysis](memory-analysis.md) covers Volatility and the volatile evidence no on-disk parser here can reach. This file covers the tools themselves: what each produces, the command shape, limitations, and failure diagnosis.

**Evidence discipline applies to tools as much as to acquisition.** Work only under written authorisation naming the systems and scope, keep a chain of custody (who collected what, when, with which tool version, stored where), hash the source and the copy and record both values, and analyse copies with the original sealed — a parser pointed at the wrong path writes CSVs into your evidence tree, and collectors like KAPE write to disk by design. Collect only what the case needs, and treat every artefact as hostile: parse in a disposable VM with snapshots, no shared folders and no network.

> **Switches are volatile.** The shapes below follow the convention these tools share — `-f` for a single file, `-d` for a directory, `--csv <dir>` with `--csvf <name>` for output. Releases rename, add and remove switches, so run each tool's own `-h` (or `--help`) and treat that as the only authority. Where this page is unsure, it says so instead of guessing.

## 2. Getting the artefacts out of an image

Parsers read files, not images. The Sleuth Kit does the extraction without mounting anything: `fls` resolves a path to a **meta address**, and `icat` reads that meta address out to a file. Mounting writes file-system metadata; TSK never does. (Imaging itself — `dd`, `dc3dd`, write blockers, hash verification — belongs to [forensic-toolkit](forensic-toolkit.md).)

```bash
# 1. Geometry: on a whole-disk image you need the NTFS partition offset in sectors
mmls /evidence/case-01/disk.dd
# what to look for: the start sector — every later command takes it as -o

# 2. Resolve artefacts to meta addresses (recursive, with full paths)
fls -o <offset> -r -p /evidence/case-01/disk.dd | grep -Ei 'Amcache\.hve|SRUDB\.dat|config/(SYSTEM|SOFTWARE|SAM|SECURITY)$|Prefetch/|ActivitiesCache\.db|/Recent/|UsnJrnl|Recycle'
# what to look for: the meta address at the start of each line, in the form <inode>-<attr>-<id> —
# the numbers differ per image, so read them from the listing rather than copying an example

# 3. Extract each hit by meta address, then hash what you extracted
icat -o <offset> /evidence/case-01/disk.dd <meta-address> > /evidence/case-01/exports/SYSTEM
# what to look for: a non-empty file of plausible size; a parse that stops part-way usually traces back
# to an extraction that stopped part-way (section 16)

# 4. NTFS metadata has no directory entry: list the volume root, then extract the files you need
fls -o <offset> /evidence/case-01/disk.dd
icat -o <offset> /evidence/case-01/disk.dd <meta-address-of-$MFT>  > /evidence/case-01/exports/MFT
icat -o <offset> /evidence/case-01/disk.dd <meta-address-of-$Boot> > /evidence/case-01/exports/Boot
# what to look for: $MFT is large (tens to hundreds of MB); a tiny file means the wrong attribute

# 5. $J is a named attribute of $Extend\$UsnJrnl, so the attribute id inside the meta address matters
fls -o <offset> -r -p /evidence/case-01/disk.dd | grep -i UsnJrnl
icat -o <offset> /evidence/case-01/disk.dd <meta-address-of-$J> > /evidence/case-01/exports/J
# what to look for: large and frequently sparse; the journal grows faster than any other input here

# 6. Many small files (Prefetch, Recent, Recycle Bin $I): tsk_recover beats one icat per file — keep the command with the case
tsk_recover -o <offset> /evidence/case-01/disk.dd /evidence/case-01/recovered
```

Extract **once** and parse many times: parsing is cheap to repeat, the `icat` commands are what you must reproduce exactly, so log the meta address and output hash for each extraction. Name export directories without `$` characters, which PowerShell expands inside double quotes. If your analysis host is Linux, do the extraction there and run the parsers on a Windows analysis VM — a parser suite living on the examinee host is a contaminated exhibit (see [lab-environment](../labs/lab-environment.md)).

## 3. PECmd — Prefetch

**What it is.** The parser for Windows Prefetch (`C:\Windows\Prefetch\*.pf`, one file per `<EXECUTABLE>-<hash>.pf`). It decompresses the file — Windows 10 and later prefetch is compressed — and decodes the run count, the stored run times, and the referenced-path structures.

**What it produces.** One CSV row per `.pf`: the executable name, the prefetch hash (derived from the executable's path, so two copies of one binary produce two files), the run count, the retained last run times, the volume and directory strings referenced during the first seconds of execution, and the files and libraries loaded.

**How to use it.**

```powershell
.\PECmd.exe -d C:\Evidence\Prefetch --csv C:\Evidence\parsed --csvf prefetch.csv
# what to look for: a row per .pf with a run count and last run time; a count above one means repeated execution
.\PECmd.exe -h   # confirm the switch set on your build before trusting the line above
```

**Limitations.**

- **Absence proves nothing on its own.** Prefetch is typically off on servers and wherever the sysmain/prefetch service is disabled; a cleaned folder looks exactly like a host that never ran anything, and the cache is bounded, so old entries are deleted as new ones appear.
- **Execution without context, and its own timestamps are not the run times.** Prefetch proves a program started, but carries no arguments, no user and no outcome; parent process and account come from process-creation events, UserAssist or the registry, and the `.pf` file's own last-write time only approximately tracks the most recent run.

## 4. AmcacheParser — Amcache.hve

**What it is.** The parser for Amcache, a registry hive the application-compatibility infrastructure maintains — usually `C:\Windows\AppCompat\Programs\Amcache.hve`, a location that moved across Windows versions. It is an inventory of what the system has seen, not a log of what it ran.

**What it produces.** CSV rows for inventoried applications and files: full path, size, **SHA-1** hash, publisher and version metadata, and first-seen timestamps. The hash is the headline: it lets you pivot to intelligence, to other hosts, and to a disk-wide search for the same content under a different name.

**How to use it.**

```powershell
.\AmcacheParser.exe -f C:\Evidence\hives\Amcache.hve --csv C:\Evidence\parsed --csvf amcache.csv
# what to look for: paths outside Program Files (Temp, Downloads, the user profile); an empty hash column is empty data, not a negative finding
.\AmcacheParser.exe -h   # confirm the input and output switches for this release
```

**Limitations.**

- **Inventory, not execution.** An entry can exist for a program the system inspected but never ran. Use Amcache for paths and hashes, and find execution elsewhere.
- **Structure varies by Windows version**, so the parser version matters as much as the hive. Record both.
- **Parse it as a hive, with its logs.** Keep `.LOG1`/`.LOG2` beside the file and check whether your build consumes them — a hive not shut down cleanly can be stale, with the newest writes still in the logs. A `reg export` `.reg` text dump is not a hive and no parser will read it.

## 5. AppCompatCacheParser — ShimCache in the SYSTEM hive

**What it is.** The parser for the AppCompatCache ("ShimCache") inside the **SYSTEM** hive at `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`. Windows uses it to decide which compatibility shims apply; forensically it records binaries that have been present on the volume.

**What it produces.** One CSV row per cached entry: the path, the entry's last-modified time where the Windows version stores one, whatever execution-indicating field that version carries, and the control set the entry came from.

**How to use it.**

```powershell
.\AppCompatCacheParser.exe -f C:\Evidence\hives\SYSTEM --csv C:\Evidence\parsed --csvf shimcache.csv
# what to look for: paths in Temp, the user profile or unusual directories, and last-modified times that disagree with the $MFT record for the same path
.\AppCompatCacheParser.exe -h   # check how your build handles the Select key and the offline control sets
```

**Limitations.**

- **Presence, not execution.** On older Windows versions entries appear from directory enumeration alone, and the execution flag on newer versions is a hint to corroborate, never a finding.
- **One value, many control sets.** The cache lives per control set, so an offline hive needs its `Select` key read to learn which set was current — and both parsed if your build only reads one.
- **Bounded by design, and it needs the real hive.** Entries are capped and evicted as new ones arrive, so a missing path is not proof of absence; and a `.reg` export will not do — extract `SYSTEM` from an image or take a lock-aware copy.

## 6. MFTECmd — `$MFT`, `$J`, `$Boot`, `$SDS`

**What it is.** The parser for the NTFS metadata files: the Master File Table, the USN change journal, the boot sector and the security-descriptor stream. It reads structure rather than directory entries, so records for files that no longer have a name are still in scope.

**What it produces.**

| Input | What the rows describe |
| --- | --- |
| `$MFT` | One row per record: entry number and sequence, parent entry, file name, in-use flag, size, and both timestamp sets — `$STANDARD_INFORMATION` and `$FILE_NAME` — which is what makes a timestamp disagreement visible |
| `$J` | One row per USN record: USN, timestamp, reason flags (create, delete, rename, data change), name and parent entry, in journal order |
| `$Boot`, `$SDS` | Boot sector and BPB fields (cluster size, MFT location, total sectors) and the security-descriptor records keyed by the identifiers MFT records reference |

**How to use it.**

```powershell
.\MFTECmd.exe -f C:\Evidence\exports\MFT --csv C:\Evidence\parsed --csvf mft.csv
# what to look for: records whose in-use flag is false, and $SI/$FN timestamp pairs that disagree by far more than the write delay between the two
.\MFTECmd.exe -f C:\Evidence\exports\J --csv C:\Evidence\parsed --csvf usn.csv
# what to look for: rename and delete reason flags on the path you are chasing; $J is chronological, so it orders activity even when higher-level artefacts were cleared
.\MFTECmd.exe -h   # confirm which switch tells the tool which NTFS file it is being handed
```

**Limitations.**

- **Size and shape are the practical problems.** `$MFT` is tens to hundreds of megabytes with a larger CSV; `$J` can be gigabytes, partly sparse, and it wraps or can be deleted outright — so check that it was active in your window before reading anything into an empty parse.
- **Paths depend on parent records.** A deleted file's parent entry may itself have been reused, so a reconstructed path is strong only while the parent's sequence number still matches.
- **Timestamps come from the artefact.** `$STANDARD_INFORMATION` is directly writable; `$FILE_NAME` is harder to reach, which is exactly why their disagreement is the signal (see [03-timeline](../methodology/03-timeline.md)).

## 7. LECmd — LNK (shell link) files

**What it is.** The parser for `.lnk` shortcut files, which the shell creates when a file is opened through it — mainly `%APPDATA%\Microsoft\Windows\Recent\`, plus application-specific recent folders.

**What it produces.** One CSV row per `.lnk`: the target path, arguments, working directory, the *target's* size and timestamps embedded in the link, the volume serial and drive type, distributed-link-tracking identifiers where present, and network share details for links pointing at a UNC path. The link's own file-system timestamps are reported separately, and they mean something different.

**How to use it.**

```powershell
.\LECmd.exe -d C:\Evidence\Recent --csv C:\Evidence\parsed --csvf lnk.csv
# what to look for: targets on removable or network volumes, and links whose target no longer exists — those point at data since deleted, renamed or unmounted
.\LECmd.exe -h   # confirm whether your build recurses, and how it reports unresolvable shell items
```

**Limitations.**

- **Self-reported and snapshotted.** Everything except the link's own timestamps is read from inside the shortcut, which is a file like any other and can be crafted, and the embedded target times date the link's last write — not the target's last use.
- **Per profile, and not every access creates one.** Links live in a user profile, so a clean `Recent` folder in one account says nothing about the others; creation also follows rules that changed across Windows versions, and cleanup removes them — absence is not absence of access.

## 8. JLECmd — jump lists

**What it is.** The parser for the two jump-list families under `%APPDATA%\Microsoft\Windows\Recent\`: `AutomaticDestinations` (`*.automaticDestinations-ms`, an OLE compound file with an embedded `DestList` stream, written by the shell) and `CustomDestinations` (`*.customDestinations-ms`, a flat record sequence written by the application). They carry different amounts of metadata.

**What it produces.** Rows per destination entry: the target path, the owning application's AppID, and — automatic jump lists only — the timestamps and interaction counters in the `DestList` stream, plus the embedded shell-link data for each entry.

**How to use it.**

```powershell
.\JLECmd.exe -d C:\Evidence\Recent\AutomaticDestinations --csv C:\Evidence\parsed --csvf jumplist_auto.csv
# what to look for: targets on removable or network volumes, and the DestList order against the timestamps — the ordering records recency on Windows 10, so the two should agree
.\JLECmd.exe -h   # confirm the switches for the CustomDestinations folder and for DestList metadata output
```

**Limitations.**

- **AppIDs are not unique names.** More than one application can share an AppID, and some are documented only by community research, so a resolved name is an interpretation — keep the raw AppID in the report.
- **Custom destinations carry no DestList**, which means no interaction counters and no per-entry timestamps: weaker evidence than the automatic family.
- **The list is a user-interface artefact.** It reflects what the taskbar shows, so entries can be reordered, pinned or removed — by the user, by the application's own cleanup, or by a profile reset that takes whole families with it.

## 9. RECmd — registry, including batch-driven runs

**What it is.** A command-line registry parser that reads hives offline — no mounting, no live registry API — and that can be driven by **batch files**: plain-text lists of keys that select a curated, repeatable set of outputs instead of a dump of the entire hive.

**What it produces.** Without a batch file, CSV rows of key path, value name, value type, value data and key last-write time for everything in the hive. With one, the same columns restricted to the keys that batch names — and the batches shipping with a release typically produce several output files in a single pass.

**How to use it.**

```powershell
.\RECmd.exe -d C:\Evidence\hives --csv C:\Evidence\parsed
# what to look for: this is a database, not a document — sort and filter it, never read it end to end
.\RECmd.exe -h   # the batch switch is build-specific: read it here, then archive the batch file you ran with the case
```

**Limitations.**

- **Key last-write times are not a change log, and a full walk is mostly noise.** Timestamps update when the key is written, can be stale, and can be manipulated; values carry no timestamp of their own, so a value's content can predate its key's timestamp. Batch files exist to make the walk bounded and repeatable.
- **Offline hives have no `CurrentControlSet`.** Read the `Select` key first; parsing `ControlSet001` on a host that was running `ControlSet002` gives the wrong services and the wrong device history.
- **Deleted keys and values** survive as unallocated cells in the hive file and are not returned by an ordinary parse; recovering them needs hive-slack analysis rather than this tool's default mode.

## 10. EvtxECmd — EVTX to CSV and JSON

**What it is.** The parser for Windows event log files (`.evtx`). It reads the binary log format and applies **map files** that turn a given event ID's payload into named fields instead of leaving it as one opaque blob.

**What it produces.** One row per event: record ID, event ID, channel, provider, level, timestamp, user SID, computer, and the payload — either expanded into mapped columns or carried as raw XML/JSON alongside. Output is CSV, and the tool also emits JSON for pipeline use.

**How to use it.**

```powershell
.\EvtxECmd.exe -d C:\Evidence\evtx --csv C:\Evidence\parsed --csvf evtx.csv
# what to look for: channel and event ID first, then the mapped payload columns; an event with no map appears as a single blob field, which is a mapping gap rather than an empty event
.\EvtxECmd.exe -h   # confirm how this release finds its map files, and which switches emit JSON
```

**Limitations.**

- **Maps decide your columns.** An event ID without a map gives you the envelope and nothing structured, so check that a map for the event ID you care about exists before concluding a field does not exist.
- **Column drift and sparse rows.** Mapped column names change between releases, which breaks scripts that join on them, and the column set differs per event ID, so the CSV has many empty cells — filter early and pin the tool version per case.
- **Collection is a separate problem.** Several KAPE EVTX modules use this engine, so its limits propagate to them, and if a channel wrapped or was cleared no parser recovers it.

## 11. SBECmd — shellbags

**What it is.** The parser for shellbag data: the per-user record of folder views Windows keeps in `UsrClass.dat` (under `Local Settings\Software\Microsoft\Windows\Shell\Bags` and `BagMRU`) and partly in `NTUSER.DAT`.

**What it produces.** One CSV row per shell item: the reconstructed path, the item type (directory, archive, network share, control panel item, and others), the target's created/accessed/modified times where the item stores them, and the key the item came from.

**How to use it.**

```powershell
.\SBECmd.exe -d C:\Evidence\hives --csv C:\Evidence\parsed --csvf shellbags.csv
# what to look for: paths on removable or network volumes, and folders that no longer exist on the host — shellbags outlive the folder, which is their distinctive value
.\SBECmd.exe -h   # confirm the input switch for one hive versus a directory of hives
```

**Limitations.**

- **A bag is view state, not a file open.** The shell can record a folder it merely enumerated or displayed in a dialog, so a shellbag supports "this folder was reachable from this profile"; where the item stores no timestamp, the artefact is a path claim only.
- **Per profile, per hive.** `UsrClass.dat` belongs to one user; a host with several accounts needs every profile parsed, and a roaming or freshly created profile holds almost nothing.
- **Volume-relative items need resolving.** Shell items for removable or network volumes carry identifiers rather than letters, so a readable path depends on resolving them correctly.

## 12. WxTCmd — Windows Timeline

**What it is.** The parser for `ActivitiesCache.db`, the SQLite database behind Windows Timeline, typically under `C:\Users\<user>\AppData\Local\ConnectedDevicesPlatform\L.<user>\` — the trailing folder name varies per profile.

**What it produces.** One row per activity: application ID, activity type, start and end times, duration, and a JSON payload that commonly carries the executable path and the document or page title. It also reports the operations records describing how each activity was created, updated or deleted.

**How to use it.**

```powershell
.\WxTCmd.exe -f C:\Evidence\timeline\ActivitiesCache.db --csv C:\Evidence\parsed --csvf timeline.csv
# what to look for: activities whose payload names a path you are chasing, and gaps where an operation row says an activity was deleted rather than never created
.\WxTCmd.exe -h   # confirm how the build treats the SQLite write-ahead log sidecar beside the database
```

**Limitations.**

- **A deprecated surface.** Microsoft ended the cross-device Timeline experience and later removed parts of the feature, so on recent builds the database may be absent, small or stale. Absence here is not evidence of anything.
- **Copy the whole database set.** A SQLite database in WAL mode has `-wal` and `-shm` sidecars; copying only the `.db` can lose the most recent activities.
- **IDs need resolving, and activities travel.** A payload that does not resolve an application ID leaves you with a number, and activities synced from another device can put a path on this host that was never opened here.

## 13. SrumECmd — SRUM (`SRUDB.dat`)

**What it is.** The parser for the System Resource Usage Monitor database, `C:\Windows\System32\sru\SRUDB.dat` — an ESE (Jet) database in which Windows records per-application resource use in hourly buckets, keyed to user SIDs. Note the spelling: the tool ships as `SrumECmd`, not `SRUMECmd`.

**What it produces.** CSV output per SRUM table: the per-application network usage table (bytes sent and received per application per hour, with the interface used), the application resource usage table (foreground and background CPU time), the energy usage table, and the ID map table that turns numeric identifiers into names.

**How to use it.**

```powershell
.\SrumECmd.exe -f C:\Evidence\sru\SRUDB.dat --csv C:\Evidence\parsed --csvf srum.csv
# what to look for: applications with traffic in a window where nothing should have been talking; byte totals alone are not exfiltration, so pair them with a network source and the ID map
.\SrumECmd.exe -h   # check whether this build takes the SOFTWARE hive so application IDs resolve to names
```

**Limitations.**

- **Hourly buckets, not connections.** SRUM answers "which application moved data in this hour, under which user SID" — not "to which address". The destination comes from another source.
- **Names depend on the ID map, and retention is short.** Without the mapping input you have numbers, and on some builds the map is sparse; the database also rolls over on the order of a month by default, so an older incident may have aged out.
- **The live copy is the hard part.** `SRUDB.dat` is open by the SRUM service: a plain `copy` from a running system can fail or produce a database with pending transactions missing. Use a VSS snapshot or an ESE-aware backup, elevated, or extract from an image.

## 14. RBCmd — Recycle Bin `$I` files

**What it is.** The parser for the `$I` metadata files in `$Recycle.Bin\<SID>\`: the small binary record Windows writes for each item sent to the Recycle Bin on Vista and later — header, original size, deletion time, and the original full path as UTF-16 text.

**What it produces.** One CSV row per `$I` file: the original path, the deleted file's size, the deletion timestamp, the structure version, the SID folder it came from, and whether the matching `$R` content file is still present. It also handles `$I` files recovered from unallocated space, which is how a deleted deletion record gets read.

**How to use it.**

```powershell
.\RBCmd.exe -d C:\Evidence\recyclebin --csv C:\Evidence\parsed --csvf recyclebin.csv
# what to look for: deletions inside your window, and rows whose $R content is missing — a path and a time with no recoverable data; extract the per-SID subfolders there first
.\RBCmd.exe -h   # confirm the input switch for a single $I file versus a directory tree
```

**Limitations.**

- **Metadata and content part company.** `$I` can survive after `$R` is gone, emptying the bin removes the pair, and `Shift`+`Delete`, applications' own deletions and deletions on network shares write nothing at all — so a missing `$I` is not evidence that nothing was deleted.
- **The `$R` name is mangled** — a truncated original name plus a random suffix. The true original path comes from the `$I` structure, which is what this tool reads; do not read it off the `$R` filename.
- **Attribution needs a second source.** The SID folder identifies the account; turning a SID into a person needs the SAM hive or the domain, and a shared account breaks it.

## 15. KAPE — targets, modules and triage collection

**What it is.** Kroll Artifact Parser and Extractor: a Windows collector and orchestrator built on two kinds of definition file.

| Concept | Definition file | What it does |
| --- | --- | --- |
| **Target** | `.tkape` files in the `Targets` folder | Selects artefact **files** by path and copies them out — Prefetch, hives, event logs, SRUM, jump lists, and whatever else the target lists. This is collection. |
| **Module** | `.mkape` files in the `Modules` folder | **Runs parsers** over a collection, or over a live source, and writes their output. Modules largely wrap the tools in this file, so their output has the same shape and inherits the same limitations. |

Both a GUI (`gKAPE`) and a CLI (`kape.exe`) exist. gKAPE is a front end that assembles the same command line, which makes it a good way to discover the switch names your build uses before you automate them.

**How to use it.**

```cmd
:: Collection only: copy a target set out of a read-only mounted image drive
kape.exe --tsource E: --target <TargetName> --tdest C:\Evidence\collect
:: what to look for: the copied tree mirrors the source layout; target names are the base names of the
:: .tkape files, so list the Targets folder for the real ones instead of guessing

:: Modules only: parse what was collected — one output folder per module, holding that parser's CSV/JSON
kape.exe --msource C:\Evidence\collect --module <ModuleName> --mdest C:\Evidence\parsed
:: To discover the switch set, use the documented route: build the command in gKAPE and read the
:: command line it produces (section 15 above), or the KAPE documentation. This file does not
:: assert `kape.exe --help` — it is not in the KAPE docs, and no installed build was available to
:: test it.
```

**Why a targets collection is triage evidence, not an acquisition.**

- **It copies a selection.** No unallocated space, no slack, no deleted records, and no file-system metadata beyond the files that matched. If it is not in the target definition, it is not in the collection.
- **It is not bit-for-bit.** There is no image-level hash of the original device, and copying changes some timestamps on the copies. You can hash the collection, but that hash proves the collection has not changed since collection — not that it represents the host.
- **It runs against a live source**, where state changes under you and the collector itself adds activity. Document the run, the time, the version and the target files, and treat the output as a lead that supports an acquisition rather than a replacement for one.
- **Definitions travel with versions.** The same target name can collect a different set in a different release, so archive the `.tkape` and `.mkape` files you ran with the case. It buys speed and data minimisation across many hosts at once; it costs completeness, and defensibility if it becomes the only record of a host's state.

**Container, CSC and VSS handling.** This page asserts no switches for them, because builds differ and an invented flag costs you a collection. Container and compound-file sources (including CSC / client-side caching data) and Volume Shadow Copy use on a live host are documented features of the KAPE project: check its documentation and the options `gKAPE` presents in your version, and record that a shadow copy is itself an action taken on the exhibit — with a time, a tool version and a result.

## 16. When a parser fails — diagnosis

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| Zero records from a hive you know is populated | Wrong hive or wrong artefact: ShimCache is in `SYSTEM`, Amcache in its own hive, shellbags in `UsrClass.dat` | Re-check the artefact map in `../cheatsheets/windows-artifacts.md`, then confirm the file you extracted is the one the parser documents |
| The tool fails outright, or returns far fewer records than expected | Hive exported while in use, or copied from a running system so it is dirty or stale | Take the hive from an image or a VSS snapshot, keep `.LOG1`/`.LOG2` beside it, and use a parser with dirty-hive recovery |
| A parse stops part-way, or a small file where a large one belongs | Truncated export: an interrupted `icat`, a copy of a file still being written, a damaged segment | Re-extract from the image, hash the extract, and compare its size against the file's `$MFT` record |
| The tool exits immediately with a framework message | Missing .NET runtime for that release | Read the release notes for the build you downloaded, install the runtime it names, or use the distribution built for your platform — never assume a version |
| A script that worked last month returns nothing, or errors on a column | CSV column drift between tool versions: headers renamed or reordered | Inspect the header line of the new output before joining on a name; pin and record tool versions per case |
| Timestamps are hours out, or sort inconsistently | FILETIME versus ISO-8601, and UTC versus local: artefacts store FILETIME (100-nanosecond ticks since 1601-01-01 UTC) while tools render ISO-8601 | Choose one convention (UTC, ISO-8601) for the whole case, state it in the report, and check each tool's timezone behaviour before combining sources |
| Fields are empty and you read that as "no activity" | Empty fields: the artefact never recorded the value, or the source was disabled (prefetch on a server, an event ID with no map) | Establish that the artefact family was enabled and that the field exists on that build before treating empty as evidence |
| Values change the moment the CSV is opened | Spreadsheets mangling values: date coercion, stripped leading zeros, long hashes rounded or shown in scientific notation | Import as text — `Import-Csv`, a database or a text editor — and never let a spreadsheet retype an evidence column |
| Access denied reading a live hive, `SRUDB.dat`, or a raw volume | Live artefacts need elevation and a lock-aware copy; raw volume and `$MFT` reads need administrator rights | Elevate deliberately, record it, and prefer an image or snapshot copy for anything that will be reported |
| The parse worked on a live host and that is your only record | Running a parser against a live system when the evidence must be a copy: the source kept changing and nothing was preserved | Parse copies. Live parsing is triage — hash what you collected, note the time, then acquire properly |
| The CSV opens as one column, or with mojibake in the header | Delimiter or encoding mismatch: a different separator, a UTF-8 BOM, or UTF-16 output | Look at the first bytes and the header line, then tell your import tool what the file actually is |
| The parser rejects the file as an unknown format | Right family, wrong era or format: a `.reg` text export is not a hive, a Windows XP `INFO2` is not a `$I` file | Identify what the artefact actually is before forcing a parser that does not cover it |

## 17. How the tools fit together

| Tool | Artefact | Question it answers | Pairs with |
| --- | --- | --- | --- |
| PECmd | `C:\Windows\Prefetch\*.pf` | Did this program execute, how often, and what did it load? | AmcacheParser, process-creation events, `$MFT` |
| AmcacheParser | `Amcache.hve` | What programs has this system seen, and what are their SHA-1 hashes? | PECmd, `$MFT`, intelligence lookups |
| AppCompatCacheParser | `AppCompatCache` value in the SYSTEM hive | Was this binary present on this volume? | PECmd, `$MFT`, AmcacheParser |
| MFTECmd | `$MFT`, `$J`, `$Boot`, `$SDS` | What files exist and existed, and what changed in what order? | Everything here — it is the timeline backbone |
| LECmd | `*.lnk` in `Recent` | What did a user open through the shell, and where did the target live? | JLECmd, shellbags, `$MFT` |
| JLECmd | `*.automaticDestinations-ms`, `*.customDestinations-ms` | What did each application recently open? | LECmd, shellbags, Timeline |
| RECmd | Hives (`SYSTEM`, `SOFTWARE`, `SAM`, `NTUSER.DAT`, `UsrClass.dat`) | What was configured — persistence, device history, policy? | MFTECmd (`$J`), SBECmd |
| EvtxECmd | `.evtx` channels | What did the OS and its components record? | MFTECmd, SRUM, KAPE module runs |
| SBECmd | `UsrClass.dat`, `NTUSER.DAT` | Which folders did a user browse, including ones now gone? | LECmd, JLECmd, RECmd |
| WxTCmd | `ActivitiesCache.db` | Which applications and documents were in use, and when? | LECmd, JLECmd, EvtxECmd |
| SrumECmd | `SRUDB.dat` | Which application moved how much data, per hour, for which SID? | EvtxECmd, network telemetry |
| RBCmd | `$I` files in `$Recycle.Bin` | What was deleted, from which path, at what time, by which SID? | MFTECmd, JLECmd, EvtxECmd |
| KAPE | Collection of all of the above | Collect, then drive the parsers in one repeatable run | Every row above — as a driver, not a replacement |

## Common Mistakes & Tips

- **Parsing the image instead of the artefact.** No parser here reads a disk image. Extract with `fls`/`icat` first, and record the meta address and hash of every extraction.
- **Skipping the partition offset.** `fls` and `icat` without the correct `-o` return garbage or nothing; read it from `mmls` once and pass it everywhere.
- **Working on the original.** Extract and parse copies, keep the master sealed, and hash both source and copy. A parser writing CSVs into your evidence directory is a chain-of-custody problem you created yourself.
- **Trusting a remembered switch.** These tools rename options between releases, and KAPE's command line in particular moves. `-h`, `--help` and `gKAPE` are the authorities, not a guide.
- **Reading an artefact above its ceiling.** Prefetch proves execution, Amcache proves inventory, ShimCache proves presence, LNK and jump lists prove interaction. Confusing them turns a lead into a false conclusion.
- **Treating empty output as a finding.** Before writing "nothing happened", establish that the artefact existed, was enabled and was not cleared. An empty parse from a disabled source means nothing at all.
- **Opening evidence CSVs in a spreadsheet.** Date coercion, stripped leading zeros and rounded hashes silently alter values. Work in `Import-Csv`, a database or a text editor, and hand out read-only copies if someone insists on a spreadsheet.
- **Mixing timestamp conventions.** Keep everything in UTC ISO-8601, note each tool's timezone behaviour, and never let FILETIME ticks and rendered strings meet in one timeline without conversion.
- **Running a live collection and calling it forensics.** A KAPE target run or a live parse is triage: fast, selective, and not the host's state. Say which one you did.
- **Leaving provenance behind.** Tool version, command line, source hash, output hash, examiner and time — for every artefact, not only the ones that produced a finding.
- **Tip:** archive the KAPE `.tkape`/`.mkape` files and RECmd batch files you ran with the case, and run each parser against two independent extractions of the same artefact before building anything on top of it.
- **Tip:** practise on images you built yourself in a disposable VM with snapshots — never on production systems, and never on media you were not authorised to examine.

## Checklist / Self-Test

- [ ] I can explain why these parsers need extracted artefacts rather than an image, and I can extract one with `fls` + `icat`.
- [ ] I can state where each of these lives: Prefetch, Amcache, ShimCache, `SRUDB.dat`, `ActivitiesCache.db`, `$I` files, shellbags.
- [ ] I checked the release notes for the .NET runtime my build needs, instead of assuming a version.
- [ ] I parsed a directory of `.pf` files and can explain why a missing entry is weak evidence.
- [ ] I parsed Amcache and can state what its hash gives me that a path does not.
- [ ] I parsed ShimCache from a SYSTEM hive and can state what it does *not* prove.
- [ ] I parsed `$MFT` and `$J` and can name one reason a reconstructed path may be wrong.
- [ ] I parsed LNK files and can distinguish the target's embedded timestamps from the link's own.
- [ ] I parsed jump lists and can explain what CustomDestinations lacks.
- [ ] I ran RECmd without a batch file, then with one, and archived the batch file with the case.
- [ ] I parsed EVTX with EvtxECmd and can explain what an unmapped event ID looks like in the output.
- [ ] I parsed shellbags, Timeline and SRUM and can state the retention limit of each.
- [ ] I parsed Recycle Bin `$I` files and can explain why a missing `$I` proves nothing.
- [ ] I can describe the difference between a KAPE target and a KAPE module, and why a target collection is not an acquisition.
- [ ] I ran `-h` or `--help` on at least three of these tools and found a switch that differs from what a guide told me.
- [ ] Every artefact I parsed came from a host I own or was explicitly authorised to examine.

## Further Resources

- Eric Zimmerman's forensic tools — downloads, release notes and per-tool documentation: ericzimmerman.github.io.
- KAPE — project repository and documentation (targets, modules, and the current switch set): github.com/EricZimmerman/KAPE and ericzimmerman.github.io/KapeDocs.
- The Sleuth Kit — `fls`, `icat`, `istat`, `tsk_recover` and the rest of the extraction toolkit: sleuthkit.org.
- RegRipper — an alternative, plugin-based offline registry parser worth cross-checking RECmd against: github.com/keydet89/RegRipper3.0.
- libyal libraries (`libesedb`, `libevtx`, `libregf`, `libfsntfs`) — the underlying parsers many tools build on, and a cross-platform route to the same artefacts: github.com/libyal.
- Plaso / log2timeline — building a super-timeline from parsed artefact output: github.com/log2timeline/plaso.
- Forensics Wiki — per-artefact reference pages, including the on-disk structures of the formats above: forensics.wiki.
- Microsoft Learn — Windows security auditing and event reference, the authority for the events these parsers surface: learn.microsoft.com/windows/security/threat-protection/auditing.
- Official eCDFP page on the INE website for current, authoritative details about the certification.

> **Verification:** checked against source, not executed — **no KAPE binary was available**. On
> **2026-09-19** `Get-Command kape.exe` returned nothing on the Windows host used for this pass, so
> no switch could be run. The claim that `--help` is not a documented switch was checked against
> the repository's own catalogue of the tool,
> `scripts/utilities/tool-specs/kape.json`, whose `provenance.sources` are the KAPE documentation
> pages (KapeDocs, fetched 2026-09-19) and whose `longFlags` list contains no `--help`; the same
> catalogue records `--tsource`, `--target`, `--tdest`, `--msource`, `--module` and `--mdest`,
> which section 15 uses. Section 15's own pointer to `gKAPE` as the way to discover switches is
> the documented route and is what the example now says.
