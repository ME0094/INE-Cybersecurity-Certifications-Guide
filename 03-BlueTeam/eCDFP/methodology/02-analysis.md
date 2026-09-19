# File System Analysis (eCDFP Methodology — Phase 02)

> Companion study guide for the eCDFP (Certified Digital Forensics Professional) Blue Team methodology track. This phase turns raw acquired data into answers at the level of the file system: which structures exist, what they record, what can be recovered, and what the metadata implies about user and attacker activity.
>
> This file is the file-system spine of the analysis phase. The Windows-specific artefacts that sit *on top of* the file system — execution, persistence, resource use and user activity — get their own depth treatment in `05-windows-artifact-forensics.md`; §11 here is the orientation that tells you what exists and when to jump across.
>
> Every command below is a **syntax reference**. This repository ships no captured command output: there is no image and no toolchain on the machine that wrote it. Where a command would print a result, the text says what to look for. Confirm flags against `--help` or the manual page for the version you install.

## Overview

Analysis (NIST's *examination* phase) is where you interrogate the acquired image. You do not read every byte — you work **artifact-driven**: form questions first (what happened, when, by whom, with which tool), then select the artefacts most likely to answer them. A disciplined order reduces noise:

1. Filesystem structure and file metadata
2. Deleted data, slack, and unallocated space
3. Operating-system artefacts (registry, prefetch, logs)
4. User/application artefacts (browsers, documents, LNK files, jump lists)
5. Targeted keyword searches and carving

Always work on a **verified working copy** of the image and keep notes of every tool, version, and command so findings are reproducible.

Two structural facts shape everything below, and both are worth stating before you open a tool:

- **A file system records two different things: content and metadata.** Recovery problems are usually metadata problems. Data that is still physically present can be unreachable because the structure that named it is gone; and metadata that is fully intact can point at content that has already been overwritten.
- **Every file system keeps more history than it needs.** Journals, slack, mirror copies, free-space bitmaps and previous-volume structures all survive by accident. The examiner's advantage is that deleting one record rarely deletes all of them.

## 1. Establish the geometry before anything else

Every tool in this phase takes an offset, and an offset read from the wrong place produces confident nonsense. Do this first, every time, and write the numbers down.

```bash
# Partition layout of the whole-disk image: note the START sector of each partition
mmls /case/evidence.dd
# What to look for: the partition table type and one row per partition, with the
# Start column in 512-byte sectors. That Start value is the -o argument for everything
# that follows. Also note any gap between partitions — unallocated space between them
# is itself searchable.

# File system details of one partition
fsstat -f ntfs -o 2048 /case/evidence.dd
# What to look for: file system type and version, volume label, cluster/block size,
# total and free counts, and the volume serial number. Record the serial: several
# artefacts embed it, and matching it proves which volume an artefact came from.
```

| Value to record | Why it matters later |
| --- | --- |
| Partition table type (MBR/GPT) | Determines what a "gap" between partitions means, and whether a second (backup) table exists |
| Partition start sectors | The `-o` argument for TSK and most parsers; wrong value = garbage or "file system not found" |
| File system type and version | Which recovery techniques are even possible (see §4) |
| Cluster / block size | Slack calculations, and interpreting sizes in metadata |
| Volume serial number | Ties artefacts found elsewhere back to this specific volume |
| Volume label | Corroborates which volume a user saw as "D:" or "Backup" |
| Total vs. free counts | Sanity check on how much was deleted recently — and on whether the image looks complete |

> Sanity check that catches a surprising number of problems: does the file system's reported size and label match what the source was supposed to contain? A 500 GB volume reporting as 8 GB, or an NTFS volume with no label on a machine whose volume was labelled, means you are reading the wrong offset — or the wrong image.

## 2. NTFS structures worth knowing

NTFS is the file system most eCDFP work touches, and it is metadata-rich in a way that rewards knowing its shape. Every NTFS metadata file has a name beginning with `$`.

| Structure | What it holds | Forensic value |
| --- | --- | --- |
| Boot sector | Geometry, cluster size, and the location of the `$MFT` | Where every other read begins; a backup copy sits at the last sector of the volume |
| `$MFT` | One record per file and directory: attributes, timestamps, sizes, data runs | The core metadata source. Resident data lives here; unallocated records survive after deletion |
| `$MFTMirr` | A copy of the first few `$MFT` records | A fallback when the primary table is damaged |
| `$LogFile` | A transaction journal of metadata operations | Reconstructs a *narrow, recent* window of changes in detail, including renames |
| `$UsnJrnl:$J` | Change journal: per-change records with reason codes | The best source for "what file operations happened when", including renames and deletions. Finite, and can be deleted |
| `$Bitmap` | Which clusters are allocated | Locating unallocated space; detecting inconsistencies |
| `$Secure` / `$SDS` | Security descriptors and which files use them | Correlating files that shared an ACL; useful for grouping |
| `$Extend` (`$ObjId`, `$Quota`, `$Reparse`) | Object identifiers, quotas, reparse points | Linking files that were moved or copied; junction and symlink targets |
| `$Volume`, `.` (root) | Volume information and the root directory entry | The root directory's own record is a useful timestamp anchor |

Attributes are the other half of the model:

- **Resident vs. non-resident data.** Small files store their content *inside* the MFT record. This is why a tiny deleted file's content sometimes survives while a large one does not: the record is the only place the data ever lived.
- **The two timestamp sets.** `$STANDARD_INFORMATION` and `$FILE_NAME` carry the same four timestamps and are updated by different events. Their disagreement is the classic timestamp-manipulation indicator — treated in full in `08-anti-forensics-and-evidence-integrity.md`.
- **Named data streams.** NTFS files can carry alternate data streams, listed as additional name entries. Look for a colon in the name field of a directory listing.
- **Compression and encryption attributes.** A compressed or EFS-encrypted file's clusters do not contain the plaintext you expect; a naive `strings` search over the volume will not find content that is compressed or encrypted in place.

```bash
# Metadata, including both timestamp sets, for one file record
istat -o 2048 /case/evidence.dd 42
# What to look for: the $STANDARD_INFORMATION and $FILE_NAME attribute blocks, the
# size fields, and the data run list. A record with a data run list but no allocated
# flag is a deleted file whose content may still be addressable.

# Dump an unallocated metadata record by its MFT entry number
icat -o 2048 /case/evidence.dd 42 > /case/exports/recovered-name.bin
# What to look for: whether the recovered bytes are plausible content, or zeros that
# mean the clusters were reused.
```

```bash
# Recover the change journal and the $MFT as files so a parser can read them
fls -o 2048 -r -p /case/evidence.dd | grep -iE '\$MFT|\$UsnJrnl|\$LogFile|\$Extend'
# What to look for: the meta addresses to hand to icat. $UsnJrnl is a directory
# containing a stream named $J; extract that specific stream, not the directory.
```

## 3. ext-family, FAT/exFAT and other file systems

The techniques transfer; the specifics do not. Know where each family differs.

### ext2 / ext3 / ext4

| Aspect | What it means for analysis |
| --- | --- |
| Superblock and block groups | The superblock holds geometry; backups exist in later block groups, which is how a damaged volume is often recoverable |
| Inode table | Fixed-size inodes hold metadata and the pointers to data blocks — the equivalent of an MFT record |
| Journal | ext3/ext4 keep a journal of metadata (and optionally data) operations, but it is a *filesystem* journal, not a queryable change log like the USN journal |
| Deletion behaviour | Deleting a file clears the inode's block pointers and removes the directory entry. The inode number is freed, so a directory listing usually shows nothing — which is why deleted-file recovery on ext4 often depends on carving or on journal analysis rather than on metadata |
| Timestamps | ext4 stores additional sub-second and "extra" timestamp fields beyond the classic second-resolution values, so a modification within the same second is distinguishable |

Practical consequence: **the drill that works beautifully on FAT is disappointing on ext4.** Do not conclude that nothing was deleted; conclude that this file system does not preserve the deletion in a directory listing, and change technique.

### FAT12/16/32 and exFAT

- **Directory entries are the metadata.** Each 8.3 entry holds name, attributes, size, cluster chain start, and timestamps; long file names are stored as a run of preceding entries.
- **Deletion marks the first character of the name** rather than removing the entry, which is why directory-entry-level recovery works well and why partial names are common.
- **Cluster chains are the allocation map.** A file's data is a linked list of clusters; overwriting any link or cluster breaks recovery beyond that point, and fragmentation is common.
- **FAT carries two copies of the allocation table**, and they can disagree — a disagreement is a corruption signal.
- **exFAT differs structurally** from FAT32 (different directory entry layout, an allocation bitmap, and different name handling), so tooling that reads FAT32 metadata may not read exFAT the same way. Confirm what your tools support for the specific variant.

### HFS+, APFS and others

- **HFS+** stores a catalogue of records with a journal, broadly analogous in forensic role to an MFT.
- **APFS** is copy-on-write and snapshot-based, which changes the analysis fundamentally: historical volume states can survive as snapshots, and "the current state" may be reconstructible from several of them. Tool support for APFS is more limited and changes quickly — check what your version supports before promising a recovery.
- **Virtual and logical layers** (LVM, Storage Spaces, RAID, LUKS containers) sit under the file system. If `fsstat` cannot identify a file system at a partition boundary, the volume above it may be an encrypted or logical container rather than a missing file system.

### Choosing your expectations by file system

| File system | Deleted-file recovery via metadata | Deletion recorded in a change log | Typical first technique |
| --- | --- | --- | --- |
| FAT / exFAT | Often good (directory entry survives) | No | `fls -d` + `icat -r` |
| NTFS | Often good (`$MFT` record marked unallocated) | Yes (USN journal, `$LogFile`) | `fls -d`, `istat`, journal parsing |
| ext4 | Usually poor (inode pointers cleared) | No queryable change log | Carving, journal analysis, file-system-specific tools |
| APFS | Depends on snapshots | Snapshots preserve volume states | Snapshot enumeration with supported tooling |

## 4. Deleted files, unallocated space and slack

### Deleted files

Deleting a file normally removes its *reference*, not its data. On NTFS the Master File Table (MFT) entry is marked unallocated, and the file's clusters stay in place until overwritten. The same logic applies to FAT and ext-family systems. Tools therefore distinguish:

- **Allocated** files — currently referenced by the filesystem.
- **Deleted/unallocated** files — metadata and/or data still present but no longer referenced.

The recovery decision tree:

```text
Is the file's metadata still present (a deleted directory entry or an unallocated MFT record)?
├── YES → Is the content's allocation still intact (cluster chain / data runs unbroken, clusters not reused)?
│         ├── YES → Metadata-based recovery: icat / tsk_recover. Names and timestamps preserved.
│         └── NO  → Partial or corrupt recovery. Recover what is there and say what is missing.
└── NO  → Carving from unallocated space. No name, no timestamps, possibly fragmented.
```

Keep both tools and results distinct in your notes, because they support different claims: metadata-based recovery preserves the file's identity; carving recovers content of unproven provenance and date.

### Slack space

When a file's logical end does not fill its last allocated cluster, the remainder is **file slack**, which has two parts:

- **RAM slack** — from the end of the file's data to the end of the last *sector*; historically filled with leftover memory contents.
- **Drive slack** — from the last sector boundary to the end of the *cluster*; may contain remnants of previously deleted files.

Slack can therefore hide fragments of old data that no longer exist as files. It is a classic place to search and carve.

```bash
# Read the allocated units of the volume rather than the files in it — the raw material
# for slack and unallocated searching
blkls -o 2048 /case/evidence.dd > /case/exports/unallocated.raw
# What to look for: on NTFS, blkls without -a gives you the unallocated units; with -a
# it gives the allocated ones. Confirm the flag semantics with blkls -h on your build,
# because the meaning of -a is exactly the kind of detail that gets misremembered.

# From there, search the unallocated region as a flat byte stream
strings -a -n 8 /case/exports/unallocated.raw | grep -iE 'password|secret|@example'
# What to look for: hits that are plausible text, with an offset you can map back to a
# cluster, so you can say where in the volume the fragment lives.
```

### Alternate Data Streams (ADS)

Hidden content attached to a file (e.g., `file.txt:hidden.exe`). TSK lists streams as additional name entries for the same file record; a name containing a colon is the signal. Extract a stream by passing its full stream name to `icat`, and expect a GUI or a file copy to lose it silently — which is exactly why ADS is used for hiding.

## 5. Previous volume states: Volume Shadow Copies and file-system journals

The most valuable and most overlooked source of recoverable content on a Windows volume is **not** unallocated space. It is the historical states the operating system kept for its own purposes.

- **Volume Shadow Copies (VSS)** are point-in-time snapshots of a volume, created by restore points, backup software, and some update processes. Where they exist, they can contain complete previous versions of files that were subsequently modified, encrypted or deleted — including the original of a document that has been replaced.
- **The lag between a change and the shadow copy** is the limitation: VSS captures state at intervals, not continuously, so the version you want may predate the change by hours.
- **Tool support varies.** TSK has no first-class VSS support; dedicated libraries and GUI tools do, and some forensic suites enumerate shadow copies natively. Check what your toolchain supports for the volume you have rather than assuming.
- **On Linux, the equivalents are different**: LVM snapshots, Btrfs and ZFS snapshots. Same idea, different plumbing.

```bash
# Look for the artefacts that indicate shadow copies exist on the volume
fls -o 2048 -r -p /case/evidence.dd | grep -iE 'System Volume Information|snapshot'
# What to look for: the System Volume Information directory and any per-snapshot
# structures inside it. On NTFS these are not ordinary files, so a plain listing is a
# weaker signal than it looks — use a tool that understands VSS and record which one.
```

> Do not report "the file was not found" when a shadow copy might hold a previous version. Where VSS or volume snapshots exist and you could not analyse them, that is a limitation to state — not a conclusion to draw.

## 6. Windows Registry Basics

The registry is a database of system and user configuration spread across **hives**. For offline analysis you analyze copies of the hive files:

| Hive | Contents of interest |
| --- | --- |
| `SYSTEM` | Control sets, services, **USBSTOR/MountedDevices** (device history), ShimCache (AppCompatCache) |
| `SOFTWARE` | Installed programs, autostart (Run/RunOnce under `...\Windows\CurrentVersion`), network settings |
| `SAM` | Local account names and password hashes |
| `SECURITY` | Policy, cached domain credentials |
| `NTUSER.DAT` (per user) | **UserAssist**, RecentDocs, TypedPaths, Run MRU, MUICache, shell history |
| `UsrClass.dat` (per user) | **Shellbags** (folder view state/timestamps), file associations |

High-value forensic keys (all under the profile or system hives):

- **Autostart keys** (`Run`, `RunOnce`, services) — persistence mechanisms used by attackers.
- **UserAssist** — records GUI program executions (paths are ROT13-obfuscated); includes run counts and last-run times.
- **Shellbags** — folder browsing history with timestamps, useful when the user deleted other traces.
- **ShimCache / Amcache** — evidence that a binary was *present* to the compatibility infrastructure, not that it ran: ShimCache can record files that were merely seen, and Amcache is an inventory rather than an execution log. Execution needs Prefetch or a process-creation event (see `05-windows-artifact-forensics.md` §1, "The evidential ladder", and `../cheatsheets/windows-artifacts.md`).
- **USBSTOR + MountedDevices** — which USB devices connected, when, and their serial numbers.

```bash
# Offline registry analysis with RegRipper (python-based, runs on hive copies)
rip.pl -r SYSTEM -p usbstor        # USB device connection history from the SYSTEM hive
rip.pl -r NTUSER.DAT -p userassist # GUI program execution records for a user
# What to look for: the plugin prints the parsed key content. Confirm plugin names with
# rip.pl -l on your install — the plugin set has grown over time.

# Pull the hives out of the image first (never parse them from a live system)
fls -o 2048 -r -p /case/evidence.dd | grep -iE 'config/(SYSTEM|SOFTWARE|SAM|SECURITY)|NTUSER\.DAT|UsrClass\.dat'
```

Registry *keys* carry a last-write timestamp, and many *values* embed timestamps — registry data is a first-class source for timeline analysis (Phase 03).

> **Three registry caveats that change conclusions.** Parse a hive together with its `.LOG1`/`.LOG2` transaction logs or a dirty hive on disk may be stale. A key's last-write time is not a value's write time. And deleted keys frequently survive in hive slack, which is how you demonstrate that a persistence key was *removed* rather than never present. All three are covered in `05-windows-artifact-forensics.md` §7 and `08-anti-forensics-and-evidence-integrity.md`.

## 7. Prefetch Basics (Windows)

Windows **Prefetch** (`C:\Windows\Prefetch\*.pf`) records the executables that ran on a system. Each `.pf` file is named `PROGRAM-<HASH>.pf` and stores the run count, first/last run times, and referenced files — a strong indicator of program execution.

- Present on client Windows by default (often disabled on servers).
- Only captures *programs*, not documents — but an opened document often launches a program, and the file may be referenced inside the `.pf`.
- Parse with public tools such as Eric Zimmerman's **PECmd**, or extract the folder from the image and analyze it:

```bash
# Parse a directory of .pf files extracted from the image (Windows-side tool)
PECmd.exe -d "C:\Case\Prefetch" --csv "C:\Case" --csvf prefetch.csv

# Or inspect one file for quick triage
PECmd.exe -f "C:\Case\Prefetch\NOTEPAD.EXE-01234567.pf"
```

```bash
# Extracting the folder from a Linux analysis host, before parsing it elsewhere
fls -o 2048 -r -p /case/evidence.dd | grep -i '/Prefetch/'
# What to look for: one entry per .pf file with its meta address; extract each with icat,
# or extract the directory contents in bulk with tsk_recover.
```

Prefetch is one artefact among several that bear on execution, and it is neither the strongest nor the most reliable on its own. The comparative treatment — including what each artefact proves and what it does not — is in `05-windows-artifact-forensics.md` §3.

## 8. Browser and Application Artifacts

### Browsers

Modern browsers store history in SQLite databases, which survive even when the browser UI history was "cleared" — but clearing *does* remove rows, so act fast and analyze copies.

- **Chrome / Edge (Chromium):** profile `History` database with `urls`, `visits`, `downloads`, `search_terms` tables; plus `Cookies`, `Login Data`, and `Cache` files.
- **Firefox:** `places.sqlite` (`moz_places`, `moz_historyvisits`), `cookies.sqlite`, `formhistory.sqlite`.

```bash
# Query a copied Chrome History database directly (never the live one)
sqlite3 "C:\Case\History" \
  "SELECT u.url, u.title, v.visit_time/1000000 - 11644473600 AS epoch
   FROM urls u JOIN visits v ON u.id = v.url ORDER BY v.visit_time DESC;"
# What to look for: rows in descending time order. The arithmetic converts the
# browser's epoch (microseconds since 1601) to Unix seconds — check the conversion
# against a row whose time you know before you trust the whole column.

# Deleted rows may still be in the free pages: do not stop at the live tables
sqlite3 "C:\Case\History" "PRAGMA page_count; PRAGMA freelist_count;"
# What to look for: a non-zero freelist count means there is freed space that a
# carving pass over the database file might still yield content from.
```

```bash
# Chromium's download table links a browsing action to a file on disk
sqlite3 /case/exports/History \
  "SELECT target_path, tab_url, start_time FROM downloads ORDER BY start_time DESC LIMIT 20;"
# What to look for: a target path that matches a suspicious file you found in the
# image, with a time you can anchor the rest of the timeline to.
```

### Application and user-activity artifacts

- **LNK files** — shortcuts created when a user opens a document or runs a program; they embed the target path and timestamps.
- **Jump Lists** (`AutomaticDestinations` / `CustomDestinations`) — Windows 7+ records of recently opened items per application.
- **Office "Recent" lists, `RecentDocs`, TypedPaths** — corroborate which files a user touched.
- **Web/email caches and chat clients** — application-specific databases worth locating per the investigation's scope.
- **Recycle Bin**: `$Recycle.Bin\<SID>\` holds `$R…` files (the original data) and `$I…` files (metadata: original path, deletion time, size). Windows XP used `C:\Recycler\<SID>\INFO2`. Deleting via `Shift`+`Delete` bypasses the bin entirely, so the absence of a `$R`/`$I` pair is not evidence that a file never existed.

The evidential weight of each of these — and the difference between *execution*, *presence* and *user interaction* — is the subject of `05-windows-artifact-forensics.md` and `../cheatsheets/windows-artifacts.md`.

## 9. Keyword Searching and Carving

### Keyword searching

When you know a target string (password, filename, domain, credit card, phrase), search the *entire* image — including unallocated and slack space — across both ASCII and UTF-16 encodings (Windows stores most text as UTF-16LE).

```bash
# Extract printable strings of a given encoding, then filter
strings -a -e l image.dd | grep -i "password"        # 16-bit little-endian (UTF-16)
strings -a image.dd | grep -iE "smith|example\.com"   # default ASCII

# Search the raw image directly; -a treats binary as text, -b gives byte offsets
grep -aob "credential" image.dd
# What to look for: byte offsets you can convert into a partition-relative location,
# so the hit can be described precisely enough to be reproduced.
```

Four search pitfalls worth knowing before you trust or distrust a result:

- **Encoding is not just ASCII or UTF-16.** Text can be UTF-8, mixed, split across sectors, or compressed. A negative ASCII result proves nothing about a UTF-16 string and vice versa.
- **Compressed and encrypted content will not match.** NTFS compression, EFS, archive contents and encrypted volumes hide strings from a raw scan, which is why a keyword search over a volume is not a completeness argument.
- **A match is not a finding.** A password string in unallocated space proves the bytes exist somewhere on the volume — not that a file contained it, not who put it there, and not when.
- **Search the index when you have one.** A pre-built index (in Autopsy or a dedicated tool) is faster and more thorough than iterating `grep` across partitions, and it keeps the search reproducible as a named query.

### Carving

**Carving** recovers files from unallocated or slack space without filesystem metadata, by recognizing content. Two approaches:

- **Signature (header/footer) carving** — match known file signatures, e.g., JPEG `FF D8 FF`, PNG `89 50 4E 47`, ZIP `50 4B 03 04`, PDF `%PDF`.
- **Content/statistical carving** — find structured data (e.g., SQLite pages, e-mail headers) even without a clean header/footer.

```bash
# foremost carves files by signature into per-type folders under the output dir
foremost -t jpeg,png,doc,zip -i image.dd -o /case/carved
# What to look for: per-type output directories with a audit file listing the offsets
# each carved file came from. Record the offsets: a carved file with no provenance is
# hard to cite in a report.
```

Carved files may be **fragmented** (split across non-contiguous clusters); simple tools recover only contiguous files, so partial or corrupted results are expected — document what you recover and how. Carved artefacts also lose their original names and timestamps, so a carved document cannot establish *when* it was created or *whose* it was; it can only establish that content resembling it existed in the unallocated region.

## 10. Practical Tooling: The Sleuth Kit and Autopsy

**The Sleuth Kit (TSK)** is the command-line workhorse for filesystem-level analysis; **Autopsy** is its GUI, adding search, carving, timeline views, and modules on top. Work on a copy of the image and always specify the partition offset you found with `mmls`.

```bash
# Partition layout of the image
mmls image.dd

# List the root directory of the NTFS partition starting at sector 2048
fls -o 2048 -r image.dd

# Show only deleted entries (these are flagged with '*' in fls output)
fls -o 2048 -r -d image.dd

# Extract the content of a specific inode/entry, e.g. 29-128-1
icat -o 2048 image.dd 29-128-1 > recovered.docx

# Find which filename references an inode (reverse lookup)
ffind -o 2048 image.dd 29-128-1

# List metadata (inodes), including deleted ones, with timestamps
ils -o 2048 -m image.dd
```

| Tool | Question it answers |
| --- | --- |
| `mmls` | What partitions exist, and at which offsets? |
| `fsstat` | What kind of file system is this, with which geometry and serial? |
| `fls` | What files and directories exist, and which are deleted? |
| `istat` | What does one file record contain — both timestamp sets, sizes, data runs? |
| `icat` | What are the contents of this file, inode or stream? |
| `ffind` | Which name refers to this inode? |
| `ils` | Which metadata records exist, including unallocated ones? |
| `blkls` | What do the allocated or unallocated units of the volume contain, as a flat stream? |
| `blkcat` | What is in this specific cluster? |
| `sigfind` | Where on the volume does this byte signature appear (e.g. a backup superblock or boot sector)? |
| `tsk_recover` | Which files can be bulk-recovered, allocated or deleted? |
| `hfind` | Does this file's hash appear in a known-good or known-bad hash set? |

```bash
# Bulk-recover deleted files into a directory tree (names are preserved when metadata is)
tsk_recover -e -o 2048 /case/evidence.dd /case/exports/recovered/
# What to look for: a directory tree mirroring the original paths. Files with names like
# $OrphanFiles or numeric-only names are recovered without their directory context —
# say so when you cite them.

# Set aside known-good OS files so the interesting ones stand out
hfind -i nsrl-md5 /case/nsrl/NSRLFile.txt
# What to look for: a populated index you can query per file hash. Confirm the index
# type and the source hash set with hfind -h on your build.
```

A typical Autopsy workflow: start a new case → add the image → let ingest modules run (file type identification, hash lookup against known-good/bad sets, keyword extraction, timeline) → drill into flagged files with hex/viewers → export exhibits. Hash sets (e.g., NSRL) let you quickly set aside known operating-system files and focus on the unusual.

## 11. Matching questions to techniques

| Question | First technique | Then |
| --- | --- | --- |
| What files were on this volume? | `fls -r` | Autopsy ingest for enrichment |
| What was deleted? | `fls -d`, `ils` | `istat` on the record; `$UsnJrnl` for the deletion time |
| Can I recover this deleted file? | `icat -r` / `tsk_recover` | Carving if the metadata path fails |
| What did this file look like before it was changed? | Volume shadow copies / snapshots | Backup copies, cloud-synced copies |
| What strings does this volume contain? | Indexed keyword search | `strings` + `grep` over `blkls` output for unallocated regions |
| Which user account owned this file? | NTFS `$Secure`/ACL grouping; profile paths | Registry artefacts (Phase 05) |
| What happened in this narrow window? | `$UsnJrnl` for file operations | `$LogFile`, then event logs (Phase 06) |
| Where is the hidden content? | ADS listing (`:` in names) | Slack and unallocated search |
| What does this file's content actually look like? | `file`, hex viewer, `blkcat` for one cluster | Application-level parsing (browser DBs, documents) |

## Common Mistakes & Tips

- **Analyzing the original image.** Always analyze a verified working copy and keep the master sealed.
- **Skipping the partition offset.** Running `fls` without `-o` on a partitioned disk yields garbage; check `mmls` first.
- **Trusting live tools on a dead image.** File-copying a live machine's `History` database can lock or alter it; copy the image/file first.
- **Only looking at allocated files.** The most interesting evidence is often deleted, in slack, or in the registry.
- **Expecting ext4 deletion to behave like FAT deletion.** Directory entries vanish on ext4; switch technique instead of concluding nothing was deleted.
- **Ignoring encoding.** Searching only ASCII misses UTF-16 text; search both, and try Unicode-capable indexing in Autopsy.
- **Treating a keyword hit as a finding.** A match proves bytes exist at an offset; it does not name a file, an author or a time.
- **Forgetting that compressed and encrypted content is invisible to a string search.** A clean keyword search is not a completeness argument.
- **Parsing a hive without its transaction logs**, or reading a key's last-write time as a value's write time. Both produce conclusions the hive does not support.
- **Overlooking shadow copies.** Where the platform kept historical volume states, "the file is not on the volume" may be true only of the current state.
- **Mixing metadata-based recovery and carving in one evidence list.** They support different claims; label each recovered item with the method that produced it.
- **Overclaiming what a tool found.** A carved fragment or a matching keyword is a lead to corroborate, not a conclusion.
- **Tip:** build a small artifact cheat-sheet (hive paths, DB schemas, key names) — it speeds up every case.
- **Tip:** keep a "tool + version + command" log; reproducibility is what makes analysis defensible.
- **Tip:** record the volume serial number with every artefact you extract, so a later reviewer can prove which volume it came from.

## Checklist / Self-Test

- [ ] Can I explain the difference between allocated, deleted, and slack data, and where each lives on NTFS?
- [ ] Can I name the NTFS metadata files that matter forensically and one question each answers?
- [ ] Can I explain resident versus non-resident data, and why it changes what recovery is possible?
- [ ] Do I know the structure of the Recycle Bin (`$R`/`$I` files) and its XP-era equivalent?
- [ ] Do I know how deletion differs across NTFS, FAT/exFAT and ext4, and how that changes my first technique?
- [ ] Can I run the recovery decision tree for a deleted file and say which branch I am in?
- [ ] Can I read a file's slack and the volume's unallocated space with `blkls`, and map a hit back to a cluster?
- [ ] Can I name the main registry hives and at least one forensic artifact found in each?
- [ ] Can I explain three ways a naive registry parse produces a wrong conclusion?
- [ ] Do I know what a Volume Shadow Copy can give me that unallocated space cannot, and how to check whether any exist?
- [ ] Can I describe what a Prefetch file records and when it will not exist?
- [ ] Do I know the key SQLite tables for Chrome/Edge history and Firefox history?
- [ ] Can I run `mmls`, `fsstat`, `fls`, `icat`, `istat`, `ils`, `blkls` and `ffind` with the correct offset argument?
- [ ] Can I craft `strings` and `grep` searches for ASCII and UTF-16 content, and state the two things such a search cannot prove?
- [ ] Do I understand what signature-based carving recovers and its limitation with fragmented files?

## Further Resources

- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **The Sleuth Kit (TSK)** — https://www.sleuthkit.org/sleuthkit/
- **Autopsy** — https://www.sleuthkit.org/autopsy/
- **Eric Zimmerman's forensic tools** (PECmd, Registry Explorer, MFTECmd, and more) — https://ericzimmerman.github.io/
- **RegRipper** (registry analysis) — https://github.com/keydet89/RegRipper3.0
- **libyal file system libraries** (`libfsntfs`, `libfsfat`, `libfsext`, `libvshadow` and siblings: the reference documentation for the on-disk structures described above) — https://github.com/libyal
- **Forensics Wiki** (artifact encyclopedia) — https://forensics.wiki/
- **SANS reading room** (white papers on Windows and browser forensics) — https://www.sans.org/reading-room/

> **Verification:** executed on **2026-09-19** against **The Sleuth Kit 4.12.1** and **sqlite3
> 3.45.1** (Ubuntu 24.04 WSL). The Section 8 pragma was run in both forms on a 10-page database
> with a freed table: `sqlite3 pragma.db "PRAGMA freelist_count;"` printed `8` and exited 0, while
> `PRAGMA free page counts;` exited 1 with `Error: in prepare, near "page": syntax error`. The
> Section 10 correction was run on an ext4 image built in `/tmp`: `ils -o 2048 -m / image.dd`
> fails — with `-o 0` as the offset it exits 1 with
> `Invalid magic value (raw_open: image "/" - is a directory)` and writes nothing to stdout —
> whereas `ils -o 0 -m image.dd` exits 0. **Not executed:** the browser-database and registry
> examples — no case image or hive is available here. The carving example was attempted and its
> cause is now **established**: `foremost` 1.5.7 and `scalpel` 1.60 are installed and both run, but
> `foremost -t jpg` (and `-t jpeg`, `-t all`) extracted **0 files** from every input tried on
> 2026-09-19 — a raw payload with the `ffd8ffe0`/`ffd9` markers, the same payload padded, and a real
> 542 091-byte JPEG from `C:\Windows\Web`, as a plain file and inside an ext4 image. The reason is
> that this build carries **no** compiled-in signature table for those types (`strings
> /usr/bin/foremost` contains no `jpg`/`jpeg`/`png`/`pdf`/`zip`) **and** `/etc/foremost.conf` ships
> with **every** one of its 239 type lines commented out, so `-t jpg` names a type that exists
> nowhere: the run completes, `audit.txt` reads `0 FILES EXTRACTED` and the exit status is 0, with
> nothing on stderr to warn you. The same run with a single line of that same config re-enabled
> (`-c` pointing at it, with `jpg y 20000000 \xff\xd8\xff\xe0\x00\x10 \xff\xd9`) carved one file,
> byte-identical to the planted payload — so the `-t jpg,pdf,zip` form above carves nothing until
> those lines are enabled, and it then matches the old JFIF header only. Confirm on your build rather
> than assuming either way.
