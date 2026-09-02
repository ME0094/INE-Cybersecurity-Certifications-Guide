# Forensic Analysis (eCDFP Methodology — Phase 02)

> Companion study guide for the eCDFP (Certified Digital Forensics Professional) Blue Team methodology track. This phase turns raw acquired data into answers: which artifacts exist, what they reveal, and what user or attacker activity they imply.

## Overview

Analysis (NIST's *examination* phase) is where you interrogate the acquired image. You do not read every byte — you work **artifact-driven**: form questions first (what happened, when, by whom, with which tool), then select the artifacts most likely to answer them. A disciplined order reduces noise:

1. Filesystem structure and file metadata
2. Deleted data, slack, and unallocated space
3. Operating-system artifacts (registry, prefetch, logs)
4. User/application artifacts (browsers, documents, LNK files, jump lists)
5. Targeted keyword searches and carving

Always work on a **verified working copy** of the image and keep notes of every tool, version, and command so findings are reproducible.

## Filesystem Artifacts

### Deleted files and unallocated space

Deleting a file normally removes its *reference*, not its data. On NTFS the Master File Table (MFT) entry is marked unallocated, and the file's clusters stay in place until overwritten. The same logic applies to FAT and ext-family systems. Tools therefore distinguish:

- **Allocated** files — currently referenced by the filesystem.
- **Deleted/unallocated** files — metadata and/or data still present but no longer referenced.

### Slack space

When a file's logical end does not fill its last allocated cluster, the remainder is **file slack**, which has two parts:

- **RAM slack** — from the end of the file's data to the end of the last *sector*; historically filled with leftover memory contents.
- **Drive slack** — from the last sector boundary to the end of the *cluster*; may contain remnants of previously deleted files.

Slack can therefore hide fragments of old data that no longer exist as files. It is a classic place to search and carve.

### Recycle Bin

- **Windows Vista and later:** `$Recycle.Bin\<SID>\` contains `$R...` files (the original data) and `$I...` files (metadata: original path, deletion time, size).
- **Windows XP:** `C:\Recycler\<SID>\INFO2` holds deletion metadata.

Deleting via Shift+Delete bypasses the Recycle Bin entirely — absence of a `$R/$I` pair is not evidence that a file never existed.

### Other high-value filesystem artifacts

- **`$MFT`** — central NTFS index; its *resident* data may survive even when file content is gone.
- **`$LogFile` / `$UsnJrnl`** — NTFS journal and USN change records describing past operations.
- **Pagefile, hiberfil.sys, swap** — may hold fragments of RAM (passwords, documents, chat).
- **Alternate Data Streams (ADS)** — hidden content attached to a file (e.g., `file.txt:hidden.exe`).

## Windows Registry Basics

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
- **ShimCache / AmCache** — evidence of executed programs, including some that never wrote other artifacts.
- **USBSTOR + MountedDevices** — which USB devices connected, when, and their serial numbers.

```bash
# Offline registry analysis with RegRipper (python-based, runs on hive copies)
rip.pl -r SYSTEM -p usbstor        # USB device connection history from the SYSTEM hive
rip.pl -r NTUSER.DAT -p userassist # GUI program execution records for a user
```

Registry *keys* carry a last-write timestamp, and many *values* embed timestamps — registry data is a first-class source for timeline analysis (Phase 03).

## Prefetch Basics (Windows)

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

## Browser and Application Artifacts

### Browsers

Modern browsers store history in SQLite databases, which survive even when the browser UI history was "cleared" — but clearing *does* remove rows, so act fast and analyze copies.

- **Chrome / Edge (Chromium):** profile `History` database with `urls`, `visits`, `downloads`, `search_terms` tables; plus `Cookies`, `Login Data`, and `Cache` files.
- **Firefox:** `places.sqlite` (`moz_places`, `moz_historyvisits`), `cookies.sqlite`, `formhistory.sqlite`.

```bash
# Query a copied Chrome History database directly (never the live one)
sqlite3 "C:\Case\History" \
  "SELECT u.url, u.title, v.visit_time/1000000 - 11644473600 AS epoch
   FROM urls u JOIN visits v ON u.id = v.url ORDER BY v.visit_time DESC;"
```

### Application and user-activity artifacts

- **LNK files** — shortcuts created when a user opens a document or runs a program; they embed the target path and timestamps.
- **Jump Lists** (`AutomaticDestinations` / `CustomDestinations`) — Windows 7+ records of recently opened items per application.
- **Office "Recent" lists, `RecentDocs`, TypedPaths** — corroborate which files a user touched.
- **Web/email caches and chat clients** — application-specific databases worth locating per the investigation's scope.

## Keyword Searching and Carving

### Keyword searching

When you know a target string (password, filename, domain, credit card, phrase), search the *entire* image — including unallocated and slack space — across both ASCII and UTF-16 encodings (Windows stores most text as UTF-16LE).

```bash
# Extract printable strings of a given encoding, then filter
strings -a -e l image.dd | grep -i "password"        # 16-bit little-endian (UTF-16)
strings -a image.dd | grep -iE "smith|example\.com"   # default ASCII

# Search the raw image directly; -a treats binary as text, -b gives byte offsets
grep -aob "credential" image.dd
```

### Carving

**Carving** recovers files from unallocated or slack space without filesystem metadata, by recognizing content. Two approaches:

- **Signature (header/footer) carving** — match known file signatures, e.g., JPEG `FF D8 FF`, PNG `89 50 4E 47`, ZIP `50 4B 03 04`, PDF `%PDF`.
- **Content/statistical carving** — find structured data (e.g., SQLite pages, e-mail headers) even without a clean header/footer.

```bash
# foremost carves files by signature into per-type folders under the output dir
foremost -t jpeg,png,doc,zip -i image.dd -o /case/carved
```

Carved files may be **fragmented** (split across non-contiguous clusters); simple tools recover only contiguous files, so partial or corrupted results are expected — document what you recover and how.

## Practical Tooling: The Sleuth Kit and Autopsy

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
ils -o 2048 -m / image.dd
```

A typical Autopsy workflow: start a new case → add the image → let ingest modules run (file type identification, hash lookup against known-good/bad sets, keyword extraction, timeline) → drill into flagged files with hex/viewers → export exhibits. Hash sets (e.g., NSRL) let you quickly set aside known operating-system files and focus on the unusual.

## Common Mistakes & Tips

- **Analyzing the original image.** Always analyze a verified working copy and keep the master sealed.
- **Skipping the partition offset.** Running `fls` without `-o` on a partitioned disk yields garbage; check `mmls` first.
- **Trusting live tools on a dead image.** File-copying a live machine's `History` database can lock or alter it; copy the image/file first.
- **Only looking at allocated files.** The most interesting evidence is often deleted, in slack, or in the registry.
- **Ignoring encoding.** Searching only ASCII misses UTF-16 text; search both, and try Unicode-capable indexing in Autopsy.
- **Overclaiming what a tool found.** A carved fragment or a matching keyword is a lead to corroborate, not a conclusion.
- **Tip:** build a small artifact cheat-sheet (hive paths, DB schemas, key names) — it speeds up every case.
- **Tip:** keep a "tool + version + command" log; reproducibility is what makes analysis defensible.

## Checklist / Self-Test

- [ ] Can I explain the difference between allocated, deleted, and slack data, and where each lives on NTFS?
- [ ] Do I know the structure of the Recycle Bin (`$R`/`$I` files) and its XP-era equivalent?
- [ ] Can I name the main registry hives and at least one forensic artifact found in each?
- [ ] Can I describe what a Prefetch file records and when it will not exist?
- [ ] Do I know the key SQLite tables for Chrome/Edge history and Firefox history?
- [ ] Can I run `mmls`, `fls`, `icat`, `ils`, and `ffind` with the correct offset argument?
- [ ] Can I craft `strings` and `grep` searches for ASCII and UTF-16 content?
- [ ] Do I understand what signature-based carving recovers and its limitation with fragmented files?

## Further Resources

- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **The Sleuth Kit (TSK)** — https://www.sleuthkit.org/sleuthkit/
- **Autopsy** — https://www.sleuthkit.org/autopsy/
- **Eric Zimmerman's forensic tools** (PECmd, Registry Explorer, and more) — https://ericzimmerman.github.io/
- **RegRipper** (registry analysis) — https://github.com/keydet89/RegRipper3.0
- **Forensics Wiki** (artifact encyclopedia) — https://forensics.wiki/
- **SANS reading room** (white papers on Windows and browser forensics) — https://www.sans.org/reading-room/
