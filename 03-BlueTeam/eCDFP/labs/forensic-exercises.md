# Forensic Exercises — Lab Guide

> eCDFP · Labs — INE Cybersecurity Certifications Study Guide
>
> Build your own forensic exercise images and run six guided drills: deleted-file recovery, browser artifact analysis, timeline construction, memory-dump analysis, Windows artefact parsing from an image, and carving from unallocated space. Everything here runs on media you create yourself — fully authorized practice.
>
> This is the **basic drills** file. Its companion `lab-environment.md` builds the VMs, snapshot discipline and acquisition procedure these drills assume; the case-level labs are `windows-execution-lab.md`, `memory-injection-lab.md`, `supertimeline-lab.md` and `anti-forensics-lab.md`.
>
> Every command is a **syntax reference**. This repository ships no captured command output: there is no image, no toolchain and no sample on the machine that wrote this file. The `#` comments inside the examples show the *shape* of the output you should expect — values, paths and metadata addresses in your run will differ, and nothing here is a transcript. Where a result would matter to a conclusion, the text says what to look for and why.

## Environment and prerequisites

Build the workbench first, following `lab-environment.md`. In short: a disposable `win-lab` Windows VM, a separate `linux-lab` analysis VM that holds the toolchain, an isolated network, consistent snapshots, and the `~/lab/<case-id>/` evidence workspace. Do not run the analysis tools on the machine that generated the evidence.

```bash
# Required packages on linux-lab (Debian/Ubuntu)
sudo apt install sleuthkit dosfstools sqlite3 foremost autopsy

# Volatility 3 (Python 3)
pipx install volatility3          # or: pip install volatility3
vol --help                        # confirm it runs and note the framework version
# What to look for: the usage line naming the version, and the plugin list. The console
# command has been both 'vol' and 'vol.py' across releases — use whichever exists.

# Optional but useful for the Windows artefact drill
# RegRipper, and the Windows-side parsers from ../tools/windows-artifact-tools.md
```

**Golden rules for every drill:**

- Work inside a **disposable VM** for anything that touches a live browser or a memory capture.
- Never practice on systems you do not own.
- Save each image plus its hash; the drills assume you keep them.
- Record the tool **name and version** for every command you run. A drill you cannot reproduce is a drill you did not learn from.
- Keep an `answer-key.md` in `notes/` for the drills where you stage activity. Scoring yourself against ground truth is the only way to tell a null result from a missed one.

## The drill loop, and how to score yourself

Each drill below follows the same shape: build the evidence, acquire it, analyse it, then compare what you found against what you planted. Run the loop twice per drill — once following the steps, once from memory with the file closed.

| Stage | What you do | What you write down |
| --- | --- | --- |
| **Build** | Create the evidence with a known ground truth | The answer key: what you did, and when, before you acquire anything |
| **Freeze** | Snapshot or power off; acquire per `lab-environment.md` | Acquisition log row: source hash, image hash, tool and version |
| **Analyse** | Run the drill's technique on the working copy | The commands, in order, with their results |
| **Score** | Compare findings against the answer key | Which artefacts found what, and which found nothing |
| **Break it** | Name one thing that would have invalidated the result | A sentence in your notes, per drill |

That last row is the part people skip and the part that matters. "This result would be invalid if I had written to the image after deleting the file" is the reflex an examiner needs.

## Drill 0 — Build the exercise image

We create a small **FAT32** image. FAT keeps directory entries for deleted files (until overwritten), which makes it ideal for the deleted-file drill — the same technique applies to NTFS, where deleted records survive in the MFT.

```bash
# 1) Create a 64 MB raw file and format it as FAT32
dd if=/dev/zero of=~/lab/case1/disk.img bs=1M count=64 status=progress
mkfs.vfat -F 32 -n LABROOT ~/lab/case1/disk.img

# 2) Mount it and add content
mkdir -p /tmp/labmnt
sudo mount -o loop ~/lab/case1/disk.img /tmp/labmnt

echo "TOP-SECRET budget planning 2025" > /tmp/labmnt/secret.pdf
echo "meeting notes"                > /tmp/labmnt/notes.txt
mkdir -p /tmp/labmnt/archive
cp /tmp/labmnt/secret.pdf /tmp/labmnt/archive/backup.pdf
sha256sum /tmp/labmnt/secret.pdf    # save this hash: it proves a clean recovery later

# 3) Delete one file on purpose, sync, and unmount — then stop writing to the image
rm /tmp/labmnt/secret.pdf
sync
sudo umount /tmp/labmnt

# 4) Verify the image is a self-contained, mountable artifact
file ~/lab/case1/disk.img            # expect: a DOS/MBR boot sector, FAT32 wording
sha256sum ~/lab/case1/disk.img > ~/lab/case1/disk.img.sha256
```

**Expected outcome:** one FAT32 image whose own hash you recorded. Deleting `secret.pdf` while it is mounted simulates a suspect who removed a file; the copy in `archive/` is your control.

> Optional realism upgrade: instead of formatting the file directly, create a partition table with `fdisk`/`parted`, then remember every TSK command needs `-o <start_sector>` from `mmls`. Doing this once is worth it — offset handling is the single most common source of confusion in the drills that follow.

**Variants worth running once each**, because they teach different lessons:

| Variant | What it shows |
| --- | --- |
| Build the image as NTFS instead of FAT32 | The same drill against an MFT, where a deleted record survives in the metadata |
| Add a partition table (see the note above) | Why `-o` exists, and what "file system not found" means |
| Create and delete a file *smaller than one cluster* | Resident data on NTFS: the content can live inside the metadata record |
| Create a large file, delete it, then write new data | Why recovery fails when clusters are reused |

## Drill 1 — Recover a deleted file

**Objective:** prove a deleted file existed, recover its exact content, and confirm integrity.

```bash
# Confirm the deletion: list deleted entries on the image
fls -f fat -d -r ~/lab/case1/disk.img
# What to look for: a line for secret.pdf marked as deleted, with a metadata address in
# the leading columns. Record that address — it is the argument for icat next.

# The allocated copy proves the filename and content existed
fls -f fat -r ~/lab/case1/disk.img
# What to look for: notes.txt and archive/backup.pdf listed as allocated, and
# secret.pdf absent from the allocated listing while present in the deleted one.

# Recover the deleted file by its meta address
icat -f fat -r ~/lab/case1/disk.img <meta-address> > ~/lab/case1/recovered_secret.pdf

# Integrity proof: compare against the hash you saved in Drill 0
sha256sum ~/lab/case1/recovered_secret.pdf
# What to look for: a digest identical to the one you saved before deleting the file.
# Identical = a clean recovery. Different = partial recovery or cluster reuse; say so.
```

**Expected outcome:** `fls -d` shows the deleted entry, `icat -r` returns the bytes, and the recovered hash matches the original. If you wrote to the image after deleting, recovery may fail or be partial — repeat Drill 0 before retrying.

Also record which files `icat` **could not** recover, and why. The negative results are part of the drill.

## Drill 2 — Identify browser artifacts

**Objective:** extract a browser profile from an image and answer *what the user looked at* using SQLite queries.

Preparation (one time, on `win-lab`, not on your daily driver): browse several sites in **Firefox**, then copy its profile databases into a second exercise image.

```bash
# On the victim VM (Firefox keeps its history in places.sqlite)
ls ~/.mozilla/firefox/*.default-release/places.sqlite ~/.mozilla/firefox/*.default-release/cookies.sqlite
# What to look for: the profile directory name — modern Firefox uses a release-suffixed
# profile, but the exact name varies. Copy the files you actually find.

# Build a small image and drop the DBs into it
dd if=/dev/zero of=~/lab/case2/browser.img bs=1M count=16 status=progress
mkfs.vfat -F 32 -n BROWSER ~/lab/case2/browser.img
sudo mount -o loop ~/lab/case2/browser.img /tmp/labmnt
sudo cp ~/.mozilla/firefox/*.default-release/places.sqlite /tmp/labmnt/
sudo cp ~/.mozilla/firefox/*.default-release/cookies.sqlite /tmp/labmnt/
sudo umount /tmp/labmnt
```

Now play the analyst — extract and interrogate the artifacts from the raw image:

```bash
# Pull the DBs out of the image with icat (find their meta addresses first)
fls -f fat -r ~/lab/case2/browser.img
icat -f fat -r ~/lab/case2/browser.img <places_meta> > ~/lab/case2/places.sqlite
icat -f fat -r ~/lab/case2/browser.img <cookies_meta> > ~/lab/case2/cookies.sqlite

# Read them with sqlite3 — most recent visits first
sqlite3 ~/lab/case2/places.sqlite \
  "SELECT p.url, p.title FROM moz_places p
   JOIN moz_historyvisits h ON p.id = h.place_id
   ORDER BY h.visit_date DESC LIMIT 10;"
# What to look for: the sites you browsed, newest first. moz_historyvisits.visit_date is
# in microseconds since the Unix epoch: divide by 1000000 before formatting it as a time.
# If the order looks wrong or the dates are absurd, you converted the wrong epoch.

# Cookies reveal sessions and trackers
sqlite3 ~/lab/case2/cookies.sqlite \
  "SELECT host, name, datetime(expiry,'unixepoch') FROM moz_cookies LIMIT 10;"
# What to look for: host names you actually visited. A cookie table with nothing in it
# means either no cookies were set or you copied the wrong file.
```

**Expected outcome:** an ordered list of visited URLs with titles and a cookie table with hosts and expiry dates — enough to state *who browsed where, when*. (Chrome works the same way: `History` DB, table `urls`; `Cookies` DB, table `cookies`.)

Two extensions that make this drill realistic:

- **Clear the browser history, then re-run the analysis.** The live tables will be empty; check the database's free pages (`PRAGMA free page counts`) and consider carving the database file. Record what you recovered and what you did not.
- **Compare the browser record against the file system.** Find the file created by a download and correlate its birth time with the corresponding row in the `downloads` table. That correlation is the actual forensic skill; the SQL is the easy part.

## Drill 3 — Build a timeline

**Objective:** turn file metadata from `disk.img` into a chronological CSV and answer "what changed, in what order."

Sleuth Kit's timeline pipeline is: `fls -m` → **body file** → `mactime` → CSV.

```bash
# Generate a body file (-m sets the path prefix used in the output)
fls -f fat -r -p -m /lab ~/lab/case1/disk.img > ~/lab/case1/body.txt

# Convert to a readable CSV (UTC keeps timestamps unambiguous)
mactime -b ~/lab/case1/body.txt -d -z UTC > ~/lab/case1/timeline.csv
head -5 ~/lab/case1/timeline.csv
# What to look for: a header row naming the columns (a date column, a size, a type, a
# mode, ids, a metadata address, and a file name), then one row per timestamped event.
# Note that a single file produces several rows — one per timestamp — and the type
# column tells you which timestamp each row represents.
```

**Expected outcome:** a CSV where you can find when `secret.pdf` was created, when it was modified, and — by comparing against `fls -d` output and the metadata record — which of its timestamps survive after deletion. Then reconstruct the order of events in one paragraph.

Three points that separate a useful timeline from a confusing one:

- **A file yields up to four rows.** If you read every row as a separate event, your event count is wrong and your narrative will be too. Filter by the type column.
- **Set the time zone explicitly** (`-z UTC`), and note it. A timeline whose zone is implicit is a timeline you cannot correlate with anything.
- **Compare bodyfile output with `ils -m` output.** `ils` adds metadata records that `fls` does not show, including records with no directory entry left — which is exactly where a deleted file's evidence lives.

For richer timelines, feed the same body file into Autopsy's timeline view, or use plaso (`log2timeline` + `psort`) on a full image — see `../tools/timeline-tools.md`, and run the case-level `supertimeline-lab.md` when you want the multi-source version.

## Drill 4 — Analyze a memory dump

**Objective:** run an end-to-end memory analysis: identify the system, enumerate processes, find an anomaly, and preserve it.

Two authorized ways to get a sample:

1. **Your own VM:** run `win-lab` in a hypervisor and snapshot its memory while a planted process runs (e.g., a copy of `notepad.exe` renamed to a path under `C:\Windows\Temp\` and started). Export the snapshot using your hypervisor's facility, and note what format it produces.
2. **Public sample:** the official Volatility sample images and DFRWS challenge dumps (dfrws.org) — download to `linux-lab`.

> Validate the dump before you analyse it. Run a basic identification plugin first; if the OS is not recognised or symbols did not resolve, fix that before interpreting anything. A plugin that failed on missing symbols gave you no result — not a clean one. See `../tools/memory-analysis.md`.

Analysis (Volatility 3):

```bash
# 1) Identify the OS and confirm symbols loaded
vol -f ~/lab/case3/mem.raw windows.info
# What to look for: the OS build, the kernel base, and evidence that a symbol table was
# located. If this step fails, every later step is meaningless.

# 2) Get the process picture — and diff the two ways of getting it
vol -f ~/lab/case3/mem.raw windows.pstree
vol -f ~/lab/case3/mem.raw windows.pslist
vol -f ~/lab/case3/mem.raw windows.psscan
vol -f ~/lab/case3/mem.raw windows.cmdline
# What to look for: a PID present in psscan and absent from pslist (a candidate hidden
# process) — and equally, a PID present in psscan with a plausible exit time (a
# terminated process, not a hidden one). Note the start times: a process started after
# the capture window cannot exist, which is a useful sanity check on your dump.

# 3) Network artifacts
vol -f ~/lab/case3/mem.raw windows.netscan

# 4) Hunt injected code in the suspicious PID, then check the structural question
vol -f ~/lab/case3/mem.raw windows.malfind --pid 2468
vol -f ~/lab/case3/mem.raw windows.vadinfo --pid 2468

# 5) Preserve the evidence
vol -f ~/lab/case3/mem.raw windows.memdump --pid 2468 --dump ~/lab/case3/dumps/
vol -f ~/lab/case3/mem.raw windows.dumpfiles --pid 2468 --dump
sha256sum ~/lab/case3/dumps/*.dmp
```

**Expected outcome:** you can name the OS/build, produce a process tree, and — if you planted the renamed `notepad.exe` — point to the anomaly: an `svchost.exe`-named process whose **parent is `explorer.exe`** (real service hosts are children of the service control manager) or whose image path points to a temporary directory. With a public sample, expect at least: OS identification, a process inventory, and one flagged process with a network connection or an executable private region. You do not need a "gotcha" finding on every sample — a clean baseline, documented, is a valid result.

Three follow-ups that turn this drill into a skill:

- **Corroborate on disk.** Image the same VM's disk and check whether the planted binary exists on disk, when it was created, and whether any artefact records its execution. Memory plus one independent artefact is the difference between a lead and a finding.
- **Try to break your own conclusion.** Name one legitimate explanation for the anomaly you found (a scheduled task, an update process, a script host you started yourself) and show why the evidence excludes it — or admit that it does not.
- **Document the failure you hit.** Missing symbols, an unusable hypervisor snapshot, a plugin name you misremembered — write it down with the error. The diagnosis table in `../tools/memory-analysis.md` exists for exactly these.

## Drill 5 — Parse Windows artefacts out of an image

**Objective:** take a Windows image, extract its artefact files without mounting it, and answer a specific question about execution and persistence.

Prerequisite: a `win-lab` Windows image built per `lab-environment.md`, preferably with some activity staged deliberately (see `windows-execution-lab.md` for a full version of this drill with an answer key).

```bash
# 1) Find the artefact files inside the image — never mount it.
#    Adjust the offset to the one mmls reports for your image.
fls -o 2048 -r -p ~/lab/case4/win.dd | grep -iE 'Prefetch|config/(SYSTEM|SOFTWARE|SAM)|NTUSER\.DAT|UsrClass\.dat|winevt/Logs'
# What to look for: a path list with a metadata address at the start of each line. Those
# addresses are what icat takes.

# 2) Extract the ones you need (record every command and hash every output)
icat -o 2048 ~/lab/case4/win.dd <SYSTEM_meta>      > ~/lab/case4/exports/SYSTEM
icat -o 2048 ~/lab/case4/win.dd <SOFTWARE_meta>    > ~/lab/case4/exports/SOFTWARE
icat -o 2048 ~/lab/case4/win.dd <NTUSER_meta>      > ~/lab/case4/exports/NTUSER.DAT
sha256sum ~/lab/case4/exports/* > ~/lab/case4/notes/exports-hashes.txt
# What to look for: extracted files whose sizes are plausible for a hive (megabytes, not
# bytes). A tiny hive means you extracted the wrong record or a slack remnant.

# 3) Extract and parse the Prefetch folder
fls -o 2048 -r -p ~/lab/case4/win.dd | grep -i '/Prefetch/.*\.pf'
# Then extract them one by one with icat into a folder and parse with a Windows-side
# parser from ../tools/windows-artifact-tools.md, on a Windows analysis host.

# 4) Registry questions, answered offline with RegRipper
rip.pl -r ~/lab/case4/exports/SYSTEM -p usbstor
rip.pl -r ~/lab/case4/exports/NTUSER.DAT -p userassist
# What to look for: device connection history from the SYSTEM hive and GUI execution
# records from the user hive. Confirm plugin names with rip.pl -l on your install.
```

**Expected outcome:** a set of hash-recorded artefacts extracted from the image by offset, plus at least two answers drawn from them — for example which USB devices the machine had seen, and which GUI programs the user profile launched. You should also be able to state, for your image, whether Prefetch was enabled and whether the Prefetch folder is populated at all — because that determines whether an empty result means anything.

What to write down as a limitation, every time: the artefacts you extracted are **copies**, the image remains the exhibit, and a hive parsed without its `.LOG1`/`.LOG2` transaction logs can be stale.

## Drill 6 — Carve from unallocated space

**Objective:** recover content with no metadata left, and be explicit about what carving cannot tell you.

```bash
# Build the scenario: create a file, delete it, then overwrite part of the image so that
# metadata recovery is no longer possible.
cp ~/lab/case1/disk.img ~/lab/case5/disk.img
# (Add a distinctive, recognisable file with a known content type first, then delete it
# and write new data over part of the volume — see Drill 0 for the mount/edit/unmount loop.)

# Carve by signature into per-type output directories
foremost -t jpg,pdf,zip -i ~/lab/case5/disk.img -o ~/lab/case5/carved
# What to look for: per-type subdirectories, and an audit file recording the byte offset
# each carved file came from. Keep that audit file with the results: a carved file whose
# origin offset is unknown cannot be cited.

# Feature extraction, for content types that are not files
bulk_extractor -o ~/lab/case5/bulk ~/lab/case5/disk.img
# What to look for: one report file per feature type, plus a histogram. Read the
# histogram first — it tells you the shape of the corpus before you read individual hits.

# Compare with the metadata-based route, on the same image
fls -f fat -d -r ~/lab/case5/disk.img
# What to look for: whether the metadata route still finds the file. If it does, carving
# was unnecessary — and the metadata route gives you a name and timestamps that carving
# never can.
```

**Expected outcome:** recovered files from the unallocated region, each labelled with the offsets it came from, plus a written comparison of what the metadata route found and what carving found. Then answer, in one sentence each:

- Which recovered artefacts have a **name**? (Only the metadata route produces names.)
- Which have a **timestamp you can defend**? (Carved content has none of its own.)
- Which show signs of **fragmentation** or of being a false positive — a byte sequence that matched a signature without being a real file?

## Common Mistakes & Tips

- **Writing to the image after deletion** — any new write can overwrite the deleted file's clusters; unmount and stop touching it before recovering.
- **Recovering before you hashed** — save the original file hash at creation time; without it you cannot *prove* a clean recovery.
- **Practicing deletion recovery on ext4** — ext-family removes directory entries on delete, so `fls -d` often finds nothing; use FAT/NTFS for this drill, and remember real-world ext4 recovery usually needs carving or journal tools.
- **Reading every bodyfile row as a separate event** — one file produces up to four rows. Filter by the type column or your timeline will over-count.
- **Leaving the timeline time zone implicit** — set UTC explicitly and record it, or the timeline cannot be correlated with anything.
- **Running the browser drill on your daily-driver browser** — use a disposable VM; you are copying a real history database.
- **Analyzing a memory dump on the box it came from** — move the sample to a clean machine first.
- **Interpreting a failed plugin as a clean result** — a symbol or requirement error means you have no result at all. Fix the toolchain before concluding anything.
- **Treating a hypervisor memory snapshot as equivalent to a purpose-built capture** — it may lack structures. Validate it before you trust it.
- **Mounting the evidence** — extract with `icat`/`tsk_recover` instead. A mount can replay a journal, update access times and create new artefacts.
- **Skipping Drill 0 cleanly** — most drill failures trace back to a sloppy exercise image; redo it rather than debugging downstream.
- **File-copying artefacts out of a live system** — copy the image or the extracted artefact, never a live database that a running application is holding open.
- **Tip:** keep an answer key for every drill where you plant activity. Scoring against ground truth is how you find out that your technique missed something rather than that nothing was there.
- **Tip:** after each drill, write one sentence naming what would invalidate your result. It is the same reflex a cross-examination will test.
- **Tip:** record tool versions as you go, not afterwards. Your report's methodology section is assembled from these notes.

## Checklist / Self-Test

- [ ] I built a FAT32 exercise image and recorded its SHA-256 before touching it further.
- [ ] I deleted a file on purpose and recovered it with `fls -d` + `icat -r`, hash-verified byte-for-byte.
- [ ] I ran the NTFS variant of Drill 0 and can explain how deletion differs from FAT.
- [ ] I extracted a browser database from an image and listed visited URLs, with the browser epoch converted correctly.
- [ ] I compared a download entry against the corresponding file's file-system timestamps.
- [ ] I generated a body file and produced a `mactime` CSV in UTC, and can read a deletion event off it.
- [ ] I checked `ils -m` output against `fls -m` output and can explain what the difference contains.
- [ ] I ran `windows.info`, `windows.pstree`, `windows.pslist`, `windows.psscan` and `windows.netscan` on a memory sample.
- [ ] I diffed `pslist` against `psscan` and can distinguish a hidden process from a terminated one.
- [ ] I spotted (or ruled out) an anomalous process, checked whether its suspicious region is file-backed, and dumped it.
- [ ] I extracted a hive and a Prefetch folder from a Windows image with `fls` + `icat`, hash-recorded the outputs, and parsed at least two artefacts.
- [ ] I carved content from unallocated space and stated, for each recovered artefact, whether it has a name and a defensible timestamp.
- [ ] Every drill artifact (image, recovered file, CSV, dump) sits in a folder with its hash recorded.
- [ ] I can explain, for each drill, one thing that would invalidate the result (write-after-delete, wrong timezone, wrong offset, missing symbols).

## Further Resources

- NIST SP 800-86 — *Guide to Integrating Forensic Techniques into Incident Response* (csrc.nist.gov/publications).
- RFC 3227 — *Guidelines for Evidence Collection and Archiving* (order of volatility) — rfc-editor.org/rfc/rfc3227.
- The Sleuth Kit wiki (body file and `mactime` format) — sleuthkit.org.
- Volatility 3 documentation and sample images — volatility3.readthedocs.io, github.com/volatilityfoundation.
- Autopsy documentation (timeline ingest) — sleuthkit.org/autopsy.
- DFRWS challenge datasets for authorized practice — dfrws.org.
- `man fls`, `man icat`, `man istat`, `man mactime`, `man mkfs.vfat` on your practice system.
