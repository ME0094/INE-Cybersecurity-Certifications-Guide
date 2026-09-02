# Forensic Exercises — Lab Guide

> eCDFP · Labs — INE Cybersecurity Certifications Study Guide
>
> Build your own forensic exercise images and run four guided drills: deleted-file recovery, browser artifact analysis, timeline construction, and memory-dump analysis. Everything here runs on media you create yourself — fully authorized practice.

## Environment and prerequisites

A Linux workstation (Debian/Ubuntu or Kali) with:

```bash
# Required packages (Debian/Ubuntu)
sudo apt install sleuthkit dosfstools sqlite3 foremost autopsy

# Volatility 3 (Python 3)
pipx install volatility3          # or: pip install volatility3
vol --help                        # confirm it runs (aliases: vol, vol.py)
```

**Golden rules for every drill:**

- Work inside a **disposable VM** for anything that touches a live browser or a memory capture.
- Never practice on systems you do not own.
- Save each image plus its hash; the drills assume you keep them.

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
file ~/lab/case1/disk.img            # ... DOS/MBR boot sector, FAT32 ...
sha256sum ~/lab/case1/disk.img > ~/lab/case1/disk.img.sha256
```

**Expected outcome:** one FAT32 image whose own hash you recorded. Deleting `secret.pdf` while it is mounted simulates a suspect who removed a file; the copy in `archive/` is your control.

> Optional realism upgrade: instead of formatting the file directly, create a partition table with `fdisk`/`parted`, then remember every TSK command needs `-o <start_sector>` from `mmls`.

## Drill 1 — Recover a deleted file

**Objective:** prove a deleted file existed, recover its exact content, and confirm integrity.

```bash
# Confirm the deletion: list deleted entries on the image
fls -f fat -d -r ~/lab/case1/disk.img
# r/r * 5:  secret.pdf          <- '*' means deleted; 5 is the meta address
# r/r * 6:  archive/backup.pdf  <- still allocated, not deleted

# The allocated copy proves the filename + content existed
fls -f fat -r ~/lab/case1/disk.img
# r/r 4:     notes.txt
# r/r 6:     archive/backup.pdf

# Recover the deleted file by its meta address
icat -f fat -r ~/lab/case1/disk.img 5 > ~/lab/case1/recovered_secret.pdf

# Integrity proof: compare against the hash you saved in Drill 0
sha256sum ~/lab/case1/recovered_secret.pdf
# <the hash you saved>  recovered_secret.pdf   <- identical = clean recovery
```

**Expected outcome:** `fls -d` shows the deleted entry with an asterisk, `icat -r` returns the bytes, and the recovered hash matches the original. If you accidentally wrote to the image after deleting, recovery may fail or be partial — repeat Drill 0 before retrying.

## Drill 2 — Identify browser artifacts

**Objective:** extract a browser profile from an image and answer *what the user looked at* using SQLite queries.

Preparation (one time, on a disposable VM): browse several sites in **Firefox**, then copy its profile databases into a second exercise image.

```bash
# On the VM (Firefox keeps its history in places.sqlite)
ls ~/.mozilla/firefox/*.default-release/places.sqlite ~/.mozilla/firefox/*.default-release/cookies.sqlite

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

# Read them with sqlite3 — most visited pages first
sqlite3 ~/lab/case2/places.sqlite \
  "SELECT p.url, p.title FROM moz_places p
   JOIN moz_historyvisits h ON p.id = h.place_id
   ORDER BY h.visit_date DESC LIMIT 10;"
# https://example.com/training        | hands-on lab site
# https://mail.example.org/inbox      | Webmail

# Cookies reveal sessions and trackers
sqlite3 ~/lab/case2/cookies.sqlite \
  "SELECT host, name, datetime(expiry,'unixepoch') FROM moz_cookies LIMIT 10;"
# .example.com   sessionid   2026-01-15 12:00:00
```

**Expected outcome:** an ordered list of visited URLs with titles and a cookie table with hosts and expiry dates — enough to state *who browsed where, when*. (Chrome works the same way: `History` DB, table `urls`; `Cookies` DB, table `cookies`.)

## Drill 3 — Build a timeline

**Objective:** turn file metadata from `disk.img` into a chronological CSV and answer "what changed, in what order."

Sleuth Kit's timeline pipeline is: `fls -m` → **body file** → `mactime` → CSV.

```bash
# Generate a body file (m = MAC times, -m /lab sets the path prefix)
fls -f fat -r -p -m /lab ~/lab/case1/disk.img > ~/lab/case1/body.txt

# Convert to a readable CSV (UTC keeps timestamps unambiguous)
mactime -b ~/lab/case1/body.txt -d -z UTC > ~/lab/case1/timeline.csv
head -5 ~/lab/case1/timeline.csv
# Date,Size,Type,Mode,UID,GID,Meta,File Name
# Sun Jan 12 10:02:00 2025,32,r/r,rwx------,0,0,5,/lab/secret.pdf
# Sun Jan 12 10:02:11 2025,40,r/r,rwx------,0,0,4,/lab/notes.txt
```

**Expected outcome:** a CSV where you can find when `secret.pdf` was created (`...` = MAC time), when it was deleted (compare with `fls -d` timestamps), and reconstruct the order of events. For richer timelines, feed the same body file into Autopsy's timeline view, or use Plaso (`log2timeline` + `psort`) on a full image.

## Drill 4 — Analyze a memory dump

**Objective:** run an end-to-end memory analysis: identify the system, enumerate processes, find an anomaly, and preserve it.

Two authorized ways to get a sample:

1. **Your own VM:** run a Windows VM in a hypervisor and snapshot its memory while a planted process runs (e.g., a copy of `notepad.exe` renamed to `C:\Windows\Temp\svchost.exe` and started). Export the snapshot (VMware `.vmem`, VirtualBox `dumpvmcore`).
2. **Public sample:** the official Volatility sample images and DFRWS challenge dumps (dfrws.org) — download to your lab machine.

Analysis (Volatility 3):

```bash
# 1) Identify the OS and confirm symbols loaded
vol -f ~/lab/case3/mem.raw windows.info

# 2) Get the process picture
vol -f ~/lab/case3/mem.raw windows.pstree
vol -f ~/lab/case3/mem.raw windows.cmdline

# 3) Network artifacts
vol -f ~/lab/case3/mem.raw windows.netscan

# 4) Hunt injected code in the suspicious PID
vol -f ~/lab/case3/mem.raw windows.malfind --pid 2468

# 5) Preserve the evidence
vol -f ~/lab/case3/mem.raw windows.memdump --pid 2468 --dump ~/lab/case3/dumps/
vol -f ~/lab/case3/mem.raw windows.dumpfiles --pid 2468 --dump
sha256sum ~/lab/case3/dumps/*.dmp
```

**Expected outcome:** you can name the OS/build, produce a process tree, and — if you planted the renamed `notepad.exe` — point to the anomaly: an `svchost.exe` whose **parent is `explorer.exe`** (real services are children of `services.exe`) or whose image path points to `Temp`. With a public sample, expect at least: OS identification, a process inventory, and a flagged process with a network connection or injected region. You do not need a "gotcha" finding on every sample — a clean baseline, documented, is a valid result.

## Common mistakes & tips

- **Writing to the image after deletion** — any new write can overwrite the deleted file's clusters; unmount and stop touching it before recovering.
- **Recovering before you hashed** — save the original file hash at creation time; without it you cannot *prove* a clean recovery.
- **Practicing deletion recovery on ext4** — ext-family removes directory entries on delete, so `fls -d` often finds nothing; use FAT/NTFS for this drill, and remember real-world ext4 recovery usually needs carving or journal tools.
- **Running the browser drill on your daily-driver browser** — use a disposable VM; you are copying a real history database.
- **Ignoring timezones in timelines** — record or convert to UTC (`mactime -z UTC`); a timeline in mixed local times is worthless.
- **Analyzing a memory dump on the box it came from** — move the sample to a clean machine first.
- **Skipping Drill 0 cleanly** — most drill failures trace back to a sloppy exercise image; redo it rather than debugging downstream.

## Checklist / Self-test

- [ ] I built a FAT32 exercise image and recorded its SHA-256 before touching it further.
- [ ] I deleted a file on purpose and recovered it with `fls -d` + `icat -r`, hash-verified byte-for-byte.
- [ ] I extracted `places.sqlite`/`cookies.sqlite` from an image and listed visited URLs with SQLite.
- [ ] I generated a body file and produced a `mactime` CSV in UTC, and can read a deletion event off it.
- [ ] I ran `windows.info`, `windows.pstree`, and `windows.netscan` on a memory sample.
- [ ] I spotted (or ruled out) an anomalous process and dumped it with `memdump`/`dumpfiles`.
- [ ] Every drill artifact (image, recovered file, CSV, dump) sits in a folder with its hash recorded.
- [ ] I can explain, for each drill, one thing that would invalidate the result (write-after-delete, wrong timezone, etc.).

## Further resources

- NIST SP 800-86 — *Guide to Integrating Forensic Techniques into Incident Response* (csrc.nist.gov/publications).
- The Sleuth Kit wiki (body file and `mactime` format) — sleuthkit.org.
- Volatility 3 documentation and sample images — volatility3.readthedocs.io, github.com/volatilityfoundation.
- Autopsy documentation (timeline ingest) — sleuthkit.org/autopsy.
- DFRWS challenge datasets for authorized practice — dfrws.org.
- `man fls`, `man icat`, `man mactime`, `man mkfs.vfat` on your practice system.
