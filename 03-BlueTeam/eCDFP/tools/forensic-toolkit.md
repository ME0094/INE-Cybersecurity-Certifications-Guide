# Forensic Toolkit — Imaging, Analysis, Hashing & Carving

> eCDFP · Tools — INE Cybersecurity Certifications Study Guide
>
> Reference guide for the core disk-forensics toolkit: acquisition with `dd`/`dc3dd`, read-only access with write blockers, file-system analysis with The Sleuth Kit (TSK) and Autopsy, integrity hashing, and data carving. All examples target media you own or are authorized to examine.

## 1. Acquisition basics

Acquisition means copying evidence **bit-for-bit without modifying the source**. Two rules dominate:

1. **Never boot, mount, or write to the source** — use a hardware write blocker or a forensic boot environment.
2. **Hash before and after** — record the source hash and prove the image matches it.

A typical acquisition workflow:

1. Attach the suspect drive through a **hardware write blocker**.
2. Identify the device node, e.g. `/dev/sdb`, and confirm it is **read-only**.
3. Hash the source *and* copy it to a clean, pre-hashed target drive.
4. Hash the image and compare; store a written acquisition log (case, date, examiner, hashes).

```bash
# Confirm the write blocker presents the device as read-only (1 = read-only)
blockdev --getro /dev/sdb
# 1
```

## 2. Imaging with dd and dc3dd

`dd` is the classic Linux imaging tool. Key options: `if=` input, `of=` output, `bs=` block size, `conv=noerror,sync` (keep going on read errors, pad bad sectors with zeros), `status=progress`.

```bash
# Full disk image of /dev/sdb to an evidence drive (target mounted elsewhere)
sudo dd if=/dev/sdb of=/mnt/evidence/case01/disk.dd bs=4M conv=noerror,sync status=progress

# The same for a raw partition (logical acquisition)
sudo dd if=/dev/sdb1 of=/mnt/evidence/case01/part1.dd bs=4M conv=noerror,sync status=progress
```

> Do **not** pipe `dd` through compression tools unless you plan for it; forensic workflows usually keep a raw image plus a compressed copy for analysis.

`dc3dd` (a fork of `dd` from the DoD Cyber Crime Center) hashes while copying and logs the result — convenient one-pass integrity.

```bash
sudo dc3dd if=/dev/sdb of=/mnt/evidence/case01/disk.dd hash=sha256 hashlog=/mnt/evidence/case01/hash.log log=/mnt/evidence/case01/acquisition.log
# dc3dd 7.2.646 started ...
# 8192+0 records in
# sha256 (of=/mnt/evidence/case01/disk.dd): 3e6a... (recorded in hash.log)
```

### FTK Imager (concept)

FTK Imager (Exterro, free) is the standard **Windows GUI** for acquisition and preview:

- Creates **raw (dd)** or **E01 (Expert Witness)** images from disks, partitions, folders, or **memory**.
- Lets you **preview** a drive or image read-only and export individual files.
- Verifies image integrity and lets you mount images as read-only logical drives for analysis.

Concept to remember: whatever the tool, acquisition must be **write-protected and hash-verified** — the tool is a convenience wrapper around the same discipline.

## 3. Write blockers

A **write blocker** sits between the suspect drive and the analysis machine, physically or logically denying write commands. Hardware blockers (Tableau, WiebeTech) are preferred for legal defensibility.

```bash
# Verify a device is read-only before you trust it
blockdev --getro /dev/sdb          # prints 1 when read-only
sudo hdparm -r /dev/sdb            # prints "readonly  = 1" when set

# Software-only fallback: never mount read-write
sudo mount -o ro,noexec,nodev /dev/sdb1 /mnt/evidence
sudo mount | grep sdb1             # confirm 'ro' appears in the options
```

Software read-only flags are a convenience, not a substitute for a hardware blocker on a real case.

## 4. Integrity hashing

Hash utilities prove nothing changed between acquisition and analysis.

```bash
# One-off hashes
sha256sum /mnt/evidence/case01/disk.dd
# 3e6a...  disk.dd
md5sum /mnt/evidence/case01/disk.dd

# Create and verify a manifest for a whole tree with hashdeep
hashdeep -c sha256 -l -r /mnt/evidence/case01/ > /mnt/evidence/case01/manifest.txt
hashdeep -k /mnt/evidence/case01/manifest.txt -r -v -a /mnt/evidence/case01/
# hashdeep: Verification completed: 0 files verified
```

Record **both** the source device hash and the image hash in your notes — equal hashes are your proof of a sound copy.

## 5. File-system analysis with The Sleuth Kit

TSK is a collection of command-line tools that read file systems from raw images **without mounting them** (mounting writes metadata; TSK never does). Install with `apt install sleuthkit` or from the official packages.

First, learn the geometry of the image with `mmls` (partition table) and `fsstat` (file-system details). For raw whole-disk images you usually need a **partition offset** (in 512-byte sectors) for the rest of the tools.

```bash
mmls /mnt/evidence/case01/disk.dd
# DOS Partition Table
# 00: Meta    0    0    1
# 01: -----   0    2047    2048
# 02: Linux   2048    1001471    999424    Ext4  (start = sector 2048)

fsstat -f ext4 -o 2048 /mnt/evidence/case01/disk.dd
# FILE SYSTEM INFORMATION
# File System Type: Ext4
# Volume Name: labroot
# ...
```

### fls — list file names

`fls` walks a directory (root by default) and prints name records. Deleted entries are marked with `*`.

```bash
fls -f ext4 -o 2048 /mnt/evidence/case01/disk.dd
# r/r 4:       lost+found
# r/r 12:      notes.txt
# r/r 15:      payroll.xlsx

# Recursive, showing deleted entries only
fls -f ext4 -o 2048 -r -d /mnt/evidence/case01/disk.dd
# r/r * 17:    secret.pdf   <- deleted: note the asterisk and the inode number
```

### icat — read a file's content by inode

`icat` outputs the content of a single inode, which is how you extract one file (including a deleted one) without a full recovery tool. Use `-r` to read the content of a deleted file.

```bash
# Extract the deleted file whose inode is 17
icat -f ext4 -o 2048 -r /mnt/evidence/case01/disk.dd 17 > /mnt/evidence/exports/secret.pdf
file /mnt/evidence/exports/secret.pdf
# secret.pdf: PDF document, version 1.5
```

### ils — list inode (meta) information

`ils` prints inode-level details — used to inspect deleted inode records that `fls` shows.

```bash
ils -f ext4 -o 2048 /mnt/evidence/case01/disk.dd
# class|host|device|start_time
# st_ino|st_alloc|st_uid|st_gid|st_mtime|st_atime|st_ctime|st_size|st_nlink
# 17|0|1000|1000|1735689600|1735689600|1735689600|88221|0
```

> The `ils` output is a body-file-like format — useful input for timeline tools (see the timeline guide and cheatsheet).

### Autopsy

**Autopsy** is a GUI built on TSK that adds a case database, keyword search, bookmarking, timeline view, and ingest modules. Typical flow:

1. Create a **new case** → add a **data source** (image or device).
2. Configure ingest modules (file type detection, hash lookup, keyword search, web artifacts).
3. Review results in the tree: extracted files, deleted files, bookmarks, and the timeline.

```bash
# Launch Autopsy (opens the local web GUI on http://127.0.0.1:9999/autopsy)
autopsy
```

Autopsy is ideal for exploration and reporting; TSK command lines are ideal for scripting and precision.

## 6. File carving

When file-system metadata is gone (formatted drive, damaged FS), **carving** scans raw bytes for file signatures and reassembles data. Carving is for *unallocated space recovery*, not a replacement for metadata-based recovery.

```bash
# foremost: carve jpg, pdf, zip files out of the raw image
foremost -i /mnt/evidence/case01/disk.dd -o /mnt/evidence/case01/carved -t jpg,pdf,zip
# Foremost version 1.5.7 by Jesse Kornblum, Kris Kendall, and Nick Mikus
# File: disk.dd | 8 files recovered

# scalpel: same idea, signature list driven by /etc/scalpel/scalpel.conf
scalpel -o /mnt/evidence/case01/carved_scalpel /mnt/evidence/case01/disk.dd

# bulk_extractor: fast parallel scan for emails, URLs, credit cards, etc.
bulk_extractor -o /mnt/evidence/case01/bulk /mnt/evidence/case01/disk.dd
# bulk_extractor version 2.0.0
# Output directory: /mnt/evidence/case01/bulk  (see url.txt, email.txt, ...)
```

Photorec (TestDisk family) is another carving option best for photo recovery. Remember: carved files lose their original names and timestamps, so document how you carved them.

## Common Mistakes & Tips

- **Mounting the evidence** — mounting a suspect image, even read-only, is a red flag on a real case; use TSK tools on the image instead.
- **Imaging the wrong device node** — always confirm with `lsblk`/`blkid` before `dd`; a single typo can destroy the wrong disk.
- **Forgetting the partition offset** — running `fls` without `-o` on a whole-disk image yields "file system not found"; read the offset from `mmls` first.
- **Trusting a hash you never compared** — compute hashes of source and image, and *look* at both strings.
- **Carving when you should recover metadata-first** — deleted-file recovery through `fls -d`/`icat -r` preserves names and metadata; carve only what metadata cannot reach.
- **Using `dd` on a mounted live system** — acquire from a forensic boot environment or write-blocked hardware, never from the running OS you are imaging.

## Checklist / Self-Test

- [ ] I can explain why write blockers and hash verification are non-negotiable in acquisition.
- [ ] I imaged a practice device with `dd` and `dc3dd` and compared the resulting hashes.
- [ ] I used `mmls` to find a partition offset and `fsstat` to identify the file system.
- [ ] I listed files with `fls`, spotted a deleted entry (`*` marker), and extracted it with `icat -r`.
- [ ] I used `ils` to read inode metadata for a deleted file.
- [ ] I created an Autopsy case, added an image, and located the deleted file there too.
- [ ] I carved files from an image with `foremost` and could name what carving does *not* preserve.
- [ ] I can list the two rules that apply to every acquisition (write-protect, hash-verify).

## Further Resources

- NIST SP 800-86 — *Guide to Integrating Forensic Techniques into Incident Response* (csrc.nist.gov/publications).
- The Sleuth Kit documentation and wiki — sleuthkit.org.
- Autopsy user documentation — sleuthkit.org/autopsy.
- dc3dd project page — sourceforge.net/projects/dc3dd.
- FTK Imager product page — exterro.com/digital-forensics-software/ftk-imager.
- hashdeep (md5deep family) — github.com/jessek/hashdeep.
- `man dd`, `man dc3dd`, `man foremost`, `man mmls` on your practice system.
