# Forensic Toolkit — Imaging, Analysis, Hashing & Carving

> eCDFP · Tools — INE Cybersecurity Certifications Study Guide
>
> Reference guide for the core disk-forensics toolkit: acquisition with `dd`/`dc3dd`, read-only access with write blockers, file-system analysis with The Sleuth Kit (TSK) and Autopsy, integrity hashing, and data carving. All examples target media you own or are authorized to examine.
>
> Every command is a **syntax reference**. This repository ships no captured command output — there is no image, no device and no toolchain on the machine that wrote this file. The short `# ...` lines inside examples are the *shape* of what a tool reports, not a transcript: where a real result would appear, the text says what to look for. Confirm flags against `--help`/`man` for the version you install.

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
# What to look for: the value 1. A 0 means the device is writable — stop and fix the
# blocker before touching anything else.

# Confirm you are looking at the device you think you are
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE
blkid
# What to look for: the evidence device, and the absence of a mount point. A mounted
# evidence device is not an evidence device.
```

### Choosing the right tool for the job

| Task | Tool | Why |
| --- | --- | --- |
| Image a whole device to raw | `dd` | Universal, simple, no dependencies |
| Image with hashing in one pass | `dc3dd` | Computes the hash while copying and can log it |
| Image into a container with its own integrity metadata | `ewfacquire` (libewf) | Compressed, segmented, verifiable, records case metadata |
| Verify a raw image against its manifest | `sha256sum -c`, `hashdeep -k -a` | Independent, cheap, repeatable |
| Verify an EWF container | `ewfverify` | Checks the container's own checksums per segment |
| Preview or selectively export files on Windows | FTK Imager | Read-only preview without imaging |
| Investigate file systems without mounting | TSK (`mmls`, `fsstat`, `fls`, `icat`, `istat`, …) | Reads the structures directly; never writes |
| Investigate with a case database and ingest | Autopsy | Search, carving, timeline, reporting on top of TSK |
| Recover content with no metadata | `foremost`, `scalpel` | Signature carving from raw bytes |
| Extract features (URLs, emails, cards) at speed | `bulk_extractor` | Parallel scanning with per-feature reports |
| Recover photos from damaged media | `photorec` (TestDisk family) | Purpose-built for camera formats and damaged cards |

## 2. Imaging with dd and dc3dd

`dd` is the classic Linux imaging tool. Key options: `if=` input, `of=` output, `bs=` block size, `conv=noerror,sync` (keep going on read errors, pad bad sectors with zeros), `status=progress`.

```bash
# Full disk image of /dev/sdb to an evidence drive (target mounted elsewhere)
sudo dd if=/dev/sdb of=/mnt/evidence/case01/disk.dd bs=4M conv=noerror,sync status=progress

# The same for a raw partition (logical acquisition)
sudo dd if=/dev/sdb1 of=/mnt/evidence/case01/part1.dd bs=4M conv=noerror,sync status=progress
# What to look for: a final record count and byte total, and no error lines. With
# conv=noerror,sync, read errors are padded rather than fatal — so "it finished" does
# NOT mean "every sector was readable". Capture the error output and count them.
```

> Do **not** pipe `dd` through compression tools unless you plan for it; forensic workflows usually keep a raw image plus a compressed copy for analysis.

`dc3dd` (a fork of `dd` from the DoD Cyber Crime Center) hashes while copying and logs the result — convenient one-pass integrity.

```bash
sudo dc3dd if=/dev/sdb of=/mnt/evidence/case01/disk.dd hash=sha256 hlog=/mnt/evidence/case01/hash.log log=/mnt/evidence/case01/acquisition.log
# What to look for: in the log, the input and output hashes printed side by side, plus
# the record counts and any bad-sector count. Confirm the switch set for your build with
# dc3dd --help: the hash-log option is `hlog=` in current releases (`hashlog=` aborts with
# `[!!] unrecognized option`).

# Re-hashing a finished image for comparison is the same command with the roles swapped
dc3dd if=/mnt/evidence/case01/disk.dd hash=sha256 hlog=/mnt/evidence/case01/rehash.log
```

### The read-error problem, stated precisely

`conv=noerror,sync` makes imaging a failing drive possible. It also means:

- **The image contains zeroes where the source was unreadable.** Those zeroes are invented data. A later attempt to read the same sector — on a different day, with a different drive — may return content, which will not match your image.
- **The source-to-image hash comparison can legitimately fail** on damaged media. Record the error count and the affected regions; a mismatch you can explain is defensible, an unexplained one is not.
- **More retries can be worse than fewer.** A drive that is failing physically may deteriorate with every pass. Where the media matters, consider professional recovery rather than repeated attempts.

### FTK Imager (concept)

FTK Imager (Exterro, free) is the standard **Windows GUI** for acquisition and preview:

- Creates **raw (dd)** or **E01 (Expert Witness)** images from disks, partitions, folders, or **memory**.
- Lets you **preview** a drive or image read-only and export individual files.
- Verifies image integrity and lets you mount images as read-only logical drives for analysis.

Concept to remember: whatever the tool, acquisition must be **write-protected and hash-verified** — the tool is a convenience wrapper around the same discipline.

### Image formats and the constraints they impose

| Format | Constraint that bites in practice |
| --- | --- |
| Raw (`.dd`/`.img`) | One file the size of the source. A 2 TB disk needs 2 TB of free space at the destination. Compression is not built in |
| Raw on a FAT32 destination | **A single file cannot exceed 4 GiB** on FAT32. A large raw image fails partway; use a different file system or EWF segmentation |
| EWF (`.E01`) | Split into segments by default, which solves the size problem; but every tool must be built with libewf support to read it |
| EWF verify | Verification covers the container's segments; it does not tell you the acquisition was complete on a failing drive |
| Compressed raw (a `dd` pipe into `gzip`) | Saves space, costs CPU, and hides the true size from your free-space planning. Hash the uncompressed stream if the case depends on it |
| Images over a network | Integrity depends on the transport. Hash at both ends and compare — the far end's value is part of the record |

## 3. Write blockers

A **write blocker** sits between the suspect drive and the analysis machine, physically or logically denying write commands. Hardware blockers (Tableau, WiebeTech) are preferred for legal defensibility.

```bash
# Verify a device is read-only before you trust it
blockdev --getro /dev/sdb          # prints 1 when read-only
sudo hdparm -r /dev/sdb            # prints "readonly  = 1" when set
# What to look for: the read-only indication from BOTH commands. If they disagree,
# believe the pessimistic one and investigate before imaging.

# Software-only fallback, and only ever on a WORKING COPY derived from the image:
# the source device is never mounted, and neither is the sealed original — a mount
# can replay a journal and write metadata (section 6).
sudo mount -o ro,noexec,nodev,loop /mnt/evidence/case01/working/part1.dd /mnt/evidence
sudo mount | grep part1.dd         # confirm 'ro' appears in the options
```

Software read-only flags are a convenience, not a substitute for a hardware blocker on a real case.

What to check before you trust the setup:

- **The OS has not automounted the device.** Disable automount, or check `lsblk`/`mount` immediately after connecting. Journal replay on a mounted NTFS volume writes to it.
- **The blocker covers the whole device, not just one partition.** A blocker that presents read-only partitions can still expose a writable raw device.
- **The device is not also reachable some other way.** A SAN LUN, a virtual disk attached twice, or a management interface can write to the same media from a path you were not thinking about.
- **Nothing on the workstation is set to write.** Indexing, antivirus real-time scanning, backup agents and desktop search all touch mounted volumes. Exclude the evidence destination from them, and record that you did.

## 4. Integrity hashing

Hash utilities prove nothing changed between acquisition and analysis.

```bash
# One-off hashes
sha256sum /mnt/evidence/case01/disk.dd
# What to look for: a 64-hex-character digest followed by the filename. Record it in the
# case notes — the value on the image is not the record; the note is.
md5sum /mnt/evidence/case01/disk.dd

# Create and verify a manifest for a whole tree with hashdeep
hashdeep -c sha256 -l -r /mnt/evidence/case01/ > /mnt/evidence/case01/manifest.txt
hashdeep -k /mnt/evidence/case01/manifest.txt -r -v -a /mnt/evidence/case01/
# What to look for: a verification summary stating how many files were verified and
# how many did not match. A nonzero mismatch count means something wrote into the
# evidence tree — stop and investigate.
```

Record **both** the source device hash and the image hash in your notes — equal hashes are your proof of a sound copy.

Keeping hashes useful rather than decorative:

- **Store the manifest outside the hashed tree.** A manifest inside the directory it describes can be edited along with the contents.
- **Re-verify at every checkout**, and record the result in the custody log — not only at acquisition.
- **Hash the artefacts you extract**, not just the image. A hive or `$MFT` pulled out with `icat` is a derived file; its hash and the command that produced it are what let a reviewer reproduce it.
- **Keep hashes out of screenshots.** Type or copy the values into the record; a screenshot of a terminal is not a hash record.

```bash
# Verify an EWF container's own integrity metadata, and read its reported metadata
ewfverify /mnt/evidence/case01/disk.E01
ewfinfo   /mnt/evidence/case01/disk.E01
# What to look for: a verification result with no mismatch, and container metadata
# (case number, exhibit, examiner, acquisition date) that matches your acquisition log.
```

## 5. File-system analysis with The Sleuth Kit

TSK is a collection of command-line tools that read file systems from raw images **without mounting them** (mounting writes metadata; TSK never does). Install with `apt install sleuthkit` or from the official packages.

First, learn the geometry of the image with `mmls` (partition table) and `fsstat` (file-system details). For raw whole-disk images you usually need a **partition offset** (in 512-byte sectors) for the rest of the tools.

```bash
mmls /mnt/evidence/case01/disk.dd
# What to look for: one row per partition with a START column in 512-byte sectors. That
# start value is the -o argument for every other tool. Do not confuse sectors with bytes:
# offset 2048 sectors = 1048576 bytes, and passing bytes where -o wants sectors is the
# single most common cause of "file system not found".

fsstat -f ext4 -o 2048 /mnt/evidence/case01/disk.dd
# What to look for: file system type and version, volume label, block/cluster size, total
# and free counts, and the volume serial. Record the serial — artefacts found elsewhere
# can be tied back to this volume with it.
```

### fls — list file names

`fls` walks a directory (root by default) and prints name records. Deleted entries are marked with `*`.

```bash
fls -f ext4 -o 2048 /mnt/evidence/case01/disk.dd
# What to look for: one line per name record, with a metadata address in the second
# column. Handle that address to icat/istat when you want the content or the metadata.

# Recursive, showing deleted entries only
fls -f ext4 -o 2048 -r -d /mnt/evidence/case01/disk.dd
# What to look for: the asterisk marker that identifies a deleted entry, and the
# metadata address you will recover with icat -r.
```

### icat — read a file's content by inode

`icat` outputs the content of a single inode, which is how you extract one file (including a deleted one) without a full recovery tool. Use `-r` to read the content of a deleted file.

```bash
# Extract the deleted file whose inode is 17
icat -f ext4 -o 2048 -r /mnt/evidence/case01/disk.dd 17 > /mnt/evidence/exports/secret.pdf
file /mnt/evidence/exports/secret.pdf
# What to look for: a file type that matches what you expected. A file that reports as
# "data" or all-zero content means the clusters were reused or the inode's runs are gone
# — say so rather than presenting a damaged recovery as a success.
```

On NTFS you can also read a specific **stream** by passing the full stream name, which is how alternate data streams are extracted.

### ils — list inode (meta) information

`ils` prints inode-level details — used to inspect deleted inode records that `fls` shows.

```bash
ils -f ext4 -o 2048 /mnt/evidence/case01/disk.dd
# What to look for: a header line naming the fields, then one line per inode including
# unallocated ones. Confirm the field order from the header rather than assuming it.
```

> The `ils` output is a body-file-like format — useful input for timeline tools (see `timeline-tools.md` and the timeline phase in `../methodology/03-timeline.md`).

```bash
# With -m you get bodyfile-formatted lines you can append to a timeline bodyfile.
# -m is a flag in ils: it takes NO argument (unlike 'fls -m <mount point>', which does).
ils -o 2048 -m /mnt/evidence/case01/disk.dd >> /mnt/evidence/case01/body.txt
```

### istat — one file record in full

`istat` is the tool you reach for when a single file matters: it prints the record's attributes, both NTFS timestamp sets, sizes, and the data run list.

```bash
istat -o 2048 /mnt/evidence/case01/disk.dd 42
# What to look for: the $STANDARD_INFORMATION and $FILE_NAME attribute blocks (their
# disagreement is a timestamp-manipulation indicator), the allocated flag, the size
# fields, and the run list. Runnable with no allocated flag = a deleted file whose
# content may still be addressable.
```

### blkls and blkcat — units rather than files

```bash
# The unallocated (or allocated) units of the volume, as a flat stream
blkls -o 2048 /mnt/evidence/case01/disk.dd > /mnt/evidence/exports/unallocated.raw
# What to look for: the volume of output, which tells you how much free space there is
# to search. Confirm the -a semantics with blkls -h: the flag selects allocated units,
# and misremembering which way round it is produces a search of the wrong region.

# One specific cluster, when you have an offset from a search hit
blkcat -o 2048 /mnt/evidence/case01/disk.dd 12345
```

### ffind, sigfind, tsk_recover, hfind

```bash
# Which name refers to this metadata address? (reverse lookup)
ffind -o 2048 /mnt/evidence/case01/disk.dd 42

# Where on the volume does this byte signature appear? (e.g. a boot sector or a
# backup superblock, when the primary structure is damaged)
sigfind -b 512 -o 510 -l AA55 /mnt/evidence/case01/disk.dd
# Note the two offsets: -b is the block size searched and -o is the offset of the
# signature WITHIN that block (the AA55 boot signature sits at byte 510 of a 512-byte
# sector). sigfind has no partition-offset switch; it scans the file you hand it.
# What to look for: a list of candidate offsets — candidates, not answers. Verify each
# one before reading a file system at that offset.

# Bulk-recover files, allocated or deleted, into a directory tree
tsk_recover -e -o 2048 /mnt/evidence/case01/disk.dd /mnt/evidence/exports/recovered/
# What to look for: recovered files organised by their original paths where metadata
# allowed it, and orphaned files (often in a $OrphanFiles directory) where it did not.
# Label orphaned recoveries as such in your notes.

# Hash-set lookup: set aside known-good OS files so the interesting ones stand out
hfind -i nsrl-md5 /mnt/evidence/nsrl/NSRLFile.txt
hfind -i nsrl-md5 /mnt/evidence/nsrl/NSRLFile.txt d41d8cd98f00b204e9800998ecf8427e
# What to look for: a match report. Confirm the index type and the hash set with
# hfind -h; mixing MD5 and SHA-1 indexes is a silent source of empty results.
```

### Autopsy

**Autopsy** is a GUI built on TSK that adds a case database, keyword search, bookmarking, timeline view, and ingest modules. Typical flow:

1. Create a **new case** → add a **data source** (image or device).
2. Configure ingest modules (file type detection, hash lookup, keyword search, web artifacts).
3. Review results in the tree: extracted files, deleted files, bookmarks, and the timeline.

```bash
# Launch Autopsy (opens the local web GUI)
autopsy
# What to look for: the case wizard. Confirm the port your build reports rather than
# assuming one; older documentation cites a default that recent releases do not use.
```

Autopsy is ideal for exploration and reporting; TSK command lines are ideal for scripting and precision. Whichever you use, the *artefact* you cite in a report is the file or record, not the screenshot of the tool that displayed it.

## 6. Why not to mount the evidence

Mounting is the fastest way to browse an image and the fastest way to destroy your own case. A mount, even read-only at the file-system level, can:

- **Replay a journal** on an uncleanly-dismounted volume, changing metadata.
- **Update access times** depending on the mount options and the volume's configuration.
- **Create new artefacts** — thumbnail caches, index entries, `.Trash` folders, macOS resource forks, Windows `System Volume Information` content.
- **Fail silently on a damaged image**, leaving you reading a partially-repaired view with no indication of what was altered.

Where you must see a file system as a file system, prefer, in order: **(1)** TSK tools on the image; **(2)** extraction of the files you need with `icat`/`tsk_recover`; **(3)** a read-only mount of a *working copy*, never the master, with that decision recorded. Never mount the sealed original.

## 7. File carving

When file-system metadata is gone (formatted drive, damaged FS), **carving** scans raw bytes for file signatures and reassembles data. Carving is for *unallocated space recovery*, not a replacement for metadata-based recovery.

```bash
# foremost: carve jpg, pdf, zip files out of the raw image
foremost -i /mnt/evidence/case01/disk.dd -o /mnt/evidence/case01/carved -t jpg,pdf,zip
# What to look for: per-type output directories and an audit file that records, for each
# carved file, the byte offset it came from. Save that audit file with the results —
# a carved file whose origin offset is unknown is hard to cite.

# scalpel: same idea, signature list driven by /etc/scalpel/scalpel.conf
scalpel -o /mnt/evidence/case01/carved_scalpel /mnt/evidence/case01/disk.dd

# bulk_extractor: fast parallel scan for emails, URLs, credit cards, etc.
bulk_extractor -o /mnt/evidence/case01/bulk /mnt/evidence/case01/disk.dd
# What to look for: one report file per feature type (URLs, email addresses, domains,
# and so on) plus a histogram summarising the scan. Read the histogram first: it tells
# you the shape of the corpus before you read individual hits.
```

Photorec (TestDisk family) is another carving option best for photo recovery. Remember: carved files lose their original names and timestamps, so document how you carved them.

Carving pitfalls that change conclusions:

- **Fragmentation.** Simple carving recovers contiguous runs. A fragmented document yields several partial files rather than one correct one.
- **False positives.** A byte sequence matching a signature inside a compressed or encrypted block is not a file. Verify carved output by opening or parsing it, not by its extension.
- **Carving carves its own input.** Running a carver on an image that contains another image file, a backup archive, or a large database multiplies the apparent evidence. Recognise nested containers and say so.
- **No provenance, no date.** A carved file cannot support a claim about when it was created or who owned it. It supports "content of this type existed in the unallocated region at offsets X–Y".
- **Do not carve before you try metadata.** `fls -d`/`icat -r`/`tsk_recover` preserve names and timestamps. Carve what metadata cannot reach.

## Common Mistakes & Tips

- **Mounting the evidence** — mounting a suspect image, even read-only, is a red flag on a real case; use TSK tools on the image instead.
- **Imaging the wrong device node** — always confirm with `lsblk`/`blkid` before `dd`; a single typo can destroy the wrong disk.
- **Confusing sectors with bytes in `-o`** — TSK offsets are in 512-byte sectors, not bytes. This is the most common cause of "file system not found".
- **Forgetting the partition offset entirely** — running `fls` without `-o` on a whole-disk image yields "file system not found"; read the offset from `mmls` first.
- **Treating a finished `dd` as a complete image** — with `conv=noerror,sync`, read errors become zeroes. Count and report them.
- **Comparing a damaged source hash and calling it a mismatch** — on failing media the comparison can legitimately differ. Explain it, do not hide it.
- **Writing a raw image onto a FAT32 destination** — the 4 GiB file-size limit breaks large images. Plan the destination file system, or use segmented EWF.
- **Trusting a hash you never compared** — compute hashes of source and image, and *look* at both strings.
- **Putting the manifest inside the tree it describes** — keep it outside, and re-verify at each checkout.
- **Carving when you should recover metadata-first** — deleted-file recovery through `fls -d`/`icat -r` preserves names and metadata; carve only what metadata cannot reach.
- **Presenting a carved file as a recovered file** — they support different claims. Label which method produced which artefact.
- **Using `dd` on a mounted live system** — acquire from a forensic boot environment or write-blocked hardware, never from the running OS you are imaging.
- **Assuming an EWF image will open everywhere** — the analysing tool needs libewf support. Prove it opens on the analysis host before you rely on it.
- **Tip:** record the tool version for every command in this file. A report that says "used Sleuth Kit" is not reproducible; `fls 4.11.1` is.
- **Tip:** keep a per-case command log as you work (`notes/commands.md`). It becomes appendix D of your report with almost no effort.
- **Tip:** when a tool fails, capture the exact error text and the command. Most of the diagnosis table in this section exists because someone did not.

## Checklist / Self-Test

- [ ] I can explain why write blockers and hash verification are non-negotiable in acquisition.
- [ ] I imaged a practice device with `dd` and `dc3dd` and compared the resulting hashes.
- [ ] I can explain what `conv=noerror,sync` does to an image, and why a damaged drive can produce a legitimate hash mismatch.
- [ ] I verified read-only state with two independent commands before imaging.
- [ ] I used `mmls` to find a partition offset and `fsstat` to identify the file system, and I recorded the volume serial.
- [ ] I can state the difference between a sector offset and a byte offset, and which one `-o` takes.
- [ ] I listed files with `fls`, spotted a deleted entry (`*` marker), and extracted it with `icat -r`.
- [ ] I used `istat` to see both timestamp sets for one file record.
- [ ] I produced an unallocated-space stream with `blkls` and searched it, mapping a hit back to a cluster.
- [ ] I bulk-recovered files with `tsk_recover` and can explain what its orphaned files mean.
- [ ] I used a hash set with `hfind` to set aside known-good files.
- [ ] I created an Autopsy case, added an image, and located the deleted file there too.
- [ ] I carved files from an image with `foremost` and could name what carving does *not* preserve.
- [ ] I can state three situations in which mounting the evidence would have altered it, and what I did instead.
- [ ] I can list the two rules that apply to every acquisition (write-protect, hash-verify).

## Further Resources

- NIST SP 800-86 — *Guide to Integrating Forensic Techniques into Incident Response* (csrc.nist.gov/publications).
- The Sleuth Kit documentation and wiki — sleuthkit.org.
- Autopsy user documentation — sleuthkit.org/autopsy.
- dc3dd project page — sourceforge.net/projects/dc3dd.
- FTK Imager product page — exterro.com/digital-forensics-software/ftk-imager.
- hashdeep (md5deep family) — github.com/jessek/hashdeep.
- libewf (EWF/E01 format, `ewfacquire`/`ewfverify`/`ewfinfo`) — github.com/libyal/libewf.
- `man dd`, `man dc3dd`, `man foremost`, `man mmls`, `man blkls`, `man tsk_recover` on your practice system.

> **Verification:** the `ils` and `sigfind` lines were executed on **2026-09-19** against
> **The Sleuth Kit 4.12.1** (Ubuntu 24.04 WSL; `ils -V` and `sigfind -V` both print `The Sleuth
> Kit ver 4.12.1`). A 16 MiB ext4 image was built in `/tmp` with `dd` + `mkfs.ext4` and populated
> with `debugfs`. `ils -e -o 0 -m test.img` exited 0 and produced 4098 bodyfile records whose name
> field is the inode, not a path (`0|<test.img-alive-1>|1|-/----------|…`). The form printed in the
> guides, `ils -o 0 -m / test.img`, exited 1 with **no stdout** and
> `Invalid magic value (raw_open: image "/" - is a directory)` — in a `>> bodyfile` pipeline the
> file simply gains nothing. `sigfind -b 512 -o 510 -l AA55 sig.bin` printed
> `Block size: 512  Offset: 510  Signature: 55AA` and reported `Block: 0` and `Block: 10` for two
> planted `55AA` signatures; `sigfind -t fat sig.bin` produced the same result, as the man page's
> example implies. The previous form, `sigfind -o 2048 -l 512 0xAA55 …`, exits 1 with
> `Invaild signature - full bytes only`, and `sigfind -o 0 -l 512 0xAA55 test.img` exits 1 with
> `Error converting offset value: 0`. The imaging and carving half was exercised separately on the
> same date against **dc3dd 7.2.646**, **foremost 1.5.7** and **scalpel 1.60**, and it produced two
> results worth recording. (1) The `dc3dd` line in section 4 uses `hashlog=`, which this version
> **rejects**: `dc3dd if=src.bin of=copy.dd hash=sha256 hashlog=hash.log log=acq.log` aborts with
> `[!!] unrecognized option hashlog=hash.log` and exit 1, and the option is now `hlog=FILE`
> (`dc3dd --help`: `hlog=FILE  Log total hashes and piecewise hashes to FILE`). With
> `hash=sha256` alone the copy works and the re-hash of `copy3.dd` matches the source
> (`2db108c9…04722`). The section already tells you to confirm the switch set with `dc3dd --help`,
> and this is what that warning is for; the example itself was left as written, as it falls outside
> this pass. (2) **No positive carving result was obtained**, so nothing here claims one:
> `foremost -i <file> -o <dir> -t jpg` extracted **0 files** from a raw file of 428 bytes containing
> the `ffd8ffe0` header and `ffd9` footer, from the same payload padded with 128 KiB of zeroes, and
> from a real 542 091-byte JPEG (`ffd8ffdb`, from `C:\Windows\Web`), whether inside an ext4 image
> written with `debugfs` or as a plain file — with `-t jpg`, `-t jpeg` and `-t all` alike. On the same
> build, `strings /usr/bin/foremost` contains **no** `jpg`, `jpeg`, `png`, `pdf` or `zip` (the short
> lowercase strings that look like type names are `docx ftyp gzip impress mdat moov mpeg office pnot
> pptx regf trak vjpeg xlsx`), and `/etc/foremost.conf` ships with **every** type line commented
> out — which its own header explains is for formats that are *not* built in. Cause not fully
> established, and `scalpel -o <dir> <img>` ran with the default (all-commented) config and carved
> nothing either. **Not executed:** `dd`/`dc3dd` against a real block device, and `bulk_extractor`
> (not installed).
