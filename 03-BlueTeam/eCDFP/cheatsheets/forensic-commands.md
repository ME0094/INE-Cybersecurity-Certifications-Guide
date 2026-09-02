# Forensic Commands — Quick Reference

> eCDFP · Cheatsheet — INE Cybersecurity Certifications Study Guide
>
> Compact command reference for acquisition, hashing, The Sleuth Kit, Autopsy, Volatility 3, and timeline tools. Run everything against media you own or are authorized to examine. `IMG` = evidence image, `DEV` = source device (e.g. `/dev/sdb`).

## 1. Acquisition

```bash
# Raw image with dd: bs=4M speeds copy, conv=noerror,sync survives bad sectors
dd if=DEV of=/evidence/case/disk.dd bs=4M conv=noerror,sync status=progress

# Single partition (logical acquisition)
dd if=/dev/sdb1 of=/evidence/case/part1.dd bs=4M conv=noerror,sync status=progress

# dc3dd: copy + hash + log in one pass
dc3dd if=DEV of=/evidence/case/disk.dd hash=sha256 \
      hashlog=/evidence/case/hash.log log=/evidence/case/acq.log

# E01 (Expert Witness) format with libewf
ewfacquire DEV            # interactive; answers recorded in a .E01 + .info

# Write-blocker sanity checks (1 / readonly means blocked)
blockdev --getro DEV      # prints 1 when read-only
hdparm -r DEV             # prints "readonly  = 1"

# Never mount the source read-write; read-only fallback only
mount -o ro,noexec,nodev /dev/sdb1 /mnt/evidence
```

## 2. Hashing & integrity

```bash
sha256sum IMG                      # one-off digest
md5sum IMG                         # legacy, keep for compat checks

# Manifest a whole evidence tree and verify it later
hashdeep -c sha256 -l -r /evidence/case/ > /evidence/case/manifest.txt
hashdeep -k /evidence/case/manifest.txt -r -v -a /evidence/case/

# Compare recovered file to original hash (lab drill)
echo "<original-hash>  recovered.pdf" | sha256sum -c -     # OK
```

## 3. The Sleuth Kit (TSK)

Common flags: `-f <fstype>` force type, `-o <sector>` partition offset (512-byte sectors), `-r` recursive, `-d` deleted only, `-p` full paths. For raw whole-disk images, read the offset from `mmls` first.

```bash
mmls IMG                        # partition layout; note Start sectors
# 02: Linux   2048  1001471  999424  Ext4     <- offset for -o is 2048

fsstat -f ext4 -o 2048 IMG      # file system details (type, label, block counts)
fls  -f ext4 -o 2048 IMG        # list files
fls  -f ext4 -o 2048 -r -d IMG  # recursive, deleted only ('*' marks deleted)
# r/r * 17:    secret.pdf

icat -f ext4 -o 2048 IMG 17 > out.pdf          # read allocated file by inode
icat -f ext4 -o 2048 -r IMG 17 > deleted.pdf   # -r = recover deleted content

ils  -f ext4 -o 2048 IMG       # inode metadata (body-file style lines)
tsk_recover -e IMG outdir/     # bulk-recover deleted files (-a = allocated only)

# NTFS note: inode addresses look like 65-128-4 (file-record / attr id);
# pass them to icat as-is.
```

## 4. Carving

```bash
foremost -i IMG -o carved/ -t jpg,pdf,zip    # signature carving
scalpel -o carved_scalpel/ IMG               # config: /etc/scalpel/scalpel.conf
photorec DEV                                 # photo/carving recovery tool
bulk_extractor -o bulk/ IMG                  # URLs, emails, credit cards...
# results land as bulk/url.txt, bulk/email.txt, ...
```

## 5. Autopsy

```bash
autopsy                 # start the local web server
# open http://127.0.0.1:9999/autopsy in a browser
```

Workflow: **New Case** → name + base dir → **Add Data Source** (image or device) → choose **ingest modules** (file type, hash lookup, keyword search, web artifacts) → analyze in tree, bookmarks, and **Timeline** view → **Generate Report** (HTML/text). Autopsy 4 has no official headless ingest CLI — for scripting, drive TSK tools directly (they are Autopsy's engine).

## 6. Volatility 3

Pattern: `vol -f IMG <module>.<plugin>` where module is `windows`, `linux`, or `macos`. Symbol tables download on first run; use `-s <dir>` when offline.

```bash
vol -f mem.raw windows.info            # OS/build, kernel base, symbols check
vol -f mem.raw windows.pslist          # process list (EPROCESS walk)
vol -f mem.raw windows.psscan          # scan for hidden processes
vol -f mem.raw windows.pstree          # process tree (spot odd parents)
vol -f mem.raw windows.cmdline         # command lines per process
vol -f mem.raw windows.netscan         # TCP/UDP endpoints + PID
vol -f mem.raw windows.malfind         # injected code / RWX regions
vol -f mem.raw windows.hashdump        # local account hashes from SAM
vol -f mem.raw windows.dlllist --pid 2468     # loaded DLLs for a PID
vol -f mem.raw windows.envars  --pid 2468     # environment block
vol -f mem.raw windows.memdump --pid 2468 --dump dumps/   # full process memory
vol -f mem.raw windows.dumpfiles --pid 2468 --dump        # extract File objects
vol -f mem.raw -r json windows.pslist # machine-readable output

# After dumping: inspect strings (Windows = UTF-16LE) and hash the artifact
strings -el dumps/2468.dmp | head -50
sha256sum dumps/2468.dmp
```

| Volatility 2 equivalent | Command |
| --- | --- |
| Profile guess | `volatility -f mem.raw imageinfo` |
| Run with profile | `volatility -f mem.raw --profile=Win7SP1x64 pslist` |
| Deleted-file scan | `volatility ... filescan` |
| Memory dump | `volatility ... memdump -p 2468 -D dumps/` |

Volatility 2 requires a `--profile` on every command and runs on Python 2 — learn it for legacy material, but prefer Volatility 3 for new work.

## 7. Timeline tools

Sleuth Kit body-file pipeline:

```bash
# body file: -m /path sets the mount prefix for full paths
fls -f fat -r -p -m /lab IMG > body.txt
# CSV timeline in UTC (comma-delimited)
mactime -b body.txt -d -z UTC > timeline.csv
head -3 timeline.csv
# Date,Size,Type,Mode,UID,GID,Meta,File Name
# Sun Jan 12 10:02:00 2025,32,r/r,rwx------,0,0,5,/lab/secret.pdf
```

Plaso (super timeline) for whole images:

```bash
log2timeline /evidence/case/plaso.dump IMG   # collect events
psort -o l2tcsv /evidence/case/plaso.dump > timeline_full.csv
pinfo /evidence/case/plaso.dump               # storage stats/sanity
```

## 8. Common mistakes & tips

- **Wrong device node** — confirm with `lsblk` before `dd`; imaging the wrong disk is irreversible.
- **No partition offset** — TSK says "file system not found" on whole-disk images when you skip `-o`; read it from `mmls`.
- **Volatility 2 without `--profile`** — every command needs it; Volatility 3 detects automatically.
- **Analyzing a live/contaminated source** — acquire to a clean target, analyze the *copy*.
- **Mixing timezones** — pin timelines to UTC (`-z UTC`) and note the convention in your report.
- **Trusting one artifact** — confirm a finding with a second tool (e.g., `fls -d` then Autopsy, `pslist` then `psscan`).

## Checklist / Self-test

- [ ] I can write a `dd` command that survives read errors and shows progress, and explain each flag.
- [ ] I can produce and verify a `hashdeep` manifest for an evidence tree.
- [ ] I can find a partition offset with `mmls` and run `fls`/`icat`/`ils` against the right offset.
- [ ] I can recover a deleted file with `fls -d` + `icat -r` and with `tsk_recover -e`.
- [ ] I can launch Autopsy and name its case → data source → ingest → timeline workflow.
- [ ] I can run `windows.info`, `pslist`, `pstree`, `netscan`, and `malfind` and read their output.
- [ ] I can dump a process with `memdump --dump` and extract files with `dumpfiles --dump`.
- [ ] I can generate a body file with `fls -m` and turn it into a UTC CSV with `mactime`.

## Further resources

- The Sleuth Kit documentation and wiki — sleuthkit.org.
- Autopsy user documentation — sleuthkit.org/autopsy.
- Volatility 3 documentation (plugin list, quickstart) — volatility3.readthedocs.io.
- Plaso (log2timeline) documentation — plaso.readthedocs.io.
- NIST SP 800-86 — *Guide to Integrating Forensic Techniques into Incident Response* (csrc.nist.gov/publications).
- Local help: `man dd`, `man fls`, `man mactime`, and `vol -h` on your practice system.
