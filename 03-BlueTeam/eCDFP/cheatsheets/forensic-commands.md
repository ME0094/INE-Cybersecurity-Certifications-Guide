# Forensic Commands — Quick Reference

> eCDFP · Cheatsheet — INE Cybersecurity Certifications Study Guide
>
> Compact command reference for acquisition, hashing, The Sleuth Kit, artefact extraction, Autopsy, Volatility 3, and timeline tools. Run everything against media you own or are authorized to examine. `IMG` = evidence image, `DEV` = source device (e.g. `/dev/sdb`), `OFF` = partition offset in **512-byte sectors** (read it from `mmls`).
>
> Every command is a **syntax reference**. This repository ships no captured command output — there is no image, no device and no toolchain on the machine that wrote this file. The `#` comments show the *shape* of what a tool reports, not a transcript; where a value would matter, ask what to look for. Confirm flags with `--help`/`man` for the version you install.

## 1. Acquisition

```bash
# Raw image with dd: bs=4M speeds copy, conv=noerror,sync survives bad sectors
dd if=DEV of=/evidence/case/disk.dd bs=4M conv=noerror,sync status=progress

# Single partition (logical acquisition)
dd if=/dev/sdb1 of=/evidence/case/part1.dd bs=4M conv=noerror,sync status=progress

# dc3dd: copy + hash + log in one pass (the hash log option is `hlog=`, not `hashlog=`)
dc3dd if=DEV of=/evidence/case/disk.dd hash=sha256 \
      hlog=/evidence/case/hash.log log=/evidence/case/acq.log

# E01 (Expert Witness) format with libewf
ewfacquire DEV            # interactive; answers recorded in a .E01 + .info

# Write-blocker sanity checks (1 / readonly means blocked)
blockdev --getro DEV      # prints 1 when read-only
hdparm -r DEV             # prints "readonly  = 1"

# If you mount at all, mount a read-only WORKING COPY derived from the image. The source
# device (DEV) is never mounted, and neither is the sealed original.
mount -o ro,noexec,nodev,loop /evidence/case/working/part1.dd /mnt/evidence
```

```bash
# Identify the device before you aim dd at it — twice
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE
blkid
# What to look for: the evidence device, with NO mount point. If it is mounted, stop.

# When the evidence is a file (VM disk, cloud export) rather than a device
file disk.vmdk disk.qcow2 disk.dd
qemu-img info disk.qcow2
# What to look for: the real container format, before you treat a virtual disk as raw.
```

> Three acquisition facts worth remembering: `conv=noerror,sync` pads unreadable sectors with zeroes (count them — a finished `dd` is not a complete image); a raw image cannot exceed 4 GiB on a FAT32 destination; and a *live* source has no stable hash, so hash the image and describe the source's state instead.

## 2. Hashing & integrity

```bash
sha256sum IMG                      # one-off digest
md5sum IMG                         # legacy, keep for compat checks

# Manifest a whole evidence tree and verify it later
hashdeep -c sha256 -l -r /evidence/case/ > /evidence/case/manifest.txt
hashdeep -k /evidence/case/manifest.txt -r -v -a /evidence/case/

# Verify an image against a stored manifest (one "<hash>  <file>" per line)
sha256sum -c /evidence/case/manifest.txt

# EWF container integrity and metadata
ewfverify /evidence/case/disk.E01
ewfinfo   /evidence/case/disk.E01

# Compare recovered file to original hash (lab drill)
echo "<original-hash>  recovered.pdf" | sha256sum -c -     # expect OK
```

Rules that keep hashes useful: store the manifest **outside** the tree it describes; re-verify at every checkout and record the result; hash every artefact you extract, not just the image; never transcribe a hash from a screenshot.

## 3. The Sleuth Kit (TSK)

Common flags: `-f <fstype>` force type, `-o <sector>` partition offset (512-byte sectors), `-r` recursive, `-d` deleted only, `-p` full paths, `fls -m <prefix>` bodyfile output with a path prefix (`ils -m` is the same idea but takes **no** argument). For raw whole-disk images, read the offset from `mmls` first.

```bash
mmls IMG                        # partition layout; note Start sectors
# What to look for: one row per partition, Start column in 512-byte sectors.
# That Start value is OFF for every command below. Do not confuse sectors with bytes.

fsstat -f ext4 -o OFF IMG       # file system type, label, block counts, volume serial
fls  -f ext4 -o OFF IMG         # list files at the root
fls  -f ext4 -o OFF -r IMG      # recursive listing
fls  -f ext4 -o OFF -r -d IMG   # deleted entries only ('*' marks them)
# What to look for: a metadata address in the leading columns of each line — that is the
# argument for icat and istat.

istat -o OFF IMG 42             # full metadata for one record
# What to look for: the $STANDARD_INFORMATION and $FILE_NAME attribute blocks (their
# disagreement suggests timestamp manipulation), the allocated flag, sizes, and data runs.

icat -o OFF IMG 42 > out.bin            # read allocated content by address
icat -o OFF -r IMG 42 > deleted.bin     # recover deleted content
# On NTFS, pass a full stream name to read an alternate data stream.

ils  -o OFF IMG                 # metadata records, including unallocated ones
ils  -o OFF -m IMG >> body.txt  # bodyfile-formatted, for timeline tools (-m takes no argument)

blkls -o OFF IMG > unallocated.raw      # units as a flat stream (check -a semantics!)
blkcat -o OFF IMG 12345                 # one cluster, when you have an offset
sigfind -b 512 -o 510 -l AA55 IMG       # where a byte signature appears (damaged FS)
# Here -o is an offset WITHIN each block of size -b, not the partition offset:
# the AA55 boot signature sits at byte 510 of a 512-byte sector.

ffind -o OFF IMG 42                     # reverse lookup: which name owns this address
tsk_recover -e -o OFF IMG outdir/       # bulk-recover files (-a = allocated only)
hfind -i nsrl-md5 path/to/NSRLFile.txt  # known-good hash set index (confirm index type)
hfind -i nsrl-md5 path/to/NSRLFile.txt <md5>

# NTFS note: metadata addresses can look like 65-128-4 (record / attribute id);
# pass them to icat/istat as they appear in the listing.
```

## 4. Carving

```bash
foremost -i IMG -o carved/ -t jpg,pdf,zip    # signature carving
scalpel -o carved_scalpel/ IMG               # config: /etc/scalpel/scalpel.conf
photorec DEV                                 # photo/carving recovery tool
bulk_extractor -o bulk/ IMG                  # URLs, emails, cards...; read the histogram first
# What to look for: per-type output directories plus foremost's audit file recording the
# byte offset of every carved file. Keep the audit file — an offset-less carved file is
# hard to cite, and carved content carries no name and no defensible timestamp.
```

## 5. Autopsy

```bash
autopsy                 # start the local web server
# What to look for: the port your build reports. Confirm it rather than assuming a
# default from older documentation.
```

Workflow: **New Case** → name + base dir → **Add Data Source** (image or device) → choose **ingest modules** (file type, hash lookup, keyword search, web artifacts) → analyze in tree, bookmarks, and **Timeline** view → **Generate Report** (HTML/text). Autopsy 4 has no official headless ingest CLI — for scripting, drive TSK tools directly (they are Autopsy's engine). Cite the artefact, not a screenshot of the tool that displayed it.

## 6. Extracting Windows artefacts from an image (without mounting)

```bash
# 1) Locate the artefact files inside the image
fls -o OFF -r -p IMG | grep -iE 'Prefetch|config/(SYSTEM|SOFTWARE|SAM|SECURITY)|NTUSER\.DAT|UsrClass\.dat|winevt/Logs|sru/'
# What to look for: a path list with metadata addresses. Those addresses feed icat.

# 2) Extract what you need, and hash every output
icat -o OFF IMG <meta> > exports/SYSTEM
icat -o OFF IMG <meta> > exports/SOFTWARE
icat -o OFF IMG <meta> > exports/NTUSER.DAT
icat -o OFF IMG <meta> > exports/SRUDB.dat
sha256sum exports/* > notes/exports-hashes.txt

# 3) Pull a whole artefact directory (e.g. Prefetch) for parsing elsewhere
fls -o OFF -r -p IMG | grep -i '/Prefetch/'          # then icat each .pf by address

# 4) Registry questions, offline (RegRipper; confirm plugin names with rip.pl -l)
rip.pl -r exports/SYSTEM -p usbstor
rip.pl -r exports/NTUSER.DAT -p userassist

# 5) Windows-side parsers for the extracted artefacts
#    (run on a Windows analysis host, never on the victim)
#    PECmd.exe  AmcacheParser.exe  AppCompatCacheParser.exe  MFTECmd.exe
#    LECmd.exe  JLECmd.exe  RECmd.exe  EvtxECmd.exe  SBECmd.exe  SrumECmd.exe  RBCmd.exe
#    See ../tools/windows-artifact-tools.md for invocation and failure modes.
```

> Two rules for this section. Extracted files are **copies** — the image remains the exhibit, so record the extraction command and the output's hash. And parse a hive together with its `.LOG1`/`.LOG2` transaction logs, or a dirty hive on disk may be stale.

## 7. Volatility 3

Pattern: `vol -f IMG <module>.<plugin>` where module is `windows`, `linux`, or `mac`. Symbol tables download on first run; use `-s <dir>` when offline. **List your build's plugins and read each plugin's `--help`** — names and module paths change between releases.

```bash
vol --help                              # framework version, global options, plugin list
vol -f IMG windows.malfind --help       # plugin-specific options for your build

vol -f mem.raw windows.info             # OS/build, kernel base, symbols check — run this first
vol -f mem.raw windows.pslist           # process list (EPROCESS walk)
vol -f mem.raw windows.psscan           # physical scan: finds unlinked/hidden processes
vol -f mem.raw windows.pstree           # process tree (spot odd parents)
vol -f mem.raw windows.cmdline          # command lines per process
vol -f mem.raw windows.envars  --pid 2468     # environment block
vol -f mem.raw windows.dlllist --pid 2468     # loaded DLLs for a PID
vol -f mem.raw windows.handles --pid 2468     # open handles for a PID
vol -f mem.raw windows.vadinfo --pid 2468     # memory regions; is it file-backed?
vol -f mem.raw windows.netscan          # TCP/UDP endpoints + owning PID
vol -f mem.raw windows.malfind          # executable private regions (a LEAD, not a verdict)
vol -f mem.raw windows.modules          # linked kernel modules
vol -f mem.raw windows.modscan          # physically found modules (differ = investigate)
vol -f mem.raw windows.hashdump         # local account hashes (sensitive evidence)
vol -f mem.raw windows.filescan         # file objects recovered from memory
vol -f mem.raw -o dumps/ windows.memmap --pid 2468 --dump   # full process memory
vol -f mem.raw -o dumps/ windows.dumpfiles --pid 2468       # extract File objects (no --dump)
vol -f mem.raw -r json windows.pslist   # machine-readable output for scripting

# After dumping: inspect strings (Windows text is often UTF-16LE) and hash the artefact
strings -el dumps/pid.2468.dmp | head -50
sha256sum dumps/pid.2468.dmp
```

| Volatility 2 equivalent | Command |
| --- | --- |
| Profile guess | `volatility -f mem.raw imageinfo` |
| Run with profile | `volatility -f mem.raw --profile=Win7SP1x64 pslist` |
| Deleted-file scan | `volatility ... filescan` |
| Memory dump | `volatility ... memdump -p 2468 -D dumps/` |

Volatility 2 requires a `--profile` on every command and runs on Python 2 — learn it for legacy material, but prefer Volatility 3 for new work. A plugin that fails on missing symbols produced **no result**; it did not report a clean system.

## 8. Timeline tools

Sleuth Kit body-file pipeline:

```bash
# body file: 'fls -m <prefix>' sets the mount prefix for full paths. 'ils -m' is a
# flag with no argument — passing one makes ils read the prefix as the image.
fls -f fat -r -p -m /lab IMG > body.txt
ils -f fat -o OFF -m IMG >> body.txt          # adds metadata records fls does not show

# CSV timeline in UTC (comma-delimited); note one file yields up to four rows
mactime -b body.txt -d -z UTC > timeline.csv
head -3 timeline.csv
# What to look for: a header naming the columns, then one row per timestamp. The type
# column tells you which of M/A/C/B that row represents — filter on it or you will
# over-count events.
```

Plaso (super timeline) for whole images:

```bash
# Confirm the CLI form for your release first: it has changed between versions.
log2timeline.py --help
psort.py --help

log2timeline.py --storage-file=case.plaso IMG   # collect events (see note above)
psort.py -o l2tcsv -w timeline.csv case.plaso   # export (the CSV module is l2tcsv)
pinfo.py case.plaso                             # storage stats/sanity: what actually parsed
# What to look for: per-parser event counts. A source type that contributed zero events
# is a hole in your timeline, not a quiet system.
```

For EVTX-as-evidence triage (Hayabusa, Chainsaw) and the reasoning behind each route, see `../tools/timeline-tools.md`; the hunting-oriented treatment is in `../../eCTHP/tools/endpoint-tools.md`.

## 9. Time conversion, the quick forms

```bash
date -u                                   # current UTC — the convention for all timelines
TZ=UTC date                               # same, for one command
date -d @1735689600 -u                    # Unix epoch seconds -> human UTC
date -u -d '2025-01-01 00:00:00' +%s      # human UTC -> epoch seconds
```

```text
Windows FILETIME  = 100-nanosecond intervals since 1601-01-01 UTC
Unix epoch (s)    = FILETIME / 10^7 - 11644473600
Chrome/WebKit     = microseconds since 1601-01-01 UTC   (divide by 10^6, then subtract 11644473600)
Unix epoch (ms)   = value / 1000
```

> Always state the time zone of a timestamp you put in a report, and record the measured clock offset of each source. A timeline whose zone is implicit cannot be correlated — see `../methodology/03-timeline.md`.

## 10. Troubleshooting: symptom → likely cause

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| TSK says the file system is not found | Missing `-o`, or an offset given in bytes rather than sectors | Read the Start column from `mmls`; offsets are in 512-byte sectors |
| `dd` finished but the hash differs from the source | Read errors padded into the image (`conv=noerror,sync`), or a live source | Check the error output and the bad-sector count; if the source was live, the comparison was never meaningful |
| Image fails partway with a size error | Destination is FAT32 and the image exceeded 4 GiB | Use a different destination file system, or segmented EWF |
| A tool cannot open an `.E01` | No libewf support in that build | Use a build with EWF support, or convert; verify on the analysis host before relying on it |
| `fls` lists nothing but `fsstat` works | Wrong directory, or you are at the wrong offset within a partitioned image | Confirm the offset and try the root listing with `-p` for full paths |
| Recovered file is all zeroes | Clusters were reused, or the wrong record was extracted | Check the record with `istat`; report a failed recovery rather than a successful one |
| Volatility plugins all error | Symbols missing (offline) or unsupported build | Fetch symbols on a connected host, or point `-s` at a local directory |
| Volatility finds nothing with no error | Possibly a partial or incompatible dump | Validate with a basic identification plugin against a known-good sample of the same OS |
| Timeline dates look impossible | Wrong epoch conversion, or a time-zone mismatch | Recompute one known event by hand before trusting the column |
| EVTX parser reports nothing | The log was empty, or the parser/mapping does not match the schema | Check the raw event with native tooling before concluding the log was empty |
| A hash manifest reports mismatches | Something wrote into the evidence tree (indexer, antivirus, a tool's default output path) | Stop, identify what wrote, and re-derive the affected working copies from the sealed original |

## 11. Common Mistakes & Tips

- **Wrong device node** — confirm with `lsblk`/`blkid` before `dd`; imaging the wrong disk is irreversible.
- **No partition offset, or bytes instead of sectors** — TSK says "file system not found"; read the offset from `mmls` and remember it is in 512-byte sectors.
- **Mounting the evidence** — extract with `icat`/`tsk_recover`; a mount can replay a journal, update access times and create new artefacts.
- **Treating a finished `dd` as a complete image** — with `conv=noerror,sync`, unreadable sectors become zeroes. Count and report them.
- **Hashing a live source and calling it a record** — a moving target has no stable hash.
- **Volatility 2 without `--profile`** — every command needs it; Volatility 3 detects automatically but needs symbols.
- **Reading a failed plugin as a clean result** — a symbol or requirement error means no result at all.
- **Analyzing a live/contaminated source** — acquire to a clean target, analyze the *copy*.
- **Mixing timezones** — pin timelines to UTC (`-z UTC`) and note the convention in your report.
- **Trusting one artifact** — confirm a finding with a second tool (e.g., `fls -d` then Autopsy, `pslist` then `psscan`).
- **Carving before trying metadata** — `fls -d`/`icat -r` preserve names and timestamps; carve only what metadata cannot reach.
- **Tip:** keep a per-case `notes/commands.md` as you work. It becomes appendix D of the report with no extra effort.
- **Tip:** when a command fails, copy the exact error text into your notes. The diagnosis table above only works if you have the message.

## Checklist / Self-Test

- [ ] I can write a `dd` command that survives read errors and shows progress, and explain each flag.
- [ ] I can identify an evidence device before imaging it, and confirm it is not mounted.
- [ ] I can produce and verify a `hashdeep` manifest for an evidence tree, and verify an EWF container.
- [ ] I can find a partition offset with `mmls` and run `fls`/`icat`/`istat`/`ils` against the right offset.
- [ ] I can explain the difference between a sector offset and a byte offset.
- [ ] I can recover a deleted file with `fls -d` + `icat -r` and with `tsk_recover -e`.
- [ ] I can extract a hive and an artefact directory out of an image with `fls` + `icat`, and record their hashes.
- [ ] I can launch Autopsy and name its case → data source → ingest → timeline workflow.
- [ ] I can run `windows.info`, `pslist`, `psscan`, `pstree`, `netscan`, `malfind` and `vadinfo` and read their output.
- [ ] I can list the plugins my Volatility build ships rather than relying on remembered names.
- [ ] I can dump a process with `windows.memmap --dump` and extract files with `windows.dumpfiles`, then hash them.
- [ ] I can generate a body file with `fls -m` and `ils -m` and turn it into a UTC CSV with `mactime`.
- [ ] I can convert between FILETIME, Unix epoch seconds and a browser microsecond timestamp.
- [ ] I can state, for a failed command, whether my result is an error or a genuine negative.

## Further Resources

- The Sleuth Kit documentation and wiki — sleuthkit.org.
- Autopsy user documentation — sleuthkit.org/autopsy.
- Volatility 3 documentation (plugin list, quickstart) — volatility3.readthedocs.io.
- Plaso (log2timeline) documentation — plaso.readthedocs.io.
- libewf (`ewfacquire`, `ewfverify`, `ewfinfo`) — github.com/libyal/libewf.
- NIST SP 800-86 — *Guide to Integrating Forensic Techniques into Incident Response* (csrc.nist.gov/publications).
- Local help: `man dd`, `man fls`, `man istat`, `man mactime`, `man tsk_recover`, and `vol --help` on your practice system.

> **Verification:** executed on **2026-09-19** against **Volatility 3 Framework 2.28.2**,
> **The Sleuth Kit 4.12.1** and **sqlite3 3.45.1** (Ubuntu 24.04 WSL). Volatility:
> `vol windows.memmap --help` prints `[--pid PID] [--dump]` with `--dump` taking no argument; the
> global `-o/--output-dir` is rejected after the plugin name
> (`vol: error: unrecognized arguments: -o /tmp`) and accepted before it. The namespace is `mac`
> (there is no `macos`), confirmed by `ls framework/plugins/` and by the plugin chooser. Sleuth
> Kit: on an ext4 image built in `/tmp` with `mkfs.ext4` and populated with `debugfs`,
> `ils -e -o 0 -m test.img` exited 0 with 4098 bodyfile records, while the form printed in the
> guides, `ils -o 0 -m / test.img`, exited 1 with no stdout at all —
> `Invalid magic value (raw_open: image "/" - is a directory)` — so a bodyfile built with it
> silently gains no lines. `sigfind -b 512 -o 510 -l AA55 sig.bin` reported
> `Block size: 512  Offset: 510  Signature: 55AA` and found the two planted signatures
> (`Block: 0`, `Block: 10`), whereas the form printed in the guides,
> `sigfind -o 2048 -l 512 0xAA55 sig.bin`, exited 1 with `Invaild signature - full bytes only`
> (sigfind's own spelling), and `sigfind -o 0 -l 512 0xAA55 test.img` exited 1 with
> `Error converting offset value: 0`. Version banner: `ils -V` / `sigfind -V` → `The Sleuth Kit
> ver 4.12.1`. The acquisition half was exercised against **dc3dd 7.2.646**, and it caught a switch
> name in section 1 that this version does not accept: `dc3dd if=src.bin of=copy.dd hash=sha256
> hashlog=hash.log log=acq.log` aborts with `[!!] unrecognized option hashlog=hash.log` and exit 1 —
> the option is now `hlog=FILE` (`dc3dd --help`: `hlog=FILE  Log total hashes and piecewise hashes to
> FILE`, alongside `log=FILE` and `mlog=FILE`). With `hash=sha256` alone, `dc3dd if=src.bin
> of=copy3.dd hash=sha256` completes and the output re-hashes to the source's digest. The line above
> was left as written — out of this pass's scope — so read it together with this note. **Not
> executed:** `dd`/`dc3dd` against a real device, and `ewfacquire` on a device; no evidence device is
> attached to this machine.
