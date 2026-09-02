# Forensic Tools for Incident Responders

> eCIR · Tools — English reference for evidence acquisition, triage, timelines, and memory analysis

Incident responders use forensic tooling not to "do forensics" for its own sake, but to
answer fast, defensible questions: *Is this host compromised? What did the attacker do?
When? What do we preserve before we touch anything?* This guide covers the tool families
you need, the concept behind each, and practical commands. Always analyze **copies**, never
your only original.

## Before You Start: Order of Operations

1. **Identify** the evidence you must preserve (running system, disk, logs, memory).
2. **Isolate** — disconnect from the network only when it will not destroy volatile data you still need.
3. **Capture volatile data first** (memory, running processes), then disk, then logs.
4. **Hash everything** at capture time and record hashes in your case notes.
5. **Work from copies** on a dedicated analyst machine, never the original media.

## Acquisition: Capturing Disk Evidence

### dd (Linux/Unix)

`dd` performs raw bit-for-bit copies. It has no built-in integrity checking, so always
hash the source and the image independently.

```bash
# Identify the device FIRST (be absolutely certain of the device name)
lsblk
sudo fdisk -l

# Raw image of /dev/sdb to an evidence drive mounted read-only
sudo dd if=/dev/sdb of=/evidence/case001/disk1.raw bs=4M conv=noerror,sync status=progress

# Hash source (as captured) and resulting image
sudo sha256sum /dev/sdb > /evidence/case001/source.sha256
sha256sum /evidence/case001/disk1.raw > /evidence/case001/image.sha256
```

> `conv=noerror,sync` keeps the copy aligned when read errors occur instead of aborting —
> a standard choice for forensic imaging. Never image a disk you are also writing to.

### EWF Tools (ewfacquire)

The Expert Witness Format (E01) stores compressed, segmented images with integrated
metadata and checksums — the format most forensic suites expect.

```bash
sudo ewfacquire /dev/sdb
# Interactive: set case number, evidence number, examiner, compression level
# Outputs segmented files: disk1.E01, disk1.E02, ... plus a .info sidecar

# Verify an acquired image
sudo ewfverify disk1.E01
```

### FTK Imager (Concept)

FTK Imager (Exterro/AccessData) is a GUI tool commonly used to:

- Create **physical images** (whole drive) or **logical images** (selected files/folders).
- Create images in **E01 or raw (dd)** formats with integrated SHA-1/MD5 hashing.
- **Preview** evidence without altering it (mount as read-only).
- Capture a **memory dump** of a live Windows system.

It is popular in triage because an analyst can image a USB stick or a folder quickly and
get a verifiable image without a full forensic workstation. The concept to master is the
same as `dd` + hashing: produce a verifiable copy and record where, when, and by whom.

## Hashing and Chain of Custody

Hashes prove integrity, not authenticity: they show an image has not changed since capture.

```bash
sha256sum disk1.raw
md5sum disk1.raw          # legacy, still widely expected by courts

# Verify a later copy matches the original image
sha256sum -c image.sha256
```

Record in every case: case ID, exhibit ID, device description, serial number, capture
method and tool version, examiner, date/time (with timezone), and hash values. Each time
evidence changes hands, log the transfer. That record is the **chain of custody**.

## Triage: Fast Collection on Live Systems

You cannot image every endpoint in a large incident. Triage collects the artifacts most
likely to reveal compromise, fast.

### KAPE (Concept)

KAPE (Kroll Artifact Parser and Extractor) collects *targets* (files and registry hives
you want) and runs *modules* (parsers that turn them into readable output) without
installing anything on the target. It is a directory of reusable definitions:

```text
kape.exe --tsource D:\evidence\live   --tdest E:\case\kape-collect --target Windows --tflush
kape.exe --msource D:\evidence\live   --mdest E:\case\kape-parse   --module !EZ1
```

- `--tsource/--tdest` — where to read from and write collected targets.
- `--target Windows` — collect the standard Windows target set (Prefetch, Amcache,
  Shimcache, event logs, SRUM, registry hives, and more).
- `--msource/--mdest` — where to read collected files and write parsed output.
- `--module !EZ1` — run the Eric Zimmerman parsing bundle (timeline, prefetch, etc.).
- `--tflush` — wipe destination folders first for a clean run.

Use KAPE to gather artifacts from many hosts in minutes, then analyze the output on your
own machine. Common practice: run KAPE on a mounted image or a live endpoint, then feed
the output into timeline tools.

### Velociraptor (Basics)

Velociraptor is a client/server platform for endpoint visibility. Small agents run on
hosts and report to a server; you launch **artifact collections** (built-in, tested
queries) across one, many, or all endpoints, and hunt with **VQL** (Velociraptor Query
Language).

```text
# On the server, list available collection artifacts
velociraptor artifacts list Windows.KapeFiles.*

# Collect an artifact from the CLI against a client
velociraptor --config server.config.yaml client collect \
  --client_id C.xxxx Windows.KapeFiles.Targets
```

Typical responder use: push `Windows.KapeFiles.*` or `Windows.Registry.*` collections to
suspect hosts, pull results into the server's UI, and pivot from one suspicious file to a
full host hunt. Because agents stay installed, you can re-query hosts later for persistence.

## Timeline Analysis

### plaso / log2timeline (Concept)

The log2timeline/plaso suite ("super timeline") parses dozens of artifact sources —
NTFS $MFT, USN journal, Prefetch, registry, browser history, event logs, syslog — into one
correlated timeline. The classic workflow:

```bash
# 1. Build the plaso storage file from an image
log2timeline.py --storage-file case001.plaso /evidence/disk1.E01

# 2. Inspect what was parsed
pinfo.py case001.plaso

# 3. Export a filtered timeline (CSV for spreadsheets)
psort.py -o l2tcsv -w timeline.csv case001.plaso

# 4. Filter by time or source (JSONL keeps full detail)
psort.py -o jsonl -w webhist.jsonl "source_short is 'WEBHIST'"
```

A super timeline answers *what happened on this host, in order* — the backbone of
reconstructing an intrusion's entry, lateral movement, and persistence.

### Autopsy (Concept)

Autopsy is an open-source GUI forensic platform built on The Sleuth Kit. It adds **ingest
modules**: file-type detection, deleted-file carving, hash-set filtering (known good/bad),
keyword search, EXIF, and a **timeline** module (powered by plaso) that visualizes events
by time. It is the fastest way to explore an image interactively: open the image, let the
modules run, then walk file activity, recovered files, and bookmarks.

## Memory Analysis: Volatility 3 (Intro)

Malware that never touches disk lives only in RAM: injected processes, reflective DLLs,
network connections without sockets visible to the OS. Volatility 3 analyzes a raw memory
dump for these. Volatility 3 dropped the "profile" requirement — plugins auto-detect the
OS.

```bash
# Windows memory dump from FTK Imager or DumpIt/winpmem
vol -f mem.raw windows.pslist          # running processes
vol -f mem.raw windows.psscan          # processes incl. terminated/hidden
vol -f mem.raw windows.cmdline         # command lines of processes
vol -f mem.raw windows.malfind         # injected / suspicious memory regions
vol -f mem.raw windows.netscan         # network artifacts from memory
vol -f mem.raw windows.hivelist        # locate registry hives in memory
vol -f mem.raw windows.dumpfiles -r shell   # extract files from memory
```

Order matters: start with process listings to spot anomalies (odd names, parents,
locations like `C:\Users\Public\` or `%TEMP%`), confirm with `cmdline`, then use
`malfind` and `netscan` to characterize behavior.

## Common Mistakes & Tips

- **Analyzing the original.** Work on hashed copies; keep originals sealed and documented.
- **Missing volatile data.** Processes, memory, and network state die with the power
  switch — capture them before pulling the plug.
- **Hashing the wrong object.** Hash the source and the image; the two hashes serve
  different purposes and both belong in the notes.
- **Wrong device in `dd`.** Misidentifying `/dev/sdX` destroys evidence — verify with
  `lsblk`/`fdisk` and serial numbers first.
- **Trusting tool output blindly.** Correlate at least two independent artifacts before
  concluding an action happened.
- **No timezone discipline.** Record UTC or local-with-offset everywhere, or timelines
  become misleading across hosts.
- **Imaging over the network without integrity controls.** If you must use network
  acquisition, wrap it in a tool that hashes and verifies (e.g., EWF over a secure channel).

## Checklist / Self-Test

- [ ] I can image a USB drive with `dd` and independently hash source and image.
- [ ] I can create and verify an E01 image with `ewfacquire`/`ewfverify`.
- [ ] I can explain when to choose FTK Imager, KAPE, or Velociraptor for a task.
- [ ] I can collect a standard Windows target set with KAPE and locate the output.
- [ ] I can build a plaso timeline from an image and export a filtered CSV.
- [ ] I can run `windows.pslist`, `windows.cmdline`, and `windows.malfind` on a memory dump.
- [ ] I maintain a chain-of-custody record with hashes for every exhibit I handle.

## Further Resources

- NIST SP 800-86, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- MITRE ATT&CK (process/behavior reference) — https://attack.mitre.org/
- plaso / log2timeline documentation — https://plaso.readthedocs.io/
- Autopsy / The Sleuth Kit — https://www.sleuthkit.org/
- Volatility 3 (GitHub) — https://github.com/volatilityfoundation/volatility3
- KAPE (Eric Zimmerman tools) — https://github.com/EricZimmerman/KAPE
- Velociraptor documentation — https://docs.velociraptor.app/
- FTK Imager product page (Exterro) — https://www.exterro.com/digital-forensics-software/ftk-imager
