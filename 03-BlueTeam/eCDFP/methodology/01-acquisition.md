# Evidence Acquisition (eCDFP Methodology — Phase 01)

> Companion study guide for the eCDFP (Certified Digital Forensics Professional) Blue Team methodology track. This phase covers the collection of digital evidence in a way that preserves its integrity and can withstand scrutiny in an incident report or a court of law.

## Overview

Acquisition is the first phase of a forensic examination (collection in the NIST SP 800-86 model). Its goal is simple to state and hard to execute perfectly: **capture the data that answers the investigation's questions while changing the source as little as possible, and prove that you did so.** Every later phase (analysis, timeline, reporting) depends on the quality and defensibility of the acquired evidence.

Two ideas drive everything in this phase:

- **Integrity** — the evidence you analyze must be bit-for-bit identical to what was on the original media.
- **Chain of custody** — you must be able to account for who handled the evidence, when, and why, from seizure to courtroom.

## Forensic Principles

### Core rules of evidence handling

1. **Do not alter the original.** Work on verified copies; keep the original sealed and stored.
2. **Document everything.** Who, what, when, where, why, and how for each action.
3. **Follow the Order of Volatility** (below) when a system is still running.
4. **Use tools you can explain.** Prefer well-known, defensible tools and record their versions and configuration.
5. **Maintain a clear chain of custody** so the evidence's history is auditable.

Locard's exchange principle applies in digital forensics too: an attacker (or an examiner) always leaves traces on the media they touch — which is why your own tools must not contaminate the evidence drive.

### Order of volatility (RFC 3227)

Capture data from the *most volatile* to the *least volatile*. Each level of volatility is lost the moment the system changes state:

1. CPU registers and cache
2. Routing tables, ARP cache, process table, kernel memory
3. Temporary file systems, swap/pagefile
4. Data stored on disk (files, unallocated space)
5. Remote logging and monitoring data (logs on other hosts)
6. Physical configuration and archival media

If you cannot capture a level (for example, no tool available for memory), document that decision and the reason — a justified gap is acceptable, an undocumented one is not.

## Live vs. Dead Acquisition

| Aspect | Live acquisition | Dead (static) acquisition |
| --- | --- | --- |
| System state | Running; you collect data as it exists | Powered off; media removed and imaged offline |
| What you get | RAM, processes, network state, mounted volumes, encryption keys | A clean disk image; no volatile data |
| Risk | The act of collecting changes system state | Powering off destroys volatile data and may trigger encryption/locks |
| When to use | Encryption in use, mission-critical systems, need for memory/processes | When the machine can be stopped and a clean image is sufficient |

**Practical guidance:** acquire memory and volatile state *before* touching the disk, then decide whether a live disk capture or a shut-down-and-image approach is appropriate. Never pull the power cable as a reflex — on systems with full-disk encryption or unsaved state, a hard power-off can make later analysis impossible or legally problematic. Weigh the trade-off and document it.

## Preparation and Documentation

Before touching the evidence:

- Assign a **case number** and an **exhibit number** (e.g., `Case-2024-001 / Exhibit 1`).
- Photograph the system and its connections; note the make, model, serial number, and state (powered on/off, open applications).
- Prepare an **acquisition worksheet**: date/time (UTC recommended), examiner name, tool and version, source device, destination file, hash values.
- Record the environment: is the machine domain-joined, encrypted (BitLocker/FileVault/LUKS), virtualized, or in the cloud?

Every observation is a data point for the report phase.

## Write Blockers and Forensic Hardware

A **write blocker** sits between the evidence drive and the acquisition workstation and enforces read-only access at the hardware level, so even the operating system cannot modify the source.

- Hardware write blockers (e.g., Tableau, Wiebetech) are the gold standard: they are OS-independent and simple to explain in court.
- Software-only "read-only" approaches (read-only mounts, `blockdev --setro`) are weaker: the OS or a buggy driver can still write (journal replay, atime updates, antivirus scans). Prefer a hardware blocker; if one is unavailable, document the risk.
- Verify the blocker works before imaging: connect the drive, confirm the OS sees it as read-only, then proceed.

Acquire on a **forensic workstation** — a clean, dedicated machine — never on the suspect's computer or a general-purpose laptop.

## Disk Imaging with `dd` and EWF

A forensic image is a bit-for-bit copy of the entire media, including unallocated space, slack, and deleted data — not a file-by-file copy. Common formats:

- **Raw** (`dd` output, `.dd`/`.img`/`.raw`) — simple, universally supported by analysis tools.
- **EWF / E01** (Expert Witness Format) — compressed and segmented, with built-in integrity metadata; produced by `ewfacquire` (libewf), Guymager, FTK Imager.
- **AFF4 / AFF** — alternative formats with compression and metadata (less common in this course's tooling).

```bash
# 1. Identify the evidence device WITHOUT letting the OS mount it.
#    (Disable automount first; verify the exact device path twice.)
sudo fdisk -l          # note the device, e.g. /dev/sdb — NOT the workstation disk!

# 2. Hash the SOURCE before imaging (hash while the write blocker is active)
sudo sha256sum /dev/sdb | tee /case/evidence-source.sha256

# 3. Create a raw forensic image.
#    conv=noerror,sync : keep going on read errors and pad them with zeros
#    bs=4M             : large block size for speed
sudo dd if=/dev/sdb of=/case/evidence.dd bs=4M conv=noerror,sync status=progress

# 4. Hash the RESULT. It must match the source hash exactly.
sha256sum /case/evidence.dd
sha256sum -c /case/evidence-source.sha256   # reads the file's stored hash
```

```bash
# Alternative: acquire directly into EWF (.E01) with libewf's ewfacquire
sudo ewfacquire /dev/sdb \
  -u "evidence-exhibit-1" \
  -e "Case 2024-001, Exhibit 1: suspect laptop HDD" \
  -m fixed \
  -t /case/evidence.E01
```

If a hardware write blocker is unavailable, a Linux host can still image a device that the kernel did not mount; the `dd`/`ewfacquire` commands above operate on the raw block device. Never image a **mounted** filesystem and call it a forensic acquisition — mounted writes can change it mid-copy.

## Hashing and Integrity Verification

Hashes are the integrity backbone of an acquisition. The forensic standard is **SHA-256** (collision-resistant, fast, and supported by every tool). MD5/SHA-1 alone are legacy; some labs compute both for compatibility, but SHA-256 is the defensible primary.

- Hash the **source** and the **destination** at acquisition time.
- Store hashes **away from the image** (in the case file / notes), so they can independently verify the image later.
- Re-hash the image each time it is checked out for analysis; the hash of the original sealed copy is the reference.

```bash
# Verify an image against its manifest (one "<hash>  <filename>" per line)
sha256sum -c /case/evidence-source.sha256

# Record hashes of both original and working copy in the notes
sha256sum /case/evidence.dd /case/working-copy.dd
```

## Post-Acquisition Steps

1. **Verify structure** — confirm the image is a valid disk you can parse:

```bash
# mmls lists the partition layout; fsstat shows filesystem metadata
mmls /case/evidence.dd
fsstat -o 2048 /case/evidence.dd      # 2048 = example NTFS partition offset in sectors
```

2. **Make a working copy** and analyze only the copy; store the original (and its hash) as the sealed master.
3. **Seal and store** the original media and images in a secure, access-controlled location, and record storage in the chain-of-custody log.

## Common Mistakes & Tips

- **Imaging the wrong device.** Double-check `fdisk -l` output; imaging your own workstation disk destroys the case AND your machine.
- **Letting the OS mount the evidence drive.** Journal replay, atime, or an antivirus can alter it; disable automount or use a write blocker before connecting.
- **Skipping the source hash.** Without a pre-image hash you cannot prove the image matches the media.
- **Only hashing a file copy.** `dd` of a mounted filesystem or copying individual files loses deleted data and produces an inconsistent snapshot.
- **Powering off without thinking.** Capture RAM first when the machine is running; on encrypted disks a forced shutdown can cost you everything.
- **Forgetting documentation.** An undocumented acquisition is nearly useless in an investigation.
- **Tip:** record the local time zone and the system time of the suspect machine — timeline analysis needs them.
- **Tip:** test your full imaging workflow (blocker, cables, storage space) before you need it under pressure.

## Checklist / Self-Test

- [ ] Can I state the five core rules of forensic evidence handling from memory?
- [ ] Can I list the order of volatility in the correct sequence and justify it?
- [ ] Do I know when a live acquisition is required instead of a dead one, and what a live acquisition must capture first?
- [ ] Can I explain why a hardware write blocker is preferred over a read-only OS mount?
- [ ] Can I write a complete `dd` imaging command with integrity options, and an `ewfacquire` equivalent?
- [ ] Do I hash the source AND the destination, and do I know how to verify with `sha256sum -c`?
- [ ] Does my acquisition worksheet record device, tool versions, UTC timestamps, and hash values?
- [ ] Can I describe the chain-of-custody information that must accompany every exhibit?

## Further Resources

- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **RFC 3227**, *Guidelines for Evidence Collection and Archiving* — https://www.rfc-editor.org/rfc/rfc3227
- **The Sleuth Kit documentation** (partition and filesystem inspection of images) — https://www.sleuthkit.org/sleuthkit/
- **libewf (EWF/E01 format) project** — https://github.com/libyal/libewf
- **SANS reading room** (white papers on acquisition and evidence handling) — https://www.sans.org/reading-room/
