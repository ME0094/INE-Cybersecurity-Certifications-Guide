# Evidence Acquisition (eCDFP Methodology — Phase 01)

> Companion study guide for the eCDFP (Certified Digital Forensics Professional) Blue Team methodology track. This phase covers the collection of digital evidence in a way that preserves its integrity and can withstand scrutiny in an incident report or a court of law.
>
> Every command below is a **syntax reference**. This repository ships no captured command output, and no acquisition was performed on the machine that wrote this file: there is no image, no device and no toolchain here. Where a command would produce a result, the text says what to look for. Confirm flags against the manual page for the version you install.

## Overview

Acquisition is the first phase of a forensic examination (collection in the NIST SP 800-86 model). Its goal is simple to state and hard to execute perfectly: **capture the data that answers the investigation's questions while changing the source as little as possible, and prove that you did so.** Every later phase (analysis, timeline, reporting) depends on the quality and defensibility of the acquired evidence.

Two ideas drive everything in this phase:

- **Integrity** — the evidence you analyze must be bit-for-bit identical to what was on the original media.
- **Chain of custody** — you must be able to account for who handled the evidence, when, and why, from seizure to courtroom.

A third idea is easy to forget and decides most disputes: **acquisition is a set of decisions, not a single command.** Which source, in which order, at which depth, with which tools, and with what documented justification. The commands are the least interesting part.

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

> Note what level 5 implies: **remote logs are more volatile than the disk** in practice, because their retention is somebody else's decision. Ordering a log export from the network or identity team is an acquisition action with a deadline, and it belongs on day one of the case, not week three. See `06-network-and-log-forensics.md`.

## Authorization, scope and data minimization

Before a single byte is copied, three questions need written answers. In a corporate investigation they are usually answered by legal, HR or the system owner; in a criminal matter they are answered by a warrant or equivalent. In a lab, they are answered by "these are my VMs".

| Question | Why it constrains the technical work |
| --- | --- |
| **On what authority?** | Consent, an employment agreement, a contractual right to audit, or legal process. The authority defines what you may look at and what you must not. |
| **What is in scope?** | Named devices, accounts, time windows, and data categories. Scope creep is both a legal risk and an analytical one: unrelated data consumes the time you need for the case. |
| **How will you minimize?** | The least invasive method that answers the question, the narrowest data category that supports it, and a record of why each acquisition was necessary. |

Practical consequences:

- **Ask for the authorization in writing and keep it in the case file.** "Verbal approval from the manager" is not an answer a reviewer will accept.
- **Record refusals and constraints.** "The mailbox was excluded from scope at legal's instruction" belongs in the report's limitations.
- **Prefer targets over wholesale copies.** Extracting the artefacts that answer the question beats imaging a machine and searching it later, both legally and analytically — provided the method is documented and the artefacts are hash-verified.
- **Minimization is continuous, not a one-time decision.** Every time you broaden a search, you are making a scope decision; note it.
- **Personal data has handling rules** (retention, storage, who may access it, when it must be destroyed) that are usually written down somewhere in your organisation. Ask before you need them.

## Choosing the acquisition method

The single most consequential decision in this phase: what to copy, at what depth. Work down this table from the least invasive option that answers the question.

| Method | What you get | What it misses | Cost and risk | Typical trigger |
| --- | --- | --- | --- | --- |
| **Targeted artefact export** | Named files or artefact sets (logs, hives, a mailbox extract) | Everything you did not name — including deleted data and unallocated space | Low; minimal disruption | A specific question with a known artefact answer |
| **Logical / file-level copy** | Files and folders through the OS, with their metadata as the OS reports it | Deleted files, slack, unallocated space, unallocated MFT records | Low | The content is what matters and the media is not evidence |
| **Live response collection** | Volatile state plus selected artefacts from a running system | Consistency: the system changes while you collect | Medium; alters the source by its very nature | The system cannot be stopped, or volatile state is in scope |
| **Memory acquisition** | RAM: processes, connections, keys, injected code | Anything that was on disk only | Medium; requires a live system and a separate analysis host | Fileless activity, encryption keys, live network state (see `../tools/memory-analysis.md`) |
| **Full disk image** | Every sector: allocated files, deleted data, slack, unallocated space | Volatile state; content protected by encryption without keys | High; needs a write blocker, time and storage | The disk is the question, or the case may go to court |
| **Physical / chip-off or firmware-level** | Content below the file system, including remapped or hidden areas | Nothing in principle | Very high; often destructive; needs specialist facilities | Damaged media, or evidence suspected below the file system |
| **Remote / over-the-network image** | A disk or volume copied across a network from a host you cannot detach | Consistency guarantees, and anything the remote tool cannot read | Medium to high; bandwidth-bound; depends on the remote host's integrity | Virtual machines, cloud volumes, remote sites (see `07-mobile-cloud-container-forensics.md`) |
| **Third-party / provider-held data** | Records held by a service provider or platform | Whatever the provider does not retain, and whatever its retention has already deleted | Low technically, high in process time | Cloud, SaaS, carrier and messaging data |

Two rules of thumb that prevent most bad acquisition choices:

1. **Choose the least invasive method that answers the question, then document the reasoning.** "Logically copied, because the question concerned current file content and no deleted-data claim was in scope" is a complete justification.
2. **Never let the tool's convenience set the scope.** If the full image is easy to make, that is not a reason to make it when a targeted export answers the question.

## Live vs. Dead Acquisition

| Aspect | Live acquisition | Dead (static) acquisition |
| --- | --- | --- |
| System state | Running; you collect data as it exists | Powered off; media removed and imaged offline |
| What you get | RAM, processes, network state, mounted volumes, encryption keys | A clean disk image; no volatile data |
| Risk | The act of collecting changes system state | Powering off destroys volatile data and may trigger encryption/locks |
| When to use | Encryption in use, mission-critical systems, need for memory/processes | When the machine can be stopped and a clean image is sufficient |

**Practical guidance:** acquire memory and volatile state *before* touching the disk, then decide whether a live disk capture or a shut-down-and-image approach is appropriate. Never pull the power cable as a reflex — on systems with full-disk encryption or unsaved state, a hard power-off can make later analysis impossible or legally problematic. Weigh the trade-off and document it.

### The "should I power it off?" decision

| Situation | Prefer | Because |
| --- | --- | --- |
| Full-disk encryption is in use and the volume is unlocked | **Keep it running**, capture memory first | Keys live in RAM. Power-off means ciphertext and no way back in |
| The system is a server providing a live service | Keep it running, collect live response, then coordinate a controlled shutdown with the owner | Availability matters, and a shutdown is itself a business event |
| Suspicious processes are running and volatile state is the question | Keep it running, capture memory and volatile state | A power-off destroys precisely the evidence in scope |
| The disk is unencrypted and nothing volatile is in scope | Powered off, then imaged | A clean image of a static disk is the most defensible artefact you can produce |
| The machine may be booby-trapped or is physically unstable | Follow the incident plan and get authorization before touching it | Physical and safety decisions are not the examiner's alone |
| It is a virtual machine | Snapshot, then acquire the disk file(s) — and record that you snapshotted | A snapshot is fast, reversible and preserves state; but note what a hypervisor snapshot does and does not include (see `../labs/lab-environment.md`) |

Whatever you choose, the *reason* is a required field in your notes. "Powered off because the volume was unencrypted and no volatile state was in scope" is defensible. "Powered it off" is not.

## Preparation and Documentation

Before touching the evidence:

- Assign a **case number** and an **exhibit number** (e.g., `Case-2024-001 / Exhibit 1`).
- Photograph the system and its connections; note the make, model, serial number, and state (powered on/off, open applications).
- Prepare an **acquisition worksheet**: date/time (UTC recommended), examiner name, tool and version, source device, destination file, hash values.
- Record the environment: is the machine domain-joined, encrypted (BitLocker/FileVault/LUKS), virtualized, or in the cloud?

Every observation is a data point for the report phase.

A worksheet template you can copy into the case file:

```text
CASE SHEET — ACQUISITION
Case number .......... CASE-2024-001
Exhibit(s) ........... E01 (disk), E02 (memory)
Authority / scope .... <who authorized, what is in scope, what is excluded>
Date and time (UTC) .. 2024-11-03 09:12
Examiner ............. <name, role>
Location ............. <room, address, or "lab VM on host X">
Source ............... make / model / serial / capacity; or VM name and disk file
Source state ......... powered on (running services: ...) | powered off | suspended
Encryption ........... none | BitLocker (key escrow: ...) | LUKS | FileVault | unknown
Volatile capture ..... memory acquired first? tool and version; where stored
Write protection ..... hardware blocker model | software read-only | none (justify)
Tool(s) and version .. <name + version for every tool used>
Destination .......... path, filesystem, free space before/after
Hashes ............... source SHA-256, image SHA-256, both recorded where?
Deviations ........... anything that did not go to plan, and the reason
```

The `Deviations` field is not optional, and an empty one is a claim that nothing went wrong. Fill it honestly; a documented deviation costs you nothing, an undocumented one costs the case.

## Write Blockers and Forensic Hardware

A **write blocker** sits between the evidence drive and the acquisition workstation and enforces read-only access at the hardware level, so even the operating system cannot modify the source.

- Hardware write blockers (e.g., Tableau, Wiebetech) are the gold standard: they are OS-independent and simple to explain in court.
- Software-only "read-only" approaches (read-only mounts, `blockdev --setro`) are weaker: the OS or a buggy driver can still write (journal replay, atime updates, antivirus scans). Prefer a hardware blocker; if one is unavailable, document the risk.
- Verify the blocker works before imaging: connect the drive, confirm the OS sees it as read-only, then proceed.

Acquire on a **forensic workstation** — a clean, dedicated machine — never on the suspect's computer or a general-purpose laptop.

What a write blocker does **not** protect you from:

- **Reading the source is not always free.** The device's own firmware can write to itself during normal operation (wear levelling, error logging, translation-table updates). A blocker prevents *your host* from writing; it cannot make the device static.
- **A blocker does not make the image complete.** Unstable sectors, a failing drive, or a translator that hides bad blocks all mean the image may differ from what the drive would report on another day. Record read errors and their count.
- **A blocker does not preserve volatile state.** It says nothing about RAM, which is why memory capture is a separate, prior step.
- **A blocker does not validate your device identification.** Verify with `lsblk`/`blkid` that you are about to read the device you think you are.
- **A software write blocker may still allow writes** through an unblocked path (a second OS, a management interface, an automount). Treat software protection as a convenience, and say so in the report.

## Disk Imaging with `dd` and EWF

A forensic image is a bit-for-bit copy of the entire media, including unallocated space, slack, and deleted data — not a file-by-file copy. Common formats:

- **Raw** (`dd` output, `.dd`/`.img`/`.raw`) — simple, universally supported by analysis tools.
- **EWF / E01** (Expert Witness Format) — compressed and segmented, with built-in integrity metadata; produced by `ewfacquire` (libewf), Guymager, FTK Imager.
- **AFF4 / AFF** — alternative formats with compression and metadata (less common in this course's tooling).

Choose between them deliberately:

| Consideration | Raw | EWF / E01 |
| --- | --- | --- |
| Tool support | Universal | Wide, but not every tool reads every variant |
| Size on disk | Full media size | Compressed; typically much smaller |
| Integrity metadata | None of its own — you supply it | Its own checksums per segment, verified by the tool |
| Segmentation and transport | One large file | Split segments travel and store more easily |
| Speed to create | Fastest | Slower; compression costs CPU |
| Traceability of the container | None; the hash manifest is everything | Container metadata records case, examiner, notes |

```bash
# 1. Identify the evidence device WITHOUT letting the OS mount it.
#    (Disable automount first; verify the exact device path twice.)
sudo fdisk -l          # note the device, e.g. /dev/sdb — NOT the workstation disk!

# 2. Hash the SOURCE before imaging (hash while the write blocker is active). Keep this
#    manifest separate: it names the DEVICE, so 'sha256sum -c' on it would re-read the
#    device — it is not a check of the image.
sudo sha256sum /dev/sdb | tee /case/evidence-source.sha256

# 3. Create a raw forensic image.
#    conv=noerror,sync : keep going on read errors and pad them with zeros
#    bs=4M             : large block size for speed
sudo dd if=/dev/sdb of=/case/evidence.dd bs=4M conv=noerror,sync status=progress

# 4. Hash the IMAGE and write the image's OWN manifest, naming the image
sha256sum /case/evidence.dd | tee /case/evidence.dd.sha256

# 5. Verify the image against the image's manifest. This reads evidence.dd and nothing else.
sha256sum -c /case/evidence.dd.sha256

# 6. Compare the two recorded digests explicitly — source device against image. They must be
#    equal. This is the source-to-image comparison, and note that it is not what step 5 did:
#    re-reading the device is a deliberate act, not a side effect of a manifest check.
cat /case/evidence-source.sha256 /case/evidence.dd.sha256
```

```bash
# Alternative: acquire directly into EWF (.E01) with libewf's ewfacquire.
# Two traps in this switch set: -u is *unattended mode* and takes NO argument, and
# -t names the target WITHOUT its extension (-t /case/evidence writes /case/evidence.E01).
sudo ewfacquire -u -C "2024-001" -D "suspect laptop HDD" -e "A. Examiner" \
  -m fixed -t /case/evidence /dev/sdb
# What to look for: a completed acquisition summary, and a read-error count you can
# explain. Confirm the switch set with ewfacquire -h on your build: it differs between
# libewf releases.
```

If a hardware write blocker is unavailable, a Linux host can still image a device that the kernel did not mount; the `dd`/`ewfacquire` commands above operate on the raw block device. Never image a **mounted** filesystem and call it a forensic acquisition — mounted writes can change it mid-copy.

> **Do not hash a live source and present it as an integrity reference.** A running disk changes while you read it, so the "source hash" of a live system is a value that describes a moving target. Where you must acquire from a live system, hash the *image*, document that the source was live and changing, and record which volatile artefacts you captured first. The defensible claim is "the image matches what the source reported during the acquisition window, and the image has not changed since" — not "the image matches the original disk".

## Special media: encryption, RAID, SSD and virtual disks

The comfortable model — "a disk is a device, an image is a copy of it" — breaks in four common situations. Each needs a decision *before* you start, because some of these choices are irreversible.

### Encrypted volumes

- **Capture memory first if the volume is unlocked.** The keys, or the material needed to derive them, may exist only in RAM.
- **Without keys, an image of an encrypted volume is ciphertext.** It is still worth acquiring — you may obtain keys later, and the container's metadata is evidence — but say plainly in the report what it contains.
- **Look for the key escrow the organisation already has**: recovery keys in a directory service, a managed-encryption console, a documented password vault. This is a question for the system owner on day one.
- **Do not attempt to force the volume.** Attempts can trigger lock-out or key destruction, depending on the implementation. Escalate to someone authorised to make that call.
- **Note the encryption state precisely**: fully encrypted, encrypted with the volume unlocked, or partially encrypted (a conversion in progress is a real and awkward state).

### RAID, LVM, Storage Spaces and spanned volumes

- **A "disk" may be a construct.** Hardware RAID hides member disks behind a controller; software RAID, LVM and Storage Spaces assemble a volume from several members.
- **Image the members wherever you can, not only the assembled volume.** Reassembling later from members is possible; recovering member-level data from an assembled image is not.
- **Record the assembly parameters**: RAID level, stripe size, member order, LVM metadata, and the controller model. Without these the members are an unreadable set of blocks.
- **Hardware RAID with a write-back cache may contain unwritten data.** A clean shutdown flushes it; a power loss may not. Note the state.

### SSD, NVMe and flash media

- **Deletion on flash may be closer to final than on spinning media.** TRIM and garbage collection can erase blocks the file system no longer references, which means a "deleted file recovery" that would work on a hard disk may find nothing.
- **The device you image is not the whole device.** Controllers remap blocks, reserve over-provisioned space and maintain their own metadata. A logical image is the device's *reported* content, not every physical cell.
- **Wear levelling spreads writes**, so a single logical change may touch several physical locations — good for the device's life, unhelpful for recovering overwritten content.
- **Record the model and firmware** and state in the report that the acquisition is the controller's view of the media.

### Virtual disks

- **A VM's "disk" is a file**, often in a format with snapshots, thin provisioning and a copy-on-write layer (VMDK, VHDX, qcow2). Imaging the wrong layer gives you the wrong data.
- **Preserve the whole chain.** The base disk plus any snapshot delta files together represent the machine's storage; a single delta file alone is not the disk.
- **Record the hypervisor and the disk format**, and prefer a hypervisor-level snapshot plus a copy of every layer over a guest-level copy.

## Memory and volatile state acquisition

Memory is the level-2 and level-3 evidence from the volatility table, and it is the only way to see activity that never touched the disk. Tooling, plugins and interpretation are covered in `../tools/memory-analysis.md`; what belongs in *this* phase is the decision and the documentation.

Capture, in order:

1. **Memory**, with a documented tool and version, to a destination that is not the source system.
2. **Volatile network and system state** that the memory image may not preserve conveniently: the routing table, ARP cache, active connections, logged-on sessions, loaded modules, and the current time.
3. **A full disk image or targeted artefact set**, per the decision table above.

```bash
# Illustrative shape of a volatile-state collection on a live Linux system.
# What to look for: consistent timestamps on every file, and a record of the exact
# command used for each one. The specific tools are your choice — record which.
date -u > /case/volatile/00-time-utc.txt
ip addr    > /case/volatile/01-ip-addr.txt
ip route   > /case/volatile/02-ip-route.txt
ip neigh   > /case/volatile/03-arp.txt
ss -anp    > /case/volatile/04-sockets.txt
ps auxww   > /case/volatile/05-processes.txt
who -a     > /case/volatile/06-sessions.txt
```

Three cautions worth stating in the report:

- **Memory acquisition alters the system.** Loading a capture tool changes memory. That is unavoidable and acceptable; not mentioning it is not.
- **A hibernation file or pagefile is not a memory image.** Both may contain fragments of RAM, and both are worth collecting — but neither is a snapshot of live state, and treating one as the other misstates your evidence.
- **A hypervisor snapshot is not a purpose-built memory capture.** It may omit structures or present memory differently. Where you use one, say so, and validate the result before analysing it (see `../labs/memory-injection-lab.md`).

## Remote and network acquisition

Sometimes the media is in a machine you cannot detach: a virtual machine, a cloud volume, a server in another country, a site with no examiner on it. Remote acquisition is legitimate and common, with three constraints.

| Constraint | Consequence | Mitigation |
| --- | --- | --- |
| The source is live and controlled by software you did not build | Consistency cannot be guaranteed the way an offline image can | Freeze where the platform allows (snapshot, suspend, quiesce); record exactly what you froze |
| The transfer is over a network you do not control | Integrity in transit, and possible interception | Hash at both ends and compare; record the transport and who operated the far end |
| The remote operator is not you | Chain of custody crosses an organisational boundary | Name the operator, their organisation, and the instructions they followed; keep the correspondence |

Practical rules:

- **Prefer a platform snapshot over a live file copy**, and prefer copying a snapshot over reading the running volume. Document which layer you copied (see "Virtual disks" above).
- **Hash at both ends.** The far end should hash before transfer; you should hash after. Two independent values that agree are the evidence that the transfer was faithful.
- **Estimate before you start.** Bandwidth, time, and storage at the destination. A multi-terabyte volume over a domestic link is not a plan.
- **Record who ran the commands on the far side, and what they ran.** Their notes are part of your chain of custody.
- **For cloud and container evidence, follow the preservation order in `07-mobile-cloud-container-forensics.md`** — the audit trail is more perishable than the volume.

## Hashing and Integrity Verification

Hashes are the integrity backbone of an acquisition. The forensic standard is **SHA-256** (collision-resistant, fast, and supported by every tool). MD5/SHA-1 alone are legacy; some labs compute both for compatibility, but SHA-256 is the defensible primary.

- Hash the **source** and the **destination** at acquisition time.
- Write a manifest **per artefact**, each naming the file it describes. `sha256sum -c` re-hashes whatever its manifest names, so a manifest of the source device verifies the device — never the image — and reading the device again is a separate, deliberate act.
- Store hashes **away from the image** (in the case file / notes), so they can independently verify the image later.
- Re-hash the image each time it is checked out for analysis; the hash of the original sealed copy is the reference.

```bash
# Verify an image against the IMAGE's manifest (one "<hash>  <filename>" per line).
# A manifest that names the source device is not this one: -c would read the device again.
sha256sum -c /case/evidence.dd.sha256

# Record hashes of both original and working copy in the notes
sha256sum /case/evidence.dd /case/working-copy.dd
```

```bash
# For EWF containers, verify the container's own integrity metadata as well
ewfverify /case/evidence.E01
ewfinfo /case/evidence.E01
# What to look for: a verification result with no mismatch, and container metadata
# that matches what you wrote into the acquisition log (case, exhibit, examiner).
```

What hashing does and does not establish:

| Claim | Established by a hash? |
| --- | --- |
| The image has not changed since you hashed it | Yes — this is exactly what a hash proves |
| The image is a faithful copy of the source at acquisition time | Yes, if the source hash was taken correctly and the values match |
| The source was not altered before you hashed it | No. A hash taken after an alteration records the altered state |
| The image came from the device you think it did | No — that is provenance, established by your acquisition record and chain of custody |
| The evidence is authentic in a legal sense | No — authenticity is a legal conclusion built on provenance, custody and methodology |

That distinction — **integrity versus authenticity** — is one of the most common misconceptions in this phase. A perfect hash of the wrong drive is a perfectly preserved copy of the wrong drive.

## Post-Acquisition Steps

1. **Verify structure** — confirm the image is a valid disk you can parse:

```bash
# mmls lists the partition layout; fsstat shows filesystem metadata
mmls /case/evidence.dd
fsstat -o 2048 /case/evidence.dd      # 2048 = example NTFS partition offset in sectors
# What to look for: a partition table that makes sense for the source, and a file
# system whose type matches what the source was expected to use. A partition layout
# that does not match the source's real configuration is a stop-and-investigate signal.
```

2. **Make a working copy** and analyze only the copy; store the original (and its hash) as the sealed master.
3. **Seal and store** the original media and images in a secure, access-controlled location, and record storage in the chain-of-custody log.

A custody log row for reference:

| Date/time (UTC) | Exhibit | Action | Handler | Location / notes |
| --- | --- | --- | --- | --- |
| 2024-11-03 09:00 | CASE-001-E01 | Seized and imaged | J. Doe | On scene, hardware write blocker |
| 2024-11-03 13:30 | CASE-001-E01 | Sealed and stored | J. Doe | Evidence locker 4 |
| 2024-11-05 10:00 | CASE-001-E01 | Checked out for analysis | A. Smith | Hash verified before and after; working copy made |

## Common Mistakes & Tips

- **Imaging the wrong device.** Double-check `fdisk -l` output; imaging your own workstation disk destroys the case AND your machine.
- **Letting the OS mount the evidence drive.** Journal replay, atime, or an antivirus can alter it; disable automount or use a write blocker before connecting.
- **Skipping the source hash.** Without a pre-image hash you cannot prove the image matches the media.
- **Only hashing a file copy.** `dd` of a mounted filesystem or copying individual files loses deleted data and produces an inconsistent snapshot.
- **Powering off without thinking.** Capture RAM first when the machine is running; on encrypted disks a forced shutdown can cost you everything.
- **Hashing a live system and calling it the reference.** A moving source has no stable hash. Hash the image, and describe the source's state honestly.
- **Treating a hypervisor snapshot as a memory image**, or the other way round. They are different artefacts with different coverage.
- **Imaging a single layer of a virtual disk** and treating it as the machine's storage. Preserve the whole chain.
- **Assuming flash behaves like a hard disk.** TRIM and garbage collection can make "deleted" final, and the controller's view is not the whole device.
- **Imaging the assembled RAID volume and discarding the members.** Members can be reassembled later; the assembled image cannot be decomposed.
- **Not recording read errors.** `conv=noerror,sync` keeps going and pads bad sectors — which means your image contains invented bytes where the source was unreadable. Record how many.
- **Forgetting documentation.** An undocumented acquisition is nearly useless in an investigation.
- **Forgetting the authority and the scope.** The most defensible acquisition in the world is worthless if you were not entitled to make it.
- **Tip:** record the local time zone and the system time of the suspect machine — timeline analysis needs them.
- **Tip:** test your full imaging workflow (blocker, cables, storage space) before you need it under pressure.
- **Tip:** write the worksheet *before* you start the copy and finish it during, not after. The fields you fill from memory are the ones that turn out to be wrong.
- **Tip:** treat the acquisition log as a deliverable, not as notes. It is the first thing a reviewer reads.

## Checklist / Self-Test

- [ ] Can I state the five core rules of forensic evidence handling from memory?
- [ ] Can I list the order of volatility in the correct sequence and justify it, including why remote logs are more perishable than the disk?
- [ ] Can I state, for a given case, who authorised the acquisition, what is in scope, and how I am minimizing?
- [ ] Can I choose an acquisition method from the decision table and justify why the more invasive options were not needed?
- [ ] Do I know when a live acquisition is required instead of a dead one, and what a live acquisition must capture first?
- [ ] Can I explain why a hardware write blocker is preferred over a read-only OS mount, and name two things a blocker does not protect me from?
- [ ] Can I write a complete `dd` imaging command with integrity options, and an `ewfacquire` equivalent?
- [ ] Can I explain why a live source has no meaningful "source hash", and how I would word the integrity claim instead?
- [ ] Can I describe what changes when the media is encrypted, part of a RAID set, flash-based, or a virtual disk?
- [ ] Do I hash the source AND the destination, and do I know how to verify with `sha256sum -c` and `ewfverify`?
- [ ] Can I explain the difference between integrity and authenticity, and why a hash proves only the first?
- [ ] Does my acquisition worksheet record authority, scope, device, tool versions, UTC timestamps, hashes and deviations?
- [ ] Can I describe the chain-of-custody information that must accompany every exhibit, and produce a custody row?
- [ ] Have I ever completed a full acquisition end to end in my own lab, from write-blocker check to sealed working copy?

## Further Resources

- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **NIST SP 800-101 Rev. 1**, *Guidelines on Mobile Device Forensics* (acquisition levels for a device you cannot detach) — https://csrc.nist.gov/publications/detail/sp/800-101/rev-1/final
- **ISO/IEC 27037**, *Guidelines for identification, collection, acquisition and preservation of digital evidence* — https://www.iso.org/standard/44381.html
- **RFC 3227**, *Guidelines for Evidence Collection and Archiving* — https://www.rfc-editor.org/rfc/rfc3227
- **The Sleuth Kit documentation** (partition and filesystem inspection of images) — https://www.sleuthkit.org/sleuthkit/
- **libewf (EWF/E01 format) project** — https://github.com/libyal/libewf
- **SANS reading room** (white papers on acquisition and evidence handling) — https://www.sans.org/reading-room/

> **Verification:** executed on **2026-09-19** (Ubuntu 24.04 WSL). The hashing flow was rehearsed
> with files standing in for the device and the image, which isolates the defect: with `source.bin`
> and `image.dd` carrying the same digest, `sha256sum -c source.sha256` printed `source.bin: OK`
> and `sha256sum -c image.dd.sha256` printed `image.dd: OK`; after flipping **one byte of the
> image**, `sha256sum -c source.sha256` still printed `source.bin: OK, exit 0` — it never opened
> the image — while `sha256sum -c image.dd.sha256` printed `image.dd: FAILED` and exited 1.
> `sha256sum --help` documents `-c, --check   read checksums from the FILEs and check them`.
> EWF was also executed with **ewfacquire/ewfverify 20140814** on a 4 MiB test file:
> `ewfacquire -u -q -C 2024-001 -D … -e … -m fixed -d sha256 -t case src.bin` printed
> `ewfacquire: SUCCESS` and wrote `case.E01`, and `ewfverify -d sha256 case.E01` printed
> `ewfverify: SUCCESS` with the stored MD5 equal to the calculated MD5 and the calculated SHA-256
> equal to the source's. That run also exposed a defect in the EWF example above that this pass was
> not scoped to change, so it is recorded rather than fixed: `-u` is *unattended mode* and takes no
> argument (`ewfacquire -h`: `-u: unattended mode (disables user interaction)`), so
> `-u "evidence-exhibit-1"` makes that string a second **source** and the acquisition aborts with
> `libbfio_pool_open: unable to open entry: 0` and no output file; and `-t` names the target
> *without* extension (`-t: specify the target file (without extension) to write to`), so
> `-t /case/evidence.E01` creates `evidence.E01.E01`. Passing the examiner name to `-e` and
> `-t /case/evidence` works.
> **Not executed:** `dd`/`dc3dd`/`ewfacquire` against a real block device —
> no evidence device is attached to this machine. The publication title was corrected against the
> NIST CSRC record, which names SP 800-101 Rev. 1 *Guidelines on Mobile Device Forensics*:
> https://csrc.nist.gov/pubs/sp/800/101/r1/final.
