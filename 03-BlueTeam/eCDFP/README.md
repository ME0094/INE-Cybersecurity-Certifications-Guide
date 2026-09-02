# eCDFP — Certified Digital Forensics Professional

> Blue Team · eCDFP module — INE Cybersecurity Certifications Study Guide
>
> Companion study material for the eCDFP certification. This is **general public study content**: it explains forensic concepts, methodology, and hands-on tooling in an authorized lab context. It does not reproduce exam content, questions, or anything covered by NDA.

## What eCDFP covers

eCDFP (Certified Digital Forensics Professional) validates hands-on **digital forensics and incident response (DFIR)** skills. The certification targets practitioners who can methodically acquire, analyze, and report on digital evidence. The four pillars of the discipline are:

1. **Acquisition** — capturing digital evidence without altering it: disk imaging, memory capture, write blockers, and hash verification so evidence stays provably intact.
2. **Analysis** — examining acquired data: file system forensics, deleted file recovery, browser artifacts, memory analysis, and malware traces.
3. **Timeline** — reconstructing *what happened and when* from file metadata, logs, and artifacts to tell the story of an incident.
4. **Reporting** — producing clear, defensible documentation of findings, methods, and chain of custody that a non-technical audience (and ideally a court) can follow.

> Framing note: exam logistics (domains, question mix, passing criteria, lab environment) are published by INE and change over time — always check the official eCDFP page for current, authoritative details before you book the exam.

## Skills you build

Working through this module develops the abilities exam candidates and working DFIR analysts rely on every day:

- Choosing the right acquisition method (logical vs. full disk vs. memory) and documenting it.
- Using a **write blocker** and verifying image integrity with cryptographic hashes.
- Navigating evidence images with file-system forensics tools (Sleuth Kit, Autopsy).
- Recovering deleted files and carving data from unallocated space.
- Extracting and interpreting **memory artifacts** with Volatility.
- Correlating browser, OS, and file-system artifacts into a coherent **timeline**.
- Writing a findings report with repeatable commands and evidence-backed conclusions.

## Module layout

This folder is your study workspace. Each subfolder has a specific role:

| Path | Purpose |
| --- | --- |
| [README.md](README.md) | This overview: what to learn, in what order, and how to self-check. |
| [methodology/](methodology/) | Phase-by-phase notes in working order: [01-acquisition](methodology/01-acquisition.md), [02-analysis](methodology/02-analysis.md), [03-timeline](methodology/03-timeline.md), [04-reporting](methodology/04-reporting.md). |
| [tools/](tools/) | Tool reference guides: [forensic-toolkit](tools/forensic-toolkit.md) (imaging, Sleuth Kit, carving) and [memory-analysis](tools/memory-analysis.md) (Volatility). |
| [labs/](labs/) | Hands-on lab guide: [forensic-exercises](labs/forensic-exercises.md) — build your own exercise images and run guided drills. |
| [cheatsheets/](cheatsheets/) | Quick-reference command sheets: [forensic-commands](cheatsheets/forensic-commands.md). |

## Prerequisites and suggested environment

You will get the most from this module if you already have:

- **Comfort with the Linux command line** — every core tool here is command-line driven.
- **Basic file-system literacy** — partitions, inodes/MFT records, allocation vs. metadata.
- **A small Windows/Linux practice lab** — ideally a hypervisor (VirtualBox, VMware, or KVM) with disposable VMs you can snapshot and destroy freely.

Recommended practice setup:

- One **analysis VM** (Debian/Ubuntu or Kali) with `sleuthkit`, `autopsy`, `foremost`, `scalpel`, `bulk_extractor`, `sqlite3`, and Volatility 3 installed.
- One or two **evidence VMs** you are allowed to break: install apps, browse, delete files, then image them.
- A spare **USB drive or scratch disk** used only for acquisition drills (a single careless `dd` can destroy real data — keep it far from anything you care about).

> Keep practice images small (64–256 MB) for the labs: they are easier to hash, faster to analyze, and you can rebuild them in seconds.

## Key terms you will meet

| Term | Meaning in one line |
| --- | --- |
| Acquisition | Making a bit-for-bit, verified copy of evidence without altering the source. |
| Write blocker | Hardware/software that physically or logically blocks writes to a suspect drive. |
| Image | A file (raw `.dd`, E01, or similar) holding the exact contents of a device or partition. |
| Hash | A cryptographic fingerprint (SHA-256, MD5) proving evidence did not change. |
| Inode / MFT record | The metadata structure that describes a file on ext-family / NTFS file systems. |
| Unallocated space | Disk area no longer referenced by file metadata — where deleted data may still live. |
| Carving | Recovering data by scanning raw bytes for file signatures, without metadata. |
| Body file / timeline | An event list built from file metadata (MAC times) to reconstruct what happened when. |
| Memory dump | A snapshot of RAM; analyzed for live processes, injected code, and network state. |
| Chain of custody | The documented, unbroken record of who handled evidence and when. |

## Evidence-handling principles

These ideas run through every pillar and every lab — internalize them early:

1. **Preserve before you analyze.** Hash first, work on copies, keep the original untouched.
2. **Document everything.** Tool, version, command, output path, hash, date, examiner.
3. **Least surprise.** Choose the least invasive method that answers the question (logical before full disk, file recovery before carving).
4. **Corroborate.** One artifact is a lead; two independent artifacts are a finding.
5. **Think about admissibility.** Even in a corporate setting, assume a report may be reviewed by people who were not in the room.

## How to use this module

Treat the folders as concentric practice rings — read, then do, then compress into memory:

1. **Read the methodology phases in order.** Acquisition → Analysis → Timeline → Reporting mirrors a real investigation and the order you will practice in.
2. **Learn one tool family at a time** using `tools/` (Sleuth Kit & carving first, then memory with Volatility — memory builds on file-system habits).
3. **Do every lab drill** in `labs/forensic-exercises.md` at least twice: once following the steps, once from memory.
4. **Drill with the cheatsheet** until the commands are reflex, then put it away and write the commands out by hand.
5. **Self-check** with each file's "Checklist / Self-test" and the module checklist below before moving on.

## Study roadmap

A realistic self-paced plan for someone with basic Linux and command-line comfort (adjust weeks to your schedule):

| Stage | Focus | Output |
| --- | --- | --- |
| Week 1 | Fundamentals + environment | Reading done; a Linux VM with `sleuthkit`, `volatility3`, and `foremost` installed and verified. |
| Week 2 | Acquisition | A full disk image + hash manifest you created yourself from a scratch drive. |
| Week 3 | Analysis (files) | Deleted file recovered from your own exercise image; file-system walk with `fls`/`fsstat`. |
| Week 4 | Analysis (memory) | A memory sample analyzed end-to-end: processes, network, suspicious process dumped. |
| Week 5 | Timeline | A timeline CSV built from a lab image; incident story summarized in 5 lines. |
| Week 6 | Reporting + review | One complete written report covering a lab scenario; cheatsheet drills from memory. |

## Lab ethics & authorization

- Practice **only** on media you own or were explicitly authorized to examine.
- Treat every sample as potentially malicious: analyze inside a **disposable VM** with no shared folders and snapshots enabled.
- Never attach a write blocker the wrong way, never image a drive that is mounted read-write, and never practice on systems you do not control.
- For public practice data, use the official sample images published by tool projects (Volatility samples, DFRWS challenge data) or your own generated images.

## Common misconceptions

- **"Deleted means gone."** Deleting usually only unlinks metadata; data persists until overwritten. Recovery is often possible — which is exactly what the analysis labs practice.
- **"Forensics is just running tools."** Tools fail silently on the wrong offset, wrong profile, or a mounted evidence drive. The skill is knowing *what to run, in what order, and how to interpret the output*.
- **"You can image a running system."** Live acquisition of memory is fine; imaging a disk from the OS that uses it is not — file changes mid-copy corrupt the evidence.
- **"One tool is enough."** Cross-verify findings (Sleuth Kit + Autopsy, `pslist` + `psscan`) before you put them in a report.
- **"A hash proves authenticity."** A hash proves *integrity* (nothing changed after you hashed). Authenticity — that the image really is the suspect's drive — is proven by your acquisition process and chain of custody.

## Where this fits the Blue Team path

Digital forensics is the after-the-fact sibling of detection and response: the SOC detects an alert, IR contains the incident, and forensics explains what actually happened so it can be prevented next time. The eCDFP skills here pair naturally with incident response, malware analysis, and threat hunting material in the Blue Team track:

- Incident response tells you *what to collect before the box is cleaned*.
- Memory and disk analysis tell you *what the attacker did while it was running*.
- Timeline work tells you *the order of events and the initial access point*.
- Reporting closes the loop with management, legal, and the next incident's playbook.

## Checklist / Self-test

Run through this module checklist — each item maps to a concrete artifact you should be able to produce:

- [ ] I can explain the four pillars (acquisition, analysis, timeline, reporting) and why order matters.
- [ ] I created a full disk image of a practice drive and verified it with `sha256sum`/`hashdeep`.
- [ ] I recovered at least one deleted file from an exercise image and explained how I proved it was deleted.
- [ ] I ran a memory-analysis workflow on a public sample: process listing → network → suspicious process dump.
- [ ] I built a timeline body file and converted it to CSV without losing timestamp context.
- [ ] I wrote one complete short report: scope, method, findings, evidence paths, and conclusions.
- [ ] I can reproduce the key commands from the cheatsheet from memory (no notes).

## Further resources

- NIST SP 800-86 — *Guide to Integrating Forensic Techniques into Incident Response* (csrc.nist.gov/publications).
- Sleuth Kit documentation and wiki — sleuthkit.org (also hosts Autopsy).
- Volatility 3 documentation — volatility3.readthedocs.io.
- Official eCDFP product page on the INE website (current syllabus, logistics, and FAQ).
- DFRWS digital forensics challenge archives — dfrws.org (authorized practice datasets).
