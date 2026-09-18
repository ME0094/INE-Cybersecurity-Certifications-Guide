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

This module covers those four as **phases 01–04** of `methodology/`, and adds four depth passes on top of them — **05** Windows artefact forensics, **06** network and log forensics, **07** mobile, cloud and container forensics, and **08** anti-forensics and evidence integrity. The phase table under *Module layout* below gives the reading order and what each one extends.

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

This folder is your study workspace — **23 Markdown files** in four subfolders:

| Folder | What is in it |
| --- | --- |
| [README.md](README.md) | This overview: what to learn, in what order, and how to self-check. |
| [`methodology/`](methodology/) | The **eight phases** of an examination, in working order — see the phase table below. |
| [`tools/`](tools/) | **Five** tool-family reference guides: acquisition and file system, memory, Windows artefacts, timelines, and estate-wide triage. |
| [`labs/`](labs/) | **Six** hands-on labs, all built on the one workbench in [lab-environment](labs/lab-environment.md). |
| [`cheatsheets/`](cheatsheets/) | **Three** quick-reference sheets for drilling. |

### `methodology/` — the eight phases, in reading order

Numbers are the reading order. Phases **01–04 are the spine** and follow NIST's process model; phases **05–08 are depth passes**, and each one states in its own header which phase it extends — 05 and 06 are companions to 02 and both feed 03, 07 extends the discipline of 01–03 to environments you cannot image, and 08 is a cross-cutting check on 02, 05, 06 and 07.

| # | File | What it covers | Where it sits |
| --- | --- | --- | --- |
| 01 | [01-acquisition](methodology/01-acquisition.md) | Collecting evidence so it stays provably intact: method choice, live vs. dead acquisition, write blockers, `dd`/EWF imaging, memory capture, hashing, chain of custody. | First phase — every later phase depends on it. |
| 02 | [02-analysis](methodology/02-analysis.md) | The file-system spine of analysis: partition geometry, NTFS and ext-family structures, deleted files, unallocated and slack space, registry, browser and application artefacts, keyword search and carving. | After 01. |
| 03 | [03-timeline](methodology/03-timeline.md) | Merging timestamps from many sources into one ordered sequence: what feeds a timeline, the bodyfile format, plaso, measuring clock skew, correlating events. | After 02 — and 05/06 both feed it. |
| 04 | [04-reporting](methodology/04-reporting.md) | Turning analysis into a defensible report: report types, anatomy and skeleton, writing a finding that survives review, confidence language, exhibits and chain-of-custody records. | Last of the spine; 08 is the final check. |
| 05 | [05-windows-artifact-forensics](methodology/05-windows-artifact-forensics.md) | The Windows artefacts that sit *on top of* the file system — execution, persistence, resource use and user activity — organised by the question each family answers, with an evidential ladder of what each proves. | Companion to 02; read 02 first, then this, then 03. |
| 06 | [06-network-and-log-forensics](methodology/06-network-and-log-forensics.md) | The records the *environment* kept about a host: who owns which log, log formats and the parsing problem, log integrity, flow and packet data, and identity resolution. | Companion to 02, and the main feeder for 03. |
| 07 | [07-mobile-cloud-container-forensics](methodology/07-mobile-cloud-container-forensics.md) | The three environments where you cannot detach a disk: mobile acquisition levels and lock state, cloud evidence obtained by API or preservation order, and containers that may not outlive the investigation. | Applies the discipline of 01–03 through a device interface or provider API instead of a write blocker. |
| 08 | [08-anti-forensics-and-evidence-integrity](methodology/08-anti-forensics-and-evidence-integrity.md) | The prior question — *has the record been changed, and by whom?*: a technique taxonomy, a displacement table, timestomping in depth, four-way tests for absent evidence, and the examiner's own integrity obligations. | Cross-cutting check on 02, 05, 06 and 07; best read last. |

### `tools/` — five reference guides

| Guide | What it covers |
| --- | --- |
| [forensic-toolkit](tools/forensic-toolkit.md) | Acquisition with `dd`/`dc3dd`/`ewfacquire`, write blockers, integrity hashing, The Sleuth Kit and Autopsy, and carving with `foremost`/`scalpel`/`bulk_extractor`. |
| [memory-analysis](tools/memory-analysis.md) | Memory forensics with Volatility: Volatility 2 vs 3, profiles and symbol tables, the essential plugins, and a repeatable workflow for chasing a suspicious process. |
| [windows-artifact-tools](tools/windows-artifact-tools.md) | The Windows parsing suite — PECmd, AmcacheParser, AppCompatCacheParser, MFTECmd, LECmd, JLECmd, RECmd, EvtxECmd, SBECmd, WxTCmd, SrumECmd, RBCmd — plus KAPE targets and modules, and diagnosis when a parser fails. |
| [timeline-tools](tools/timeline-tools.md) | The three routes to an ordered event list — TSK bodyfile with `mactime`, the plaso/log2timeline pipeline, and rule-based EVTX triage — plus how to filter, judge timestamps and report a derived artefact. |
| [triage-at-scale](tools/triage-at-scale.md) | Collecting and querying evidence across many endpoints without imaging each disk: Velociraptor's architecture, operating it, the offline collector, evidence handling for remote collection, and when to triage instead of acquiring. |

### `labs/` — six labs, and the phase each one drills

| Lab | What you do | Goes with |
| --- | --- | --- |
| [lab-environment](labs/lab-environment.md) | Build the workbench every other lab assumes: hypervisor and isolated network, a disposable `win-lab` victim, a separate `linux-lab` analysis host, a verified toolchain, snapshot discipline, the `~/lab/<case-id>/` evidence workspace convention, and one standard acquisition procedure. | **Read first** — no other lab restates it. |
| [forensic-exercises](labs/forensic-exercises.md) | The basic drills (Drills 0–6): build your own exercise image, recover a deleted file, identify browser artefacts, build a timeline, analyse a memory dump, parse Windows artefacts out of an image, and carve from unallocated space. | The file-system and basic-tooling side of 01–03. |
| [windows-execution-lab](labs/windows-execution-lab.md) | Five deliberate executions on `win-lab` with the ground truth written down *before* acquisition, then prove — or fail to prove — each one from Prefetch, Amcache, ShimCache, UserAssist, SRUM, the event streams, LNK/jump lists and `$MFT`/USN. | Phase 05, using [windows-artifact-tools](tools/windows-artifact-tools.md). |
| [memory-injection-lab](labs/memory-injection-lab.md) | One process running injected code: capture memory, validate the dump before trusting it, locate the injected region with Volatility 3, take it off the image, and corroborate it outside memory — stating plainly what the evidence cannot show. | The memory work of Phase 01 with [memory-analysis](tools/memory-analysis.md). |
| [supertimeline-lab](labs/supertimeline-lab.md) | Stage a small, entirely benign incident on `win-lab`, acquire it, build three timeline routes over the same evidence, and reconstruct the incident from timestamps alone against a sealed answer key. | Phase 03, using [timeline-tools](tools/timeline-tools.md). |
| [anti-forensics-lab](labs/anti-forensics-lab.md) | Do the tampering yourself inside a disposable VM — timestomping, two kinds of deletion, clearing a log channel, deleting prefetch entries, removing the USN journal, plus a Linux variant — and then detect each act from the image. | Phase 08. |

> Phases 02, 04, 06 and 07 have no dedicated lab: the file-system drills in `forensic-exercises.md` exercise phase 02, and 06 and 07 are read-and-apply phases rather than bench exercises.

### `cheatsheets/` — three quick-reference sheets

| Sheet | What it is for |
| --- | --- |
| [forensic-commands](cheatsheets/forensic-commands.md) | The compact command reference: acquisition, hashing, The Sleuth Kit, artefact extraction, Autopsy, Volatility 3 and the timeline tools. |
| [windows-artifacts](cheatsheets/windows-artifacts.md) | Windows artefacts ordered by the question they answer, each with what it proves and what it does not, a path-and-hive quick reference, and what destroys each one. |
| [evidence-validity](cheatsheets/evidence-validity.md) | What each evidence source can and cannot establish: evidence classes and their ceilings, clock reliability by source, the identity ladder, what a hash does and does not prove, and anti-forensic ceilings. |

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

1. **Read the methodology phases in order.** Acquisition → Analysis → Timeline → Reporting (phases 01–04) mirrors a real investigation and the order you will practice in. Read 05 and 06 straight after 02, because both are feeders for 03; take 07 after 03; finish with 08, which cross-checks everything you found.
2. **Build the workbench before the first drill.** `labs/lab-environment.md` is the single source of truth for the VMs, snapshots, evidence workspace and acquisition procedure every other lab assumes.
3. **Learn one tool family at a time** using `tools/` (Sleuth Kit & carving first, then Windows artefact parsers, then memory with Volatility, then timelines — memory and timelines both build on file-system habits). `triage-at-scale.md` is the estate-wide counterpart and reads best after the single-host material.
4. **Do every lab drill, basic then case-level.** `labs/forensic-exercises.md` holds the basic drills; the case-level labs are `windows-execution-lab.md`, `memory-injection-lab.md`, `supertimeline-lab.md` and `anti-forensics-lab.md`. Run each at least twice: once following the steps, once from memory against its answer key.
5. **Drill with the cheatsheets** until the commands and the artefact caveats are reflex, then put them away and write them out by hand. Use `windows-artifacts.md` and `evidence-validity.md` before you write any conclusion, not after.
6. **Self-check** with each file's "Checklist / Self-Test" and the module checklist below before moving on.

## Study roadmap

A realistic self-paced plan for someone with basic Linux and command-line comfort (adjust weeks to your schedule):

| Stage | Focus | Output |
| --- | --- | --- |
| Week 1 | Fundamentals + environment | Reading done; the workbench from [lab-environment](labs/lab-environment.md) built — a Linux VM with `sleuthkit`, `volatility3`, and `foremost` installed and verified. |
| Week 2 | Acquisition | A full disk image + hash manifest you created yourself from a scratch drive. |
| Week 3 | Analysis (files) | Deleted file recovered from your own exercise image; file-system walk with `fls`/`fsstat`. |
| Week 4 | Analysis (memory) | A memory sample analyzed end-to-end: processes, network, suspicious process dumped. |
| Week 5 | Timeline | A timeline CSV built from a lab image; incident story summarized in 5 lines. |
| Week 6 | Reporting + review | One complete written report covering a lab scenario; cheatsheet drills from memory. |
| Week 7 | Depth phases + a case-level lab | Phases 05–08 read; one case-level lab — [windows-execution-lab](labs/windows-execution-lab.md), [memory-injection-lab](labs/memory-injection-lab.md), [supertimeline-lab](labs/supertimeline-lab.md) or [anti-forensics-lab](labs/anti-forensics-lab.md) — completed end to end and scored against its sealed answer key. |

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

Digital forensics is the after-the-fact sibling of detection and response: the SOC detects an alert, IR contains the incident, and forensics explains what actually happened so it can be prevented next time. The eCDFP skills here pair naturally with the other Blue Team modules — [eSOC](../eSOC/README.md) (monitoring and triage), [eCIR](../eCIR/README.md) (incident response) and [eCTHP](../eCTHP/README.md) (threat hunting):

- Incident response tells you *what to collect before the box is cleaned*.
- Memory and disk analysis tell you *what the attacker did while it was running*.
- Timeline work tells you *the order of events and the initial access point*.
- Threat hunting turns the artifacts you learn to read here into hypotheses you can test across the whole estate, not just on the one machine you imaged.
- Reporting closes the loop with management, legal, and the next incident's playbook.

## Checklist / Self-Test

Run through this module checklist — each item maps to a concrete artifact you should be able to produce:

- [ ] I can explain the four pillars (acquisition, analysis, timeline, reporting) and why order matters, and say where each of the eight methodology phases sits relative to them.
- [ ] I built the workbench from [lab-environment](labs/lab-environment.md) and can state its snapshot naming, evidence workspace convention and acquisition steps without looking.
- [ ] I created a full disk image of a practice drive and verified it with `sha256sum`/`hashdeep`.
- [ ] I recovered at least one deleted file from an exercise image and explained how I proved it was deleted.
- [ ] I ran a memory-analysis workflow on a public sample: process listing → network → suspicious process dump.
- [ ] I built a timeline body file and converted it to CSV without losing timestamp context.
- [ ] I completed one case-level lab and scored it against its own sealed answer key.
- [ ] For any artefact I cite, I can state both what it proves and what it does not — the discipline of [evidence-validity](cheatsheets/evidence-validity.md).
- [ ] I wrote one complete short report: scope, method, findings, evidence paths, and conclusions.
- [ ] I can reproduce the key commands from the cheatsheets from memory (no notes).

## Further Resources

- NIST SP 800-86 — *Guide to Integrating Forensic Techniques into Incident Response* (csrc.nist.gov/publications).
- Sleuth Kit documentation and wiki — sleuthkit.org (also hosts Autopsy).
- Volatility 3 documentation — volatility3.readthedocs.io.
- Official eCDFP product page (current syllabus, logistics, and FAQ): <https://ine.com/security/certifications/ecdfp-certification>. If it ever 404s, fall back to the certification directory <https://ine.com/certifications>.
- DFRWS digital forensics challenge archives — dfrws.org (authorized practice datasets).
