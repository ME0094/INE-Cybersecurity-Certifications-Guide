# Lab Environment — A Disposable Forensic Workbench

> eCDFP · Labs — INE Cybersecurity Certifications Study Guide
>
> Build the workbench every other lab in this folder assumes: a hypervisor with a disposable Windows victim, a separate Linux analysis VM that holds the toolchain, a fixed snapshot discipline, an evidence workspace convention, and one acquisition procedure you follow the same way every time. Everything here runs on hardware and VMs you own.
>
> Every command in this file is a **syntax reference**. Nothing in this repository was captured on the machine that wrote it: this is a documentation-only repo with no hypervisor, no forensic image, no memory dump and no toolchain installed. Where a command would print something, this file tells you what to look for instead of inventing the output. Confirm every flag against `--help` or the manual page for the version you actually install.

## 1. What this workbench is for

A forensic lab has one non-negotiable property that a general-purpose lab does not: **the machine that produces the evidence must never be the machine that analyses it.** Everything else in this file exists to make that property easy to keep.

The workbench gives you four things:

1. **A victim you are allowed to break.** A Windows VM you can install on, execute in, delete from, tamper with, and revert — with no consequence beyond a snapshot rollback.
2. **A separate, clean analysis host.** A Linux VM with the toolchain, which never runs the activity being investigated, so nothing it does contaminates the evidence.
3. **A repeatable evidence pipeline.** One acquisition procedure, one hashing convention, one log format — applied identically in every lab, so the mechanics never compete with the analysis for your attention.
4. **A reset that takes minutes.** Snapshots named consistently, so "start over" is a decision rather than an investigation.

> This is the companion to the drills, not a substitute for them. `forensic-exercises.md` holds the basic drills; `windows-execution-lab.md`, `memory-injection-lab.md`, `supertimeline-lab.md` and `anti-forensics-lab.md` are the case labs that assume this environment already exists.

## 2. Authorization and safety rules — read before you build anything

These are not formalities. A forensic lab contains deletion, tampering and acquisition tooling, and the failure mode is prosecutable.

- **Only your own equipment, or equipment for which you hold written authorization.** Written means a document naming the scope and the window, signed by someone entitled to give it.
- **The lab network must not route anywhere you do not own.** Use an internal/host-only adapter with no route out. Check the adapter settings every time you start the VMs, not once when you built them.
- **Disable host integration on every VM**: shared folders, shared clipboard, drag-and-drop, shared drives. They are a data-leak path and they destroy the realism of the exercises.
- **Never put real data, real credentials or real personal information in the lab.** Lab-only accounts, lab-only passwords, lab-only documents. Evidence minimization applies to practice too: the habit you build is the habit you keep.
- **Acquire from a powered-off VM, or from a declared live state you have recorded.** Do not image a disk from the guest OS that is using it. The one deliberate exception is memory capture, which is *only* possible live — and which the labs treat as a separate, documented procedure.
- **Never mount an evidence image.** Read it with file-system-aware tools. Mounting, even read-only, changes your own confidence in the evidence and is indefensible if the case ever leaves the lab.
- **Revert, do not repair.** A victim VM that has been tampered with is a used exhibit. Roll back to the snapshot rather than cleaning it up.
- **If internet access is needed** (package installs, tool downloads), enable it deliberately on one VM, record when it was enabled, and disable it afterwards. An always-on NAT adapter in a forensic lab is a mistake waiting to be explained.

> If you cannot state the authorization in one sentence — whose equipment, authorized by whom, for what window — you are not ready to build this environment.

## 3. Virtual machines and topology

Three VMs, one isolated network:

```text
                 ┌────────────────────────────────────────────┐
                 │   vmnet-forensics (host-only / internal)     │
                 │   e.g. 10.20.20.0/24, no default route       │
                 └────────────────────────────────────────────┘
                        │                  │
        ┌───────────────┘                  └───────────────┐
        │                                                  │
┌──────────────────┐                            ┌───────────────────────┐
│     win-lab      │                            │      linux-lab        │
│  Windows 10/11   │   evidence travels as      │  Debian/Ubuntu        │
│  the victim      │ ─────────────────────────► │  the analysis host    │
│  disposable      │   a read-only disk, a raw  │  toolchain + evidence │
│                  │   file, or a memory dump   │  workspace            │
└──────────────────┘                            └───────────────────────┘
        ▲
        │  optional: a Linux victim for
        │  cross-platform artefacts
┌──────────────────┐
│  linux-victim    │
│  Debian/Ubuntu   │
└──────────────────┘
```

| Node | Role | Example address | Notes |
| --- | --- | --- | --- |
| `win-lab` | The victim. Windows 10/11, the account `labuser`, everything the labs plant and then investigate. | `10.20.20.11` | Must be disposable. Never store anything here you would miss. |
| `linux-lab` | The analysis host and examiner workstation. Toolchain, evidence workspace, notes. | `10.20.20.20` | Never the machine that produced the evidence. |
| `linux-victim` | Optional. A second victim for cross-platform artefacts (ext-family file systems, `auth.log`, shell history). | `10.20.20.12` | Add it if a lab needs a non-Windows artefact source. |
| Analysis host adapter | A second, NAT adapter on `linux-lab` only, enabled on purpose when you need packages. | — | Enable, install, disable, record it. |

**Why the split matters.** Everything the victim does is potential evidence. Everything the analysis host does is potential contamination. Keeping them in separate VMs makes the second problem disappear, and it makes the first one visible: when a lab goes wrong, you can still say with confidence which machine introduced the anomaly.

> Do not run the analysis toolchain on the victim "just this once". The single most common unrecoverable lab error is acquiring from, and then analysing on, the same machine — after which no result in the case can be trusted.

## 4. Resource requirements

Budget RAM first: virtualisation memory overcommit is where labs die with mysterious timeouts.

| Component | vCPU | RAM | Disk | Notes |
| --- | --- | --- | --- | --- |
| Hypervisor host (total) | 4–8 | **16 GB minimum**, 32 GB comfortable | 200 GB+ on SSD | SSD matters: imaging and parsing are I/O-heavy |
| `win-lab` | 2 | 4 GB | 60 GB thin | 4 GB is the practical floor for a usable Windows guest |
| `linux-lab` | 2–4 | 4 GB (8 GB for large plaso runs) | 80 GB thin | A plaso storage file over a real image is big; a memory dump is as big as the VM's RAM |
| `linux-victim` (optional) | 1 | 2 GB | 20 GB thin | No desktop environment needed |
| Spare headroom | — | — | 40 GB | For dumps, exports and working copies |

Practical notes:

- **A memory dump is roughly the size of the guest's RAM.** A 4 GB `win-lab` produces a multi-gigabyte artefact; plan the space before you capture, not after.
- **Working copies multiply.** A raw image plus an E01 plus extracted artefacts plus a plaso storage file can be several times the size of the original disk. Thin-provision, but monitor the host.
- **Do not build a deep snapshot chain on a nearly full host disk.** It is the most common cause of a corrupted lab.
- **Pin every VM to UTC** and check it (`timedatectl` on Linux, the time-zone setting on Windows). Timestamps that disagree between nodes break every timeline lab in ways that look like findings.

## 5. Snapshots, naming and the golden baseline

Name snapshots before you need them, so reverting is mechanical:

| Snapshot name | Taken when | Purpose |
| --- | --- | --- |
| `00-clean-install` | Immediately after installing and patching the OS, before any tooling or activity | The only state you can rebuild from scratch |
| `01-tooled` | After installing the lab's tooling on that VM | Saves a reinstall when you break something small |
| `02-baseline` | After a reboot, with nothing running, on a machine you have verified is quiet | The reference point for "what is normal here" |
| `03-<case>-before` | Immediately before you stage the activity for a lab | The state to return to in order to repeat the lab |
| `04-<case>-after` | Immediately after staging the activity and before acquisition | Lets you re-acquire without re-staging |

Rules that keep the chain usable:

- **`03-<case>-before` is not optional.** Repeating a lab from a clean snapshot is how you learn; repeating it from a used one teaches you the wrong thing.
- **Snapshot before installing tooling, not after.** If a tool install goes wrong, you want to be able to undo it without losing the OS.
- **Never snapshot a running victim mid-activity.** A snapshot that includes half of the staged actions is worse than no snapshot, because you will later mistake its state for a clean baseline.
- **Reverting is not analysis.** If you revert before you have acquired the evidence, you have destroyed the exhibit.

## 6. Build order

Build in this order and verify each step. An environment assembled all at once and debugged later produces evidence you cannot trust.

### Step 1 — Hypervisor and isolated network

```text
1. Install the hypervisor (VirtualBox, VMware Workstation/Player, or KVM/libvirt).
2. Create a host-only / internal network: 10.20.20.0/24, no gateway, no default route.
3. Create the VMs with the resources from section 4, with NO network adapter attached yet.
4. Disable shared folders, shared clipboard, drag-and-drop and shared drives on each VM.
5. Confirm from a guest that it cannot reach the internet once attached. Write down what
   you ran and what you saw; this is the first entry in your lab log.
```

### Step 2 — `linux-lab` (the analysis host)

Install the OS, patch it while you still have a NAT adapter or host internet, then attach the isolated adapter and install the toolchain.

```bash
# Update and install the core forensic packages (Debian/Ubuntu names)
sudo apt update
sudo apt install sleuthkit dc3dd foremost scalpel bulk_extractor testdisk hashdeep sqlite3

# EWF/E01 support: the package that provides ewfacquire differs across releases.
# Look it up rather than trusting a package name:
apt-cache search libewf
# Install what provides ewfacquire, then confirm the tools exist:
ewfacquire -h
ewfinfo -h

# Volatility 3 (Python 3)
pipx install volatility3
# Confirm the console command name on your install (it has appeared as both
# 'vol' and 'vol.py'): run --help before scripting anything.
vol --help
```

If your distro's packages are old, note the versions you actually have: an outdated `sleuthkit` may not read a file system your victim uses, and an outdated parser is a silent source of wrong answers.

> Windows-side parsers (Eric Zimmerman's tools, KAPE, the EVTX triage tools, Velociraptor) run on the *analysis* host only if you make it a Windows analysis VM, or on a separate Windows VM. Do not install them on `win-lab`: a victim with forensic tooling on it is a contaminated exhibit. See `../tools/windows-artifact-tools.md` and `../tools/triage-at-scale.md`.

### Step 3 — `win-lab` (the victim)

```text
1. Install Windows 10/11 and patch it fully — this is the one moment you should let it
   reach the internet, before it joins the isolated network.
2. Create the lab-only local account 'labuser' with a lab-only password.
   Give it administrative rights only if the lab you are about to run needs them,
   and revert to a standard account afterwards.
3. Take snapshot '00-clean-install'.
4. Attach the isolated adapter, set a static address, confirm no route out.
5. Take snapshot '01-tooled' once the machine is quiet, and '02-baseline' after a reboot.
```

Decide deliberately whether `win-lab` has Sysmon, process-creation auditing and PowerShell logging installed. Several labs depend on knowing what the event streams would have recorded, and the honest answer "auditing was not enabled, so this artefact does not exist" is itself a lab outcome worth producing at least once.

### Step 4 — `linux-victim` (optional)

Install a minimal Debian/Ubuntu, create a lab account, confirm it boots to a prompt, and snapshot. Nothing about it needs to be interesting: it exists so a lab can show you an artefact class that Windows does not have.

### Step 5 — Verify the toolchain before you trust a result

Prove each tool runs and reports its own version. Record the versions in your lab log — a report that says "used Sleuth Kit" without a version is not reproducible.

```bash
# Every one of these should print a version or a usage summary.
# What to look for: a version string, and no interpreter/loader error.
mmls -V
fls -V
mactime -V
sha256sum --version
foremost -V
bulk_extractor -h | head -n 5
vol --help | head -n 20
```

A tool that fails here will fail mid-case. Fix it now, while nothing is at stake.

## 7. The evidence workspace convention

One directory per case, identical every time. Predictable paths are what stop you from overwriting an exhibit at 2 a.m.

```text
~/lab/<case-id>/
├── evidence/        # acquired images and dumps, and their hashes. Treat as read-only.
├── working/         # verified copies you analyse and can afford to lose
├── exports/         # artefacts extracted from images (hives, $MFT, EVTX, SQLite DBs)
├── dumps/           # process and memory regions dumped during analysis
├── reports/         # timelines, filtered subsets, report drafts
└── notes/
    ├── case-log.md       # chronological notes, written as you work
    ├── acquisition-log.md# one row per acquisition event
    └── answer-key.md     # ground truth for the lab (when the lab has one)
```

Conventions:

- **`evidence/` is write-once.** After acquisition, nothing modifies it. If a tool needs to write, it writes into `working/`.
- **`working/` is disposable and always derived from `evidence/` by a command you wrote down.**
- **`exports/` is derived, not authoritative.** An extracted hive is a copy; the image it came from is the exhibit.
- **Every file that matters has a hash recorded next to it**, or is listed in the hash manifest.

```bash
# Hash everything you acquire, and keep the manifest with the case, not with the file
cd ~/lab/case-01
sha256sum evidence/*.dd evidence/*.E01 > notes/evidence-hashes.txt
# What to look for: one "<hash>  <filename>" line per exhibit, and no error lines
# about unreadable files.
```

## 8. The standard acquisition procedure

Follow the same eight steps every time. The point is not ceremony; it is that a procedure you never improvise is a procedure you can defend.

```text
1. DECIDE.  Which question does this acquisition answer, and is the least invasive method
            that answers it enough? (Logical before full disk; memory only if live state
            is actually in scope.)
2. RECORD.  Case id, exhibit number, examiner, date/time in UTC, and the state of the
            machine (powered on or off, what was running, whether it is encrypted).
3. FREEZE.  Shut the VM down cleanly, or snapshot it. Note in the log that you did.
            For a live memory capture, this step is replaced by: capture memory FIRST,
            then decide about the disk.
4. EXPOSE.  Attach the victim's disk to linux-lab read-only (USB/disk passthrough of a
            powered-off VM, or the VM's disk file opened as a raw source), or copy the
            disk file into evidence/ if your hypervisor stores it as a plain file.
            Confirm the source is not mounted and not writable.
5. HASH.    Hash the SOURCE before you read anything else from it.
6. IMAGE.   Raw image with dd/dc3dd, and/or E01 with ewfacquire. Record the tool and
            version. Never image a mounted file system.
7. VERIFY.  Hash the IMAGE and compare. Where the format supports it, verify the
            container's own integrity check as well (ewfverify for EWF). A mismatch
            means you stop and re-acquire; it is never "close enough".
8. LOG.     Write the acquisition row (section 9) and seal evidence/: nothing writes to
            it again. Analyse from a copy in working/.
```

```bash
# Step 5-7 in commands, against a raw disk file the hypervisor stores on the host.
# Replace DEVSRC with your actual source device; verify it twice before running dd.
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT
# What to look for: the evidence disk, and the fact that it is NOT your system disk
# and NOT mounted.

# 5. Hash the source
sha256sum /dev/sdb | tee ~/lab/case-01/notes/source-hash.txt

# 6. Image it, tolerating read errors
sudo dd if=/dev/sdb of=~/lab/case-01/evidence/disk.dd bs=4M conv=noerror,sync status=progress

# 7. Hash the image and compare with the source hash, character by character
sha256sum ~/lab/case-01/evidence/disk.dd
```

```bash
# The E01 alternative: a container with its own integrity metadata
sudo ewfacquire /dev/sdb \
  -t ~/lab/case-01/evidence/disk.E01 \
  -u "case-01-exhibit-1" \
  -e "Case 01, Exhibit 1: win-lab system disk" \
  -m fixed
# What to look for: a completed acquisition summary and no read-error count you
# cannot explain. Confirm the switch set with ewfacquire -h on your build.

# Verify the container afterwards
ewfverify ~/lab/case-01/evidence/disk.E01
```

> **Never image a device you have not positively identified.** `dd` writes wherever it is told. The single command that destroys a case is a correct `dd` aimed at the wrong device node.

## 9. Chain of custody and the case log

Two records, both written **as the work happens**, never reconstructed afterwards.

**Acquisition log** — one row per acquisition event:

| Date/time (UTC) | Exhibit | Action | Source | Destination | Tool + version | Hash (SHA-256) | Examiner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-01-14 09:12 | CASE-01-E01 | Disk imaged | `/dev/sdb` (win-lab disk) | `evidence/disk.dd` | `dd` (coreutils 9.x) | *(record the value you actually got)* | labuser |
| 2026-01-14 09:31 | CASE-01-E01 | Image verified | `evidence/disk.dd` | — | `sha256sum` | *(must equal the source hash)* | labuser |
| 2026-01-14 10:02 | CASE-01-E01 | Working copy created | `evidence/disk.dd` | `working/disk.dd` | `cp` | *(record it)* | labuser |

**Case log** — free-form, chronological, and honest about interruptions:

```text
2026-01-14 09:05 UTC — Reverted win-lab to '03-case01-before'.
2026-01-14 09:08 UTC — Staged activity per the lab script; answer key completed
                     at 09:41 (times recorded from the guest's clock, which reads UTC).
2026-01-14 09:45 UTC — Snapshot '04-case01-after' taken; VM powered off.
2026-01-14 09:50 UTC — Note: forgot to disable the NAT adapter before staging. The guest
                     had no route out (verified), so no external traffic is possible,
                     but this deviates from the procedure and is recorded here.
```

That last line is the kind of entry that makes a report credible. Undocumented deviations are what destroy it.

## 10. Reset and rebuild

When a lab has gone wrong — a tool wrote to the image, the victim got contaminated, an acquisition is unverifiable — reset instead of debugging.

```text
1. Confirm you no longer need anything in ~/lab/<case-id>/working, exports, dumps, reports.
2. If you have NOT yet acquired, revert the victim to '03-<case>-before' and re-stage.
3. If you HAVE acquired but the acquisition is suspect, keep the suspect image in a
   folder named clearly as such (e.g. evidence-suspect-do-not-cite/), revert the VM,
   re-stage, and re-acquire. Never quietly replace an image.
4. Reboot linux-lab and confirm it has no leftover mounts of evidence files
   (mount | grep -i lab, and check for loop devices).
5. Re-verify the toolchain (section 6, step 5) if anything behaved strangely.
6. Write the reset in the case log, with the reason.
```

```bash
# Confirm nothing from evidence/ is mounted and no stale loop devices remain
mount | grep -i "$HOME/lab"
losetup -a
# What to look for: no output, or only devices you can account for.
```

## 11. Common Mistakes & Tips

- **Analysing on the victim.** The one error that invalidates the whole case. Keep `linux-lab` clean.
- **Acquiring a mounted or running file system.** Journal replay and ordinary writes change the image mid-copy. Freeze first, then read.
- **Skipping the source hash.** Without a pre-image hash of the source you cannot demonstrate that the image matches the media, and a later mismatch becomes unexplainable.
- **Imaging the wrong device.** Identify the source with `lsblk` and confirm it is not your system disk and not mounted. Do it twice.
- **Writing to `evidence/`.** Every tool that needs to write goes to `working/`. Discover an accidental write in the hash manifest, not in court.
- **Trusting a version-less toolchain.** Record versions; a report without them cannot be reproduced.
- **Disabling the isolated adapter "for a moment".** Enable, use, disable, and log it — every time.
- **Ignoring the guest clock.** Record the victim's time zone and any offset at acquisition. Every timeline lab depends on it.
- **Tip:** write the acquisition log row before you start the copy, not after you finish it. The timestamp you reconstruct from memory is the one that turns out to be wrong.
- **Tip:** keep an `answer-key.md` for every case lab. Scoring yourself against ground truth is the only way to know whether a null result means "nothing there" or "I did not look properly".

## Checklist / Self-Test

- [ ] I can state, in one sentence, the authorization covering my lab hardware, VMs and network.
- [ ] My VMs run on a host-only network with no route out, and I verified it from a guest rather than assuming it.
- [ ] Host integration (shared folders, clipboard, drag-and-drop) is disabled on every VM.
- [ ] I understand why the analysis host must never be the machine that produced the evidence, and my setup keeps them separate.
- [ ] I created snapshots named `00-clean-install`, `01-tooled`, `02-baseline`, `03-<case>-before` and `04-<case>-after`, and I know what each is for.
- [ ] Every VM is pinned to UTC and I recorded the victim's time zone.
- [ ] My toolchain is installed, each tool prints a version, and I wrote those versions into my lab log.
- [ ] I created the `~/lab/<case-id>/` workspace with `evidence/`, `working/`, `exports/`, `dumps/`, `reports/` and `notes/`.
- [ ] I have acquired at least one image following all eight steps, and the source hash equals the image hash.
- [ ] I have an acquisition log with a row per event, and a case log that records deviations honestly.
- [ ] I know how to reset the lab, and I have done it at least once without losing anything I needed.
- [ ] No evidence file has ever been mounted, and `mount`/`losetup` show nothing stale.

## Further Resources

- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **ISO/IEC 27037**, *Guidelines for identification, collection, acquisition and preservation of digital evidence* — https://www.iso.org/standard/44381.html
- **RFC 3227**, *Guidelines for Evidence Collection and Archiving* (order of volatility) — https://www.rfc-editor.org/rfc/rfc3227
- **The Sleuth Kit** (partition and file-system tools used throughout the analysis labs) — https://www.sleuthkit.org/sleuthkit/
- **Volatility 3 documentation** (installation, symbols, plugin reference) — https://volatility3.readthedocs.io/
- **libewf** (EWF/E01 container tools, including `ewfacquire` and `ewfverify`) — https://github.com/libyal/libewf
- **DFRWS forensics challenge archives** (authorized practice datasets) — https://dfrws.org/
