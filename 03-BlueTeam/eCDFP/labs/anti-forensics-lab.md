# Anti-Forensics Lab — Tampering You Can Detect

> eCDFP · Labs — INE Cybersecurity Certifications Study Guide
>
> A reproducible lab in which you perform anti-forensic actions **inside your own disposable VM**, then detect them from the acquired evidence. Every command below is a syntax reference, not a transcript: this repository ships no captured command output, no hashes, no timestamps and no event IDs taken from any real system. Everything runs on VMs you own, on a host-only network, scoped to a lab volume you are willing to destroy and rebuild.

## 1. Objective

This lab inverts the usual exercise: you do the tampering yourself, then prove it from the image against an answer key written and sealed **before** anything was acquired. A detection written after reading the key proves nothing.

By the end you should be able to:

1. Tell a **timestomp** — one file whose two timestamp sets disagree — from a legitimate change such as a copy, a restore or an installer.
2. Read a **gap in an artefact's coverage** (a journal that does not span the window, a channel whose oldest retained record is younger than its neighbours) as a claim to test, not a conclusion to publish, and tell **absence of an artefact** apart from **absence of the activity**: prefetch has no entry — did the program not run, or was the entry deleted?
3. State which artefacts survive each technique and which technique destroys which artefact, in a table you can defend.

The analytical method for this subject is [08-anti-forensics-and-evidence-integrity.md](../methodology/08-anti-forensics-and-evidence-integrity.md); read that for the reasoning, run this for the reflexes.

## 2. Prerequisites

Read [lab-environment.md](lab-environment.md) first: it is the single source of truth for the VM inventory, snapshot naming, evidence workspace layout and acquisition flow. Nothing here restates it, so do not improvise a variant.

| What you need | Where it comes from |
| --- | --- |
| The shared contract: `win-lab` (Windows victim), `linux-lab` (analysis VM / examiner workstation), host-only network, `labuser`, a lab-only password, and snapshots `03-anti-forensics-before` / `04-anti-forensics-after` | [lab-environment.md](lab-environment.md) |
| Parsers: MFT and USN journal, `$LogFile`, prefetch, Amcache/ShimCache/UserAssist/SRUM, evtx, registry, Recycle Bin | [windows-artifact-tools.md](../tools/windows-artifact-tools.md) |
| Which artefact answers which question, and where each one lives | [windows-artifacts.md](../cheatsheets/windows-artifacts.md) |
| Image-handling drills, if `mmls` / `fls` / `icat` are not yet reflex | [forensic-exercises.md](forensic-exercises.md) |
| The artefact-driven analysis order section 6 follows | [02-analysis.md](../methodology/02-analysis.md) |

- **Elevation is a per-step decision, not a mode,** and the parsers never go on `win-lab`: section 4 marks the steps needing an elevated shell, everything else runs as `labuser`, and a victim used as an analysis machine is no longer a clean victim.

## 3. Ethics, authorization and blast radius — read before doing anything

The techniques in section 4 are indistinguishable from attacker behaviour to anything that can see the VM. Any EDR agent, network sensor or backup job observing this activity will treat it as an intrusion, and there is no cover story if it is watching a machine you do not own.

- **Only your own disposable VM, on a host-only network.** No host integration: no shared folders, clipboard, drag-and-drop or bridged adapter. Verify before the session, the way `hunting-range-setup.md` verifies isolation.
- **Snapshot first, and revert between attempts.** `03-anti-forensics-before` must exist and be clean before the first technique; a contaminated baseline makes the next attempt unscoreable.
- **Never run any of this outside the lab.** Not a work machine, a client system, or a cloud instance you happen to hold credentials for: "it was only a timestamp" is not a defence, because you are destroying another party's records. Every path in section 4 is a lab path, and the one volume-wide operation is called out explicitly — if you would not be comfortable reformatting that volume, do not run it there.
- **The defender's justification for doing this at all:** you cannot recognise tampering you have never produced. An analyst who has never deleted a prefetch file — and never watched the deletion leave a trace — will read "no prefetch entry" as "the program never ran" and write it into a report.
- **Evidence ethics still apply, even when the evidence is yours.** Authorization is trivial here; the rest is not optional practice: hash the source, hash the image, log every artefact you handle, work on copies, minimise what you copy out.

> One sentence, every session: this is my disposable VM, on my hardware, on an isolated network, holding nothing I need. If any part of that is false, stop.

## 4. Build the scenario

All of this happens on `win-lab`, in the order given, with the answer key written as you go. Nothing is imaged until section 4 is complete: each step obscures or destroys the trace of an earlier one, so the order changes what you can detect.

### The answer key — written first, sealed second

Keep it in `~/lab/<case-id>/notes/` on `linux-lab`, or on paper — anywhere that is not the image. The angle brackets are placeholders, not examples.

```text
Case: <case-id>   Examiner: <name>   Snapshot before: 03-anti-forensics-before
VM clock offset vs host clock at start: <measure it; do not assume UTC>
Step | UTC start | UTC end | Exact command or GUI action
-----+-----------+---------+--------------------------------------------------
4a   |           |         | new folder + N files; true hashes recorded below
4b   |           |         | timestomp on <which files>; values set: <value>
4c   |           |         | <file> deleted in Explorer; <file> deleted with Remove-Item
4d   |           |         | wevtutil cl <channel>   (channel config before/after: <verbatim>)
4e   |           |         | Remove-Item C:\Windows\Prefetch\<exact .pf name>
4f   |           |         | fsutil usn deletejournal /d C:   (journal before/after: <verbatim>)
True hashes at 4a, before anything changed:   <filename>  <sha256 you computed>
Before/after, verbatim:  fsutil usn queryjournal C: <> / <>   ·   wevtutil gl <channel> <> / <>   ·   Prefetch listing <> / <>
Snapshot after: 04-anti-forensics-after
```

Record **UTC** and say how you established it — a key in local time with an unrecorded offset is worthless for section 6. Then seal it: write your analysis before you reopen the key.

### 4a — Create the working folder and record ground truth

No elevation. Use a disposable folder on the lab volume, not the profile or the system drive root; before touching anything, record the before-state of the two volume-wide artefacts in your key with `fsutil usn queryjournal C:` and a `dir /a C:\Windows\Prefetch\*.pf`.

```powershell
$lab = 'C:\lab-anti\case-files'
New-Item -ItemType Directory -Path $lab -Force | Out-Null
1..5 | ForEach-Object { Set-Content -LiteralPath (Join-Path $lab ("note{0}.txt" -f $_)) -Value "lab file $_" }
# what to look for: the TRUE creation/modification/access times and hashes — copy them into the
# answer key now, because you cannot reconstruct them later with certainty.
Get-ChildItem -LiteralPath $lab -File | Select-Object Name, Length, CreationTimeUtc, LastWriteTimeUtc, LastAccessTimeUtc
Get-FileHash -Algorithm SHA256 -Path (Join-Path $lab '*.txt')
```

### 4b — Timestomp a subset

Change the timestamps on **some** files, not all: the untouched files are your control group, showing what an honest record looks like on this build, which is the only way to judge the changed ones.

```powershell
# No elevation needed for files you own. Timestomp two of the five.
Get-ChildItem -LiteralPath 'C:\lab-anti\case-files' -File | Select-Object -First 2 | ForEach-Object {
  $item = Get-Item -LiteralPath $_.FullName
  $item.CreationTimeUtc  = (Get-Date).AddYears(-3)
  $item.LastWriteTimeUtc = (Get-Date).AddYears(-3)
  Get-Item -LiteralPath $_.FullName | Select-Object Name, CreationTimeUtc, LastWriteTimeUtc   # what to look for: did the value take effect?
}
# Alternative provider-based form — confirm it behaves on your build, and note which you used:
# Set-ItemProperty -LiteralPath 'C:\lab-anti\case-files\note1.txt' -Name LastWriteTime -Value (Get-Date).AddYears(-3)
```

The mechanism you are exposing: the timestamp-setting API writes `$STANDARD_INFORMATION` in the MFT record while `$FILE_NAME` usually keeps the values it was created with. Some operations *do* refresh `$FILE_NAME` — a rename within the same volume is the classic case — so the detection is the **comparison**, not an assumption about which set should be older. `$STANDARD_INFORMATION` also carries an **entry-modification** timestamp the API does not let you set; it moves whenever the record is modified at all, which is exactly what a timestomp does.

### 4c — Delete a subset, two different ways

```powershell
# Route 1 — a scripted delete. Remove-Item deletes the file; it does NOT use the Recycle Bin.
Remove-Item -LiteralPath 'C:\lab-anti\case-files\note5.txt'
```

```text
Route 2 — by hand: open the folder in File Explorer and delete note4.txt with an ordinary
Delete (not Shift+Delete), so the Recycle Bin is used. What this buys you: one missing file
with an $I/$R metadata pair, one with none — section 6 asks you to explain the difference
from the evidence alone.
```

Leave the folder itself in place: deleting the whole folder is what an anti-forensic operator often does, and it is exactly what makes the surviving context unreadable. Run that variant once, on a copy, to feel the difference.

### 4d — Clear one event log channel

Elevation required.

```cmd
wevtutil el                      :: pick a channel you have actually written events to
wevtutil gl <channel>            :: what to look for: size, retention and enabled state BEFORE the clear
wevtutil cl <channel>            :: the technique — note the exact channel name in the key
wevtutil gl <channel>            :: what to look for: same configuration, contents gone — compare its
                                 :: oldest retained record with the channels you did not touch
```

Windows records the clear, in a channel that is usually *not* the one you cleared: confirm the identifier on your build with `wevtutil /?` and by inspecting the channels afterwards, and do not trust an ID from a blog, including this one. The cleared channel's **oldest retained record becomes much younger** than the equivalent record in untouched channels. And if the channel was forwarded to a collector, the records you destroyed locally still exist remotely — configure one channel to forward in your range, then clear it, and that experiment changes how you think about log-tampering detection permanently.

### 4e — Delete the prefetch entries for a program you ran

Elevation required.

```powershell
# Run the program several times first, so the artefact is meaningful (run count, last-run time).
Start-Process notepad.exe ; Start-Sleep -Seconds 3 ; Start-Process notepad.exe
# what to look for: the exact .pf filename — it embeds a hash derived from the executable path,
# so it is not simply NOTEPAD.EXE.pf. Copy the real name into the answer key.
Get-ChildItem -LiteralPath 'C:\Windows\Prefetch' -Filter '*.pf' | Select-Object Name, LastWriteTimeUtc
Remove-Item -LiteralPath 'C:\Windows\Prefetch\<exact-name-you-recorded>.pf'
# what to look for: the deletion is itself a file-system event, and the execution is still
# recorded by artefacts you have not touched (section 6, step 5).
```

Prefetch may be disabled on your build — SSD-only policy, a server SKU, a hardening baseline — so confirm entries are being produced *before* deleting one: deleting an artefact that was never written yields a false negative you will later misread as a clean result.

### 4f — Optionally remove the USN change journal

Elevation required, and this affects **the whole volume**, not the folder you have been working in: it destroys the change history of every file on that disk. Run it only on the disposable lab volume, only after recording the before-values in your key.

```cmd
fsutil usn /?                    :: confirm the subcommands on your build; do not trust this file for the switch
fsutil usn queryjournal C:       :: what to look for: identifier and first/next USN BEFORE deletion
fsutil usn deletejournal /d C:   :: the technique — whole volume, needs elevation
fsutil usn queryjournal C:       :: what to look for: absent, or recreated with a different identifier
                                 :: or a first USN that no longer reaches back to your snapshot?
```

Reading the journal back afterwards is optional (the read form is slow; redirect it to a file). The finding is not in the journal's contents but in its **coverage** — whether it still spans the window in which you tampered.

### 4g — A Linux variant, for contrast

Only if your range includes a disposable **Linux victim**; `linux-lab` is your examiner workstation under the shared contract, and the machine that generated evidence must never be the one that analyses it, so build a separate throwaway VM or skip this step.

```bash
mkdir -p ~/lab-anti/linux-case && cd ~/lab-anti/linux-case
for i in 1 2 3 4 5; do echo "lab file $i" > "note$i.txt"; done
stat -c '%n birth=%w modify=%y change=%z' note*.txt        # what to look for: the TRUE values, first
sha256sum note*.txt | tee ~/lab/<case-id>/notes/linux-hashes.txt
touch -d '2019-01-01 00:00:00 UTC' note1.txt               # forged mtime/atime
touch -t 201901010000 note2.txt                            # the same, as [[CC]YY]MMDDhhmm[.ss]
stat -c '%n birth=%w modify=%y change=%z' note*.txt        # what to look for: what moved, and what refused to
sudo truncate -s 0 /var/log/<your-lab-log>                 # the log half: truncate, do not delete
# what to look for: metadata consistent with truncation rather than rotation — and, if the log was
# forwarded, the local truncation destroyed nothing that matters. That is the finding.
```

The contrast with NTFS is the lesson: `touch` rewrites the modification time, and the **inode change time** records that metadata change, so it moves too. A modification time older than the change time of the same inode is the tell — the same shape of finding as `$STANDARD_INFORMATION` versus `$FILE_NAME`, arrived at from a different filesystem. Birth time is not settable through `touch` at all.

## 5. Freeze and acquire

1. **Finish the answer key first, then stop touching `win-lab`.** Section 4 is not complete until every line holds real UTC values, exact commands, the true hashes from 4a and the verbatim before/after state — and no tidying up, no "one more check" afterwards: every extra command writes to the volume you are about to image and adds events to the window you are trying to characterise.
3. **Take snapshot `04-anti-forensics-after`.** It is not evidence — it is what lets you re-run the same analysis against the same state, which is why a destructive acquisition costs you nothing here.
4. **Then follow the acquisition flow in [lab-environment.md](lab-environment.md):** power the victim off, attach its disk read-only or as a raw file, hash the source, image with `dd` / `dc3dd` and/or `ewfacquire`, re-hash, and write the acquisition log line (UTC, examiner, tool and version, source, destination, hashes). Do not improvise a variant here.
5. **Never mount the image, and analyse on `linux-lab`** — never on the machine that generated the evidence, which here would corrupt the volume-wide coverage questions in steps 3 and 6 of section 6. Work on a verified copy in `~/lab/<case-id>/working/` with the sealed master and its hash untouched beside it, and note in the case file that the answer key exists and is unopened.

Acquiring before the key is finished does not produce a scored exercise; it produces a story about what you think you did.

## 6. Analysis — what to look for, in this order

Cheap and broad first (what exists, what changed) and expensive and narrow last — and the *coverage* questions before the *content* questions, because a finding about content is worthless if you have not established that the artefact was collecting. Exact parser invocations are in [windows-artifact-tools.md](../tools/windows-artifact-tools.md); run each tool with no arguments (or `--help`, `Get-Help`, `fsutil usn /?`) to confirm usage on the version you installed.

**Step 1 — Establish the window and the baseline.**

```bash
mmls ~/lab/<case-id>/working/copy.dd      # what to look for: the partition offset every later command needs
fls -o <offset> -r -p -m /case ~/lab/<case-id>/working/copy.dd > ~/lab/<case-id>/working/body.txt
mactime -b ~/lab/<case-id>/working/body.txt -d -z UTC > ~/lab/<case-id>/exports/timeline.csv
```

Note the limitation now: a body file built by `fls` carries the timestamps the metadata exposes, which on NTFS is the `$STANDARD_INFORMATION` set, so it cannot show the disagreement step 2 looks for.

**Step 2 — `$STANDARD_INFORMATION` versus `$FILE_NAME`, same record.**

```bash
# Parse $MFT with a parser reporting BOTH sets (MFTECmd on a Windows analysis box, or a Python
# MFT parser on linux-lab).
# what to look for, per record: $SI creation/modification against $FN creation/modification for
# the SAME file; a $SI creation time predating the volume's creation or the OS install; and a
# $SI entry-modification time inside your window while creation/modification claim years earlier
# — the record was modified after the time it now asserts.

istat -o <offset> ~/lab/<case-id>/working/copy.dd <inode>
# what to look for: allocation and the standard times (istat does not show the $FILE_NAME set)
```

At this point you have one lead, not a finding: a copy, a restore or an installer can look similar, and step 3 is what turns it into a finding.

**Step 3 — The USN change journal: coverage, gaps, resets.**

```bash
# The journal lives in $Extend\$J: locate it, icat it out by meta address, then parse it.
fls -o <offset> -r ~/lab/<case-id>/working/copy.dd | grep -i '\$Extend'
icat -o <offset> ~/lab/<case-id>/working/copy.dd <journal-meta-address> > ~/lab/<case-id>/working/J.bin
# what to look for: the earliest record's timestamp (does the journal reach back BEFORE your snapshot?), delete and basic-information-change records for the files you touched, the absence of those records when 4a-4c prove the operations happened, and a first USN that no longer starts where the journal started.
```

Keep two sentences separate: a journal that *contains* the tampering (delete records, records of the metadata change) is evidence **of** the activity; a journal whose coverage *starts after* it is evidence for a different proposition — that something removed the journal. Compare your findings against the live values you recorded in 4a and 4f (`fsutil usn queryjournal C:` on the VM, never on the image) to see whether the identifier changed, the first USN jumped forward, or the journal is gone.

**Step 4 — `$LogFile` records for the window.** Parse `$LogFile` with a log-aware parser. **What to look for:** transaction records inside your window (file creation, deletion, metadata updates), and whether the log covers the window at all. `$LogFile` is a ring buffer that can roll over in hours on a busy volume, so "does not reach back far enough" may be a limitation of the artefact rather than tampering — say which one you are looking at.

**Step 5 — Prefetch absence against other execution evidence.** Establish the execution from artefacts the tampering did not touch, then compare.

```text
1. Prefetch from the image (PECmd against the extracted Prefetch folder): is there an entry for the
   program you ran in 4e? Check .pf files were being produced at all — see the note in section 4e.
2. Amcache     C:\Windows\AppCompat\Programs\Amcache.hve                        (AmcacheParser)
3. ShimCache   SYSTEM hive, ControlSet001\Control\Session Manager\AppCompatCache
                                                                     (AppCompatCacheParser)
4. UserAssist  NTUSER.DAT, ...\Explorer\UserAssist\{<GUID>}\Count        (RECmd / RegRipper)
5. SRUM        C:\Windows\System32\sru\SRUDB.dat                                 (SRUM parser)
   what to look for: two or more of 2-5 recording the same executable in the same window with NO
   prefetch entry for it — the signature of prefetch DELETION. A program that never ran leaves
   nothing in any of them.
```

```bash
sudo ausearch -k exec -ts recent -i    # Linux side, if you built that victim
# what to look for: exec records for the binary — present locally, or only in the forwarded copy
# on the collector after your truncation.
```

**Step 6 — The event-log gap and the clearing record.** Parse the `.evtx` files with your evtx parser (or Chainsaw / EvtxECmd). **What to look for**, per channel: the oldest retained record's timestamp compared *across* channels; a clearing record and *which* channel it landed in (typically not the cleared one); a discontinuity or jump in record identifiers; and the channel's size and retention against the verbatim values from 4d. Confirm the clearing record's identifier on your own build before citing it — it is version-dependent, and an ID copied from a study guide is the kind of claim that collapses in review. The durable, ID-independent observation is the comparison between channels: PowerShell Operational, System, the Sysmon channel and your cleared channel each have an oldest retained record, and they should roughly agree. The one that does not is your finding.

**Step 7 — Registry last-write times that contradict file times.** With RegRipper or RECmd on copies of the hives, **what to look for** is a key whose last-write time falls inside your window and whose values name a file whose `$SI` timestamps now claim years earlier. Useful keys: Amcache, UserAssist, RecentDocs, Shellbags (USRCLASS.DAT), BAM — remembering that a key's last-write time covers the whole key and cannot be attributed to one value.

**Step 8 — Recycle Bin `$I`/`$R` pairs versus the files actually missing.**

```bash
fls -o <offset> -r ~/lab/<case-id>/working/copy.dd | grep -i '\$Recycle.Bin'
# what to look for: $I records naming original paths and deletion times — and, more interesting,
# which deleted files have NO $I/$R pair. Compare that set against the files actually missing.
```

Deletions through the shell produce a pair; deletions by an API call or a script (4c route 1) do not, so the Recycle Bin is a **behavioural** artefact: it can tell you not just that a file disappeared but roughly how. A missing pair is never proof of tampering on its own — Shift+Delete, a same-volume move and a delete from a removable volume produce the same picture.

**Step 9 — The residual MFT record of a deleted file.**

```bash
fls -o <offset> -r -d ~/lab/<case-id>/working/copy.dd    # deleted entries ('*' = deleted)
istat -o <offset> ~/lab/<case-id>/working/copy.dd <inode>
icat -o <offset> ~/lab/<case-id>/working/copy.dd <inode> > ~/lab/<case-id>/exports/recovered.bin
sha256sum ~/lab/<case-id>/exports/recovered.bin
# what to look for: a hash matching the answer key (clean recovery of data the operator believed
# was gone), a partial or non-matching result (clusters reused), or resident data still inside the
# MFT record itself.
```

**Only now open the sealed answer key**, compare line by line, and score yourself the way `hunting-exercises.md` scores a hunt: found, missed, and what you concluded that the data could not support.

## 7. What you should observe

Described as behaviour and signatures, never as invented output. Depending on your build, your timing and how busy the volume was, you may observe some, all or none of these — a documented negative result against a verified acquisition is valid, and worth more than a fabricated one.

- **A file whose two timestamp sets disagree.** The same MFT record reports one creation/modification time in `$STANDARD_INFORMATION` and another in `$FILE_NAME`, while the untouched control files in the folder do not — strongest when a `$SI` entry-modification time sits inside your window while `$SI` creation claims years earlier, or when a `$SI` timestamp is older than the volume's own creation and the OS install.
- **A deletion window the journal cannot account for** — either the journal contains the operations, or its coverage begins after them. The second case is a finding about the journal, not about the files; write it that way.
- **An execution several artefacts corroborate and prefetch does not:** two or more of Amcache, ShimCache, UserAssist and SRUM recording the executable inside the window with no prefetch entry — after ruling out the counter-example that prefetch was never being written on this build.
- **A channel whose oldest retained record is younger than the others**, with a clearing record in a channel other than the one cleared — and, if you configured forwarding, the destroyed records still present on the collector.
- **Registry last-write times that contradict file times**, and **one deleted file with an `$I`/`$R` pair next to one without**, explained by *how* each was deleted rather than a guess about intent.
- **A residual MFT record whose data is still recoverable**, hashing to the value recorded before the deletion: the operator removed the reference, not the data. **On Linux, a modification time older than the inode change time** is the same class of finding — the forged time is visible precisely because `touch` had to change metadata to forge it.

## 8. What survives, and what destroys it

| Technique | What it leaves behind | What would remove that trace | Confidence |
| --- | --- | --- | --- |
| Timestomp via property assignment | `$SI` changed, `$FILE_NAME` typically unchanged; `$SI` entry-modification time inside the window; a basic-information-change record in the USN journal; registry residue (Amcache/UserAssist) still in the true window | Editing `$FILE_NAME` directly with a raw MFT editor (volume offline), which itself alters the record and the transaction log | High when the two sets disagree and the control files agree; medium on a difference alone |
| Delete a subset of files, or a whole folder | MFT record marked unallocated, USN delete records, data intact in unallocated clusters until reused, `$I`/`$R` pair only if deleted through the shell — and, for the whole folder, the surviving context that made those traces readable is gone | Overwriting free space, or enough activity to reuse the clusters; nothing brings the destroyed context back | High for the deletion; lower for the content; low on intent without context |
| Clear an event channel (`wevtutil cl`) | Configuration retained, contents gone, clearing record in another channel, oldest retained record much younger than neighbours, a gap against any forwarded copy | Clearing the recording channel too (which records its own clearing), or never enabling the auditing that writes it | High that a clear occurred; low to nil about what was in it, unless it was forwarded |
| Delete prefetch entries | The deletion is itself a file-system event; the execution remains in Amcache, ShimCache, UserAssist, SRUM and BAM | Deleting those too — more work, more traces, and registry keys whose last-write times move into the window | High that the artefact was removed; medium on what ran until two other artefacts agree |
| Remove the USN journal (`fsutil usn deletejournal`) | Journal absent or recreated with a different identifier and a first USN inside your window; volume-wide loss of change history; the utility's own execution may be recorded elsewhere | Nothing practical — Windows regenerates the journal, and the missing coverage is itself the finding | High that the journal does not cover the window; the technique is inferred from context |
| Truncate a log, or forge times with `touch` (Linux) | Truncation metadata rather than rotation metadata, with early records gone; or a modification time moved while the inode change time moved with it and the birth time did not | Truncating the collector's forwarded copy too — a second system, with its own access records; or direct inode editing on an offline volume | High if a forwarded copy exists, or — for `touch` — always, since the change time is not forgeable from userspace |

## 9. The corroboration rule

**A single mismatched timestamp is a lead, not a conclusion.** Copying a file, restoring from backup, extracting an archive or installing software can each produce a difference between the two timestamp sets. Tampering is *proven* only when **independent artefacts agree**: the MFT record's disagreement, plus a USN record showing the metadata change inside the window, plus a registry key whose last-write time contradicts the file it describes. Two independent artefacts is the threshold; three is a finding you can defend.

1. **Two views of one source are one artefact.** The `fls` body file and the `mactime` CSV are the same data twice, and the Explorer-visible timestamps and `$STANDARD_INFORMATION` are the same attribute: their agreement proves nothing.
2. **An absence is evidence only if you can show the artefact was collecting.** "No prefetch entry" means "prefetch was not being written" until you prove otherwise — likewise a journal that does not reach back far enough, and a channel whose records start late because of its size and retention rather than a clear.
3. **The lab is not complete until you have two independent artefacts for at least one technique**, plus a written statement of which techniques you could only establish to the single-artefact level, and why.

## Common Mistakes & Tips

- **Running the tampering outside the lab.** The failure mode is not a bad result, it is a destroyed audit trail on somebody else's system — snapshot first, isolate first, and re-read section 3 if you are tempted to "just test it quickly".
- **Writing or amending the answer key after the acquisition.** That converts a scored exercise into a narrative: write it as you go, seal it, open it only after section 6.
- **Timestomping every file, and forgetting that the timestomp is itself recorded.** Without untouched control files you cannot tell an anomaly from normal behaviour on that build — and the USN journal sees the metadata change while `$SI`'s entry-modification time moves, so both are leads: use them.
- **Deleting the whole folder for speed, or clearing a channel you never wrote to.** The first destroys the context that makes the surviving artefacts readable (delete a subset, two ways, and explain the difference); the second leaves no coverage difference to measure (generate events first, and record the configuration before and after).
- **Assuming prefetch exists.** Check `.pf` files are being produced before deleting one; on a build where prefetch is off, the absence you "find" is your own configuration.
- **Treating one timestamp as proof, or analysing on the machine that generated the evidence.** A difference is a lead and two agreeing independent artefacts are a finding; and this is the lab where breaking the shared rule silently corrupts your own coverage questions.
- **Mounting the image "just to check".** It writes: work through parsers on the verified copy, keep the master sealed, and re-hash the copy when you finish.
- **Recording times without a timezone,** or running the volume-wide operation on a volume you care about. Pin everything to UTC, record the offset you measured, and remember `fsutil usn deletejournal` affects the whole disk permanently.
- **Tip:** do the cheapest coverage checks first and the content questions last — a beautifully recovered file proves nothing if the artefact that should have recorded its creation was never collecting — and keep a per-artefact log line (tool, version, command, input, output path, hash) for every parser you run, because a reviewer will want to reproduce you.

## Checklist / Self-Test

- [ ] I can state, in one sentence, that everything here ran on a VM I own, on an isolated network, snapshotted first.
- [ ] I wrote an answer key with UTC times, exact commands, true hashes and verbatim before/after artefact state, and sealed it before acquiring.
- [ ] I kept untouched control files alongside the timestomped ones, and compared `$STANDARD_INFORMATION` with `$FILE_NAME` for the same record, including the `$SI` entry-modification time.
- [ ] I deleted one file through the shell and one through a script, and can explain the difference in their traces.
- [ ] I recorded the event channel's configuration before and after clearing it, and identified a clearing record with its ID confirmed on my own build.
- [ ] Before `fsutil usn deletejournal` I recorded the journal's identifier and first/next USN, and I assessed the journal's *coverage* separately from its contents; I also know the operation is elevated and volume-wide.
- [ ] I acquired following [lab-environment.md](lab-environment.md), hashed source and image, logged the acquisition, and analysed a verified copy without mounting it.
- [ ] I corroborated (or excluded) one execution across at least two artefacts other than prefetch, having first confirmed prefetch entries were being produced at all.
- [ ] I compared Recycle Bin `$I`/`$R` pairs against the set of files actually missing.
- [ ] I attempted recovery of a deleted file's data and compared its hash against the answer key.
- [ ] For at least one technique I have **two independent artefacts** that agree, and I have written down which techniques I could support with only one.
- [ ] I can state one technique I could not detect on my build, and why (artefact disabled, rolled over, not collected).

## Further Resources

- MITRE ATT&CK — Indicator Removal (`T1070`), including the sub-techniques for clearing Windows event logs and timestomping: <https://attack.mitre.org/techniques/T1070/>.
- NIST SP 800-86, *Guide to Integrating Forensic Techniques into Incident Response* — <https://csrc.nist.gov/pubs/sp/800/86/final>.
- RFC 3227, *Guidelines for Evidence Collection and Archiving* — <https://www.rfc-editor.org/rfc/rfc3227>.
- Microsoft, `wevtutil` command reference (channels, configuration, clearing) — <https://learn.microsoft.com/windows-server/administration/windows-commands/wevtutil>.
- Microsoft, `fsutil usn` reference (query, read and manage the change journal) — <https://learn.microsoft.com/windows-server/administration/windows-commands/fsutil-usn>.
- Microsoft, *File Times* — how the timestamp-setting API behaves and which times it writes — <https://learn.microsoft.com/windows/win32/sysinfo/file-times>.
- Eric Zimmerman's tools — MFT and USN journal parsing, prefetch, Amcache, ShimCache, Recycle Bin, registry: <https://ericzimmerman.github.io/>.
- The Sleuth Kit wiki — NTFS `$MFT`, `$LogFile` and `$UsnJrnl` structure, plus the body-file format: <https://wiki.sleuthkit.org/index.php?title=NTFS>.
- Forensics Wiki — artefact encyclopedia and tool notes: <https://forensics.wiki/>.
- SANS Reading Room — white papers on timestomping, anti-forensics and evidence integrity: <https://www.sans.org/reading-room/>.
- libyal — `libfsntfs` and `libewf`, the libraries behind several parsers above: <https://github.com/libyal>.
- Official eCDFP page on the INE website for current, authoritative information about the certification.
