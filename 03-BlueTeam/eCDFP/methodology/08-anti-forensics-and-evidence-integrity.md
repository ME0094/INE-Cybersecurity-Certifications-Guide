# Anti-Forensics and Evidence Integrity (eCDFP Methodology — Phase 08)

> Companion study guide for the eCDFP (Certified Digital Forensics Professional) Blue Team methodology track. Every other phase assumes the record is intact and asks what it says. This one asks a prior question: **has the record been changed, and by whom?** It then turns the same lens on the examiner, because anti-forensics has two authors — the adversary and the person holding the evidence.
>
> Where this phase sits: it is a cross-cutting check on Phases 02, 05, 06 and 07, and its practical output is a set of artefacts to hunt in any case where the evidence looks *too* clean. `../labs/anti-forensics-lab.md` is the drill that turns this file into a reflex.
>
> Every command in this file is a **syntax reference**. This repository ships no captured output: there is no image, no hive and no parser on the machine that wrote it. Where a command would print a result, the text says what to look for. Confirm flags against `--help` or the manual page for the version you install.

## Overview

The central idea of this phase is that **anti-forensics rarely erases evidence; it displaces it.** Removing an artefact leaves a record of the removal, and destroying one copy usually promotes another copy you had not considered:

- Deleting a file updates the file-system metadata *about* that deletion, and the entry usually survives in the `$MFT` as unallocated.
- Clearing an event log writes a record saying the log was cleared, and leaves a channel whose oldest retained event is conspicuously newer than its neighbours'.
- Wiping free space produces evidence that a wiping tool ran, and a large contiguous run of uniform data in exactly the region where interesting content used to be.
- Reformatting a volume leaves the previous file system's structures at an offset the new one does not overwrite, if it was a quick format.
- Destroying the original leaves the copy that was synchronised, attached to an email, previewed by a thumbnailer, cached by a browser, written to a pagefile, or held by a backup.

So the practical question is never "did they erase it", but **"where did it go, and what did the erasing itself leave behind?"**

The second idea is symmetry. An examiner is equally capable of altering evidence — by mounting an image, by letting an operating system thumbnail it, by running a parser that writes to the evidence directory, by examining a device with the same OS that produced it. The difference between contamination and anti-forensics is not the mechanism; it is authorization, documentation and intent. That makes this phase as much about your own discipline as about the adversary's.

## 1. A taxonomy of anti-forensic technique

| Family | Technique | Targets | What the technique tends to produce instead |
| --- | --- | --- | --- |
| **Artefact deletion** | Removing files, caches, prefetch entries, task definitions, registry keys, mailboxes | The artefact that would name the activity | File-system metadata about the deletion; a surviving duplicate in another cache; a gap in a sequence |
| **Artefact disabling** | Turning off auditing, stopping a logging agent, narrowing a configuration, reducing a channel's size | The recording capability itself | A configuration-change event; an agent stop/start; a channel whose history is shorter than its peers' |
| **Data destruction** | Overwriting free space, wiping specific files, crypto-erasing a volume, physical destruction | Recoverable content | The wipe tool's own execution evidence; uniform overwrite regions; survivors in pagefile, hibernation file, slack, backups and cloud copies |
| **Timestamp manipulation** | Changing creation/modification times; copying one file's timestamps onto another | The temporal story | An inconsistency between the two NTFS timestamp sets; archived copies of the original times in journals and caches |
| **Log tampering** | Clearing a channel, editing a log file, attacking the collector, truncating retention | The authoritative record | Sequence-number and record-ID gaps; monotonicity breaks; a cleared-channel record; disagreement between local and shipped copies |
| **Data hiding** | Steganography, alternate data streams, hidden volumes or partitions, deceptive file extensions, unusual container formats | Discoverability | The container's own anomaly: a stream nothing references, a partition no file system claims, an extension that disagrees with the content |
| **Trail obfuscation** | Forged artefacts, planted documents, tools renamed to look legitimate, activity attributed to another account or language | Your interpretation | Internal inconsistency: a forged artefact that lacks the corroborating artefacts its story would require |
| **Encryption and encoding** | Full-disk encryption, encrypted archives, obfuscated scripts | Readability of content | The volume's structural metadata, keys held in memory or in escrow, and the tooling used to create it |
| **Legitimate-tool abuse** | Living off the land: built-in administration tools doing the work | The assumption that built-in equals benign | Process ancestry and command-line arguments — the artefact that shows *how* a legitimate tool was used |
| **Attacking the investigation** | Targeting the collector, the analyst, or the tooling | Your ability to conclude anything | Nothing subtle: an attacked collector or a corrupted tool chain is usually loud, which is why it is rare |

Two observations that shape how you work:

- **Deletion is the least effective technique on this list.** It is the one people reach for first and the one that leaves the most metadata behind.
- **Disabling is the most effective**, because it produces an absence, and absences are what examiners misread. Which is why §4 exists.

## 2. The displacement table — where the record of the act survives

Use this as a hunting list. For each technique: the artefact attacked, and what to look at *instead*.

| Technique | Artefact attacked | What records the act | Where to look |
| --- | --- | --- | --- |
| File deleted | File content | `$MFT` record marked unallocated; `$UsnJrnl` delete reason code; `$LogFile` records | `istat` on the file record; `$UsnJrnl` for the delete's timestamp; the parent directory's metadata |
| File deleted bypassing the Recycle Bin | The `$I`/`$R` pair that would have existed | The same MFT/USN records, but nothing in the bin | Absence of a bin entry is *not* absence of deletion — check the file system |
| Prefetch entries deleted | Execution evidence | The Prefetch directory's own file-system records | `$MFT`/`$UsnJrnl` entries for the `.pf` files; execution evidence from Amcache or UserAssist that prefetch no longer corroborates |
| Event log cleared | The channel's history | The clearing record written into the channel; a channel whose oldest retained event is far younger than its siblings | Compare the oldest retained record per channel and the log files' timestamps |
| Auditing disabled or narrowed | Future events | Audit-policy change events; the policy configuration itself | Policy-change records and the host's current audit configuration |
| Logging agent stopped or reconfigured | The shipped record | Agent service start/stop events; where applicable, an agent configuration-change event | Service control events on the host; any ingest gap at the collector |
| USN change journal deleted | File-operation history | The journal's absence, its identifier change, and the fact that its earliest retained record is much younger than the file system | Compare the journal's earliest record against the volume's own history |
| Free space wiped | Deleted content | The wipe tool's execution evidence; large uniform regions where previously unallocated data had structure | Prefetch/Amcache/UserAssist for the wiping tool; a content scan for uniform overwrite patterns |
| Timestamps modified | The temporal story | A mismatch between the two NTFS timestamp sets, and copies of the original times elsewhere | §3 below |
| Volume reformatted (quick) | The previous file system | The old file-system structures at an offset the new one did not touch | Search raw for previous volume signatures and their metadata |
| File encrypted | Content | The tooling used; keys in memory, escrow, or a recovery agent | Memory capture; the tool's own execution artefacts; the recovery-key record wherever it is stored |
| Collectors attacked | Centralised evidence | Loud failures: gaps in sequence numbers, ingest anomalies, agent restarts | Collector-side ingest history and the host's own local copy |

> The pattern to internalise: **for every artefact you expected and did not find, ask what the *absence's* cause would look like.** Then look for that. "No prefetch for the payload" is not a finding; "no prefetch for the payload, but the Prefetch directory shows entries created and deleted in the same window, and Amcache has an execution entry" is.

## 3. Timestomping in depth

Timestamp manipulation is the anti-forensic technique most worth mastering, because it is common, it is detectable, and detection depends on knowing where timestamps are *duplicated*.

### 3.1 Why it is detectable at all

On NTFS, a file's timestamps exist in more than one place, and they are not updated by the same events:

| Location | Contains | Updated when |
| --- | --- | --- |
| `$STANDARD_INFORMATION` attribute in the `$MFT` record | Modified, accessed, changed, created | By normal file operations *and* by any tool that sets timestamps |
| `$FILE_NAME` attribute (and the directory index entry that mirrors it) | The same four values | On operations that touch the directory entry — creation, rename, move — **not** by a tool that only writes `$STANDARD_INFORMATION` |
| `$UsnJrnl` records | The time of each change record | As changes occur |
| `$LogFile` | Transaction records for metadata changes | While the volume is mounted and busy |
| Other artefacts that copied a timestamp | LNK files embed their target's timestamps; Prefetch and Amcache record their own; registry keys carry last-write times | When those artefacts were created |

A naive timestamp editor changes `$STANDARD_INFORMATION` and leaves the other copies alone. That divergence is the finding.

### 3.2 Indicators, from weakest to strongest

1. **A mismatch between `$STANDARD_INFORMATION` and `$FILE_NAME` times.** Suggestive. Legitimate activity can produce mismatches — a file created and then moved, or restored from a backup, or written by a tool that sets times deliberately (installers, archive extractors, build systems). This is a lead, not a proof.
2. **Sub-second precision that disagrees with the file system's native resolution**, or a set of timestamps with the sub-second field zeroed where the surrounding files have non-zero values. Suggestive evidence of an API call that wrote times directly rather than an operation that produced them naturally.
3. **A creation time earlier than something that must precede it**: earlier than the volume's own creation, earlier than the parent directory, or earlier than the OS installation on that volume. A file cannot have been created before the volume existed, and this contradiction is difficult to explain innocently.
4. **Timestamps that exactly match a known system file's values** — for example a malicious binary whose four timestamps match a Windows system library's to the tick. Coincidence is not credible at that precision.
5. **A file whose timestamps are internally inconsistent with its content or its neighbours**: a "three-year-old" file sitting in a directory created last week, whose siblings are all recent.
6. **Independent artefacts disagreeing.** Prefetch says the program ran on Tuesday; `$STANDARD_INFORMATION` says the binary was created six months earlier; Amcache records a first-run entry dated Tuesday. The mismatch across artefacts is the strongest form of this evidence, because falsifying all of them consistently requires effort that most tampering does not make.

### 3.3 How to examine it

```bash
# Show both NTFS timestamp sets for one file record (Sleuth Kit)
istat -o 2048 /evidence/case-01/evidence/disk.dd <mft-entry>
# What to look for: which of the sets is anomalous, and whether the difference is
# consistent with a rename/move (legitimate) or with a rewrite of one set only.

# Extract the change journal and look at the create/delete/rename records
# (see ../tools/windows-artifact-tools.md for the MFTECmd invocation that parses $J)
# What to look for: records whose timestamp disagrees with the MFT record's, and
# rename reason codes that explain a legitimate $FILE_NAME divergence.
```

```powershell
# Parser-side: $MFT output exposes both timestamp sets per record
MFTECmd.exe -f "C:\case\exports\$MFT" --csv "C:\case\reports" --csvf mft.csv
# What to look for: rows where the standard-information and file-name columns
# disagree, and rows whose sub-second values are inconsistent with their neighbours.
# Confirm the exact column names with MFTECmd --help on your build.
```

Then apply the corroboration rule from §5: one mismatched pair is a lead; a mismatch plus an independent artefact that contradicts the forged story is a finding.

### 3.4 What timestomping does not fix

Attackers who change timestamps frequently do not change everything the timestamps agree with:

- **Journal records** for the create, write, rename or delete, each with its own timestamp.
- **Caches that recorded the file** when it was first seen: Amcache, ShimCache, Prefetch, SRUM.
- **Log entries** about execution or installation.
- **Copies elsewhere**: backups, cloud synchronisation, email attachments, the machine the file was copied from.
- **The directory entry's own consistency**: siblings, the parent's timestamps, and the volume's history.

This is why timestomping is a technique that buys time rather than immunity, and why the honest conclusion is usually "the timestamps for this file are not reliable; the following independent artefacts place the activity at T."

## 4. Absence of evidence: the four-way test

When you cannot find the artefact you expected, resist both failure modes: assuming the activity did not happen, and assuming the evidence was destroyed. Run this test instead.

| Step | Question | What a positive result looks like |
| --- | --- | --- |
| **1. Health** | Was the artefact's subsystem collecting at all, on this build, with these policies, in this window? | Other entries from the same window exist, so the mechanism was alive |
| **2. The act** | Is there a record of the *removal* or *disabling*? | A delete record, a cleared-channel record, an audit-policy change, an agent stop, a journal reset |
| **3. Reach** | Is there a source the activity's author could not reach? | A shipped log copy, a collector, a second machine, a cloud-side record |
| **4. Copies** | Did the artefact exist elsewhere by design? | A synchronised copy, a backup, an email attachment, a cache on another host |

Only after all four come back negative are you entitled to write "no evidence of X was found", and even then you write it with the artefacts you checked and their retention, not as a bare assertion.

A worked example of the reasoning, in words rather than output:

> *Expected:* a Prefetch entry for the payload, which executed at 03:12.
> *Health:* the Prefetch directory contains entries from 02:40 and 04:05, so the mechanism was alive.
> *The act:* the `$UsnJrnl` shows a delete record for a `.pf` file at 03:40, and the `$MFT` has an unallocated record whose filename matches the payload's name plus a hash.
> *Reach:* no shipped evidence exists on this standalone host.
> *Copies:* Amcache has a file entry for the same path with a matching first-seen window.
> *Conclusion:* prefetch was present and was deleted after the activity; the execution is corroborated by Amcache and by the file-system metadata; the deletion itself is evidence of intent to conceal, subject to the alternatives in §5.

## 5. The claim ladder, applied to anti-forensics

Anti-forensic conclusions are where over-claiming is most tempting and most damaging. Grade every statement:

| Claim | What it needs |
| --- | --- |
| "A file was deleted at T." | A delete record with a timestamp, or an unallocated record plus corroboration |
| "The deletion was not performed through the Recycle Bin." | Absence of a bin entry **plus** a positive deletion record — never the absence alone |
| "Timestamps for this file were modified after creation." | A mismatch between the timestamp sets, or a contradiction with the volume's history |
| "Someone attempted to conceal activity." | Timestamp manipulation **or** artefact removal **or** logging disabled, each with its own record |
| "The user did it deliberately." | Attribution of the session, evidence of intent, and an alternative-explanation analysis — usually a legal question as much as a technical one |

And the alternative explanations you must address before the last two rows, because each one is common and innocent:

- **Tooling**: installers, archive extractors, backup restores, synchronisation clients and build systems set or preserve timestamps as a feature. Some legitimate software adjusts timestamps to preserve source metadata.
- **OS behaviour**: a feature update or cleanup task can remove Prefetch entries; a log can be cleared by an over-zealous maintenance script; a channel can be resized by policy.
- **Administrator action**: a system administrator doing exactly what an anti-forensic actor would do, for legitimate reasons, without documentation.
- **Coincidence**: an unrelated process that happened to delete similar files in the same window.

Writing "consistent with deliberate concealment, though an unrecorded administrative cleanup would produce the same signature, and no change-management record was available to exclude it" is a mature finding. The same evidence stated as "the attacker wiped the logs" is not, and a reviewer will take it apart.

## 6. Your own integrity obligations

You are also a potential source of alteration. The mechanisms are mundane and the consequences are severe.

| Risk | Why it happens | Control |
| --- | --- | --- |
| Mounting an image | The OS replays the journal, updates access times, creates thumbnails and index entries | Never mount evidence; use file-system-aware tools on the image |
| Letting a desktop environment or indexer see the evidence | A GUI browser or a media indexer touches files | Keep the analysis host headless where practical, and keep evidence outside indexed paths |
| Antivirus scanning evidence | Quarantines or rewrites files | Exclude the evidence directory from real-time scanning, and record that you did |
| Analysing with the same OS that produced the evidence | Auto-mount, indexing, and OS-generated artefacts appear *inside* the evidence | Analyse on the other platform, or in a VM with those features disabled |
| A parser that writes into the evidence directory | Default output paths | Pass explicit output paths into `working/`, and check the hash manifest afterwards |
| Repeated examination of the original | Every read is theoretically free, every write is not | Examine a verified working copy; verify the master's hash at each checkout |
| Reconstructing notes afterwards | Human memory is unreliable and shaped by the conclusion | Write contemporaneous notes, with commands and timestamps |
| "Tidying up" mid-case | Removing a suspicious file, resetting a password, restarting a service | Do not. Record it, get authorisation, and preserve before you change anything |

```bash
# The habit that catches accidental writes: verify against the manifest after every session
sha256sum -c /evidence/case-01/notes/evidence-hashes.txt
# What to look for: "OK" for every exhibit. A FAILED line means something modified
# the evidence directory; stop and investigate before doing anything else.
```

**When you do break a rule**, the professional response is not silence. It is: record what happened, in the case log, with the time; quantify the effect honestly (which artefact could have changed, and which findings depend on it); remediate by re-acquiring from the source where that is possible; and if the effect is material, say so in the limitations section of the report. An examiner who documents a mistake keeps their credibility. One who conceals it loses the case and their reputation together.

## 7. Wording anti-forensic findings

Three sentences that do the job, and the reasoning behind each:

- **"The Prefetch directory contained no entry for the payload. The directory's other entries span the incident window, so the prefetch mechanism was active. The `$UsnJrnl` records a delete for a file with a matching name at 03:40, 28 minutes after the process-creation event recorded by the Amcache entry for the same path."** — Health, act, corroboration. No claim about intent.
- **"The `$STANDARD_INFORMATION` created timestamp for the file is 2019-04-02, which precedes the volume's creation by four years. The `$FILE_NAME` timestamps and the `$UsnJrnl` record are consistent with a creation in March of the incident year. The `$STANDARD_INFORMATION` times are therefore not reliable."** — One contradiction, stated concretely, with the conclusion limited to the artefact.
- **"Activity consistent with deliberate concealment was identified: an event-log channel was cleared, and the log configuration was modified within the same window. Change-management records were requested and none covered this change; the possibility of an undocumented administrative action could not be fully excluded from the artefacts available."** — Finding plus alternative plus limitation.

## Common Mistakes & Tips

- **Reading an absence as a fact.** "No event log entry" means either the event did not happen or the log could not have recorded it. Run the four-way test before concluding anything.
- **Calling one timestamp mismatch timestomping.** Legitimate moves, restores, extractors and installers produce mismatches. Look for the second, independent contradiction.
- **Missing the deletion record while chasing the deleted file.** The `$MFT` record, the `$UsnJrnl` delete reason, and the `$LogFile` entry are frequently easier to find than the content.
- **Forgetting that a cleared log records its own clearing.** The clearing record and the channel's truncated history are themselves artefacts; check the oldest retained event per channel.
- **Treating the local log as authoritative.** Prefer the shipped copy; where there is none, state that the local copy was alterable by anyone with administrative access.
- **Assuming a wipe removes everything.** Pagefile, hibernation file, slack, backup copies, cloud synchronisation, mail attachments and the second machine are all outside the wiped region.
- **Ignoring the attacker's *use* of legitimate tools.** Living-off-the-land activity is anti-forensic in effect: parentage and command-line arguments are where it becomes visible.
- **Contaminating the evidence yourself.** Mounting, indexing, AV scanning, and analysing on the producing platform are all alterations, and all avoidable.
- **Not verifying the evidence hash after a session.** If anything wrote to `evidence/`, you want to know now, not in court.
- **Skipping the alternative-explanation analysis.** Installers, cleanup tasks and undocumented admin work produce the same signatures as concealment. Address them explicitly.
- **Tip:** in any case where the absence of artefacts is central, build a table of "artefact → expected → health check → removal record → independent source". It converts a suspicion into an argument.
- **Tip:** log your own actions as carefully as you log the adversary's. Your case log is the part of the evidence that only you can produce.

## Checklist / Self-Test

- [ ] Can I state the displacement principle and give three examples where removing an artefact produced a new one?
- [ ] Can I name the two NTFS timestamp sets and explain which operations update each?
- [ ] Can I rank timestomping indicators from weakest to strongest, and say why a single mismatch is only a lead?
- [ ] Can I explain why the strongest timestomping evidence is disagreement between independent artefacts rather than between two timestamps?
- [ ] Can I apply the four-way absence test (health, act, reach, copies) to an artefact I expected and did not find?
- [ ] Can I name what a deleted prefetch entry, a cleared event log and a deleted USN journal each leave behind?
- [ ] Can I describe what survives a free-space wipe and where it would be found?
- [ ] Can I list three legitimate causes of a timestamp mismatch before claiming manipulation?
- [ ] Can I name four ways an examiner can accidentally alter evidence, and the control for each?
- [ ] Do I verify the evidence hash manifest after every analysis session?
- [ ] If I broke a procedure, would I know how to document it, quantify its effect, and where to state it in the report?
- [ ] Can I word an anti-forensic finding that states what the artefacts support, names the alternative explanations, and keeps intent claims in a separate, labelled sentence?

## Further Resources

- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **ISO/IEC 27037**, *Guidelines for identification, collection, acquisition and preservation of digital evidence* — https://www.iso.org/standard/44381.html
- **RFC 3227**, *Guidelines for Evidence Collection and Archiving* — https://www.rfc-editor.org/rfc/rfc3227
- **The Sleuth Kit** (`istat` for both NTFS timestamp sets; `fls`/`icat`/`ils` for the file-system record) — https://www.sleuthkit.org/sleuthkit/
- **Eric Zimmerman's forensic tools** (`MFTECmd` for `$MFT`/`$J`, `RECmd`/Registry Explorer for hive slack and dirty-hive recovery) — https://ericzimmerman.github.io/
- **Forensics Wiki** (per-artefact references, including timestamp semantics) — https://forensics.wiki/
- **DFRWS challenge archives** (authorized practice datasets, several of which include tampering) — https://dfrws.org/
