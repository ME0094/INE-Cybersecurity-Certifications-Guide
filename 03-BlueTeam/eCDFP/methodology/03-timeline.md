# Timeline Analysis (eCDFP Methodology — Phase 03)

> Companion study guide for the eCDFP (Certified Digital Forensics Professional) Blue Team methodology track. This phase answers the investigator's core question — *what happened, in what order?* — by merging timestamps from many artifact classes into one browsable sequence of events.
>
> The tooling that builds these timelines is in `../tools/timeline-tools.md`; this file owns the concepts, the correlation method and the judgement calls. `../labs/supertimeline-lab.md` is the drill.
>
> Every command below is a **syntax reference**. This repository ships no captured command output: there is no image, no log store and no timeline tool on the machine that wrote this file. Where a command would print a result, the text says what to look for. CLI forms for timeline tools change between releases — confirm them with `--help` on the version you install.

## Overview

Individual artifacts tell you *something happened*; timelines tell you *when and in what sequence*. The goal of timeline analysis is to reconstruct user and attacker activity by correlating timestamps across the filesystem, registry, logs, and (when available) memory captures.

Two terms are worth knowing precisely:

- **Timeline** — events from one source or a narrow question (e.g., "what executables ran?").
- **Supertimeline** — every timestampable event from *all* sources merged and sorted. The concept was popularized by Harlan Carvey; plaso is the tool most associated with building them today.

A supertimeline is intentionally noisy — its power is that you can *filter* it down to a focused timeline for a specific question.

Three principles keep the work honest:

1. **A timeline is a derived artefact, not evidence.** The events are evidence; the ordering is your product. That is why the sources, the tool version and the exact filters must be recorded, and why the raw sources must be preserved alongside the output.
2. **Timestamps are claims.** Each one was produced by some subsystem, with its own clock, its own resolution and its own update rules. Correlation means deciding which claims you trust, and saying so.
3. **Order is not causation.** A timeline shows that B followed A. Whether A caused B is an inference you must argue separately.

## What Feeds a Timeline

| Source | Example artifacts | What the timestamps tell you |
| --- | --- | --- |
| Filesystem metadata | MFT entries, directory entries | File creation, modification, access, MFT-record change (MACB) times |
| NTFS specifics | `$STANDARD_INFORMATION` vs `$FILE_NAME` times; USN journal; `$LogFile` | File operations; anti-forensic tampering (one timestamp set changed, the other not) |
| Registry | Key last-write times; UserAssist, Shellbags, MRU values | Program execution, folder browsing, device connections, user actions |
| Logs | Windows Event Logs (`.evtx`), Sysmon, Syslog, web/application logs | Logons, process creation, network activity, attacker commands |
| Applications | Browser history, LNK files, jump lists, Office recent files | What the user viewed, opened, downloaded, searched |
| Memory | Process creation times, network connections, loaded modules | Live activity at the moment of capture |

The classic per-file representation is the **MACB** set: **M**odified, **A**ccessed, **C**hanged (MFT record / inode change), **B**irth (created). Each gives a different clue about a file's history.

### What each timestamp is actually good for

The MACB letters look symmetrical and are not. Rank them before you build an argument on one:

| Timestamp | Updated by | Reliability | Best used for |
| --- | --- | --- | --- |
| **B** (birth / created) | File creation; also settable by many tools | Moderate — forgeable, and copied by some restores and extractors | Anchoring when corroborated by another artefact |
| **M** (modified) | Content writes | High for "content changed", and the least forgeable of the four in practice because writes keep happening | Establishing that content changed at a time |
| **A** (accessed) | Reads, when access-time updates are enabled | **Low.** Often disabled entirely, updated lazily, or disturbed by backups, indexing and antivirus | Almost nothing on its own; use for "was read" only with corroboration |
| **C** (changed / MFT record modified) | Metadata changes, including permission and attribute changes | Moderate; the entry most often *not* touched by timestamp editors | Detecting tampering by disagreement with M or B |

For NTFS, remember that each of these exists **twice** (`$STANDARD_INFORMATION` and `$FILE_NAME`), updated by different events; on ext4, sub-second fields give you precision beyond whole seconds. Both points are treated in `05-windows-artifact-forensics.md` §3 and `08-anti-forensics-and-evidence-integrity.md` §3.

## Choosing how to build the timeline

| Route | Best for | Cost | What it misses | Coverage honesty |
| --- | --- | --- | --- | --- |
| Sleuth Kit bodyfile → `mactime` | A file-system-only question on one image; a quick check | Low; minutes | Registry, event logs, applications, memory | You can state exactly what it covered: file system metadata only |
| plaso / log2timeline → `psort` | A full supertimeline over a real image, or several sources merged | High; CPU, RAM and a storage file several times the source size | Whatever no parser supports, and whatever the parsers do not recognise | You must check which parsers actually ran |
| Rule-based EVTX triage (Hayabusa, Chainsaw) | A log-centric incident with a collected `.evtx` set | Low | Everything outside the logs; and everything no rule describes | Only the rules' coverage, which you did not write |
| Targeted extracts (one artefact family at a time) | A specific question with a known answer | Very low | Everything not extracted | The narrowest and the most defensible scope statement |

Most cases use two of these: a wide supertimeline to find the shape, then targeted extracts to prove the specific events you will cite. Say which route produced which finding.

## The Bodyfile Format

Many timeline tools normalize timestamps into a **bodyfile**: one pipe-delimited record per event. Tools like `fls`/`ils` (with `-m`) and `mactime` (TSK) use it; it is also the interchange format behind many GUI timelines.

```
MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
```

```bash
# Build a bodyfile from an image (Sleuth Kit classic workflow)
fls -o 2048 -r -m / image.dd > body.txt    # -m adds mount point to paths
ils -o 2048 -m image.dd >> body.txt        # add unallocated inode metadata
# Note the asymmetry: 'fls -m <mount point>' takes an argument, 'ils -m' does not.
# Give ils one and it reads the prefix as the image name instead.

# Generate a sorted timeline in CSV from the bodyfile
mactime -b body.txt -d > timeline.csv
# What to look for: a date column plus one row per timestamped event, and a file-name
# column carrying the mount prefix you supplied. Confirm the option letters with
# mactime -h: -d selects CSV-style delimited output, and the time-zone option matters
# (UTC is the safe choice).
```

Three things to know before you trust a bodyfile timeline:

- **Every timestamp becomes its own row.** One file yields up to four events. A file touched four times in one second produces four rows that look like four separate events — which is why the "Type" column matters when you read the output.
- **`fls -m` and `ils -m` give you different subsets.** `fls` walks allocated *and* deleted directory entries; `ils` adds metadata records including those with no directory entry left. Run both, and note that duplicated events can appear.
- **A wrong time zone offset produces plausible nonsense.** Dates that are shifted by hours, or events placed in the wrong day, are the signature. Set the display time zone explicitly and record it.

The bodyfile approach scales poorly across *many* sources, which is why plaso exists — but understanding the format explains what every timeline tool is doing under the hood.

## Building Timelines with plaso / log2timeline

**plaso** (formerly *log2timeline*) parses an enormous set of artifact types — filesystem metadata, registry hives, event logs, browsers, and dozens of application formats — into a single **storage file** you can then filter and export.

The pipeline has three steps:

1. **Collect** — `log2timeline.py` parses sources into a plaso storage file.
2. **Filter/export** — `psort.py` sorts, filters, and converts to CSV, JSON, etc.
3. **Inspect** — `pinfo.py` and `psteal.py` (a collect-and-export shortcut) support triage.

```bash
# Parse the filesystem artifacts of an image into a storage file.
# NOTE: CLI forms vary between plaso releases; run <tool> --help to confirm the
# storage-file option, and where the filter expression must sit, before you commit
# either form to a report.
log2timeline.py --storage-file=case.plaso image.dd

# Add additional extracted sources (e.g., event logs pulled from the image)
log2timeline.py --storage-file=case.plaso /case/evidence_extracted_logs/

# Dump the whole supertimeline as sorted CSV. The CSV output module is called `l2tcsv`
# (`-o csv` is rejected: `ERROR: Unsupported output format: csv.`). Confirm the module
# list on your build with `psort.py --output-format list`.
psort.py -o l2tcsv -w timeline.csv case.plaso

# Filter: only events after a date, from the prefetch parser.
# The filter expression is a positional argument and must come AFTER the storage file:
# placed before it, psort reads it as part of the path and fails to compile the expression.
psort.py -o l2tcsv -w prefetch.csv case.plaso \
  "date > '2024-11-01 00:00:00' and parser == 'prefetch'"
# What to look for: the filter is a string expression over event fields. Confirm the
# field names your release exposes — `pinfo.py` output and the parser list are the
# authority, not a remembered example.
```

```bash
# One-shot alternative for quick triage: parse and export in a single command.
# Use --output-format: a bare `--output` is ambiguous in current releases and exits 2.
psteal.py --source image.dd --storage-file=case.plaso --output-format l2tcsv --write timeline.csv
```

Export formats you will meet: `l2tcsv`/`csv` (flat tables for Excel), `json` (for scripting), and the classic bodyfile. Time-zone handling matters: plaso records timestamps in UTC by default, and you choose the display zone at export — store UTC, display local.

**Prove the parse before you trust it.** A plaso run that silently skipped a source type produces a timeline with a hole in it, not an error message. After collecting, check what was actually parsed: list the parsers that produced events and the number of events per parser, and compare that list against the sources you expected. An `.evtx` file that contributed zero events is a finding about your pipeline, not about the incident.

## Measuring clock skew instead of assuming it

Correlation across sources fails on time, and "assume the clocks were right" is not a method. Measure, and record the result per source.

```text
1. FIND A SHARED EVENT. Pick something that two independent sources both recorded:
   a file written by a scheduled task that also logged, a logon that appears in both
   the DC and the local Security log, a download that appears in browser history and
   in proxy logs.
2. COMPARE THE TIMESTAMPS. The difference is the skew (plus any deliberate offset).
3. ANCHOR TO THE MOST TRUSTWORTHY SOURCE. Typically a domain controller, a network
   device with an external time source, or a provider-generated cloud timestamp —
   not the suspect host.
4. APPLY AND DOCUMENT. Record the measured offset per source, and correct the timeline,
   or state in the report that a known offset was left uncorrected and why.
```

Additional anchors when you have no shared event:

- **NTP and time-service logs** on the host show whether it was synchronising, and when the last successful sync was.
- **File system artefacts created by synchronised infrastructure** — a Group Policy refresh, a scheduled backup, an update — carry timestamps from a source you trust.
- **Boot and shutdown events** with an external counterpart (a hypervisor's own logs, a network device seeing the interface go down).
- **Daylight-saving transitions** are the trap inside this exercise: a host logging in local time without an offset produces an hour that occurs twice or not at all. Where the window spans a transition, say explicitly which mapping you used.

## Correlating Events Across Sources

A timeline is only as good as the correlation you do on top of it. Effective correlation asks three questions per candidate event:

1. **Is the timestamp trustworthy?** System clock skew, NTP drift, or deliberate clock changes distort events. Anchor with events from trusted sources (firewall/router logs, domain controller logs) that carry their own reliable time.
2. **Does the event stand alone or corroborate?** One registry Run key is weak; a Run key + a Prefetch entry + a Sysmon process-create event for the same binary on the same minute is strong.
3. **What does the *absence* say?** Gaps — e.g., a file whose `$STANDARD_INFORMATION` times were changed but whose `$FILE_NAME` times were not — are themselves evidence of tampering (timestomping).

Practical correlation workflow:

- Normalize everything to **UTC** and one format.
- Build a **baseline** of normal activity (scheduled tasks, updates) to filter noise.
- Search the timeline around *known* events (malware hash hit, alert time, user-reported incident) and work outward — the "known-event anchoring" method.
- Then pivot on **entities**, not just times: the same executable, account, or IP across event types.

### The reading loop, in operational order

```text
1. ANCHOR. Choose the one event you trust most — usually the artefact that opened the
   case. Write down its time and its source.
2. WINDOW. Take a narrow slice around it (minutes, not days). Read everything in it
   before filtering anything out.
3. PIVOT. Take one entity from that window — a path, a hash, an account, a hostname —
   and ask where else it appears, in the whole timeline, across all sources.
4. WIDEN ONLY WHEN THE QUESTION CHANGES. If widening produces no new answer, the
   question was already answered.
5. RECORD. For every claim you keep, note the source, the exact filter, and the tool
   version. For every claim you discard, note why — "benign, matched the update window"
   is a result worth keeping.
6. EXPORT. Save the filtered subset as an exhibit, and state the filter that produced it.
```

Two habits make this productive rather than overwhelming:

- **Keep the unfiltered timeline.** A filtered export is what you cite; the full output is what proves you did not filter away the answer. Store both.
- **Filter on entities, not on volume.** Excluding a noisy process by *what it is* keeps the timeline readable while preserving the anomalous instances of the same process. Excluding a whole time range hides whatever else happened in it.

### Grading a timeline event before you rely on it

Assign each event you intend to cite to a grade, and put the grade in your notes. It takes seconds and it prevents the most common reporting error — treating a weak timestamp like a strong one.

| Grade | Basis | Example |
| --- | --- | --- |
| **A** | Independent source with its own reliable clock, recording the event directly | A firewall log of the connection; a provider-generated audit record; a domain controller's authentication event |
| **B** | Host-generated record of the event, with the host's clock validated | A file-system timestamp on a host whose clock you checked; a service start event |
| **C** | Derived or cached record, update rules uncertain, or clock unvalidated | ShimCache-style caches; access times; a timestamp you had to infer |
| **D** | Reconstructed from context, with no timestamp of its own | An event established only by ordering, or by a gap between two records |

A conclusion built entirely on C and D evidence is not wrong — it is provisional, and it should say so.

## Reconstructing User and Attacker Activity

Timeline analysis pays off when you turn event rows into a narrative mapped to an intrusion or user-action model. A compact example (an illustrative composite, not captured output from this repository):

| Time (UTC) | Source | Event | Interpretation |
| --- | --- | --- | --- |
| 09:02:11 | Sysmon | `powershell.exe` process create, user `alice` | Initial execution |
| 09:02:14 | Filesystem | `C:\Users\alice\AppData\...\payload.exe` birth | Dropped file |
| 09:02:30 | Registry (Run key) | New value pointing to payload.exe | Persistence |
| 09:03:05 | Network logs | Outbound beacon to 203.0.113.7:4444 | C2 communication |
| 09:04:00 | Event Log | Logon type 3 from `alice` workstation to `FILE-SRV` | Lateral movement |

Chained like this, the rows describe an attack: execution → persistence → command-and-control → lateral movement. The same discipline reconstructs *user* activity: browsing history plus download timestamps plus file births plus document edits tell the story of what a user actually did.

Notice what the table does *not* claim. It says a Run key was written, not that the attacker wrote it; it says a beacon is consistent with C2, not that the binary was malware. Every row is a fact plus a labelled interpretation, and the interpretation column is where a reviewer will aim.

### What a good narrative needs

- **A start.** The earliest event you can defend, with its grade.
- **A chain.** Each step corroborated by at least one independent source, or explicitly marked as single-source.
- **The gaps named.** Where a source was absent, cleared, or rotated out, say so at the point in the story where it matters.
- **The alternative reading.** At least one competing explanation for the sequence, and why the evidence favours yours — or why it does not.
- **The limit of the timeline.** What your sources cannot show: file content, intent, activity on hosts you did not collect from, anything encrypted.

## Common Mistakes & Tips

- **Ignoring clock skew.** Correlating against wall-clock time without accounting for a skewed system clock misplaces events by minutes or hours; anchor to trusted external logs.
- **Mixing time zones.** A timeline half in local time and half in UTC produces phantom sequences; normalize to UTC early.
- **Assuming the clocks were right because nobody mentioned a problem.** Measure skew with a shared event; record the offset per source.
- **Treating every timestamp as equal.** Access times are unreliable (updates, AV scans); creation times can be forged or copied with a file; prefer corroborated event sets.
- **Ignoring access-time behaviour.** Whether access times update at all depends on the volume's configuration. Establish it before you argue from an `A` timestamp.
- **Filtering before understanding.** Jumping straight to a narrow filter hides the "boring" events that make anomalies visible; explore the supertimeline first.
- **Throwing away the unfiltered timeline.** Keep both the full output and the cited subset; the full one is your evidence that the filter was not the answer.
- **Trusting a parse you never verified.** A parser that skipped a source type leaves a hole with no error message. Check the per-parser event counts.
- **Forgetting non-filesystem sources.** A filesystem-only timeline misses registry, log, and memory events — the attacker's actual actions.
- **Overlooking timestomping.** Mismatched `$STANDARD_INFORMATION` vs `$FILE_NAME` times are a red flag, not a curiosity.
- **Reading ordering as causation.** "B followed A" and "A caused B" are different sentences. Use the second only with an argument.
- **Presenting a timeline without its provenance.** The storage file name, the tool version, the source list and the filters all belong in the report; a CSV with no method behind it is not reproducible.
- **Tip:** record the system time zone and clock offset of every machine at acquisition (Phase 01) — your Phase 03 analysis depends on it.
- **Tip:** keep hypotheses explicit; use the timeline to *test* them, not to confirm what you already believe.
- **Tip:** grade every event you cite (A–D above) and carry the grade into the report. It is the cheapest credibility you will ever buy.
- **Tip:** when two sources disagree about a time, write both and explain the disagreement. A report that quietly picks one will be questioned; one that shows the reasoning will not.

## Checklist / Self-Test

- [ ] Can I explain the difference between a timeline and a supertimeline?
- [ ] Can I name at least five artifact classes that contribute timestamps, and one artifact each?
- [ ] Do I know what MACB stands for, what each timestamp indicates, and which of the four is least reliable?
- [ ] Can I state the two NTFS timestamp sets and why their disagreement matters?
- [ ] Can I choose between a bodyfile timeline, a plaso supertimeline and rule-based EVTX triage, and justify the choice?
- [ ] Can I write a bodyfile record and describe each of its fields?
- [ ] Can I describe the plaso pipeline (collect → storage → export) and give example commands, and how I would confirm the CLI form for my release?
- [ ] Can I verify that a plaso run actually parsed the sources I expected, rather than assuming it did?
- [ ] Can I measure clock skew between two sources using a shared event, and describe what I would do with the result?
- [ ] Can I describe the daylight-saving failure mode and how I would handle a window that spans a transition?
- [ ] Can I explain why UTC normalization and clock-skew checking matter before correlating events?
- [ ] Can I run the reading loop — anchor, window, pivot, widen, record, export — on a timeline I built myself?
- [ ] Can I grade a timeline event A–D and explain why the grade changes the wording of my conclusion?
- [ ] Can I correlate a filesystem event, a registry event, and a log event into one coherent attack narrative, with the interpretation column labelled as inference?
- [ ] Do I know how mismatched `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps indicate tampering?
- [ ] For my last timeline, can I state the filter that produced each cited subset, and where the unfiltered output is stored?

## Further Resources

- **plaso documentation** — https://plaso.readthedocs.io/
- **log2timeline / plaso project** — https://github.com/log2timeline/plaso
- **The Sleuth Kit `mactime` and bodyfile documentation** — https://www.sleuthkit.org/sleuthkit/man/mactime.html
- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **RFC 3227**, *Guidelines for Evidence Collection and Archiving* (why ordering and time handling start at acquisition) — https://www.rfc-editor.org/rfc/rfc3227
- **Forensics Wiki** (timeline analysis and tooling overviews) — https://forensics.wiki/
- **SANS reading room** (white papers on timeline analysis) — https://www.sans.org/reading-room/

> **Verification:** the Sleuth Kit half was executed on **2026-09-19** against **The Sleuth Kit
> 4.12.1** (Ubuntu 24.04 WSL). On an ext4 image built in `/tmp` with `mkfs.ext4`, the corrected
> pipeline ran end to end: `fls -f ext4 -o 0 -r -p -m /lab test.img` followed by
> `ils -f ext4 -o 0 -e -m test.img >> body.txt` (then `mactime -b body.txt -d -z UTC`) produced the
> CSV, with the `/lab` mount prefix on the `fls` rows. `ils -e -o 0 -m test.img` alone exited 0 and
> wrote 4098 records — and note that its name field is an inode, `<test.img-alive-1>`, not a path.
> The form printed in the guides, `ils -o 0 -m / test.img`, exited 1 with no stdout
> (`Invalid magic value (raw_open: image "/" - is a directory)`), contributing nothing to the
> bodyfile. The plaso half was then executed too, against **plaso 20260720** (`/opt/pytools/bin/`) on
> the same date, and it both confirms and qualifies the examples above. Confirmed:
> `log2timeline --storage-file=case.plaso disk.img` runs to `Processing completed.` and writes the
> storage file (53 248 bytes over a 16 MiB ext4 image); `--help` documents `--storage_file PATH,
> --storage-file PATH` as one option with two spellings; `pinfo case.plaso` prints the per-parser
> breakdown this file tells you to read (`Events generated per parser: filestat : 12`); `psort -o
> l2tcsv -w timeline.csv case.plaso` exits 0 and writes the CSV, so the positional storage file is
> right. Qualified — three differences from the examples above, recorded but **not** changed, as
> they fall outside this pass: (1) the output module is `l2tcsv`, not `csv` — `psort -o csv …`
> fails with `ERROR: Unsupported output format: csv.`; the installed release can be asked to list its
> own modules (the option is `--output-format list`, spelled with a hyphen) and it answers
> `l2tcsv, dynamic, json, json_line, kml, l2ttln, null, opensearch, opensearch_ts, rawpy, tln, xlsx`
> — there is no `csv` and no `jsonl`; (2) the **filter must follow
> the storage file** — the order printed above (`-w out.csv "<filter>" case.plaso`) fails with
> `ERROR: Unable to compile filter expression with error: Unsupported initial state: OPERATOR -
> premature end of expression at position 10: case.plaso <--->`, because the path is consumed as the
> filter, and `psort -o l2tcsv -w out.csv case.plaso "parser == 'filestat'"` exits 0; and (3) this
> release installs the entry points **without** the `.py` suffix (`log2timeline`, `psort`, `pinfo`,
> `psteal`), so the `log2timeline.py` spelling in the examples is the legacy one.
