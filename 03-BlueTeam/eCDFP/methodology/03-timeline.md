# Timeline Analysis (eCDFP Methodology — Phase 03)

> Companion study guide for the eCDFP (Certified Digital Forensics Professional) Blue Team methodology track. This phase answers the investigator's core question — *what happened, in what order?* — by merging timestamps from many artifact classes into one browsable sequence of events.

## Overview

Individual artifacts tell you *something happened*; timelines tell you *when and in what sequence*. The goal of timeline analysis is to reconstruct user and attacker activity by correlating timestamps across the filesystem, registry, logs, and (when available) memory captures.

Two terms are worth knowing precisely:

- **Timeline** — events from one source or a narrow question (e.g., "what executables ran?").
- **Supertimeline** — every timestampable event from *all* sources merged and sorted. The concept was popularized by Harlan Carvey; plaso is the tool most associated with building them today.

A supertimeline is intentionally noisy — its power is that you can *filter* it down to a focused timeline for a specific question.

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

## The Bodyfile Format

Many timeline tools normalize timestamps into a **bodyfile**: one pipe-delimited record per event. Tools like `fls`/`ils` (with `-m`) and `mactime` (TSK) use it; it is also the interchange format behind many GUI timelines.

```
MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
```

```bash
# Build a bodyfile from an image (Sleuth Kit classic workflow)
fls -o 2048 -r -m / image.dd > body.txt    # -m adds mount point to paths
ils -o 2048 -m / image.dd >> body.txt      # add unallocated inode metadata

# Generate a sorted timeline in CSV from the bodyfile
mactime -b body.txt -d > timeline.csv
```

The bodyfile approach scales poorly across *many* sources, which is why plaso exists — but understanding the format explains what every timeline tool is doing under the hood.

## Building Timelines with plaso / log2timeline

**plaso** (formerly *log2timeline*) parses an enormous set of artifact types — filesystem metadata, registry hives, event logs, browsers, and dozens of application formats — into a single **storage file** you can then filter and export.

The pipeline has three steps:

1. **Collect** — `log2timeline.py` parses sources into a plaso storage file.
2. **Filter/export** — `psort.py` sorts, filters, and converts to CSV, JSON, etc.
3. **Inspect** — `pinfo.py` and `psteal.py` (a collect-and-export shortcut) support triage.

```bash
# Parse the filesystem artifacts of an image into a storage file.
# NOTE: CLI forms vary between plaso releases; run <tool> --help to confirm.
log2timeline.py --storage-file=case.plaso image.dd

# Add additional extracted sources (e.g., event logs pulled from the image)
log2timeline.py --storage-file=case.plaso /case/evidence_extracted_logs/

# Dump the whole supertimeline as sorted CSV
psort.py -o csv -w timeline.csv case.plaso

# Filter: only events after a date, from the prefetch parser
psort.py -o csv -w prefetch.csv \
  "date > '2024-11-01 00:00:00' and parser == 'prefetch'" case.plaso
```

```bash
# One-shot alternative for quick triage: parse and export in a single command
psteal.py --source image.dd --storage-file=case.plaso --output csv --write timeline.csv
```

Export formats you will meet: `l2tcsv`/`csv` (flat tables for Excel), `json` (for scripting), and the classic bodyfile. Time-zone handling matters: plaso records timestamps in UTC by default, and you choose the display zone at export — store UTC, display local.

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

## Reconstructing User and Attacker Activity

Timeline analysis pays off when you turn event rows into a narrative mapped to an intrusion or user-action model. A compact example:

| Time (UTC) | Source | Event | Interpretation |
| --- | --- | --- | --- |
| 09:02:11 | Sysmon | `powershell.exe` process create, user `alice` | Initial execution |
| 09:02:14 | Filesystem | `C:\Users\alice\AppData\...\payload.exe` birth | Dropped file |
| 09:02:30 | Registry (Run key) | New value pointing to payload.exe | Persistence |
| 09:03:05 | Network logs | Outbound beacon to 203.0.113.7:4444 | C2 communication |
| 09:04:00 | Event Log | Logon type 3 from `alice` workstation to `FILE-SRV` | Lateral movement |

Chained like this, the rows describe an attack: execution → persistence → command-and-control → lateral movement. The same discipline reconstructs *user* activity: browsing history plus download timestamps plus file births plus document edits tell the story of what a user actually did.

## Common Mistakes & Tips

- **Ignoring clock skew.** Correlating against wall-clock time without accounting for a skewed system clock misplaces events by minutes or hours; anchor to trusted external logs.
- **Mixing time zones.** A timeline half in local time and half in UTC produces phantom sequences; normalize to UTC early.
- **Treating every timestamp as equal.** Access times are unreliable (updates, AV scans); creation times can be forged or copied with a file; prefer corroborated event sets.
- **Filtering before understanding.** Jumping straight to a narrow filter hides the "boring" events that make anomalies visible; explore the supertimeline first.
- **Forgetting non-filesystem sources.** A filesystem-only timeline misses registry, log, and memory events — the attacker's actual actions.
- **Overlooking timestomping.** Mismatched `$STANDARD_INFORMATION` vs `$FILE_NAME` times are a red flag, not a curiosity.
- **Tip:** record the system time zone and clock offset of every machine at acquisition (Phase 01) — your Phase 03 analysis depends on it.
- **Tip:** keep hypotheses explicit; use the timeline to *test* them, not to confirm what you already believe.

## Checklist / Self-Test

- [ ] Can I explain the difference between a timeline and a supertimeline?
- [ ] Can I name at least five artifact classes that contribute timestamps, and one artifact each?
- [ ] Do I know what MACB stands for and what each timestamp indicates?
- [ ] Can I write a bodyfile record and describe each of its fields?
- [ ] Can I describe the plaso pipeline (log2timeline → storage → psort) and give example commands?
- [ ] Can I explain why UTC normalization and clock-skew checking matter before correlating events?
- [ ] Can I correlate a filesystem event, a registry event, and a log event into one coherent attack narrative?
- [ ] Do I know how mismatched `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps indicate tampering?

## Further Resources

- **plaso documentation** — https://plaso.readthedocs.io/
- **log2timeline / plaso project** — https://github.com/log2timeline/plaso
- **The Sleuth Kit `mactime` and bodyfile documentation** — https://www.sleuthkit.org/sleuthkit/man/mactime.html
- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **Forensics Wiki** (timeline analysis and tooling overviews) — https://forensics.wiki/
- **SANS reading room** (white papers on timeline analysis) — https://www.sans.org/reading-room/
