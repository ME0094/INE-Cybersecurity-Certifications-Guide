# Timeline Tools — Bodyfiles, Plaso & EVTX Triage

> eCDFP · Tools — INE Cybersecurity Certifications Study Guide
>
> The tooling that turns acquired evidence into an ordered event list: Sleuth Kit bodyfiles, the plaso/log2timeline pipeline, and rule-based `.evtx` triage — plus how to filter that list, judge its timestamps and report it without fooling yourself. Every command here is a **syntax reference**, reconstructed from tool documentation and intended to be confirmed against the release you installed. This repository ships **no captured command output**, no evidence images and no `.evtx` sets, so nothing below can be pasted anywhere and expected to produce a row.
>
> The conceptual phase — what a supertimeline is, MACB, correlation discipline — lives in [`../methodology/03-timeline.md`](../methodology/03-timeline.md); this file is its tooling companion and does not restate it. All work targets media you own or are explicitly authorised to examine, always on copies, with hashes recorded.

## 1. Three routes, compared before you type anything

The same question ("what happened, in what order?") has three practical routes. They differ in coverage, cost and how much of your conclusion rests on someone else's rules. Pick deliberately.

| Route | Built from | Coverage | Cost | Output | Defensibility | Use when |
| --- | --- | --- | --- | --- | --- | --- |
| **1. TSK bodyfile → `mactime`** | File-system metadata read straight from the image by `fls`/`ils` | Files, directories and inode records only — no registry, no logs, no applications | Low: minutes on a small image, modest RAM, small output | Pipe-delimited bodyfile → CSV/text | High: a short deterministic pipeline you can re-run byte-for-byte | The question is file-system-only, the image is small, or you need one reproducible command you can defend line by line |
| **2. plaso storage → `psort`** | A parser farm over every artefact type it recognises | Broadest: file system, registry, event logs, browsers, dozens of application formats | High: long processing, large storage file, real RAM pressure | Storage file → CSV/JSON/bodyfile in many shapes | High but version-sensitive — record the plaso release | Many sources must be merged into one sequence and you can afford the processing time |
| **3. Rule-based EVTX triage (Hayabusa / Chainsaw)** | Only the Windows event logs you collected | Windows logs only | Low: minutes over a directory of `.evtx` | CSV/JSON of rule matches; raw dumps | Medium alone — an interpretation built on a ruleset and a mapping file | The question is Windows-side behaviour and you need a ranked lead list fast |

Routes are not exclusive, and the usual sequence is 3 → 1/2: triage the logs for leads, then corroborate each lead against the file system and registry, where the evidence for *what changed on disk* actually lives.

> Coverage first: any route reports "nothing" when it was given nothing. Before reading an empty result as absence, confirm what you fed in (Section 7).

## 2. Route 1 — bodyfile with `fls`/`ils`, timeline with `mactime`

`fls` and `ils` are covered as file-system tools in [`forensic-toolkit.md`](forensic-toolkit.md) — including the partition offset habit (`-o`) that makes or breaks every one of these commands. Here the subject is the flag that turns them into timeline input: `-m`, which switches the output to **mactime format** and, in `fls`, prefixes every path with the mount point you supply. `ils -m` is the same flag but takes **no** argument — there is no prefix to give it.

```bash
# One bodyfile per source. Name it after the exhibit, not "body.txt":
# the mount prefix is the only thing that tells a later reader which image a row came from.
fls -f ntfs -o 2048 -r -p -m /case001/disk /evidence/case001/disk.dd > /evidence/case001/body-disk.txt
# what to look for: one pipe-delimited line per file, every path carrying the /case001/disk prefix

# Append inode-level records, including unallocated inodes, to the same bodyfile.
# ils -m takes no argument, so these records carry no mount prefix of their own —
# another reason to keep one bodyfile per source.
ils -o 2048 -m /evidence/case001/disk.dd >> /evidence/case001/body-disk.txt
# what to look for: appended inode records that give deletion and allocation context fls alone does not

# Convert the bodyfile into a sorted, human-readable CSV in UTC
mactime -b /evidence/case001/body-disk.txt -d -z UTC > /evidence/case001/timeline-disk.csv
# what to look for: a UTC date column, and a row count in the same order of magnitude as the bodyfile's line count
```

`-d` selects comma-delimited output; without a zone flag the dates are rendered in whatever the tool assumes, which is how mixed-zone timelines are born.

### The bodyfile field layout

Eleven pipe-delimited fields per record, one record per event:

```text
MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
# what to look for: eleven fields in exactly this order — a record with a different field count is a corrupt or hand-edited bodyfile
```

| # | Field | What it is | Reading note |
| --- | --- | --- | --- |
| 1 | `MD5` | Content hash, when one was computed | Usually `0` in a `fls`/`ils` bodyfile — do not read it as a mismatch |
| 2 | `name` | Full path, mount prefix included | This is your only source attribution: make the prefix unique per image |
| 3 | `inode` | Inode / MFT record number | Joins the timeline back to `icat`, `istat`, `ils` |
| 4 | `mode_as_string` | TSK mode string (`r/r`, `d/d`, …) | The `*` marker of a deleted entry rides in here |
| 5–6 | `UID`, `GID` | Numeric owner | Only meaningful with the image's own passwd/group resolution |
| 7 | `size` | Size in bytes | For a directory record, not a content size |
| 8–11 | `atime`, `mtime`, `ctime`, `crtime` | Access, modify, inode-change, birth | Epoch seconds; `0` means the file system did not record that time |

Each of the four times becomes its own row in the mactime output, which is why one file produces up to four timeline events.

### Why it scales badly, and what it silently omits

- **One source at a time.** Recent TSK releases accept more than one `-b`, which merges bodyfiles into a single sorted timeline — confirm with `man mactime` on your build. Even then, merging shifts the work onto you: nothing deduplicates, and nothing reconciles two machines' clocks.
- **No merge with non-file-system evidence.** Registry last-write times, event logs, prefetch, amcache, browser history and memory artefacts do not enter a bodyfile unless another tool composes one for them. A bodyfile-only timeline is a *file-system* timeline and should be labelled as such.
- **Metadata, never content.** The bodyfile says a file existed, was sized, and carried four times. It never says what the file did, who ran it, or what the log recorded.
- **No provenance column.** Once two sources are merged, the mount prefix is the only thing distinguishing them — which is why `-m /case001/disk` beats `-m /`.
- **Access times are weak evidence.** `atime` moves on backups, antivirus scans and indexers. Correlation discipline for that judgement is in [`../methodology/03-timeline.md`](../methodology/03-timeline.md).

Its virtue is that it is short, fast, and re-runnable from the hash-verified image in one line — which is exactly what a report appendix needs. The lab version of this pipeline is in [`../labs/forensic-exercises.md`](../labs/forensic-exercises.md).

## 3. Route 2 — plaso: collect, export, inspect

plaso's design is a split you should keep split: **collect** once into a storage file, then **export and filter** as many times as the investigation needs. Re-parsing an image because you wanted a different filter is the most common way to waste a day.

**What the storage file is.** A single container holding every parsed event, each tagged with its source, parser and timestamp basis, plus a provenance section describing where the events came from (current releases back it with SQLite). It is usually the largest artefact you produce and the one you must keep: it is the input to every export, and its hash belongs in the report next to the image's.

**The CLI moves between releases.** The plaso section of [`../methodology/03-timeline.md`](../methodology/03-timeline.md) already warns about this, and every example in this repository is consistent with itself: the `--storage-file=` form is what this file, the methodology phase and [`../cheatsheets/forensic-commands.md`](../cheatsheets/forensic-commands.md) all use. Older plaso generations accepted the storage file positionally, and that form still circulates in tutorials; ask the installed release instead of trusting either.

```bash
# First action on any new machine: ask the tools what they accept
log2timeline.py --help
psort.py --help
pinfo.py --help
psteal.py --help
# what to look for: the storage-file option, the output-module flag, and where the filter expression must sit in the argument list
```

### Collect

```bash
# One storage file per case, pointed at the image (or at an extracted evidence tree)
log2timeline.py --storage-file=/evidence/case001/case001.plaso /evidence/case001/disk.dd
# what to look for: per-parser progress and a completion line; a storage file that exists and is not empty

# The same storage file accumulates sources — run log2timeline again for extra inputs
log2timeline.py --storage-file=/evidence/case001/case001.plaso /evidence/case001/extracted_logs/
# what to look for: parsers running for the second source while the first source's events remain

# Inspect before exporting: this is the cheapest sanity check in the whole route
pinfo.py /evidence/case001/case001.plaso
# what to look for: total event count and per-parser counts — a parser sitting at zero is your first skipped-format clue
```

Processing cost is dominated by artefact *density*, not image size: a log-heavy source costs far more per gigabyte than a disk full of media, and it inflates the storage file disproportionately. Budget disk headroom generously, measure on a small lab image (the module's practice images are deliberately small, see [`../README.md`](../README.md)) and only then commit a production case to it.

### Export and filter

```bash
# Full export. This is the file that gets unmanageably large — see Section 7.
psort.py -o l2tcsv -w /evidence/case001/timeline-all.csv /evidence/case001/case001.plaso
# what to look for: a header row, and a row count consistent with the event count pinfo reported

# Narrow export: a date window plus a parser expression, as one quoted argument.
# `l2tcsv` is the CSV module (`-o csv` does not exist; `-o json_line` is the JSON-lines one),
# and the filter is a positional argument that belongs AFTER the storage file.
psort.py -o l2tcsv -w /evidence/case001/prefetch-window.csv \
  /evidence/case001/case001.plaso \
  "date > '2024-11-03 09:00:00' and date < '2024-11-03 09:05:00' and parser == 'prefetch'"
# what to look for: every row inside the window, and nothing outside it — a stray row means your timezone assumption is wrong, not that the tool is broken

# One-shot triage: collect and export in a single command, useful for a first look.
# `--output` alone is ambiguous in current releases; name the option in full.
psteal.py --source /evidence/case001/disk.dd \
  --storage-file=/evidence/case001/case001.plaso \
  --output-format l2tcsv --write /evidence/case001/triage.csv
# what to look for: the same two artefacts a two-step run would leave (storage file plus export), so nothing is lost if you later want a different filter
```

Filter expressions are release-specific: `date` comparisons and `parser == '...'` appear in this repository's own examples, and `source_short is 'WEBHIST'` appears in the eCIR module's. Confirm the operators your release accepts against its filter documentation — reachable from `psort.py --help` — before you build a filter you will have to reproduce in a report.

**Output modules.** The ones this repository already refers to are `l2tcsv`/`csv` (flat tables for a spreadsheet or a database) and `json`/`jsonl` (for scripting and for feeding a viewer). Run `psort.py --help` to list what your release ships rather than assuming a module name from a tutorial.

**Store UTC, display local.** plaso records events in UTC and the display zone is chosen at export; the methodology file makes the same point. Pick one display zone for the whole case, write it into the method record (Section 8), and never mix a UTC filter with a local-time report — that is where phantom "five-minute gaps" come from.

## 4. Route 3 — EVTX as evidence

The hunting treatment of Hayabusa and Chainsaw is in [`../../eCTHP/tools/endpoint-tools.md`](../../eCTHP/tools/endpoint-tools.md) (sections 8–9): what the tools are, how to configure them and how to hunt with them. This section is about the different job — treating `.evtx` as an **exhibit**, and being honest about what a rule match is worth.

### Get the channels off the machine properly

Events live as files under `C:\Windows\System32\winevt\Logs\`. On a live host, copy the *channel*, not the file: the Event Log service holds those files open, and a plain file copy can fail with a sharing violation or succeed while missing the newest records.

```cmd
:: Export through the Event Log API — a consistent snapshot that works on a live host
wevtutil epl Security C:\case001\evtx\Security.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\case001\evtx\Sysmon.evtx
:: what to look for: one file per channel, opening and parsing cleanly in an offline tool — a zero-byte or unparseable file means the export failed, not that the channel was empty
```

On a dead-box image the equations change: the files are static, so a hash-verified copy is the right move, and the image itself is the provenance.

```bash
# Locate the log files on the imaged volume before deciding what to extract
fls -f ntfs -o 2048 -r -p /evidence/case001/disk.dd | grep -i 'winevt/Logs'
# what to look for: which channels actually exist on this disk — an expected channel that is absent is itself a finding to explain

# Extract one channel by inode (see forensic-toolkit.md for icat and how to obtain the inode)
icat -f ntfs -o 2048 /evidence/case001/disk.dd 12345 > /evidence/case001/evtx/Security.evtx
# what to look for: an extracted file beginning with the EVTX signature ("ElfFile") that parses offline; hash it straight away
```

### What the triage tools produce

```cmd
:: Hayabusa: rules first, then one timeline across the collected set
hayabusa.exe update-rules
hayabusa.exe csv-timeline -d C:\case001\evtx\ -o C:\case001\out\timeline.csv
hayabusa.exe json-timeline -d C:\case001\evtx\ -o C:\case001\out\timeline.json
:: what to look for: how many rules the run loaded, the per-hit rule name, level, channel and timestamp, and any tool warning about rules it could not apply
```

```bash
# Chainsaw: rule hits, plus the raw dump that is the completeness check no rule can give you
chainsaw hunt C:/case001/evtx/ -s C:/case001/sigma-rules/ \
  --mapping C:/case001/chainsaw/mappings/sigma-event-logs-all.yml -o C:/case001/out/
chainsaw dump C:/case001/evtx/
# what to look for: hits that name both the rule that fired and the source file — and, in the dump, the events the rules never looked for
```

Flag names and profiles have moved between releases for both tools (the same caveat is recorded in `endpoint-tools.md`). Verify against `hayabusa.exe help` and `chainsaw hunt --help` on the version you actually run.

### What a rule-match timeline is worth as evidence

- **It is a lead generator, not evidence.** The match is somebody's interpretation of a raw event; the *raw event* is the evidence, and the summary is the index to it. `endpoint-tools.md` states this directly: a CSV of rule hits is a summary, not a record. Attach the underlying event — exported channel, or the raw XML for the single event — as the exhibit.
- **It cannot be reproduced without the rules.** Record the ruleset version or commit, the mapping file and its hash, the tool version and the exact command line. A rule-match list with none of that is an assertion.
- **Silence proves nothing.** A behaviour nobody wrote a rule for produces no row at all, which looks identical to a clean environment; a stale mapping fails the same silent way.
- **It inherits the audit-policy problem.** If `4688`, command-line auditing or script block logging were off on the host, the event never existed, and no rule can match it. Check what was being logged before interpreting an absence.
- **Expect false positives and say so.** Report how many hits you reviewed and dismissed, not only the ones you kept. A triage list presented without its precision is a misleading exhibit.
- **Keep the inputs.** The exported `.evtx` set, its hashes, the ruleset and mapping, and the tool binaries/versions are what make the output defensible months later.

## 5. Reading a timeline like an analyst

A timeline is not read from the top. It is *interrogated*, in a loop that starts narrow, widens only under a reason, and ends in an exported artefact that someone else could regenerate.

1. **Anchor on something you already know** — the alert time, a hash hit, the acquisition timestamp, a user's report. Unknown rows get meaning only relative to a known one; the methodology file calls this known-event anchoring.
2. **Open a narrow window** around the anchor. Minutes, not days, on the first pass.
3. **Pivot on entities**, not on time: the same process name, account, path, key or address across event types. Repetition across independent sources is what turns a row into a finding.
4. **Corroborate before you conclude.** One artefact is a lead; two independent artefacts that agree are a finding — the module's evidence-handling principle.
5. **Widen only when the question changes** — not because the window felt thin. If you widen, write down why.
6. **Export the filtered subset as an exhibit**, and record the filter verbatim.

```bash
# Steps 1-2: anchor plus a narrow window. The storage file is reused — nothing is reparsed.
psort.py -o l2tcsv -w /evidence/case001/exhibits/E05-window.csv \
  "date > '2024-11-03 09:00:00' and date < '2024-11-03 09:05:00'" \
  /evidence/case001/case001.plaso
# what to look for: the anchor event sitting inside the window — if it is absent, suspect the anchor's timezone before you suspect the data

# Step 3: entity pivot across the whole storage file rather than the window
psort.py -o l2tcsv -w /evidence/case001/exhibits/E06-entity.csv \
  "parser == 'prefetch' or parser == 'winreg' or parser == 'winevtx'" \
  /evidence/case001/case001.plaso
# what to look for: the same entity reappearing under different parsers — that coincidence is the corroboration you are looking for

# Step 6: hash the exhibit and file the filter next to it
sha256sum /evidence/case001/exhibits/E05-window.csv
# what to look for: a digest you can quote in the report beside the exact filter string that produced the file
```

For the bodyfile route the same pivots are plain text operations, which is its quiet advantage:

```bash
# Reduce before you sort: keep one tree, then timeline only that
grep '/Windows/Temp/' /evidence/case001/body-disk.txt > /evidence/case001/body-temp.txt
mactime -b /evidence/case001/body-temp.txt -d -z UTC > /evidence/case001/exhibits/E07-temp.csv
# what to look for: whether the file you care about appears where the file-system metadata says it should — and hash both the input subset and the output
```

> **A filter is part of your method.** A filtered timeline that cannot be regenerated is an unsupported opinion. Write the filter down exactly as typed — not paraphrased — together with the tool version, the storage file's hash and the display zone. Note also what the filter *excluded*: the interesting rows in a real case are often the ones a hurry would have filtered away.

## 6. Timestamp trust

Every row in a timeline is an assertion about time. Test the assertion before you build on it.

| Situation | What you are actually looking at | Trust | What to do |
| --- | --- | --- | --- |
| NTFS `$STANDARD_INFORMATION` vs `$FILE_NAME` times | Two independent timestamp sets in the same MFT record, updated by different code paths | Neither alone | Compare both; a mismatch is the classic timestomping indicator, not a curiosity |
| Bodyfile / `mactime` times | Which NTFS attribute the release's mactime format reads | Depends on the release | Confirm with `man fls` on your build, and cross-check one file against `istat`, which shows both attribute sets |
| Two hosts, same case | Wall clocks that were never synchronised | Low until anchored | Anchor to a source with its own reliable time — domain controller, firewall, router |
| Filter says one thing, report says another | A display zone chosen twice, differently | Fabricated precision | Fix one zone per case, in UTC, and state it |
| Rows one second apart | Timestamps whose precision is coarser than the ordering you want | Over-read | Events inside one granularity unit are *concurrent*, not sequential |

Notes that decide real arguments:

- **Clock skew and NTP drift** shift a whole host's timeline, uniformly, by minutes or hours. Capture the host's time configuration while you still can.
- **Precision differs by source.** NTFS and event logs carry 100-nanosecond resolution; FAT write times are coarse (seconds at best); many log providers only populate whole seconds. Never claim an ordering finer than the coarsest source in the comparison.
- **Time zone is a property of the host at the time of the event**, and hosts change zones when a user travels. Record the zone and corroborate a mid-case change in the System channel rather than silently re-rendering the timeline.
- **Carved files have no timestamps at all** — carving destroys the metadata that carried them (`forensic-toolkit.md` makes the same point). Recovered-by-carving artefacts belong in a separate section of the report, not in the timeline.
- **An event with no timestamp cannot join a timeline.** If an artefact carries only a relative order, a sequence number, or no time field at all, record it as supporting evidence alongside the timeline and say why it is not a row.

```powershell
# Windows: record the host's time story as part of the acquisition record
w32tm /query /status
# what to look for: the time source (domain, NTP, or local CMOS) and the last successful sync — a host on its own CMOS has a weaker clock story

Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation'
# what to look for: the zone in force when you read it — history needs corroboration, this only proves the present
```

```bash
# Linux: same question, different tools
timedatectl
# what to look for: whether the clock is synchronised and which zone the host considered local

chronyc tracking     # when chrony is the time daemon
# what to look for: the reported offset — a large last offset explains a whole-timeline shift
```

## 7. Failure diagnosis

| Symptom | Likely cause | Check |
| --- | --- | --- |
| plaso dies partway through | Storage file filled the volume, or a worker exhausted RAM | Free space on the storage volume; the release's worker/processing memory-limit option in `log2timeline.py --help`; process one source at a time |
| A whole artefact class is missing from the storage file | The format was unsupported or the parser never engaged — silently | Per-parser counts from `pinfo.py`; the processing log |
| `psort` errors on the filter | Expression quoting, a `==`/`is` the release does not accept, or the expression placed before the storage file | Simplify to a single clause, re-add clauses one at a time; confirm argument order with `psort.py --help` |
| The CSV is far too large to open | Every event, unfiltered, in a spreadsheet | Re-filter from the storage file; query the CSV in a database instead of a GUI |
| `mactime` prints nonsensical dates | Epoch or offset error: wrong `-z`, wrong `-o`, or a bodyfile built against a different time base | `head`/`tail` the CSV — dates at 1970, 1601 or 2038 mean a mistake, not a finding |
| An `.evtx` will not parse, or parses without recent events | It was copied while in use | Re-export through the Event Log API, or extract the file from the image instead |
| The timeline "is empty" | No events in the window, wrong channel, an unsupported format, or a filter/zone mismatch | Confirm the input actually contains events before touching the filter |

```bash
# Did the bodyfile get anything at all?
wc -l /evidence/case001/body-disk.txt
head -1 /evidence/case001/body-disk.txt
# what to look for: a plausible line count and a first record whose fields are pipe-separated in the documented order, not an error message

# Is the storage file populated, and by which parsers?
pinfo.py /evidence/case001/case001.plaso
# what to look for: a non-zero event count and a parser breakdown — a parser at zero means unsupported format, which is not the same as absent activity
```

```bash
# Date sanity before you trust any ordering, on either route
head -3 /evidence/case001/timeline-disk.csv
tail -3 /evidence/case001/timeline-disk.csv
# what to look for: dates inside the window you expect, at both ends — a 1970/1601/2038 boundary is an epoch or timezone error, never evidence
```

**When the export is too big for a spreadsheet.** Spreadsheets cap out around a million rows, and even below that limit they mangle long paths and silently rewrite date formats. Do not open the export; query it.

```bash
# Load the CSV into a database and ask questions with SQL (sqlite3 CLI with .import --csv)
sqlite3 /evidence/case001/timeline.db ".import --csv /evidence/case001/timeline-all.csv events"
sqlite3 /evidence/case001/timeline.db "SELECT count(*) FROM events;"
# what to look for: a row count matching the export, then WHERE clauses instead of scrolling — check '.help import' if your sqlite3 is older than 3.32
```

The other two answers are better still: re-filter from the storage file so you never materialise the whole thing, or load the case into a timeline viewer built for millions of events (see Further Resources). For a quick look at a CSV too large for an editor, `grep` on the entity of interest beats opening the file.

## 8. Evidence handling for a derived artefact

A timeline is a **derived artefact**: it is produced *from* evidence and is not itself the evidence. Everything that follows from that is an obligation.

- **Authorisation and scope, in writing, before the first command.** Media you own or were explicitly authorised to examine; nothing else.
- **Work on copies.** The image, the extracted `.evtx` set and the exported files are all copies; the source is never mounted read-write and never written to.
- **Hash the inputs and the outputs.** Source and image hashes prove a sound copy; hashes of the bodyfile, storage file and every exported exhibit tie the report's claims to the files that were actually produced.
- **Preserve what the timeline was derived from.** Deleting the storage file after exporting a CSV makes the CSV unreproducible. The inputs are exhibits too: image, extracted channels, bodyfile, storage file.
- **Record tool and version for every step.** "plaso" is not a version; the reporting phase requires the release, and a filter's meaning can change between them.
- **Never hand-edit a timeline to fix ordering.** Re-filter and re-export instead. If annotation is unavoidable, do it in a separate copy with a separate column, and disclose it in the report.
- **State limitations.** Missing channels, a wrapped Security log, disabled auditing, clock skew, an unsupported format — those limit what you can conclude, and stating them strengthens the report rather than weakening it.
- **File exhibits consistently and reference them by number** so a finding points at an artefact a reviewer can open.

```text
# Method record — one per derived timeline artefact (fill every field, no blanks)
Artefact:    CASE-001-Exx  <what it is: window / entity pivot / full timeline>
Input:       <exhibit id> (SHA-256 <hash>), storage file <name> (SHA-256 <hash>)
Tool:        <tool> <version>   (e.g. psort.py from plaso <release>; mactime from TSK <release>)
Command:     <verbatim, including the exact filter expression and quoting>
Timezone:    stored UTC; displayed <zone>
Output:      <format, path> (SHA-256 <hash>)
Examiner:    <name>, <date and time UTC>
Limitations: <what the artefact cannot show>
# what to look for: every field filled in, no blanks — an unfilled field is the gap a reviewer will find first
```

## Common Mistakes & Tips

- **Presenting a rule-match CSV as evidence.** It is an index to the raw events, and the rules that produced it are a version you must record. Keep the exported logs.
- **Re-parsing the image for every new question.** Filter the storage file instead — that is the entire reason plaso has two phases.
- **Losing source attribution in a bodyfile.** `-m /` on three images produces three indistinguishable timelines; make each mount prefix name its exhibit.
- **Labelling a bodyfile timeline as "the timeline".** It is the *file-system* timeline. Registry, logs and application artefacts are absent, and their absence is not evidence of inactivity.
- **Opening the export in a spreadsheet.** Long paths get truncated, dates get reinterpreted, and rows silently fall off the bottom. Query the CSV or, better, re-filter.
- **Trusting dates before sanity-checking them.** Three lines from the head and three from the tail catch the epoch and timezone mistakes that otherwise reach a report.
- **Mixing display zones between the filter and the narrative.** Decide UTC once and enforce it; record the zone in the method note.
- **Reading an empty result as "nothing happened".** Confirm coverage — channel present, auditing enabled, parser ran, window correct — before you write the word "no".
- **Analysing the only copy.** Timelines are built on copies; the original stays pristine and hashed.
- **Forgetting that the tool's flags are a moving target.** Every command in this file is a syntax reference. Ask `--help` (or `help`, on Windows binaries) on the release you installed, and quote that release in the report.

## Checklist / Self-Test

- [ ] I can name the three routes and pick one for a stated question, with a reason for the coverage/cost trade-off.
- [ ] I built a bodyfile with `fls -m` and `ils -m`, and can describe each of the eleven fields in order.
- [ ] I produced a UTC CSV with `mactime -b … -d -z UTC` and read a deletion out of it.
- [ ] I can explain why a bodyfile timeline is a file-system timeline, and name two artefact classes it never contains.
- [ ] I ran `log2timeline.py --help`, `psort.py --help` and `pinfo.py --help` on my own installation and confirmed the storage-file and output-module options.
- [ ] I built a storage file, inspected it with `pinfo.py`, and exported a date-windowed, parser-filtered CSV from it.
- [ ] I can state what the plaso storage file is and why its hash belongs in the report.
- [ ] I exported an `.evtx` channel with `wevtutil epl`, hashed it, and parsed it offline.
- [ ] I generated a Hayabusa or Chainsaw timeline and can name the exact rule version and mapping file it used.
- [ ] I can explain why a rule match is a lead and the raw event is the evidence.
- [ ] I anchored a timeline on a known event, opened a minutes-wide window, and pivoted on an entity across two parsers.
- [ ] I exported a filtered subset as an exhibit and recorded the filter verbatim alongside its hash.
- [ ] I can state the `$STANDARD_INFORMATION` versus `$FILE_NAME` mismatch and what it indicates.
- [ ] I recorded a host's time source, time zone and synchronisation state as part of acquisition.
- [ ] I keep the inputs to every timeline I produce — image, extracted logs, bodyfile, storage file — and can regenerate any exhibit from them.
- [ ] Every artefact I analysed came from media I own or was authorised to examine.

## Further Resources

- **plaso documentation** — https://plaso.readthedocs.io/
- **plaso / log2timeline project** (releases, release notes, changing CLI) — https://github.com/log2timeline/plaso
- **The Sleuth Kit man pages** — `mactime` at https://www.sleuthkit.org/sleuthkit/man/mactime.html and `fls` at https://www.sleuthkit.org/sleuthkit/man/fls.html
- **Timesketch** (collaborative timeline analysis for millions of events) — https://timesketch.org/
- **Hayabusa** — https://github.com/Yamato-Security/hayabusa
- **Chainsaw** — https://github.com/WithSecureLabs/chainsaw
- **Sigma** (the rule format both tools consume) — https://github.com/SigmaHQ/sigma
- **EvtxECmd / Evtx project** (independent EVTX parsing for cross-checking) — https://github.com/EricZimmerman/evtx
- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **Local help on your practice system** — `man mactime`, `man fls`, `man ils`, `log2timeline.py --help`, `psort.py --help`, `hayabusa.exe help`.
- **In this repository** — [`../methodology/03-timeline.md`](../methodology/03-timeline.md) (the conceptual phase), [`forensic-toolkit.md`](forensic-toolkit.md) (`fls`/`ils` basics), [`../cheatsheets/forensic-commands.md`](../cheatsheets/forensic-commands.md) (compact command sheet), [`../../eCTHP/tools/endpoint-tools.md`](../../eCTHP/tools/endpoint-tools.md) (Hayabusa and Chainsaw from the hunting angle), [`../labs/forensic-exercises.md`](../labs/forensic-exercises.md) (the bodyfile-to-CSV drill).

> **Verification:** the bodyfile half was executed on **2026-09-19** against **The Sleuth Kit
> 4.12.1** (Ubuntu 24.04 WSL). On an ext4 image built in `/tmp` with `mkfs.ext4`,
> `fls -f ext4 -o 0 -r -p -m /lab test.img` produced records carrying the `/lab` prefix, and
> `ils -o 2048 -m /evidence/case001/disk.dd` (the form previously printed here) exits 1 with no
> stdout — `Invalid magic value (raw_open: image "/" - is a directory)` — while
> `ils -o 0 -e -m test.img` exits 0 and writes 4098 records whose name field is an inode, not a
> path, which is why the note about the missing mount prefix was added. `mactime -b body.txt -d -z
> UTC` then produced the CSV. The plaso route was executed too, against **plaso 20260720**
> (`/opt/pytools/bin/`) on the same date: `log2timeline --storage-file=case.plaso disk.img` completed
> and wrote the storage file, `pinfo case.plaso` printed the per-parser breakdown this file tells you
> to read (`filestat : 12`), and `psort` exported it. Four differences from the examples above were
> measured and are recorded rather than changed, as they fall outside this pass. (1) `-o csv` is not
> an output module in this release: `psort -o csv …` fails with `ERROR: Unsupported output format:
> csv.`, and `psort --output-format list` offers `l2tcsv, dynamic, json, json_line, kml, l2ttln,
> null, opensearch, opensearch_ts, rawpy, tln, xlsx` — so `l2tcsv` (which section 3 already uses)
> works and `csv`/`jsonl` do not. (2) The filter must come **after** the storage file, which is the
> reverse of the order printed here: `-w out.csv "<filter>" case.plaso` fails with
> `ERROR: Unable to compile filter expression with error: Unsupported initial state: OPERATOR -
> premature end of expression at position 10: case.plaso <--->`, while `-w out.csv case.plaso
> "<filter>"` exits 0. This file's own diagnosis table already lists "the expression placed before
> the storage file" as a failure mode, so the examples above contradict it. (3) `psteal --output` is
> ambiguous in this release — `psteal --source … --output csv` exits 2 with `psteal: error: ambiguous
> option: --output could match … --output_format, --output-format`; `--output-format l2tcsv` exits 0.
> (4) The entry points have **no** `.py` suffix here (`log2timeline`, `psort`, `pinfo`, `psteal`).
> A filter that compiles can also still return zero rows: `"parser == 'filestat'"` returned a
> header-only CSV while `pinfo` reported 12 events under `filestat`; the cause was not established,
> so treat a filtered count as something to verify against `pinfo`. **Not executed:** the EVTX triage
> tools (`hayabusa`, `chainsaw` are not installed here).
