# Supertimeline Lab — Reconstructing an Incident from Timestamps

> eCDFP · Labs — INE Cybersecurity Certifications Study Guide
>
> Stage a small, entirely benign incident on your own `win-lab` VM, acquire it properly, merge its artifacts into one super-timeline, and reconstruct the incident from timestamps alone — scoring yourself against an answer key written **before** acquisition.
>
> Every command here is a **syntax reference**. This repository ships no captured command output: there is no image, no plaso storage file and no EVTX set behind this lab, so nothing here was run. Where a command would print something, this file describes what to look for instead. Confirm every switch, filter field and output module against `--help` / `-h` for the version you actually install.
>
> Everything runs on VMs you own, on an isolated host-only network. Concepts: [03-timeline](../methodology/03-timeline.md). Tooling: [timeline tools](../tools/timeline-tools.md). VM inventory, snapshot chain, evidence workspace and acquisition procedure: [lab-environment.md](lab-environment.md). This lab assumes all three and restates none of them.

## 1. Objective

Build one super-timeline over several sources, read a complete ordered incident out of it, and defend every sentence against the source that supports it. By the end you should be able to:

1. **Construct three timeline routes** over the same evidence — a file-system bodyfile, a plaso super-timeline, and the event-log stream alone — and say what each is blind to.
2. **Correlate across sources** so that each step is corroborated by the next step's artefact instead of assembled from your memory of what you staged.
3. **Distinguish absence from invisibility**: an event that left no trace because the source could not have recorded it is a finding; an empty query result is not.
4. **Produce a defensible derived artefact** — a filtered subset carrying its filter, command, version and hash.
5. **Score yourself against ground truth**, including the step you could not recover and the reason you verified for it.

The deliverable is not the CSV. It is a short narrative in which every claim names the source, the artefact and the time, plus an explicit list of what you could not establish.

## 2. Prerequisites

- **[lab-environment.md](lab-environment.md) built and verified**: both VMs, the toolchain printing its versions ([lab-environment.md:177](lab-environment.md)), the snapshot chain, and `~/lab/<case-id>/` following the workspace convention ([lab-environment.md:197-223](lab-environment.md)).
- **The timeline tooling from [timeline tools](../tools/timeline-tools.md)** on `linux-lab`, plus working familiarity with `fls`/`ils`/`mactime`, `log2timeline.py`/`pinfo.py`/`psort.py`, and one EVTX triage tool. This file uses those tools; it does not re-teach them.
- **Headroom for the parse**: a plaso storage file over a real image is large and the parse is memory- and I/O-hungry ([lab-environment.md:84](lab-environment.md)).
- **An empty answer key** at `~/lab/<case-id>/notes/answer-key.md` ([lab-environment.md:207](lab-environment.md)), written as you stage and sealed before acquisition. If it is not empty when you start, you are about to read someone else's answers.
- **Clock discipline**: both VMs pinned to UTC and the victim's zone recorded ([lab-environment.md:93](lab-environment.md), [lab-environment.md:343](lab-environment.md)).
- **For section 4**: a text editor, an in-lab HTTP source (see the warning in section 4.1), and the willingness to write the answer key by hand as you go.

## 3. Ethics and authorization

This lab stages activity that looks like an intrusion to any automated control. The rules at [lab-environment.md:22-35](lab-environment.md) apply in full; three carry extra weight here.

- **Your own disposable VM, or one covered by written authorization naming scope and window.** Never stage this on a laptop, a work machine, or anything attached to a network you do not own.
- **Snapshot `03-supertimeline-before` first.** Every action in section 4 is undone by reverting to it — that is the whole cleanup. A lab you cannot revert, you cannot repeat.
- **No host integration, no route out.** Shared folders, clipboard, drag-and-drop and shared drives off; the lab subnet has no default route. The download in section 4 comes from a node *inside* the lab, never the internet. Lab-only accounts, lab-only passwords, lab-only documents: no real credentials or personal data anywhere in the victim.

**Why the lab is legitimate.** You cannot learn to reconstruct an incident without knowing the ground truth of one. An unwitnessed machine teaches tool mechanics and nothing about interpretation — you can produce a beautiful timeline with no way to tell whether your reading of it is right. Staging the activity gives you what casework never gives you at the start, a *known* sequence, so what you practise is the reading rather than the guessing. It is also why the answer key is written before acquisition and sealed until section 11: the moment you consult it mid-analysis, you are no longer analysing.

## 4. Stage the incident

A download, a renamed copy, an execution, two persistence mechanisms, a new account, a connection attempt that goes nowhere, a document, two deletions, then nothing at all — performed in this fixed order on `win-lab`, with **the UTC time of every step written into the answer key as you perform it, before any acquisition.**

Nothing here is real malware. The payload is a script you write; it opens no sockets and its only effect is one line in a marker file. Every action is reversible by reverting `win-lab` to `03-supertimeline-before`.

### 4.1 Before you stage anything

**Author the payload and hash it.** The hash is what lets you connect the same content across a rename, and it belongs in the answer key before anything executes.

```bash
# On the node that will SERVE the file — not linux-lab: see the warning below.
mkdir -p ~/lab-stage && cd ~/lab-stage
# The whole payload: it writes one marker line and exits.
printf '%s\n' '@echo off' \
  'echo LAB-MARKER %DATE% %TIME% >> "%TEMP%\lab-marker.txt"' > lab-runner.cmd
sha256sum lab-runner.cmd | tee lab-runner.cmd.sha256   # record this in the answer key

# Serve it on the lab subnet. What to look for: a request line per fetch — a second,
# independent record of the download that does not live on the victim at all.
python3 -m http.server --help
python3 -m http.server 8080 --bind 0.0.0.0
```

> **Serve it from a node that is not `linux-lab`** — the optional `linux-victim`, or a throwaway HTTP container on the hypervisor host attached to the lab network. The analysis host must never be a participant in the incident it examines ([lab-environment.md:68-74](lab-environment.md)). If you have no third node, write the deviation and its reason into the case log, as [lab-environment.md:299-309](lab-environment.md) shows.

**Record the time base before you touch the victim.** Everything later is expressed in UTC ([03-timeline:79](../methodology/03-timeline.md)), and the offset is a fact about the timeline, not a footnote ([lab-environment.md:343](lab-environment.md)).

```bash
# On win-lab (PowerShell): zone, reading, sync state — then on linux-lab, at the same moment
Get-TimeZone | Select-Object Id, BaseUtcOffset; Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'; w32tm /query /status
date -u +'%Y-%m-%d %H:%M:%S UTC'
```

Two readings a few seconds apart, not hours. Write the victim's zone, the measured offset and whether it was reading UTC into `notes/case-log.md`. If it was not, every export needs that offset applied and stated.

### 4.2 The sequence, in fixed order

Give yourself a one-line answer-key helper on `linux-lab` — `stamp() { printf '%s | %s\n' "$1" "$2" >> ~/lab/<case-id>/notes/answer-key.md; }` — and call it as `stamp "<victim UTC time>" "<step>"` after every action below, using the **victim's** clock reading, since that is the time base you will analyse in.

Steps 1–4 build the file chain. Step 1 goes through the browser GUI deliberately: a programmatic fetch leaves different artefacts, and the browser artefacts are half the point of the step.

```powershell
# 1. Download in the browser, from the lab-internal URL only
Start-Process 'http://10.20.20.12:8080/lab-runner.cmd'
#    What to look for: a copy in %USERPROFILE%\Downloads plus a browser download record, and
#    possibly a Mark-of-the-Web stream — check for it rather than assuming it:
Get-Item "$env:USERPROFILE\Downloads\lab-runner.cmd" -Stream *
# 2. Copy it into a user-writable temporary folder
Copy-Item "$env:USERPROFILE\Downloads\lab-runner.cmd" "$env:TEMP\lab-runner.cmd"
# 3. Rename it — the cheapest masquerade there is, and why the hash pivot matters later
Rename-Item -Path "$env:TEMP\lab-runner.cmd" -NewName 'lab-update-check.cmd'
```

```cmd
:: 4. Execute it by its new name, from the explorer or a shell, as a user would
"%TEMP%\lab-update-check.cmd"

:: 5. A scheduled task pointing at it — elevated. Confirm the switches: schtasks /create /?
schtasks /create /tn "LabUpdater" /tr "%TEMP%\lab-update-check.cmd" /sc onlogon /ru labuser /f

:: 6. An autorun registry value — a per-user Run value needs no elevation
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v LabUpdater /t REG_SZ /d "%TEMP%\lab-update-check.cmd" /f

:: 7. A second local account — elevated; '*' prompts, so use a lab-only password
net user labuser2 * /add
```

```powershell
# 8. An outbound connection attempt to a host that does not answer: an address in the lab
#    subnet with nothing listening, and a name that cannot resolve ('.invalid' is reserved).
Test-NetConnection -ComputerName 10.20.20.99 -Port 4444 -InformationLevel Detailed
Resolve-DnsName -Name no-such-host.lab.invalid
# 9. Open a document through the GUI, so the shell's recent-item mechanisms can record it
Start-Process notepad.exe "$env:USERPROFILE\Documents\lab-report.txt"
```

```cmd
:: 10. Delete two files by two DIFFERENT routes and record which was which in the answer key.
::     (a) the payload's marker file, %TEMP%\lab-marker.txt — through the Recycle Bin, from the GUI
::     (b) the downloaded original — permanently:
del "%USERPROFILE%\Downloads\lab-runner.cmd"
```

Why those two, and why two routes: they leave a deleted-record trail without breaking the persistence chain, so the timeline should show both a path that still resolves (the renamed copy, named by the task and the Run value) and paths that no longer do — and the two deletion routes produce visibly different shapes, which is a result rather than noise.

**11. Do nothing at all for several minutes**, recording the UTC time at the start and at the end. The quiet period is part of the data: it is the window in which you test whether your filters can produce a *meaningful* absence (section 7), and it cannot be reconstructed afterwards if you never bounded it.

### 4.3 Seal the answer key

`notes/answer-key.md` now holds all eleven steps with UTC times, the payload hash, the offset measured in 4.1 and the two deletion routes — written before acquisition, so none of it can have been shaped by the evidence. Close it and do not reopen it until section 11. Do not keep a copy on `win-lab`: an answer key inside the exhibit is an answer key you read out of the evidence instead of deriving.

## 5. Freeze and acquire

```text
1. Record the end of the quiet period in the answer key.
2. Close the browser, the document and any shell you opened during staging.
3. Take snapshot '04-supertimeline-after' on win-lab (the '04-<case>-after' pattern).
4. Shut the VM down cleanly.
5. Acquire by the standard procedure in lab-environment.md section 8: hash the source,
   image with dd/dc3dd and/or ewfacquire, re-hash the image, write the acquisition row.
   Do not mount the image; analyse a verified working copy.
```

Two facts to record as you go, because they explain the tail of your timeline: **the shutdown is itself a state change** (the image is the post-shutdown state, moments after the snapshot — note the shutdown time so a late event is attributable to your procedure rather than the incident), and **the tools have versions**, because a report naming a suite without a version cannot be reproduced ([04-reporting](../methodology/04-reporting.md), "Documenting Methodology and Evidence").

**Why disk is mandatory and memory is optional.** Disk is mandatory because the staged incident *is* persisted state — two persistence mechanisms, a renamed file, two deletions, a new account — and a powered-off disk can be imaged reproducibly and hashed end to end ([lab-environment.md:30](lab-environment.md)). Memory is optional because nothing here needs live-only state to be reconstructed, with one instructive exception: step 8. What a memory capture adds to a timeline:

- **Process creation times** — a start time per process instance, which is not the same claim as the file-system timestamps of the image the process came from. The disk can say a script ran; memory can say when *this instance* started and whether it is still running.
- **Network state at the moment of capture** — the only place that distinguishes "the connection attempt never produced a session" from "a session existed and closed before shutdown". For a step whose whole point is that the far end never answered, that is the corroboration you want.
- **Loaded modules and open handles**, which can tie a process to a file the file system alone cannot.

Two costs, neither small. Memory is only available **live**, so capturing it forces the capture *before* the freeze and reorders your acquisition — record that in the acquisition log. And the capture tool runs on the victim, leaving its own artefacts in the timeline you are about to build. Both facts belong in the case log before you start, not in the report afterwards.

## 6. Build the sources

Three routes over the same evidence, each answering a different question. Build all three: section 9 compares them, and you cannot compare what you did not run. All three run on `linux-lab`, against a **verified working copy** in `working/` — never against `evidence/`, never against the victim.

### 6.1 Route A — the file-system timeline (Sleuth Kit bodyfile)

The classic pipeline, unchanged since the bodyfile format was defined (the Bodyfile Format section of [03-timeline](../methodology/03-timeline.md)). TSK takes single-dash switches (`fls -V`, `fls -h`); confirm on your build.

```bash
# Partition layout first — every later TSK command needs the right offset
mmls ~/lab/<case-id>/working/disk.dd
# Bodyfile: the allocated namespace, then the inode metadata the namespace no longer references
fls -o <offset> -r -m / ~/lab/<case-id>/working/disk.dd > ~/lab/<case-id>/working/body.txt
ils -o <offset> -m ~/lab/<case-id>/working/disk.dd >> ~/lab/<case-id>/working/body.txt
mactime -b ~/lab/<case-id>/working/body.txt -d -z UTC > ~/lab/<case-id>/exports/fs-timeline.csv
# What to look for: one row per file per timestamp type, and a file thick enough to be plausible
# for the machine you acquired — a wrong offset or file system gives a thin or nonsensical file.
```

In this incident, look for **the two names of one file** (the download's birth and the renamed copy's birth, in two directories — and neither row tells you they are the same content, which is what your recorded payload hash is for); **the marker file and its deletion**, including any new recycle-container entry; **paths that no longer resolve**, since the deleted view lists entries that have left the namespace ([forensic-exercises.md:133-145](forensic-exercises.md) is the basic version of that reading); and **containers rather than contents** — the task file and the registry hives are containers whose timestamps you get here and whose *definitions* you do not. On NTFS the bodyfile carries one timestamp set; the other set is a separate reading, and a mismatch between them is the timestomping signal in the timestamp-reliability table of [03-timeline](../methodology/03-timeline.md). Find that switch on your own version rather than trusting a remembered one.

### 6.2 Route B — the plaso super-timeline over the image and the extracted artefacts

One parse, one storage file, then as many filters as you have questions ([03-timeline:48-79](../methodology/03-timeline.md)). Confirm the current CLI shape first: plaso's command forms have changed across releases.

```bash
log2timeline.py --help
# Parse the image into a case-named storage file
log2timeline.py --storage-file ~/lab/<case-id>/working/<case-id>.plaso ~/lab/<case-id>/working/disk.dd
# Add the extracted artefacts as a second source — hives, EVTX, browser databases, prefetch,
# task files, all in one directory (section 6.3 shows the extraction shape). Keeping that
# directory is what lets a reviewer check you.
log2timeline.py --storage-file ~/lab/<case-id>/working/<case-id>.plaso ~/lab/<case-id>/exports/artefacts/
# Sanity before you trust any filter result
pinfo.py ~/lab/<case-id>/working/<case-id>.plaso
```

In `pinfo.py`, read the **per-parser breakdown**: a parser that produced no events against a source you know exists is a parsing or version problem, not an absence of activity — and everything in section 8 depends on knowing which sources actually fired. Also note warnings about unreadable sources and the storage file's size, because you are about to hash it.

### 6.3 Route C — the event-log stream alone

Extract the logs **without mounting the image**, by the meta addresses `fls` reports, then triage on the analysis host.

```bash
fls -o <offset> -r -p ~/lab/<case-id>/working/disk.dd | grep -i 'winevt'
icat -o <offset> ~/lab/<case-id>/working/disk.dd <meta-address> > ~/lab/<case-id>/exports/artefacts/Security.evtx
```

The Windows-side triage tools belong on the **analysis** host or a dedicated Windows analysis VM — never on `win-lab`, which would become a contaminated exhibit ([lab-environment.md:154](lab-environment.md)). Each has its own argument style and version drift, so discover the form rather than copying a remembered one:

```powershell
.\EvtxECmd.exe --help
.\chainsaw.exe --help        # chainsaw: hunt / search / dump sub-commands
.\hayabusa.exe --help        # hayabusa: csv-timeline and friends
# Same shape in all three: EVTX file(s) in, one CSV timeline out, one record per event.
```

What this route teaches: **which staged steps have an event at all** (task creation, account creation and process execution are the candidates, and each depends on a policy a default install may not have enabled — whether the record exists is a fact about the configuration, and you can only state it by looking); **what is structurally invisible here** (the download, the copy, the rename and the document being opened are, on a default configuration, not event-log events at all — no amount of filtering will produce them); and **which channels do not exist**, since a channel never created because its provider never ran is a very different statement from a channel that is present and empty. List what is actually in the extraction directory before concluding anything. This route has the most precise timestamps and the most stable schema of the three, which is exactly why it is easy to over-trust: it is a policy-dependent view of the machine, not a view of the machine.

## 7. Read it like an analyst

The method, in order. Its central discipline: **pivot on entities, not on time**. Widening a window adds noise from every unrelated component on the machine; pivoting on a name, a path, an account or a hash adds only events plausibly belonging to the same actor.

**1. Fix the time base.** Write the victim's zone, your measured offset and the display zone you will export in into the case log. Every filter below is in UTC. Store UTC, display local if you must ([03-timeline:79](../methodology/03-timeline.md)) — but never mix the two inside one subset, because a mixed subset produces a sequence that exists only in your spreadsheet.

**2. Anchor on an event you already know.** Pick one step from the answer key with the richest artefact potential in the routes you built and write its time down. From now on the answer key stays closed: you are allowed to know the anchor, and nothing else.

**3. Open a narrow window around the anchor** — a few minutes is enough to find the neighbouring steps, and deliberately too small to contain the incident.

```bash
# Filter syntax and field names vary between plaso releases. Confirm on yours:
psort.py --help
psort.py -o l2tcsv -w ~/lab/<case-id>/exports/window-<n>.csv \
  ~/lab/<case-id>/working/<case-id>.plaso \
  "date > '<anchor-time>' and date < '<anchor-time plus a few minutes>'"
# What to look for: rows that are NOT the anchor. Its neighbours are the free information in
# this step; the anchor itself proves nothing you did not already know.
```

**4. Pivot on entities**, with **no time bound at all** — read a name, a path, an account or the hash out of that window, then search the whole storage file for it. The four pivots that matter here: **the payload hash** (the one entity that survives the rename, which is why you hashed it in 4.1); **the file name in both its forms**, each searched separately; **the paths** (the user's temporary directory, downloads, the system Tasks folder, the recycle container); and **the accounts** (`labuser` and `labuser2` separately, because the new account's creation is an independent branch rather than part of the file chain).

**5. Widen only when the question changes** — not when a query returned too little. Write the new question down before you widen, so the wider window is aimed at something.

**6. Only now, look for what nobody told you about.** With the chain reconstructed, re-read the super-timeline for activity the answer key does not contain. This is where a lab becomes practice for real work, and where an unfiltered CSV tempts you to invent a narrative out of routine background activity.

**7. Run the negative control.** Re-run your working filters over a window you know is quiet — the quiet period from step 11 — and over one you know is not. One direction proves your filter can find things; the other proves an empty result means something.

> **A filter is part of your method and must be written down exactly.** Exactly means: the tool and its version, the storage file name **and its SHA-256**, the display time zone, the filter string verbatim including its quoting, the export command verbatim, and any limit or truncation you applied. A subset you cannot regenerate from your notes is not evidence; it is a screenshot.

## 8. What you should observe

Described as behaviour, never as counts, dates or rows: no image, storage file or EVTX set exists behind this file, so any specific timestamp written here would be invented. Read this as a list of things to confirm in your own output.

- **An ordered chain in which each step corroborates the next.** The download precedes the copy, which precedes the rename of the same content; the rename precedes the execution; the execution precedes both persistence mechanisms, each of which *names the post-rename path*; the account creation is an independent branch rather than part of the file chain; the connection attempt follows the execution; the document open is a second independent branch; the deletions come last, and one of them should show as a path that has gone from the namespace while the other appears as a recycle-container entry — comparing those two shapes is a result. The test is mechanical: each step's artefact should name an entity from the previous one. A step that only makes sense once you know the answer key is not corroborated — it is remembered.
- **At least one step visible in two independent sources.** The likeliest candidate is the execution, where a file-system record of the payload having run and an event-log record of a process having been created can both exist. Whether they *do* depends on what is enabled, which is why section 6.2's per-parser check comes before this claim. Name the pair explicitly and check both rather than inferring one from the other.
- **At least one step visible in only one source — with a reason you verified.** This is the most valuable result in the lab. The three realistic candidates: *opening a document* (nothing on a default configuration writes an event-log record for it; the only traces are shell-level recent-item artefacts, whose presence depends on version and settings); *the failed connection attempt* (there is no session, so anything that records sessions records nothing, and whether an attempt is recorded at all depends on a network-event provider or firewall log being configured — a name that fails to resolve leaves a resolver query, not a connection); *the browser download* (visible in browser artefacts only, and only if the browser wrote a record and the profile was not cleared).
- **The quiet period as an absence, meaningful only because you proved the sources work.** Because you demonstrated that your filter returns events over a window where you know activity happened, an empty window where you know nothing happened is informative rather than an artefact of a broken query, a wrong zone or a parser that silently failed. Note what the quiet period is *not*: components on a Windows host keep writing routinely regardless of user activity, so the absence you are reading is the absence of *staged-step* events. Decide which of those two you are claiming, and say so.
- **Anything you did not stage.** The remainder of the super-timeline is the machine's own background life; naming it, and why it is not part of the incident, is part of the analysis — and it is where a careless narrative invents an intrusion out of a software update.

> If you write a count, a date or a row number into your notes, it must have come from the output in front of you. Nothing in this file can supply one.

## 9. Compare the routes

| Route | What it covers | What it misses | What it costs | How defensible its output is |
| --- | --- | --- | --- | --- |
| **A — bodyfile** (`fls`/`ils` → `mactime`) | Every file and directory the file system still references, with its timestamp set; deleted entries still in metadata; the containers of registry and task artefacts | All content: no registry values, no task definitions, no event records, no browser history, nothing from unallocated space | Cheapest: minutes, one CSV, nothing beyond TSK | Strong for "this path existed and changed at this time", and re-checkable by re-running two commands — but silent on meaning, since it cannot say what a write *was* |
| **B — plaso super-timeline** (image + extracted artefacts) | One merged, sorted stream over file system, registry, EVTX, browser, prefetch and more, with per-event parser provenance | Parsers that did not fire; artefact classes whose timestamps mean different things (an access time is not a creation time); anything whose artefact was never created | The expensive one: a storage file comparable to the source in size, a long parse, real RAM ([lab-environment.md:84](lab-environment.md)) | Highest, on one condition — that you keep the storage file, its hash and the exact commands. Per-event parser attribution is what makes each claim checkable by someone else |
| **C — event-log stream alone** | What the logging subsystem recorded: process creation, task and account changes and similar, with precise timestamps and a stable schema | Everything that is not an event: files, registry, browser, and every event type whose audit policy was off | Cheap and fast once extracted; triage tools add detections on top | Very high per event and easy to explain to a non-specialist, but a narrow, policy-dependent view — an empty result here is a statement about the victim's auditing configuration, not about the incident |

None of the three is "the" timeline. The defensible report says which route supports each sentence, and says out loud where the routes disagree: a file-system birth time and an event-log process-creation time for the same action are different readings of it, and the difference deserves a sentence rather than a resolution. Memory, if you captured it, is not a fourth merged stream — it corroborates (process creation times, network state at capture) and it is the only source for whether the failed connection attempt ever had a session.

## 10. Keep the timeline defensible

A timeline is a **derived artefact**. Its inputs are the exhibit; it is not.

- **Tool and version per command** — `04-reporting` is explicit that naming the suite is not enough ([04-reporting](../methodology/04-reporting.md), "Documenting Methodology and Evidence").
- **The storage file's name and SHA-256**, hashed at creation and again before you cite a filter result. If the two differ, the storage file changed and everything derived from it is in question.
- **The exact filter** — verbatim, with its quoting, display zone and anchor value — and **the export command** verbatim, including the output module, because modules change the column set and therefore what a subset can be shown to contain.
- **The filtered subset as an exhibit**: exported into `reports/`, named, hashed, and logged as an acquisition-style row. That CSV is what a reviewer reads; the storage file is what proves the CSV is a faithful filter over it.
- **The raw sources kept** — image, extraction directory, storage file, bodyfile, with hashes. The derived-artefact rule is simple: if the inputs are preserved and the commands recorded, the derived timeline can be regenerated and checked; if either is missing, it is an assertion with a timestamp column.
- **Authorisation, custody and minimisation** — the authorisation recorded before staging, one log row per handling event, and the discipline of exporting only the rows that answer the question. A whole-machine super-timeline of a user's laptop contains personal data even when the incident is small.

```bash
# Hash the storage file when it is created, and again when you cite it
sha256sum ~/lab/<case-id>/working/<case-id>.plaso | tee -a ~/lab/<case-id>/notes/evidence-hashes.txt
# Hash the exhibit you export, and log the export row
sha256sum ~/lab/<case-id>/reports/<case-id>-exhibit-<n>-window.csv
```

## 11. Score yourself against the answer key

Now — and only now — open `notes/answer-key.md`. Write your narrative first; scoring a narrative you have already adjusted to the truth scores nothing.

```text
One row per staged step, in the order you performed it, filled from your own work:

| Staged step | Staged time (UTC) | Recovered? | Route and source that shows it | Second, independent source | Hardest part |
```

Then answer four questions in writing:

1. **How many staged steps did you recover?** Your number, from your own narrative. A step counts only if you can name the source and the artefact that shows it.
2. **Which source found each one?** The pattern worth noticing is which route carries the *sequence* and which carries the *identity*: routes typically agree on what happened and disagree about how precisely they can place it.
3. **Which step was hardest, and why?** Usually one of two shapes — a step whose artefact depends on a policy you had not confirmed (so you had to establish that the record could exist before concluding anything from its absence), or a step with no file to find, such as a connection attempt to nowhere or a document that was merely opened.
4. **Which step could no source show — and the mechanism you verified for it.** "It is not in the event log because auditing for that category was not enabled on this victim" is a finding you can defend; "it is not in the event log" is a query result. Check the policy, provider or feature state before writing the reason down, and cite where you checked it.

Score your precision as well as your recall: count the rows in your filtered subsets that were routine machine activity rather than staged steps, and note what would have removed them. A result that includes a step you know happened *and* a verified reason why it could not be visible is better than a lucky match — that is the sentence that separates a reconstructed timeline from a narrated one.

## Common Mistakes & Tips

- **Reading the answer key first.** The most expensive mistake here, because it is invisible: you will produce a correct narrative and learn nothing about reading evidence. Write, then score.
- **Pivoting by widening the time range.** Widening adds every unrelated component on the machine; pivoting on a hash or a path adds only plausible events. Widen when the *question* changes, and write the new question down first.
- **Treating the full super-timeline CSV as the analysis.** It is the raw material you filter from. A report citing "the timeline" without a filter has cited nothing checkable.
- **A filter you cannot regenerate** — missing quoting, missing display zone, missing tool version. Record the filter as you type it, not afterwards.
- **Mixing display zones across subsets.** One subset in UTC and the next in local time produces a sequence that exists only in your spreadsheet. The victim's offset is part of the timeline, as the closing tips of [03-timeline](../methodology/03-timeline.md) put it.
- **Concluding absence from a parser that never ran.** Check the per-parser breakdown before writing "no such activity": a failed parse looks exactly like a clean machine.
- **Analysing on the victim, or mounting the image.** Both are covered at [lab-environment.md:334-345](lab-environment.md), and both invalidate the case rather than one result.
- **Leaving the answer key on the victim**, where it becomes evidence — the one artefact that can tell you the answer without the timeline supporting it.
- **Capturing memory after the freeze.** Memory is only available live; if you want it, the capture goes first and its own artefacts go into the timeline you are about to build.
- **Asserting a step was "not recorded" without checking the policy.** "Not enabled" and "not present" are different findings, and only one of them is about the incident.
- **Trusting the bodyfile for content questions.** It says a path existed and changed; it cannot say what the task pointed at or which value was written.
- **Tip:** parse once, filter many times — re-parsing per question costs hours and leaves several storage files and no single artefact to cite. And write each sentence of the narrative next to the subset that supports it: a narrative written afterwards, from memory of a CSV, is where invented detail enters a report, and it is the one error this lab exists to train out.

## Checklist / Self-Test

- [ ] `win-lab` was reverted to `03-supertimeline-before` before staging, and I know reverting is the whole cleanup.
- [ ] The payload is a script I wrote, it does nothing but write a marker, and no real malware was involved.
- [ ] I recorded the victim's time zone and measured clock offset before staging, and my timeline is expressed in UTC.
- [ ] I wrote every staged step into the answer key **as I performed it**, before acquisition, and sealed it until section 11.
- [ ] I hashed the payload before staging, so the rename is provable by content rather than by name.
- [ ] I took snapshot `04-supertimeline-after`, shut the VM down cleanly, and acquired with source and image hashes recorded.
- [ ] I never mounted the image, and every analysis ran on a verified working copy on `linux-lab`.
- [ ] Route A produced a bodyfile and a UTC `mactime` timeline, and I can read a deletion off it.
- [ ] Route B produced a storage file, I checked its per-parser breakdown with `pinfo.py`, and I hashed the storage file.
- [ ] Route C produced extracted logs and a triaged event timeline, and I know which staged steps it contains and which it structurally cannot.
- [ ] I can name a step that two independent sources show, and one that only one shows, with the verified mechanism for why the others could not.
- [ ] I ran a negative control over the quiet period and can explain why its absence is meaningful rather than merely empty.
- [ ] I exported the filtered subset as a named exhibit, hashed it, and recorded the exact filter and export command beside it.
- [ ] I kept the image, extraction directory, bodyfile and storage file so the timeline can be re-derived.
- [ ] I scored myself against the answer key after writing my narrative, including the step I could not recover.

## Further Resources

- **plaso documentation** (log2timeline, pinfo, psort, filters and output modules) — https://plaso.readthedocs.io/
- **plaso / log2timeline project** (release notes: the CLI does change) — https://github.com/log2timeline/plaso
- **The Sleuth Kit** — `mactime` and the bodyfile format — https://www.sleuthkit.org/sleuthkit/man/mactime.html
- **Timesketch** (collaborative timeline analysis over a plaso storage file) — https://timesketch.org/
- **EvtxECmd** (Eric Zimmerman's EVTX parser, CSV/JSON timeline output; it lives in the `evtx` repository) — https://github.com/EricZimmerman/evtx
- **Chainsaw** (rapid EVTX triage and Sigma-based hunting) — https://github.com/WithSecureLabs/chainsaw
- **Hayabusa** (Sigma-based Windows event-log timeline generator) — https://github.com/Yamato-Security/hayabusa
- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **RFC 3227**, *Guidelines for Evidence Collection and Archiving* (order of volatility — why memory precedes disk) — https://www.rfc-editor.org/rfc/rfc3227
- **ISO/IEC 27037**, *Guidelines for identification, collection, acquisition and preservation of digital evidence* — https://www.iso.org/standard/44381.html
- **RFC 2606** (the `.invalid` reserved name used in step 8) — https://www.rfc-editor.org/rfc/rfc2606
- **Official eCDFP page on the INE website** for current, authoritative certification details — https://ine.com/security/certifications/ecdfp-certification

> **Verification:** the Sleuth Kit half was executed on **2026-09-19** against **The Sleuth Kit
> 4.12.1** (Ubuntu 24.04 WSL): on an ext4 image built in `/tmp`, `fls -f ext4 -o 0 -r -p -m /lab` +
> `ils -f ext4 -o 0 -e -m` + `mactime -b … -d -z UTC` ran end to end, while the form previously
> printed here, `ils -o <offset> -m / disk.dd`, exits 1 with no stdout
> (`Invalid magic value (raw_open: image "/" - is a directory)`). The four internal citations were
> repointed by section after checking their targets: `04-reporting` puts the tool-and-version
> requirement under "Documenting Methodology and Evidence"; `03-timeline` puts the bodyfile
> pipeline under "The Bodyfile Format", the NTFS timestamp-set discussion in the
> timestamp-reliability table, and the clock-offset advice among its closing tips. The plaso route
> was executed too, against **plaso 20260720** on the same date: `log2timeline
> --storage-file=<case>.plaso disk.img` completed, and `pinfo` printed the per-parser breakdown that
> section 6.2 tells you to read (`Events generated per parser: filestat : 12`), so the storage-file
> form and the sanity check are both real. Two caveats measured on this release, recorded and **not**
> changed here: the output module is `l2tcsv` (`psort -o csv …` fails with `ERROR: Unsupported output
> format: csv.`) and the filter expression must follow the storage file (`psort … <filter> <path>`
> fails with `ERROR: Unable to compile filter expression … premature end of expression`). **Not
> executed:** the EVTX triage tools (Hayabusa and Chainsaw are not installed here) and the lab
> itself — no `win-lab` VM exists on this machine, so every step below remains a syntax reference.
