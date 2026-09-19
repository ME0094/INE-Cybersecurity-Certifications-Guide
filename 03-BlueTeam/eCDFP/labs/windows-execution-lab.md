# Windows Execution Lab — Proving What Ran

> eCDFP · Labs — INE Cybersecurity Certifications Study Guide
>
> One question — *what actually executed on this Windows host?* — five deliberate executions on `win-lab`, one hash-verified disk image, and every artefact family Windows keeps about program execution. You write the ground truth down **before** you acquire anything, then try to recover each execution from the evidence alone.
>
> Every command here is a **syntax reference**. This repository ships no captured command output: there is no VM, no image and no parser on the machine that wrote it, so where a command would print something this file says what to look for instead of inventing a result. Confirm each tool's switches with `-h` or `--help` on the build you actually install, and run everything on VMs you own or are explicitly authorized to examine.

## 1. Objective

Answer one question from evidence: **what actually executed on this host, and how do you prove it?**

That sentence hides four different claims, and most mistakes in this area are a confusion between them: the file **existed** on disk; the file was **copied, created or touched**; a **user interacted** with it; the file **executed**. Only the last answers "what ran". Every family in section 6 carries one or two of those claims and not the others, and section 8 makes the difference explicit. The reasoning that turns those artefacts into a defensible execution claim — rather than a recital of a tool's output — is [05-windows-artifact-forensics.md](../methodology/05-windows-artifact-forensics.md).

You learn the distinction the only way it can be learned: by planting five executions whose ground truth you know, acquiring the disk as [lab-environment.md](lab-environment.md) prescribes, and seeing which of the five you can still prove afterwards. The deliverable is a **scored, evidenced list** — this execution, proven by two independent artefacts; that one, only inferable; this other one, not recoverable at all — with the structural reason attached to each. The valuable outcome is a calibrated sense of absence: a lab where everything leaves a trace teaches you nothing about what a missing trace means.

## 2. Prerequisites

1. **The workbench, built and verified** per [lab-environment.md](lab-environment.md): `win-lab` and `linux-lab`, isolated network, verified toolchain, the `~/lab/<case-id>/` evidence workspace, the eight-step acquisition procedure. This lab does not restate any of it.
2. **Snapshot `03-exec-before` on `win-lab`**, taken after step 3 below and before you stage a single execution — the state you revert to in order to repeat the lab.
3. **A pre-flight telemetry record**, captured *before* staging: what the evidence can prove later is decided here.

```powershell
# The guest clock, and the offset if the guest is not on UTC.
(Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
Get-TimeZone | Select-Object Id, BaseUtcOffset
# Is app prefetching enabled? Read the value; do not infer it from an empty folder. The
# property is EnablePrefetcher under the PrefetchParameters key of the SYSTEM hive.
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' | Select-Object EnablePrefetcher
# Process-creation auditing, and whether the command line is included.
auditpol /get /subcategory:"Process Creation"
# What to look for: the three settings that decide what sections 6.1 and 6.6 can say at
# all. "No Auditing" is a legitimate lab state — and an important result.
```

4. **The parsers** from [windows-artifact-tools.md](../tools/windows-artifact-tools.md), installed and verified as that file describes — on a **Windows analysis host**, never on `win-lab` (a victim carrying forensic tooling is a contaminated exhibit).
5. **`sleuthkit` and an imaging tool** (`dc3dd` and/or `ewfacquire`) on `linux-lab`, plus the lookup table from [windows-artifacts.md](../cheatsheets/windows-artifacts.md).
6. **An answer key** — `notes/answer-key.md` or a spreadsheet, writable while the VM runs and complete before acquisition.

## 3. Ethics and authorization

- **Your own disposable VM, or one you hold written authorization to examine** — a document naming the scope and the window, signed by someone entitled to give it. If you cannot state the authorization in one sentence — whose equipment, authorized by whom, for what window — you are not ready to stage this lab.
- **Snapshot first.** `03-exec-before` before any execution, `04-exec-after` immediately after. You are deliberately creating activity you will later investigate; reverting is how you get to do it again.
- **No host integration and no real data.** Shared folders, clipboard, drag-and-drop and shared drives off: they leak data and silently add file activity that contaminates your file-system evidence. Lab-only account (`labuser`), lab-only password, lab-only files — data minimisation applies to practice too, because the habit you build is the habit you keep.
- **Why this lab is legitimate.** A defender has to know which artefacts survive which kind of execution, and that knowledge cannot be bought from outside: you cannot learn what a missing Prefetch entry means by looking at someone else's machine, or from a screenshot. You learn it by planting known executions in a VM you may destroy. The technique is dual-use — the same knowledge tells an operator what to erase — but the defender's version is "which of my artefacts is authoritative, and which is decoration".
- **Chain of custody from the first byte.** Hash the source, hash the image, work on a verified copy, log every acquisition row, never mount the image. There is no version of this lab in which evidence integrity is optional because "it is only practice".

## 4. Build the evidence

Five executions, staged in order, on `win-lab`, as `labuser`; each stresses a **different** artefact family. For every one of them, note the guest clock (section 2, step 3) before and after the action and write the UTC time, the exact command or action and the artefacts you expect into the answer key **as you stage it**.

> An answer key written after acquisition records what you found rather than what happened, and the lab collapses into confirmation bias with extra steps.

### 4.1 (a) A normal installed program, launched from the Start menu

Install a program through its own installer, launch it **from the Start menu**, close it. The GUI interaction is the point: this is the scenario with the richest artefact support, and it is your positive control. Prefetch for the program, a UserAssist GUI-launch record, an Amcache/ShimCache entry for its binary, a jump-list entry — and a process-creation event only if the streams were live — are what should let you prove it; record the program's exact install path.

### 4.2 (b) A portable executable from a user-writable path

A real PE copied into a user-writable directory — `%TEMP%`, or a folder on the desktop — and run once. A copy of an in-box binary stands in for a portable tool: the *path* is what matters, not the payload.

```powershell
Copy-Item "$env:SystemRoot\System32\notepad.exe" "$env:TEMP\lab-portable.exe"
Start-Process "$env:TEMP\lab-portable.exe"
# What to look for: a Prefetch entry named for LAB-PORTABLE.EXE, an Amcache record carrying
# that full path, and the copy itself in the file system. Record the FULL path, not the name.
```

### 4.3 (c) A command through `cmd.exe` and through PowerShell

Two executions that differ only in the host, so you can see how much of the evidence is host-specific.

```cmd
cmd.exe /c "whoami > %TEMP%\lab-cmd-output.txt"
```

```powershell
powershell.exe -NoProfile -Command "Get-Date | Out-File -FilePath $env:TEMP\lab-ps-output.txt"
# What to look for: a 4688 only if auditing was configured BEFORE this ran; a 4104 only if
# script block logging was on; a Sysmon event only if Sysmon was already installed. The
# redirect in (c1) also leaves a file-system artefact worth chasing.
```

### 4.4 (d) A script executed through a script host other than PowerShell

`wscript.exe` / `cscript.exe` run VBScript or JScript and are **not** covered by PowerShell script block logging — a real blind spot on an otherwise well-instrumented host.

```cmd
echo WScript.Echo "LAB-WSH-EXEC" > %TEMP%\lab-exec.vbs
cscript.exe //nologo %TEMP%\lab-exec.vbs
wscript.exe %TEMP%\lab-exec.vbs
# What to look for: the script file on disk with a hash, plus a Prefetch entry and a
# process-creation event for the HOST. wscript shows a dialog — dismiss it and check nothing.
```

### 4.5 (e) The negative control — a file that never ran

Copy an executable-shaped file into the profile, then **look at it without running it**: right-click, Properties, read the details, close. Nothing executes the file.

```powershell
Copy-Item "$env:SystemRoot\System32\cmd.exe" "$env:USERPROFILE\Desktop\lab-never-run.exe"
Copy-Item "$env:SystemRoot\win.ini" "$env:USERPROFILE\Desktop\lab-never-opened.txt"
# What to look for: both files in $MFT and the USN journal with the copy's creation times,
# and NOTHING for either in Prefetch, the process-creation stream or UserAssist.
```

> The negative control matters as much as the four positives, and it is the row people quietly drop when it returns "nothing". A lab where everything leaves a trace teaches you nothing about absence: without (e) you cannot tell whether "no Prefetch entry" means "did not run" or "I cannot read Prefetch". The pair (b)/(e) is the sharpest comparison here — two executable files in user-writable paths, one run and one merely present, which you must tell apart from the image alone.

### 4.6 The answer key

Fill this in **before** the disk is imaged, from the guest clock, in UTC.

```text
Case id: ___  Exhibit: ___  Examiner: ___   Pre-flight — Prefetch ___  Sysmon ___  4688 ___  command line ___  4104 ___   Guest time zone ___  UTC offset ___
UTC | #  | Action / exact command                            | Expected artefacts
----|----|---------------------------------------------------|-------------------
    | a  | Start menu launch of <installed program>          | Prefetch, UserAssist, Amcache/ShimCache, jump list
    | b  | Copy + run %TEMP%\lab-portable.exe                | Prefetch, Amcache, MFT/USN, process-creation if enabled
    | c1 | cmd.exe /c "whoami > %TEMP%\lab-cmd-output.txt"   | 4688/Sysmon if enabled, MFT/USN for the output file
    | c2 | powershell.exe -NoProfile -Command "..."          | 4104 if enabled, 4688/Sysmon if enabled, MFT/USN
    | d  | cscript //nologo %TEMP%\lab-exec.vbs (+ wscript)  | Prefetch for the host, MFT/USN for the .vbs; NO 4104
    | e  | Copy lab-never-run.exe + view Properties only     | MFT/USN only; nothing in Prefetch/Sysmon/4688
```

## 5. Freeze and acquire

The staging is done. Shut the VM down cleanly and take snapshot `04-exec-after` on `win-lab` **before** you acquire: the snapshot lets you re-acquire without re-staging, but it is not a substitute for the image. Then run the eight-step acquisition procedure from [lab-environment.md](lab-environment.md) on `linux-lab` — the analysis host is never the machine that produced the evidence.

- **Close the answer key before the acquisition log opens.** Ground truth must be complete and timestamped before the first byte is read.
- **Write the acquisition row with the source hash, the image hash and the tool versions.** A comparison you cannot reconstruct is not a verification; if the two hashes differ, stop and re-acquire rather than quietly replacing the image. Then analyse a copy: section 6 runs against a verified working copy in `working/`, never against `evidence/`, and never with the image mounted.

```bash
sha256sum /dev/sdb                                 # source: hash BEFORE reading data
sha256sum ~/lab/<case-id>/evidence/disk.dd         # image: hash AFTER the copy
# What to look for: two identical strings; a mismatch is a stop-work condition to record.
```

## 6. Analysis

One subsection per artefact family, ordered from the cheapest question to the most expensive: the execution caches first, then the event streams, then the user-interaction artefacts, then the file system that underpins all of them.

**Before you start.** Extract the artefacts into `exports/` with the tools in [forensic-toolkit.md](../tools/forensic-toolkit.md) (or a collection tool on a Windows analysis host) and parse the copies. This section tells you what each family means and what to look for; it deliberately does not re-teach invocation. Switch sets, batch files and each parser's failure modes live in [windows-artifact-tools.md](../tools/windows-artifact-tools.md); the artefact-to-path lookup table, including the exact hive keys, lives in [windows-artifacts.md](../cheatsheets/windows-artifacts.md). Confirm every option with `-h` on your build, and record in your notes which streams were live before staging (section 2, step 3): you cannot interpret a missing event until you know whether the stream was recording.

### 6.1 Prefetch — which program ran

```powershell
PECmd.exe -d "<extracted Prefetch folder>" --csv "<out>" --csvf prefetch.csv
# What to look for: an entry for the program from (a), one for LAB-PORTABLE.EXE from (b),
# one for the script host from (d), nothing for (e) — and last-run times to compare.
```

Prefetch records the *images* that ran, which makes it the closest thing Windows has to an execution log for programs, and a matching last-run time is your strongest single proof of execution. Three structural limits belong in your notes: it is often disabled on server editions, it can be disabled by policy on any edition, and it can be cleared. Where it was cleared or disabled you will find nothing, must fall back to the streams and to Amcache, and must weaken the conclusion accordingly.

### 6.2 Amcache — what was present, and often what ran

```powershell
AmcacheParser.exe -f "<extracted Amcache.hve>" --csv "<out>"
# What to look for: records whose paths match the binaries from (a), (b) and (d), with the
# hash and size reported. Ask of every record: does this say the file was RUN, or only SEEN?
```

Amcache is an application-compatibility inventory, not an execution log. It records paths, sizes and hashes of executables that existed on the host, and it survives some cleanups that take Prefetch with them. It is also not created for everything, and a promising-looking entry for a file from (e) — the negative control — is precisely the trap this lab is built to expose. Read an Amcache record as *the file existed and was inventoried*; corroborate execution elsewhere.

### 6.3 ShimCache / AppCompatCache — a compatibility cache, not an execution log

```powershell
AppCompatCacheParser.exe -f "<extracted SYSTEM hive>" --csv "<out>"
# What to look for: your copied binaries' paths with the timestamps the parser reports, and
# which entries carry an execution indicator on YOUR build.
```

AppCompatCache exists so Windows can decide how to shim an executable, and it is populated as the compatibility engine encounters files — which is not the same event as executing them. Treat presence as evidence the host knew about a file at some point, treat any execution indicator as build-dependent, and never build an "it ran" claim on this family alone. It can also be cleared.

### 6.4 UserAssist — what a user launched through the shell

```bash
# NTUSER.DAT with RegRipper's userassist profile; options and failure modes: see the toolkit.
rip.pl -r NTUSER.DAT -p userassist
# What to look for: an entry for the program launched from the Start menu in (a), with its
# run count and last-run time — and whether (b) appears, which depends on HOW you ran it.
```

UserAssist records GUI programs started through Explorer. Its names are obfuscated and it carries run counts, which makes it the natural corroboration for (a). The honest caveats: it does not record command-line launches, and it is a per-user registry artefact a cleanup tool may reset. A record here proves a **user interaction**; its absence does not prove the program never ran.

### 6.5 SRUM — resource usage, and how long something ran

```powershell
# Confirm the switch set on your build first: this parser needs the SRUDB.dat and the SOFTWARE hive.
SrumECmd.exe -h
# What to look for in the application-usage and network-usage tables: your binaries from (a)
# and (b), with usage volume and the time window attributed to them.
```

SRUM is a resource-accounting database, and that framing is what makes it useful: a program in an application-usage record consumed CPU or network inside a recorded window, which is execution evidence of a different kind from a run time. Two limits matter — SRUM keeps a rolling window and older records roll off, so it will never show you the distant past; and it must be parsed from a copy, because it is an ESE database whose application identifiers need the SOFTWARE hive to resolve. Confirm the table identifiers in [windows-artifacts.md](../cheatsheets/windows-artifacts.md) rather than trusting a memory of the GUIDs.

### 6.6 The event streams — the only artefacts that name a process, if they were recording

Three streams, three prerequisites, one shared rule: **a process-creation event exists only if the stream was configured before the execution happened.** You cannot backfill them.

One naming detail before you type a path: the `/` in a channel name becomes `%4` in the file name under `C:\Windows\System32\winevt\Logs`. The Sysmon operational channel is therefore the file `Microsoft-Windows-Sysmon%4Operational.evtx`, not `...-Operational.evtx`. The examples below read the copied log files directly; if you export the channel with `wevtutil epl "<channel>" <name>.evtx` instead, cite the name you chose for the export.

```powershell
# 4688 — prerequisite: auditing enabled BEFORE staging, command line included.
auditpol /get /subcategory:"Process Creation"
# What to look for: (c1), (c2) and (d) as records with a command line. Without the
# command-line sub-setting you learn that a process ran, not what it was told to do.
# Sysmon process creation (ID 1) — prerequisite: Sysmon already installed with process
# creation in its config.
Get-WinEvent -Path .\Microsoft-Windows-Sysmon%4Operational.evtx -MaxEvents 20 | Select-Object TimeCreated, Id
# What to look for: one event per staged execution, including the script host from (d), with
# image path, parent image and command line.
# PowerShell script block logging (4104) — prerequisite: policy applied before the session
# that ran the script started.
Get-WinEvent -Path .\Microsoft-Windows-PowerShell%4Operational.evtx -MaxEvents 20 | Select-Object TimeCreated, Id
# What to look for: the script block from (c2) — and nothing for (d), because PowerShell
# logging does not see VBScript.
```

Run these against the **exported** EVTX files on the analysis host; offline parsing options are in [windows-artifact-tools.md](../tools/windows-artifact-tools.md). Note the two independent ways these streams fail you: not enabled, and enabled but wrapped — a small channel overwrites old events, and the evidence is gone while everything looks healthy.

### 6.7 LNK files and jump lists — what a user touched

```powershell
LECmd.exe -d "<extracted LNK folder>" --csv "<out>" --csvf lecmd.csv
JLECmd.exe -d "<extracted AutomaticDestinations folder>" --csv "<out>" --csvf jlecmd.csv
# What to look for: an entry pointing at something the user opened, with its target path and
# timestamps. Then ask: does this belong to a file that RAN, or to one merely OPENED?
```

LNK files are created by shell interaction — opening a document, double-clicking a program, dragging a file. That is why they belong in the *user interaction* column and not the *execution* column. Scenario (a) usually leaves a jump-list entry for the application; scenario (e) leaves nothing, because you only right-clicked; and a LNK pointing at a path you copied but never opened is entirely possible from other activity on the host. Use this family to corroborate who did something, not to prove that something executed.

### 6.8 The file system — `$MFT`, the USN journal, and the binaries themselves

```powershell
MFTECmd.exe -f "<extracted \$MFT>" --csv "<out>" --csvf mft.csv
MFTECmd.exe -f "<extracted \$UsnJrnl `$J>" --csv "<out>" --csvf usn.csv
# What to look for: creation and modification times for the two files from (e), the copy of
# lab-portable.exe from (b) and the .vbs from (d). The USN journal adds the change
# operations — created, written, renamed — reconstructing the act of copying.
```

```bash
mmls ~/lab/<case-id>/working/disk.dd          # the NTFS offset every TSK command below needs
fls -f ntfs -o <offset> -r ~/lab/<case-id>/working/disk.dd
icat -f ntfs -o <offset> ~/lab/<case-id>/working/disk.dd <meta> > ~/lab/<case-id>/exports/lab-portable.exe
sha256sum ~/lab/<case-id>/exports/lab-portable.exe
# What to look for: the file's bytes and a hash to compare against the system original —
# identical content under a different name is a finding the event streams may never give you.
```

The file system answers presence, creation and provenance, not execution: every file from (e) is right there, fully recoverable, and none of it ever ran. Keep the timestamps honest too — `$STANDARD_INFORMATION` and `$FILE_NAME` times can disagree, and a disagreement is a question to ask, not a conclusion to draw.

## 7. What you should observe

**(a) Installed program from the Start menu.** Provable with several independent artefacts: an execution cache keyed to the program, a user-interaction record for the GUI launch, an inventory record for the binary, a jump-list entry, and a process-creation event if the streams were live. When two unrelated families agree on the same last-run time, you have a finding rather than a lead.

**(b) Portable executable from a user-writable path.** Provable, but by a narrower set: the execution cache and the inventory record are the natural witnesses, the file system proves the copy, and the process-creation stream proves the execution *if it was live*. Construct the weak version at least once — Prefetch disabled, auditing not configured before staging — and you will find that the file system proves the file existed and was written at a known time while nothing in the image proves it was ever launched.

**(c) A command through `cmd.exe` and through PowerShell.** Almost everything here depends on the event streams, because neither a shell built-in nor a short command necessarily leaves an execution cache of its own. What survives when the streams are off is *indirect*: the redirected output file from (c1) in `%TEMP%`, which proves that **something** executed a command at that time but not which command, by whom or from where. The PowerShell side is deliberately asymmetric — script block content survives even an obfuscated command line, but only if logging was enabled before the session started.

**(d) A script through `wscript.exe` / `cscript.exe`.** You should be able to prove the **script host** executed: an execution cache entry for the host, a process-creation event naming it, and the script file on disk with a hash. Proving *which script* it ran is a harder question, and the honest answer is usually "by its side effects, or not at all" — PowerShell's script block logging does not apply to VBScript, so the content is knowable only if you recovered the file and can attribute it. This is the blind spot the scenario exists to demonstrate.

**(e) The negative control.** Presence yes, execution no. You should recover both files from the file system with their creation times and find **nothing** attributable to them in the execution caches or the process-creation streams. If you believe you have proven that (e) executed, you have not found a surprising result — you have found a false positive, and the next step is to identify which artefact you misread. This is the most useful thing in the lab: it calibrates every "no evidence of execution" conclusion you will ever write.

**The structural reasons for what you cannot recover.** These are properties of the artefacts, not tool bugs, and they belong in your notes beside the gap they explain:

- **Prefetch can be absent by design** — frequently disabled on server editions, disableable by policy on client editions, and clearable by cleanup tooling or deliberately. An empty Prefetch folder means "no evidence here", never "nothing ran".
- **AppCompatCache is a compatibility cache, not an execution log.** It is populated as the compatibility engine encounters executables, and it can be cleared. Any execution indicator it carries is build-dependent.
- **Amcache survives some cleanup but is not created for everything.** Read it as an inventory: excellent for "this binary existed at this path with this hash", unreliable for "this binary ran".
- **Process-creation events exist only if auditing was configured *before* the execution.** No post-incident configuration recovers a 4688, a Sysmon event or a 4104 for activity that predates it; enabled-but-wrapped reaches the same end more slowly.
- **LNK files and jump lists record user interaction, not execution.** They prove the shell touched an item; they cannot prove the item ran.

## 8. The distinction that is the point of the lab

| Artefact | Execution happened | File existed on disk | Copied or touched | User interacted | What it does **not** prove |
| --- | --- | --- | --- | --- | --- |
| Prefetch | proves | does not prove | does not prove | does not prove | Who ran it, when the file was copied, or that nothing ran — absence also means "disabled" or "cleared". |
| Amcache | does not prove (an inventory, not a run log) | proves | proves presence at that path | does not prove | That the binary was ever launched, or the order of events. |
| AppCompatCache (ShimCache) | does not prove | proves presence when the cache was written | partly | does not prove | Execution. It is a compatibility cache and it can be cleared. |
| UserAssist | proves a GUI launch through Explorer | proves | does not prove | proves | Command-line launches; it is a per-user record a cleanup tool may reset. |
| SRUM | proves an app consumed resources inside its window | does not prove | does not prove | does not prove | Anything outside the rolling window; it needs the SOFTWARE hive to resolve identities. |
| Security 4688 | proves (with the command line only if that sub-setting was on) | does not prove | does not prove | does not prove | Anything predating the audit policy, or lost when the channel wrapped. |
| Sysmon process creation | proves, with parent, command line and hashes | partly (hash of the image) | does not prove | does not prove | Anything predating Sysmon's install; absence says nothing about old activity. |
| PowerShell 4104 | proves script content executed inside PowerShell | does not prove — `-Command` and encoded arguments have no file on disk | does not prove | does not prove | The user, and every non-PowerShell script host. |
| LNK files | does not prove | proves a target path (possibly stale, or on removable media) | proves it was opened or referenced through the shell | proves | Execution of the target. |
| Jump lists | does not prove | proves a referenced item | proves interaction | proves | That the item was executed rather than merely opened. |
| `$MFT` | does not prove | proves | proves creation, deletion and rename times | does not prove | Execution; the standard-information and file-name times can disagree or be manipulated. |
| `$UsnJrnl` | does not prove | proves | proves the change operations, in order | does not prove | Execution; its window is bounded and old records roll off. |

Two conclusions follow, and they are the whole lab. **Only the execution caches and the process-creation streams ever say "this ran"** — and both can be absent for reasons that have nothing to do with whether it ran. **Everything else is corroboration**: one artefact is a lead, two independent families agreeing is a finding, and the rows marked "does not prove" are not the weak ones — they are the families that tell you what else happened, which is usually what the investigation needs.

## 9. Score yourself against the answer key

Open the answer key now. For each planted action, decide which verdict the evidence supports — *proved*, *inferred* or *not recovered* — and name the artefact that carried the proof.

```text
Action | Verdict (proved / inferred / not recovered) | Artefact(s) that proved it | Expected but absent | Why it was absent
-------|---------------------------------------------|----------------------------|---------------------|------------------
a      |                                             |                            |                     |
b      |                                             |                            |                     |
c1     |                                             |                            |                     |
c2     |                                             |                            |                     |
d      |                                             |                            |                     |
e      | (negative control — see below)              |                            |                     |
```

- **How many executions did you prove, how many only infer, how many could you not recover at all?** Name the artefact behind each. "Four proved, one inferred, and the inferred one is (d) because the script's content was never logged" is a complete answer; a count with no attribution is not. Where you found nothing, say so plainly and name the telemetry you confirmed was not recording — and for anything you expected but did not find, write the structural reason beside it: Prefetch disabled or cleared, Amcache not created for that file type, auditing off before staging, channel wrapped, family not applicable to that kind of execution.
- **Record the negative control result explicitly.** State, for both files from (e), that presence was proven and execution was not, and name the artefact you checked to rule execution out. A run in which (e) goes unreported is incomplete however well the positives went.
- **Find your own false positive.** Most people get at least one: an inventory record read as a run, a LNK read as an execution, a file-creation time read as a start time. Write down which artefact you over-read and what the correct reading is — this is the reason the lab exists.
- **Change one variable and repeat.** Revert to `03-exec-before`, enable what was missing (Prefetch, Sysmon with process creation, 4688 with the command line, 4104), re-stage the same five executions and re-acquire. The difference between the two scorecards is the real result of this lab: a measured statement about what your instrumentation buys you.

## Common Mistakes & Tips

- **Staging before recording the telemetry state.** If you do not know whether 4688, Sysmon, 4104 and Prefetch were live beforehand, you cannot interpret a single absence — and absences are half of this lab's output.
- **Writing the answer key after acquiring.** It stops being ground truth and becomes a transcript of your findings. Write each row as you stage the action.
- **Treating AppCompatCache or Amcache as execution logs, or a LNK as proof of execution.** None of the three says a file ran; scenario (e) is the row that punishes the mistake.
- **Dropping the negative control from the report** because it "found nothing". It found exactly what it was built to find, and it is the only row that shows your method discriminates.
- **Concluding "it never ran" from an empty Prefetch folder.** Say "no Prefetch evidence" and name the other families you checked, plus whether Prefetch was even enabled.
- **Skipping the source hash, or skimming the comparison.** A mismatch is a stop-work condition, not a rounding error: re-acquire and log why. Mounting the image, or analysing on the victim, invalidates the run the same way.
- **Ignoring the guest clock and time zone.** Every artefact in section 6 carries a timestamp; if you cannot put them all in one UTC frame, scoring becomes guesswork.
- **Tip:** hash the copied binaries at staging time and again after extraction — matching content across a rename is often the only proof that survives an otherwise quiet host.
- **Tip:** when an action yields nothing, write down which families you checked and what each would have looked like had it been present. That list is what stops "I found nothing" from meaning "I did not look".
- **Tip:** keep parser versions in your notes. A finding you cannot reproduce with the same tool version is an anecdote.

## Checklist / Self-Test

- [ ] I can state the authorization for this lab in one sentence, and it names my own equipment.
- [ ] I recorded, before staging, whether Prefetch, Sysmon, 4688 (with command line) and 4104 were enabled on `win-lab`.
- [ ] Snapshot `03-exec-before` existed before I staged anything, and `04-exec-after` was taken immediately after.
- [ ] All five scenarios were staged: (a) Start menu launch, (b) portable executable from a user-writable path, (c) `cmd.exe` and PowerShell, (d) `wscript.exe`/`cscript.exe`, (e) the negative control.
- [ ] The answer key was complete, timestamped in UTC and closed **before** the disk was imaged.
- [ ] The source hash and image hash match, both are in the acquisition log with tool versions, the image was never mounted, and I parsed a verified working copy on the analysis host — not on `win-lab`.
- [ ] I checked all eight artefact families from section 6, including the negative result for (e) in each.
- [ ] For every scenario I can name the artefact that proved it, or state honestly that it was only inferred or not recoverable — with the structural reason.
- [ ] I can explain, for at least two artefacts, why they do **not** prove execution.
- [ ] I recorded the negative control result explicitly and named the artefact I checked to rule execution out.
- [ ] I found and wrote down at least one artefact I initially over-read, and what the correct reading is.
- [ ] I re-ran the lab with the missing telemetry enabled and can state what the difference bought me.

## Further Resources

- **Eric Zimmerman's tools** (`PECmd`, `AmcacheParser`, `AppCompatCacheParser`, `MFTECmd`, `LECmd`, `JLECmd`, `SrumECmd`, `RECmd` and the rest) — https://ericzimmerman.github.io/
- **Microsoft Learn — Sysmon** (installation, configuration schema, event IDs) — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- **Microsoft Learn — command line process auditing** (the `4688` prerequisite and its sub-setting) — https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- **Microsoft Learn — about logging in PowerShell** (script block logging and its policy) — https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
- **`auditpol` reference** (audit policy subcategories, including Process Creation) — https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol
- **libscca**, **libfsntfs**, **libesedb** (documented formats behind ShimCache, `$MFT`/USN and SRUM) — https://github.com/libyal
- **Forensics Wiki** (artefact encyclopedia: Prefetch, Amcache, ShimCache, UserAssist, SRUM) — https://forensics.wiki/
- **MITRE ATT&CK** (the techniques that make execution artefacts interesting) — https://attack.mitre.org/
- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **The Sleuth Kit** (the file-system tools used in section 6.8) — https://www.sleuthkit.org/sleuthkit/
- Official eCDFP product page on the INE website for current, authoritative details about the certification — https://ine.com/security/certifications/ecdfp-certification

> **Verification:** the `%4` file-naming rule was executed on **Windows 11 Pro (10.0.26200)** on
> **2026-09-19**: `Get-ChildItem C:\Windows\System32\winevt\Logs -Filter *PowerShell*` returns
> `Microsoft-Windows-PowerShell%4Admin.evtx` and
> `Microsoft-Windows-PowerShell%4Operational.evtx`, and the same listing contains both forms side
> by side — `Microsoft-Windows-Kernel-Power%4Thermal-Operational.evtx` (channel
> `Microsoft-Windows-Kernel-Power/Thermal-Operational`) and
> `Microsoft-Windows-Hyper-V-VMMS-Operational.evtx` (a channel name with no `/`). The `%4` marks
> the `/` in the channel name; a dash in the name is just a dash. **Not executed:** the Sysmon
> line — `Get-ChildItem … -Filter *Sysmon*` returns nothing because Sysmon is not installed on this
> machine, so the file does not exist here to open; the name follows the same rule, and
> `wevtutil epl "Microsoft-Windows-Sysmon/Operational" <name>.evtx` is the route to use when the
> channel has never been written.
