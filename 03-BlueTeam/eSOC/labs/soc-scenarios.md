# SOC Lab Practice — Scenario Drills

> eSOC · Labs — INE-Cybersecurity-Certifications-Guide

Theory is cheap; triage muscle memory is not. This guide walks you through building a small, safe **detection lab** and then running scenario drills that mimic the alerts a tier-1 SOC analyst sees every shift. Every drill ends with concrete expected outcomes so you can tell when the lab is working.

> ⚠️ **Safety rules first.** Everything here is for a lab you own and control, on an isolated network (NAT or host-only), using disposable credentials. Never generate attack traffic against systems you do not own, never run real malware on a machine with access to production data, and disable the lab network when you are done.

## Lab Blueprint (Pick One Stack)

You need two logical parts: **something that collects and searches events** (the SIEM) and **something that generates events** (the test endpoint). The `tools/siem-tools.md` file covers install details; here is the sizing and topology:

```text
                    ┌─────────────────────────────┐
                    │  SIEM VM (6-8 GB RAM)       │
  Windows test VM   │  Elastic Stack (Docker) or  │
  (2-4 GB RAM)      │  Wazuh manager + dashboard  │
  agents ──────────►│                             │
  winlogbeat/wazuh  │  Kibana / Wazuh dashboard   │
                    └─────────────────────────────┘
```

Minimum useful setup:

1. **SIEM host** — a VM with Docker (easiest) running the Elastic Stack or a Wazuh manager; 6–8 GB RAM, 2+ CPUs.
2. **Windows test endpoint** — a Windows 10/11 or Server VM with:
   - **Command-line auditing enabled** (Process Creation includes command line): enable via GPO or `auditpol` — this is what makes Event 4688 useful.
   - **PowerShell Script Block Logging** (Event 4104) enabled via GPO.
   - Optionally **Sysmon** (from the Sysinternals suite) for richer Event IDs 1/3/11/13.
   - The SIEM agent installed (Winlogbeat, or the Wazuh agent).
3. **Snapshot discipline** — take a clean snapshot of the endpoint *before* every drill so you can reset in seconds.

A quick way to confirm collection end-to-end on the Elastic path:

```powershell
# From an elevated PowerShell on the Windows endpoint: generate the event for
# real by attempting a bad logon (drill 1 uses the same shape). A genuine 4625
# carries every field the pipeline parses; there is no shortcut that writes a
# convincing Security event by hand - the Security channel is not writable that
# way, and a fabricated event would prove nothing about collection anyway.
net use \\127.0.0.1\IPC$ /user:lab\ghost WrongPass!
# Then watch Kibana within ~30 seconds
```

Then search in Kibana (Discover):

```text
event.code : 4625 and host.name : "win-test-01"
```

Expected outcome: the event appears with parsed fields (`user.name`, `source.ip`, `winlog.event_id`).

## Generating Sample Events Safely

You do not need real malware to practice detection. Attack *shapes* can be reproduced with harmless stand-ins that produce the same log signatures:

| Detection target | Safe stand-in to generate | What the logs look like |
|---|---|---|
| Encoded PowerShell | `powershell -EncodedCommand <base64 of "Write-Host lab-test">` | Event 4688/Sysmon 1 + 4104 with `-EncodedCommand` in command line |
| Mimikatz-style strings | Create a `.txt` with `sekurlsa::logonpasswords` / `privilege::debug` lines | File on disk → exercise your YARA rule from `tools/detection-rules/` |
| Failed-logon spike | 20 rapid bad logons: `net use \\127.0.0.1\IPC$ /user:lab\ghost WrongPass!` in a loop | Event 4625 storms from `127.0.0.1` |
| New local admin | `net user labadmin P@ssw0rd! /add` then `net localgroup administrators labadmin /add` | Events 4720 + 4732 (if auditing enabled) |
| Persistence-ish task | `schtasks /create /tn "LabTask" /tr "calc.exe" /sc once /st 23:59` | Sysmon 1 / 4688 showing `schtasks.exe` |
| Outbound beacon shape | `powershell -c "1..20 \| % { Invoke-WebRequest http://10.0.0.10:8080/beacon; Start-Sleep -Seconds 60 }"` | Repeated connections to one IP every ~60 s |

Always keep a list of what you generated, when, and from which account. That log is the "ground truth" you compare your detections against.

## Scenario Drills

For each drill: read the setup, run it, triage the resulting alert using the template in `cheatsheets/alert-triage-guide.md`, and confirm the expected outcome before moving on.

### Drill 1 — Failed Logon Spike (Credential Stuffing Shape)

- **Objective:** detect an abnormally high number of failed logons for one account in a short window.
- **Steps:** from the Windows endpoint, run ~20 failed logons in a loop against a deliberately wrong password; then check the SIEM for `4625` events, grouping by `user.name` and `source.ip`.
- **Triage angle:** is this one user typo-ing, or many accounts hit from one source? Check whether any successful logon (4624) follows.
- **Expected outcome:** the SIEM shows a visible cluster of 4625s with a consistent source IP; your aggregation query returns a count well above baseline. Confidence that the pipeline works: **high**.

```text
# Kibana KQL - the filter half. KQL has no pipe and no aggregation: it selects
# documents, and the "group by" is a second step (see the ES|QL block below, a
# Discover table, or a dashboard visualization).
event.code : 4625 and winlog.event_data.SubStatus : "0xC000006A"
```

```esql
// The counting half, in the same Kibana search bar (ES|QL, Elastic 8.11+)
FROM logs-windows.*
| WHERE event.code == "4625"
| STATS attempts = COUNT(*) BY user.name, source.ip
| SORT attempts DESC
| LIMIT 10
```

### Drill 2 — Encoded PowerShell (Obfuscated Script Shape)

- **Objective:** catch PowerShell launched with `-EncodedCommand`, a common way attackers hide payloads.
- **Steps:** base64-encode a harmless command and run it; watch for Event 4688/Sysmon 1 (process creation with command line) and Event 4104 (script block).
- **Expected outcome:** your SIEM query for `process.command_line : *EncodedCommand*` returns exactly the event you generated; your Sigma rule from `sigma-example.yml` — once converted to your backend — fires on it.
- **Follow-up:** write down how you would confirm whether the decoded payload is malicious (decode the base64 and read it — in this lab it is your own harmless text).

### Drill 3 — Mimikatz-Style Strings on Disk (YARA Practice)

- **Objective:** learn to scan files with YARA and understand detection-vs-reality gaps.
- **Steps:** create a plain text file containing several Mimikatz-style strings; run your rule:

```bash
yara ../tools/detection-rules/yara-rules/yara-example.yar suspicious.txt
```

- **Expected outcome:** `Suspicious_CredDump_Strings_AnyFile` matches the file and prints the rule name. Its companion `Suspicious_CredDump_Strings_PE` stays silent, because a `.txt` is not a PE — that silence is the lesson of the pair, not a failure of the drill. Then scan a normal file (e.g., `notepad.exe`): neither rule matches, because it carries none of those strings.
- **Triage angle:** a *text* file matching is low severity (maybe someone saved notes); the *same strings inside a real PE or in memory* would be high severity — which is why the two rules are separate. YARA identifies; analysts judge.

### Drill 4 — New Local Administrator Account

- **Objective:** detect account-creation persistence on an endpoint.
- **Steps:** create a local user and add it to Administrators; search for 4720 (user created) and 4732 (member added to group), and correlate both with the same target account.
- **Expected outcome:** both events appear with matching `TargetUserName`; the timeline shows create → add-to-group within seconds. If your SIEM/EDR has an account-management rule pack, it may alert on its own.
- **Triage angle:** who created it (the `SubjectUserName`), and was it an approved IT action? In the lab, it was you — in a real SOC this drill is your "insider/compromise" mental model.

### Drill 5 — Scheduled Task as Persistence Shape

- **Objective:** recognize a scheduled task being created by a non-standard process.
- **Steps:** create a scheduled task that launches a calculator or PowerShell; then inspect the process-creation telemetry around the `schtasks.exe` invocation.
- **Expected outcome:** your query for `process.name : schtasks.exe` (or `taskeng.exe`/`svchost.exe` firing the task later) shows the creation event and, when the task fires, the child process it started.
- **Triage angle:** task creation is noisy — legitimate software does it constantly. The interesting question is always *who created it and what does it run*.

### Drill 6 — Full "Mini Shift" (Cumulative)

- **Objective:** simulate a real triage session using everything above.
- **Steps:** reset the endpoint snapshot; then, as a "noisy colleague", generate 3–4 of the above event types in random order while you are not watching. Sit down later, open the alert queue, and triage each one with the 5-W template; escalate at least one to a written note as if handing off to tier 2.
- **Expected outcome:** you can reconstruct, from SIEM data alone, what happened, when, on which host, and from which account — and you have a written triage note for each. If you cannot tell the story from logs, re-run the drill with tighter timing and take notes.

## Common Mistakes & Tips

- **Skipping baseline.** Without knowing your lab's *normal* 4625 count, you cannot recognize a spike. Generate a quiet day first and screenshot the normal state.
- **Wrong time range again.** The #1 "my drill didn't show up" cause is a search window that closed before the event landed. Give agents 20–60 seconds and search `now-15m`.
- **Not enabling the right logging.** Event 4688 without command-line auditing, or no 4104, silently starves your best detections. Verify with `wevtutil qe Security /c:5 /rd:true /f:text` on the endpoint.
- **Reusing real credentials.** Lab accounts only, and change them between sessions.
- **Forgetting the endpoint firewall/network.** Keep the lab on NAT/host-only and confirm agents can reach the SIEM (test with `Test-NetConnection siem-host -Port 9200` on Windows, or `nc -vz` on Linux).
- **Not resetting between drills.** Snapshot the endpoint before each drill; otherwise your next drill's alerts are contaminated by the previous one's.
- **Running real malware "to see".** Do not. The stand-in table above produces the detection signatures you need without the risk.

## Checklist / Self-Test

- [ ] My lab is isolated (NAT/host-only), uses disposable credentials, and I can snapshot/reset the endpoint.
- [ ] Windows command-line auditing (4688 + command line) and PowerShell Script Block Logging (4104) are enabled.
- [ ] Events generated on the endpoint appear in the SIEM within ~60 seconds with parsed fields.
- [ ] I completed all six drills and verified the expected outcome for each.
- [ ] I ran my own Sigma rule (converted to my backend) and my own YARA rule against a generated event/file.
- [ ] I can reproduce the full timeline of a drill from SIEM data alone (what / who / when / where).
- [ ] I triaged every drill alert using the fill-in template from the alert triage guide.
- [ ] I shut down or disconnected the lab network when not practicing.

> **Verification:** the YARA pair in `../tools/detection-rules/yara-rules/yara-example.yar` was run with **yara 4.5.0** on **2026-09-19**, against test files created under `/tmp` (nothing was written inside the repository). A harmless `.txt` holding three of the strings matches `Suspicious_CredDump_Strings_AnyFile` and nothing else; the same strings appended to a real PE (`notepad.exe`) match `Suspicious_CredDump_Strings_PE` as well; `notepad.exe` alone and a text file with no such strings match nothing. Under the earlier single-rule version the `.txt` produced **no match at all**.
>
> The `Write-EventLog` shortcut that used to appear under *Lab Blueprint* was also executed, on **2026-09-19** on Windows (PowerShell, elevated session), with the redirect removed so the error was visible: `Write-EventLog -LogName Security -Source Microsoft-Windows-Security-Auditing -EventId 4625 -Message "lab test"` writes nothing and reports on stderr, in Spanish because this Windows is localised, `No se pudo abrir la clave del Registro para el registro "Security" del origen "Microsoft-Windows-Security-Auditing".` — *the registry key for the "Security" log could not be opened for that source*. It is a **non-terminating** error, which is exactly why the original `2>$null` made the command look like it had worked. No event was created, and the shortcut has been removed.

## Further Resources

- Elastic Stack installation docs — https://www.elastic.co/guide/en/elastic-stack/current/index.html
- Wazuh quickstart — https://documentation.wazuh.com/current/quickstart.html
- Sysinternals Sysmon — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows security auditing / Event 4688 (Microsoft Learn) — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
- PowerShell Script Block Logging configuration (Microsoft Learn)
- SigmaHQ — https://github.com/SigmaHQ/sigma
- YARA documentation — https://yara.readthedocs.io/
- MITRE ATT&CK — https://attack.mitre.org/
