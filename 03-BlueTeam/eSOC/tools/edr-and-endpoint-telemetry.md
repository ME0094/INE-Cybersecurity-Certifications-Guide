# EDR and Endpoint Telemetry, Seen From the SOC

> eSOC · Tools — INE-Cybersecurity-Certifications-Guide
>
> The EDR is the console a tier-1 analyst opens second, after the SIEM alert, and the one that most often answers the question the alert raised. This file covers what endpoint detection and response actually produces, how to read a process tree, which actions the console can take on your behalf, what the endpoint telemetry looks like once it lands in the SIEM, and where EDR coverage quietly ends.
>
> **Console field names differ between vendors.** The examples here describe *what to look for* using the vocabulary shared across EDR products and the Sysmon/ECS schemas; no live console was queried while writing this note, and no vendor's output is reproduced. Map each concept onto your own console's names once, and write the mapping down for the next shift.

## 1. What an EDR Is, and What It Is Not

**What it is.** An agent on each endpoint that collects deep, high-frequency telemetry (process creation and ancestry, file writes, registry changes, network connections, image loads, script content) and applies behavioural detections to that stream locally and in the cloud. It is also an *action* platform: the console can isolate, kill, quarantine, and collect.

**What it produces**, in the order a triage analyst consumes it:

| Output | What it answers | Typical shape |
|---|---|---|
| **Detection alert** | Why the analyst is here | A named behaviour, a severity, a host, a process, and often a MITRE technique mapping |
| **Process tree** | What ran, what started it, what it started next | Parent chain with command lines, users, hashes, and timestamps |
| **Event timeline for the host** | What else happened around the same time | Network connections, file and registry writes, logons, module loads |
| **File and hash detail** | What the artefact is | Path, hash, signer and signature status, prevalence in the estate |
| **Containment state** | Whether the host is currently isolated | Isolation status, who triggered it, when |

**What it is not.** It is not a SIEM (no cross-source correlation over weeks), not a case-management system, not a forensic acquisition tool (it preserves some data, not a disk image), and not a substitute for log collection — EDR consoles expire data faster than a SIEM's retention policy, so anything you may need in three months must reach the SIEM as well.

## 2. Reading a Process Tree

The process tree is the fastest story in an investigation, and it is read from the root downwards, asking one question per level.

```text
winword.exe                  <- Did an Office product need to start a shell at all?
  └── cmd.exe                <- Shell from a document process: no.
        └── powershell.exe   <- Encoded arguments here would raise this to high confidence.
              └── certutil.exe -urlcache -split -f http://... <path>   <- Download utility as a grandchild.
```

| Question at each level | Benign look | Suspicious look |
|---|---|---|
| Is this parent *supposed* to start children? | A scheduled task runner, a service host, an installer | An Office document process, a mail client, a PDF reader |
| Is the child a shell or a script host? | Rarely, from user applications | `cmd`, `powershell`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32` |
| Do the command-line arguments match the parent's job? | A management agent invoking its own module by full path | Encoded or obfuscated arguments, `-w hidden`, `-nop`, URLs, user-writable paths |
| Where does the binary live? | `C:\Windows\System32`, `Program Files`, a signed vendor path | `\AppData\`, `\Temp\`, `\ProgramData\`, `\Public\`, a recycle-bin path |
| Is it signed, and does the signature match the path? | Valid signature from the publisher the path claims | Unsigned, invalid signature, or a legitimate binary living in an odd place |

Two reading rules that prevent most misjudgements:

1. **The alert names a file; the tree names a behaviour.** Triage the tree, not the file. A "suspicious binary" that was launched by the user's own installer and made no network connections is a different case from the same binary launched by a macro.
2. **Absence of a sibling process is evidence.** If a download utility ran and *no* child process or network connection follows, say so: an attempt that failed is still an attempt, and its failure mode tells you about the environment's controls.

## 3. Endpoint Telemetry Inside the SIEM

Most EDRs can forward their telemetry to the SIEM, where it joins identity, network, and cloud data. Knowing which endpoint event maps to which question is what lets you triage from the SIEM alone when the EDR console is unavailable.

The Sysmon/Windows event vocabulary below is the common denominator (Elastic's ECS carries the same information under `process.*`, `file.*`, `registry.*`, `network.*`):

| Question | Sysmon / Windows event | ECS-shaped fields to pivot on |
|---|---|---|
| What ran, and what started it? | Sysmon 1, Security 4688 (+ command line) | `process.name`, `process.command_line`, `process.parent.name`, `process.parent.command_line`, `user.name` |
| What did it talk to? | Sysmon 3 | `process.name`, `destination.ip`, `destination.port`, `destination.domain`, `network.direction` |
| What did it write? | Sysmon 11 (file create), 23/26 (delete) | `file.path`, `file.name`, `file.hash.sha256` |
| What did it change in the registry? | Sysmon 12/13/14 | `registry.path`, `registry.value`, `registry.data.strings` — the raw value is a **string**, so match carefully |
| What did it load or inject into? | Sysmon 7 (image load), 8 (CreateRemoteThread), 10 (process access) | `process.name`, `dll.name`, `winlog.event_data.TargetImage`, `winlog.event_data.GrantedAccess` |
| What did it resolve? | Sysmon 22, DNS server logs | `dns.question.name`, `dns.answers` |
| What script content ran? | PowerShell 4104 (script block), 4103 (module) | `powershell.file.script_block_text`, `winlog.event_data.ScriptBlockText` |
| What persisted? | Sysmon 13 (Run keys), 4698 (scheduled task), 7045 (service) | `registry.path`, `winlog.event_data.TaskName`, `winlog.event_data.ServiceName` |
| Did the defensive tooling get touched? | Defender 5001/5007, Sysmon 16 (config change) | `event.code`, `winlog.event_data` |

> **The registry trap.** Registry values arrive as strings, so `0` and `1` do not compare as numbers, and case does not always fold. When a rule that pivots on a registry value returns nothing, inspect one document and match on the string form before you conclude the value was never set.

## 4. What the EDR Console Can Do on Your Behalf

Endpoint response actions are what distinguishes an EDR from a log source. Know each one's blast radius before you use it, and which ones need approval (see `../methodology/04-response.md` for the decision table).

| Action | Effect | Reversible | Tier-1 default |
|---|---|---|---|
| **Isolate host** (network containment) | Blocks network I/O except agent management; the host keeps running and keeps reporting | Yes, instantly | Preferred first containment for a compromised endpoint |
| **Kill process** | Terminates the running process | No — the process state is gone | Only with IR approval; destructive to volatile evidence |
| **Quarantine / delete file** | Removes the artefact from the filesystem | Quarantine is restorable in most products; deletion is not | IR decision; never before the artefact is hashed and recorded |
| **Collect triage package** | Gathers volatile data and logs from the host for offline analysis | Yes, read-only in effect | Do it early if the playbook allows — it is the cheapest evidence you will get |
| **Live terminal / remote shell** | Interactive access to the host | Yes, but it is an action *on* the host | Only with approval and awareness: it changes state and can tip off an adversary |
| **Tag / add to a group** | Marks the host for policy or scoping | Yes | Useful, harmless: tag the host the moment it is in scope |

Two rules that belong next to every one of those buttons: **verify the action took effect** (an isolation that silently failed leaves you believing you are contained), and **record who approved it and when** in the case — endpoint actions are production changes.

## 5. Where EDR Coverage Ends

The console's confident interface hides a set of gaps that produce exactly the failure mode a SOC fears: a clean-looking host that was never watched.

| Gap | What it looks like | How to detect it |
|---|---|---|
| Agent not installed or not running | The host simply does not appear in a search | Compare the asset inventory against the console's device list (see `../methodology/01-monitoring.md`) |
| Sensor in "monitor only" / audit mode | Detections appear but nothing blocks or isolates | Check the policy assigned to the host's group |
| Exclusions written for performance or compatibility | The technique "does not happen" on specific paths or process names | Audit the exclusion list; broad exclusions are how a defended estate has unmonitored corners |
| Telemetry not forwarded to the SIEM | The EDR knows, the SIEM does not; correlation across sources silently fails | Confirm the forwarding integration is enabled for the group, not just globally |
| Short console retention | The event is gone in days, while the SIEM has months | Check the console's retention against your investigation window |
| Unmanaged platforms and devices | macOS/Linux/VDI/OT systems absent because nobody deployed an agent | Inventory by OS and asset class, not by ticket volume |
| Cloud and identity actions invisible to the agent | The attacker never touched a managed endpoint (token theft, mail rules, new API keys) | Those layers need their own telemetry: IdP sign-in logs, CloudTrail, audit logs |

> The most common real-world surprise: a host that reports no detections because its group has a policy with the prevention features disabled. Before you tell anyone "the EDR would have caught it", check the policy attached to that host.

## 6. Working the Alert: SIEM and EDR Together

A repeatable division of labour, so neither console is opened blindly:

1. **SIEM first, for context.** What else does the environment show for this host, user, and address? This answers whether the activity is isolated or spread (see the correlation table in `../methodology/03-investigation.md`).
2. **EDR second, for causation.** The process tree and the host timeline attribute the behaviour to a process and a user, and show what followed.
3. **Back to the SIEM to confirm nothing is missed.** The EDR sees the endpoint; the SIEM sees authentication, proxy, DNS, mail, and cloud events the agent never touched.
4. **Fix the data, not just the case.** When you find a detection that existed in the EDR but never reached the SIEM, that integration gap becomes a ticket — otherwise the next analyst repeats your work from a weaker position.

## Common Mistakes & Tips

- **Mistake:** triaging the file the alert named instead of the behaviour it describes. *Tip:* read the process tree first; the same binary is benign or malicious depending on its parent and its children.
- **Mistake:** assuming "no EDR alert" means "the EDR looked and found nothing". *Tip:* check that the agent is installed, running, in a prevention-enabled policy, and forwarding to the SIEM.
- **Mistake:** isolating a host without verifying the isolation. *Tip:* confirm from a second viewpoint; unverified containment is a belief, not a control.
- **Mistake:** using the live terminal on a host under investigation because it is convenient. *Tip:* it changes state and may tip off the adversary — it is an approved action, not a convenience.
- **Mistake:** relying on the EDR console as your evidence store. *Tip:* console retention is usually short; if it must survive the investigation, it has to reach the SIEM or a case artefact.
- **Mistake:** treating a registry comparison as numeric. *Tip:* registry values arrive as strings — inspect one document before writing the match.
- **Mistake:** trusting a detection's severity label as the case severity. *Tip:* severity is a property of the *asset and the account* as much as of the technique.

## Checklist / Self-Test

- [ ] I can explain the difference between what a SIEM and an EDR each know, and which one can act.
- [ ] I can read a process tree from root to leaf and name the suspicious property at each level.
- [ ] I can map at least five Sysmon/Windows event IDs to the question each answers, and to their ECS-shaped fields.
- [ ] I know which registry-value comparisons require string matching rather than numeric.
- [ ] I can name the endpoint response actions, their blast radius, and which ones need IR approval.
- [ ] I can verify that an isolation actually took effect, from a second viewpoint.
- [ ] I can list five ways EDR coverage silently ends, and how to detect each one.
- [ ] I have checked whether my EDR telemetry reaches the SIEM, for the asset groups that matter.
- [ ] I can describe the order in which I use the SIEM and the EDR during triage, and why.

## Further Resources

- Microsoft Learn — Sysmon (event IDs, configuration, and what each event contains): https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Microsoft Learn — Windows security auditing events (process creation, logon, Kerberos): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings
- Elastic — Elastic Defend and endpoint event fields (ECS): https://www.elastic.co/guide/en/security/current/endpoint-protection-intro.html
- Wazuh — agent capabilities, file integrity monitoring, and active response: https://documentation.wazuh.com/current/user-manual/capabilities/index.html
- MITRE ATT&CK — techniques that endpoint telemetry exposes, with their data sources: https://attack.mitre.org
- MITRE D3FEND — defensive techniques for endpoint analysis and hardening, useful when naming a control: https://d3fend.mitre.org/
- SigmaHQ — process-creation and registry rule collections to compare your own logic against: https://github.com/SigmaHQ/sigma
