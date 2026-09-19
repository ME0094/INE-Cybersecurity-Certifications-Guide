# Hunting Range Setup — A Disposable Lab You Can Rebuild

> eCTHP · Labs — INE Cybersecurity Certifications Study Guide
>
> Build a reproducible, throwaway threat-hunting range on your own hypervisor: a Windows victim with Sysmon and event forwarding, a Linux victim with `auditd`, a log collector, an optional attacker to emulate techniques, and — most importantly — a reset procedure that gives you a clean, known baseline every time. Everything here runs on systems you own or are explicitly authorized to use.

## 1. What this range is for

Hunting is a skill you can only build against data you trust. The point of this range is not realism for its own sake; it is to give you:

1. **A known baseline.** You know exactly what is installed and what normal activity looks like, so an anomaly is genuinely an anomaly.
2. **End-to-end telemetry you configured yourself.** You know which events are collected, which fields exist, and where the blind spots are — because you built the pipeline.
3. **Deliberate activity you generated.** You know what the attacker emulation did and when, so you can check whether your hunt found it and whether it found anything else.
4. **Disposability.** Revert, rebuild, and hunt again. A range you are afraid to break is a range you will not practise in.

> What it is **not**: a substitute for a production hunt. Production adds scale, noise, unknown baselines, and politics. This range builds the mechanics and the reflexes; the tradecraft transfers, the data does not (see `../methodology/04-hunting-tradecraft.md`).

## 2. Authorization and safety rules — read before you build anything

These are not optional formalities. A hunting range is an offensive-capability lab, and the failure mode is prosecutable.

- **Only your own systems, or systems for which you hold written authorization.** That means your hardware, your hypervisor, and your VMs. Written authorization means a document that names the scope and the window and is signed by someone entitled to give it.
- **The attack segment must not reach anything you do not own.** Use an internal/host-only network with no route out, and never bridge the attacker VM. Check your hypervisor's adapter settings every single time you start the range.
- **Disable host integration on victim and attacker VMs**: shared folders, shared clipboard, drag-and-drop, and shared drives. They are a data-leak path and a realism destroyer.
- **Treat emulated malware as real malware.** Snapshot before, revert after, and never copy samples or emulation output to your daily-driver machine.
- **Never point emulation tooling at an address that is not inside the range.** Verify the target list before you press enter, and prefer targets by name from your own lab inventory.
- **No production credentials, certificates, or data in the range.** Use lab-only accounts and lab-only passwords.
- **No accidental egress.** If the range needs internet (to install packages or pull rules), do it on purpose, from a specific VM, through a NAT adapter you enable and then disable. Recording when it was enabled belongs in your range log.

> If you cannot state the authorization in one sentence — whose equipment, authorized by whom, for what window — you are not ready to build the range.

## 3. Topology

A four-node range is enough for every exercise in `hunting-exercises.md` — two victims, a collector, and an optional attacker — and small enough to snapshot and rebuild:

```text
                    ┌──────────────────────────────────────────────┐
                    │      vmnet-lab (internal / host-only)         │
                    │      e.g. 10.10.10.0/24, no default route     │
                    └──────────────────────────────────────────────┘
                             │             │             │
        ┌────────────────────┘             │             └───────────────────┐
        │                                  │                                 │
┌───────────────┐                 ┌─────────────────┐               ┌────────────────┐
│  WIN-VICTIM   │                 │   LINUX-VICTIM  │               │   COLLECTOR    │
│  Windows 10/11│                 │  Debian/Ubuntu  │               │  Debian/Ubuntu │
│  Sysmon       │                 │  auditd         │               │  log store     │
│  Winlogbeat / │ ──────────────► │  rsyslog /      │ ────────────► │  SIEM / files  │
│  Elastic Agt  │   forwarding    │  Filebeat       │   forwarding  │  Zeek (opt.)   │
└───────────────┘                 └─────────────────┘               └────────────────┘
        ▲                                  ▲                                 ▲
        │                                  │                                 │
        └──────────────────────────────────┴─────────────────────────────────┘
                                           │
                                  ┌─────────────────┐
                                  │  ATTACKER (opt) │
                                  │  Kali Linux     │
                                  │  emulation only │
                                  └─────────────────┘
```

**Why this shape.** The two victims give you both operating systems' telemetry. The collector is the thing you query, so it must be separate from the victims — hunting a host on the host teaches you nothing about centralised data. The attacker is optional but valuable: it produces the ground truth you test your hunt against.

**Addressing.** Give every node a static address in one lab-only subnet and write the assignments down. DHCP churn in a range makes every finding unreproducible.

| Node | Role | Example address |
| --- | --- | --- |
| `win-victim` | Windows endpoint telemetry (Sysmon, Event Log, PowerShell logging) | `10.10.10.11` |
| `linux-victim` | Linux endpoint telemetry (`auditd`), can also host a web service or SSH | `10.10.10.12` |
| `collector` | Central log store and query surface; optionally a Zeek sensor | `10.10.10.20` |
| `attacker` | Technique emulation only — never leaves the subnet | `10.10.10.50` |

## 4. Resource requirements

A comfortable range fits on a modern workstation. Budget RAM first; virtualisation memory overcommit is where ranges die with mysterious timeouts.

| Component | vCPU | RAM | Disk | Notes |
| --- | --- | --- | --- | --- |
| Hypervisor host (total) | 4–8 | **16 GB minimum**, 32 GB comfortable | 150 GB+ on SSD | SSD matters: log writing is constant |
| `win-victim` | 2 | 4 GB | 60 GB thin | Windows 10/11; 4 GB is the practical floor |
| `linux-victim` | 1–2 | 2 GB | 20 GB thin | No desktop environment needed |
| `collector` | 2–4 | 4 GB (8 GB for a full Elastic single-node) | 60 GB thin | Log volume grows fast; thin-provision and monitor |
| `attacker` | 2 | 2–4 GB | 40 GB thin | Kali or a minimal Linux with the emulation tooling |
| Zeek sensor (optional) | 1–2 | 2 GB | 20 GB | Can be co-located on the collector if RAM allows |

Practical notes:

- **Do not thin-provision the snapshot chain to death.** Long snapshot trees on a nearly full host disk are the most common cause of a corrupted range.
- **Host-only networking costs nothing and saves everything.** If you need package installs, add a second NAT adapter to one VM at a time.
- **Set every VM's clock the same way.** Pin all VMs to UTC and note it. Timestamps that disagree between nodes will break sequence hunts in ways that look like attacker behaviour.
- **Keep the range small and snapshotted** rather than large and fragile. You will iterate dozens of times; a five-minute rebuild is worth more than an extra node.

## 5. Build order

Build in this order and verify at each step. A range built all at once and debugged later produces telemetry gaps you will mistake for clean results.

### Step 1 — Hypervisor and isolated network

```text
1. Install the hypervisor (VirtualBox, VMware Workstation/ESXi, or KVM/libvirt).
2. Create an internal/host-only network: 10.10.10.0/24, DHCP disabled or scoped to the lab.
3. Create the four VMs with the resources from section 4, with no network adapters
   attached yet — attach them one at a time as you build.
4. Disable shared folders, shared clipboard, and drag-and-drop on every VM.
```

Name your snapshots consistently from the start — `00-clean-install`, `01-telemetry-verified`, `02-exercise-NN-before` — so reverting is a decision rather than an investigation.

### Step 2 — Windows victim

```text
1. Install Windows, fully patch it (this is the one time you should let it reach
   the internet — do it before you attach it to the isolated network).
2. Create a lab-only local account, e.g. 'labuser' with a lab-only password.
   Use it for the credential and account exercises.
3. Take snapshot '00-clean-install'.
4. Attach the internal adapter, set the static address, then install telemetry.
```

Install Sysmon from a baseline configuration and enable PowerShell logging (both are documented in `../tools/endpoint-tools.md`):

```powershell
# Sysmon: install with a baseline config, then confirm the channel exists
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5

# PowerShell script block logging (applies to new PowerShell sessions)
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
  -Name EnableScriptBlockLogging -Value 1 -Type DWord

# Command-line auditing for legacy 4688 events (belt and braces alongside Sysmon)
auditpol /set /subcategory:"Process Creation" /success:enable
```

Choose **one** forwarding mechanism and commit to it. Both of these are viable in a lab:

```powershell
# Option A: Winlogbeat (Elastic). Configure winlogbeat.event_logs for the
# Sysmon, Security, System, and PowerShell Operational channels, then:
.\winlogbeat.exe test config
.\winlogbeat.exe test output
.\install-service-winlogbeat.ps1

# Option B: native Windows Event Forwarding to a collector
winrm quickconfig
# On the collector: wecutil qc   then subscribe with a subscription definition:
# wecutil cs .\subscription.xml
```

### Step 3 — Linux victim

```bash
# Install the audit subsystem
sudo apt update && sudo apt install -y auditd audispd-plugins
sudo systemctl enable --now auditd

# Hunting rules with keys (one rule per line in /etc/audit/rules.d/hunt.rules)
cat <<'EOF' | sudo tee /etc/audit/rules.d/hunt.rules
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k exec
-w /etc/passwd -p wa -k identity
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/ssh/sshd_config -p wa -k ssh_config
EOF

sudo augenrules --load
sudo auditctl -l          # confirm the rules are loaded

# Forward the log to the collector (rsyslog example)
# /etc/rsyslog.d/50-audit.conf -> forward /var/log/audit/audit.log, then:
sudo systemctl restart rsyslog
```

### Step 4 — Collector

Pick the lightest option that can answer the questions you intend to ask, and only escalate when you hit its limit:

| Option | Setup cost | Good for | Ceiling |
| --- | --- | --- | --- |
| **Plain files + `rsyslog`** | Minutes | Learning the tools (Chainsaw, Hayabusa, `ausearch`) on real collected logs | No correlation, no dashboards |
| **Elastic single-node** | An hour, real RAM | KQL hunts, correlation, dashboards, EQL sequences | Memory-hungry; needs tuning |
| **Splunk Free** | An hour | Practising SPL and `stats`/`streamstats` pipelines | Daily ingest cap |
| **Velociraptor server** | An hour | Fleet-style querying of the victims, raw artefact collection | Not a retention/correlation engine |

```bash
# Collector baseline: create the receiving surface and prove it is writable
sudo mkdir -p /lab/logs/win /lab/logs/linux
sudo chown -R "$USER":"$USER" /lab/logs

# If you add a Zeek sensor on this node, capture on the lab interface only
# (see ../tools/network-tools.md for the log formats you get)
sudo zeek -i <lab-interface>
```

Keep a **range log** — a plain text file in the range directory — recording: VM names and addresses, snapshot names, every installed tool with its version, every configuration file you changed, and (crucially) when any VM had internet access. Without it, you cannot reproduce your own findings, and a hunt you cannot reproduce is an anecdote.

### Step 5 — Attacker (optional but recommended)

The attacker node exists to generate **known** activity. Two approaches, in increasing order of realism:

```text
A. Manual emulation. Run the technique yourself from the attacker VM or from the
   victim's own shell: create a scheduled task, add a Run key, start a beaconing
   script, copy a file over SMB. Cheapest, most controllable, and enough for every
   exercise in hunting-exercises.md.

B. Framework emulation. Atomic Red Team (atomic tests mapped to ATT&CK technique IDs)
   or CALDERA (automated adversary emulation). More realistic sequences, more moving
   parts, and more chances to generate activity you did not intend — log what you ran.
```

```powershell
# Atomic Red Team: documented install and invocation shape on the victim or attacker.
# Follow the project README for the current install steps and test numbers.
Install-AtomicRedTeam -getAtomics
Invoke-AtomicTest T1059.001          # technique-level: run all tests for the technique
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

> Emulation frameworks execute real attack techniques. Run them only inside the isolated range, only against victims you own, and only after checking the targets. Never install them on a machine that can reach anything you do not control.

## 6. Network isolation

Isolation is the control that keeps a hunting lab from becoming an incident.

```text
Checklist for every session, before you start any activity:

[ ] Victim and attacker adapters are internal/host-only — NOT bridged.
[ ] No route from the lab subnet to your LAN, your corporate network, or the internet.
[ ] Any NAT adapter used for package installs is detached or disabled.
[ ] Host integration (shared folders, clipboard, drag-and-drop) is off on every VM.
[ ] The attacker VM's default route, if it has one, points inside the lab only.
```

Verify isolation rather than assuming it:

```bash
# From the attacker VM: the only reachable route should be the lab subnet
ip route

# From a victim: confirm it cannot reach the internet while isolated
ping -c 2 10.10.10.20      # collector: expected to work
ping -c 2 8.8.8.8          # internet: expected to FAIL while the range is isolated
```

```powershell
# From the Windows victim
Get-NetIPConfiguration
Test-NetConnection 10.10.10.20     # collector
Test-NetConnection 8.8.8.8         # expected to fail while isolated
```

A ping that unexpectedly succeeds is a stop-work condition for the session, not a curiosity.

## 7. Snapshots and the golden baseline

The single highest-value habit in this lab: **snapshot a state you have verified, not a state you hope is right.**

```text
Snapshot discipline:

00-clean-install        OS installed and patched, no telemetry yet.
01-telemetry-verified   Sysmon + PowerShell logging + forwarding + auditd loaded,
                        and you have PROVED a real event reached the collector
                        (section 8). This is your golden baseline.
02-exercise-NN-before   Taken immediately before an exercise, so you can revert
                        to 'before' and re-run the same hunt against the same state.
```

Rules that keep snapshots useful:

- **Never take a snapshot of a victim while emulated activity is running.** You will restore an infected state as your baseline and spend an afternoon confused.
- **Verify, then snapshot.** A `01-telemetry-verified` snapshot taken before you confirmed the pipeline works encodes a broken range as truth.
- **Revert between exercises** rather than cleaning up by hand. Hand cleanup leaves artefacts that corrupt the next exercise's baseline.
- **Keep the collector's data and the victims' snapshots in step.** If you revert a victim but keep a week of collector data, your hunt window contains events from a state that no longer exists. Note the revert in the range log.

## 8. Verify the telemetry before you hunt

This is the step that people skip and later regret. **You are proving the pipeline, not hunting yet.** For each check, generate a known event, then find it in the collector.

### Windows

```powershell
# Generate a known event: a process creation you control
Start-Process notepad.exe

# And a known script block
powershell -Command "Write-Output 'LAB-TELEMETRY-CHECK'"

# Confirm it exists locally in Sysmon (Event ID 1) before chasing the collector
Get-WinEvent -FilterHashtable @{
  LogName   = 'Microsoft-Windows-Sysmon/Operational'
  Id        = 1
  StartTime = (Get-Date).AddMinutes(-5)
} | Select-Object TimeCreated, Id
```

Then run the equivalent query **on the collector** for the same time window. Look for: the event is present, `Image`/`CommandLine` are populated (not empty), the host name matches, and `TimeCreated` agrees with the victim's clock. If any of those fail, fix the pipeline before hunting — a missing field is a blind spot you will otherwise mistake for clean activity.

Also verify that PowerShell logging is live: `4104` events for your `Write-Output` check should exist in `Microsoft-Windows-PowerShell/Operational`. If they do not, the policy did not apply to the session you used — open a **new** PowerShell window and repeat.

### Linux

```bash
# Generate a known event
whoami
sudo -n true 2>/dev/null || true

# Confirm auditd recorded the execution by key
sudo ausearch -k exec -ts recent

# Confirm the log is being forwarded to the collector
sudo tail -n 5 /var/log/audit/audit.log
```

### Collector

```bash
# Files arriving?
ls -lh /lab/logs/win /lab/logs/linux

# If you run a SIEM: query for the lab check event by host and time window,
# then confirm the field names in a sample document before writing any hunt query.
```

**Only now take the `01-telemetry-verified` snapshot.** Then move on to `hunting-exercises.md`.

## 9. Reset the range from zero

Rebuild is a procedure, not a memory exercise. It should take minutes and produce an identical range.

```text
Standard reset (fast — revert, don't reinstall):

1. Stop the attacker VM and any emulation still running.
2. Revert every victim VM to '01-telemetry-verified'.
3. Revert or truncate the collector's data for the previous exercise
   (delete the index/dataset, or archive its export to /lab/exports/).
4. Confirm isolation again (section 6) — reverting a VM can restore an old adapter config.
5. Re-verify telemetry with the quick check: one process creation on Windows and one
   execve record on Linux, both found in the collector (section 8).
6. Timestamp a new entry in the range log: date, exercise number, snapshot names.
```

```text
Full rebuild (when the range is beyond reverting, or you want a clean-room check):

1. Delete or archive the VMs; keep the range log and any exported artefacts.
2. Recreate from section 5 in order, verifying at each step.
3. Re-take the snapshot chain: 00-clean-install, then 01-telemetry-verified
   only after the section 8 checks pass.
4. Diff your new configuration against the range log — any difference is either a
   deliberate change (record it) or a mistake (fix it now, while it is cheap).
```

> Rebuild the range from scratch at least once even if nothing is broken. It is the only way to know that your documented setup is sufficient — the same reason a backup is not a backup until you have restored from it.

## Common Mistakes & Tips

- **Hunting before telemetry is verified.** The most expensive mistake in this lab. A gap in collection looks exactly like clean activity, and you will write a confident, wrong conclusion on top of it.
- **Bridging the attacker VM "just for a moment".** That moment is the whole risk. Isolate first, install packages deliberately, isolate again.
- **Snapshotted after emulation.** You have just promoted an infected state to baseline. Always revert to a verified-clean snapshot between exercises.
- **Clock drift between nodes.** A sequence hunt across drifted clocks produces impossible orderings. Pin every VM to UTC and check the offset before you build a timeline.
- **Only forwarding the Security log.** Service installs (`7045`) arrive in System, task changes in TaskScheduler Operational, PowerShell in its own channel. Configure the whole set or document the gap.
- **A channel that wrapped before you collected it.** Small default log sizes on a lab VM lose data within days. Increase channel sizes and forward continuously.
- **Emulation without a record.** If you do not log what you ran and when, you cannot tell whether your hunt found the technique or noise — and you cannot score your own hunt.
- **A range that is too big to rebuild.** Four nodes you can rebuild in five minutes beat fifteen you are afraid to touch.
- **Forgetting the ethics line.** Every session: is this my system or is this authorized, in writing, for this window? If the answer is not an immediate yes, stop.

## Checklist / Self-Test

- [ ] I can state, in one sentence, the authorization under which I run this range.
- [ ] All four VMs use an internal/host-only network, and I verified no route leaves the lab subnet.
- [ ] Shared folders, clipboard, and drag-and-drop are disabled on every VM.
- [ ] Windows victim: Sysmon is installed from a baseline config and the channel produces events.
- [ ] Windows victim: PowerShell script block logging produces `4104` events for a known script.
- [ ] Windows victim: events reach the collector with `Image` and `CommandLine` populated.
- [ ] Linux victim: `auditd` rules are loaded, keyed, and produce `execve` records I can query with `ausearch -k`.
- [ ] Collector: I can query both victims' telemetry for a bounded time window with no gaps.
- [ ] I have a verified `01-telemetry-verified` snapshot for every victim.
- [ ] I can reset the range to the golden baseline in under ten minutes, and I have done it at least once.
- [ ] My range log records addresses, versions, changed configuration files, snapshot names, and any internet exposure.
- [ ] Every VM in the range is mine or covered by written authorization.

## Further Resources

- Sysmon and baseline configurations — learn.microsoft.com/sysinternals/downloads/sysmon; github.com/SwiftOnSecurity/sysmon-config; github.com/olafhartong/sysmon-modular.
- Windows Event Forwarding and `wecutil` — learn.microsoft.com/windows/win32/wec/windows-event-collector.
- Winlogbeat and Elastic Agent — elastic.co/guide/en/beats/winlogbeat/current/index.html.
- `auditd` and Linux Audit — man pages for `auditd`, `auditctl`, `ausearch`, `aureport`; github.com/linux-audit.
- Atomic Red Team — github.com/redcanaryco/atomic-red-team (install and test documentation).
- MITRE CALDERA — caldera.mitre.org.
- MITRE ATT&CK — attack.mitre.org (technique IDs used to write emulation and hunt hypotheses).
- Velociraptor documentation (fleet querying against your range) — docs.velociraptor.app.
- Official eCTHP page on the INE website for current, authoritative details about the certification.
