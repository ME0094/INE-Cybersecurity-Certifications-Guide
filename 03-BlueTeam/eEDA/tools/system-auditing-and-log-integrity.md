# System Auditing and Log Integrity

> eEDA · Tools — INE-Cybersecurity-Certifications-Guide
>
> The tools that answer "what happened on this host, and can I still prove it next month?" — `auditd` rules and searches, `journald`, the Windows event log's own configuration, and the retention and forwarding controls that decide whether a record is evidence or a liability. Read this with [../methodology/04-security-engineering](../methodology/04-security-engineering.md) (logging architecture and pipeline controls) and [../methodology/09-soc-and-incident-response-interface](../methodology/09-soc-and-incident-response-interface.md) (what the administrator owes the SOC).

## 1. Behaviour Questions and Their Sources

[Endpoint Inventory and Query](endpoint-inventory-and-query.md) splits state from behaviour: inventory answers *what exists*, auditing answers *what happened*. The auditing sources are not interchangeable, and picking the wrong one produces a confident empty answer.

| Question | Source that can answer it | Why not the others |
|---|---|---|
| Who changed `/etc/passwd`, and when? | `auditd` file watch with a key | The package database and file metadata show the current state, not the author |
| Which commands ran as root? | `auditd` `execve` rules, or EDR process telemetry | `journald` records service output, not every command line |
| Why did this service restart at 03:12? | `journald` unit messages | `auditd` only sees what a rule matches; unit internals are not kernel audit events |
| Which process wrote that registry value? | Sysmon or EDR telemetry | The Windows Security channel does not record registry writes by default, and `auditd` is Linux-only |
| Was an account created, and by whom? | `auditd` watch on the account files, plus the Windows Security channel's account-management events | A user list shows the account exists now; it does not name the creator |
| What was deleted from the log? | Nothing on the host — this is the question only **off-host** copies can answer | A log cannot testify to its own missing rows; see section 5 |

> Rule of thumb for auditing: **a rule records what it matches, and nothing else.** Absence of an event is not absence of activity — it is either no activity or no rule.

## 2. auditd: Rules That Survive a Reboot

**What it is.** The Linux kernel audit subsystem with the `auditd` userspace daemon: it records syscalls, file access, and attribute changes to a log written by root-owned processes, so the account being watched cannot quietly rewrite its own trail — as long as the log is not on the same compromised host.

**What it produces.** `/var/log/audit/audit.log` plus rotated files, queried with `ausearch` and summarised with `aureport`.

**How to use it.** Rules come in two forms, and only one of them survives a reboot:

```bash
# Live rules -- convenient for testing, GONE on reboot
sudo auditctl -w /etc/passwd -p wa -k identity
sudo auditctl -l                                  # list what is currently loaded

# Persistent rules -- the only form that counts as a control
#   write /etc/audit/rules.d/<name>.rules, then load them:
sudo augenrules --load
```

Example persistent rule file `/etc/audit/rules.d/eeda-baseline.rules`:

```text
# Credential and privilege files: writes and attribute changes
-w /etc/passwd  -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/group   -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Command execution by real users (auid) -- not by system services
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k exec

# Make the loaded rule set immutable until the next reboot
-e 2
```

Rule anatomy, token by token:

| Token | Meaning | Note |
|---|---|---|
| `-w /path` | Watch a file or directory | Trailing slash means "this directory and its children" |
| `-p wa` | Permissions to audit: `w`rite, `a`ttribute change; also `r`ead, `x` execute | Watching reads is expensive and noisy |
| `-k <key>` | Your own search key | The key is what makes `ausearch -k` usable; name it after the control, not the path |
| `-a always,exit -S execve` | Syscall rule: act on every exit of this syscall | `arch=b64` keeps 32-bit compatibility calls from doubling your events |
| `-F auid>=1000 -F auid!=unset` | Filter to a logged-in user's session | Without this, cron and daemons flood the exec key |
| `-e 2` | Immutable: rules cannot be changed until reboot | A rule set an attacker can unload is not a control |

Five settings in `/etc/audit/auditd.conf` decide what happens when the log is under pressure, and they are the difference between "we have a gap" and "we have evidence":

| Setting | What it decides |
|---|---|
| `max_log_file` | Size in MB before the log is rotated |
| `max_log_file_action` | What to do at that size: rotate, keep, or stop |
| `num_logs` | How many rotated logs are kept — your on-host history window |
| `space_left_action`, `admin_space_left_action` | What happens as the disk fills (warn, email, or take the host down) |
| `disk_full_action`, `disk_error_action` | The last resort when there is no space left or the disk errors |
| `flush` | How often buffered audit data reaches disk |

Confirm the accepted values on your build with `man auditd.conf` before you change any of them — the failure modes differ, and one of them stops the system.

Two failure modes worth memorising, because both are silent:

- **Backlog overflow.** The kernel queue fills under load and events are dropped. The dropped count is in `auditctl -s` (`lost`), which nobody reads until an investigation has a hole in it. Alert on it.
- **Not configured at all.** A host with no rules and an empty `ausearch` looks exactly like a host where nothing happened.

## 3. Searching and Reporting: ausearch and aureport

Once the rules run and the key exists, the value is in retrieval. Ask for a claim you can defend in a report, with a time range and a source file:

```bash
# Everything tagged with the identity key, today, interpreted (-i)
sudo ausearch -k identity -ts today -i

# A bounded window -- the form that goes into an evidence folder
sudo ausearch -k identity -ts 09/01/2026 00:00:00 -te 09/08/2026 00:00:00 -i

# From a specific rotated file, after the live log has moved on
sudo ausearch -if /var/log/audit/audit.log.2 -k sudoers -i

# By message class or by executable, instead of by key
sudo ausearch -m EXECVE -ts today -i
sudo ausearch -x /usr/bin/sudo -ts today -i

# Summaries: the shape an auditor or a manager reads first
sudo aureport -au            # authentication
sudo aureport -l             # logins
sudo aureport -x             # executables
sudo aureport --summary      # all categories, one screen
```

The working loop is the same one [Compliance Tools](compliance-tools.md) describes for evidence generally: **decide the question → make sure a rule matches it → let the log collect → search by key over a bounded window → archive that output with the retention your policy promises.** The rule set and the search commands are two halves of one control; a rule nobody searches is cost without coverage.

## 4. journald: System and Service Events

**What it is.** systemd's logging service: it captures kernel messages and the standard output of units, stores them in a binary journal, and serves them through `journalctl`. It is the fastest way to answer "what did this service say before it died?".

**What it produces.** Journal entries with `_SYSTEMD_UNIT`, `_PID`, `_COMM`, priority, and boot ID metadata — fields you can filter on, which is why it beats plain text log files for service work.

```bash
journalctl -u sshd -b                 # one unit, current boot
journalctl -p err -b                  # errors and worse, current boot
journalctl -k                         # kernel messages only
journalctl --since "1 hour ago" --until "10 min ago"
journalctl --list-boots               # how far back this journal actually goes
journalctl --disk-usage               # space the journal is consuming
```

The single most consequential setting is **persistence**. With volatile storage the journal lives in `/run` and is destroyed at every reboot, so "the log is missing" is not an incident — it is the configured behaviour:

```ini
# /etc/systemd/journald.conf
[Journal]
Storage=persistent        # write to /var/log/journal, not /run/log/journal
SystemMaxUse=2G           # cap the total size
MaxRetentionSec=90day     # cap the age
ForwardToSyslog=yes       # let rsyslog ship it off-host as well
```

`journalctl --list-boots` is the honest check: if it shows a single boot on a host that has restarted many times, the setting is wrong or the journal was vacuumed.

**Integrity.** A journal file is a file under root's control, so it is not tamper-evident by default. Two controls change that, and they answer different questions:

- **Forward Secure Sealing (`Seal=yes` with `journalctl --setup-keys`)** makes tampering provable: entries are cryptographically sealed, and `journalctl --verify` reports what does not check out. You learn *that* someone edited the journal.
- **Forwarding off-host** (rsyslog, an agent, or `systemd-journal-upload`) makes deletion ineffective: the copy you need is somewhere the attacker did not have root. You keep the evidence itself.

Sealing proves; forwarding preserves. An estate with sealing but no forwarding can prove it lost its logs and still cannot reconstruct them.

## 5. Integrity: "the Log Is Missing" and What It Really Means

Log integrity is a design property, not a tool you install afterwards. Every row below is a real failure mode with a control that prevents it — and the control belongs to the administrator, not to the SIEM vendor.

| What you observe | What actually happened | Control that prevents it |
|---|---|---|
| Journal shows only the current boot | Volatile storage, or `--vacuum` ran | `Storage=persistent` plus a retention figure you can defend |
| The window you need has been rotated away | Rotation sized for disk, not for incident response | `num_logs`, `SystemMaxUse`, and a retention tier that matches policy |
| A silent gap of minutes in `auditd` | Backlog overflow under load | Watch the `lost` counter in `auditctl -s`; raise the backlog; alert on it |
| Audit stops entirely near a full disk | `disk_full_action` / `space_left_action` did what it was told | A dedicated volume for `/var/log/audit`, plus disk alerts well before the threshold |
| Windows Security log jumps forward in time | `retention: false` and `autoBackup: false`: oldest events are overwritten | Size the channel for the window you must keep, and forward to a collector |
| Every log on the host is gone | Root-level attacker cleared it (Windows records this) | Forward off-host **before** you need it; immutable or WORM storage for high-value logs |
| Correlated events do not line up | Clock skew between sources | NTP everywhere; a skewed log is not evidence |

The Windows side of that table is verifiable from the channel's own configuration. This is the real output from the workstation where this module was written — exactly what `wevtutil gl <channel>` prints:

```text
> wevtutil gl Security
name: Security
enabled: true
type: Admin
owningPublisher:
isolation: Custom
channelAccess: O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)
logging:
  logFileName: %SystemRoot%\System32\Winevt\Logs\Security.evtx
  retention: false
  autoBackup: false
  maxSize: 20971520
publishing:
  fileMax: 1
```

Read the three fields under `logging`: `maxSize: 20971520` is about 20 MB, `retention: false` means the oldest events are discarded as new ones arrive, and `autoBackup: false` means nothing is archived when the file fills. So this channel is a **ring buffer of its own recent past** — the exact configuration that loses the window an investigation needs once a chatty rule or a noisy event source fills 20 MB in a day. The fix is not "read the log more often": it is to size it deliberately and forward it.

## 6. Windows: Which Channel Answers What

The Windows equivalent of an audit rule set is a combination of **audit policy**, **channel configuration**, and — for depth the built-in channels lack — **Sysmon**.

| Channel | Answers | Notes |
|---|---|---|
| `Security` | Logon and logoff, account management, privilege use, log cleared (event 1102), object access if policy enables it | Requires elevation to read; content does not exist unless audit policy enables the subcategory |
| `System` | Service start and stop, driver load, unexpected shutdown | Readable without elevation; the fastest "why did the service restart?" answer |
| `Application` | Application errors and crashes | Vendor-dependent; useful context, weak evidence |
| `Microsoft-Windows-Sysmon/Operational` | Process creation with parent, command line and hashes; network connections; registry changes | **Not built in** — Sysmon has to be deployed, and its configuration file decides what exists |
| `Microsoft-Windows-PowerShell/Operational` | Script block logging, when policy enables it | The only good answer to "what did that PowerShell actually do?" |

```powershell
# Channel configuration: the integrity fields (works without elevation) -- verified here
wevtutil gl Security

# Every channel on the host, when you need the exact name of one
wevtutil el

# Read the System channel (works without elevation) -- verified here
Get-WinEvent -LogName System -MaxEvents 2

# Count events in a channel over a window
(Get-WinEvent -LogName System -MaxEvents 500 |
  Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-24) }).Count

# What is actually being audited (needs elevation)
auditpol /get /category:*
auditpol /set /subcategory:"Process Creation" /success:enable
```

Verified in the module's authoring environment, so you know what to expect:

```text
> Get-WinEvent -LogName System -MaxEvents 2
  Id LevelDisplayName TimeCreated
  -- ---------------- -----------
7040 Información      18/09/2026 14:48:11
7040 Información      18/09/2026 14:45:32

> Get-WinEvent -LogName Security -MaxEvents 1
FAILED: Attempted to perform an unauthorized operation.
```

Two lessons from that pair of commands, both about expectations rather than syntax: the `System` channel is readable from an ordinary session, while the `Security` channel **is not** — so a "read the Security log" step in a script fails silently or loudly depending on who runs it. And audit policy is the precondition for content: `auditpol /get /category:*` (which this sandbox refused to run, so no output is shown here) tells you whether process creation, logon, or object access is recorded at all. An empty `Security` channel and a disabled subcategory look identical from `Get-WinEvent`.

For a fleet, the honest architectural answers are **Windows Event Forwarding** (source-initiated subscription to a collector) or an agent that ships events to the SIEM. Reading channels host by host is a triage technique, not a collection strategy; the administrator's deliverable is the pipeline described in [../methodology/09-soc-and-incident-response-interface](../methodology/09-soc-and-incident-response-interface.md).

## 7. Choosing the Source Without Guessing

| If the question is about… | Start here | Because |
|---|---|---|
| A file your policy calls critical | `auditd` watch + key | Kernel-level, independent of the application's own logging |
| A command a human ran | `auditd` `execve` rule or EDR process telemetry | The shell's history file is editable by the user; audit is not |
| A service's behaviour before failure | `journalctl -u <unit>` | Unit stdout/stderr plus structured metadata |
| A Windows service or driver change | `System` channel | Recorded without extra policy |
| Authentication on Windows | `Security` channel, with audit policy enabled | Nothing is recorded until the subcategory is on |
| Process ancestry and command lines on Windows | Sysmon | The built-in channels do not carry it |
| Whether the log itself is trustworthy | Forwarding, retention, and sealing — section 5 | No host-local tool can prove its own completeness |

## Common Mistakes & Tips

- **Rules created with `auditctl` and never persisted.** They vanish on reboot, and nobody notices until an investigation asks about a window in the past. Write `/etc/audit/rules.d/*.rules` and load with `augenrules --load`.
- **Watching reads.** `-p r` on busy files or directories produces enormous volume, rotates your history away, and buries the signal. Watch writes and attribute changes; add reads only with a specific question.
- **Keys named after paths.** Use the control's name (`identity`, `sudoers`), so the same key survives a path change and reads well in an evidence list.
- **Leaving the default retention in place.** Windows channels at `retention: false` and a small `maxSize` overwrite the evidence you will want; the default is a decision someone made by not making one.
- **Assuming auditd remembers what it did not match.** New rules apply from the moment they load forward — never backward. Every rule you add today has no history.
- **Reading a log from the host you are investigating while logged in as a local administrator.** Your own actions join the evidence, and on a compromised host your reading is not necessarily what the file says.
- **Treating a full log as success.** `space_left_action` and `disk_full_action` decide between a gap and an outage. Read `auditd.conf` before an incident picks for you.
- **No clock discipline.** Correlating auditd, journald, and a firewall log without NTP produces a timeline nobody can trust — the [../methodology/04-security-engineering](../methodology/04-security-engineering.md) note lists time sync as a control, not a nicety.
- **Tip**: prove the pipeline with a known event. Change a watched file on purpose, then find it in the search, in the forwarded copy, and in the SIEM. A log path you have never tested end to end is an assumption.

## Checklist / Self-Test

- [ ] I can state, for one host, which of my security questions each source (`auditd`, `journald`, Windows channels, Sysmon) can and cannot answer.
- [ ] I can write a persistent audit rule file with two file watches and one `execve` rule, and load it with `augenrules --load`.
- [ ] I can explain what `-p wa`, `-k`, `-F auid>=1000`, and `-e 2` each do in a rule.
- [ ] I can retrieve events for one key over a bounded window with `ausearch` and summarise them with `aureport`.
- [ ] I can name three `auditd.conf` settings that decide what happens when the log runs out of space.
- [ ] I can check whether a journal survives a reboot and say which setting decides it.
- [ ] I can read `wevtutil gl Security` and explain what `retention`, `autoBackup`, and `maxSize` mean for an investigation.
- [ ] I can name two Windows channels readable without elevation and one that requires it.
- [ ] I can explain why an empty `ausearch` result is not evidence that nothing happened.
- [ ] I can describe the control that turns "the attacker deleted the logs" from a dead end into a survivable event.
- [ ] I have completed at least one end-to-end proof: created a known event, found it locally, and found it in the forwarded copy.

## Further Resources

- [Linux auditd man page](https://man7.org/linux/man-pages/man8/auditd.8.html) — daemon reference; see also `auditctl(8)`, `auditd.conf(5)`, `ausearch(8)`, `aureport(8)`.
- [Red Hat: Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening) — practical rule sets and key conventions.
- [systemd: journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html) — filtering, verification, and sealing options.
- [systemd: journald.conf](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html) — `Storage`, size limits, retention, and `Seal`.
- [Microsoft: Windows Event Forwarding](https://learn.microsoft.com/en-us/windows/win32/wevtutil/wevtutil) — the `wevtutil` command reference behind the `gl` output above.
- [Microsoft: Auditpol](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol) — reading and setting audit policy by subcategory.
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) — deployment and configuration for the process, network, and registry telemetry the built-in channels lack.
- [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final) — Guide to Computer Security Log Management, for retention and infrastructure reasoning.
- [CIS Controls](https://www.cisecurity.org/controls) — control 8 (Audit Log Management).

---

> ⚠️ Personal study notes. Commands marked as verified were executed in the Windows environment where this module was written and their output is reproduced verbatim. The Linux `auditd` and `journald` material is a syntax reference: no Linux host was available here, so confirm every flag on your build with the manual pages before relying on it, and never paste a rule set into production without testing it on a disposable VM.
