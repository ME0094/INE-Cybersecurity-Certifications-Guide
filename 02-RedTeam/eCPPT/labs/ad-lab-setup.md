# Building an Active Directory Lab

> 02-RedTeam · eCPPT labs — INE-Cybersecurity-Certifications-Guide (English)

A small, deliberately misconfigured Active Directory lab is where eCPPT-style
skills (domain enumeration, Kerberoasting, pass-the-hash, ACL abuse, delegation
attacks) become muscle memory. This guide builds that lab on a hypervisor with
**Windows Server evaluation media** (free, 180-day trial), **Windows client
VMs**, and a **Kali** attack box. Everything is your own isolated environment —
that is what makes practicing attacks legal.

## Lab design and requirements

| VM | Role | Specs (minimum) | IP (example) |
|---|---|---|---|
| `DC01` | Windows Server 2022 Evaluation — Domain Controller + DNS + DHCP | 2 vCPU / 4 GB / 60 GB | `10.0.0.10` (static) |
| `SRV01` | Windows Server 2022 Evaluation — file server, misconfig target | 2 vCPU / 2 GB / 40 GB | `10.0.0.11` (static) |
| `WS01` | Windows 10/11 Pro/Enterprise Evaluation — joined workstation | 2 vCPU / 4 GB / 60 GB | DHCP |
| `KALI` | Kali Linux — attack box | 2 vCPU / 4 GB / 40 GB | `10.0.0.50` (static) |

Total host memory needed: ~16 GB. Use a **host-only or isolated NAT network**
(e.g., `10.0.0.0/24`) so lab traffic never reaches your real LAN.

> Create the *domain* with a private TLD that is obviously fake: `corp.local`,
> `lab.corp`, or similar. Never use a real public domain.

## 1. Domain controller (DC01)

1. Install **Windows Server 2022 Evaluation (Desktop Experience)**.
2. Set a static IP, point DNS to itself, rename the host, reboot:

```powershell
# In an elevated PowerShell on DC01:
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.0.0.10 -PrefixLength 24 -DefaultGateway 10.0.0.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1
Rename-Computer -NewName DC01 -Restart
```

3. Install the AD DS role and promote to a new forest (this is the whole
   domain: no parent):

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest `
  -DomainName "corp.local" `
  -DomainNetbiosName "CORP" `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "DSRM-P@ssw0rd!" -AsPlainText -Force) `
  -InstallDns:$true `
  -Force:$true
# The server installs DNS, creates the forest, and reboots automatically.
```

4. After reboot verify: `Get-ADDomain`, `Get-ADDomainController -Filter *`,
   and `dcdiag`.

## 2. DNS and DHCP

DNS was installed with AD DS. Confirm forward lookup works, then add DHCP so
clients configure themselves:

```powershell
# DNS checks (from DC01)
Resolve-DnsName corp.local
Resolve-DnsName dc01.corp.local

# Add the DHCP role
Install-WindowsFeature DHCP -IncludeManagementTools

# Create a scope for clients (needs the DHCP admin group + authorization)
Add-DhcpServerv4Scope -Name "LabClients" -StartRange 10.0.0.100 -EndRange 10.0.0.200 -SubnetMask 255.255.255.0
Set-DhcpServerv4OptionValue -OptionId 6 -Value 10.0.0.10      # DNS server
Set-DhcpServerv4OptionValue -OptionId 3 -Value 10.0.0.1       # gateway
Add-DhcpServerInDC -DnsName dc01.corp.local                    # authorize in AD
Restart-Service dhcpserver
```

## 3. Users, groups, and OUs

Create a structure you can attack later: OUs per department, normal users, a
service account, and a "real" Domain Admin that is *not* the built-in
Administrator.

```powershell
# OUs
New-ADOrganizationalUnit -Name "Employees" -Path "DC=corp,DC=local"
New-ADOrganizationalUnit -Name "Service Accounts" -Path "DC=corp,DC=local"
New-ADOrganizationalUnit -Name "Servers" -Path "DC=corp,DC=local"

# Helper function to create an enabled user quickly
function New-LabUser($Sam, $Name, $OU, $Pass) {
    New-ADUser -SamAccountName $Sam -Name $Name -UserPrincipalName "$Sam@corp.local" `
        -Path $OU -AccountPassword (ConvertTo-SecureString $Pass -AsPlainText -Force) -Enabled $true
}
New-LabUser "alice" "Alice Sales"   "OU=Employees,DC=corp,DC=local" "Autumn2024!"
New-LabUser "bob"   "Bob IT"        "OU=Employees,DC=corp,DC=local" "Autumn2024!"
New-LabUser "mike"  "Mike Jr. IT"   "OU=Employees,DC=corp,DC=local" "Autumn2024!"

# A *separate* account that is really in Domain Admins (DA compromises should
# feel different from Administrator)
New-LabUser "da.smith" "Dana Smith (DA)" "OU=Employees,DC=corp,DC=local" "Summer2024!x"
Add-ADGroupMember -Identity "Domain Admins" -Members "da.smith"

# A Kerberoastable service account with a weak password (intentional!)
New-ADUser -SamAccountName "svc_sql" -Name "SQL Service Account" `
    -Path "OU=Service Accounts,DC=corp,DC=local" -Enabled $true `
    -AccountPassword (ConvertTo-SecureString "sqlp@ss123" -AsPlainText -Force)
Set-ADUser svc_sql -ServicePrincipalNames @{ Add = "MSSQLSvc/sql01.corp.local:1433" }
```

Group strategy for later scenarios: a `WebAdmins` domain group acts as local
admin on SRV01 via group nesting; the built-in high-value groups stay untouched.

## 4. Deliberate misconfigurations

The lab is only useful if it *contains* the weaknesses you want to practice —
enable them intentionally:

```powershell
# --- Misconfig 1: Password reuse + a domain user local-admin on SRV01 ----
# On SRV01 (as local Administrator), add domain users to local admins:
Add-LocalGroupMember -Group "Administrators" -Member "CORP\bob"
Add-LocalGroupMember -Group "Administrators" -Member "CORP\svc_sql"

# --- Misconfig 2: Same local Administrator password on every host ---------
# (Run on DC01 and SRV01): mimics the classic pass-the-hash playground
Set-LocalUser -Name Administrator -Password (ConvertTo-SecureString "LocalAdm!2024" -AsPlainText -Force)

# --- Misconfig 3: WDigest plaintext storage (mimikatz sekurlsa practice) ---
# (On SRV01, then reboot and log users on)
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

# --- Misconfig 4: Unconstrained delegation on SRV01 -----------------------
Set-ADComputer -Identity SRV01 -TrustedForDelegation $true

# --- Misconfig 5: ACL abuse - mike may reset da.smith's password ----------
# (Do this from an elevated session as a domain admin; GUI alternative:
#  ADUC -> da.smith -> Properties -> Security -> Add mike -> "Reset password")
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    (New-Object System.Security.Principal.NTAccount("CORP\mike")),
    "ExtendedRight","Allow",
    [guid]"00299570-246d-11d0-a768-00aa006e0529")   # User-Force-Change-Password
$acl = Get-Acl "AD:\CN=da.smith,OU=Employees,DC=corp,DC=local"
$acl.AddAccessRule($rule)
Set-Acl "AD:\CN=da.smith,OU=Employees,DC=corp,DC=local" $acl

# --- Misconfig 6: Enable WinRM + RDP everywhere for lateral movement ------
# On each Windows VM (elevated):
Enable-PSRemoting -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

Each misconfiguration gets a one-line comment in your notes explaining what
technique it enables — that mapping is exactly what the attack simulations
drill.

## 5. Join client machines

On WS01 (Windows 10/11 Pro or Enterprise), point DNS at the DC, then join:

```powershell
# WS01, elevated: set DNS, join, reboot
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.0.0.10
Add-Computer -DomainName corp.local -Credential CORP\Administrator -Restart
```

Verify on the DC afterwards: `Get-ADComputer -Filter *` and, from WS01,
`whoami /fqdn` and `nltest /dsgetdc:corp.local`. Log `bob` and `alice` into
WS01 at least once so session data exists for BloodHound later.

## 6. Attack box (Kali) and tooling

```bash
# Kali on the same host-only network; static IP, DNS -> DC
sudo tee /etc/network/interfaces.d/lab <<'EOF'
auto eth0
iface eth0 inet static
    address 10.0.0.50
    netmask 255.255.255.0
    gateway 10.0.0.1
    dns-nameservers 10.0.0.10
EOF

# Tools used by the labs and simulations
sudo apt update
sudo apt install -y bloodhound bloodhound-python neo4j impacket-scripts \
                    netexec evil-winrm hashcat seclists
```

Check reachability and name resolution:

```bash
ping -c1 10.0.0.10
nslookup dc01.corp.local 10.0.0.10
nmap -Pn -p 53,88,135,139,389,445,5985 10.0.0.10   # DC ports open?
```

## 7. Networking, time sync, and snapshots

- **Isolation**: all lab VMs on one host-only network; no internet from the
  DC/clients is *required*, but Kali needs internet for package installs (use
  NAT only during setup, then switch to host-only).
- **Time sync**: Kerberos fails if clocks drift more than ~5 minutes. Let
  clients sync to the DC:
  `w32tm /config /syncfromflags:domhier /update && w32tm /resync` (or keep
  VMware Tools time sync enabled and correct on the DC).
- **Snapshots** (the single most important lab habit):
  1. After AD install + DNS verify → snapshot `01-DC-Base`.
  2. After joining WS01 and adding all users/misconfigs → snapshot
     `02-Lab-Clean` — this is your reusable baseline.
  3. Before **every** attack simulation → snapshot `Scenario-N-Start`.
  4. To reset: revert to `02-Lab-Clean`, change any passwords you reset during
     the previous run, and re-snapshot.
- **Memory snapshots** capture active sessions — take them *after* logging
  users in if you want session data on restore.

## Checklist / Self-test

- [ ] DC01 promotes cleanly; `dcdiag` reports no errors
- [ ] Clients get IP/DNS from DHCP and resolve `corp.local`
- [ ] All planned users/groups exist and the service account has an SPN
- [ ] Every deliberate misconfiguration is enabled and documented
- [ ] WS01 is domain-joined and can query `whoami /fqdn` as `CORP\bob`
- [ ] Kali resolves and scans the DC; BloodHound/impacket tools installed
- [ ] Snapshot `02-Lab-Clean` exists and restoring it works
- [ ] I can reproduce the whole build from these notes alone in under a day

## Common mistakes & tips

- **Real TLD or public DNS name** — always use `.local`/fake domains to avoid
  DNS conflicts and legal-looking traffic.
- **Forgetting DSRM/SAFE mode password** — write it down; you need it for
  directory repairs.
- **Clocks out of sync** — Kerberos errors (`KRB_AP_ERR_SKEW`) trace back to
  time 90% of the time.
- **Lab without snapshots** — you *will* break the domain during an ACL or
  delegation exercise; snapshots make that a 2-minute fix.
- **Antivirus interfering with exercises** — Windows Defender real-time
  protection will quarantine Mimikatz/SharpHound; in this *isolated lab* you
  may disable it, but never on anything real.
- **Joining clients with DNS pointing at the router** — the #1 "can't find the
  domain" cause; DNS must point at the DC.

## Further resources

- [Microsoft Learn — Install Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100-)
- [Microsoft Learn — Active Directory administrative center / ADUC](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/active-directory-administrative-center)
- [Microsoft Learn — Windows Server evaluation downloads](https://www.microsoft.com/en-us/evalcenter/)
- [Kali Linux — documentation](https://www.kali.org/docs/)
- [HackTricks — Active Directory methodology](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology.html)
