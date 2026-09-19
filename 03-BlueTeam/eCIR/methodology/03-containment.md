# eCIR Methodology — Phase 3: Containment

> eCIR · Incident Response Methodology — INE-Cybersecurity-Certifications-Guide

Containment limits the damage while the investigation continues. The goal is
not to clean the environment (that is Eradication) but to **stop the
bleeding**: cut off the adversary's access, prevent lateral movement and data
loss, and buy time to scope, preserve evidence, and plan recovery. NIST
SP 800-61 treats containment as a strategy decision that must balance speed,
evidence preservation, and business continuity — and it must be made *before*
acting, because many containment actions are themselves disruptive.
## Containment Goals and Decision Criteria
Containment succeeds when the adversary can no longer:
- reach the C2 infrastructure,
- authenticate with compromised credentials,
- move laterally to new hosts, or
- exfiltrate or encrypt data.

Decisions should weigh four criteria:

| Criterion | Question to ask |
| --- | --- |
| Speed vs. evidence | Act in seconds (exfiltration in progress) or capture evidence first? |
| Business impact | Which systems can we take offline without breaking the business? |
| Stealth vs. disruption | Will the adversary notice and accelerate (e.g., trigger ransomware)? |
| Legal / compliance | Is there a legal hold or regulatory duty to preserve data? |

```text
Containment decision aid (example):
- Exfiltration observed in real time -> act now, preserve what you can later.
- C2 beaconing only, no data movement -> capture a network/process snapshot
  first, then isolate.
- Attacker active on domain controllers -> do NOT kill the DCs blindly;
  disable the compromised accounts and cut the C2 path first, or you may
  lock out the enterprise and tip off the adversary.
```
## Short-Term vs. Long-Term Containment
- **Short-term containment** is immediate, often coarse: isolate hosts, block
  IPs, disable accounts. It stops the bleeding but is usually not sustainable
  (business disruption, lost visibility).
- **Long-term containment** is a deliberate, temporary state that keeps the
  adversary out while eradication and recovery are prepared: e.g., rebuilt
  network segments with stricter rules, accounts recreated with MFA, and
  critical data blocked at the application layer.

```text
Example sequence:
Short-term: isolate the 40 infected endpoints at the switch/EDR level.
Long-term:  while eradication is prepared, move critical servers to a
            segmented "clean" VLAN with allowlisted access and monitor all
            traffic entering it.
```

Never mistake long-term containment for done: it is a bridge, not a
destination. Track every temporary rule so it is removed or made permanent
during Eradication/Recovery — stale containment rules are a classic finding
in post-incident reviews.
## Host Isolation
Isolating a host stops it from reaching the network — and the network from
reaching it. Prefer the method that preserves the most evidence and
management capability:
1. **EDR/agent isolation** (best): vendor features isolate the endpoint while
   keeping the agent and your management channel alive.
2. **Network-level isolation** at the switch/VM/firewall (good): move the
   host to a quarantine VLAN or block its traffic without touching the disk.
3. **Host firewall / NIC disable** (last resort): severs your own management
   path and is hard to reverse remotely.

```powershell
# Windows: block inbound AND outbound at the host firewall (use with care —
# this also blocks your remote management of the host)
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

# Linux: drop all traffic to/from the host
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
```

Record the MAC/IP and switch port before isolation so the host can be found
and reconnected later, and keep an out-of-band path (KVM, iLO/iDRAC) in case
host-level blocking cuts SSH/RDP.
## Account Disabling and Credential Response
Compromised accounts are the adversary's keys — take them back. Act on the
*account*, not just the session, and remember that an attacker may have
created backdoor accounts (check for new accounts in privileged groups during
detection).

```powershell
# Disable the compromised account
Disable-ADAccount -Identity jsmith

# Force a password reset on next logon
Set-ADAccountPassword -Identity jsmith -Reset `
  -NewPassword (Read-Host -AsSecureString)
Set-ADUser -Identity jsmith -ChangePasswordAtLogon $true

# Revoke active sessions (RDP example — run against the target host)
query user /server:SRV-APP01
logoff 3 /server:SRV-APP01

# Cloud/IdP: revoke sessions and tokens from the identity-provider admin
# console; rotate API keys and service-account secrets the account could reach.
```

Credential hygiene rules during containment:
- Disable accounts *before* resetting passwords, so the attacker cannot use
  the brief reset window.
- Treat every credential the account touched as exposed: password vaults,
  service accounts, cached domain credentials, API keys, certificates.
- If privileged credentials (e.g., domain admin) are suspected exposed, plan
  a full rotation — including `krbtgt` if a golden-ticket attack is
  suspected — as part of Eradication, not ad hoc.
## Network Segmentation and IOC Blocking
Cut the adversary's command-and-control and movement paths at the network
layer. Block *known* attacker infrastructure quickly, but remember IP and
domain blocks are temporary — adversaries rotate infrastructure. The durable
fix is segmentation and allowlisting.

```powershell
# Windows Firewall: block outbound to a known C2 IP
New-NetFirewallRule -DisplayName "IR Block C2 203.0.113.66" `
  -Direction Outbound -RemoteAddress 203.0.113.66 -Action Block
```

```bash
# Linux firewall: drop traffic to/from a C2 host
sudo iptables -A OUTPUT -d 203.0.113.66 -j DROP
sudo iptables -A INPUT -s 203.0.113.66 -j DROP
```

Also block the DNS path by **sinkholing** the malicious domain on your DNS
server (point it to a sinkhole IP and log every query). Larger moves that
belong in long-term containment:
- Move critical servers into a protected segment where only allowlisted
  source/destination pairs are permitted.
- Enforce network-level authentication (802.1X) so compromised endpoints
  cannot simply join the trusted LAN.
- Apply micro-segmentation between tiers (web -> app -> DB) so a compromised
  web server cannot reach the database directly.
## Preserving Evidence While Containing
Containment and forensics conflict: isolation often destroys volatile
evidence. Where the situation allows, capture the most volatile data
**before** you cut the network. Follow the **order of volatility from RFC 3227,
*Guidelines for Evidence Collection and Archiving*, §2.1** — most volatile first:

1. Registers, cache
2. Routing table, ARP cache, process table, kernel statistics, memory
3. Temporary file systems
4. Disk
5. Remote logging and monitoring data relevant to the system in question
6. Physical configuration, network topology

The eCDFP module carries the same order under the same six headings
(`../../eCDFP/methodology/01-acquisition.md`), with swap/pagefile spelled out at level 3.
Use one list, not two.

```powershell
# Windows: VOLATILE state first — this is what isolation and power-off destroy.
# Write to the mounted evidence medium with an ABSOLUTE path, never to C:\ and never
# to a relative folder: a capture on the investigated host contaminates the case.
$EV = 'E:\evidence\case-014'
New-Item -ItemType Directory -Force -Path $EV | Out-Null
# A literal "Z" in a format string is a character, not a conversion: it stamps a LOCAL
# time as if it were UTC. Convert first, then format.
(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") | Out-File "$EV\start-time.txt"
Get-NetTCPConnection -State Established | Export-Csv "$EV\connections.csv"
Get-Process | Select-Object Id, ProcessName, Path, StartTime |
  Export-Csv "$EV\processes.csv" -NoTypeInformation
```

```powershell
# Windows: on-disk triage capture — NOT volatile. Read it whenever it is convenient,
# but capture it before eradication, because cleanup destroys it.
$EV = 'E:\evidence\case-014'
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' |
  Out-File "$EV\runkeys.txt"
# Hash key artifacts (copy to evidence media first, then hash the copy)
Get-FileHash -Algorithm SHA256 C:\Windows\Temp\sample.dll |
  Out-File "$EV\hashes.txt"
```

Registry `Run` keys and a file hash are **persisted state, not volatile state**: they survive a
reboot, so putting them in the volatile block teaches the wrong reflex. Keep the two captures
separate and label them as such in the case file.

```bash
# Linux: VOLATILE state first, before cutting the network.
# Run as root (sudo -i). $EV is an ABSOLUTE path on the mounted evidence medium.
EV=/mnt/evidence/case-014
mkdir -p "$EV"
ss -tunap > "$EV/connections.txt"
ps -auxf  > "$EV/processes.txt"
```

```bash
# Linux: on-disk triage capture — NOT volatile, and not on the host's own root filesystem.
EV=/mnt/evidence/case-014
sha256sum /tmp/sample.bin > "$EV/hashes.txt"
```

Evidence-handling rules while containing:
1. Document every action with a timestamp (scribe or log).
2. Capture to dedicated evidence media, never the system under investigation.
3. Use write blockers for disk acquisition; hash before and after (chain of
   custody).
4. Do not "clean up" malware yet — removal belongs to Eradication and may
   destroy evidence you still need to scope fully.

```text
Chain-of-custody log (example fields):
Date/Time (UTC) | Action | Performed by | Evidence ID | Location | Notes
2025-06-01 03:12Z | RAM capture | jdoe | E-001 | host srv01 | WinPmem, hash ok
2025-06-01 03:15Z | Network cut | jdoe | — | srv01 | switch port 12 disabled
```
## Documenting Containment and Re-scoping
Containment is not a single action — it is a state that must be maintained
and verified:
- Re-check periodically that blocked IOCs are still blocked and isolated
  hosts are still isolated (attackers or automation may undo your work).
- Re-run the scope questions from Detection after each containment action:
  did the adversary find an alternate path?
- Record each action's *effectiveness* (e.g., "C2 beaconing stopped at
  03:16Z after firewall rule applied") — this feeds Metrics and Lessons
  Learned in Phase 5.
## Common Mistakes & Tips
- **Mistake:** Isolating a host and destroying the network evidence needed to
  find the C2 or exfiltration target. **Tip:** Capture connections and
  processes first when seconds of delay are affordable.
- **Mistake:** Disabling the wrong account or locking out legitimate users
  because the alert named a shared mailbox/service account. **Tip:** Verify
  the account and its dependencies before disabling.
- **Mistake:** Host-level firewall blocking that severs your only management
  channel. **Tip:** Prefer EDR isolation or switch-level quarantine; keep an
  out-of-band path.
- **Mistake:** Blocking one C2 IP while the adversary has ten more and a
  fast-flux domain. **Tip:** Block the domain and DNS path too, and treat IP
  blocks as temporary.
- **Mistake:** Forgetting attacker-created backdoor accounts — you contain
  the original account and they walk back in through the new one. **Tip:**
  Audit new/changed privileged accounts and group membership early.
- **Mistake:** Leaving temporary containment rules in place for months.
  **Tip:** Tag every rule with owner and expiry; review in Phase 5.
- **Mistake:** Containing without telling business owners, who then "fix" the
  outage by re-enabling the host. **Tip:** Communicate the plan and expected
  duration through the defined escalation channel.
## Checklist / Self-Test
- [ ] I can explain the difference between short-term and long-term
      containment and give one example of each.
- [ ] I can list the four decision criteria for choosing a containment action
      and apply them to a scenario.
- [ ] I can rank host-isolation methods (EDR, network, host firewall) by
      evidence preservation and reversibility.
- [ ] I can disable a compromised Active Directory account and reset its
      password in the correct order with PowerShell.
- [ ] I can block a C2 IP at the host firewall and explain why IP/domain
      blocking alone is only temporary.
- [ ] I know the order of volatility (RFC 3227) and can separate volatile capture
      (connections, processes, memory) from on-disk triage (Run keys, file hashes),
      and say which of the two isolation destroys.
- [ ] I can fill in a chain-of-custody log entry and explain why it matters.
- [ ] I can describe why checking for attacker-created backdoor accounts is
      part of account containment.

> **Verification:** the order of volatility was **checked against RFC 3227, *Guidelines for
> Evidence Collection and Archiving*, §2.1** (`curl` of the RFC text, HTTP 200 on 2026-09-19) and
> the six levels above are its wording, not a paraphrase. The NIST SP 800-61 Rev. 3 link was
> checked with `curl` on 2026-09-19 (HTTP 200). The PowerShell and shell capture blocks are
> **unverified syntax references — not run**: the paths are illustrative and must be pointed at
> your own mounted evidence medium before use.

## Further Resources
- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide* —
  https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- NIST SP 800-61 Rev. 3, *Incident Response Recommendations and Considerations for
  Cybersecurity Risk Management: A CSF 2.0 Community Profile* (April 2025) —
  https://csrc.nist.gov/pubs/sp/800/61/r3/final
- RFC 3227, *Guidelines for Evidence Collection and Archiving* (order of volatility) —
  https://www.rfc-editor.org/rfc/rfc3227
- NIST SP 800-86, *Guide to Integrating Forensic Techniques into Incident
  Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- MITRE ATT&CK — https://attack.mitre.org (Command and Control and Lateral
  Movement tactics show what containment must interrupt)
- SANS Reading Room (incident handling / containment papers) —
  https://www.sans.org/reading-room/
