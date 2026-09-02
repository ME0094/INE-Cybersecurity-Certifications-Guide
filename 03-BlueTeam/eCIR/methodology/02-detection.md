# eCIR Methodology — Phase 2: Detection & Analysis

> eCIR · Incident Response Methodology — INE-Cybersecurity-Certifications-Guide

Detection is where an incident goes from noise to a declared, scoped event.
Analysts must distinguish routine events from genuine incidents, triage
quickly, pull the right telemetry, understand what the adversary did, and
estimate how far they got. NIST SP 800-61 calls this phase "Detection and
Analysis" and stresses that its quality determines the cost of everything
that follows: the earlier and more accurately you detect and scope, the
cheaper containment and eradication will be.

## Events vs. Incidents

- **Event:** any observable occurrence in a system or network — a logon, a
  DNS query, an alert, a reboot. Most events are benign.
- **Incident:** an event (or series of events) that violates policy or poses
  a realistic threat to confidentiality, integrity, or availability — e.g., a
  successful phishing logon, ransomware execution, or data exfiltration.

The SOC's daily job is triage: decide which events warrant investigation.
NIST recommends retaining evidence and analyzing *suspicious* events even
when they turn out benign — the analysis improves detection quality and
documents the decision.

```text
Event vs. incident examples:
- Benign event: user logon from home IP at 09:02, as usual.
- Suspicious event: same account logs on from a foreign IP at 03:10 with a
  new device — investigate.
- Incident: the foreign-IP logon is followed by the account adding itself to
  a privileged group — declare an incident and contain.
```

## Detection Sources and Telemetry

Good detection comes from layered, correlated sources; no single source is
enough:

| Source | What it reveals | Typical examples |
| --- | --- | --- |
| EDR / AV | Malware execution, persistence, process behavior | Detection alerts, process trees |
| SIEM | Correlated events across sources | Aggregated alerts, dashboards |
| Authentication logs | Credential abuse, brute force, lateral movement | AD logon events, MFA denials |
| Network (NetFlow/IDS) | C2 communication, scanning, data transfer | Firewall/IDS alerts, flows |
| DNS logs | C2 domains, DNS tunneling | Query logs, sinkhole hits |
| Proxy / email gateway | Phishing, malicious downloads | Mail headers, URL blocks |
| Cloud audit logs | API abuse, credential theft in cloud | CloudTrail, audit logs |
| OS/application logs | Host-level detail | Event logs, syslog, app logs |
| Threat intel feeds | Known IOCs, adversary context | IOC matches, TTP descriptions |

Because attackers increasingly operate in the cloud and use legitimate
services (living off the land), also log and monitor identity-provider
activity, SaaS admin actions, and API usage.

## Initial Triage

Triage should answer: **Is this real, how bad could it be, and who needs to
know now?** Work from a fixed checklist so tired analysts skip nothing.

```markdown
## Triage checklist (10–15 minutes)
1. Read the alert. What triggered it, on which host/account, at what time?
2. Correlate: do other sources (auth, EDR, DNS) show related activity?
3. Check the asset: is it critical? What data does it hold?
4. Estimate credibility: is this a known false-positive pattern?
5. Determine the actor: automated scanning or targeted activity?
6. Check for IOCs: hashes, domains, IPs, unusual processes/commands.
7. Decide and act: dismiss with a note, escalate to an incident, or keep
   monitoring. Record the decision and the reason.
```

Never let an alert sit without a disposition. A useful severity model:

```text
Severity = f(impact, scope, confidence)
- SEV-3: suspected, limited to one low-value host, low confidence
- SEV-2: confirmed on one or several real hosts; possible data impact
- SEV-1: confirmed broad scope / critical systems / data exfiltration —
         activate full IR immediately
```

## Log and Telemetry Review

When an alert is confirmed, reconstruct the attacker's actions from logs. On
Windows, focus on the security and system channels with the right event IDs:

```powershell
# Recent failed logons for one account (Event ID 4625)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625;
  StartTime=(Get-Date).AddDays(-7)} |
  Where-Object { $_.Message -match 'Account Name:\s+jsmith' } |
  Select-Object TimeCreated, Id, Message | Format-List

# All logons by account (4624) — logon types: 2=interactive,
# 3=network, 10=remote interactive (RDP)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624;
  StartTime=(Get-Date).AddDays(-7)} |
  Where-Object { $_.Message -match 'jsmith' } |
  Select-Object TimeCreated, Message | Format-List

# Services installed (7045, System log); audit log cleared (1102)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045;
  StartTime=(Get-Date).AddDays(-7)} | Select TimeCreated, Message | Format-List
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} |
  Select TimeCreated, Message | Format-List
```

On Linux hosts:

```bash
# Authentication successes and failures
journalctl -u ssh --since "7 days ago" | grep -E "Failed|Accepted password"
grep -E "Failed password|Accepted" /var/log/auth.log | tail -100

# Recently modified files in world-writable staging areas
find /tmp /var/tmp /dev/shm -type f -newermt "7 days ago" -ls 2>/dev/null

# Listening sockets and established connections
ss -tunap
```

Wherever possible, search **centralized logs** (SIEM) rather than hopping
onto live hosts — querying live hosts disturbs evidence and may alert the
adversary. Build reusable SIEM queries for your top alert types during Phase 1
so analysts do not rewrite them mid-incident.

## Malware Analysis Basics

When a malicious file is found, basic analysis answers: *what does it do, how
did it get here, and is it unique to us?*

1. **Preserve first.** Hash the original artifact before doing anything else
   and copy it to evidence storage.
2. **Static analysis:** examine the file without executing it.
3. **Dynamic analysis:** observe behavior in a controlled, isolated sandbox.
4. **Share safely:** submit hashes (not necessarily the original file) to
   public sandboxes only if the file is not sensitive and policy allows —
   uploading a file can breach confidentiality.

```bash
# Static triage on a Linux analysis box
sha256sum sample.bin                 # hash = the IOC you share
file sample.bin                      # true file type, not fooled by extension
strings -n 8 sample.bin | head -50   # embedded URLs, IPs, commands
yara /path/to/rules.yar sample.bin   # scan with community/private rules

# Windows equivalent (PowerShell on an analyst host)
Get-FileHash -Algorithm SHA256 .\sample.bin
# Sysinternals sigcheck for signature/version; strings for embedded data
```

```text
Dynamic analysis (inside an isolated VM — snapshot first!):
1. Snapshot the clean VM.
2. Execute the sample; record: registry Run keys, scheduled tasks/services
   created, outbound connections, new files on disk.
3. Revert the snapshot and document findings.
```

Never execute untrusted malware on a production host or an unisolated lab
box. Keep the analysis VM network-isolated (host-only) and snapshot before
each run.

## Scoping and Determining the Blast Radius

Scoping answers the question leadership will ask next: **how big is this?**
Build the scope from evidence, not intuition. Work backwards from the first
confirmed compromise outward:

```text
Scope questions to answer:
1. Which accounts are affected? (source user, admin, service accounts)
2. Which hosts are affected? (EDR search: same hash, C2, parent process,
   scheduled task name)
3. Which credentials may be exposed? (password reuse, cached creds, domain
   admin, service accounts)
4. Which data can affected hosts/accounts reach? (shares, mailboxes,
   databases, cloud storage)
5. What is the time window? (first -> last evidence = dwell time)
6. Is this one incident or several related ones? (e.g., two phishing
   campaigns using the same infrastructure)
```

Use **IOC and behavioral hunting** to widen or confirm scope:

```text
Pivot chain example:
malicious hash -> hosts with the hash (EDR) -> processes that launched it ->
accounts running them -> logons of those accounts elsewhere -> new hosts ->
data repositories those accounts can reach = blast radius estimate.
```

Document the scope estimate, its assumptions, and its confidence level. Scope
grows and shrinks as new telemetry arrives — that is normal. Re-scope whenever
a new host, account, or data store enters the picture.

## Common Mistakes & Tips

- **Mistake:** Dismissing alerts because similar ones were false positives
  before. **Tip:** Treat every alert as new until correlation proves
  otherwise; document each disposition.
- **Mistake:** Logging into compromised hosts to "take a look," alerting the
  adversary or destroying volatile evidence. **Tip:** Use EDR/SIEM telemetry
  first; go hands-on only with a plan.
- **Mistake:** Looking only at the endpoint and missing network/cloud
  evidence. **Tip:** Correlate auth, DNS/proxy, and EDR before declaring
  scope.
- **Mistake:** Hunting with IOCs only (hashes, IPs) and missing behavioral
  detection. **Tip:** Use ATT&CK techniques — attackers change hashes easily,
  techniques less so.
- **Mistake:** Executing suspicious files to "see what happens." **Tip:**
  Hash first, analyze statically, then run only in an isolated, snapshotted
  VM.
- **Mistake:** Uploading sensitive binaries to public sandboxes. **Tip:**
  Check confidentiality policy; prefer private sandboxes or hash-only
  lookups.
- **Mistake:** Not recording the triage decision. **Tip:** If it is not
  written down, it did not happen — log time, source, decision, and reason.

## Checklist / Self-test

- [ ] I can explain the difference between an event and an incident with an
      example of each.
- [ ] I can list at least six detection/telemetry sources and what each
      reveals about an attack.
- [ ] I can perform initial triage of an alert and assign a severity using
      impact, scope, and confidence.
- [ ] I can pull Windows security log events (4624, 4625, 4688, 7045, 1102)
      with Get-WinEvent and interpret logon types.
- [ ] I can list the static-analysis steps for a suspicious binary (hash,
      type, strings, YARA) in the correct order.
- [ ] I can describe a pivot chain that turns one IOC into a blast-radius
      estimate.
- [ ] I know why logging onto a compromised host during detection is risky
      and can name safer alternatives.
- [ ] I can define dwell time and explain why it matters for scoping.

## Further resources

- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide* —
  https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- NIST SP 800-83 Rev. 1, *Guide to Malware Incident Prevention and Handling* —
  https://csrc.nist.gov/publications/detail/sp/800-83/rev-1/final
- MITRE ATT&CK — https://attack.mitre.org (technique-oriented detection and
  hunting)
- SANS Reading Room (DFIR and malware analysis papers) —
  https://www.sans.org/reading-room/
