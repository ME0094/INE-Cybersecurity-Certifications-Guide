# eSOC Methodology — Phase 4: Response

> Tier-1 SOC Analyst focus · INE-Cybersecurity-Certifications-Guide

Response turns a confirmed finding into action. This guide covers first responder actions, containment basics (isolating a host, disabling an account), evidence preservation fundamentals, escalation to the incident response (IR) team, and the communication and playbook discipline that keeps a response safe and coordinated.

## The Tier-1 Role in Response

A tier-1 analyst is usually the **first responder**, not the incident commander. Your jobs, in order: (1) protect yourself and others from harm, (2) stop the bleeding with approved, reversible actions, (3) preserve evidence for later analysis, (4) communicate clearly and escalate early. Tier-1 does not perform deep forensics, negotiate with attackers, or unilaterally change production — those belong to IR and management. Acting beyond your authority is itself an incident risk.

Response order of operations:

```text
CONFIRM (alert is a true positive, from Phase 3)
   |
   +-- FIRST RESPONDER ACTIONS  (notify, protect, capture what you can)
   |        |
   +-- CONTAINMENT  (approved, reversible, documented)
   |        |
   +-- EVIDENCE PRESERVATION  (before destructive steps)
   |        |
   +-- ESCALATION  (IR handoff with complete notes)
   |        |
   +-- COMMUNICATION & PLAYBOOK DISCIPLINE (throughout)
```

## First Responder Actions

Before any containment, do the safe and fast things that prevent data loss and prevent panic-driven mistakes:

1. **Notify.** Inform the on-call lead / IR manager and the asset owner per your communication plan. Response is a team sport from minute one.
2. **Assess safety and blast radius.** Is the host a domain controller, a payment server, a hospital device? Does the account have administrative rights? Safety and criticality change every later decision.
3. **Capture volatile context early — if authorized and able.** Live state (running processes, network connections, logged-on users) can vanish when you disconnect the host. If your playbook allows a quick, non-destructive snapshot, take it *before* isolation.
4. **Do not log into the compromised host with privileged credentials.** The attacker may be watching; your domain admin account is a gift. Use separate, low-privilege analyst credentials or dedicated tools.
5. **Do not poke the adversary.** No scanning, no "let me see what they do," no rebooting to "fix" it — each action destroys evidence and can alert the attacker.
6. **Preserve the big picture.** Note the time, the alert IDs, and what is already known (Phase 3 notes) so nothing is lost in the rush.

## Containment Basics

Containment limits the attacker's reach. Every action must be **pre-approved by the playbook or the on-call lead**, **reversible where possible**, and **logged with timestamp and rationale**.

### Isolate the Host

Goal: cut the compromised machine's ability to talk to the network while keeping it alive for evidence.

- **Preferred — network-level isolation:** block the host at the switch port, via firewall rule, or through EDR "isolate host" so the host stays powered on but cannot communicate. This preserves evidence and stops lateral movement.
- **Fallback — disconnect the cable/disable Wi-Fi:** effective but loses remote management and remote evidence options.
- **Last resort — power off:** only when a host is actively destructive (encrypting files, exfiltrating). Power-off loses volatile memory evidence.

EDR isolation is the modern default when available:

```text
Action:  EDR console -> isolate endpoint HOST-CORP-042
Effect:  Host remains on; all network I/O blocked except agent management
Verify:  confirm isolation state in console; document start time
Reversal: unisolate only with IR approval after investigation
```

### Disable the Account

Goal: stop an attacker who is using stolen credentials.

- Disable the account in the identity provider (AD user properties, Azure AD, IdP) or force a password reset — do both when the account is confirmed compromised.
- Revoke sessions and tokens: force logoff, revoke Kerberos tickets (reset the account password / `Revoke-AzureADUserAllRefreshToken` equivalent), kill active VPN sessions.
- Watch for **re-enablement**: if the account re-activates, an attacker with higher privilege is controlling it — escalate immediately.

Disable plus revoke, PowerShell concept:

```powershell
# Confirm the account and reason BEFORE running (two-person rule where possible)
Disable-ADAccount -Identity "CORP\j.doe" -Reason "Compromised credential - SOC-2025-001"
# Revoke existing Kerberos tickets by resetting the password
Set-ADAccountPassword -Identity "CORP\j.doe" -Reset -NewPassword (ConvertTo-SecureString ...)
# Document: who, when, why, ticket ID
```

Containment does not end with one action: after isolating the host, re-check the timeline for *other* hosts or accounts the attacker may have reached. Containment of one box while the attacker owns three more is theater.

## Evidence Preservation Basics

Evidence must survive the response so IR and (potentially) legal can use it. The rules are simple and strict:

1. **Order of volatility first.** Capture memory → network state → processes → disk artifacts → logs. The most volatile data disappears first.
2. **Do not modify the original.** Analyze copies, never the source. Booting the machine, installing tools, or even logging in changes evidence.
3. **Write-protect media.** Forensic images go to write-blocked destinations; hashes are computed at acquisition time (SHA-256) and verified later.
4. **Maintain chain of custody.** Every piece of evidence is recorded: who collected it, when, from where, how it was stored, who handled it. A break in the chain can make evidence unusable.
5. **Protect the collection channel.** Send evidence over controlled channels (case share, encrypted transfer), not email or chat.

Tier-1 evidence actions are usually *preservation*, not full forensics:

```text
DO (approved, non-destructive):
  - note hostname, serial, time source, owner before any action
  - collect event logs / SIEM exports for the affected window
  - export the timeline from Phase 3 with alert references
  - hash any file artifact you must copy (Get-FileHash / sha256sum)
  - record the exact containment actions and timestamps

DO NOT:
  - delete files, "clean" the machine, or run AV scans to remove malware
  - reboot or power-cycle without IR approval
  - log into the host with admin credentials to "look around"
  - copy artifacts to personal or unapproved storage
```

## Escalation to Incident Response

Escalate when containment does not fully explain or stop the activity, or when the impact exceeds tier-1 authority. The handoff quality decides how fast IR can act.

A complete escalation package contains:

- **Case ID and summary** — what happened, in plain language.
- **Scope** — hosts, users, IPs, domains; confirmed vs suspected.
- **Timeline** — every key event with timestamps and evidence references.
- **Actions already taken** — alerts validated, host isolated, account disabled (with times).
- **Open questions** — what is still unknown (e.g., "how did the account get the password?", "is the C2 IP shared?").
- **Contacts** — asset owner, system administrator, manager already notified.

Escalation criteria (escalate now if any apply):

- Malware or C2 activity confirmed and not fully contained.
- Privileged account, domain controller, or critical asset involved.
- Lateral movement or persistence detected.
- Evidence that data was exfiltrated or destroyed.
- You are unsure whether the activity is contained — escalate while it is still small.

After handoff, tier-1 roles shift to *support*: keep monitoring for related indicators, run queries IR requests, and document new findings into the same case.

## Communication & Playbook Discipline

Chaos is the enemy; structure is the tool.

- **Follow the playbook.** Playbooks exist because someone already thought through the safe sequence. Deviate only with the lead's approval and a recorded reason.
- **Use the communication plan.** Know who to call, in what order, and through which channel. Incident bridges/channels are for coordination; do not narrate every query in them.
- **Write timelines as you go.** Post-action notes with timestamps turn into the incident record. Vague recollections written hours later are worthless.
- **Respect information control.** Do not share details with people who do not need them, and never discuss on personal devices or public channels. Public leaks can tip off an attacker and create legal exposure.
- **Call for help early.** "Escalate early" is a feature, not a failure. IR would rather get a small confirmed case at 10 minutes than a full breach at 10 hours.
- **Debrief after.** Response does not end at containment; lessons-learned input (what worked, what slowed us down) is part of the analyst's job.

A simple response status board to keep the story straight:

```text
TIME (UTC)   ACTION                             OWNER      STATUS
02:14        Alert SOC-2025-001 ACK'd           A. Tier1   done
02:16        Lead notified                       A. Tier1   done
02:21        EDR isolation HOST-CORP-042         A. Tier1   done
02:23        Account CORP\j.doe disabled         A. Tier1   done
02:30        Timeline export saved to case       A. Tier1   done
02:35        Escalated to IR (package sent)      A. Tier1   done
02:50        Monitoring for related IPs          A. Tier1   active
```

## Common Mistakes & Tips

- **Mistake:** using the domain admin account to investigate the compromised host. *Tip:* assume the attacker watches; use separate low-privilege or dedicated credentials.
- **Mistake:** powering off the host "to be safe," destroying volatile evidence and remote visibility. *Tip:* network-isolate or use EDR isolation first; power off only for active destruction.
- **Mistake:** deleting malware or "cleaning" the machine before evidence is captured. *Tip:* preserve first; IR decides cleanup.
- **Mistake:** containing one host and stopping. *Tip:* always hunt for related hosts/accounts sharing the same indicators.
- **Mistake:** unapproved or undocumented actions. *Tip:* every containment step needs approval, a timestamp, and a note in the case.
- **Mistake:** solo heroics and silence. *Tip:* notify early, escalate early, and let the playbook and the team carry the response.

## Checklist / Self-Test

- [ ] I know my role as first responder and what is outside my authority.
- [ ] I follow the order: notify → protect → capture → contain → preserve → escalate.
- [ ] I can isolate a host (EDR/network) and verify the isolation took effect.
- [ ] I can disable a compromised account and revoke its sessions/tokens.
- [ ] I preserve evidence without modifying it and record chain-of-custody details.
- [ ] My escalation package contains summary, scope, timeline, actions taken, and open questions.
- [ ] I communicate through approved channels only and follow the playbook.
- [ ] I post timestamped notes during the response, not vague recollections after.

## Further Resources

- NIST SP 800-61 Rev. 3 — Computer Security Incident Handling Guide: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- CISA — Incident Response resources and best practices: https://www.cisa.gov/resources-tools
- MITRE ATT&CK — technique context for containment and detection decisions: https://attack.mitre.org
- SANS Incident Handlers' Handbook (defensible process guidance): https://www.sans.org/white-papers/33901/
- Microsoft Learn — Azure AD / Entra ID account incident response guidance: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/
