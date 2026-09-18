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

Disable plus revoke, PowerShell concept. This is a shape to adapt, not a runbook: the commands were **not executed while writing this note**, and all of them change production state, so they belong in a playbook with a named approver:

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

## Containment Decision Table

Every containment action trades one risk for another. Choose deliberately, and know which trade you are making before you touch anything.

| Action | Stops | Costs you | Reversible? | Approval | Prefer it when |
|---|---|---|---|---|---|
| EDR network isolation | C2, lateral movement, exfiltration from that host | Nothing permanent; the host keeps running for evidence | Yes, instantly | Playbook or on-call lead | Default first move for a compromised endpoint |
| Switch-port disable / firewall block | All network I/O from the host | Remote management and remote collection | Yes, with console or network access | Playbook or network owner | No EDR agent, or the agent is untrusted |
| Cable pull / Wi-Fi disable | Network access | Remote visibility, and volatile state if the host sleeps | Physically trivial, operationally disruptive | On-site resources | Physical access is available and remote options failed |
| Account disable | Reuse of the stolen credential | Business process stops; the user may need to be paged | Yes | Playbook or identity owner | Credential confirmed or strongly suspected compromised |
| Password reset + session revoke | Live Kerberos tickets, refresh tokens, VPN sessions | User disruption, helpdesk load | Yes (a new credential is issued) | Identity owner | Account confirmed compromised — do it *together with* the disable |
| Block destination (IP/domain) at egress | Beaconing to that destination | Other destinations stay reachable; a legitimate service may break | Yes | Playbook | The destination is confirmed malicious and the host is not isolated yet |
| Kill process / quarantine file | The running implant | Volatile evidence, and the attacker learns you are watching | No — process state is gone | IR, normally not tier 1 | A destructive process is actively encrypting or exfiltrating |
| Power off | Everything, including encryption in progress | All volatile evidence: memory, connections, logged-on sessions | No | Incident commander | Only when destruction is active and isolation is unavailable |

> Two rules keep this table usable: **contain the network before the power** (isolation preserves evidence, power-off destroys it), and **never leave the account live while you isolate the host** (if the credential was stolen, the host is not the only door).

## Playbook Anatomy — and How to Read One Under Pressure

A playbook is not a script; it is a decision document with a fixed shape. Learn to find these five parts in the first ten seconds, because during a live incident you will not read it end to end:

1. **Trigger** — which alert or condition starts this playbook, and at what severity.
2. **Pre-checks** — what must be true before acting: authorization, asset criticality, whether the action is reversible.
3. **Actions** — numbered, with the exact console or command and who performs each one.
4. **Verification** — how you confirm the action *took effect*. Isolation that silently failed is worse than no isolation, because you now believe you are contained.
5. **Rollback and handoff** — how to undo it, and what to write in the case when you stop.

The two most common tier-1 actions, expanded into that shape. Adapt them to your own tools and authority; nothing here was executed while writing this note.

**Playbook A — Isolate a compromised endpoint**

```text
TRIGGER        High/critical alert confirmed as a true positive on a managed endpoint.
PRE-CHECKS     Authorization per policy?  Asset criticality known (DC, hypervisor host,
               clinical device)?  Does a production service run on it?  Can the EDR still
               reach the host after isolation to keep collecting?
ACTIONS        1. Open the case; note the UTC start time.
               2. Capture volatile context if authorized and possible: logged-on users,
                  active network connections, running processes (read-only collection).
               3. Trigger EDR isolation. Do NOT log in with privileged credentials.
               4. Notify the on-call lead and the asset owner.
VERIFICATION   Isolation shows as active in the console; a test connection to the host
               fails from your workstation; the agent is still checking in and still
               delivering telemetry.
ROLLBACK       Unisolate only with IR approval and a recorded reason.
HANDOFF        Case note: what was isolated, when, why, evidence collected, ownership
               transferred to IR, and what monitoring continues.
```

**Playbook B — Disable a compromised account**

```text
TRIGGER        Confirmed or strongly suspected credential compromise.
PRE-CHECKS     Is it a service account (what breaks when it stops working)?  Who is the
               identity owner?  Is there a break-glass dependency on this account?
ACTIONS        1. Disable the account in the identity provider.
               2. Reset the password and revoke sessions/refresh tokens; kill VPN sessions.
               3. Check for a second path: other accounts from the same source IP, new
                  sessions on the same host, new mail rules or application consents.
               4. Notify the identity owner and the user's manager per the plan.
VERIFICATION   Authentication attempts by the account now fail; no new sessions appear in
               the IdP/AD; no re-enable event. A re-enable, or a new session, means a
               higher-privileged actor is present - escalate immediately.
ROLLBACK       Re-enable only through the identity owner, with the case reference.
HANDOFF        Case note: who disabled what, when, which sessions were revoked, what
               service impact exists, and what remains unexplained.
```

## What Tier 1 Collects: Evidence Actions and Their Risks

Tier 1 preserves evidence; it does not perform forensics. The distinction matters because most useful-looking commands also *change* something.

| Action | What it gives you | Evidence risk | Notes |
|---|---|---|---|
| Export the affected event channels (for example `wevtutil epl <channel> <file>`) | A copy of the raw logs for the window, usable offline | None, if you write to a new file on a share you control | Confirm in your own lab that the export leaves the live log intact before relying on it |
| SIEM export of the timeline and the raw matched events | The canonical timeline with platform timestamps | None | Do it early — retention windows may not cover the investigation |
| Hash a file you must copy (`Get-FileHash`, `sha256sum`) | Integrity of the artifact, and a value to pivot on | None | Record the hash in the case immediately: the hash *is* the identity of the artifact |
| `netstat -ano` / `Get-NetTCPConnection` on the live host | Which process owned which connection right then | None, but it captures only the present instant | Only if the playbook allows touching the host at all; assume the attacker can see you |
| Registry export of a suspicious key (`reg export`) | A faithful copy of the configuration that achieved persistence | None, if exported to a new file | Safer than transcribing the key by hand |
| Running an AV scan or "cleaning" the machine | Peace of mind | **Destructive** — it modifies the system and can delete the evidence | Never tier 1, and never before IR says so |
| Rebooting the host | A temporarily quiet endpoint | **Destructive** — loses volatile evidence and may trigger the payload's persistence | Only with IR approval |

The chain-of-custody rules above apply to every row: whoever collects gives the artifact an identity (a hash), a location, a time (UTC), and a name. An artifact without those four attributes is not evidence; it is a copy of something.

## Post-Incident: The Tier-1 Contribution

Response ends, learning is optional, and the learning is what makes the next shift shorter. Two contributions belong specifically to the analyst who worked the alert:

- **Detection feedback.** Which alert fired, when, and would a *different* rule have caught the activity earlier? The distance between "when the attacker acted" and "when the alert fired" is a detection requirement you are uniquely placed to write down. Hand it to the detection owner together with the query that would have found it (see `05-use-cases-and-tuning.md`).
- **Process feedback.** What slowed the response: a playbook step that did not match reality, an approval that took forty minutes, a log that was never collected, an escalation contact who was unreachable, a query you had to rebuild from memory. These are the inputs to a lessons-learned review, and the reason your queries belong verbatim in the case.

Also worth writing once, while it is fresh: **what you would do differently**, phrased as a process change rather than self-criticism. "I should have checked the other account from the same source IP before isolating" becomes a checklist item; "I was too slow" changes nothing.

## Common Mistakes & Tips

- **Mistake:** using the domain admin account to investigate the compromised host. *Tip:* assume the attacker watches; use separate low-privilege or dedicated credentials.
- **Mistake:** powering off the host "to be safe," destroying volatile evidence and remote visibility. *Tip:* network-isolate or use EDR isolation first; power off only for active destruction.
- **Mistake:** deleting malware or "cleaning" the machine before evidence is captured. *Tip:* preserve first; IR decides cleanup.
- **Mistake:** containing one host and stopping. *Tip:* always hunt for related hosts/accounts sharing the same indicators.
- **Mistake:** unapproved or undocumented actions. *Tip:* every containment step needs approval, a timestamp, and a note in the case.
- **Mistake:** solo heroics and silence. *Tip:* notify early, escalate early, and let the playbook and the team carry the response.
- **Mistake:** choosing containment by habit instead of by trade-off. *Tip:* state what the action stops, what it costs, and whether it is reversible before you perform it.
- **Mistake:** isolating a host and assuming it worked. *Tip:* verify the isolation state from a second viewpoint; unverified containment is a belief, not a control.
- **Mistake:** leaving the compromised account active while the host is isolated. *Tip:* if the credential is stolen, the host was only one of the doors.
- **Mistake:** asking for forgiveness after an unapproved action. *Tip:* approval is part of the action; if the playbook does not cover it, escalate the decision instead of making it.
- **Mistake:** going straight to power-off because it feels decisive. *Tip:* power-off is the only containment that destroys the evidence you are about to need — isolate the network, keep the host alive.

## Checklist / Self-Test

- [ ] I know my role as first responder and what is outside my authority.
- [ ] I follow the order: notify → protect → capture → contain → preserve → escalate.
- [ ] I can isolate a host (EDR/network) and verify the isolation took effect.
- [ ] I can disable a compromised account and revoke its sessions/tokens.
- [ ] I preserve evidence without modifying it and record chain-of-custody details.
- [ ] My escalation package contains summary, scope, timeline, actions taken, and open questions.
- [ ] I communicate through approved channels only and follow the playbook.
- [ ] I post timestamped notes during the response, not vague recollections after.
- [ ] I can name five containment actions with their cost, reversibility, and required approval.
- [ ] I can find the trigger, pre-checks, actions, verification, and rollback of a playbook I have never read before.
- [ ] I verify that an isolation or disable actually took effect, from a second viewpoint.
- [ ] I know which evidence actions are read-only and which ones destroy evidence.
- [ ] I have written what I would do differently as a process change, not as self-criticism.

## Further Resources

- NIST SP 800-61 Rev. 3 — Computer Security Incident Handling Guide: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- CISA — Incident Response resources and best practices: https://www.cisa.gov/resources-tools
- MITRE ATT&CK — technique context for containment and detection decisions: https://attack.mitre.org
- SANS Incident Handlers' Handbook (defensible process guidance): https://www.sans.org/white-papers/33901/
- Microsoft Learn — Azure AD / Entra ID account incident response guidance: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/
