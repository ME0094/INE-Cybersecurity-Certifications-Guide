# Alert Triage Quick Guide

> eSOC · Cheatsheets — INE-Cybersecurity-Certifications-Guide

Triage is the discipline of turning an alert into a decision: **benign, suspicious (keep watching), or malicious (escalate)** — fast, defensibly, and with notes someone else can read. This cheatsheet is a desk reference: keep it open while you practice the drills in `../labs/soc-scenarios.md`.

> Golden rule: **an alert is a hypothesis, not a verdict.** Your job is to gather enough evidence to raise or lower your confidence, then act or document accordingly.

## The Triage Decision Flow

```text
                        ┌─────────────┐
                        │ Alert fires │
                        └──────┬──────┘
                               ▼
                    ┌─────────────────────┐
                    │ 1. VALIDATE         │  Does the event really exist?
                    │    raw log evidence │  Is the rule logic sound here?
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │ 2. ENRICH           │  Pull context: asset, user,
                    │    pivot & correlate│  timeline, parent/child events
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │ 3. ANSWER THE 5 Ws  │  what / who / when / where / why
                    └──────────┬──────────┘
                               ▼
              ┌────────────────┴────────────────┐
              ▼                                 ▼
   Confident benign / false            Suspicious or confirmed
   positive?                            malicious?
              │                                 │
              ▼                                 ▼
   Document + close;                 Escalate per criteria,
   consider rule tuning              contain if needed, note
              │                                 │
              └───────────────┬─────────────────┘
                              ▼
                    Write the triage note
                    (template below)
```

Repeat for the next alert. Speed comes from a consistent loop, not from guessing.

## The Five Questions (5 Ws) to Answer

| Question | What you are really asking | Where to look |
|---|---|---|
| **What** | What action or event triggered this? What process, file, connection, or registry change? | Alert details, raw log, process tree |
| **Who** | Which user and which host are involved? Is the account service vs. human? Privileged? | `user.name`, `host.name`, AD lookups |
| **When** | Exact timestamp(s). Is it outside business hours? Is it a burst or a one-off? | Event time (mind UTC!), histogram view |
| **Where** | Source and destination: IPs, ports, domains, filesystem paths, parent process | `source.ip`, `destination.ip`, process ancestry |
| **Why** | Does it make sense? Is this normal admin behaviour, or does it fit a known technique/purpose? | Baselines, ATT&CK mapping, user's job role |

If you cannot answer *why it might be real*, you are not ready to close it.

## Enrichment Sources (Go-To List)

Pull from cheap sources first; escalate only what still looks real after enrichment.

1. **SIEM historical search** — what else did this user/host do in the last 24–72 h? Pattern of life beats a single event.
2. **Process ancestry / EDR console** — who started the process, and what did it start afterwards? (The process tree is usually the fastest story.)
3. **Active Directory** — account exists? Disabled? Recently created? Password last set? Group memberships?
4. **Asset inventory / CMDB** — is the host a domain controller, a finance laptop, a decommissioned server? Criticality changes severity.
5. **Threat intelligence** — hash/IP/domain lookups: VirusTotal, MISP, AlienVault OTX, or your org's TI feed. A brand-new domain or a "no results" hash is itself a signal.
6. **OSINT / reputation** — who owns the destination IP/domain; geolocation; is it a known cloud provider (often abused, sometimes legitimate)?
7. **Sandbox / detonation** — for suspicious files, detonate in an isolated sandbox and watch behaviour (only where authorized).
8. **The user** — a quick chat ("were you installing something at 3 PM?") resolves a surprising share of alerts and is a legitimate analyst tool.

Rule of thumb: **enrich until the story is coherent**, then decide. Do not enrich forever.

## Escalation Criteria

Escalate (tier 2 / incident response / on-call) when any of these is true:

- **Confirmed malicious activity**, not just suspicious: malware detonation, credential theft indicators, C2/beacon traffic, ransomware behaviour.
- **Credential compromise signals**: successful logons from a new/foreign source right after a failed-logon spike; Kerberoasting-like patterns; disabled accounts suddenly active.
- **Lateral movement indicators**: unusual RDP/SMB/PSExec/WMI activity between internal hosts, especially toward servers or domain controllers.
- **Data exfiltration shape**: large or unusual outbound transfers, DNS tunnelling signs, emailing archives to external addresses.
- **Critical asset involved**: the host or account is domain admin, a DC, a crown-jewel server, or has regulatory/compliance weight.
- **Impact or containment need**: the alert implies an active breach where waiting risks damage — escalate even at medium confidence.
- **You cannot determine** whether it is benign after reasonable enrichment. "I don't know" is a valid escalation reason when documented.

Severity shorthand (align to your org's scale):

| Level | Meaning | Example |
|---|---|---|
| Info/Low | Expected or unactionable | Failed logon typo, blocked scan |
| Medium | Needs review this shift | Failed-logon burst from one source IP |
| High | Investigate promptly | Encoded PowerShell from an admin account, or credential-dump strings on a server |
| Critical | Immediate, active response | Ransomware execution / DC compromise |

## Fill-In Triage Template

Copy this block into your notes (or a ticket) for every alert you touch:

```text
TRIAGE NOTE — <rule/alert title>          Ticket/ID: <id>

1. VALIDATE
   Raw event(s) confirmed?        [yes/no]  Evidence:
   Rule fired on genuine match?   [yes/no]  Notes:

2. THE FIVE Ws
   What  : <process/file/connection + action>
   Who   : user=< >  host=< >  privileged? <yes/no>
   When  : <timestamp(s), timezone>   outside hours? <yes/no>
   Where : src=< > dst=< >  parent proc=< >  path=< >
   Why   : <plausible legit explanation OR suspicious pattern + ATT&CK id>

3. ENRICHMENT CONSULTED
   [ ] SIEM history   [ ] EDR/process tree   [ ] Active Directory
   [ ] Asset inventory[ ] Threat intel       [ ] OSINT
   [ ] Sandbox        [ ] User interview
   Key findings: <what changed your confidence, and why>

4. DECISION
   [ ] Benign / false positive   -> close; rule tuning note: <...>
   [ ] Suspicious, keep watching -> follow-up time: <...>
   [ ] Malicious / escalate      -> escalation reason: <...>
   Confidence: low / medium / high

5. NEXT STEPS / HANDOFF
   Containment taken: <isolate host / disable account / block IP ...>
   Handed to: <team/person> at <time> — summary for next analyst:
   <one paragraph: what happened, what you proved, what you recommend>
```

## Common Mistakes & Tips

- **Closing on the first glance.** "Looks like a false positive" without a raw-log check is how real incidents slip through. Validate first, always.
- **Ignoring time zones.** 03:00 UTC might be 23:00 local — or vice versa. Convert before judging "off-hours".
- **Escalating everything.** Alert fatigue is real; escalation is a decision with evidence, not a reflex. If you escalate 100% of alerts, you are the SIEM.
- **Never closing the loop.** A false positive you do not report means the same noise hits tomorrow's shift. Note the tuning suggestion.
- **Single-source answers.** An alert confirmed only by the alert itself is unconfirmed. Get a second source (raw log, EDR tree, AD).
- **Skipping the notes.** If it is not written down, it did not happen — for the next shift, for metrics, and for your own learning.
- **Not knowing the baseline.** "Spike" is meaningless without "normal". Know your environment's quiet-day counts.
- **Forgetting containment verbs.** If it is malicious, the note must say what was done to stop it — isolation, account disable, block, or "escalated for containment".

## Checklist / Self-Test

- [ ] I can recite the triage flow from memory: validate → enrich → 5 Ws → decide → document.
- [ ] I can list at least five enrichment sources and say when each is worth checking.
- [ ] I can state my organization's/lab's severity scale and two example alerts per level.
- [ ] I know at least five escalation triggers and can name one for credential compromise and one for lateral movement.
- [ ] I can fill in the full triage template for a sample alert in under 10 minutes.
- [ ] I always record a tuning note when I close an alert as a false positive.
- [ ] I check the time zone on every timestamp before drawing conclusions.
- [ ] I practise the loop on every drill alert from the SOC lab scenarios.

> **Verification:** checked against the Elastic Common Schema sources on 2026-09-19 (https://github.com/elastic/ecs — `schemas/user.yml`, `schemas/host.yml`, `schemas/source.yml`, `schemas/destination.yml`): `user.name`, `host.name`, `source.ip` and `destination.ip`, the fields named in the 5-Ws table, are all real ECS definitions. The triage flow, the escalation criteria and the template are process artefacts — nothing in this sheet was executed, and no alert was triaged to produce it.

## Further Resources

- MITRE ATT&CK — https://attack.mitre.org/ (technique IDs for escalation notes)
- MITRE ATT&CK Navigator — https://mitre-attack.github.io/attack-navigator/
- FIRST CVSS / severity guidance — https://www.first.org/cvss/
- SANS / industry blog articles on alert triage and SOC operations
- Elastic Security docs (alert management in Kibana) — https://www.elastic.co/guide/en/security/current/index.html
- Wazuh alerts documentation — https://documentation.wazuh.com/current/user-manual/manager/alert-management.html
- VirusTotal — https://www.virustotal.com/ and AlienVault OTX — https://otx.alienvault.com/
