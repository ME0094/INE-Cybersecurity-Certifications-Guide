# eCIR Methodology — Phase 1: Preparation

> eCIR · Incident Response Methodology — INE-Cybersecurity-Certifications-Guide

Preparation is the phase that determines whether an incident response (IR)
team contains a breach in hours or flounders for days. Everything you do
later — detection, containment, eradication, recovery, lessons learned — is
faster, safer, and more defensible when policies, plans, roles, playbooks,
tools, and communication paths already exist and have been exercised. This
guide follows the lifecycle described in NIST SP 800-61, where preparation is
the first phase and the continuous-improvement loop that closes the cycle.
## Why Preparation Matters
- **Speed under pressure:** decisions about who does what are made in advance,
  not during an outage.
- **Evidence integrity:** pre-approved forensic tooling and acquisition
  procedures keep findings accurate and defensible.
- **Reduced blast radius:** teams that have rehearsed containment act sooner,
  and earlier containment directly reduces damage and cost.
- **Credible reporting:** with defined roles, communication plans, and
  metrics, executives, legal, PR, and regulators get consistent information.

A useful mental model: preparation turns IR from *"figure it out live"* into
*"execute the plan and adapt only where the plan does not fit."*
## IR Policy and Plan
The **IR policy** is a short, executive-level document that establishes the
program's authority and mandate. The **IR plan** is the operational document
that implements the policy.

```markdown
# IR POLICY (abridged example)
1. Purpose: Protect confidentiality, integrity, and availability by responding
   to security incidents in a coordinated, documented manner.
2. Scope: All information systems and data owned or operated by the company,
   including cloud, remote, and contractor environments.
3. Authority: The CISO designates the IR team; team members may take
   containment actions defined in approved playbooks without further approval.
4. Definitions: incident, event, breach (see Phase 2 — Detection).
5. Reporting obligations: legal/regulatory notification owner is General
   Counsel; customer notification is approved by the CEO/CISO.
6. Review: This policy is reviewed annually and after every major incident.
```

The **IR plan** should answer six questions concretely:
1. Who is on the IR team, and who is the incident commander?
2. What constitutes an incident, and how is it reported and escalated?
3. What are the phases and decision gates of the response process?
4. What tools, data sources, and evidence-handling procedures exist?
5. How is communication handled internally and externally?
6. How are severity levels defined, and who may declare each level?

Keep the plan versioned, stored somewhere reachable during an incident
(printed and offline copies included), and reviewed at least annually and
after every exercise and major incident.
## Team Roles
Every responder needs to know their lane. A useful pattern is a small core
team plus extended participants, coordinated by an incident commander who owns
decisions and a scribe who owns documentation.

| Role | Responsibility | Typical seat |
| --- | --- | --- |
| Incident Commander (IC) | Owns decisions, priorities, and communication; does not do hands-on analysis | IR lead / manager |
| Scribe / Documentation | Records every action, timestamp, and decision | Junior analyst |
| Triage / Tier-1 | First review of alerts, initial classification | SOC analyst |
| Lead Analyst | Deep forensics, malware analysis, root cause | DFIR specialist |
| Communications lead | Internal stakeholders, executives, PR, legal, regulators | Comms / legal |
| IT / Systems owner | Implements containment and restoration actions | Sysadmin / cloud team |
| Legal / Compliance | Advice on evidence, privacy, notification duties | Counsel |
| HR / Physical security | Insider-threat aspects, employee-related incidents | HR lead |

Document a **succession chain** for every role (who replaces the IC if they
are unavailable) and keep an on-call rotation that is actually staffed 24/7.
## Playbooks
A playbook is a step-by-step runbook for one incident type. It translates the
generic plan into actions a tired analyst can follow at 3 a.m.

```markdown
# Playbook skeleton — Phishing / Credential Theft (abridged)

## Trigger
User-reported suspicious email; gateway alert; impossible-travel logon.
## Triage (10 min)
1. Collect the email headers and the reported URL/attachment (do not open it).
2. Check mail gateway logs and the URL reputation.
3. Determine if credentials were submitted: search SIEM for failed logons,
   then a successful logon from a new IP shortly after the phish.
4. Classify severity: credential submitted + sign-in observed = HIGH.
## Containment (30 min)
1. Disable the affected account and force a password reset.
2. Revoke sessions/tokens (see identity-provider playbook).
3. Block the phishing domain and sender at the gateway.
4. Preserve a copy of the email as evidence.
## Escalation criteria
Lateral movement or data exfiltration observed -> call the IC and activate
the full IR plan.
```

Keep playbooks for the incidents you see most: phishing/credential theft,
malware/ransomware, unauthorized access, DDoS, data leak, and insider threat.
Test each playbook in a tabletop before you trust it in production.
## Tooling Readiness
Prepare, patch, and pre-test your toolchain *before* an incident. Maintain an
inventory of where each tool lives, who can run it, and which accounts hold
the permissions it needs (privileged access for EDR isolation and AD actions).

```markdown
## IR Tooling Readiness Checklist (example)
- [ ] EDR deployed on all endpoints/servers; alerts flowing to SIEM
- [ ] SIEM search bookmarks/queries saved for common hunting scenarios
- [ ] Centralized logging: auth, DNS, DHCP, proxy, cloud audit logs
- [ ] Forensic jump kit imaged and verified (write blockers, cables, USB)
- [ ] Acquisition tools tested: FTK Imager, dd, WinPmem, LiME
- [ ] Hashing verified (sha256sum / Get-FileHash) on analyst hosts
- [ ] Out-of-band communication channel tested
- [ ] Password vault + break-glass accounts verified quarterly
- [ ] Backups tested: at least one restore drill per critical system per year
- [ ] EDR signatures and detection rules updated
```

Log retention is a preparation decision with direct detection impact: if you
retain 30 days of logs but your average dwell time is 60 days, you are blind
to half of every incident. Align retention with your threat model and
compliance obligations, and keep an immutable copy of the critical sources.
## Severity Levels
One scale, used everywhere in this module. The numeric `SEV-n` form and the word label are the
**same** scale — pick whichever your tooling speaks, and quote both when you escalate.

| Level | Label | Meaning | First response |
| --- | --- | --- | --- |
| SEV-1 | CRITICAL | Confirmed broad scope, critical systems, or data exfiltration | Activate full IR immediately; notify executives inside the SLA |
| SEV-2 | HIGH | Confirmed on one or several real hosts; possible data impact | Full IR for the affected scope; executives within the hour |
| SEV-3 | MEDIUM | Suspected, limited to one low-value host, low confidence | Investigate during business hours; no external notification |
| SEV-4 | LOW | Minor policy violation, no evidence of compromise | Routine ticket |

> **A false positive is not a severity level.** An alert that proves benign is closed as a false
> positive — or as a true positive with no impact — and it leaves the scale entirely. It is never
> "a SEV-3". Mixing the two turns a detection-tuning metric into an incident category, and the
> incident-commander succession plan ends up being exercised on noise.

Phase 2 (`02-detection.md`) assigns the level during triage and Phase 3 onward inherits it. Where
a tool carries its own numeric scale (TheHive's `severity: 1–4`, for example), record the tool's
value **and** its mapping here, so two systems cannot disagree silently.
## Communication Channels
Incidents need communication that the attacker cannot read or block. Prepare:
- An **internal incident channel** (out-of-band if the corporate chat may
  itself be compromised) for the IR team.
- An **escalation matrix** mapping severity to whom to notify and within what
  time.
- **Pre-approved external templates** for customers, regulators, and press
  that legal has already reviewed — fill-in-the-blank beats drafting from
  scratch.
- **Code words and offline contact lists** in case corporate systems are down.

```markdown
## Escalation matrix (example)
Severity 1 / CRITICAL (enterprise-wide ransomware, confirmed data breach):
- IR team: immediately | Executives: 15 min | Legal: 30 min
- Customers: per legal | Regulators: per law (e.g., GDPR: 72 hours)
Severity 2 / HIGH (single-host malware, no data impact):
- IR team: immediately | Executives: 1 hour
- Legal: notify only if breach of personal data is possible
Severity 3 / MEDIUM (suspected, one low-value host, low confidence):
- IR team: within business hours | No external notification
Severity 4 / LOW (minor policy violation, no evidence of compromise):
- Routine ticket | No external notification
```
## Training and Tabletop Exercises
People forget procedures they do not rehearse. Build a training calendar:

| Exercise type | Frequency | What it validates |
| --- | --- | --- |
| Tool training (DFIR, EDR, SIEM) | Quarterly | Analysts can run acquisitions and searches |
| Tabletop (discussion-based) | Quarterly | Roles, decisions, communication under a narrative |
| Functional drill | Annually | Live execution of one playbook on test systems |
| Full-scale exercise | Annually or biennial | End-to-end response incl. executive/legal/PR |

A good tabletop uses injects that force decisions:

```text
Tabletop inject example (ransomware):
- 09:00  Analyst reports 40 endpoints encrypting files; ransom note displayed.
- 09:15  Legal asks: do we have backups? Are we allowed to pay (never pay
         without leadership decision + legal review)?
- 09:30  Executives ask for a containment estimate and customer impact.
- 09:45  The EDR team reports the actor used a dormant admin account. What
         is the first account action? Who approves it?
```

Each exercise ends with a short after-action list of two or three fixes, and
someone must own each fix until it is done.
## Business Continuity Context
IR stops the bleeding; **business continuity (BC) and disaster recovery (DR)**
keep the business alive while you work. Know before an incident:
- **RTO (Recovery Time Objective):** how long a system can be down.
- **RPO (Recovery Point Objective):** how much data loss is acceptable.
- Which systems are business-critical and which can wait.
- Where DR sites/cloud regions are, and who can activate failover.
- Manual workarounds for key processes (paper, phone, offline spreadsheets).

```text
Decision aid (example):
- Payment processing must resume in <= 4 hours -> RTO 4h, DR site hot.
- CRM may lose 24h of updates -> RPO 24h, nightly backups.
- If containment requires taking the ERP offline for 3 days but the business
  needs it in 8 hours, the recovery strategy must be decided at leadership
  level BEFORE the containment action is taken.
```

Coordinate IR and BC plans so the teams do not fight: IR may want systems
offline for forensics while BC wants them restored — the decision framework
(severity, criticality, legal hold) must exist in advance.
## Common Mistakes & Tips
- **Mistake:** A 90-page plan nobody has read. **Tip:** Keep the plan short
  and the playbooks detailed; run a tabletop within a month of publishing.
- **Mistake:** The only copy of the plan lives on the SharePoint server the
  ransomware encrypted. **Tip:** Keep offline and out-of-band copies.
- **Mistake:** Untested forensic images and restore drills — "we thought the
  backup worked." **Tip:** Do a quarterly restore drill and test the jump kit.
- **Mistake:** Single points of failure in roles and tool access. **Tip:**
  Maintain succession chains, break-glass accounts, and secondary tooling.
- **Mistake:** Communication paths the attacker can monitor (posting evidence
  in the corporate chat). **Tip:** Pre-establish an out-of-band channel and
  decide when it becomes mandatory.
- **Mistake:** Preparing only for technical incidents, ignoring legal, PR,
  and regulatory aspects. **Tip:** Include legal and communications in
  exercises so notification timing is realistic.
## Checklist / Self-Test
- [ ] I can explain the difference between an IR policy and an IR plan and
      name the six questions every IR plan must answer.
- [ ] I can list the core IR roles and the incident commander's
      responsibility, and name the succession chain for each role.
- [ ] I can describe the structure of a playbook and sketch one for phishing
      or malware without referencing notes.
- [ ] I can name at least five items on an IR tooling readiness checklist and
      explain why log retention length matters.
- [ ] I can build an escalation matrix mapping severity to who gets notified
      and within what time frame.
- [ ] I can distinguish tabletop, functional, and full-scale exercises and
      give one example inject for a ransomware scenario.
- [ ] I can define RTO and RPO and explain how business continuity decisions
      interact with containment decisions.
- [ ] I know where the offline copy of the IR plan and the out-of-band
      contact list are stored at my organization.
> **Verification:** checked against **NIST SP 800-61 Rev. 3**
> (`https://csrc.nist.gov/pubs/sp/800/61/r3/final`, HTTP 200 on **2026-09-19**) and the **GDPR**
> (`https://eur-lex.europa.eu/eli/reg/2016/679/oj`, HTTP 200, same date): the publication page
> carries the title this file cites, and Article 33(1) reads *"not later than 72 hours"*, which is
> the number in the escalation matrix. The two hashing commands in the tooling checklist were run
> on this host — `sha256sum` (GNU coreutils 9.4, Ubuntu 24.04 WSL) and
> `Get-FileHash -Algorithm SHA256` (PowerShell 7.6.6, Windows 11), both printing a digest for a
> file of known content. **Not executed:** the plans, playbooks and exercises above are documents,
> not runs — no team, no tabletop and no incident exists on this machine.

## Further Resources
- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide* —
  https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- NIST SP 800-61 Rev. 3, *Incident Response Recommendations and Considerations for
  Cybersecurity Risk Management: A CSF 2.0 Community Profile* (April 2025) —
  https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-184, *Guide for Cybersecurity Event Recovery* —
  https://csrc.nist.gov/publications/detail/sp/800-184/final
- MITRE ATT&CK — https://attack.mitre.org (framework for adversary behavior;
  useful when designing detection and response preparation)
- SANS Reading Room (Incident Handling papers) — https://www.sans.org/reading-room/
