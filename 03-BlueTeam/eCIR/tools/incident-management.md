# Incident Management Tooling and Process

> eCIR · Tools — English reference for running incidents: ticketing, case files, evidence tracking, and communications

Technical containment fails if the incident is mismanaged. Incident management keeps
everyone aligned: who is doing what, what was found, what evidence exists, and what has
been communicated — internally and externally. This guide covers the platforms, the
documentation habits, and the templates a responder needs.

## The Management Backbone: Ticketing / IR Platforms

An incident tracker is the single source of truth. Options range from general ITSM
platforms to purpose-built IR/SOAR tools; concepts matter more than the brand:

- **IR-native platforms** — TheHive, DFIR-IRIS: built for cases with linked observables
  (IPs, hashes, domains), evidence, and task checklists.
- **Incident/help-desk trackers** — Jira (with IR add-ons), ServiceNow, RTIR: broad
  workflow, SLAs, approvals; you adapt them with IR fields and boards.
- **What to demand from any tool**:
  - One case per incident, with severity/status/assignment fields and an audit trail.
  - Every action logged against the case with author and timestamp.
  - Attachments/links for evidence, screenshots, and raw logs.
  - Escalation and SLA views so nothing stalls silently.

Example — creating a case via TheHive-style REST API (endpoint shapes vary by version;
check the platform's API docs):

```bash
curl -k -X POST "https://thehive.local/api/v1/case" \
  -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
        "title": "Suspected ransomware on WS-042",
        "description": "Files encrypted + ransom note. Source: SOC alert #8812.",
        "severity": 3,
        "tlp": 2,
        "tags": ["ransomware", "endpoint"],
        "tasks": [
          {"title": "Preserve memory and disk image"},
          {"title": "Identify initial access vector"}
        ]
      }'
```

## Case Documentation: The Written Record

Discipline beats memory. Open a case file immediately and keep it current, because a
week-old incident is reconstructed from notes, not recollections. A minimal case file:

```text
CASE 2025-014
──────────────────────────────────────────────
Opened : 2025-06-02 09:14 UTC by M. Chen (IR lead)
Status : CONTAINMENT
Severity: HIGH (candidate ransomware, single host confirmed)
Assets : WS-042 (Windows 11, user K. Roy), corp-dc01 (suspect logins)

SYNOPSIS
  SOC alert 8812: WS-042 wrote 2.1 GB in 40 min to \\corp-dc01\share. User reports
  files renamed with .locked extension and a ransom note.

TIMELINE (oldest first; UTC)
  2025-06-02 08:03  Alert 8812 fired (file-write volume anomaly)
  2025-06-02 08:20  Analyst confirms ransom-note file on WS-042 (hash logged)
  2025-06-02 08:45  Host isolated on quarantine VLAN; memory captured
  ...

EVIDENCE LOG
  E-001 WS-042 memory dump (winpmem)  SHA256 9f2c...  M. Chen 08:47 UTC
  E-002 WS-042 KAPE collection        SHA256 41ab...  M. Chen 09:05 UTC

ACTIONS LOG
  09:10  Disabled K. Roy's account per containment decision (lead + manager ok)
  ...

COMMS LOG
  09:30  Executive brief sent (template EXEC-BRIEF) — no customer impact confirmed
  ...
```

Conventions that keep case files usable:

- **One case number everywhere** — ticketing system, evidence IDs, emails, file names.
- **UTC timestamps** in logs; convert for human summaries.
- **Decisions recorded with rationale** ("disabled account X because..."), not just actions.
- **Every finding tied to evidence** ("Prefetch shows x.exe → see E-002").
- **Ownership explicit** — one incident commander, one comms lead, one scribe.

## Evidence Tracking

Evidence is only as good as its documentation. Maintain an evidence register (spreadsheet
or platform fields) with one row per exhibit:

| Exhibit | Source | Type | Tool + version | Hash (SHA-256) | Collected by | Date/Time (UTC) | Location |
| ------- | ------ | ---- | -------------- | -------------- | ------------ | --------------- | -------- |
| E-001 | WS-042 | Memory dump | winpmem 3.3 | 9f2c… | M. Chen | 2025-06-02 08:47 | \ev\case-014 |
| E-002 | WS-042 | Artifacts | KAPE 1.3 | 41ab… | M. Chen | 2025-06-02 09:05 | \ev\case-014 |

Rules:

- Hash at collection; verify before and after any transfer or analysis run.
- Store on dedicated media; mark exhibits as original vs. working copy.
- Record every handoff (who, when, why) — the chain of custody.
- Never let analysts write to evidence media or to the imaged original.

## Communication Templates

Communications are part of the response, not an afterthought. Adapt these freely.

### Internal Notification (Ops/SOC bridge)

```text
Subject: [IR-2025-014] ACTIVE INCIDENT — suspected ransomware, WS-042 isolated

Severity: HIGH     Status: CONTAINMENT     Updated: <UTC timestamp>

Summary: SOC alert 8812 — possible ransomware on WS-042 (user K. Roy). Files
renamed with .locked extension; ransom note present. No confirmed spread yet.

Containment so far: host isolated on quarantine VLAN; user account disabled.

Actions needed:
  [ ] AD team: review logins by K.Roy account since 2025-06-01
  [ ] Backup team: confirm offline backups for WS-042 and file share
  [ ] All: do NOT power off or reconnect WS-042

Next update: <time> or on material change. Bridge: <link/line>
```

### Executive Brief

```text
Subject: Security incident update — <date>

What happened: A single employee workstation showed signs of file-encrypting
malware this morning. We isolated the machine within ~40 minutes of detection.

Impact: No confirmed customer data impact. One workstation affected; no
evidence of spread at this time.

What we are doing: Preserving evidence, checking related accounts/systems, and
working from verified backups for recovery.

What we need from you: <decision, if any, e.g., breach-notification threshold>
Next update: <time>
```

### External Party (Vendor / ISP / CERT / Law Enforcement)

```text
Subject: [IR-2025-014] Request for assistance — <date> (TLP:AMBER)

We are responding to a suspected <ransomware/account-compromise> incident.
We request <log preservation for IP X / C2 takedown / guidance>.

Contact: <name>, <role>, <phone>, <email>   Case ref: IR-2025-014
```

Mark external messages with a TLP label (CLEAR/GREEN/AMBER/RED) so recipients know how
far the information may travel. Never put unverified claims or irrelevant personal data
in external messages.

## Coordinating Teams and External Parties

Typical structure during a significant incident:

- **Incident Commander** — owns the response, decisions, and priorities.
- **Technical responders** — triage, forensics, containment, eradication.
- **Communications lead** — internal updates and the single external voice.
- **Legal / compliance** — regulatory obligations (e.g., breach notification), privilege.
- **Business owners / PR** — customer impact, messaging, regulatory threshold decisions.
- **IT operations / engineering** — implementing changes (isolations, rebuilds, patches).

Escalation paths to define in advance (in the playbook, not during the fire): when the
IR team is called, when management is notified, when legal/CERT/law enforcement is
engaged, and who is authorized to make each call. Afterward, hold a lessons-learned
review and update the playbook — the loop that makes the next incident cheaper.

## Common Mistakes & Tips

- **Parallel tools, no single record.** Pick one case tracker and make everything
  reference it; duplicated notes get lost.
- **Communication gaps at handoffs.** Shift changes and phase changes (detection →
  containment) are where information dies — require a written handoff note.
- **Unverifiable evidence.** No hash, no chain-of-custody entry → the evidence is
  effectively useless later.
- **Over-sharing externally.** Route all external contact through the designated lead;
  one uncoordinated email can breach confidentiality or notification rules.
- **Skipping decision logs.** If the record only shows actions, the "why" is lost and
  the lessons-learned review becomes guesswork.
- **Treating the template as the message.** Templates keep structure; the content must
  still be accurate, current, and specific to this incident.

## Checklist / Self-test

- [ ] I know which ticketing/IR platform our team uses and how to open a case with severity and assignment.
- [ ] I can produce a complete case file: synopsis, timeline, evidence log, actions log, comms log.
- [ ] Every exhibit I handle has an ID, tool+version, hash, collector, and timestamp.
- [ ] I can draft an internal ops notification and an executive brief from the same facts.
- [ ] I know our escalation path: who to call, when, and who is authorized for each step.
- [ ] I can state the TLP label policy and when external parties must be engaged.
- [ ] I have a personal habit of logging actions and decisions contemporaneously during drills.

## Further Resources

- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide* (communications and coordination chapters) — https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- FIRST PSIRT Services Framework — https://www.first.org/standards/frameworks/psirts/
- MITRE ATT&CK (for scoping/communication of behaviors) — https://attack.mitre.org/
- TheHive project — https://thehive-project.org/
- DFIR-IRIS documentation — https://docs.dfir-iris.org/
- RTIR (Request Tracker for Incident Response, Best Practical) — https://bestpractical.com/rtir
