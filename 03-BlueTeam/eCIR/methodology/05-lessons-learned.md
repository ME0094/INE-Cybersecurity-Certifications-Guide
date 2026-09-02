# eCIR Methodology — Phase 5: Lessons Learned

> eCIR · Incident Response Methodology — INE-Cybersecurity-Certifications-Guide

The incident may be over, but the work is not: Lessons Learned is where the
organization turns a painful event into durable improvement. NIST SP 800-61
makes this phase mandatory ("do not skip this step") and recommends holding a
meeting within a few weeks of the incident to review what happened, why it
happened, and what should change. Organizations that skip it repeat the same
incidents with the same costs; organizations that do it well get faster
detection, cheaper response, and stronger defenses every cycle.

## Post-Incident Review (PIR)

Two complementary reviews should happen:

- **Hot wash** — immediately after containment/eradication, while details are
  fresh. Short, operational, no blame: what worked, what broke, what is still
  missing?
- **Formal PIR** — two to four weeks later, once the dust settles and the
  timeline and metrics are compiled. Structured, documented, with assigned
  owners and deadlines for every action item.

```text
PIR meeting agenda (90 minutes):
1. Incident summary and severity (5 min)
2. Timeline walkthrough: detection → containment → eradication → recovery
   (30 min)
3. Root-cause discussion (not blame) (20 min)
4. What went well / what went wrong (15 min)
5. Metrics review (5 min)
6. Action items: owner + due date for each (15 min)
```

Rules for a productive PIR:

- **No blame.** The goal is system improvement, not punishment; a blame
  culture guarantees people hide the next incident longer.
- **Base it on evidence.** Use the documented timeline and logs, not memory.
- **Limit action items.** Three to five concrete, owned, dated improvements
  beat a 40-item wish list nobody executes.
- **Track to closure.** Revisit open items at a regular security meeting until
  they are done.

## Timeline Reconstruction

A precise timeline is the backbone of the PIR, the report, and any legal or
regulatory inquiry. Reconstruct it from the artifacts collected during the
response:

- SIEM/EDR alerts and raw logs (auth, DNS, proxy, process creation)
- Email and messaging records, ticketing system, change requests
- Forensic artifacts (registry, prefetch/Amcache, shell history, browser data)
- Witness statements and responder notes — interview people early, while
  memory is fresh

Normalize everything to **UTC** and one consistent format so events sort
cleanly, and note the source and confidence of each entry.

```text
Timeline fragment (UTC):
2025-05-30 08:12:17  Phish delivered to jsmith (gateway log)
2025-05-30 08:23:44  jsmith submits credentials (proxy log, phish domain)
2025-05-30 08:24:02  Successful logon from 203.0.113.66 (AD, Event 4624)
2025-05-30 09:05:31  Suspicious PowerShell invoked (EDR alert 4412)
2025-05-30 09:06:10  Cobalt Strike beacon established (EDR/netflow)
2025-05-30 11:40:00  Lateral movement to SRV-FILE01 (Event 4624, logon type 3)
2025-05-31 03:12:55  First data exfiltration to 198.51.100.7 (proxy log)
2025-06-01 02:30:00  Detection alert escalated (SEV-2)
2025-06-01 03:10:00  Containment: account disabled, host isolated
```

For larger incidents, structured timeline tooling helps (e.g., the
log2timeline/plaso suite can parse many log formats into one timeline), but a
carefully maintained spreadsheet with time, event, source, and confidence is
often sufficient and easier to audit.

## Root-Cause Analysis

Root-cause analysis asks *why* the incident happened, repeatedly, until it
reaches a systemic cause — not a proximate one. The **5 Whys** technique is
simple and effective:

```text
Problem: Ransomware encrypted 40 workstations.
Why 1? An employee opened a malicious attachment.
Why 2? The attachment was not blocked by the email gateway.
Why 3? The gateway rule set had not been updated in 11 months.
Why 4? No one owned email-gateway rule maintenance.
Why 5? Security operations had no defined control-ownership and review
       process for gateway rules.

Systemic root causes identified:
- Missing ownership/periodic review for email controls.
- No exercise of the phishing playbook (see Phase 1) before the event.
Corrective actions → these become Phase 5 action items and feed back into
Preparation (the lifecycle closes here).
```

Distinguish root causes from contributing factors and from the *initial
vector* vs. the *spread enablers*: the phish was the vector, but missing MFA
and excessive service-account privileges enabled the blast radius. Fix all of
them, not just the vector.

## Metrics

You cannot improve what you do not measure. Track a small, consistent set of
IR metrics across incidents and review trends at the PIR:

| Metric | Definition | Why it matters |
| --- | --- | --- |
| MTTD (Mean Time to Detect) | Time from compromise to detection | Shorter = smaller blast radius |
| MTTA (Mean Time to Acknowledge) | Detection to first responder action | Measures triage responsiveness |
| MTTR (Mean Time to Respond/Recover) | Detection to recovery | Total cost driver |
| Dwell time | Adversary presence in the environment | Core scoping and detection metric |
| Containment time | Detection to effective containment | Measures Phase 3 quality |
| False-positive rate | Alerts escalated that were not incidents | Detection-tuning health |
| Repeat incidents | Same root cause recurring | Proves whether fixes worked |

```text
Example trend finding:
"Mean dwell time dropped from 41 days (Q1, two incidents) to 6 days (Q2,
one incident) after EDR deployment and the new authentication-failure
detection rule. Containment time remains above target on SEV-1s because
the incident-commander succession plan was untested — action item #2."
```

Be honest about definitions and normalize for severity: one massive incident
will skew monthly averages, so also report medians and per-incident values.

## Improving Playbooks and Controls

Every finding from the PIR maps to an artifact from Phase 1 (Preparation) or a
control to harden. Update:

- **Playbooks** — add the steps that were missing, fix the ones that failed,
  and note the real-world timings (playbooks should reflect reality).
- **Detection rules and SIEM queries** — tune false positives, add the
  behavioral detections that would have caught this incident earlier.
- **IR plan and tooling** — fix gaps in tool access, logging coverage, and
  role assignments discovered during response.
- **Security controls** — patch policy, MFA rollout, privilege reviews,
  network segmentation, backup validation.
- **Training and exercises** — design the next tabletop around this
  incident's failure points to prove the fixes work.

```text
Action item template:
ID | Finding | Action | Owner | Due date | Verification
A1 | Phishing playbook lacked credential-revocation step | Add IdP
   session-revocation step to playbook v2.1 | SOC lead | 2025-07-01 |
   Reviewed in tabletop July
A2 | Dwell time 41 days | Deploy authentication anomaly rule | Detection
   engineer | 2025-06-15 | Rule firing in SIEM staging
A3 | Gateway rules unowned | Assign rule-review ownership, quarterly review |
   Security engineer | 2025-06-30 | Review calendar entry + sign-off
```

## Reporting to Stakeholders

Different audiences need different reports. Prepare them from the same
evidence base but with different depth and tone:

- **Technical report (full):** timeline, indicators, root cause, technical
  actions, artifacts — for the IR team and engineers.
- **Executive summary (short):** what happened, impact, what was done, what is
  being fixed, residual risk — decisions, not jargon.
- **Legal/regulatory notifications:** facts, dates, data involved, actions —
  coordinate timing with counsel (e.g., breach-notification laws, GDPR's
  72-hour notification for personal-data breaches).
- **Customer/PR statements:** prepared with communications and legal; state
  facts, protect investigation details, avoid speculation.

```markdown
# Executive incident summary (template)

## What happened
(2–3 sentences: when, what type of incident, what systems/data were affected)

## Impact
(What data or systems were affected; business impact; current status)

## Response
(When detected, containment and eradication actions taken, current posture)

## What we are fixing
(Action items with dates — shows control and accountability)

## Residual risk and next steps
(Anything still open; when the formal PIR report is due)
```

Keep one **master incident record** (ticket number, severity, timeline,
actions, evidence index, reports) so any stakeholder question can be answered
from a single source of truth.

## Common Mistakes & Tips

- **Mistake:** Skipping the PIR "because we are busy." **Tip:** Schedule it
  before the incident is even closed; a 90-minute meeting saves days in the
  next incident.
- **Mistake:** Turning the PIR into a blame session. **Tip:** Enforce the
  no-blame rule; phrase findings as system gaps ("no owner for gateway
  rules"), not personal failures.
- **Mistake:** Reconstructing the timeline from memory weeks later.
  **Tip:** Keep the scribe's log live during the incident and normalize all
  timestamps to UTC as you go.
- **Mistake:** Stopping at the proximate cause ("the user clicked") and never
  finding the systemic cause. **Tip:** Use 5 Whys and separate the initial
  vector from the spread enablers.
- **Mistake:** 40 action items with no owners. **Tip:** Prioritize 3–5,
  assign owners and due dates, and track to closure in regular meetings.
- **Mistake:** Measuring metrics inconsistently between incidents.
  **Tip:** Define each metric once, document the definition, and report
  medians alongside averages.
- **Mistake:** Letting the executive summary drift into technical detail or
  speculation. **Tip:** Separate technical, executive, legal, and PR reports;
  review externally facing ones with counsel.
- **Mistake:** Never testing whether the fixes work. **Tip:** Make the next
  tabletop exercise replay the previous incident's failure points.

## Checklist / Self-test

- [ ] I can explain the difference between a hot wash and a formal PIR and
      when each should happen.
- [ ] I can build a UTC-normalized timeline fragment from multiple log sources
      and mark source/confidence per entry.
- [ ] I can run a 5 Whys root-cause analysis and distinguish the initial
      vector from the enablers that spread the incident.
- [ ] I can define MTTD, MTTA, MTTR, and dwell time and explain what each
      measures.
- [ ] I can convert a PIR finding into an action item with owner, due date,
      and a verification step.
- [ ] I can outline an executive incident summary and a full technical report
      from the same incident record.
- [ ] I know why playbooks, detection rules, and the next tabletop exercise
      must be updated after every incident.
- [ ] I can explain why a no-blame culture is essential for effective lessons
      learned.

## Further resources

- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide* —
  https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- MITRE ATT&CK — https://attack.mitre.org (used when translating findings
  into detection and prevention improvements)
- SANS Reading Room (post-incident, metrics, and security-awareness papers) —
  https://www.sans.org/reading-room/
