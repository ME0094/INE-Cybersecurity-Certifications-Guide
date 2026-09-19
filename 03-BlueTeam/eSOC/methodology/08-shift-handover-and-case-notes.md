# eSOC Methodology — Phase 8: Shift Handover and Case Notes

> Tier-1 SOC Analyst focus · INE-Cybersecurity-Certifications-Guide
>
> A SOC's memory is written, not verbal. This phase covers the two documents that carry it across the shift boundary — the handover note and the case note — plus the registers that stop the next analyst from rediscovering known conditions, and the minimum state that must be transferred when an investigation is still in flight. The writing standards here are the same ones the other phases assume; this file is about the mechanics of the boundary itself.

## 1. Why Handover Is a Security Control

An alert that nobody knows about is not being monitored. Handover failure produces a specific and predictable class of incident:

- An investigation that was 80 % complete is restarted from zero because the leaving analyst's reasoning died with their shift.
- An open action ("check the other host that logged on from that IP") is never performed, and the second compromised host stays live for days.
- A suppression is still in force, nobody knows, and a real detection stays silent through the weekend.
- A data source has been down for six hours; the next shift reads an empty dashboard as a quiet night.

Each of those is a control failure with a documentation root cause. The fix is mechanical and cheap: a handover that takes fifteen minutes and a note that takes five.

> The test of a handover is not "did I explain everything". It is: **can the next analyst continue without asking me anything?** If they have to message you at home, the handover was incomplete — and the point of it is that you should be able to sleep.

## 2. What Must Cross the Shift Boundary

Six categories, every time. Anything not in one of them does not need to cross.

| Category | What to transfer | Why it is missed so often |
|---|---|---|
| **Open incidents and high-severity cases** | Case ID, one-line state, last verified finding, owner, next action | Replaced with "nothing major happened", which is not transferable information |
| **In-flight investigations** | The hypothesis, the queries already run, what was ruled out, what remains | Analysts report conclusions and lose the reasoning that produced them |
| **Open actions with owners and deadlines** | Action, owner, due time, status | Verbal actions evaporate; unwritten owners do not act |
| **Known conditions** | Active suppressions, planned change windows, expected noisy jobs, degraded sources | The next shift interprets a planned condition as an event, or an outage as calm |
| **Collection and tooling health** | Sources down or lagging, agents not reporting, parsers broken, cases of missing data | A broken source looks identical to a quiet environment |
| **Queue state** | Depth by severity, the oldest open alert and its age, any alert deliberately parked | Queue depth is the only way the next shift judges its own load honestly |

## 3. The Handover Note

Fill this in at the end of every shift, even a quiet one — a documented quiet shift is evidence; a silent one is an absence of information. Adapt the field names to your tool, keep the fields.

```text
SHIFT HANDOVER — <date> <shift> <analyst>
================================================================================
QUEUE STATE
  Open alerts:        critical ____  high ____  medium ____  low ____
  Oldest open alert:  <id> <age> - why it is still open: __________________
  Deliberately parked (with reason and re-check time): __________________

OPEN INCIDENTS / HIGH-SEVERITY CASES
  Case <id> | severity | state (one line) | owner | next action + due time
  Case <id> | ...

IN-FLIGHT INVESTIGATIONS (not yet a case)
  What:      <entity: host / user / IP / hash>
  Hypothesis: <what you think is happening, and why>
  Already done: <queries run, sources checked - so nobody repeats them>
  Ruled out:   <what you eliminated, and with what evidence>
  Still open:  <the specific question the next shift should answer>
  Time box / escalate by: <time>

ACTIONS HANDED OVER
  [ ] <action>            owner: <name>   due: <time>   status: open
  [ ] <action>            owner: <name>   due: <time>   status: open

KNOWN CONDITIONS (do not re-investigate from scratch)
  Active suppression: <rule> scoped to <what>, expires <when>, case <id>
  Expected activity:  <job/deployment> on <hosts> at <time>, owner <name>
  Degraded source:    <source> down/lagging since <time>, ticket <id>
  Parsing defect:     <field> empty for <source> since <time>, ticket <id>

VERIFIED SINCE LAST HANDOVER
  <facts established this shift: "confirmed the hash on HOST-A came from mail
   attachment X"; "verified 4625 spike was the misconfigured service account">

NOT CHECKED / NOT COVERED
  <what you could not look at, and why - a gap stated is a gap someone can close>
================================================================================
```

The two fields that make this note worth writing are **"Already done"** and **"Not checked"**. The first stops duplicated work; the second is the only honest way to record partial coverage.

## 4. The Fifteen-Minute Verbal Handover

The written note is the record; the conversation is where the reasoning transfers. A fixed agenda keeps it short:

1. **Queue state and anything parked** (2 minutes) — depth, oldest alert, deliberate deferrals.
2. **Open incidents, by severity** (3 minutes) — case ID, state, next action, who owns it now.
3. **In-flight investigations** (4 minutes) — hypothesis and the one question the next shift must answer. Walk through the timeline, not the conclusion.
4. **Actions and owners** (2 minutes) — confirm each open action out loud and confirm the owner acknowledges it. An action acknowledged aloud by a named owner is more likely to be done than one in a list nobody read.
5. **Known conditions and source health** (2 minutes) — suppressions in force, planned activity, broken sources.
6. **Questions to the outgoing analyst** (2 minutes) — the incoming analyst's chance to challenge the state. This is where a wrong hypothesis gets caught before it is inherited.

Keep it to fifteen minutes. A handover that runs forty minutes is a status meeting, and the information in it stops being read.

## 5. Case Note Standards

A case note is read by: the next shift, tier 2, IR, possibly management after an incident, and you in three months when a similar alert fires. Write for those readers, not for yourself.

| Rule | Why | Example |
|---|---|---|
| **Separate facts from assessment** | The difference between what is known and what is believed must survive the handoff | `FACT: svchost.exe spawned powershell.exe at 02:12:40Z (4688). ASSESSMENT: the parent is unremarkable - Task Scheduler and WMI launch children from svchost.exe - so the finding rests on the child's arguments: an encoded command no scheduled task or agent on this host explains, confidence medium` |
| **Timestamp in UTC, first, consistently** | Timelines merge across sources; local time does not | `2025-06-01 02:12:40Z`, never "just after 2" |
| **Reference the evidence, do not paste the world** | A note is an index into the data, not a copy of it | "Event 4688, host WIN-FIN-07 (raw event id `abc123`)" rather than a wall of XML |
| **Write as you go** | Reasoning reconstructed hours later loses the questions you discarded | Record the query you ran and its result at the moment you run it |
| **State confidence explicitly** | "Probable" and "confirmed" must not be interchangeable | `confidence: medium`, `confidence: high - two independent sources agree` |
| **Record negative results** | They prevent repeated work and show scope | "No MISP match for the destination; no prior sighting of the domain in this account's history" |
| **Keep the action log current** | The case is the coordination surface for a team | Timestamped action lines, not a narrative paragraph |
| **Close with a conclusion and a next step** | An open case without a next action is a case nobody owns | "Contained; monitoring for the same destination on other hosts for 72 h; owner: tier 2" |

Naming and identification conventions worth having before you need them:

- **One case ID per incident**, reused in every note, query comment, containment record, and escalation. Never a second ID "because this is a different ticket system".
- **Entity naming exactly as it appears in the data** (`WIN-FIN-07`, `CORP\m.lopez`, `203.0.113.77`). Nicknames and abbreviations make notes unsearchable.
- **One case per incident, not one per alert.** Correlated alerts belong to the same case; splitting them fragments the timeline, and the timeline is the case.

## 6. The Open Action Register

Actions are where investigations leak. Keep them in one place, with an owner and a time, inside the case.

| Action | Owner | Due (UTC) | Status | Evidence of completion |
|---|---|---|---|---|
| Confirm whether other hosts logged on from `198.51.100.9` | A. Tier1 | 06:00 | open | Query result attached to the case |
| Ask the user whether they opened the attachment | B. Tier1 | 09:00 | open | Note with the user's answer and the time |
| Verify the suppression on rule X expires Friday | C. Lead | Fri 00:00 | open | Suppression record screenshot/ID in the case |
| Re-check the destination IP for new sightings | A. Tier1 | +24 h | open | SIEM search result recorded |

Three properties make this register work: **every row has an owner** (not "the team"), **every row has a due time**, and **completion is evidenced** — an action marked done with no artefact is indistinguishable from an action forgotten. When a case is handed to IR, the register travels with it.

## 7. Handing Over an In-Flight Investigation

The most expensive handover failure, and the one with the clearest minimum standard. Before you leave, the next analyst must be able to answer all six questions from your note alone:

1. **What entities are in scope?** Hosts, users, addresses, hashes, domains — exactly as they appear in the data.
2. **What is the hypothesis, stated as something that could be wrong?** "Attacker used stolen credentials and established a scheduled task" is falsifiable; "this looks bad" is not.
3. **What have you already verified?** With timestamps and event references.
4. **What have you ruled out, and how?** The ruled-out list is often the most valuable part, because it prevents the next analyst re-walking a dead end.
5. **What is the single next question?** One question, not five; the next shift should not have to choose.
6. **When does it escalate if unanswered?** A time and a trigger, so the decision does not depend on who is on duty.

```text
In-flight handover, condensed (paper example, no live data):
  SCOPE      WIN-FIN-07, CORP\m.lopez, 198.51.100.9, 203.0.113.77
  HYPOTHESIS The 02:11 UTC logon is a stolen credential: six failures from a public
             address followed by a success, then encoded PowerShell whose parent is
             svchost.exe - a task/WMI launch, so the anomaly is the arguments, not the parent.
             Falsifiable by: the source being an approved VPN egress (verify with Network team).
  VERIFIED   4625 x6 then 4624 type 3 at 02:12:01Z; 4688 encoded PowerShell 02:12:40Z;
             three TCP sessions to one address at ~60 s intervals from 02:13Z.
  RULED OUT  Scheduled maintenance window (no change record); the user's own workstation
             (they are travelling; VPN session was from a different address).
  NEXT       Does 198.51.100.9 belong to the corporate VPN pool? If not -> escalate now.
  DEADLINE   Escalate by 08:00Z if unanswered; do not close without an answer.
```

## 8. Note Quality: Weak and Strong

| Weak handover line | The problem | Strong version |
|---|---|---|
| "Quiet night, nothing to report." | Not information; hides coverage gaps | "Quiet: 34 alerts, all closed FP with reasons (top rule: encoded PowerShell x19, excluded parent confirmed). Sources all reporting. Nothing parked, nothing open." |
| "Investigating a suspicious logon." | No entities, no hypothesis, no next step | "SCOPE ... HYPOTHESIS ... NEXT ... DEADLINE ..." as in section 7 |
| "Tier 2 will look at it." | No state, no identifier | "Case SOC-2025-001 escalated to tier 2 at 02:35Z with full package; tier 2 owner: <name>; awaiting their scope confirmation." |
| "Rule X is noisy, someone should fix it." | No measurement, no owner, will not be fixed | "Rule X: 41 alerts this shift, all the same signed inventory agent on asset group FIN-WKS. Proposed exclusion logged in the tuning backlog; owner <name>; re-review Friday." |
| "Logs seem to be missing for HOST-B." | Ambiguous and unactionable | "HOST-B has sent no events since 23:40Z; agent service stopped (ticket INF-4471 raised, owner <name>); collection gap from 23:40Z to present — treat absence of alerts for HOST-B as absence of data." |

The pattern in every strong version: **what happened, how it is known, who owns the next step, and what a reader must not conclude from silence.** That last clause is what turns a note into a control.

## Common Mistakes & Tips

- **Mistake:** treating handover as a formality when the shift was quiet. *Tip:* a documented quiet shift with counts and verified sources is evidence of coverage; "nothing happened" is not.
- **Mistake:** transferring conclusions without the reasoning. *Tip:* hand over the hypothesis, the queries already run, and what was ruled out — the next analyst must be able to disagree with you on evidence.
- **Mistake:** writing actions without owners. *Tip:* "someone should check" means nobody will; name a person and a time, and confirm it aloud in the verbal handover.
- **Mistake:** letting suppressions and expected activity live only in someone's memory. *Tip:* keep the known-conditions register in the handover note; a suppression nobody knows about is a silent gap.
- **Mistake:** reporting an empty dashboard as calm. *Tip:* state source health every handover; a broken source and a quiet environment look identical from the queue.
- **Mistake:** writing notes for yourself. *Tip:* the readers are the next shift, tier 2, IR, and you in three months; facts and assessments labelled, UTC everywhere, evidence referenced not pasted.
- **Mistake:** leaving an investigation as "in progress" with no deadline. *Tip:* an in-flight case needs a next question, a time, and an escalation trigger, or it dies quietly at the shift boundary.

## Checklist / Self-Test

- [ ] My handover note covers queue state, open cases, in-flight investigations, actions, known conditions, and source health.
- [ ] Every open action in my handover has a named owner, a due time, and evidence of completion when done.
- [ ] I record what was already checked and what was ruled out, so the next shift does not repeat it.
- [ ] I state what I did *not* check, so partial coverage is visible rather than implied.
- [ ] I can express an in-flight investigation as scope, hypothesis, verified, ruled out, next question, deadline.
- [ ] My case notes separate facts from assessment and label confidence explicitly.
- [ ] All timestamps in my notes are UTC and consistent across sources.
- [ ] I use one case ID per incident and the exact entity names from the data.
- [ ] I confirm open actions aloud with the incoming analyst, by name.
- [ ] I can explain why an empty dashboard is not the same as a calm night.

## Further Resources

- NIST SP 800-61r3 — incident response lifecycle, documentation, and communication expectations: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-92 — log management, retention, and the records an analyst relies on: https://csrc.nist.gov/pubs/sp/800/92/final
- MITRE ATT&CK — technique vocabulary for hypotheses that other analysts can interpret: https://attack.mitre.org
- TheHive Project — case and task management model for documenting investigations: https://thehive-project.org/
- CISA — incident response resources and coordination guidance: https://www.cisa.gov/resources-tools
- FIRST — Traffic Light Protocol (TLP) for handling information that crosses team boundaries: https://www.first.org/tlp/
