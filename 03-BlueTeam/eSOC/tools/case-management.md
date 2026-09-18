# Case Management and Enrichment Platforms — TheHive and Cortex

> eSOC · Tools — INE-Cybersecurity-Certifications-Guide
>
> An alert queue tells you what to look at; a case tool tells you what has been decided, by whom, and what happens next. This file covers the case-management model an analyst works inside (cases, tasks, observables), how TheHive and Cortex split the work between recording and enriching, how templates stop every analyst reinventing every investigation, and the failure modes that make a case tool quietly useless.
>
> **Interface and field names differ between TheHive 3, 4 and 5.** The concepts below are stable across them; the exact labels are not. Verify field names against the version your organisation runs, and treat the configuration examples as shapes to adapt. Nothing here was executed or screenshotted while writing this note.

## 1. Why a Case Tool Exists

A SIEM alert queue and a case tool answer different questions, and conflating them produces the failure the case tool was bought to prevent.

| Question | Alert queue | Case tool |
|---|---|---|
| What should I look at now? | Yes | No |
| What has been decided about this, and by whom? | Only as free-text comments | Yes, with ownership and state |
| What tasks remain, and who owns each? | No | Yes |
| What indicators did we observe, and can we search them? | No | Yes, as structured observables |
| What will enrich each indicator, consistently? | No | Yes, via analyzers |
| How long did this take, and where did it get stuck? | Partially | Yes, from state transitions |
| What does the next shift need to know? | Somewhere in the notes | In a structured summary and task list |

The practical test: **if a colleague takes over your case with no conversation and no access to you, can they continue?** In a queue, that depends on your prose. In a case tool, the state, owner, tasks, and observables carry most of it — and the prose becomes the explanation rather than the only record.

## 2. The Object Model

Every case tool is a small graph of objects. Learning the graph once makes any of them easy to operate.

| Object | What it holds | How an analyst uses it |
|---|---|---|
| **Alert** | An incoming detection, still in triage; may be merged into a case or dismissed | Where the SIEM's alert becomes a record with a reason |
| **Case** | The investigation: title, severity, TLP/PAP classification, owner, summary, tags, tasks, observables | The unit of ownership and reporting |
| **Task** | A single step with an assignee, a status, and a description | How open actions survive a shift boundary |
| **Observable** | A structured indicator (IP, domain, hash, URL, account, file) with flags and tags | The searchable memory of the investigation; the input to analyzers |
| **TTP** | A MITRE ATT&CK technique or tactic attached to the case | Coverage reporting and pattern recognition across cases |
| **Template** | A reusable case or task skeleton for a recurring scenario | Consistency: every phishing case asks the same questions |
| **Analyzer** (Cortex) | An enrichment job launched against an observable | Turns "check reputation" into a repeatable one-click action |
| **Responder** (Cortex) | An action job launched against an observable | Block, isolate, notify — the orchestrated half of "response" |
| **Report** | The stored output of an analyzer, with a taxonomy level and confidence | The evidence behind the enrichment line in your note |

> The single most useful habit with this model: **record observables as structured objects, not as text in the summary.** A hash written in a paragraph is lost; a hash recorded as an observable is searchable across every case you have ever worked, which is how you discover that today's alert is the third sighting this quarter.

## 3. Case Lifecycle and What Each State Means

States differ by product; the meanings do not. Map your tool's labels onto these five before you work a shift with it.

| State | Meaning | What must be true before leaving it |
|---|---|---|
| **New / Open** | Incoming, not yet claimed | An owner is assigned (unowned cases are where work dies) |
| **In progress** | Someone is working it | Tasks exist with owners, and the summary says what is known so far |
| **Pending / Blocked** | Waiting on a third party, a user's answer, or another team | The blocker, who owns it, and a date to re-check are recorded — never just "waiting" |
| **Resolved / Closed** | A verdict was reached and documented | Summary, verdict, actions taken, and any follow-up (a task on another case, or a monitoring note) |
| **Merged / Duplicate** | The same incident as another case | A link to the surviving case, so metrics do not double-count |

For a tier-1 analyst, the boundary that matters most is **Pending vs In progress**. "Pending" with no owner and no date is how investigations disappear for a week; treating it as "not my problem anymore" is the most common cause of a reopened case.

## 4. TheHive and Cortex: Who Does What

The two products are designed together, and the division of labour is the point.

| Product | Role | What the analyst does with it |
|---|---|---|
| **TheHive** | Case management: alerts, cases, tasks, observables, TTPs, templates, dashboards | Owns the record. Every decision, action, and artefact lives here |
| **Cortex** | Analysis and response engine: analyzers enrich, responders act | Called *from* a case, on *specific* observables. Results land back on the observable as reports |

The workflow that makes the pair useful, in the order it happens during triage:

1. **An alert becomes a case** (or is dismissed with a reason and a category — dismissal reasons are your tuning input).
2. **Observables are extracted from the alert** — the destination address, the hash, the account, the hostname — and stored as typed objects with a TLP/PAP classification.
3. **Analyzers run against those observables** — reputation, sandbox, passive DNS, whatever your instance is configured with. Each produces a **report** and a **taxonomy level** (typically something like info / safe / suspicious / malicious) with a **confidence** value.
4. **The analyst reads the reports, not just the levels.** The level is a summary produced by someone else's logic; the report shows the evidence and lets you disagree with it.
5. **Responders run only when the action is approved** — blocking, isolating, notifying. In most deployments tier 1 should *not* have responder access to containment actions; that is a deliberate design choice, not a limitation.
6. **Tasks record the work that is not an observable** — "call the user", "check the other host", "ask the network team whether the address is in the VPN pool".
7. **The case closes with a summary** that a reader can act on: verdict, evidence, actions, follow-ups.

> Two configuration facts worth knowing even as a consumer: **analyzers cost API quota and time**, so running eight of them on every observable slows the queue and may exhaust a rate limit; and **a responder is a write action on production**, so its authorisation and its blast radius belong in the playbook, not in an analyst's judgement at 03:00.

## 5. Templates: Consistency Instead of Improvisation

A template is how a SOC's best investigation becomes everyone's default. It is also the cheapest improvement available to a tier-1 analyst, because writing down the steps you just improvised is a five-minute task that pays back at every future shift.

What a good case template contains:

- **Title and description** for the scenario (for example "phishing attachment reported by a user").
- **Task list**, in order, with assignees implied: verify the raw event; extract observables; run the configured analyzers; check whether other users received the same message; check whether the attachment was opened anywhere; contain if confirmed; notify the reporting user; write the summary.
- **Severity and classification defaults** (TLP/PAP) so nobody has to guess under pressure.
- **Required fields before closing**, which is how the summary standard survives contact with a busy shift.

The sign that templates are working: a colleague who has never seen the scenario before can complete the case correctly without asking anyone. The sign they are not: they exist, nobody uses them, and every case looks different.

## 6. Metrics the Case Tool Actually Produces

Case tools are where the honest SOC metrics come from, because they record state transitions rather than just alert counts (see `../methodology/07-soc-metrics.md` for how to interpret them).

| Metric | Where it comes from | What it tells you |
|---|---|---|
| Cases per period, by severity and type | Case objects | The real shape of the workload, not the queue's noise |
| Time in each state | State transition timestamps | Where cases stall: triage, waiting on a third party, or closure |
| Task completion rate and overdue tasks | Task statuses | Whether open actions survive shift boundaries |
| Closure reason distribution | The closure field | The tuning backlog, quantified |
| False-positive rate per detection rule | Alert/case links | Which rules cost more attention than they earn |
| Observable recurrence | Observable search across cases | The indicator you have now seen three times, which changes its weight |
| Reopened cases | State history | Triage quality, and the cost of closing too early |

## 7. Diagnostics: When the Case Tool Misbehaves

| Symptom | Likely cause | Check |
|---|---|---|
| Analyzer report stuck "in progress" | The Cortex worker cannot reach the service, or the API key expired | Cortex job status and worker logs; the analyzer's key |
| Every analyzer fails for one observable type | Malformed value for that observable's type (an address stored as a domain, a defanged URL) | The observable's type and its exact value |
| Rate-limit errors from an external service | Too many analyzers, or a shared key across the team | Which analyzers use that service, and how often they run |
| Two cases for one incident | Alerts merged late, or two shifts both claimed it | Search recent cases by observable before opening a new one |
| Closed cases with no summary | No required-field enforcement at closure | Template configuration, and a quality review on a sample of closures |
| Metrics show zero for a period | Cases closed through a different path (bulk closure, API, or a duplicate system) | How closure actually happens, before trusting the dashboard |

Two habits that keep a case tool honest: **search before you create** (a duplicate case fragments the timeline and corrupts the metrics), and **write the closure summary as if it were the only thing the next analyst will read** — because for most operational questions, it is.

## Common Mistakes & Tips

- **Mistake:** treating the case tool as paperwork that delays the investigation. *Tip:* the tool *is* the investigation's memory; the tasks and observables you record are what let someone else continue, and what generate the metrics that justify staffing.
- **Mistake:** writing observables into the narrative text instead of as objects. *Tip:* a structured observable is searchable across every case you have worked; a hash in a paragraph is lost.
- **Mistake:** leaving a case in "pending" with no owner and no date. *Tip:* pending needs a named blocker owner and a re-check date, or the case is abandoned rather than paused.
- **Mistake:** trusting the analyzer's taxonomy level without reading the report. *Tip:* the level is someone else's summarised opinion; the report is the evidence you can argue with.
- **Mistake:** running every configured analyzer on every observable. *Tip:* each one costs time and quota; run the ones whose outcome could change your verdict.
- **Mistake:** giving tier 1 responder access to containment actions because it is more convenient. *Tip:* separate the analysis role from the write action, or your fastest analyst becomes your least-reviewed containment operator.
- **Mistake:** opening a new case without searching existing ones by observable. *Tip:* search first — the third sighting of an indicator is materially different from the first.

## Checklist / Self-Test

- [ ] I can name the difference between what an alert queue and a case tool each record.
- [ ] I can describe a case's objects — alert, case, task, observable, TTP, template, analyzer, responder, report — and how they relate.
- [ ] I record indicators as structured observables rather than as text in a summary.
- [ ] I can state my tool's five lifecycle states and the entry condition for each.
- [ ] I know what must be true before a case leaves "pending" and who owns the blocker.
- [ ] I read analyzer reports and not only their taxonomy levels.
- [ ] I know which responders exist in my environment, who may run them, and why that separation matters.
- [ ] I can explain why closure summaries and closure categories are the tuning backlog's raw material.
- [ ] I search existing cases by observable before creating a new one.
- [ ] I know which metrics my case tool produces and which ones my SOC actually reviews.

## Further Resources

- TheHive Project — case management platform documentation: https://docs.strangebee.com/
- TheHive Project — project home and community: https://thehive-project.org/
- Cortex — analyzers and responders documentation: https://docs.strangebee.com/cortex/
- MISP Project — sharing and enriching indicators alongside case management: https://www.misp-project.org/documentation/
- MITRE ATT&CK — the TTP vocabulary case tools attach to investigations: https://attack.mitre.org
- NIST SP 800-61r3 — incident documentation and lifecycle expectations: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- FIRST — Traffic Light Protocol (TLP), used for case and observable classification: https://www.first.org/tlp/
