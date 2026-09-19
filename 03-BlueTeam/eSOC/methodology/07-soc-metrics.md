# eSOC Methodology — Phase 7: SOC Metrics

> Tier-1 SOC Analyst focus · INE-Cybersecurity-Certifications-Guide
>
> Metrics exist to make decisions, not to decorate a slide. This phase defines the handful of measures that actually describe a SOC's performance, shows where each one comes from in the data an analyst already generates, and explains how the same numbers get gamed, misread, or used to punish the wrong people. Every formula here is stated explicitly, because the definitions of these acronyms differ between organisations and an undefined metric is an argument waiting to happen.

## 1. First, the Rule Against Vanity Metrics

A useful metric changes a decision. Before adding one to a dashboard, answer: *who acts differently depending on this number, and how?*

| Metric | The decision it supports | Useful? |
|---|---|---|
| Mean time to acknowledge, by severity | Whether the on-call rotation and staffing cover the alert flow | Yes |
| Alerts closed per analyst per shift | Almost always becomes a per-person target that rewards fast, shallow closures | No, on its own |
| Number of rules in production | Whether detection content management is happening at all | Weakly — only alongside coverage and fidelity |
| Percentage of ATT&CK techniques with at least one detection | Where to invest detection engineering next | Yes, with the caveat that it measures *claimed* coverage |
| Alerts closed as false positive | The tuning backlog — the raw material of improvement | Yes, if closure reasons are honest |
| "Number of incidents handled" | Depends entirely on what counts as an incident; easy to inflate by redefining | Rarely |

> **Goodhart's law applies to every analyst metric.** The moment a number becomes a performance target, it stops measuring what it was measuring: closure speed improves by closing alerts faster, and false-positive counts fall by reclassifying them. Use metrics to steer the *system* — staffing, tuning, coverage, tooling — and never as a per-person scoreboard.

## 2. The Time Metrics: Define Them or Do Not Quote Them

The acronyms below are the industry's shorthand, but "MTTR" means *respond* in some organisations and *resolve* in others. Always publish the definition with the number.

| Metric | Definition used here | Clock starts | Clock stops | Typical data source |
|---|---|---|---|---|
| **MTTD** — mean time to detect | Mean elapsed time from the first evidence of the activity to the creation of an alert or case | First event in the SIEM attributable to the activity (for a known incident, the true "patient zero" event) | Alert/case creation timestamp | SIEM events vs. case creation time; for real incidents, post-hoc timeline |
| **MTTA** — mean time to acknowledge | Mean elapsed time from alert creation to an analyst taking ownership | Alert creation | Acknowledge action in the queue/case tool | Alert queue timestamps |
| **MTTC** — mean time to contain | Mean elapsed time from confirmation to effective containment | Analyst confirms the true positive | Containment verified (isolation active, account disabled) | Case notes with UTC timestamps |
| **MTTR** — mean time to respond **or** resolve | *State which one.* Respond: confirmation to first action. Resolve: alert creation to case closure | As defined by your SOC, published alongside the number | As defined by your SOC | Case tool lifecycle fields |
| **Dwell time** | How long the adversary was present before being detected | Earliest evidence of intrusion | Detection | Reconstructed post-incident timeline, not a live dashboard |

Four measurement traps, all of which make numbers look better than reality:

1. **MTTD measured from the alert.** If MTTD is computed as "alert creation minus alert creation", it is always zero. Measuring it honestly requires the post-incident timeline: were there events in the data *before* the alert fired that a better rule would have caught? For SOCs without that discipline, report **coverage** and **dwell time from confirmed incidents** instead of a live MTTD — and say which one you are reporting.
2. **Clock source mismatch.** Alert creation time (platform clock), event time (host clock), and analyst action time (case tool clock) live in different systems. Skewed host clocks and timezone bugs corrupt the metric silently. Validate the clocks before you trust the average.
3. **Backfill distortion.** After an agent outage, thousands of old events arrive at once and can create alerts with old timestamps and new creation times, producing spectacular fake MTTDs. Exclude backfilled alerts or annotate them.
4. **Averages hide the tail.** A mean MTTA of 12 minutes can hide the fact that the worst 5 % waited nine hours. Report a percentile (p90 or p95) alongside the mean, because the tail is where the missed alerts live.

## 3. Alert Load: Capacity Is Arithmetic, Not Opinion

Alert volume per analyst is the metric that most directly predicts missed incidents, and it is the easiest to compute from the queue.

| Measure | Formula | How to read it |
|---|---|---|
| **Arrival rate** | Alerts created per hour (by shift, by severity) | The input side of the queue |
| **Clearing rate** | Alerts closed per analyst-hour × analysts on shift | The output side |
| **Queue depth trend** | Open alerts at shift start, compared across shifts | The trend matters more than the value: a persistently rising backlog is unbounded by construction |
| **Backlog ageing** | Age of the oldest open alert, and the count older than one shift | The direct measure of what is being missed |
| **Handling time** | Median analyst minutes per closed alert, by rule | Turns volume into capacity: alerts × minutes = analyst hours required |
| **Occupancy** | Analyst hours spent on alerts ÷ analyst hours on shift | Near 100 % occupancy means no time for tuning, hunts, or learning — and no slack for a real incident |

The arithmetic that makes the argument for you, using hypothetical inputs:

```text
Assume:  420 alerts per 24 h, 3 analysts across two shifts (24 analyst-hours),
         median handling time 11 minutes.
Demand:  420 x 11 min = 4 620 minutes = 77 analyst-hours.
Reality: 77 required vs 24 available -> the queue cannot be cleared by triage alone.
Conclusion (not "work faster"): the volume must come down by rule-level tuning,
         or staffing must change, or both. Both are management decisions, which is
         exactly why the number needs to be on the report.
```

That calculation is more persuasive than any statement about being busy, and it shifts the conversation from analyst effort to detection design — where the actual fix lives.

## 4. Triage Quality: Did the Decisions Hold Up?

Speed without accuracy is a queue that empties while incidents escape. Quality metrics are the counterweight.

| Metric | Formula | What it exposes |
|---|---|---|
| **False-positive rate** | FP closed ÷ all closed, per rule and overall | Noise; per rule, it is the tuning input |
| **Fidelity (precision)** | Confirmed TP ÷ (TP + FP) | Whether the rule matches how the environment actually behaves |
| **Reopening rate** | Alerts/cases reopened ÷ closed | Premature closures — the cheapest early warning of a triage quality problem |
| **Escalation precision** | Escalations confirmed by tier 2/IR ÷ escalations sent | Whether analysts escalate on evidence or on discomfort |
| **Escalation latency** | Time from confirmation to escalation sent | The cost of hesitation — usually a process or authority problem, not an analyst problem |
| **Missed-detection count** | Incidents found by other means (user report, external notification, another team) ÷ all incidents | The most important number in the SOC, and the least often published |
| **Closure reason completeness** | Closures with a reason and a category ÷ all closures | Whether the improvement loop has any input at all |

Two of these deserve emphasis:

- **Escalation precision is not a target to maximise.** Chasing 100 % precision teaches analysts to escalate only when certain, which is exactly the failure mode escalation criteria exist to prevent. A healthy SOC has some false escalations and treats them as the cost of not missing incidents.
- **Missed detections are the honest measure of detection coverage.** If most incidents arrive by user report rather than by your own alerting, coverage is lower than the rule count suggests, whatever the ATT&CK heat map says.

## 5. Coverage and Detection Content Metrics

These describe the *system*, and they are what a detection engineering programme reports.

| Metric | How to compute it | Caveat to publish with it |
|---|---|---|
| ATT&CK technique coverage | Techniques with ≥1 rule in production ÷ techniques considered relevant to the environment | Measures claimed coverage, not validated coverage; two techniques validated by emulation beat twenty mapped on paper |
| Validated detections | Rules with a recorded positive test (and a date) ÷ rules in production | The gap is your real risk: untested rules may be silently broken |
| Data-source coverage | Critical assets/classes sending parsed events ÷ those inventoried | A rule cannot fire on a host that sends nothing (see `01-monitoring.md`) |
| Rule health distribution | Count of rules by lifecycle state (production / tuning / deprecated / retired) | A set with no retirements in a year is not stable; it is unattended |
| Rules never fired | Rules with zero alerts in the period | Ambiguous by itself: validate the data source before concluding "quiet" |
| Mean time to rule update | From intel/case input to a deployed, validated rule | Measures how fast intelligence becomes detection — a queueing problem like any other |

## 6. Where the Numbers Come From

Nothing in this phase requires a new tool: the data is already produced by triage, if it is recorded consistently.

| Metric | Source | What must exist for it to be computable |
|---|---|---|
| MTTA | Alert creation time + acknowledge event | An acknowledge action that is actually used (not an implicit "I read it") |
| Handling time | Case tool time-in-state, or analyst time entries | State transitions recorded honestly |
| Fidelity / FP rate | Closure reason with a **category**, not just free text | A closure taxonomy agreed with the analysts who must use it |
| Queue depth and ageing | Open-alert counts by severity over time | Alerts that stay open are not silently auto-closed by a scheduled job |
| Coverage | Asset inventory joined to data-source health | An inventory that includes the assets that do not report |
| Dwell time | Post-incident timeline | The discipline to reconstruct the timeline backwards past the alert (see `03-investigation.md`) |

Query shapes for the queue-side measures — syntax references to adapt in your own platform, **not executed while writing this note** (there is no SIEM on the machine that produced it):

```spl
# Splunk: alerts per rule per day, with closure outcomes (field names are illustrative)
index=soc_alerts earliest=-30d
| bin _time span=1d
| stats count as alerts,
        count(eval(closure_category="true_positive")) as tp,
        count(eval(closure_category="false_positive")) as fp
        by _time, rule_name
| eval fidelity = if(tp+fp > 0, round(tp/(tp+fp)*100, 1), null())
| sort - alerts
```

```kusto
// Microsoft Sentinel KQL: alert volume and acknowledge latency by severity
SecurityAlert
| where TimeGenerated > ago(30d)
| extend Acked = todatetime(ExtendedProperties["AcknowledgedAt"])
| summarize Alerts = count(),
            MedianAckMinutes = percentile(datetime_diff('minute', TimeGenerated, Acked), 50),
            P95AckMinutes    = percentile(datetime_diff('minute', TimeGenerated, Acked), 95)
            by AlertSeverity
| sort by Alerts desc
```

```text
# Kibana / Elastic Security: the same question through the detection alert index
# (aggregation, not plain KQL - use a visualization or ES|QL on .alerts-security.*)
FROM .alerts-security.alerts-*
| STATS alerts = COUNT(*) BY kibana.alert.rule.name, kibana.alert.severity
| SORT alerts DESC
| LIMIT 20
```

The field names above differ by integration and version. Confirm them against a real alert document (expand one alert and read its fields) before building a dashboard on them — a metrics dashboard built on guessed field names reports zero, and zero looks like good news.

## 7. Reporting: Different Audiences, Different Numbers

The same data, presented three ways, and one presentation that must be avoided.

| Audience | What they need | What to leave out |
|---|---|---|
| The SOC team | Per-rule volume and fidelity, queue ageing, open tuning items, coverage gaps | Per-analyst rankings and any number that reads as a score |
| SOC management | Alert demand vs. capacity (the arithmetic in section 3), MTTA by severity with percentiles, escalation precision, backlog trend | Raw alert counts with no denominator |
| Leadership / risk owners | Trend of dwell time and missed detections, coverage against the techniques that matter to the business, confirmed incidents and their business impact | Tool-level detail, and any metric that cannot be explained in one sentence |

**Never publish a per-analyst leaderboard of closures or speed.** It optimises for closing, not for deciding, and it makes analysts avoid hard alerts — the exact behaviour that lets incidents through. If an individual's numbers are looked at at all, it belongs in a coaching conversation with the underlying cases open on the table, never in a ranked table.

## 8. Worked Example: Reading a Month Honestly

Hypothetical inputs, chosen to show the reasoning rather than to quote a benchmark. Assume a six-analyst SOC, 24/7 coverage, one month of data.

```text
Inputs (assumed, not measured here):
  Alerts created ................. 8 400       Closed ................. 8 350
  Closed as true positive ........   310       Closed as false positive 8 040
  Escalated to tier 2 ............   290       Confirmed by tier 2 ...   180
  Reopened .......................    24
  Incidents reported by users ....     7       of which SOC had alerted on 2

Derived:
  Fidelity ....................... 310 / 8 350           = 3.7 %
  Escalation precision .......... 180 / 290             = 62 %
  Reopening rate ................  24 / 8 350           = 0.29 %
  Missed detections ............. (7-2) / 7             = 71 % arrived without our alert

Honest reading:
  - 3.7 % fidelity is not an analyst problem: it says most production rules do not
    match this environment's normal behaviour. That is a tuning and design backlog.
  - 62 % escalation precision is acceptable; pushing it higher by escalating less
    would raise the risk that the 71 % missed figure gets worse.
  - 71 % of incidents arriving without an alert is the headline metric. The rule
    count and the ATT&CK heat map both look fine and are both misleading.
```

The point of the exercise: three numbers from one dataset tell three different stories, and only the third one is about whether the SOC would actually notice an intrusion. A report containing only "8 400 alerts handled" reads like success and says nothing.

## 9. Using Metrics Without Breaking the Team

- **Publish definitions with every number.** One line each: what starts the clock, what stops it, what is excluded.
- **Show the trend and the distribution, not a single value.** A mean plus p95, and this month against last, is the minimum honest presentation.
- **Attribute metrics to rules and to the system, not to people.** "Rule X produces a third of the queue" is actionable; "analyst Y closed fewest alerts" is not.
- **Let the analysts see the data first.** Metrics that appear only in management decks are resented and, worse, unverified — the people who know what the numbers mean should be the first to check them.
- **Fix the metric when it changes behaviour badly.** If a new measure makes analysts avoid a class of alerts, the measure is wrong, even if it is technically accurate.

## Common Mistakes & Tips

- **Mistake:** quoting MTTR without saying whether it is respond or resolve. *Tip:* publish the definition next to the value; a metric that means two things means nothing.
- **Mistake:** computing MTTD from alert creation to alert creation. *Tip:* honest detection latency needs the post-incident timeline; otherwise report coverage and dwell time instead.
- **Mistake:** reporting means with no percentile. *Tip:* publish p95 as well — the tail is where the missed alerts are.
- **Mistake:** letting backfilled alerts into the latency numbers. *Tip:* exclude or annotate after an agent outage, or the month's figures become fiction.
- **Mistake:** turning closure counts into a per-person target. *Tip:* target the system (tuning, staffing, tooling); the moment speed is scored, quality falls.
- **Mistake:** measuring success by alerts handled. *Tip:* the metric that decides whether the SOC works is how many incidents arrived *without* an alert — measure it, even though it is uncomfortable.
- **Mistake:** building a dashboard on guessed field names. *Tip:* confirm every field against one real alert document first; a dashboard full of zeros looks like a quiet month.

## Checklist / Self-Test

- [ ] I can define MTTD, MTTA, MTTC, and MTTR with an explicit start and stop event for each.
- [ ] I can explain why MTTR is ambiguous and state which definition my SOC uses.
- [ ] I can compute alert demand in analyst-hours from volume and handling time.
- [ ] I can explain why a rising backlog is unbounded when the arrival rate exceeds the clearing rate.
- [ ] I can compute fidelity, escalation precision, and reopening rate for a period.
- [ ] I can name the metric that best predicts missed incidents in my environment, and where its data lives.
- [ ] I know which fields my platform records for acknowledge and closure, and I have verified them on a real alert.
- [ ] I can explain why per-analyst leaderboards damage triage quality.
- [ ] I can present the same month's numbers to the team, to management, and to leadership without misleading any of them.

## Further Resources

- NIST SP 800-61r3 — *Incident Response Recommendations and Considerations for Cybersecurity Risk Management* (response lifecycle framing, April 2025): https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-92 — *Guide to Computer Security Log Management* (retention, source validation): https://csrc.nist.gov/pubs/sp/800/92/final
- MITRE ATT&CK Navigator — technique coverage tracking: https://mitre-attack.github.io/attack-navigator/
- MITRE ATT&CK — data sources and detections, for coverage metrics with evidence behind them: https://attack.mitre.org
- Elastic Security — detection alert management and rule monitoring: https://www.elastic.co/guide/en/security/current/index.html
- Wazuh — alert reporting and dashboards: https://documentation.wazuh.com/current/user-manual/manager/alert-management.html
- FIRST — CVSS for the severity inputs that feed prioritisation decisions: https://www.first.org/cvss/
