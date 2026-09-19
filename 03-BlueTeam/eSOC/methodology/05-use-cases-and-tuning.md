# eSOC Methodology — Phase 5: Use Cases and Tuning

> Tier-1 SOC Analyst focus · INE-Cybersecurity-Certifications-Guide
>
> A use case is the unit of work a SOC sells: one behaviour, written down, mapped to data, alerted on, triaged, tuned, and eventually retired. This phase covers the lifecycle of a rule, how to measure whether it is worth keeping, how the tuning backlog is worked instead of complained about, and how suppression can remove noise without removing the detection. It assumes you have read `02-detection.md`; where that file covers *authoring* and the noise-reduction techniques, this one covers *keeping rules alive*.

## 1. What a Use Case Is, and What It Is Not

A use case is not a rule. It is a small product with a behaviour, an owner, and a measured outcome. The rule is only its implementation.

| Part | The question it answers | Example |
|---|---|---|
| Behaviour | What adversary or misuse behaviour is being detected? | A macro survives the "enable content" prompt and spawns a script host |
| Rationale | Why does this matter in *this* environment? | Office documents arrive by mail; the population is targeted by commodity phishing |
| Data | Which source and fields carry the behaviour? | Process creation with command line; `ParentImage`, `Image`, `CommandLine`, `User` |
| Logic | What condition separates it from ordinary activity? | Office parents × script-host or download-utility children |
| Alert | What does the analyst receive, and how urgent is it? | High severity, one alert per host per 15 minutes, with the process tree attached |
| Playbook | What does the analyst do with it? | Verify parent, decode payload if encoded, check the document's origin, scope the host |
| Metric | How do we know it is healthy? | Alerts/week, false-positive rate, share of the queue, time to acknowledge |
| Owner | Who is accountable for it? | Named detection engineer, with the SOC as the consumer |
| Review date | When is it re-examined? | Quarterly, plus any time the data source changes |

Anything missing from that table is a gap that will surface later. A rule without an owner rots; a rule without metrics is judged by feelings; a rule without a playbook trains analysts to close alerts they do not understand.

> The most common structural failure is a use case with no *rationale*. "This is a known ATT&CK technique" is not a reason to alert on it in your environment — every technique is known. The reason is that *your* assets, users, or data make this behaviour worth an analyst's attention. If you cannot state it in one sentence, the rule belongs on a watchlist of detection ideas, not in the alert queue.

## 2. The Rule Lifecycle End to End

Rules move through states, and each transition has an owner and a criterion. Writing the states down is what turns a pile of YAML into a managed capability.

| State | Meaning | Enters when | Leaves when | Decided by |
|---|---|---|---|---|
| **Proposed** | An idea with a hypothesis and a candidate data source | Threat intel, an incident, a hunt finding, or a coverage gap review | Data is confirmed available | Detection engineer |
| **In development** | Being written and tested | Data mapping done | Positive test passes | Author |
| **Testing** | Running in the platform but not in the queue (or alerting to a test channel) | Rule validates syntactically | A known false-positive rate exists after a quiet period | Author + SOC lead |
| **Production** | In the analyst queue with an owner, severity, and playbook | Negative validation done and volume accepted | Noise exceeds value, or the technique is retired | SOC lead |
| **Tuning** | In production but flagged for change | FP rate above target, or queue share too high | The change is validated and deployed | Detection engineer |
| **Deprecated** | Kept in the repo, not deployed | Superseded by a better rule or an unused technique | — | Detection engineer |
| **Retired** | Removed from the platform, with the reason recorded | Never fires, never confirms, or the source was decommissioned | — | SOC lead |

Three properties of this table matter operationally:

- **"Testing" is not optional.** A rule that goes from development straight into a production queue transfers its unknown error rate directly onto whoever is on shift. Even a week in a test channel produces a number.
- **Retirement is a success, not a confession.** A retired rule with a recorded reason ("technique no longer exposed: the legacy protocol was decommissioned") is a coverage decision. A rule that quietly stays deployed and ignored is a permanent source of noise and a false sense of coverage.
- **Every state change is a diff.** Rules belong in version control (Sigma in a repository, or the platform's own rule objects with change history). The question "why does this rule look like this?" must have an answer that is not archaeology.

## 3. Anatomy of a Use Case Document

The template below is what an analyst should be able to find for any alert in the queue. Adapt the field names to your platform; keep the fields, because each one is consumed by somebody.

```text
USE CASE — <short behaviour name>                       ID: UC-<nnn>   State: production
----------------------------------------------------------------------------------------
BEHAVIOUR      One sentence, plain language, no tool names.
RATIONALE      Why it matters here: which assets/users/data, which threat pattern.
ATT&CK         Tactics and technique IDs (attack.t1059.001 style).
DATA           Source(s) + required fields + minimum collection config to work at all.
LOGIC          Linked rule file(s) + backend rule ID(s) + any correlated threshold.
FALSE POSITIVES Known-good causes seen so far, each with the date it was confirmed.
EXCLUSIONS     Each exclusion, its scope, who approved it, and its re-review date.
PLAYBOOK       1) What the analyst checks first  2) What benign looks like
               3) When to escalate  4) What to contain, if anything.
SEVERITY       Level + why (impact x confidence), and whether it pages anyone.
EXPECTED VOLUME Alerts/week observed, and the share of the queue it represents.
OWNER          Named person + team.  REVIEW DATE: <yyyy-mm-dd>
CHANGELOG      Dated entries: what changed, why, and the measured effect afterwards.
```

The two fields teams skip are `FALSE POSITIVES` and `CHANGELOG`. They are also the two that make the difference between a rule that improves and a rule that becomes background noise: the first is the input to tuning, and the second is the proof that tuning happened.

## 4. Measuring a Rule Before You Tune It

Tuning without numbers is guessing. Four figures are enough to make a defensible decision, and all four are countable in any platform.

| Metric | Definition | What a bad value tells you |
|---|---|---|
| **Alert volume** | Alerts per week from this rule | Above your triage capacity, the rule is hiding other detections |
| **Fidelity (true-positive rate)** | Confirmed TP ÷ (confirmed TP + confirmed FP), over a defined period | Low fidelity means the logic does not match how the environment actually behaves |
| **Queue share** | Alerts from this rule ÷ all alerts, over the same period | One rule above roughly a third of the queue is a structural problem, not a nuisance |
| **Time to triage** | Median analyst minutes per alert from this rule | High cost with low value is the strongest case for retirement — even a rare rule can be unaffordable |

Compute them from what the queue already records, and write the numbers into the use case document with the date. Two cautions:

- **Fidelity depends on honest closure categories.** If everyone closes alerts as "false positive" by default, the number is fiction. The closure reason is data; treat it as an obligation.
- **Low volume is not automatically good.** A rule that fires twice a year and confirms both times may be excellent. A rule that fires twice a year because it is broken is not — distinguish the two by validating the data source, as `01-monitoring.md` describes.

```text
Worked reading (paper example, no live data):
  Rule A: 900 alerts/week, 45 confirmed TP    -> fidelity ~5%, high volume  -> tune or split
  Rule B:  12 alerts/week, 10 confirmed TP    -> fidelity ~83%, useful       -> keep, maybe widen
  Rule C:   3 alerts/week,  0 confirmed ever  -> either quiet or broken      -> validate data, then retire
```

## 5. The Tuning Backlog as a Process

Tuning fails as a heroic activity and works as a queue. Treat it exactly like the alert queue: it has an owner, a cadence, priorities, and an exit condition.

| Item type | Typical source | Reasonable priority | Exit condition |
|---|---|---|---|
| Detection that misses a confirmed incident | Post-incident review | Highest — a proven gap | New rule validated against the real activity |
| Rule producing more than a third of the queue | Queue metrics | High | Volume reduced with the positive case still firing |
| Rule with unknown fidelity after a quarter in production | Use case document | High — it is an unmeasured risk | Number recorded, decision made |
| Exclusion requested by an analyst | Triage notes | Medium | Exclusion documented with scope and re-review date |
| Parser or field-name defect | Triage notes ("the field was empty") | Medium — it silently disables rules | Pipeline fixed, affected rules re-tested |
| YARA or rule set refresh from upstream | Community repository update | Low, on a schedule | Reviewed, tested locally, then adopted selectively |
| Cosmetic rename, tag cleanup, level adjustment | Housekeeping | Low | Done in a batch, in version control |

**Regression testing is part of every change.** Before a tuned rule goes back into production, re-run the original positive case and confirm it still fires. This is the single most-skipped step in tuning, and skipping it converts a noisy detection into a silent one that everyone believes is working.

Keep a copy of the artefacts you test with: the generated event, the sample file for a YARA rule, the query you used. A regression suite of five lab-generated cases is worth more than a page of good intentions.

## 6. Suppression Discipline: The Process Half

`02-detection.md` covers *what* each noise-reduction technique costs. This section covers the process that keeps the cost visible.

1. **Nothing is suppressed without a written reason and a date.** The minimum viable record is a rule comment: `# excluded 2025-06-01 by A.Tier1 — signed inventory agent, confirmed with asset owner; re-review 2025-09-01`.
2. **Suppressions expire by default.** A suppression with no re-review date is a permanent decision made in a hurry. Put the date in the rule, the use case document, and the tuning backlog.
3. **Suppress the narrowest thing that removes the noise.** Identity (a signed binary path, a service account, an asset group) beats location; location beats "this rule, everywhere".
4. **A suppression is announced.** If a rule stops alerting in a situation where someone expects it to, say so in the shift handover. Silent suppressions are why analysts lose trust in the queue.
5. **Every suppression is a signal about something upstream.** Recurring exclusions on the same host usually mean an untagged asset or an unmanaged application; the fix belongs there, not in the rule.

## 7. Tuning Worksheet

Fill this in before changing a rule; it takes ten minutes and prevents most rework.

```text
TUNING WORKSHEET — rule: <name>   date: <yyyy-mm-dd>   analyst: <name>
--------------------------------------------------------------------------------
1. NUMBERS
   Alerts (window): ______   Window length: ______   Queue share: ______ %
   Confirmed TP: ______   Confirmed FP: ______   Fidelity: ______ %
   Median triage minutes: ______

2. FALSE-POSITIVE CLASSES (from 02-detection.md - classify, do not guess)
   [ ] parser artifact          [ ] legitimate admin tooling
   [ ] business process         [ ] threshold too tight
   [ ] missing context          [ ] environmental change
   [ ] rule logic gap

3. ROOT CAUSE
   The noise exists because: ____________________________________________
   Upstream fix available? [ ] yes -> what: ______________  [ ] no

4. PROPOSED CHANGE (narrowest first)
   [ ] fix the pipeline           [ ] add exclusion (scope: ______)
   [ ] widen threshold            [ ] add context field
   [ ] split the rule             [ ] retire the rule
   Exact diff: _________________________________________________________

5. REGRESSION TEST
   Positive case re-run? [ ] yes -> still fires? [ ] yes  [ ] no (stop, fix)
   Negative case re-run? [ ] yes -> volume now: ______ per week

6. RECORD
   Use case doc updated? [ ] yes    Changelog entry added? [ ] yes
   Re-review date set: ____________  Approved by: ____________
```

## 8. The Quarterly Rule Review, in Thirty Minutes

A review that takes an hour per rule will not happen. A review that follows five questions will.

1. **What did each production rule produce last quarter?** Volume and fidelity, straight from the queue export. No numbers means the rule is unmanaged — that itself is the finding.
2. **What is the worst rule in the list?** Rank by (alerts × analyst minutes) ÷ confirmed true positives. That rule gets a decision today: tune, split, or retire.
3. **Which rules are in the queue with no playbook entry?** Those alerts are being closed by improvisation. Write the one paragraph now or take the rule out.
4. **Which ATT&CK techniques did we gain or lose?** Coverage changes silently when a data source is decommissioned. Compare the technique list to last quarter's.
5. **What did the environment change that the rules do not know about?** New systems, new tooling, a re-IP'd subnet, an acquired business unit — each is a source of both blind spots and noise.

Record the outcome as decisions, not discussion: keep, change (with the diff), retire (with the reason). Then update the use case documents the same week, while the reasoning is still available.

## 9. Worked Example: Three Weeks of Closures, One Rule Change

A pattern every analyst has met. A rule for "suspicious command-line utilities" produces about 40 alerts a week. Each closure note says some version of "false positive, IT tool".

**Week 1.** An analyst closes twelve alerts with "FP". Nothing changes. This is the default behaviour of an untuned rule set and it is not the analyst's fault: their job is the queue, and the queue never asks why.

**Week 2.** Someone reads the closure notes. The class is obvious — legitimate administrative tooling — and the affected hosts are all in the same asset group. The tempting fix is to raise the threshold from one occurrence to five, which would also stop the abuse case the rule exists for.

**Week 3.** The correct change is narrow and evidence-based: an exclusion for the IT tool's *signed binary path* and the asset group it runs in, with a dated comment, plus a widened positive test. The rule's fidelity goes up without losing the behaviour; the queue drops by the same margin. Two follow-ups are recorded rather than forgotten: the tool is still untagged in the asset inventory (the reason the rule could not filter on context), and the closure notes now include a class so the next review takes minutes instead of hours.

The measurable output of this story is not "we reduced noise". It is: a documented exclusion with an expiry, a context gap recorded for the asset owners, and a rule that still fires on the thing it was built for.

## Common Mistakes & Tips

- **Mistake:** treating tuning as a personal favour done when someone complains. *Tip:* put it in a backlog with an owner and a cadence; unowned tuning does not happen.
- **Mistake:** raising a threshold to silence noise. *Tip:* thresholds trade detection for quiet — use them only when the low-and-slow variant of the technique is not the case you care about.
- **Mistake:** measuring a rule by how it feels. *Tip:* volume, fidelity, queue share, and triage minutes are countable in any platform; write the numbers down with the date.
- **Mistake:** shipping a tuned rule without re-running the positive case. *Tip:* regression testing is not optional — an over-tuned rule is a silent gap that everyone believes is coverage.
- **Mistake:** keeping a rule because "we might need it". *Tip:* an unused rule costs attention every review and creates false confidence in coverage reports; retire it with a reason and a date.
- **Mistake:** writing rules nobody can triage. *Tip:* no rule enters the queue without a playbook paragraph. An alert without a "what to check first" is an invitation to close it wrongly.

## Checklist / Self-Test

- [ ] I can list the seven parts of a use case and point at each one for a real rule in my environment.
- [ ] I can name the lifecycle states of a rule and the criterion for each transition.
- [ ] I can compute volume, fidelity, queue share, and triage minutes for a rule from the queue data.
- [ ] I have classified at least one false positive by cause and applied the correct fix layer.
- [ ] I can state why a threshold change is a detection trade-off rather than a free fix.
- [ ] Every exclusion I have seen carries a reason, a scope, and a re-review date.
- [ ] I have re-run a positive test case after a rule change and confirmed it still fires.
- [ ] I can run a thirty-minute rule review and produce decisions rather than discussion.
- [ ] I know which rules in my environment should be retired, and I can say why.

## Further Resources

- SigmaHQ — rule repository and specification for writing portable detection content: https://github.com/SigmaHQ/sigma
- Sigma specification (rule structure and modifiers): https://github.com/SigmaHQ/sigma-specification
- MITRE ATT&CK — technique coverage as the vocabulary of a use case catalog: https://attack.mitre.org
- MITRE ATT&CK Navigator — visual coverage tracking per technique: https://mitre-attack.github.io/attack-navigator/
- NIST SP 800-92 — Guide to Computer Security Log Management (source validation and retention): https://csrc.nist.gov/pubs/sp/800/92/final
- Elastic Security — detection rule management, exceptions, and rule monitoring: https://www.elastic.co/guide/en/security/current/index.html
- Splunk — correlation search and alert tuning documentation: https://docs.splunk.com/
