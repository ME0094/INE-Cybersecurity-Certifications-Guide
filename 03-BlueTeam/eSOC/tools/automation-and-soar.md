# Automation and SOAR — What to Automate and What Must Stay Human

> eSOC · Tools — INE-Cybersecurity-Certifications-Guide
>
> Automation is the only lever a SOC has that scales without hiring, and it is also the fastest way to turn one bad detection into a hundred wrong actions. This file covers what deserves to be automated and what must stay with a human, how a playbook is structured so it survives an incident, enrichment as the highest-value lowest-risk automation, the platforms that implement this (TheHive and Cortex, Shuffle, and the commercial SOARs), and the failure modes that make an automated SOC worse than a manual one.
>
> **Nothing here was executed, and no product was queried while writing this note.** Product capabilities are described at the level that is stable across versions; interface names, app availability and API shapes differ between releases and between deployments. Verify them against the version you run before you build on them.

## 1. What SOAR Is, and What It Is Not

SOAR — Security Orchestration, Automation and Response — is the layer that connects tools to each other and runs a defined sequence of steps when something happens. `siem-tools.md` places it in the stack; this file is about using it without creating new problems.

| SOAR is | SOAR is not |
|---|---|
| A way to run the same reliable steps at 03:00 as at 11:00 | A substitute for a decision nobody has made yet |
| Glue between systems that already work: SIEM, EDR, identity, ticketing, threat intel | A detection engine, a SIEM, or a case-management tool (see `case-management.md`) |
| A place to encode a playbook that a human already follows successfully | A way to skip the playbook-writing step because the tool has a canvas |
| An auditable record of what was done automatically, and when | A licence to act without authority because it was "the automation" |
| A reducer of repetitive toil — enrichment, ticketing, notification | A reducer of analyst judgement — verdicts, escalation, communication |

The distinction that matters most for a tier-1 analyst: **automation executes decisions that someone already made well.** If the decision is not yet good, automation industrialises the mistake at machine speed.

## 2. The Automation Test: Does This Decision Have a Rule?

Before automating anything, answer these six questions. A single "no" does not forbid automation; it tells you which guardrail the automation needs.

| Question | Why it decides the design |
|---|---|
| **Is the outcome deterministic?** Given the same inputs, is there one correct action? | Judgement calls cannot be automated, only assisted |
| **Is the input reliable?** Does the alert you are triggering on have known, populated fields? | Automating on a field that is sometimes empty produces random behaviour, not automation |
| **Is the action reversible?** | Reversible actions can be automated earlier; irreversible ones need a human gate every time |
| **Is the decision's quality measured?** Do you know the detection's fidelity? | Automating a rule with unknown fidelity multiplies its error rate by its volume |
| **Is the failure mode acceptable?** What happens when it fires wrongly? | An extra ticket is cheap; isolating a domain controller is not |
| **Is the toil worth removing?** How many analyst minutes per week does it save? | Automation has an upkeep cost that recurs forever |

Worked through on the tasks a tier-1 analyst actually repeats:

| Task | Automate? | Why |
|---|---|---|
| Enrich an alert with reputation, asset owner and historical sightings | Yes, first | Deterministic, read-only, and it saves time on every alert |
| Create a case and populate it with the alert's observables | Yes | Mechanical, and it improves the record rather than the decision |
| Notify the on-call analyst for a critical alert | Yes | Deterministic routing, with an escalation path if nobody acknowledges |
| Collect the standard evidence package for a triaged alert | Yes, if it is read-only and pre-authorised | Repetitive and easy to get wrong at 04:00 — but the collection must not modify the host |
| Compute and post the alert's context (baseline deviation, first-seen) | Yes | It is arithmetic, and arithmetic does not get tired |
| Block an indicator that a feed marked malicious | Only with a gate | Feeds produce false positives; a blanket auto-block is an outage generator |
| Isolate a host | Only after the decision is mature, narrowly scoped, with approval | The action is disruptive and its correctness depends on context the automation does not have |
| Disable an account | Same as isolation | Blast radius on business processes; usually an identity-owner decision |
| Close an alert as a false positive | No — never on a verdict | Auto-closing destroys the tuning signal and the audit trail (`05-use-cases-and-tuning.md`) |
| Decide whether an incident is an incident | No | Escalation is a judgement with legal and business consequences |
| Write the case summary and the handover | Assist, never auto-publish | The narrative is where the next analyst's understanding lives |

## 3. What Must Stay Human

Four categories, and they are stable across every SOC maturity level.

1. **Verdicts.** Benign, suspicious or malicious is an assessment of evidence. An automated classifier can *propose* a label with a confidence; only a person is accountable for it.
2. **Escalation and containment decisions with blast radius.** Whether to isolate a host, disable an account, or block a destination depends on asset criticality, business context and the incident's shape — context a playbook has, at best, partially.
3. **Anything irreversible.** Wiping, reimaging, deleting mailbox content, revoking access en masse, or running a "clean" action on a live host. `04-response.md` marks which tier-1 actions destroy evidence.
4. **Communication.** Telling a user their account was compromised, notifying management, talking to a customer or a regulator. Automation can *prepare* the message; a human sends it.

The practical pattern is the **approval gate**: the automation does the work up to the point of action, presents the proposed action with its inputs and its expected consequence, and waits for a named human to approve. The gate is not bureaucracy — it is the mechanism that keeps the speed of automation without transferring accountability to a script.

## 4. The Playbook, Part by Part

`04-response.md` describes the five parts a playbook must have for a human to read it under pressure: **trigger, pre-checks, actions, verification, rollback and handoff**. Automation needs those five plus the parts a machine requires in order to run unattended and to be debugged afterwards.

| Part | What it contains | The automation-specific question |
|---|---|---|
| **Trigger** | The alert, condition or schedule that starts it, with severity | Is the trigger's data reliable enough to act on? |
| **Pre-checks** | Authorisation, asset criticality, whether the action is reversible | Can the automation *evaluate* these, or must it stop and ask? |
| **Inputs** | Exactly which fields each step consumes | What happens when a field is missing — skip, halt, or ask? |
| **Actions** | Numbered steps, with the system and the account used for each | Is each step idempotent — safe to run twice on the same alert? |
| **Authority** | Who or what approves each action, and which require a human gate | Which credential does it use, and what is that credential allowed to do? |
| **Verification** | How the result is confirmed to have taken effect | Does the automation verify, or does it assume success? Silent failures are the norm, not the exception |
| **Error handling** | What happens on timeout, rate limit, API change or partial success | Does the playbook fail loudly into the case, or quietly into a log nobody reads? |
| **Rollback / handoff** | How to undo, and what the human receives | Is the undone action recorded as a false action in the metrics? |
| **Metadata** | Owner, version, last tested date, expected duration | A playbook without an owner is already broken; you just have not noticed yet |

Playbook A and Playbook B in `04-response.md` (isolate an endpoint, disable an account) are written for a human. Read them once from the automation's perspective and you will see which steps a machine can do — collect context, open the case, notify — and which steps need the gate: the isolation and the disable.

## 5. Automated Enrichment: The Best Return for the Least Risk

If a SOC automates one thing, this is it. Enrichment is read-only, runs on every alert, and its output is what makes triage fast.

What to enrich, in the order it earns its place:

1. **Reputation and ownership** of addresses, domains, hashes and URLs — the lookups an analyst performs dozens of times a shift (`enrichment-and-ti-tools.md` covers each service and what it can and cannot prove).
2. **Asset context** — what the host is, its criticality tier, its owner. This is what turns "an endpoint alerted" into "a finance file server alerted".
3. **User and identity context** — human or service account, department, privileged or not, and whether it has triggered anything in the last 90 days.
4. **Historical sighting** — has this indicator appeared in a case before? A third sighting is materially different from a first.

Four rules keep automated enrichment from producing confident nonsense:

- **Enrich only what could change the verdict.** Each lookup costs time, quota and sometimes money; an enrichment that never changes a decision is decoration.
- **Cache and deduplicate.** The same address appears on fifty alerts; look it up once per window and record when it was looked up.
- **Never send internal data to a public service.** An internal hostname, an unhashed internal path or a document submits your incident to whoever is watching that service — `../methodology/06-threat-intel-and-enrichment.md` covers the handling rule and the distribution levels that go with it.
- **Fail open, and say so.** If a lookup times out, the alert must still reach an analyst, with the gap recorded on the case. An enrichment failure that blocks triage converts a nice-to-have into an outage.

## 6. Platforms: TheHive and Cortex, Shuffle, and the Commercial SOARs

The categories matter more than the products, because the same architecture appears in all of them: a **trigger**, a set of **integrations**, a **workflow**, and a **record** of what happened.

| Approach | What it is | Where it fits |
|---|---|---|
| **TheHive + Cortex** | Case management plus an analysis-and-response engine. Cortex **analyzers** enrich an observable; Cortex **responders** act on it; results land back on the case as reports with a taxonomy level and confidence | The most common open-source pairing, and the one to learn if you want to see the analysis/action split in the open. `case-management.md` covers the object model it enforces |
| **Shuffle** | An open-source, self-hosted automation platform: you build a workflow by connecting an app to a trigger and chaining steps, calling the APIs of the tools you already run | Chaining systems that have APIs but no shared automation layer. Self-hosting keeps credentials and alert data inside your infrastructure; check that the app you need exists in the version you deploy |
| **Commercial SOAR platforms** (for example Splunk SOAR, Palo Alto XSOAR) | Integrated playbook engines with large integration libraries, case management and reporting | Environments already standardised on the surrounding stack. The architecture is the same; the licence cost and the integration library differ |
| **No SOAR at all** | A scheduled script, a webhook, and the case tool's API | A legitimate first step, and often the honest one: automating two steps well beats deploying a platform nobody maintains |

Two divisions of labour are worth internalising because they are the safety design, not a limitation. In Cortex, **an analyzer reads and a responder writes**: running eight analyzers on every observable costs quota and delays the queue, while a responder acts on production and therefore belongs behind an approval and a playbook, never in an analyst's improvisation at 03:00. In general, keep the identity that *analyses* separate from the identity that *acts*, with the narrowest permissions each one needs — a SOAR running as a domain administrator has turned every playbook bug into a potential incident.

## 7. Guardrails

These are the controls that make automation defensible in a review after something goes wrong.

- **Least privilege per integration.** A scoped API key per tool, with the minimum rights, rotated on a schedule, and stored where the playbook cannot leak it into a case comment.
- **Allow-lists for actions.** The set of things automation may do is written down. Anything outside it stops and asks.
- **Dry-run mode.** Every new playbook runs in a mode that logs what it *would* do.
- **Blast-radius limits.** Hard caps in the playbook itself: never isolate more than N hosts per hour, never touch a domain controller or a hypervisor host automatically, never disable an account whose owner is in the break-glass group.
- **Idempotency.** The same alert delivered twice must not produce two isolations or two tickets. Key the action on the alert or case id.
- **Audit everything into the case.** Every automated action, its inputs, its result and its failure lands on the record — otherwise the next analyst cannot reconstruct what happened before they arrived.
- **A kill switch.** One documented way to stop all automation, known to everyone on shift, tested at least once.
- **Change control.** Playbooks live in version control, get peer review, and carry a last-tested date. A playbook edited in production during an incident is a new, untested playbook.

## 8. Metrics for Automation

Automation is a cost with a benefit, so measure both — and be careful, because the easy numbers lie (`07-soc-metrics.md` on Goodhart's law applies directly here).

| Metric | What it tells you | The trap |
|---|---|---|
| Minutes saved per alert × alerts | Whether the thing pays for itself | Saved minutes that produce no better decisions are just a quieter queue |
| Coverage: share of alerts that trigger an automated step | How much of the workload is still manual | High coverage of a bad process is still a bad process |
| **Reverted actions** | The quality of what the automation did | The single most important number here; every reversal is a false action |
| Human-intervention rate per playbook | Whether the gate is doing real work or rubber-stamping | A gate that is always approved is either unnecessary or ignored |
| Playbook failure rate, and how long failures go unnoticed | Whether the automation is still running at all | A playbook that quietly dies looks exactly like a quiet shift |
| Upkeep cost per playbook (hours per quarter) | Whether the portfolio is sustainable | Ten playbooks nobody maintains are worse than two that work |
| Time to acknowledge / time to contain | The outcome the automation exists to improve | Improves fastest by closing alerts faster, which is not the same thing |

## 9. Failure Modes: When Automation Makes Things Worse

Each of these has been paid for by a real SOC. The countermeasure is the second column.

| Failure | What it looks like | Countermeasure |
|---|---|---|
| **Automating an immature decision** | A rule with unmeasured fidelity invokes an automated action, and the environment is acted on at the rule's error rate | Automate the action only after the decision has a measured fidelity and a documented exclusion process (`05-use-cases-and-tuning.md`) |
| **Playbooks nobody maintains** | An API changed, a token expired, a field was renamed — and the playbook has been failing silently for weeks | An owner, a version, a last-tested date, and alerting *on the automation's own failures* |
| **The gate that is always approved** | Every proposed action is rubber-stamped because the queue is long | Either narrow the action so it does not need a gate, or make the gate meaningful — but do not keep a theatre of review |
| **Auto-closing to clean the queue** | Alerts disappear without a verdict; closure speed improves and the tuning signal is destroyed | Verdicts and closure reasons stay human; automate *preparation*, never the verdict |
| **Batch false containment** | One noisy rule, one playbook, twenty hosts isolated in ten minutes | Fidelity gate, blast-radius caps, and a rate limit on actions per window |
| **Enrichment storms** | Quota exhausted by noon; the tools you depend on start rate-limiting you | Cache, deduplicate, and enrich only what could change a verdict |
| **Fragile assumptions** | A regex over a message format, a scraped web console, a hard-coded field name | Prefer documented APIs; treat anything that parses a human-readable format as a thing that will break |
| **Automating around a detection problem** | Playbooks that triage noise instead of fixing the rule that generates it | Auto-triage of noise is a symptom; the fix belongs upstream in the rule, and the automation belongs to the *good* rules |
| **The learning loop disappears** | Analysts stop seeing the alerts and therefore stop noticing the pattern | Keep a sample of automated alerts visible and review them; the analyst's judgement is the asset automation is supposed to protect |
| **Accountability drift** | "The automation did it" becomes an answer in a post-incident review | Every automated action names the playbook, its owner, and the human who approved the design |

## 10. A Maturity Path: Read-Only First

Automation is a ladder, and each rung has a precondition. Skipping rungs is how SOCs end up with an automated incident.

| Rung | What you automate | Precondition to climb |
|---|---|---|
| 1. **Read** | Enrichment, context assembly, case creation from alerts | The alert's fields are reliable and the enrichment cannot act |
| 2. **Notify** | Ticketing, paging, routing by severity, recording to the case | Notification paths are tested, and unacknowledged criticals escalate |
| 3. **Recommend** | The automation proposes a verdict or an action with its evidence and waits | Detection fidelity is measured, and the proposed action is reviewable in seconds |
| 4. **Act narrowly** | Reversible, narrow, high-confidence actions execute automatically, with caps and a kill switch | Reverted-action rate is measured and near zero, and the blast radius is provably bounded |
| 5. **Orchestrate** | Multi-step response with human gates at the irreversible points, and the whole path audited into the case | Everything above, plus playbook ownership, review, and an exercised rollback |

Most SOCs get real value from rungs 1 and 2 and a careful part of rung 3. Rungs 4 and 5 are earned with measured fidelity, not with enthusiasm.

## Common Mistakes & Tips

- **Mistake:** automating the first process you can, because the tool makes it easy. *Tip:* automate the highest-volume *deterministic* task — usually enrichment — and leave the judgement calls alone.
- **Mistake:** treating the SOAR platform as the project. *Tip:* the deliverable is a written playbook with an owner; the platform is only where it runs.
- **Mistake:** measuring automation by the alerts it processed. *Tip:* measure reverted actions and playbook failures — the numbers that reveal what it got wrong.
- **Mistake:** building the playbook around one incident's specifics. *Tip:* write it around the *class* of incident, and handle the exceptions with a human gate rather than with more branches.
- **Mistake:** giving the automation a powerful service account "so it can do everything". *Tip:* one scoped identity per integration, with the minimum rights each step needs.
- **Mistake:** letting a failed playbook stay silent. *Tip:* failure must land on the case and in a channel someone watches; silent success and silent failure look identical from the queue.
- **Mistake:** automating a decision the team has not agreed on. *Tip:* if two analysts would act differently on the same alert, the playbook will encode one of them arbitrarily — settle the decision first, in the playbook, in writing.
- **Mistake:** assuming the automation removed the need to look. *Tip:* stay able to do the task by hand; the shift where the automation is down is the shift you need the skill.

## Checklist / Self-Test

- [ ] I can explain the difference between SOAR, a SIEM, and a case-management tool.
- [ ] I can apply the six-question automation test to a task and justify the answer.
- [ ] I can name four categories of work that must stay human, and why.
- [ ] I can describe a playbook's trigger, pre-checks, inputs, actions, authority, verification, error handling, rollback and handoff.
- [ ] I know which steps of a containment playbook need an approval gate in my environment.
- [ ] I can list what is worth enriching automatically, and what I would not send to a public service.
- [ ] I can name the analyzers/responders split (or its equivalent) in the platform I use, and who may run a responder.
- [ ] I can name three guardrails — least privilege, idempotency, blast-radius cap, kill switch, version control — and where each applies.
- [ ] I can state the reverted-action rate and the playbook failure rate for the automation I operate.
- [ ] I can explain why auto-closing alerts as false positives is not automation but data loss.

## Further Resources

- TheHive Project — case management documentation: https://docs.strangebee.com/
- Cortex — analyzers and responders documentation: https://docs.strangebee.com/cortex/
- Shuffle — open-source automation platform documentation: https://shuffler.io/docs
- Splunk SOAR — playbook and automation concepts: https://docs.splunk.com/Documentation/SOAR
- Palo Alto Networks Cortex XSOAR — playbook development concepts: https://docs-cortex.paloaltonetworks.com/
- MITRE ATT&CK — the technique vocabulary playbooks are scoped against: https://attack.mitre.org/
- NIST SP 800-61r3 — incident handling lifecycle, including the documentation expectations automation must feed: https://csrc.nist.gov/pubs/sp/800/61/r3/final
