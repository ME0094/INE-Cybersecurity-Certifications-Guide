# Building a Hunting Program (eCTHP Methodology — Phase 01)

> Companion study guide for the eCTHP (Certified Threat Hunting Professional) Blue Team methodology track. This phase is about turning hunting from an occasional favour into a repeatable capability: who hunts, what they hunt, how they decide, and how anyone knows whether it worked.

## Overview

Threat hunting is **proactive, hypothesis-driven investigation of your own environment for adversary activity that your existing detections did not catch**. Everything else in this module is machinery in service of that sentence.

Most teams that "hunt" are actually doing something else. Sorting alerts is triage. Watching a dashboard is monitoring. Reading an intelligence report is research. None of those is wrong, and all of them feed hunting — but none of them starts with a hypothesis about what an adversary would do in *your* environment and then goes looking for the evidence.

A program exists so the work does not depend on one curious analyst having a free afternoon. Concretely, a hunting program answers four questions in advance:

1. **Who** hunts, and what else are they responsible for?
2. **What** gets hunted, chosen deliberately rather than by mood?
3. **How** is a hunt run and recorded, so results compound?
4. **Whether** it worked, measured well enough to justify the next quarter.

## Hunting vs. monitoring vs. detection vs. response

The disciplines overlap, but the trigger, the goal, and the output differ. Confusing them is the most common reason hunting programmes stall.

| Discipline | Triggered by | Question it answers | Output |
| --- | --- | --- | --- |
| Monitoring | Continuous collection | "Is anything alerting right now?" | Eyes on a queue, dashboards, escalation |
| Detection | A known behaviour worth alerting on | "Does this known pattern appear?" | An alert, a rule, a ticket |
| Threat hunting | A hypothesis, decided by a human | "Is this behaviour happening here, even though nobody alerted?" | A verdict, evidence, new detections, closed gaps |
| Incident response | A confirmed incident | "What happened, how far did it spread, what do we do?" | Containment, eradication, recovery, lessons |
| Forensics | A legal or investigative question | "What exactly happened, provably?" | Defensible findings and evidence |

Two consequences follow:

- **Hunting is not a substitute for detection.** If you find the same behaviour by hand twice, you owe the SOC a rule the second time. Hunting is a coverage *generator*, not a service desk.
- **Hunting is not response.** The moment your hunt confirms live malicious activity, it becomes an incident and IR owns the clock. Your job is to hand over scope, evidence, and queries — not to start deleting files.

## The maturity ladder: from IOCs to TTPs

Two simple models explain what most programmes grow through. Use them to place your own team honestly.

**The Pyramid of Pain** ranks indicators by how much it costs the adversary when you can detect them. From bottom (easy for the attacker to change) to top (hard):

1. Hash values
2. IP addresses
3. Domain names
4. Network and host artifacts (registry keys, file paths, named pipes, user agents)
5. Tools (the specific utilities and malware families in use)
6. TTPs (the behaviour itself)

Detecting at the bottom is cheap and brittle; the adversary rotates a hash in seconds. Detecting behaviour at the top costs them retraining, retooling, and re-planning. Hunting at the TTP level is where durable value lives.

**A widely used hunting maturity model** (David Bianco's HMM) describes the same journey organizationally:

| Level | Name | How hunts are chosen | Where the evidence comes from |
| --- | --- | --- | --- |
| HMM0 | Initial | No hunts; the team relies entirely on automated alerting | Whatever alerts happen to fire |
| HMM1 | Minimal | Indicator-based: hunt the hashes, IPs, and domains from intelligence feeds | IOC searches across collected data |
| HMM2 | Procedural | Technique-based: hunt a specific ATT&CK procedure with a written plan | Analytics and queries built by the team |
| HMM3 | Innovative | Hypotheses come from analysis, intelligence, and red team results, and the team automates what it can | Custom analytics, correlation, and enriched data |
| HMM4 | Leading | Hunting is largely automated and continuously data-driven | Machine-assisted analytics over broad telemetry |

> The point of the ladder is not to reach level four. It is to know which level you are on, so you stop calling an IOC sweep a hunt and start investing in the telemetry and analytics your next level needs.

## Roles on a hunting team

Hunting is a team sport even when one person does the querying. These are roles, not necessarily headcount — one analyst may hold three of them.

| Role | Responsibility | Not responsible for |
| --- | --- | --- |
| Hunt lead | Owns the hunt backlog, picks targets, sets end conditions, chairs the readout | Being the fastest query writer |
| Hunter | Writes hypotheses, runs queries, triages, pivots, reaches a verdict | Deciding what to fix |
| Detection engineer | Turns confirmed findings into tested, tuned, versioned rules | Chasing the original intrusion |
| Threat intelligence analyst | Supplies actor, sector, and TTP context; receives back what was actually observed | Producing an IOC list and calling it done |
| Telemetry / platform engineer | Keeps sources flowing, healthy, and queryable; implements new collection | Interpreting hunts |
| IR liaison | Provides incident context, receives escalations, decides on containment | Hunting on a live incident |
| Purple team partner | Re-runs the technique after a detection is deployed to confirm it fires | Signing off their own work alone |

A useful rule: **a hunt without a detection engineer attached is a report nobody reads**, and a detection engineer without hunters is guessing at what to build.

## Rituals and cadence

Rhythms are what keep a programme honest. A workable starting cadence:

- **Weekly hunt standup (30 min).** Review open hunts, close anything past its end condition, pick the next target, assign the hunter.
- **Hunt intake.** Anyone — SOC, IR, threat intel, IT, red team — can propose a target. Proposals enter one backlog; the lead prioritizes.
- **Structured hunt.** Timeboxed (typically two to five analyst-days). Hypothesis and end condition written before the first query.
- **Readout.** Every hunt closes with a short session: hypothesis, data used, verdict, new detections, gaps found, recommended next target.
- **Detection handoff.** Findings that deserve automation go to the detection engineer with the emulation that reproduced them.
- **Quarterly coverage review.** Step back from individual hunts: which tactics, platforms, and data sources have you actually exercised lately? Where is the backlog biased?
- **Purple team exercise.** Once a quarter, run a technique end to end — emulate, hunt blind, deploy the detection, re-emulate, tune.

Every hunt writes to the **hunt journal** (see Phase 02). The journal is the programme's memory: without it, the team relearns the same lessons every quarter.

## Choosing a hunt target

A target is a *behaviour plus a scope*, not a topic. "Ransomware" is a topic; "credential dumping from LSASS on Windows servers in the finance segment over the last 30 days" is a target.

Score candidate targets against criteria like these — the numbers are illustrative, the discipline is not:

| Criterion | Question to ask | Weight |
| --- | --- | --- |
| Intelligence relevance | Are credible reports describing this against organisations like ours? | High |
| Detection gap | Do we have a rule for it? Has that rule ever fired in a real incident? | High |
| Impact if present | If this is happening, what does it cost us? | High |
| Telemetry readiness | Can we even see it today, with validated sources? | Medium |
| Effort and complexity | How many analyst-days, and do we have the skills? | Medium |
| Recent context | Did an incident, audit, red team, or sector alert point here? | Medium |
| Freshness | Did we hunt this recently, or is the target stale? | Low |

**Start with impact and visibility, not with what is fashionable.** A hunt for a technique on a platform whose telemetry you cannot query consumes days and ends in "unknown". Anchor on data you have already proven works, and let gaps you discover become collection requests for the next cycle.

Good early targets for a new programme usually share three traits: they use telemetry you already ingest, they map to a technique your detections do not cover, and the adversary behaviour is specific enough to be visible — for example autorun registry persistence, scheduled task creation, or unusual outbound beaconing.

## Metrics that mean something

Metrics drive behaviour, so choose ones that reward real work rather than volume.

| Metric | Definition | What it tells you | How it gets gamed |
| --- | --- | --- | --- |
| Hypotheses run | Hunts closed with a written hypothesis and verdict | Whether the programme is actually operating | Padding the journal with trivial hunts |
| Confirmed findings | Hunts that produced real malicious or misconfigured activity | Signal coming out of hunting | Counting benign-but-interesting oddities as findings |
| Refuted hypotheses | Hunts properly closed as "not present", with evidence | Scientific hygiene; also proves coverage | Avoiding hard hypotheses so everything is refuted |
| New detections deployed | Rules that came out of hunts and survived tuning | Whether hunting feeds the SOC | Shipping noisy rules nobody keeps |
| Coverage gained | Prioritized ATT&CK techniques now detectable that were not before | Progress against a deliberate target list | Counting rules instead of techniques |
| Telemetry gaps closed | Data sources added or repaired because a hunt needed them | Long-term capability growth | Declaring gaps "closed" by policy rather than by data |
| Time to detect in a hunt | How long the hunt took to surface the activity | Efficiency, and whether scope was too broad | Narrowing scope until every hunt is fast and empty |
| Repeat-hunt success | Techniques you re-hunted after deploying a rule that now alert automatically | Closure of the loop | Re-hunting only what is already covered |

Report metrics quarterly, next to a short narrative of what was found and what changed. A dashboard without a story invites arguments about definitions instead of about defence.

## Integrating with the SOC

Hunting and SOC operations are one feedback loop, running in both directions.

**From the SOC to hunting:**

- Alerts that analysts keep marking as "unusual but benign" — is the pattern a detection waiting for a better rule?
- Near-misses: the alert fired on a lesser technique while a more interesting one sat in the same data.
- Blind spots analysts complain about ("we cannot see X") — often a telemetry, not a rule, problem.
- Tuning history: which rules are noisy, which have never fired, which were retired and why.

**From hunting to the SOC:**

- **New detections**, delivered with a positive test (the emulation that triggers them) and a negative test (benign activity that must not).
- **Triage guidance** for those detections: what to look at first, what a false positive looks like, when to escalate.
- **Severity and expected volume**, so the queue is not flooded by a rule nobody sized.

Practical guardrails: keep the two backlogs distinct (hunting is not a place to hide triage), never let hunting claim response authority, and route every confirmed intrusion to IR immediately rather than completing the hunt first.

## Integrating with incident response

Hunting and IR trade assets continuously.

- **IR feeds hunting:** the initial access vector, the TTPs observed, the LOLBins used, the time window, and the hosts in scope. A recent incident is the richest hypothesis source a programme ever gets.
- **Hunting feeds IR:** a plausible hypothesis, a scope, a timeline, and queries that can be re-run on demand. When a hunt confirms live activity, the evidence package — queries, result sets, artifact hashes, timeline — is exactly what IR needs to start containment without repeating work.
- **Both feed forensics:** preserved artifacts and documented collection let an eCDFP-style examination pick up where the hunt stopped.

One rule prevents most friction: **agree on the escalation trigger in advance.** Define what converts a hunt into an incident (confirmed execution of malicious code, evidence of data access, an active C2 channel) and who declares it. Deciding this mid-hunt, at speed, is how scope gets missed.

## Common Mistakes & Tips

- **Calling alert review hunting.** If the queue drives the work, it is triage. A hunt starts from a hypothesis you wrote before opening the platform.
- **Hunting without a programme.** One-off heroics produce findings and no capability. Keep the journal, keep the backlog, keep the readout.
- **Unfalsifiable targets.** "Look for lateral movement" cannot be closed. "Do Windows admin-share logons appear from workstations that never perform them?" can.
- **Ignoring your own data health.** A hunt on a source that has silently stopped shipping logs ends in a false "not present". Validate sources first (Phase 03).
- **Hunting only what you can already see.** Comfortable hunts rarely close gaps. Deliberately pick one target per cycle whose telemetry is shaky.
- **Never converting findings into detections.** Undetected findings decay. The rule is the deliverable; the report is the packaging.
- **Measuring alerts instead of coverage.** Volume rewards noise. Coverage against a prioritized technique list rewards defence.
- **Tip:** keep a "hunt this next" note in the journal at all times — every hunt generates at least one follow-up idea.
- **Tip:** review your journal quarterly for hunts that produced neither a detection nor a gap; they usually reveal a target-selection problem, not a lazy hunter.

## Checklist / Self-Test

- [ ] Can I state the difference between monitoring, detection, hunting, response, and forensics in one sentence each?
- [ ] Can I explain the Pyramid of Pain and why TTP-level detection is more durable than hash-level detection?
- [ ] Can I place a team on the HMM ladder and justify the placement?
- [ ] Can I list the roles a hunting programme needs and what each one owns?
- [ ] Can I design a weekly and quarterly ritual cadence that a small team could actually sustain?
- [ ] Can I score three candidate hunt targets against explicit criteria and defend the ordering?
- [ ] Can I name five programme metrics and explain how each one could be gamed?
- [ ] Do I know what the SOC gives hunting, and what hunting owes the SOC in return?
- [ ] Can I define the trigger that turns a hunt into an incident, and who declares it?

## Further Resources

- **MITRE ATT&CK** (the shared vocabulary for targets and coverage) — https://attack.mitre.org/
- **MITRE Cyber Analytics Repository (CAR)** (analytic logic and coverage ideas) — https://car.mitre.org/
- **NIST SP 800-61 Rev. 2**, *Computer Security Incident Handling Guide* (handling lifecycle and coordination) — https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- **Sigma** (rule format for handing hunts to detection engineering) — https://sigmahq.io/
- **Official eCTHP product page** (authoritative syllabus and logistics) — https://ine.com/security/certifications/ecthp-certification
