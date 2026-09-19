# Hypothesis Generation (eCTHP Methodology — Phase 02)

> Companion study guide for the eCTHP (Certified Threat Hunting Professional) Blue Team methodology track. This phase is where a hunt is actually decided: where hypotheses come from, how to write one that can be proven wrong, how to prioritize between them, and how to record them so the work compounds.

## Overview

A hunt is only as good as its hypothesis. If the hypothesis is vague, the query is guesswork and the conclusion is an opinion. If it is falsifiable, you get one of two useful outcomes — *found it* or *proved it is not there* — and both change how you defend the environment.

A usable hunting hypothesis has four parts:

| Part | Question it answers | Example |
| --- | --- | --- |
| **Subject** | Who or what acts? | An external actor with valid credentials |
| **Behaviour** | What do they do, in observable terms? | Creates a scheduled task that runs an unsigned binary |
| **Data** | Where would the evidence appear? | Sysmon event 11 with `\Tasks\` in the path, TaskCache registry writes, Security event 4698 |
| **Confirmation criteria** | What exactly would confirm it, and what would refute it? | Confirm: a task created outside the change window combined with a missing signature on the target binary. Refute: all task creations map to the software deployment tool in the same minute |

Write all four before you touch a query tool. If you cannot fill in the data column, you have found a telemetry question rather than a hunt — go to Phase 03 first.

## Where hypotheses come from

Six sources cover almost everything. A healthy programme draws from all of them in rotation, because each one has a blind spot.

### 1. Threat intelligence

Reports, sector advisories, and vendor research describe what adversaries actually do. Read them for **behaviour**, not for the IOC list.

- Extract the procedure: which tool, which built-in binary, which protocol, which account type.
- Translate it into your environment: do you run that product, that identity provider, that cloud service?
- Prefer intelligence that names techniques over intelligence that only names malware families.
- Report back: intelligence teams want to know which of their reported TTPs you actually found (usually none, sometimes one, and that is the value).

### 2. MITRE ATT&CK

ATT&CK is the map that turns "hunt something" into a scoped target.

- Pick a tactic, then a technique, then a sub-technique. The narrower the sub-technique, the more visible the artefacts.
- Read the technique page's procedure examples and detection notes for the concrete observables.
- Use ATT&CK Navigator layers to visualize where your detections exist and where they do not — a **gap analysis** gives you a prioritized target list rather than a hunch. Confirm the current naming of ATT&CK's data-source and detection-strategy mappings on the site, since MITRE has restructured them across versions.
- Remember ATT&CK describes *what* is possible, not what is happening to you. The hypothesis is what tests that.

### 3. Adversary emulation

Running the technique yourself is the fastest way to learn what it looks like — and to prove whether your telemetry can see it at all.

```powershell
# Atomic Red Team: install the module, then inspect and run individual tests
Install-Module -Name invoke-atomicredteam -Scope CurrentUser
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"

Invoke-AtomicTest T1059.001 -ShowDetails        # list tests, prerequisites, and cleanup for the technique
Invoke-AtomicTest T1059.001 -GetPrereqs         # fetch what the tests need
Invoke-AtomicTest T1059.001 -TestNumbers 1      # run one test
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup   # undo it
```

Before running anything: use a disposable lab VM, snapshot it, and confirm the atomic's cleanup step works. Check the technique IDs against the current ATT&CK version, since MITRE renumbers and merges techniques between releases.

For multi-step, multi-host behaviour, MITRE Caldera gives you an adversary emulation server: from a clone of the project, the usual local start is `python3 server.py --insecure`, and you deploy an agent to your lab host from the web interface (see the project README for the flags and agent options for your version). Emulation is also the **validation** mechanism for Phase 05: you will run the same technique again after deploying the detection.

### 4. Detection gap analysis

Look at your own rules and alerts, not at the internet.

- Techniques with **no rule at all** — the first place to look.
- Techniques whose **last alert was months or years ago** — either they stopped happening or the rule quietly broke.
- Rules that **never fired** since deployment but should have; test with emulation before trusting them.
- Rules that were **retired** during triage tuning: the behaviour did not disappear, it just stopped alerting.

### 5. Incident response findings

Every incident is a hypothesis factory, and usually the highest-yield one.

- Re-hunt the initial access vector elsewhere in the estate: was that host unique, or was it just the first one noticed?
- Re-hunt each observed TTP across all retained data and all hosts, not just the ones in scope of the incident.
- Test whether the detection that caught this incident would have caught the same behaviour with a different parent process, account, or path. If not, you have a gap and a concrete tuning task.

### 6. Environment and business context

Your own change history generates hypotheses nobody else can.

- Recent mergers, new cloud tenants, new remote-access paths, new administrative tooling.
- Business peaks and quiet periods — activity outside them deserves a second look.
- Crown-jewel assets and the identity paths that reach them.
- Anomalies found while doing other work (the odd service account, the forgotten jump host).

## Writing a falsifiable hypothesis

Use one sentence, with the four parts visible. A reliable template:

> **If** *[actor or activity]* uses *[technique, in observable terms]* against *[scope: host class, account type, window]*, **then** *[data source]* will show *[specific observable pattern]*, **and the hypothesis is refuted if** *[expected evidence is absent while the data source is proven healthy]*.

Two worked examples:

```text
H-2026-014  Scheduled task persistence outside the change window
Subject:      any process running on Windows workstations
Behaviour:    creating a scheduled task that executes a binary from a user-writable directory
Data:         Sysmon 11 (file created under \Windows\System32\Tasks\), Sysmon 13 (TaskCache registry
              value set), Security 4698, Sysmon 1 for schtasks.exe with /create
Confirm if:   a task is created outside the approved deployment window AND the referenced binary is
              unsigned or lives outside Program Files / Windows
Refute if:    every creation maps to the deployment tool, the same minute, and a signed installer
Scope:        all Windows workstations, last 30 days
End condition: all candidates triaged or one confirmed
```

```text
H-2026-015  Beaconing without a malware alert
Subject:      any process on a server
Behaviour:    periodic outbound connections at a near-constant interval to a single external address
Data:         Zeek conn.log (ts, id.orig_h, id.resp_h, id.resp_p, duration, orig/resp_bytes),
              Sysmon 3, proxy logs
Confirm if:   a host makes many short, similarly sized connections to one destination at intervals
              with low jitter, and the destination is not a known update or telemetry endpoint
Refute if:    the pattern matches a documented service (backup, monitoring agent, NTP) or the interval
              is irregular and payload sizes vary randomly
Scope:        servers in the data-centre segment, last 14 days of flow data
End condition: top 20 recurring destinations triaged
```

### Properties of a good hypothesis

- **Falsifiable.** You can state, up front, what evidence would make you abandon it. "Something feels off on the file server" is not falsifiable, so it can never be closed.
- **Observable.** The behaviour is expressed in terms that appear in telemetry, not in intent ("the attacker tries to escalate privileges" becomes "a process requests a token with `SeDebugPrivilege`").
- **Scoped.** Host class, account class, and time window. Unbounded scope is an unfunded mandate.
- **Bounded in effort.** An end condition exists: when the candidate list is triaged, when the timebox expires, when the first confirmation arrives.
- **Independent of its answer.** You are testing, not confirming. If you already know the conclusion, you are writing a report, not a hypothesis.

### Anti-patterns

- **Unfalsifiable goals.** "Hunt for lateral movement" has no refutation condition and therefore no result.
- **Boiling the ocean.** "Find all malicious activity in the last year" guarantees an unfinished hunt.
- **Hypotheses shaped by available tools.** "Whatever my dashboard shows" is backwards; decide what to look for, then check whether you can see it.
- **Confirmation bias.** Stopping at the first benign explanation without documenting why it is benign.
- **Hunting your own tooling.** Running the query before establishing a baseline means you will "find" vulnerability scanners, backup jobs, and your own emulation every time.
- **Confusing absence with safety.** "No results" only refutes the hypothesis when the data source is validated (Phase 03).

## Prioritizing the backlog

Keep one backlog of candidate hypotheses and a small work-in-progress limit — one or two open hunts per hunter. A hypothesis that sits untouched for a quarter is usually a signal that it should be re-scoped or dropped.

Score each candidate on dimensions like these:

| Dimension | Question | What a high score looks like |
| --- | --- | --- |
| Impact | What does this cost us if it is real and undetected? | Crown-jewel data, domain-wide identities, production downtime |
| Intelligence confidence | How credible and how specific is the reporting? | Named techniques, sector-relevant, multiple sources |
| Gap size | How far is our current coverage from catching it? | No rule, no telemetry, or a rule that has never fired |
| Telemetry readiness | Can we answer it today, with proven sources? | Validated, retained, queryable data for the whole scope |
| Effort | How many analyst-days, and do we have the skills? | Fits the timebox; no unfunded tooling project |
| Freshness | When did we last hunt this, and has anything changed? | New tooling, new technique variant, or long-standing gap |
| Detection payoff | If confirmed, does it become a durable rule? | TTP-level behaviour that repeats across hosts |

Two practical heuristics:

- **Alternate between high-impact and gap-closing hunts.** High-impact hunts reassure the business; gap-closing hunts grow capability. A programme that only does the first never improves.
- **Never schedule a hunt whose telemetry you have not validated.** Fix the data source first, or pick a different target and record the gap as a separate work item.

## The hunt journal

The journal is the programme's memory and the reason a hunt can be re-run six months later. One entry per hunt, kept in whatever tool you already use (wiki, ticket, markdown repository) — but kept.

```text
Hunt ID:            H-2026-014
Date opened/closed: 2026-09-14 / 2026-09-18
Hunter:             <name>
Hypothesis:         <one sentence, with subject, behaviour, data, criteria>
Priority rationale: <which dimensions scored high and why>
Scope:              <hosts, accounts, time window, data sources>
Data health check:  <source, how you proved it healthy, last event seen>
Queries:            <verbatim, with the platform and date run>
Candidates triaged: <count, and how they were filtered>
Findings:           <confirmed / refuted / inconclusive, with evidence references>
Evidence:           <artifacts, hashes, screenshots, exported result sets>
New detections:     <rule IDs created, or "none" plus the reason>
Gaps found:         <telemetry, tooling, or process gaps discovered>
Follow-ups:         <next hypotheses this generated>
Verdict notes:      <what would change the verdict; residual uncertainty>
```

Journal discipline that pays off:

- **Write the hypothesis and queries before running them.** A journal entry edited after the fact is a summary, not a record.
- **Record queries verbatim**, including the platform, the time range, and the index or table. Field names differ between SIEMs.
- **Record the negative result too.** "Refuted after triaging 42 candidates" is a coverage claim you can defend.
- **Note what changed in the environment afterwards.** A hypothesis refuted in September may be true in December.
- **Link out**: the rule that came from the hunt, the ticket that requested it, the incident that seeded it.

## Common Mistakes & Tips

- **Writing the hypothesis after the query.** The most common failure. It turns discovery into justification and destroys the audit trail.
- **Hypotheses too broad to close.** Split "hunt for persistence" into registry autoruns, scheduled tasks, services, and WMI subscriptions — four hunts with four verdicts.
- **Trusting an emulation result without cleanup.** Atomics that leave artifacts behind contaminate the next hunt; run `-Cleanup` and snapshot.
- **Assuming your rule works because it is deployed.** Validate with emulation; a rule that has never fired may be broken rather than lucky.
- **Forgetting the baseline.** Establish what normal looks like in the same data, same window, before deciding something is anomalous.
- **No end condition.** A hunt without one becomes permanent background work that nobody ever closes.
- **Tip:** write the "refute if" line first — it is harder than the confirmation line, and it is what makes the hunt honest.
- **Tip:** keep a running list of hypotheses rejected during prioritization. They are the next quarter's targets, and the record shows the choices were deliberate.

## Checklist / Self-Test

- [ ] Can I state the four parts of a hunting hypothesis and write one from scratch?
- [ ] Can I name six sources of hypotheses and one weakness of each?
- [ ] Can I turn an ATT&CK technique page into a scoped, observable hypothesis?
- [ ] Can I run a single Atomic Red Team test, verify the artifacts it left, and clean it up?
- [ ] Can I explain how a detection gap analysis produces a prioritized target list?
- [ ] Can I score five candidate hypotheses against explicit criteria and defend the ordering?
- [ ] Can I explain why "no results" is not the same as "not present"?
- [ ] Does my hunt journal contain hypothesis, queries, data health, findings, detections, and gaps for every hunt?
- [ ] Can I identify at least three unfalsifiable hypotheses in my own backlog and re-scope them?

> **Verification:** checked against **MITRE ATT&CK** on **2026-09-19**: `T1059.001` is *Command
> and Scripting Interpreter: PowerShell* (`https://attack.mitre.org/techniques/T1059/001/`, HTTP
> 200) and `T1027` is *Obfuscated Files or Information* — the same two IDs and names as in the
> ATT&CK data set the installed Sigma validator carries (sigma-cli 3.1.0, 697 techniques), which is
> the mapping the detection phase tags with. The Atomic Red Team and Caldera repositories the
> emulation section points at resolve (HTTP 200). **Not executed:** no atomic was run and no
> emulation was performed — the module is not installed here and the techniques are offensive — so
> the `Invoke-AtomicTest` lines remain the project's documented invocation rather than a run.

## Further Resources

- **MITRE ATT&CK** — https://attack.mitre.org/
- **ATT&CK Navigator** (coverage layers and gap analysis) — https://mitre-attack.github.io/attack-navigator/
- **MITRE Cyber Analytics Repository (CAR)** — https://car.mitre.org/
- **Atomic Red Team** (technique emulation and cleanup) — https://github.com/redcanaryco/atomic-red-team
- **MITRE Caldera** (automated adversary emulation) — https://github.com/mitre/caldera
- **Sigma** (rule format for the detections a hunt produces) — https://sigmahq.io/
- **Official eCTHP product page** (authoritative syllabus and logistics) — https://ine.com/security/certifications/ecthp-certification
