# Risk Management

> eEDA · Methodology — Enterprise Defense Administrator
>
> Phase 02 of nine. Risk management is the decision engine behind every control the later phases build: [05](05-asset-inventory-and-configuration.md) inventories what is at risk, [07](07-vulnerability-and-patch-management.md) prioritises by the logic set here, and [08](08-continuity-and-recovery.md) buys down the worst outcomes.

## Purpose

Risk management is the engine that drives every security decision: it tells you what to protect, how much to invest, and when a control is proportionate or wasteful. Blue-team defenders apply risk thinking daily — triaging alerts, prioritizing patching, scoping audits. This guide covers risk identification, qualitative and quantitative assessment, likelihood and impact, treatment options, risk registers, and the frameworks you will meet in enterprise practice (NIST RMF, ISO 31000, and FAIR).

## Core Concepts and Vocabulary

- **Risk** — the effect of uncertainty on objectives, commonly expressed as the combination of the likelihood of an event and its impact.
- **Asset** — something of value: data, systems, people, reputation.
- **Threat** — anything that can exploit a vulnerability to harm an asset (actor + capability + intent).
- **Vulnerability** — a weakness that a threat can exploit.
- **Threat event** — an occurrence that could harm an asset.
- **Exposure** — the extent to which an asset is reachable by a threat.
- **Inherent risk** — risk before any controls are applied.
- **Residual risk** — risk that remains after controls; **this** is what management accepts or rejects.
- **Risk appetite** — the amount of risk the organization is willing to accept to reach its goals.
- **Risk tolerance** — the acceptable deviation from appetite for a specific objective or asset.

A useful mental model: **Risk = f(Threat, Vulnerability, Asset value)**. No threat, no exploitable weakness, or no value means no meaningful risk — which is why decommissioning unused assets is such a powerful (and cheap) risk reduction.

## Risk Identification

Identification must be systematic, not anecdotal. Common input sources:

- Asset inventory and data classification results
- Vulnerability scans and penetration test findings
- Threat intelligence (sector-specific TTPs, current campaigns)
- Incident post-mortems and near-miss reviews
- Change management pipeline (new apps, cloud migrations, M&A)
- Business impact analysis (BIA) and dependency maps
- Regulatory requirements and contractual obligations
- Interviews with system owners and process experts

Practical identification techniques:

```text
Asset-centric : start from the asset register -> what can hurt each asset?
Threat-centric: start from threat actors/campaigns -> what do they target?
Scenario-based: "what if" workshops (e.g., ransomware on the ERP, cloud key leak)
Checklist     : control catalogs (CIS, NIST SP 800-53, ISO/IEC 27001:2022 Annex A)
```

Output: a structured list of candidate risks, each with an owner and a clear statement. A well-formed risk statement is specific: "Ransomware encrypts the finance file shares, causing >72h downtime for month-end close," not "cyber attack."

## Risk Assessment: Qualitative vs Quantitative

### Qualitative assessment

Rates likelihood and impact on ordinal scales (Low/Medium/High or 1–5), often combined in a heat map. Fast, cheap, and understandable by non-specialists, but subjective and imprecise — two analysts can rate the same risk differently.

Example 5x5 scale and matrix:

```text
Likelihood: 1 Rare, 2 Unlikely, 3 Possible, 4 Likely, 5 Almost certain
Impact:     1 Negligible, 2 Minor, 3 Moderate, 4 Major, 5 Severe

Rating = Likelihood x Impact (1-25)

              Impact
             1   2   3   4   5
Likelihood 1 1   2   3   4   5
           2 2   4   6   8   10
           3 3   6   9   12  15
           4 4   8   12  16  20
           5 5   10  15  20  25

1-6 Low, 7-14 Medium, 15-19 High, 20-25 Critical
```

Use written definitions for each cell so ratings mean the same thing across the company ("Impact 4 = regulatory fine above X or loss of a Tier-1 application for >8h").

### Quantitative assessment

Expresses risk in numbers: expected loss, probability percentages, and cost. More defensible for investment decisions but data-hungry and slower. Common outputs:

- **SLE (Single Loss Expectancy)** = AV (asset value) × EF (exposure factor)
- **ARO (Annualized Rate of Occurrence)** — expected occurrences per year
- **ALE (Annualized Loss Expectancy)** = SLE × ARO

```text
Example: customer database
  AV  = $1,000,000        asset value
  EF  = 0.4               breach destroys/costs 40% of value
  SLE = $400,000
  ARO = 0.1               once every 10 years
  ALE = $40,000 / year

A compensating control costing $15,000/year that cuts ARO to 0.02
is justified: new ALE = $8,000 -> annual saving of $32,000.
```

Because point estimates hide uncertainty, real quantitative work uses ranges and distributions (Monte Carlo) rather than single magic numbers.

## Likelihood and Impact in Practice

- **Likelihood** should consider current controls and environmental factors (exposure to the internet, attacker motivation, existing mitigations), not just historical frequency.
- **Impact** has several dimensions: financial, operational (downtime), legal/regulatory, reputational, and health/safety. Do not reduce impact to dollars alone.
- Write **impact criteria per organization**; a "major" impact for a hospital (patient safety) differs from a retailer's.

```text
Impact dimension | Example measure
Financial        | Direct loss, remediation cost, fines
Operational      | RTO/RPO missed, service outage hours
Regulatory       | Breach-notification obligations triggered
Reputational     | Customer churn, media coverage
```

## Risk Treatment Options

After assessment, choose a response. The four classic options:

1. **Avoid** — eliminate the activity or asset that creates the risk (e.g., drop a high-risk product line, decommission a legacy service). Only valid when the business can live without the activity.
2. **Mitigate (reduce)** — apply controls to lower likelihood and/or impact (patching, MFA, segmentation, backups). The default for most operational risks.
3. **Transfer (share)** — shift part of the financial risk to another party (cyber insurance, contracts, outsourcing). Note: transfer does not remove legal accountability or operational impact — insurance pays money, not reputation or downtime.
4. **Accept** — consciously accept residual risk within appetite, documented and approved by the right owner (this is not "ignore"). Risks above tolerance must be escalated, not silently absorbed.

```text
Risk: Public web app prone to credential stuffing
Option      Action
Avoid       Take the app offline (only if business value is low)
Mitigate    MFA, rate limiting, bot detection, WAF
Transfer    Cyber insurance with credential-stuffing coverage
Accept      Residual risk of successful login abuse on low-value accounts
```

Decision rule: mitigate until residual risk fits appetite; if residual risk is still above tolerance, escalate for avoid/transfer/accept at the appropriate level.

## Risk Registers

A risk register is the single source of truth for identified and treated risks. Enterprise tools (GRC platforms) automate it, but a spreadsheet is a fine starting point.

```text
ID  | Risk description                | Category | Owner      | L | I | Score
R-1 | Ransomware hits file shares     | Malware  | IT Ops Mgr | 4 | 4 | 16 (High)
    | Treatment | Residual | Status | Review date
    | Air-gapped backups, EDR, seg.  | 2x3 = 6  | In progress | 2026-01-15
```

Register hygiene:

- One owner per risk; risks without owners drift.
- Capture the **residual**, not just the inherent, score.
- Track treatment plans as open actions with due dates.
- Review on a fixed cadence (monthly/quarterly) and whenever a major change occurs.

## Frameworks

### NIST Risk Management Framework (RMF)

A structured, seven-step lifecycle used heavily in US government and adopted widely in industry:

1. **Prepare** — organization-level and system-level preparation.
2. **Categorize** — the system and its information (impact levels per NIST SP 800-60 / FIPS 199).
3. **Select** — baseline controls (NIST SP 800-53) tailored to the system.
4. **Implement** — put the controls in place and document them.
5. **Assess** — evaluate controls against the requirements (SP 800-53A).
6. **Authorize** — senior official accepts the residual risk (ATO — Authority to Operate).
7. **Monitor** — continuously track control effectiveness and system changes.

The **ATO** concept is valuable beyond government: it forces an explicit, dated, named risk-acceptance decision before a system goes live.

### ISO 31000

The international risk-management *principles* standard, deliberately framework- and industry-agnostic:

- Principles (value creation, integrated, structured, tailored, inclusive, dynamic, continual improvement…)
- Framework (leadership and commitment, design, implementation, evaluation, improvement)
- Process loop: **Communication & consultation → Scope/context/criteria → Risk assessment (identification → analysis → evaluation) → Treatment → Monitoring & review**

ISO 31000 does not prescribe controls or methods — it tells you *how to run risk management as a process*, which is why it composes well with ISO 27001's risk treatment requirements (Clause 6.1).

### FAIR (intro)

**Factor Analysis of Information Risk** (Open Group standard) is the leading model for quantitative cyber risk. It decomposes risk so that numbers have defensible meaning:

```text
Risk = Loss Event Frequency (LEF) x Loss Magnitude (LM)

LEF = Threat Event Frequency (TEF) x Vulnerability (V, chance threat succeeds)
LM  = Primary loss + Secondary loss (stakeholder reactions, fines, response)

Each factor is estimated as a range/distribution, propagated with Monte
Carlo simulation to produce a loss exceedance curve:
  e.g., "10% chance of losing more than $5M/year to cyber events."
```

FAIR's value is discipline: it forces you to separate *frequency of attack* from *probability of success* and to model loss in multiple forms rather than one gut-feeling dollar figure.

## Writing a Risk Statement

The register is only as useful as the sentence in its second column. A vague statement cannot be scored consistently, cannot be treated specifically, and cannot be re-assessed next quarter.

Use this shape:

```text
<Threat source> exploits <vulnerability or condition> on <asset / process>
causing <business impact>, with <qualifying context>.
```

| Weak statement | Why it fails | Rewritten |
|---|---|---|
| "Cyber attack" | No asset, no impact, nothing to treat | "Ransomware encrypts finance file shares, stopping month-end close for more than 72 hours" |
| "Unpatched CMS plugin" | That is a vulnerability, not a risk | "An attacker exploits the unpatched CMS plugin on the public web shop to deface the storefront, causing a 48-hour sales outage and media attention" |
| "Insider threat" | Too broad to score or treat | "A departing engineer with standing production access copies the customer database to personal storage, triggering a GDPR breach-notification duty" |
| "Cloud misconfiguration" | Names a cause, not a loss event | "A public read permission on the analytics storage bucket exposes 400,000 customer records until discovered" |
| "Users are the weakest link" | An opinion, not a scenario | "A finance user approves a payment redirected by a business-email-compromise email, losing up to €50,000 per event" |

Two tests before a statement enters the register: **can you name the loss event** (what actually happens to the business), and **can you name the owner** (who is accountable for treating it). If either fails, it is an observation, not a risk.

## Worked Example: One Risk, End to End

Acme Widgets Inc. (see [../labs/security-policy-exercises](../labs/security-policy-exercises.md)) runs a single risk through the whole process — this is the exercise worth repeating with your own scenarios.

```text
1. IDENTIFY
   Source        : incident post-mortem at a peer company + vulnerability scan finding
   Statement     : "An attacker exploits the internet-facing web shop CMS to deploy
                    ransomware on the web server, taking the shop offline for more
                    than 24 hours and exposing customer personal data."
   Asset         : ACME-WEB-01 (T1, internet-facing, PCI DSS and GDPR scope)
   Owner         : Web systems lead (accountable), security team (treatment actions)

2. ASSESS (qualitative)
   Likelihood 4 (Likely) — internet-facing, public exploit code exists, patching lag
   Impact     4 (Major)  — 24h+ sales outage, breach-notification duty, contractual penalties
   Inherent score 16 (High) against the defined 5x5 criteria

3. QUANTIFY (where the numbers exist)
   AV  = €1,200,000  (revenue at risk + remediation + notification cost)
   EF  = 0.35        (partial service loss and remediation, not total asset loss)
   SLE = €420,000
   ARO = 0.25        (approximately once every four years)
   ALE = €105,000 per year

4. TREAT
   Mitigate: emergency patching within the critical SLA, WAF virtual patching,
             web server rebuild from a hardened image, daily verified backups,
             alerting on file-integrity changes in the web root.
   Cost    : €18,000/year (tooling, licence, engineering time)
   Residual: likelihood 2, impact 4 -> residual score 8 (Medium)
   Justification: ALE falls far more than the control cost, and the residual fits
                  the board-approved appetite for a T1 internet-facing asset.

5. RECORD AND REVIEW
   Register entry R-014, owner: Web systems lead, treatment due 2026-04-30,
   next review 2026-07-01 or on any change to the web platform.
```

What makes this defensible in a review: the impact claim is tied to a named business consequence, the residual score is recorded separately from the inherent one, the control has a cost, and the owner is a person rather than a team name.

## The Register: Fields That Pay for Themselves

A register with just ID / description / score / owner is a start, but four extra fields do the heavy lifting in audits and budget conversations:

| Field | Why it earns its column |
|---|---|
| **Existing controls** | Prevents the classic mistake of scoring inherent risk as if nothing were in place, and shows reviewers what already works |
| **Planned treatment + due date** | Turns the register into a project list; each open treatment is a tracked action |
| **Residual score** | The number decisions are actually made on (see the mistakes section) |
| **Framework mapping** | Lets one register serve risk management, compliance evidence, and internal audit at once |

Markdown template you can copy into a working document:

```markdown
| ID | Category | Risk statement | Asset(s) | Existing controls | Inherent L | Inherent I | Inherent score | Treatment | Planned control | Owner | Due | Residual L | Residual I | Residual score | Status | Review date | Framework refs |
|----|----------|----------------|----------|-------------------|-----------|-----------|----------------|-----------|-----------------|-------|-----|-----------|-----------|----------------|--------|-------------|----------------|
| R-014 | Malware / availability | Attacker exploits CMS on public web shop to deploy ransomware, taking the shop offline >24h and exposing personal data | ACME-WEB-01 | WAF, EDR, nightly backup | 4 | 4 | 16 High | Mitigate | Emergency patch SLA, image rebuild, FIM alerting | Web lead | 2026-04-30 | 2 | 4 | 8 Medium | In progress | 2026-07-01 | CIS 7, A.8.8, CSF ID.RA |
```

Keep two working views of the same data: a **treatment view** (everything with an open action, sorted by due date) and a **residual view** (everything still above appetite, sorted by residual score). The board sees the second; the engineers work the first.

## Assessing Risk in a Change Request

Administrators approve and implement changes constantly, and most change processes treat security as a checkbox. A five-question assessment keeps it proportionate:

```text
1. What new exposure does this create?     (new port, new service, new data flow, new third party)
2. Which assets and data classes does it touch, and at what tier?
3. Does it weaken any existing control?    (encryption, logging, segmentation, access control)
4. Can it be reversed, and how quickly?    (rollback plan and time)
5. What monitoring would tell us within 24 hours if it goes wrong?
```

Decision rule: if the change creates new internet exposure, touches T1 assets, or weakens a control, it needs a security review and a rollback plan before implementation — and the assessment is attached to the change record. Otherwise, implement it as a standard change. Two of these assessments filled in honestly will show you whether your change process is a control or a formality.

## Third-Party and Cloud Risk

Two risk classes that behave differently from internal ones, and that administrators end up implementing:

- **Third-party (supply chain).** You inherit their incident as your own. Assess: what data do they hold, what access do they have to your environment, how would you know if they were breached, and what does the contract require them to tell you and within what time? Map it to CIS Controls v8 control 15 and ISO/IEC 27001 Annex A 5.19/5.20.
- **Cloud.** Your risk is a shared responsibility: the provider secures the platform, you secure the configuration. The most common loss events are misconfigured storage, over-broad identity roles, and unmanaged accounts in forgotten subscriptions — all three are inventory and access problems ([05](05-asset-inventory-and-configuration.md), [06](06-identity-and-privileged-access.md)) before they are anything else.

> For both classes, the useful register fields are the ones that force accountability: which contract clause obliges them to notify you, and which internal owner monitors that they do.

## Common Mistakes & Tips

- **Risk = vulnerability scanning.** A list of CVEs is not a risk assessment — you must attach assets, threat context, and business impact.
- **Only scoring inherent risk.** Decisions must be made on residual risk; otherwise you keep re-fighting the same battles.
- **Rating without definitions.** A 5-point scale with no written criteria is astrology — every team will score differently.
- **Accepting risk silently.** Acceptance requires an owner, a signature/approval, a date, and a review trigger. "We just didn't patch it" is not acceptance.
- **Ignoring likelihood realism** — treating every internet-exposed system as equally likely to be hit ignores attacker economics and current threat intel.
- **Treating insurance as transfer of everything** — legal liability, operational impact, and reputational harm stay with you.
- **Tip**: pick one risk scenario and run it through all three styles (qualitative heat map, ALE arithmetic, and a FAIR-style range) to see how conclusions differ and converge.
- **Tip**: tie every security project in your roadmap back to a register entry — this is how security budgets get defended.
- **Statements that name a cause instead of a loss.** "Unpatched plugin" and "misconfigured bucket" are conditions. The risk is the loss event they enable. If a row cannot be scored by two different people to within one point, rewrite it.
- **Registers that only engineers can read.** A register nobody outside security understands cannot be used to accept risk, fund treatment, or brief a board. Write the statement in business language and keep the technical detail in the treatment column.
- **No existing-controls column.** Without it, reviewers score inherent risk as if nothing were deployed, overstate exposure, and lose trust in the register the first time an engineer points out the control that already exists.
- **Treatments with no due date and no owner.** A register row with no tracked action is a note. Every treatment needs a person and a date, or it belongs in the observations pile.
- **Assessing third parties once, at onboarding.** Supply-chain risk changes when they change their platform, their subcontractors, or their ownership. Put them on the same review cycle as internal risks.
- **Tip**: after each incident, ask the blunt question — "was this scenario in the register, and if not, why not?" Both answers are useful: a missing scenario is a coverage gap, and a present-but-untreated one is an escalation.

## Checklist / Self-Test

- [ ] I can define risk, threat, vulnerability, exposure, and residual risk precisely.
- [ ] I can run a qualitative assessment with a defined 5x5 matrix and written cell criteria.
- [ ] I can compute SLE, ARO, and ALE for a worked example and judge whether a control is cost-justified.
- [ ] I can list the four treatment options and state when each is appropriate.
- [ ] I can explain why transfer (insurance) does not remove operational or legal risk.
- [ ] I can build and maintain a risk register with owners, residual scores, and review dates.
- [ ] I can recite the seven NIST RMF steps and explain the purpose of the ATO.
- [ ] I can outline ISO 31000's process loop and FAIR's core decomposition (LEF × LM).
- [ ] I can rewrite a vague risk observation into a statement naming threat source, condition, asset, and business impact.
- [ ] I can run one risk end to end: identify, assess qualitatively, quantify with ALE, choose a treatment, record the residual, and set a review date.
- [ ] I can list the register fields that earn their column, and explain why existing controls and residual scores are not optional.
- [ ] I can assess a change request against the five exposure questions and decide whether it needs a security review.
- [ ] I can explain how third-party and cloud risk differ from internal risk, and which contract and Annex A clauses make them accountable.

> **Verification:** executed against PowerShell 7.6.6 on 2026-09-19: the arithmetic in this note was recomputed and holds — the 5×5 matrix products, and the worked example ($1,000,000 × 0.4 = $400,000 SLE; × 0.1 ARO = $40,000 ALE; a control that cuts ARO to 0.02 leaves $8,000, an annual saving of $32,000). The SLE/ARO/ALE definitions themselves are the standard ones and were not re-sourced for this pass.

## Further Resources

- NIST Risk Management Framework overview: https://csrc.nist.gov/projects/risk-management
- NIST SP 800-37 Rev. 2 (RMF guide): https://csrc.nist.gov/pubs/sp/800/37/r2/final
- NIST SP 800-30 (risk assessment guide): https://csrc.nist.gov/pubs/sp/800/30/r1/final
- ISO 31000 — risk management standard page: https://www.iso.org/iso-31000-risk-management.html
- The Open Group — Open FAIR (risk analysis standard): https://www.opengroup.org/open-fair
- ENISA — risk management resources: https://www.enisa.europa.eu
