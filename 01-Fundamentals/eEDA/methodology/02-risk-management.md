# Risk Management

> eEDA · Methodology — Enterprise Defense Administrator

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
Checklist     : control catalogs (CIS, NIST SP 800-53, ISO 27002 Annex A)
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

## Common Mistakes & Tips

- **Risk = vulnerability scanning.** A list of CVEs is not a risk assessment — you must attach assets, threat context, and business impact.
- **Only scoring inherent risk.** Decisions must be made on residual risk; otherwise you keep re-fighting the same battles.
- **Rating without definitions.** A 5-point scale with no written criteria is astrology — every team will score differently.
- **Accepting risk silently.** Acceptance requires an owner, a signature/approval, a date, and a review trigger. "We just didn't patch it" is not acceptance.
- **Ignoring likelihood realism** — treating every internet-exposed system as equally likely to be hit ignores attacker economics and current threat intel.
- **Treating insurance as transfer of everything** — legal liability, operational impact, and reputational harm stay with you.
- **Tip**: pick one risk scenario and run it through all three styles (qualitative heat map, ALE arithmetic, and a FAIR-style range) to see how conclusions differ and converge.
- **Tip**: tie every security project in your roadmap back to a register entry — this is how security budgets get defended.

## Checklist / Self-test

- [ ] I can define risk, threat, vulnerability, exposure, and residual risk precisely.
- [ ] I can run a qualitative assessment with a defined 5x5 matrix and written cell criteria.
- [ ] I can compute SLE, ARO, and ALE for a worked example and judge whether a control is cost-justified.
- [ ] I can list the four treatment options and state when each is appropriate.
- [ ] I can explain why transfer (insurance) does not remove operational or legal risk.
- [ ] I can build and maintain a risk register with owners, residual scores, and review dates.
- [ ] I can recite the seven NIST RMF steps and explain the purpose of the ATO.
- [ ] I can outline ISO 31000's process loop and FAIR's core decomposition (LEF × LM).

## Further Resources

- NIST Risk Management Framework overview: https://csrc.nist.gov/projects/risk-management
- NIST SP 800-37 Rev. 2 (RMF guide): https://csrc.nist.gov/pubs/sp/800/37/r2/upd1/final
- NIST SP 800-30 (risk assessment guide): https://csrc.nist.gov/pubs/sp/800/30/r1/final
- ISO 31000 — risk management standard page: https://www.iso.org/iso-31000-risk-management.html
- The Open Group FAIR standard (intro): https://www.opengroup.org/faq/open-fair-standard
- ENISA — risk management resources: https://www.enisa.europa.eu
