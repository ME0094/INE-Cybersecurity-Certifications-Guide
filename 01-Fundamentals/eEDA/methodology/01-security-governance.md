# Security Governance

> eEDA · Methodology — Enterprise Defense Administrator

## Purpose

Security governance is the system by which an organization directs and controls its security program: who decides, what gets decided, how decisions are documented, and how the board verifies that security actually improves. For a blue-team professional this is the layer that turns technical controls into a defensible program, budgeted, measured, and audited. This guide explains governance concepts, roles, the document hierarchy, objectives, frameworks, and reporting so you can speak the language of management and auditors.

## What Security Governance Is (and Is Not)

Governance answers the question **"are we doing the right security things, in the right way, for the right reasons?"** It is distinct from management:

| Aspect | Governance | Management |
|---|---|---|
| Focus | Direction, oversight, accountability | Day-to-day execution and operation |
| Typical owner | Board, executive leadership (CISO) | Security managers, engineers, analysts |
| Horizon | Strategic (quarters/years) | Operational (weeks/days) |
| Output | Policies, objectives, risk appetite, reporting | Controls, alerts, patching, incident handling |

A common analogy: governance sets the destination and the route; management drives the car and fixes flat tires.

## Roles and Responsibilities

Clear accountability prevents the classic failure of "security is everyone's problem, so nobody owns it."

- **Board of directors / audit committee** — ultimate accountability. Approves risk appetite, reviews material cyber risk, and ensures the program is resourced. Delegates oversight to an audit/risk committee.
- **Executive leadership (CEO/CFO/COO)** — accepts enterprise risk on behalf of the organization and funds the program.
- **Chief Information Security Officer (CISO)** — owns the security program end to end: strategy, budget, policy, and escalation. The CISO reports to the board or audit committee at least annually (many do quarterly) and should have a direct channel independent of the CIO so security is not subordinated to IT delivery pressure.
- **Security team (blue team / SOC / engineering)** — implements policy through controls, runs monitoring and incident response, and feeds metrics upward.
- **Business unit leaders / data owners** — accountable for the confidentiality, integrity, and availability (CIA) of the assets and data their unit uses; must apply security requirements to their processes.
- **Employees** — the first line of defense: follow policy, report suspicious activity.
- **Internal audit** — independent assurance that controls operate as intended; reports findings to the audit committee, not to the CISO (independence matters).

Example RACI outline for a policy change:

```text
Activity                         R         A        C                 I
Policy draft                     Security  CISO     Legal, HR         Board
Risk acceptance for exceptions   CISO      CISO     Business owner    Audit cte.
Metrics review                   SOC lead  CISO     IT, business      Board/cte.
Annual risk assessment           Risk mgr  CISO     All units         Audit cte.

R = Responsible, A = Accountable, C = Consulted, I = Informed
```

## Policies vs Standards vs Procedures vs Guidelines

These terms are frequently misused; the hierarchy matters because each sits at a different level of authority.

- **Policy** — high-level, mandatory statement of intent and expectations, approved by senior leadership. Example: "All remote access must be authenticated with multi-factor authentication."
- **Standard** — mandatory, measurable requirements that implement a policy. Example: "Remote access must use hardware-backed MFA; passwordless fallback is forbidden."
- **Procedure** — step-by-step mandatory how-to for a task, tied to a standard. Example: the ticket flow a helpdesk agent follows to enroll a user's MFA device.
- **Guideline** — recommended, non-mandatory advice that helps people comply. Example: suggested password-manager vendors or ergonomic guidance.

```text
Policy      -> WHY and intent        (board/CISO level)
Standard    -> WHAT must be true     (measurable, auditable)
Procedure   -> HOW to do it          (step-by-step)
Guideline   -> SUGGESTIONS           (optional best practice)
```

If a control fails an audit, auditors usually trace it up this chain: did the procedure exist, was the standard measurable, and did the policy authorize the standard?

## Security Strategy and Objectives

Strategy connects business goals to security work. A useful security strategy states:

1. **Alignment**: which business objectives (growth, M&A, cloud adoption) create which security requirements.
2. **Risk posture**: the level of risk the organization accepts (risk appetite).
3. **Priorities**: the top 3–5 strategic initiatives (e.g., identity-centric security, visibility/logging, third-party risk).
4. **Outcomes and measures**: how success is recognized.

```text
Business goal:  expand SaaS product to the EU market
Security need:  data residency, GDPR-aligned controls
Initiative:     re-platform customer data to EU region + DLP pilot
Outcome metric: 100% customer data in approved regions; 0 major DLP incidents
```

Strategic objectives are often written as SMART statements: Specific, Measurable, Achievable, Relevant, Time-bound. Example: "Reduce mean time to detect (MTTD) from 7 days to under 24 hours for critical alerts by Q4."

## Governance Frameworks

Frameworks give you a vocabulary and a control structure that auditors and regulators recognize. Two foundational ones:

### ISO/IEC 27001 (governance clauses)

ISO/IEC 27001 is the management-system standard. The clauses that are pure governance:

- **Clause 4 — Context of the organization**: understand internal/external issues and interested parties; define the scope of the ISMS.
- **Clause 5 — Leadership**: top management must demonstrate commitment, establish a security policy, and assign roles/responsibilities.
- **Clause 6 — Planning**: address risks and opportunities; set security objectives and plan how to achieve them.
- **Clause 7 — Support**: provide resources, competence, awareness, and documented information.
- **Clause 8 — Operation**: run the risk treatment plan and operational controls.
- **Clause 9 — Performance evaluation**: monitor, measure, analyze, and perform internal audits and management review.
- **Clause 10 — Improvement**: correct nonconformities and continuously improve.

Annex A (the control list, now also published as ISO/IEC 27002) is where governance turns into concrete controls — access control, supplier security, incident management, and so on. Certification requires an accredited external audit.

### COBIT (essentials)

COBIT (Control Objectives for Information and Related Technologies, ISACA) frames governance as a set of processes evaluated with capability levels:

- Govern and manage the enterprise IT through domains such as *Evaluate, Direct and Monitor (EDM)* and *Align, Plan and Organize (APO)*.
- Its hallmark is **process capability levels** (0 – Incomplete to 5 – Optimizing), scored with a formal assessment method.
- COBIT is a governance *and* management framework, so it pairs well with ISO 27001 (controls) and NIST CSF (outcomes).

```text
NIST CSF    -> outcome language ("what good looks like": Identify/Protect/Detect/Respond/Recover)
ISO 27001   -> auditable management system + Annex A controls
COBIT       -> governance processes and capability maturity
```

Many enterprises use NIST CSF for board communication and ISO/IEC 27001 for certification/audit, with COBIT for process maturity where IT governance is regulated (e.g., banking).

## Security Metrics and Reporting

Reporting is how governance closes the loop: leadership can only steer with trustworthy numbers. Principles:

- **Measure outcomes, not just activity.** "Ran 2,000 scans" is activity; "critical unpatched exposure reduced from 40 to 3 systems" is an outcome.
- **Keep a small executive scorecard** — 5 to 10 KPIs the board can absorb, with trends rather than single snapshots.
- **Define each metric**: source data, formula, owner, and caveats. A metric without a definition invites disputes.

Example executive dashboard:

```text
Security KPI Dashboard — Q3
-----------------------------------------------------------------
1. Open critical vulnerabilities (>30 days)      : 12   (target < 20)
2. MFA coverage on privileged accounts           : 98%  (target 100%)
3. Mean time to detect (MTTD)                    : 4.5h (target < 24h)
4. Mean time to respond (MTTR)                   : 2.1h (target < 8h)
5. Phishing click rate (simulated)               : 3.1% (target < 5%)
6. Patch compliance (critical, 7-day SLA)        : 94%  (target > 95%)
7. Security incidents with business impact       : 1
8. Vendor reviews past due                       : 6    (target 0)
```

The same data serves different audiences: technical detail for the security team, risk-level summaries for the CISO, and trend lines plus exception notes for the board. Never let a metric become a surprise at the board meeting — escalate negative trends as they develop.

## Common Mistakes & Tips

- **Policies written by one person and never approved** — an unapproved policy has no authority. Route drafts through legal, HR, and the affected business owners, then to the CISO/board for sign-off.
- **Confusing policy with procedure** — putting "how to configure the firewall" inside the acceptable-use policy bloats it and makes it unreadable and unmaintainable. Keep intent at the top, mechanics below.
- **No review cycle** — set review dates (annual minimum) and treat regulations/technology change as triggers. A policy citing a decommissioned tool undermines the whole program.
- **Security reporting buried in IT metrics** — the board needs cyber-risk language, not server counts. Translate technical findings into business exposure ("we are exposed to a $2M fraud scenario until X is done").
- **CISO without board access** — if the CISO reports only through the CIO, resource conflicts are rarely escalated. Establish an independent reporting line.
- **Tip**: publish policies in a central, version-controlled location with effective dates and an owner named on each document.
- **Tip**: rehearse one board-quality metric pack per quarter so that when an incident happens, the reporting muscle already exists.

## Checklist / Self-Test

- [ ] I can explain the difference between governance and management with a concrete example.
- [ ] I can name who is accountable (board, CISO) versus responsible (security team) for the program.
- [ ] I can define policy, standard, procedure, and guideline and give one example of each.
- [ ] I can map ISO/IEC 27001 Clauses 5, 6, and 9 to concrete activities in an organization.
- [ ] I can state what COBIT adds (process capability assessment) versus ISO 27001 and NIST CSF.
- [ ] I can draft a SMART security objective tied to a business goal.
- [ ] I can build a 6–8 KPI executive scorecard and define one metric's source, formula, and owner.
- [ ] I can explain why outcome metrics matter more than activity metrics in board reporting.

## Further Resources

- NIST — Cybersecurity Framework (CSF 2.0): https://www.nist.gov/cyberframework
- ISO/IEC 27001 information — public summary: https://www.iso.org/standard/27001
- ISO/IEC 27002 control reference (ISO page): https://www.iso.org/standard/75652.html
- ISACA COBIT overview: https://www.isaca.org/resources/cobit
- ENISA — cybersecurity governance guidance: https://www.enisa.europa.eu
- NIST SP 800-100 — Information Security Handbook (governance practices): https://csrc.nist.gov/publications/detail/sp/800-100/final
