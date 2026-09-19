# Security Governance

> eEDA · Methodology — Enterprise Defense Administrator
>
> Phase 01 of nine. Governance is the frame every later phase hangs from: it decides, and phases [05](05-asset-inventory-and-configuration.md) to [09](09-soc-and-incident-response-interface.md) execute those decisions as inventories, access control, patching, recovery, and detection.

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
NIST CSF    -> outcome language ("what good looks like": the six CSF 2.0 functions —
               Govern/Identify/Protect/Detect/Respond/Recover)
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

## Translating Findings into Board Language

The most common failure in security reporting is not bad data; it is untranslated data. The board does not fund a control, it funds an outcome. Practise the translation until it is automatic:

| Technical finding | Business exposure (the board line) | The ask |
|---|---|---|
| "MFA is not enforced on 3 of 214 privileged accounts" | "Three administrator accounts can be taken over with a stolen password; those accounts can reach customer data." | Approve the 3-week remediation project; accept a temporary access freeze |
| "No tested restore of the ERP backup in 14 months" | "If the ERP is encrypted today, we cannot state when order processing resumes — the recovery objective is unproven." | Fund the standby environment and the quarterly restore test |
| "18% of endpoints are outside the managed inventory" | "We cannot patch, monitor, or prove compliance for roughly one in five devices, and we do not know what they are." | Approve the discovery-and-onboarding cycle and its owner |
| "24 findings past the critical patch SLA" | "24 known, fixable weaknesses are open beyond the deadline we set for ourselves; a breach here would be hard to defend as unforeseeable." | Approve the emergency patch window and the exception review |
| "1,400 audit-log failures per day from the finance segment" | "We are blind in the segment that processes payments, so we cannot say whether it has already been accessed." | Fund the log pipeline fix as an outage-risk item |

Two rules make these lines land. **Name the consequence, not the control** — "we cannot demonstrate recovery" beats "the backup job is unverified". And **always pair the exposure with a specific decision** — a finding presented without an ask becomes an agenda item that recurs every quarter.

## Delegated Authority: Writing Down Who May Decide What

Governance fails quietly when decision rights are assumed. A delegation-of-authority table turns "someone should decide" into a named, bounded decision — and it is the artifact that stops escalation paralysis during an incident.

| Decision | Who decides | Bounded by | Recorded as |
|---|---|---|---|
| Approve a policy or a change to a standard | CISO (policy), security architecture board (standards) | Board-approved risk appetite | Version-controlled document with approval record |
| Accept residual risk on a new system | Business owner with the CISO's concurrence | Risk register entry, reviewed annually | Signed acceptance with expiry |
| Approve a temporary policy exception | CISO, or the delegate named in the policy | Maximum 90 days before review | Exception register entry |
| Approve an emergency change outside the CAB | Duty manager + security on-call | Security-relevant changes only, retro-approved within 5 days | Change ticket marked emergency |
| Isolate a system during a live incident | Incident responder (see [09](09-soc-and-incident-response-interface.md)) | Scope of the declared incident | Incident action log |
| Approve an unpatched exception past the SLA | Risk owner, not the engineering team (see [07](07-vulnerability-and-patch-management.md)) | Compensating controls documented | Exception with expiry date |
| Onboard a third party with data access | Data owner + procurement + security review | Data classification and contract clauses | Third-party register entry |

If a table like this does not exist, the practical consequence is that urgent decisions get made by whoever is most senior in the room, and the risk is accepted by nobody in particular.

## Policy Documents: The Artifact and Its Control Fields

Auditors do not assess intent; they assess documents. Every policy, standard, and procedure you write needs the same control block, because a document without it cannot be shown to be current, owned, or approved.

```markdown
# <Organization> — <Policy title>

| Field | Value |
|---|---|
| Document type | Policy / Standard / Procedure / Guideline |
| Document ID | SEC-POL-004 |
| Version | 1.2 |
| Owner (accountable) | CISO |
| Author (responsible) | Security Governance Lead |
| Approved by / date | Executive Committee / 2026-02-14 |
| Effective date | 2026-03-01 |
| Next review date | 2027-03-01 (or on material change) |
| Related frameworks | ISO/IEC 27001:2022 A.5.1; NIST CSF 2.0 GV.PO; CIS Controls v8 control 6 (safeguard 6.5, MFA for administrative access) |
| Related documents | SEC-STD-011 MFA standard; SEC-PR-020 MFA enrolment procedure |
| Exceptions register | EXC-REG-2026 (see section 6) |

## 1. Purpose
## 2. Scope (who and what it applies to; what is explicitly out of scope)
## 3. Policy statements (numbered, testable requirements)
## 4. Roles and responsibilities (mapped to the governance RACI)
## 5. Compliance and enforcement (who monitors, what happens on breach)
## 6. Exceptions (how to request one, who approves, maximum duration)
## 7. Related documents and revision history
```

Two quality tests to apply before publication:

- **Testability.** "Systems must be secure" cannot be audited. "All remote access is authenticated with MFA; enrolments are recorded in the identity platform" can be sampled.
- **Traceability.** Each numbered statement should trace upward to a framework requirement and downward to a control, an owner, and (eventually) evidence. That chain is what makes an audit a formality rather than a fire drill (see [03-compliance-basics](03-compliance-basics.md)).

## Governing the Exceptions

The exception process is the part of governance that actually gets exercised, and the part most often improvised. Govern it explicitly:

```text
1. REQUEST      The requester states which policy statement or standard cannot be met,
                on which assets, for how long, and why.
2. ASSESS       Security states the risk in business terms and proposes compensating
                controls (see the exception fields in ../labs/risk-exception-writeup.md).
3. DECIDE       The risk owner named in the delegation-of-authority table accepts or
                rejects the residual risk. The engineer does not accept their own risk.
4. TIME-BOX     Every exception has an expiry date. Renewal is a new decision, not an
                automatic extension.
5. MONITOR      Exceptions are counted, reported and reviewed with the other risks.
                A rising exception count is a strategy finding, not an administrative one.
6. CLOSE        When the underlying issue is fixed, the exception closes with the
                remediation evidence attached.
```

The metric to watch is not the number of exceptions but their **age distribution**: a cluster of exceptions renewed for the third time is a project that has been avoided for two years, and it belongs on the risk committee's agenda rather than in a spreadsheet.

## Common Mistakes & Tips

- **Policies written by one person and never approved** — an unapproved policy has no authority. Route drafts through legal, HR, and the affected business owners, then to the CISO/board for sign-off.
- **Confusing policy with procedure** — putting "how to configure the firewall" inside the acceptable-use policy bloats it and makes it unreadable and unmaintainable. Keep intent at the top, mechanics below.
- **No review cycle** — set review dates (annual minimum) and treat regulations/technology change as triggers. A policy citing a decommissioned tool undermines the whole program.
- **Security reporting buried in IT metrics** — the board needs cyber-risk language, not server counts. Translate technical findings into business exposure ("we are exposed to a $2M fraud scenario until X is done").
- **CISO without board access** — if the CISO reports only through the CIO, resource conflicts are rarely escalated. Establish an independent reporting line.
- **Tip**: publish policies in a central, version-controlled location with effective dates and an owner named on each document.
- **Tip**: rehearse one board-quality metric pack per quarter so that when an incident happens, the reporting muscle already exists.
- **Reporting a finding without an ask.** A board paper that ends in "we will monitor" produces no decision and returns next quarter. End each item with the decision you want.
- **Assuming decision rights instead of writing them down.** Without a delegation-of-authority table, risk gets accepted by whoever is most senior in the room, and no one is accountable afterwards.
- **Exceptions managed in email.** An exception that is not in a register with an expiry date is an undocumented, permanent policy deviation. Register it, count it, review it.
- **Documents without a control block.** A policy with no owner, version, approval date, or review date will fail its first audit regardless of how good its content is.
- **Tip**: number every policy statement so that exceptions, findings, and audit samples can cite "statement 4.3" instead of "the part about MFA".

## Checklist / Self-Test

- [ ] I can explain the difference between governance and management with a concrete example.
- [ ] I can name who is accountable (board, CISO) versus responsible (security team) for the program.
- [ ] I can define policy, standard, procedure, and guideline and give one example of each.
- [ ] I can map ISO/IEC 27001 Clauses 5, 6, and 9 to concrete activities in an organization.
- [ ] I can state what COBIT adds (process capability assessment) versus ISO 27001 and NIST CSF.
- [ ] I can draft a SMART security objective tied to a business goal.
- [ ] I can build a 6–8 KPI executive scorecard and define one metric's source, formula, and owner.
- [ ] I can explain why outcome metrics matter more than activity metrics in board reporting.
- [ ] I can rewrite a technical finding as a board line with a named business exposure and a specific ask.
- [ ] I can draft a delegation-of-authority table naming who decides policy, exceptions, emergency changes, and risk acceptance.
- [ ] I can produce a policy document control block with owner, version, approval, and review dates, and map it to at least one framework requirement.
- [ ] I can describe the six steps of the exception process and explain why the engineer must not accept their own risk.
- [ ] I can explain what the age distribution of open exceptions tells you that their count does not.

> **Verification:** checked against the CIS Controls v8 page for control 6 on 2026-09-19 (https://www.cisecurity.org/controls/access-control-management, titled "CIS Critical Security Control 6: Access Control Management"): the MFA-for-administrative-access citation in the policy template therefore points at Access Control Management — safeguard 6.5 — and not at Account Management, which is control 5.

## Further Resources

- NIST — Cybersecurity Framework (CSF 2.0): https://www.nist.gov/cyberframework
- ISO/IEC 27001 information — public summary: https://www.iso.org/standard/27001
- ISO/IEC 27002 control reference (ISO page): https://www.iso.org/standard/75652.html
- ISACA COBIT overview: https://www.isaca.org/resources/cobit
- ENISA — cybersecurity governance guidance: https://www.enisa.europa.eu
- NIST SP 800-100 — Information Security Handbook (governance practices): https://csrc.nist.gov/publications/detail/sp/800-100/final
