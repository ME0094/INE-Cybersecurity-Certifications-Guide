# eAIS Phase 09 — AI Governance and Lifecycle

> eAIS methodology · Phase 09 · English study guide — INE-Cybersecurity-Certifications-Guide

> **Style note.** Every command and code fragment in this file is a syntax reference: none of it was executed while writing this file. There is no model endpoint, no vector store, and no ticket system on the machine it was written on. The register, gate, and evidence records below are shapes to adapt — they are *our* schema, not a published standard format.

## Purpose of this phase

Phases 02–04 catalogue attacks and Phase 05 catalogues controls. This phase covers the part that decides whether those controls are ever *in place and still in place*: who owns an AI system, what is recorded about it, which decisions require evidence before they ship, and what an organisation can prove about its own system six months after a review.

The deliverables of this phase are an inventory with mandatory fields, a gate table with named approvers, a change-control rule for prompts and models, a role/decision-rights table, an incident playbook that accounts for what makes AI incidents different, an evidence-and-retention rule, and a metric set that resists being gamed. The commands, scanners, and case libraries live elsewhere in the module; this file links to them instead of restating them.

## Why governance is a security control, not paperwork

The decisions that actually prevent an AI incident are made before anyone writes a prompt, and they are architecture decisions:

- **Which corpus a caller's query can reach.** Enforced in the retrieval query and in the credential's scope — see [07-privacy-and-data-leakage.md](07-privacy-and-data-leakage.md).
- **Which tools the agent holds, with which scopes, expiring when.** Enforced at dispatch and approval — see [05-defensive-controls.md](05-defensive-controls.md).
- **Who may replace the model artifact or the prompt template, and whether anything verifies the substitution.** Enforced by pinning, hashing, and a deploy gate — see [03-model-poisoning.md](03-model-poisoning.md).
- **Whether a model output reaches a sink as trusted input.** Enforced at the sink, per destination.

None of these is a sentence in a system prompt, and none of them is fixed by a better prompt: an injected instruction arrives in the same channel as the user's text, so a policy written *inside* the model competes with the attacker's text on the attacker's terms. That is why the corrective action for a finding is so often a permission change, a corpus change, or a version rollback — and a permission change is a decision that needs an owner, a record, and a date. That process is what this phase is about.

The two artefacts that make governance a security function rather than a documentation function are:

1. **The inventory**, which answers "what is affected, who owns it, who must be told" during an incident, when nobody has time to reconstruct it.
2. **The reversal point**, which answers "what exactly do we roll back to, and who can do it in the next ten minutes".

A governance programme that cannot produce those two on demand has produced documents, not control. Say so plainly in the review rather than counting policy pages as maturity.

```text
Three questions a governance conversation must be able to answer about one system
[ ] If this agent sends one unauthorised email now, who is paged, and who disables the tool?
[ ] If the model artifact must be reverted, what version, verified how, and approved by whom?
[ ] If a customer asks which of their data reached this system, which record answers that?
```

## Mapping to the NIST AI RMF

The NIST AI Risk Management Framework is organised around four functions — **govern**, **map**, **measure**, **manage** — and the NIST Generative AI Profile (NIST AI 600-1) is the profile that tailors that framework to generative-AI systems. The framework is model-agnostic and does not prescribe your artefacts; the value here is that it forces each function to name a *product* and a *signature*. Fill the last column with a person's role, never with a team name.

| Function | What it must produce in your organisation | Concrete artefact | Who signs it |
| --- | --- | --- | --- |
| **Govern** | The rules everyone else works inside: ownership, risk tolerance, acceptable use, retention policy, who may approve what | The AI policy, the role/decision-rights table below, the register-of-record location | The accountable executive who owns AI risk |
| **Map** | Context and risk identification per system: purpose, affected parties, data touched, authority reachable, exposure | One inventory row per system, plus a per-system risk note naming the worst plausible outcome | The system owner, reviewed by the AI security lead |
| **Measure** | Evidence that the controls work, on the current version, under a stated budget | Evaluation records: corpus revision, versions tested, result, budget — see [08-evaluation-and-continuous-red-teaming.md](08-evaluation-and-continuous-red-teaming.md) | The AI security lead |
| **Manage** | Prioritised treatment, acceptance with an expiry, monitoring, and response | The risk-treatment plan, the accepted-risk register, and the incident playbook in this file | The risk owner for each entry; the incident commander for a live event |

The functions are not a waterfall, and GOVERN is not a first phase you finish: it is the set of decisions the other three keep needing. What makes an organisation's mapping useful is being able to point at the artefact and the date for each cell — the mapping itself is a claim, and the artefact is the evidence.

The same table, seen from the module's side: what each phase of eAIS produces, and which function consumes it. The point of the right column is that no phase's output is an end in itself — every one of them lands in a governance function, or it lands nowhere.

| eAIS phase | What it produces | RMF function that consumes it |
| --- | --- | --- |
| [01-ai-models.md](01-ai-models.md) | Component inventory of one application; trust-boundary sketch; version-per-component habit | **Map** — the per-system inventory row is assembled from these components |
| [02-prompt-injection.md](02-prompt-injection.md) | Injection mechanisms, delivery channels, and the impact model based on reachable tools | **Map** (risk identification) and **Measure** (the cases that later prove a control) |
| [03-model-poisoning.md](03-model-poisoning.md) | Provenance and hash discipline, load-format rules, AIBOM entries, artifact-incident handling | **Map** (what the system is built from) and **Manage** (supply-chain treatment and revert) |
| [04-adversarial-attacks.md](04-adversarial-attacks.md) | Robustness measurements with attack budgets: what was tested, at what cost, with which result | **Measure** — the numbers a sign-off quotes |
| [05-defensive-controls.md](05-defensive-controls.md) | Control catalogue, least-privilege design, logging and redaction decisions, incident playbooks | **Manage** — the controls that treatment plans actually deploy |
| [06-agent-and-tool-security.md](06-agent-and-tool-security.md) | Tool authority model, permission inventory, memory and state handling | **Map** (authority reachable) and **Manage** (authority reduction) |
| [07-privacy-and-data-leakage.md](07-privacy-and-data-leakage.md) | Data-plane inventory, retrieval-authorization decisions, retention and deletion runbooks | **Map** (data touched) and **Manage** (deletion and notification) |
| [08-evaluation-and-continuous-red-teaming.md](08-evaluation-and-continuous-red-teaming.md) | Versioned corpus, metric convention, cadence, and the sign-off record with its limits | **Measure** — and **Govern**, which consumes the cadence and the ownership |
| This file | Ownership, gates, change control, decision rights, evidence and retention rules | **Govern** — and it consumes the other three to decide what to require |

## Two other frameworks a governance conversation runs into

The AI RMF is the frame this module uses, but a review will name two others, and knowing what
each of them actually is prevents the two commonest errors: treating a management-system
standard as a security control, and treating a regulation's date as a security deadline.

**ISO/IEC 42001:2023 — *Information technology — Artificial intelligence — Management
system*.** This is a certifiable *management-system* standard, built on the same
plan-do-check-act shape as ISO/IEC 27001, not a list of controls or a maturity score. What it
asks an organisation to have is what this phase has already asked for in different words: a
defined scope, an AI policy, named roles and responsibilities, documented objectives, an
internal audit, a corrective-action process, and management review with records. If a
governance programme can produce the inventory and the gate table above with dates and owners,
most of the 42001 evidence set already exists as a by-product; if it cannot, an ISO 42001
certificate would certify the paperwork rather than the system. The module links no ISO page
because ISO's own catalogue sits behind bot protection and the standard is not freely
downloadable — cite it by number and year, and read the clause text through your own licensed
copy rather than a summary.

**Regulation (EU) 2024/1689 — the EU AI Act.** A regulation, not a framework: it creates legal
obligations with dates, and its application is staged rather than simultaneous. Article 113 is
the article that says when, and it is worth quoting rather than paraphrasing, because a
governance calendar is built from it: the Regulation **applies from 2 August 2026**, *except*
that (a) Chapters I and II apply from **2 February 2025** — which includes the Article 5
prohibited practices and the Article 4 AI-literacy duty; (b) Chapter III Section 4, Chapter V
(general-purpose AI models), Chapter VII (governance), Chapter XII and Article 78 apply from
**2 August 2025**; and (c) Article 6(1) and its corresponding obligations — high-risk
classification for AI that is a safety component of, or is itself, a product covered by the
Annex I harmonisation legislation — apply from **2 August 2027**. Two security-relevant
consequences follow directly from the text: for a system that is high-risk, risk management,
technical documentation, logging and post-market monitoring are *obligations* rather than good
practice you may defer; and a *serious incident* carries a reporting clock, which is why the
incident playbook in this phase should name who classifies an event as reportable rather than
assuming that question can be answered during the incident.

Neither framework makes a system secure, and a mapping table is not a control. Treat both as
requirements to *satisfy with the evidence this phase already produces*: the inventory row, the
gate record, the evaluation result, and the incident log are what an auditor or a regulator
asks to see, and they are the same artefacts that make a finding actionable at 02:00.

> **Not legal advice.** The paragraphs above describe what the documents say and when parts of
> the regulation apply; they are study notes, not a compliance opinion. Scoping a specific
> system — whether it is high-risk, who is the provider versus the deployer, what must be
> documented in which jurisdiction — is a question for your legal function, and the dates have
> been amended before and may be again. Verify against the official text on EUR-Lex before you
> put a date in a plan.

## AI system inventory

The register is **one row per AI system**, not per component and not per data plane: the component inventory for a single application lives in [01-ai-models.md](01-ai-models.md) and the data planes in [07-privacy-and-data-leakage.md](07-privacy-and-data-leakage.md). The register's job is to be the thing you can read at 02:00 without opening a repository.

| Field | What it captures | Why it matters the day of the incident |
| --- | --- | --- |
| **Owner** (a person, with a deputy) | Who is accountable for the system's behaviour and its risk acceptance | Determines who can authorise disabling a tool or reverting a version, and who answers for the decision afterwards |
| **Purpose and intended use** | What the system is for, and explicitly what it is not for | Separates "misuse by a user who went off-label" from "the system behaving as designed"; both are findings, with different fixes |
| **Model, version, and hash** | Base model, fine-tune or adapter, exact version, artifact digest, load format | You cannot revert, re-verify, or prove what ran without it; a hash mismatch is the fastest possible supply-chain answer |
| **Tokenizer and chat template version** | The component that defines role boundaries and how context is assembled | Explains why an injection worked after a template or runtime upgrade when nothing else changed |
| **Embedding model and version** | Which model vectors the index, and which vectors queries | Index and query must use the same model; a silent mismatch degrades retrieval and can change which documents outrank trustworthy ones |
| **Data sources** | Training, fine-tuning, and RAG corpora, with their provenance and ingest path | Produces the affected-data list for a notification, and the scope of a deletion request |
| **Tools and permissions** | Every tool, its scopes, the credential type, whether a human approval gates it | This field *is* the blast radius: it decides whether an injection is a nuisance or an unauthorised action under the app's identity |
| **Exposure** | Internal, partner, or public; who can reach it and from where | Sets the attacker population, and the honest severity of every finding above |
| **Personal data processed** | Which categories, in which plane, under which retention setting | Drives notification, deletion, and the decision to log raw content or only digests |
| **Last evaluation** | Date, corpus revision, versions tested, result, and the budget it was measured with | Tells you how stale the assurance is; an evaluation that does not name a version is not evidence for the version now in production |
| **Status** | Design, build, pilot, production, deprecated, retired | Prevents the two commonest register errors: testing something already retired, and forgetting that a "pilot" is handling real data |

Two rules keep the register usable rather than decorative. **One field per decision you would have to make without it** — if nobody can name the decision, the field is decoration. And **the register is discovered, not declared**: population comes from the deploys, the provider invoices, the egress logs, and the ticket queue, because the systems missing from an inventory are exactly the ones nobody volunteered.

```yaml
# Shape of one register entry (our schema, not a standard format).
id: support-assistant-prod
owner: name.surname@example         # plus a named deputy
purpose: "answer internal policy questions from the reviewed handbook"
not_for: "HR casework, legal advice, customer commitments"
model: {artifact: "vendor-endpoint", version: "pinned-id", sha256: "recorded-at-vetting", load_format: "vendor-hosted"}
tokenizer_template_revision: "recorded-with-artifact"
embeddings: {model: "same-for-index-and-query", version: "pinned-id"}
sources: [{kind: rag, corpus: "handbook-vetted", ingest: "reviewed-upload"}]
tools:
  - {name: "search_handbook", scope: "read", approval: none}
  - {name: "send_reply", scope: "write-external", approval: "human, resolved-arguments shown"}
exposure: internal
personal_data: ["employee names", "ticket identifiers"]
last_evaluation: {date: "recorded", corpus_revision: "recorded", versions: ["model", "template", "tools"], result: "recorded", budget: "recorded"}
status: production
reversal_point: "previous pinned artifact + template revision, verified by hash"
```

## Lifecycle gates

A gate is a decision with a named approver and a required piece of evidence. The table below is the minimum set; adapt the wording, keep the shape. The last column matters most in practice, because it is the one that tells a new joiner what "we always do it this way" actually protects.

| Stage | Decision taken here | Evidence required | Who approves | What can be skipped / what never |
| --- | --- | --- | --- | --- |
| **Design** | Intended use, out-of-scope uses, tool set, exposure, data classes | A one-page design note naming the worst plausible outcome and the authority the system will hold | System owner + AI security lead | Format and length can be skipped; naming the reachable authority cannot |
| **Data** | Which corpora may enter; provenance and licence; personal data handling and retention | Provenance record, vetting result, ingest path, retention setting | Data engineering lead + privacy/legal review | A large corpus can be built incrementally; ingesting unattributed or unlicensed content cannot |
| **Build / model selection** | Which artifact, which fine-tune, which adapters, pinned how | Hash manifest and an AIBOM entry per artifact — see [03-model-poisoning.md](03-model-poisoning.md) | Platform lead + AI security lead | A benchmark run can be deferred; the hash record cannot, because it cannot be reconstructed later |
| **Integration** | Tool registry, scopes, approval gates, retrieval authorization, sink handling | Permission table per tool, retrieval filter in the query, output handling per sink | AI security lead + system owner | Naming conventions and dashboards can wait; least privilege and the retrieval predicate cannot |
| **Pre-deployment** | Whether the measured behaviour is acceptable to ship | Evaluation record on the *deployable* versions, plus the regression corpus revision — see [08-evaluation-and-continuous-red-teaming.md](08-evaluation-and-continuous-red-teaming.md) | AI security lead; system owner accepts residual risk | Optional case families can be deferred **in writing, with a date**; a missing record on the shipped versions cannot |
| **Operation** | Monitoring, alert ownership, review cadence, register accuracy | Logged field list with its redaction rule, alert owners, register review date | Platform lead + system owner | Dashboards and cosmetic alerting can wait; a named owner per alert cannot |
| **Change** | Whether this change may ship, and on which evidence | Version diff (prompt, model, tools, retrieval config) plus re-run of the affected case families | Depends on the change class — see the section below | A gate can be light for a copy edit; it cannot be skipped for anything that alters authority, corpus scope, or output handling |
| **Retirement** | Where the data goes, what is deleted, who is told | Deletion record across the planes in [07-privacy-and-data-leakage.md](07-privacy-and-data-leakage.md), plus the consumer list of its outputs | System owner + privacy/legal review | Archiving the design note is optional; leaving credentials live and the corpus readable is not |

Two supporting rules: **a gate is a decision, not a meeting**, so an approval may be a record with a reviewer, a version, and a date; and **the emergency bypass has a name and a follow-up date** — an undocumented fast path is indistinguishable, in the record, from no gate at all.

## Change management for prompt, model, and tool changes

A prompt-template change is a security change, and the reason is structural rather than stylistic. The template defines which segment carries instructions and which carries data, whether retrieved text shares a channel with the system message, which tool schemas the model sees, and what the refusal posture is. A one-line edit can move a boundary that four phases of controls assumed. Treating it as a copy edit is how a reviewed system silently becomes an unreviewed one.

| Change class | Examples | Minimum gate |
| --- | --- | --- |
| **Cosmetic** | Tone, wording of a non-policy reply, formatting | Recorded version bump; no evaluation required |
| **Instruction-boundary** | Delimiters, segment labels, ordering of system/context/user, role definitions | Re-run the injection and extraction families; review by the AI security lead |
| **Capability** | New tool, new scope, new corpus, larger context, new sink | Full integration evidence: permission table, retrieval predicate, sink handling, plus the tool-authority case family |
| **Artifact** | Model version, adapter, tokenizer, embedding model, reranker | Hash record, deploy-time verification, and a differential run of the full suite against the previous version |
| **Configuration** | Retrieval `k`, filters, guardrail thresholds, timeouts, quotas | Threshold and false-positive evidence — a guardrail change is a change to both what it blocks and what it breaks |

Versioning and reversal, in the order that matters during an incident:

1. **Every version identifier is recorded in the trace**, so a finding can be attributed to a template revision and an artifact, not to "the assistant".
2. **Rollback is one operation** with a named operator, not a rebuild from memory: keep the previous template revision and the previous pinned artifact reachable, and verify by hash on the way back in.
3. **Rollback resets derived state too.** Caches keyed on prompt text, index versions, and any long-lived agent memory written under the bad version are part of the change, and a rollback that leaves them in place reproduces the behaviour you were reverting.
4. **Re-deploy the evidence with the change.** The evaluation record is attached to the version it measured; a record without a version is treated as expired.

```jsonl
{"change_id": "...", "class": "instruction-boundary", "diff_scope": ["prompt_template"], "versions_after": {"template": "...", "model": "...", "tools": "unchanged"}, "cases_rerun": ["injection_*", "extraction_*"], "result": "recorded", "approved_by": "...", "date": "recorded", "rollback_target": "previous template revision"}
{"change_id": "...", "class": "emergency", "reason": "...", "approved_by": "...", "follow_up_review_due": "recorded"}
```

## Third-party and supply-chain governance

Four supplier classes carry AI-specific governance questions: the **model provider** (hosted endpoint or downloadable artifact), **dataset and adapters** (training or fine-tune material, including third-party fine-tunes), **corpus sources** for retrieval (a vendor knowledge base, a shared wiki, a crawler), and the **platform** on which inference runs. The supply-chain mechanics — provenance, load formats, hash verification, AIBOM entries, and what to do when an artifact is suspected — are in [03-model-poisoning.md](03-model-poisoning.md); do not restate them here. What belongs in governance is the *ask, the record, and the exit*.

- **Ask the provider:** which artifact version is serving me and how do I pin it; what do you retain of my requests and my context, for how long, and who can read it; is my data used to improve the product or to train anything; what are the rate limits and how do I revoke a key; what notice do you commit to before deprecating a version; what do you commit to disclosing after an incident on your side.
- **Ask about every corpus source:** who can write to it, whether writes are reviewed, whether deletions propagate to the index, and whether a document's authority is recorded at ingest.
- **Record where engineers can read it:** the pinned version and hash, the retention and training-use terms as paraphrased by you (not a link to a contract nobody opens), the deprecation date you are tracking, and the person who tracks it.
- **Keep an exit:** a second provider or a local artifact you have actually loaded once, plus a tested path to move the corpus. An untested exit plan is an assumption.

The failure this prevents is not a clever attack; it is discovering during an incident that the version you must revert to is no longer served, that nobody recorded which of three corpora fed the affected index, or that the contract's retention terms were never read by anyone technical.

## Roles and decision rights

Roles are accountability, not headcount — one person may hold several. What makes the table useful is the third column: most governance failures are a role quietly deciding something it does not own.

| Role | Decides | Does not decide |
| --- | --- | --- |
| **System owner** (business) | Intended use, exposure, acceptable residual risk, whether to ship or retire, the register entry's content | Whether a control is adequate, what the technical severity of a finding is, what the evaluation corpus contains |
| **AI security lead** | Security requirements per gate, severity of findings, which case families must be re-run, whether a change is instruction-boundary or capability class | Business value and risk appetite, data-protection obligations, incident containment authority once an incident is declared |
| **Data engineering lead** | Corpus composition, ingest path, provenance and vetting, retention settings applied to stores | Tool authority, output handling at sinks, who may query the corpus |
| **Platform team** | Deployment, pinning and hash verification, runtime isolation, quotas and timeouts, rollback execution | Which data may be processed; the content of policy; whether a finding is accepted |
| **Privacy / legal (generic)** | Which data may be processed, retention and deletion obligations, what is notified to whom, contract terms | Technical severity, tool scopes, prompt design |
| **Incident response** | Containment and eradication actions once an incident is declared, evidence preservation, the decision to notify | Long-term risk acceptance, product decisions, permanent control design (it hands findings back to the owner) |

Two rules keep this workable: **anyone can raise a finding, and exactly one role accepts the risk** — acceptance is a written entry with an expiry, not a meeting outcome; and **the person who can disable a tool is named in the register**, because during an incident authority is worth more than consensus.

## Acceptable use and operator guidance

The people who use the system daily are a control layer, and they are only useful if someone has written down, in their language, what to do. This belongs in the register's system documentation and in the onboarding of whatever team operates it.

- **What never goes into a prompt or an upload:** credentials and tokens, personal data the system is not approved to process, and content whose disclosure you would have to report. Say what to do instead — redact, use the approved corpus, or ask.
- **What counts as suspicious input:** a document or email that contains instructions directed at the assistant, a supplier page that tells the reader what to do, unexpected urgency, or anything asking the assistant to change its own rules. Operators should be told the honest version: the assistant cannot reliably distinguish an instruction from content, so *they* are the second pair of eyes.
- **When to escalate, and to whom:** any action the system took that nobody requested, any output that reached a person or system it should not have, any request for data outside the operator's own entitlement, any repeated evasion of a filter, and any sudden refusal to work. Give a channel and a named owner, not "contact IT".
- **What an approval means.** If a human gate exists, the approver is asserting that the *resolved* arguments are correct — recipient, amount, path, query — not that the assistant's summary looked reasonable. Write that down, or approval becomes a rubber stamp.
- **What the assistant's output is not.** It is not authorization, not a legal or medical opinion, not a record of fact, and not evidence that a control worked. Treat generated content as a draft from an untrusted source, which is also why it is reviewed before it leaves.
- **Off-label use is a reportable event, not a secret.** Teams route around unusable tools quietly; a one-line "we use it for X" report converts a shadow deployment into a register row.

## AI incident response

AI incidents differ from classic ones in ways that change the first ten minutes. Containment is usually **removing authority, not isolating a host**: disabling a tool, narrowing a scope, revoking the token the agent used. Reversal is a **version operation** — template revision, artifact, index — not a backup restore. The primary evidence is **trace data**, which is also sensitive data. And the affected parties include people who never interacted with the system but received the agent's actions, or whose data sat in the context that leaked.

What changes, concretely:

- **Disable the tool, not the model.** Taking the agent's write-capable tool away stops the bleed while leaving the read path available for the investigation.
- **Rotate every credential the agent could use, and check what they touched.** An agent's credentials were used under the app's identity, so the access log is the scope.
- **Revert deliberately.** Prompt template, model artifact, retrieval configuration, and the derived caches or memory written under the bad version — in that order, each verified, with a record of what was reverted and when.
- **Preserve the trace before you fix anything.** Tool calls with resolved arguments, retrieved document IDs, the assembled context, the version identifiers, and the approval records. Redact on export, and record who accessed the export.
- **Assume the output travelled.** Content the agent generated may have been emailed, pasted, filed, or acted upon; the notification list is consumers of the output, not just users of the system.
- **Notify affected tenants and users** where the agent acted as them or exposed their data; the register's owner and personal-data fields are what make this list producible.

| Step | Evidence produced | Owner |
| --- | --- | --- |
| 1. Declare and scope | Incident record naming the system, versions, time window, and the authority the agent held | Incident commander |
| 2. Contain authority | Tool disabled or scope narrowed; tokens revoked; approval gates closed; the change recorded with a timestamp | Platform team, on the commander's call |
| 3. Preserve | Trace export (redacted) with version identifiers, retrieved IDs, tool arguments, approvals, and the chain of custody | Incident response |
| 4. Determine blast radius | List of actions taken by the agent, data touched, recipients reached, and the tenants affected; the register supplies the owner list | Incident response + system owner |
| 5. Eradicate and revert | Rollback record: what was reverted, to which verified version, by whom, plus cache and memory resets | Platform team + AI security lead |
| 6. Notify | Notification list with the data categories and the actions taken; contract obligations checked against the provider terms recorded at supplier review | System owner + privacy/legal |
| 7. Close the loop | Finding with severity, the case added to the regression corpus, the gate that would have caught it, and the register field that was missing | AI security lead |

The last step is the one that is skipped and the most valuable: an incident that does not produce a new case in the corpus and a new gate requirement will recur on the next version.

## Audit evidence and retention

The question evidence must answer is narrow and concrete: *what was evaluated, on which versions, with what result, approved by whom, on what date.* Anything that does not answer that question is storage cost and exposure.

| Evidence class | Keep | Do not keep |
| --- | --- | --- |
| Gate approvals | Decision, change class, versions before and after, approver, date, conditions and expiry of any bypass | Full meeting notes; opinions; drafts |
| Evaluation records | Corpus revision, case identifiers, versions tested, result, budget, and the limitations stated at the time | Raw harmful outputs pasted into a shared document; they are material you then have to handle |
| Artifact provenance | Hashes, load formats, source, vetting date, and the AIBOM entry | Vendor binaries copied into the evidence store |
| Inventory history | Periodic snapshots of the register, so you can say what was believed true on a given date | Personal data beyond identifiers needed to route a notification |
| Incident records | Timeline, actions taken, reverted versions, notification list, and the resulting finding | Unredacted trace exports kept past the investigation window |

Three rules keep the evidence store from becoming the breach: **reference data by digest** and keep the sensitive original in the system that already protects it; **one retention period per evidence class, with a stated purpose**, so "keep everything" is never the default; and **the evidence store has its own access control and its own review**, because it is a copy of your most sensitive material with an audience that spans teams.

## Metrics for a governance programme

Metrics change behaviour, so each one below is paired with the way it gets gamed. Report them together with a short narrative, and prefer a rate over a count.

| Metric | What it measures | How it is faked |
| --- | --- | --- |
| Systems inventoried | Coverage of the register against reality | Counting components as systems, or rows created at review time and never maintained; measure instead against deploys, invoices, and egress logs |
| Evaluations current | Share of production systems measured on their *current* versions within cadence | Running the cheap case families, or re-labelling an old record; require version identifiers and a budget in the record |
| Changes that passed a gate | Proportion of shipped changes with a gate record | Declaring everything cosmetic; raise the bar by auditing a sample of "cosmetic" changes against the change-class table |
| Open findings by age and severity | Whether treatment actually happens | Closing findings as "accepted" without an expiry, or splitting one finding into many small ones |
| Accepted exceptions with an expiry date | Whether accepted risk is being re-decided rather than forgotten | Blanket acceptance with a far-future date, or renewing an expiry without re-testing the compensating control |
| Time from incident to reverted version | Operability of the reversal point | Practising rollback only on systems that are trivial to rebuild; test on the one with the most state |

## Limits

- **A mapping is not compliance.** Describing a system in the RMF's vocabulary proves nothing about it; the artefacts and dates are the claim, and the artefacts are what a reviewer asks for. An unfalsifiable governance story is worse than a short honest one, because it is believed.
- **A stale inventory is worse than none.** An empty register tells you to go and look; a register with 60% of the systems missing and confident-looking fields tells you the affected system is not there. Date every review and treat an old snapshot as a lead, not an answer.
- **Governance does not replace technical controls.** A gate approves a control; it does not implement one. If the tool is still not least-privileged after the gate, the gate documented a decision nobody executed.
- **A gate that approves everything is a queue.** Measure the rate of conditions attached, not the rate of approvals. An approval process with a stable 100% approval rate and no recorded conditions is a rubber stamp with a ticket number.
- **The framework cannot tell you your own risk appetite.** The RMF is deliberately model-agnostic and organisation-agnostic; which residual risks are acceptable is a decision your organisation makes and then lives with.
- **Retirement is not deletion.** Retiring a system removes its tool credentials and its exposure; it does not remove documents from an index, content from weights, or answers from caches. That work is enumerated in [07-privacy-and-data-leakage.md](07-privacy-and-data-leakage.md).

## Where this fits the module

This phase supplies the decisions and the records; commands, procedures, and compressed tables live in the sibling files. Link to them rather than restating them.

| Path | Layer | Read it for |
| --- | --- | --- |
| [../README.md](../README.md) | Overview | Module roadmap and the certification-level picture |
| [01-ai-models.md](01-ai-models.md) | methodology — concepts | The component inventory and trust boundaries that fill one register row |
| [02-prompt-injection.md](02-prompt-injection.md) | methodology — concepts | The attack classes whose findings enter the register as risk notes |
| [03-model-poisoning.md](03-model-poisoning.md) | methodology — concepts | Provenance, hashes, load formats, AIBOM, and artifact-incident handling |
| [04-adversarial-attacks.md](04-adversarial-attacks.md) | methodology — concepts | Measurement discipline — what an evaluation result does and does not support |
| [05-defensive-controls.md](05-defensive-controls.md) | methodology — concepts | Control catalogue, least privilege, logging and redaction, incident playbooks |
| [07-privacy-and-data-leakage.md](07-privacy-and-data-leakage.md) | methodology — concepts | Data planes, retention and deletion runbooks behind the personal-data field |
| [08-evaluation-and-continuous-red-teaming.md](08-evaluation-and-continuous-red-teaming.md) | methodology — concepts | Corpus revision, metrics, cadence, and the sign-off record a gate approval cites |
| [../tools/ai-testing-tools.md](../tools/ai-testing-tools.md) | tools — commands | Which instrument produces the evidence a gate asks for |
| [../tools/evaluation-and-guardrails.md](../tools/evaluation-and-guardrails.md) | tools — commands | Evaluation and guardrail tooling, including false-positive measurement |
| [../tools/rag-and-vector-store-security.md](../tools/rag-and-vector-store-security.md) | tools — commands | Corpus provenance and index-level access control in practice |
| [../tools/observability-and-tracing.md](../tools/observability-and-tracing.md) | tools — commands | The trace and log field inventory that makes incident evidence producible |
| [../labs/llm-testing.md](../labs/llm-testing.md) | labs — procedures | The local lab target used to rehearse a gate's evidence on something disposable |
| [../labs/injection-lab.md](../labs/injection-lab.md) | labs — procedures | Injection drills behind the instruction-boundary change class |
| [../labs/rag-data-leakage-lab.md](../labs/rag-data-leakage-lab.md) | labs — procedures | The retrieval and tenancy procedures a data gate should require |
| [../labs/agent-tool-abuse-lab.md](../labs/agent-tool-abuse-lab.md) | labs — procedures | The permission inventory that populates the tools field, and tool-authority drills |
| [../labs/guardrail-evaluation-lab.md](../labs/guardrail-evaluation-lab.md) | labs — procedures | Measuring a guardrail change before the change-class gate approves it |
| [../cheatsheets/ai-attack-vectors.md](../cheatsheets/ai-attack-vectors.md) | cheatsheets — compressed | Vector → pattern → defence recall when writing a risk note |
| [../cheatsheets/attack-to-control-mapping.md](../cheatsheets/attack-to-control-mapping.md) | cheatsheets — compressed | Which control answers which vector, and what proves it is present |
| [../cheatsheets/tool-selection.md](../cheatsheets/tool-selection.md) | cheatsheets — compressed | Which tool to reach for under time pressure |
| [../cheatsheets/llm-test-case-library.md](../cheatsheets/llm-test-case-library.md) | cheatsheets — compressed | Reusable cases that seed a gate's re-run set |

## Common Mistakes & Tips

- **Treating the inventory as a one-off project.** A register filled in during an audit and never reviewed is a historical document. Give it a review date, an owner, and a discovery loop — deploys, invoices, egress logs, tickets.
- **Naming teams instead of people.** "Platform owns it" survives right up to the moment someone must disable a tool at 02:00. Every register row and every gate needs a named human and a deputy.
- **Recording the model and forgetting the template, tokenizer, and embedding model.** These components version independently, and an injection that starts working after an upgrade usually moved in one of them.
- **Letting the prompt change slip through as a copy edit.** If the template defines what counts as instructions, editing it is a security change; classify it, re-run the affected families, and record the version.
- **Approving a change by looking at the model's summary.** The approval asserts that the resolved arguments are correct. If the approver cannot see the actual recipient, path, or query, the control does not exist.
- **Accepting risk without an expiry.** Risk acceptance is a decision with a date on it; without an expiry it silently becomes a permanent configuration.
- **Keeping unredacted traces "as evidence" forever.** You have built a second, weaker copy of your most sensitive data. Reference by digest, redact at write time, and set one retention period per evidence class.
- **Tip:** for every gate, ask what a *new* joiner would have to read to approve it. If the answer is a person's memory, the gate is not yet a process.
- **Tip:** rehearse one rollback per quarter on your stateful system — the one with an index, caches, or agent memory — not on the stateless one that rebuilds in minutes.

## Checklist / Self-Test

- [ ] I can explain why a permission decision, not a prompt sentence, is what stops an injected instruction from becoming an action.
- [ ] I can name the four NIST AI RMF functions and, for each, an artefact my organisation produces and the role that signs it.
- [ ] I can state what each eAIS phase 01–08 produces and which RMF function consumes it.
- [ ] I can fill a register row for one real system, including the tools-and-permissions field, and justify every field by a decision it enables.
- [ ] I can name the eight lifecycle gates, what each decides, and which evidence can be deferred versus which never can.
- [ ] I can classify a prompt or model change into the right change class and state the minimum gate it needs.
- [ ] I can list four supplier classes and the questions I would ask and record for each.
- [ ] I can assign each decision in the roles table to a role, and say which role accepts residual risk.
- [ ] I can describe what changes in the first ten minutes of an AI incident compared with a classic host incident.
- [ ] I can state what evidence I keep for a gate approval and an evaluation, and what I deliberately do not keep.
- [ ] I can name five governance metrics and how each one is gamed.
- [ ] I can state the limits of my governance story — what it does not prove and what it does not control.

## Further Resources

- [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — the risk categories a register's risk note should be written against, in words rather than IDs.
- [OWASP GenAI Security Project](https://genai.owasp.org/) — guidance library behind those categories, useful when drafting acceptable-use rules.
- [MITRE ATLAS](https://atlas.mitre.org/) — adversarial technique landscape for AI systems, for threat-informed gate requirements.
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) — the govern / map / measure / manage structure this phase maps onto.
- [NIST AI 600-1 — Generative AI Profile](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-600-1) — the profile that tailors the framework to generative-AI systems.
- **ISO/IEC 42001:2023**, *Information technology — Artificial intelligence — Management system* — the certifiable management-system standard whose evidence set overlaps this phase's artefacts. Cite it by number and year; the standard is not freely downloadable.
- [Regulation (EU) 2024/1689 (the EU AI Act), consolidated text on EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) — Article 113 is the staged-application article quoted above; Article 5 is the prohibitions. Read the regulation, not a summary of it, and take scoping questions to your legal function.
- [INE Security — eAIS (AI Systems Security Specialist) official certification page](https://ine.com/security/certifications/eais-certification) — the credential this module supports.

> **Verification:** the EU AI Act dates and scope in the section above were read from the
> official consolidated text on EUR-Lex on **2026-09-19** (`curl -L` of
> `https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202401689` → HTTP 200), where
> Article 113 states: *"It shall apply from 2 August 2026. However: (a) Chapters I and II shall
> apply from 2 February 2025; (b) Chapter III Section 4, Chapter V, Chapter VII and Chapter XII
> and Article 78 shall apply from 2 August 2025, with the exception of Article 101; (c) Article
> 6(1) and the corresponding obligations in this Regulation shall apply from 2 August 2027."*
> **CWE-1426 — Improper Validation of Generative AI Output** was confirmed against
> `https://cwe.mitre.org/data/definitions/1426.html` in the same session (HTTP 200; the page
> title reads *"CWE-1426: Improper Validation of Generative AI Output (4.20)"*). The ISO/IEC
> 42001 entry carries **no** link because `iso.org` answers HTTP 403 to automated requests, so
> it could not be verified here — the number and year are the citation, and that limit is
> stated rather than papered over.
