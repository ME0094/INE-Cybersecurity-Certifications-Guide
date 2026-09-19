# Observability and Tracing for AI Systems

> eAIS · Tools — INE-Cybersecurity-Certifications-Guide · English
>
> The trace is the instrument you reach for after an AI system does something unexpected: it answers *which
> prompt ran, which documents were retrieved, which tools were called with which arguments, which guardrail
> fired, and what it cost*. This file covers the span shape worth capturing, the redaction, retention and
> sampling decisions behind it, incident reconstruction, detection signals, and where tracing stops helping.

> **Nothing here was executed.** No query, trace, or command in this file was executed while writing it: this
> machine has no LLM application, no tracing backend, and no API keys. The trace shapes here are schemas to
> adapt to your own stack. Field names below are a *proposal* for your own schema — not a standard, and nothing
> shown is captured output.

## What this file covers

Observability is a **security tool**, not a debugging convenience: one dataset answers **investigation** (why did
the assistant email that address?), **detection** (injection and tool abuse are behavioural — the trace is the
only place their sequence becomes visible) and **measurement** (a control whose verdicts were never recorded
cannot be shown to work). Without a trace, an incident becomes an interview.

Scope, so nothing here is duplicated: [methodology/05-defensive-controls.md](../methodology/05-defensive-controls.md)
states the *requirement* (log the decision trail, redact before storage, alert on blast-radius events) — this
file is the tooling side of it. Concepts are in [methodology/01-ai-models.md](../methodology/01-ai-models.md),
the app to instrument first in [labs/llm-testing.md](../labs/llm-testing.md), the test tooling in
[ai-testing-tools.md](ai-testing-tools.md), and the category decision table in
[tool-selection.md](../cheatsheets/tool-selection.md).

> Tracing is *your* observation of *your* process — not surveillance, and not a substitute for authorization.
> Instrument systems you own or are explicitly allowed to monitor, and treat the trace store as production data.

## The trace shape of an LLM request

A **trace** is one unit of work end to end (normally one user request); a **span** is one timed operation inside
it, linked to its parent by id; a **field** is a key-value pair you can query later; a **correlation id** joins
your spans to another system's record. Naming differs between stacks — what matters is that the tree exists and
the ids join. One request is a tree: a root span for the app handler, children for retrieval, each model call,
each tool call and each guardrail check. The table below is the minimum a *security* investigation needs; most
applications log the prompt and the answer, which are the two fields the user can already see.

| Field (proposed name) | Question it answers | What you lose when it is missing |
| --- | --- | --- |
| `trace_id`, `span_id`, `parent_span_id` | Which request is this, and what happened inside it, in order? | No sequence, no chain, no attribution: events readable, incident not reconstructable. |
| `conversation_id` / session id | Which multi-turn conversation does this belong to? | Escalation split across turns becomes invisible. |
| `user_id`, `tenant_id` | Who asked, and whose data was in scope? | Incidents cannot be scoped or notified, and cross-tenant leakage becomes undetectable. |
| `auth_kind`, `key_id`, `source_ip`, `env`, `app_version` | Human, service or leaked key — and which code, in which environment? | A compromised credential looks like normal automation, and no fix can be tied to a deploy. |
| `model_id`, `model_revision`, decoding params | Which model answered, and can this be re-run? | A behaviour change after an upgrade is unattributable; aliases hide the revision unless you record the resolved one. |
| `prompt_template_id`, `template_hash`, `system_prompt_hash`, `tool_registry_version` | Which prompt text, which instructions, which tool schemas? | Prompt drift and control regressions are invisible, and you cannot prove the model was told not to comply. |
| Retrieved `doc_id` / `chunk_id`, `score`, `rank` | Which content entered the context, and how strongly did it match? | Indirect injection has no visible cause; a poisoned document is indistinguishable from a relevant one. |
| `collection` / `origin` per document | Where did the content come from? | Sibling poisoned documents cannot be found, and the ingest pipeline cannot be fixed. |
| `acl_checked_as` (identity used for the filter), `docs_filtered_out`, reason | Who was allowed to see it, and what was withheld? | A tenant-bleed bug looks like a correct retrieval, and "a rail removed it" is indistinguishable from "no rail saw it". |
| Messages sent to the model (or refs + digests) | What exactly was in context? | You cannot separate "the model fabricated it" from "the document told it to". |
| Final output (text or digest + ref), `finish_reason` | What left the system, and did it end cleanly? | Data-loss investigations dead-end at the API boundary, and truncation is misread as refusal. |
| Tool `name` + version + `arguments` (redacted per policy) | What was touched, and what was it asked to do? | Tool abuse is invisible; egress to a new destination or a cross-user record id becomes unrecognisable. |
| Tool authorization (scopes, policy result, credential id — never the secret) | Was it permitted, and under which authority? | An over-permissioned service account looks like a normal authorized call. |
| Tool `result_status`, size, digest | Did it work, and what came back? | Attack chains break silently at the hop where the tool failed. |
| Tool `effect` class (read / write / egress, internal / external) | Did this leave the boundary? | The most useful single field for triage and for detection rules. |
| Guardrail `id`, version, verdict, score, `saw: raw` / `rewritten` | Which control saw which text, and what did it decide? | Coverage is unmeasurable, block rates undefined, and you will "fix" a rail that never saw the payload. |
| Guardrail error/timeout + fail-open or fail-closed | Did the control fail silently? | A rail that errors open is a defence that only appears present. |
| Tokens in/out, cost per trace | What did this cost, and is it anomalous? | Extraction and distillation probing hide behind normal-looking requests. |
| Latency per stage (retrieval, model, each tool, each rail) | Where did the time go? | A model problem is indistinguishable from a retrieval, tool or rail problem. |
| Retries, fallbacks, timeouts | Was this the first attempt? | Duplicate side effects (two emails) look like one action. |
| `outcome` label (answered / refused / blocked / error / handoff) | How did it end? | Every rate worth reporting — block, escalation, error — is undefined. |
| Online evaluation labels + user feedback | Was it actually good or bad? | No ground truth, so nothing can be prioritised or proven improved. |

> **Copy the shape, not the names.** Whatever tracing or evaluation stack you already run can carry these facts;
> some of them (`effect` class, `acl_checked_as`, guardrail `saw`) only your application knows and only you can
> define. Defining them is the work.

A schema of my own design, for illustration — placeholder shape, not a standard, not captured output:

```json
{ "trace_id": "<id>", "span_id": "<id>", "parent_span_id": "<id|null>", "start": "<ts>", "end": "<ts>",
  "kind": "retrieval | model | tool | guardrail | http",
  "actor": { "user_id": "<id>", "tenant_id": "<id>", "auth_kind": "user | service", "key_id": "<id>" },
  "model": { "id": "<name>", "revision": "<pinned-or-unknown>", "params_digest": "<hash>" },
  "prompt": { "template_hash": "sha256:<h>", "system_hash": "sha256:<h>", "tools_version": "<id>" },
  "retrieval": { "acl_checked_as": "<role>", "docs": [ { "doc_id": "<id>", "score": "<n>", "collection": "<n>", "origin": "<uri>" } ],
                 "docs_filtered_out": [ { "doc_id": "<id>", "reason": "<policy-or-rail>" } ] },
  "tool": { "name": "<tool>", "args_digest": "<hash>", "effect": "read | write | egress", "reach": "internal | external",
            "authz": { "decision": "allow | deny", "scopes": ["<s>"] }, "status": "<ok|error|timeout>" },
  "guardrail": { "id": "<id>", "verdict": "pass | block | rewrite | flag", "saw": "raw | rewritten", "failure_mode": "closed | open" },
  "usage": { "tokens_in": "<n>", "tokens_out": "<n>", "cost": "<n>" }, "outcome": "answered | refused | blocked | error | handoff" }
```

Spans are normally emitted one per line and joined later by `trace_id` / `parent_span_id`, which is why the
*identifiers* must never be sampled away:

```jsonl
{"trace_id":"<id>","span_id":"<id>","parent_span_id":null,"kind":"http","actor":{"user_id":"<id>","tenant_id":"<id>"}}
{"trace_id":"<id>","span_id":"<id>","parent_span_id":"<root>","kind":"tool","tool":{"name":"<tool>","effect":"egress","reach":"external","authz":{"decision":"allow"},"status":"ok"}}
{"trace_id":"<id>","span_id":"<id>","parent_span_id":"<root>","kind":"guardrail","guardrail":{"id":"<id>","verdict":"pass","saw":"raw"}}
```

## Prompts are data: logging them is a decision

A trace is a copy of everything the model saw and produced: user messages, retrieved documents, tool arguments
and results, often the system prompt. That makes the trace store simultaneously your **best security dataset**
and the **largest data repository you have ever created** — frequently with weaker access control than the
systems it copied.

| Decision | Default to | Why |
| --- | --- | --- |
| Prompt body at rest | Field-level redaction: keep structure and digests, mask identifiers and secrets | Hashing the whole prompt destroys the evidence needed to reconstruct an attack; storing it raw creates a second copy of every secret. |
| Sensitive-field inventory | Enumerate and mark the fields in the schema before they appear | Redaction driven by a written list is auditable; redaction by guesswork is not. |
| Hashing | Digest exact-match secrets you still need to join on | A digest of a low-entropy value (account number, phone number) is reversible by enumeration: a join key, not anonymisation. |
| Retention | Metadata long, payloads short, retention per field class in the schema | Investigations outlive verbose payloads; the spine is what you need months later. |
| Access control, tenancy, deletion | Two roles (payload and metadata readers), least privilege on payloads, an audited "reveal" with a reason, per-tenant partitioning, and an index from user to traces | If a support role can full-text search all prompts, your trace store is an insider data-leak path; and "we cannot find it, so we cannot delete it" is a compliance incident. |
| Secret hygiene upstream | Fix the app so the secret never enters the trace | Redaction is a fallback for data that must be there, not a licence to log credentials. |

Classification, retention rules and user rights belong to
[methodology/07-privacy-and-data-leakage.md](../methodology/07-privacy-and-data-leakage.md) and to the
governance phase (`methodology/09-ai-governance-and-lifecycle.md`). This file stops at the engineering that
makes those rules implementable: a field inventory, a redaction hook at ingest, an ACL on the payload store,
and a retention setting per field class.

```python
# Sketch, not a working module: redact at ingest, field by field, and keep the shape.
SENSITIVE_FIELDS = {"email", "phone", "iban", "card", "api_key", "token", "session_id"}
CORRELATE_BY_DIGEST = {"user_id", "account_number"}   # low entropy: join key only, still sensitive

def redact_span(span: dict) -> dict:
    for k, v in list(span.items()):
        if k in SENSITIVE_FIELDS:      span[k] = "<redacted>"
        elif k in CORRELATE_BY_DIGEST: span[k] = "sha256:" + digest(v)   # correlate, don't read
        elif isinstance(v, dict):      span[k] = redact_span(v)          # recurse into payloads
    return span
# Answer on paper before shipping: which fields are verbatim / digested / redacted; where the raw payload goes
# and under which ACL and retention; how the hook itself is tested.
```

## Sampling

Volume forces a decision; the mistake is sampling the *category of event you will need most*.

| Category | Sample it? | Reason |
| --- | --- | --- |
| Verbose payloads (full prompt and response bodies) | Yes, at a low but *stated* rate | High volume, mostly boring; enough to characterise normal traffic. |
| The spine: ids, timestamps, span kind, model revision, template hash, tool name, rail verdict, outcome, cost | No — 100% | Cheap, and exactly what reconstructs a chain later. Sampling it makes "no tool span" ambiguous. |
| First egress call per conversation, session or tenant | Never | The first time a system talks to a new destination is the highest-value event you will record. |
| First write-tool call per conversation or day | Never | First side effect is where blast radius starts. |
| Guardrail blocks, rewrites, flags, errors and timeouts | Never | Your only measurement of control coverage, your injection-canary feed, and the failure mode a silent control hides. |
| Retrieval where the ACL identity differed from the user, or documents were filtered out | Never | The tenant-bleed and rail-behaviour signal. |
| Traces whose `outcome` is `blocked`, `error` or `handoff` | Never | Interesting end states are rare; sampling them removes the detection surface. |
| Everything ordinary and high-volume | Sample, and record that you did | Cheap statistics need less than full fidelity. |

**Head sampling cannot keep the interesting traces**, because interestingness is often known only at the end
(the rail fired at the last hop; the egress tool ran after the model answered): use a keep-rule evaluated at
trace end over buffered spans, retaining the whole trace on a match. And **sampling must preserve joins** —
drop payloads, never identifiers or links, and record the sampling decision so nobody reads a gap as "it did
not happen".

```text
# Shape of a keep-rule policy (evaluate at trace end; retain the whole trace on any match)
KEEP whole trace if any of:
  guardrail.verdict != "pass"
  tool.effect in ("write", "egress") and first_occurrence(destination, tenant)
  retrieval.acl_checked_as != actor.user_id
  retrieval.docs_filtered_out is not empty
  outcome in ("blocked", "error", "handoff")
ELSE retain the spine and sample payloads at <rate>
ALWAYS emit trace_id, span_id, parent_span_id, kind, actor, env   # join keys are never optional
```

## Reconstructing an incident from traces

A worked example in behaviour only — the values belong to your environment. Scenario: a user asks a support
assistant to summarise a document; the summary is later emailed to an address the user never mentioned.

| Hop | What the spans show (shape) | Claim it supports | If the span is absent, you cannot say |
| --- | --- | --- | --- |
| 1. Retrieval | A document list with ids, scores, collection, origin, and the identity the ACL filter ran as. | *This document entered the context, under this permission.* | Whether the content came from retrieval at all, or from a pasted message or an earlier turn. |
| 2. Provenance | A high score for a collection whose documents normally come from an ingest pipeline no end user owns. | *The model was steered by content of unexpected origin* — the indirect-injection signature. | Whether the document was poisoned or merely mis-ingested: provenance is reportable, intent is not. |
| 3. Model call | Messages sent (or digests plus document refs) including the document body. | *The injected text was in the model's context when it answered.* | You cannot rule out fabrication: the answer may be the model's own invention. |
| 4. Read tool | `effect: read` with arguments referencing a record or mailbox outside the caller's scope. | *The agent fetched data the user was not entitled to see.* | The user-visible answer looks ordinary; the privilege escalation is invisible. |
| 5. Egress tool | `effect: egress`, `reach: external`, destination absent from the conversation, same trace. | *Content left the boundary, to a destination the user never named* — exfiltration, attempted or achieved. | You know a bad answer was produced, not whether anything actually left. |
| 6. Guardrails | Verdicts for input, retrieval and output rails, with version, the text each saw (`raw`/`rewritten`), and errors. | *Which control had a chance to stop it, and what each decided.* | You cannot distinguish "the rail passed it", "not wired here" and "errored open". |
| 7. Outcome | Final `outcome` label, tool result status, usage and cost. | *The chain completed or broke at hop N*, and what it cost. | Severity and scope: a failed attempt is indistinguishable from a successful one. |

The strongest defensible statement has this shape: *for trace X, the process recorded that document D (origin O,
ACL identity I) was placed in context, a read tool returned data outside I's scope, an egress tool with
destination E ran and returned status S, and the rails recorded verdicts V1..Vn.* Anything beyond that — what
the model "intended", whether the provider filtered it, whether a human acted on the email — needs a different
evidence source. Say what you observed, attribute it to the span that observed it, and name the gap.

Such a chain is joinable only if three invariants held *before* the incident: identifiers propagate across
services (one conversation, one `conversation_id`), timestamps share one time base with a known skew tolerance,
and no hop is silently uninstrumented.

## From traces to detections

A trace is not an alert: these become detections only once someone wrote the rule, set the threshold from a
baseline and accepted the noise. Most belong in a saved query or a review queue before they belong in a pager.

| Signal observable in the trace | Why it matters | Expected false positives | Where it is implemented |
| --- | --- | --- | --- |
| Egress call to a destination not previously seen for the tenant, or outside the tool's allow-list | The payoff step of most injection chains | New integrations, first legitimate use, marketing links | Saved query plus allow-list; alert at high severity once the list is stable |
| Read tool fetching outside the caller's scope (arguments reference another user's record) | Over-permissioned tool or credential | Shared service accounts, admin assistants, batch jobs | Alert, high severity; feeds a least-privilege fix |
| High retrieval score with provenance outside the curated collections | Poisoned or mis-ingested content steering answers | New corpora being onboarded, bulk imports | Review queue, not a page: provenance changes are a human call |
| Retrieval with no ACL filter, or applied as a service identity instead of the user | Cross-tenant leakage | Legacy pipelines, internal-only collections | Rule plus ticket; a defect class, not an incident |
| Expected guardrail verdict missing for a request path | A control that is not actually running (fail-open) | Recently added paths, shadow-mode rollouts | Trace-completeness check over span kinds, not over content |
| Guardrail block/rewrite rate spike for one user, tenant or key | Probing campaign, or a broken client | Shared accounts, load tests, one noisy integration | Per-entity baseline plus alert |
| Novel sequence in one trace (broad reads then egress) | The classic exfiltration shape | Legitimate bulk export and reporting automation | Sequence rule with an allow-list of known automations |
| Token/cost spike per key with high prompt diversity | Extraction or distillation probing | Long documents, batch summarisation | Budget alert, then a review of prompt diversity |
| Instruction-like text in *retrieved* content correlating with a change of action | Indirect injection that actually worked | Documents that legitimately quote policies or examples | Never detect on phrasing alone: correlate content with behaviour change, then review |
| Burst of tool authorization denials | Misconfigured agent, or probing a scope it lacks | Config drift after a deploy | Alert plus the config change that caused it |

**Derive every threshold from a baseline you can point at** (any number copied from anywhere, including this
table, is a placeholder), and **retire rules that only ever fire or never fire**.

## Traces as the evaluation dataset

Real traces are the test corpus you cannot buy: real phrasings, real documents, real tool sequences. Turning an
incident into a frozen case converts it into a regression gate, and it is the bridge to
[ai-testing-tools.md](ai-testing-tools.md) and [labs/llm-testing.md](../labs/llm-testing.md). The pipeline:
**select** a trace whose outcome you care about → **de-identify** it (synthetic payloads, real structure) →
**freeze** the case (prompt, context documents, tool stubs, expected label) → **replay** against the changed
prompt, model, rail or tool config → **compare the label**, not the prose.

| Field to keep when a trace becomes a case | Why it must be in the case |
| --- | --- |
| Case id and source trace id (as a reference, not as a payload) | A reviewer can return to the original behaviour without copying production data around. |
| Attack class (injection, jailbreak, extraction, tool abuse) | Coverage can be reported per family instead of as one number. |
| Prompt and the exact context documents (or synthetic equivalents) | The case is only reproducible if its context is part of it; retrieval is where indirect injection lives. |
| Tool stubs and their simulated responses | Tool-abuse cases fail spuriously against real or unavailable tools. |
| Expected label (`safe`, `blocked`, `leaked`, `complied`) | Without an expectation it is a transcript, not a test. |
| Pins: template hash, model revision, guardrail version, tool registry version | A pass means nothing if you cannot say what was under test. |
| Note that payloads were synthesised or partially retained | Prevents a later reader from treating it as a faithful replay. |

Version cases like code: immutable once frozen, reviewed when changed, referenced by the run report — a case
edited in place silently loses its history, and the next person comparing pass rates is comparing two different
tests. Keep production payloads out of the corpus unless the environment is expressly cleared for them.

```json
{"case_id":"inj-indirect-001","source_trace":"<trace-id>","class":"indirect-injection","input":"<fictional question>",
 "context_docs":["<synthetic-doc-id>"],"tool_stubs":["<read-tool>","<egress-tool>"],"expected":"safe",
 "pins":{"template_hash":"sha256:<h>","model_revision":"<pinned>","guardrail_version":"<id>"},
 "notes":"payload synthesised from a production trace; values replaced"}
```

## What tracing will not tell you

- **The model's reasoning.** A model's narrative about its own decision is another output, not a causal
  explanation: useful as a hypothesis, never as evidence.
- **What the provider did internally.** Routing between revisions behind an alias, provider-side moderation, or
  why a request was refused upstream are outside your process. Record the provider's request id so you can
  *ask* — never assert what you cannot see.
- **The system prompt, the tool implementation or the retrieval policy — unless you logged them.** A tool call
  with arguments says nothing about what the tool did with them; only the tool's own audit trail does.
- **Anything outside your instrumented path.** Another service using the same credential, the ingest job that
  stored the poisoned document, a human exporting data by hand, a prompt typed into a provider console.
- **The absence of an action.** Missing spans are ambiguous by construction: not called, not instrumented,
  sampled away, dropped on shutdown, lost in a crash. Absence of evidence is not an all-clear.
- **The attack nobody attempted** — and nothing for free: instrumentation adds latency, payloads add storage and
  data-protection surface, and being observed changes behaviour.

## Failure diagnosis

| Symptom | Probable cause | Check |
| --- | --- | --- |
| No tool spans, though tools clearly ran | Instrumentation wraps only the model client; tool and async children are not propagated | Call one tool deliberately in staging and look for a child span; verify context propagation across threads/async boundaries. |
| The user never appears in the trace | Identity resolved after the root span is created, or a downstream service writes under a service account | Compare the root span's `actor` fields with the identity layer's own log for the same request id. |
| The payload is unreadable | Redaction too early or too broad (whole prompt hashed instead of sensitive fields) | Replay one fixed request with known test values and read what was stored; then decide field by field and document it. |
| Last month's incident cannot be investigated | Retention shorter than the detection-and-investigation cycle | Compare mean time-to-detect plus time-to-investigate with the retention window; keep metadata longer than payloads. |
| Cost is measured, latency is not | Only billed usage fields are captured; per-stage timers are missing | Check for start/end on each span and whether model time is separable from retrieval, tool and rail time. |
| Two services report different ids for one conversation | No shared correlation scheme; each service generates its own root | Search both services for the same conversation and check whether *any* field is common; then propagate a conversation id plus one id per hop. |
| Guardrail verdicts exist but you cannot tell what the rail saw | The rail span records the verdict without the inspected text or its version | Add the `saw: raw`/`rewritten` marker and the rail version, then re-test with a known payload. |
| Traces look complete but outcomes are missing | The label is written after the response is sent, so the span closes first | Check span end ordering and where the label is emitted; label at the app boundary, not in the model client. |
| Duplicate traces for one user action | Retries at the app or proxy layer create a second root span | Correlate on your request id and count traces per user action; separate retry from a genuine second request. |
| Every request looks identical | Payload sampling plus aggregation stripped differentiating fields before storage | Diff two raw spans from different requests and confirm template hash, model revision and tool arguments survive. |

```bash
# Shape of the self-check you run on your own stack — shape only, no invented flags.
# 1. Send one request to the lab app (../labs/llm-testing.md) and keep the ids it returns.
# 2. Select that request id in your trace store and list the span kinds you got back.
# 3. Compare that list with the trace-shape table above and write down what is missing, field by field.
```

## Module map — where this file sits

Reading order for the eAIS module, relative to this directory. Every path below is a link to a file that exists in this checkout.

| Area | Files |
| --- | --- |
| Overview | [README.md](../README.md) |
| Methodology (reading order) | [01-ai-models.md](../methodology/01-ai-models.md), [02-prompt-injection.md](../methodology/02-prompt-injection.md), [03-model-poisoning.md](../methodology/03-model-poisoning.md), [04-adversarial-attacks.md](../methodology/04-adversarial-attacks.md), [05-defensive-controls.md](../methodology/05-defensive-controls.md), [06-agent-and-tool-security.md](../methodology/06-agent-and-tool-security.md), [07-privacy-and-data-leakage.md](../methodology/07-privacy-and-data-leakage.md), [08-evaluation-and-continuous-red-teaming.md](../methodology/08-evaluation-and-continuous-red-teaming.md), [09-ai-governance-and-lifecycle.md](../methodology/09-ai-governance-and-lifecycle.md) (01–09 in total) |
| Tools | [ai-testing-tools.md](ai-testing-tools.md), [evaluation-and-guardrails.md](evaluation-and-guardrails.md), [observability-and-tracing.md](observability-and-tracing.md) (this file), [offensive-scanners.md](offensive-scanners.md), [rag-and-vector-store-security.md](rag-and-vector-store-security.md) |
| Labs | [llm-testing.md](../labs/llm-testing.md), [injection-lab.md](../labs/injection-lab.md), [agent-tool-abuse-lab.md](../labs/agent-tool-abuse-lab.md), [guardrail-evaluation-lab.md](../labs/guardrail-evaluation-lab.md), [rag-data-leakage-lab.md](../labs/rag-data-leakage-lab.md), [data-poisoning-lab.md](../labs/data-poisoning-lab.md) |
| Cheatsheets | [ai-attack-vectors.md](../cheatsheets/ai-attack-vectors.md), [tool-selection.md](../cheatsheets/tool-selection.md), [attack-to-control-mapping.md](../cheatsheets/attack-to-control-mapping.md), [llm-test-case-library.md](../cheatsheets/llm-test-case-library.md) |

Traces supply the evidence for the agent-tool-abuse lab (unprovable without tool spans), the corpus for the
test-case library, the verdict data behind any guardrail claim, and the observation layer that
[methodology/05-defensive-controls.md](../methodology/05-defensive-controls.md) requires but does not specify.

## Common Mistakes & Tips

- **Instrumenting the model and forgetting the tools.** Tool spans are the highest-value spans, because that is where impact happens.
- **Logging the prompt and calling it observability.** That is what the user can already see; evidence lives in retrieval provenance, tool arguments, rail verdicts and outcomes.
- **Sampling the spine.** Sampling payloads is a budget decision; sampling verdicts, tool names and outcomes discards the investigation before it starts.
- **Storing raw prompts in a shared index.** You have built the largest data-leak surface in the company; decide field by field and test the redaction hook with known values.
- **Reading a missing span as "it did not happen".** Say "not recorded" until the path is proven instrumented; most wrong incident conclusions come from this one.
- **Reading traces as intent.** Traces record observations; write findings in that voice and keep the model's own narrative out of the evidence section.
- **Tip:** define the schema *before* the next feature ships — fields added later are missing for every incident that already happened.
- **Tip:** replay one synthetic incident through your own stack (a document carrying an instruction, a read, an egress) and check that the chain joins.

## Checklist / Self-Test

- [ ] I can define trace, span, field and correlation id, and say why each matters to an investigation.
- [ ] I can list the fields an investigation needs for retrieval, model, tool, guardrail, cost and outcome, with the "what you lose" for at least five.
- [ ] I can explain why the tool `effect` class (read/write/egress, internal/external) is worth defining in my own schema.
- [ ] I can state my redaction decisions field by field, including why a digest of a low-entropy value is not anonymisation.
- [ ] I can name the event classes that must never be sampled, and why head sampling alone cannot keep them.
- [ ] I can walk an indirect-injection-plus-exfiltration chain hop by hop and name the span each claim requires.
- [ ] I can turn three trace signals into detections with thresholds derived from a baseline, and state the expected false positive for each.
- [ ] I can convert a trace into a versioned evaluation case without copying production data, and say which pins make a pass meaningful.
- [ ] I can list five things tracing will not tell me, including two needing a different evidence source.
- [ ] I have run one synthetic incident through my own stack and confirmed the chain joins by ids alone.

> **Verification:** this file states at the top that nothing in it was executed, and that stands
> for the traces, queries and detections. What a pass can still check was checked on
> **2026-09-19** under Python 3.12.3: the span-shape block parses as JSON and the three span rows
> parse as JSONL, one object per line; the `redact_span()` sketch compiles and, run with a
> stand-in digest, masks the field named `email` at both depths, digests `user_id` and
> `account_number`, and leaves `tool.arguments` untouched — which is the gap the surrounding text
> asks you to close deliberately. One formatting defect found here was repaired in the same
> pass: the case-schema fence below the trace section was labelled `jsonl` while holding a
> single pretty-printed object across four lines, so a line-per-record reader could not parse
> it; it is now labelled `json`, which is what it is. No tracing backend, exporter or
> application exists on this machine, so no span was ever emitted and no detection rule was run.

## Further Resources

- OWASP Top 10 for Large Language Model Applications — https://owasp.org/www-project-top-10-for-large-language-model-applications/ (the failure classes whose behaviour a trace must make observable).
- OWASP GenAI Security Project — https://genai.owasp.org/ (guidance on logging, monitoring and incident handling for generative AI systems).
- MITRE ATLAS — https://atlas.mitre.org/ (the technique vocabulary to attach to detections, so a rule and a report name the same behaviour).
- NIST AI Risk Management Framework — https://www.nist.gov/itl/ai-risk-management-framework (measurement and monitoring as risk-management functions).
- NIST AI 600-1, Generative AI Profile — https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf (risk categories to keep in view when deciding what to record and retain).
- Your own tracing or evaluation stack's documentation — the field names, exporters and sampling controls you can actually rely on in your deployment.
- INE Security — eAIS (AI Systems Security Specialist) — https://ine.com/security/certifications/eais-certification

**Monitor only systems you own or are explicitly authorized to observe, and treat every trace, document and
prompt you collect as production data.**
