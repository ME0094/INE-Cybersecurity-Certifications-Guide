# eAIS Phase 06 — Agent and Tool Security

> eAIS methodology · Phase 06 · English study guide — INE-Cybersecurity-Certifications-Guide
>
> The step where a model stops answering and starts *acting*. Phase 02 delivers instructions through text, Phase 05 selects and bounds the controls, and this phase covers the mechanism in between: the dispatch boundary, the tool registry, argument validation, the agent runtime's isolation, the memory plane that outlives a session, and the trace that makes a multi-step run reconstructable. Phase 07 inventories the data an agent can read; this phase bounds what it can *do*.

> **Style note.** Every command and code fragment in this file is a syntax reference: none of it was executed while writing this file. There is no local model, no agent runtime, and no tool server on the machine it was written on. The drills that produce the evidence this phase asks for are in [`../labs/agent-tool-abuse-lab.md`](../labs/agent-tool-abuse-lab.md), and nothing below is captured output.

## Purpose of this phase

An agent is a loop: the model reads a context, emits a decision (usually a tool name and arguments), something executes it, the result goes back into the context, and the loop runs again. Everything before that execution is text, and text is Phase 02's problem. What this phase owns is the **execution**: what may run, with which values, under whose authority, inside which boundary, and what remains afterwards to prove it happened.

By the end of this phase you should be able to:

- Draw the **dispatch boundary** of a concrete agent and name the four things the dispatcher decides.
- Distinguish a **capability bug** (the agent holds authority the task never needed) from an **injection bug** (the authority was correct and the instruction was hostile), because the corrective action differs.
- Explain **tool confusion** and design a tool set where the least-privileged tool is the one a paraphrase actually selects.
- State the single rule that defuses indirect injection into an agent, and implement it as **per-value provenance** rather than a request-level flag.
- Specify the four **runtime isolation** properties you can claim about a sandbox, and the observation that proves each one.
- Name, for every control in this phase, the measurement that would show it working — and the drill in this module that produces that measurement.

The division of labour with its neighbours is deliberate. Phase 05 owns the *control catalogue*, the permission-model table, and the human-approval design. Phase 07 owns the *data planes* an agent reads and the deletion story. This phase owns the loop: the boundary, the tool surface, the arguments, the runtime, and the per-call evidence.

## What an agent adds to the attack surface

Four deltas turn a chat application into a system with a blast radius. Read the third column first: it is the part a chatbot cannot do at all.

| Delta | What changes technically | What an attacker gains |
| --- | --- | --- |
| **Output becomes action** | A generated string is parsed as a call and executed; the model's text is now a control channel, not a reply | No longer just an embarrassing answer — a recipient, a file, a payment, a query |
| **Results re-enter the context** | Tool output, fetched pages, and retrieved chunks are appended to the same context window the instructions live in | A second and third injection path that never passes through the input filter (Phase 02) |
| **State persists** | Memory, scratch files, caches, and conversation history survive the turn | A one-shot injection becomes a durable one, and it can cross sessions or tenants |
| **The agent holds credentials** | Each tool carries an identity with real permissions against real systems | The confused-deputy shape: the attacker borrows the agent's authority instead of stealing it |

The consequences worth writing down before any drill:

1. **Severity stops being a property of the payload.** The same injected sentence is a nuisance against a read-only summariser and an incident against an agent holding a send-capable credential. Impact is bounded by *reachable authority*, which is Phase 05's permission model — which is why Phase 05 calls that model the load-bearing control and this phase treats it as the input to everything else.
2. **The trajectory, not the turn, is the object under test.** A single call can be perfectly allowed and the *sequence* still be the attack. Any control that only sees one call at a time cannot express "read broadly, then send" as a rule.
3. **Text can carry data from anywhere; an instruction has exactly one authorized source.** The authenticated user turn — or a policy an owner configured — is the only place an instruction may come from. A retrieved chunk, a tool result, a fetched page, and a memory note are *data*, whatever they claim about themselves. Everything in the sections below is an implementation of that one rule.

## The dispatch boundary

The dispatch boundary is the line between "the model said so" and "it happened". It is the only place in the system where a single check can stop a hostile call, and it is usually implemented as a thin `if tool_name in tools` that decides nothing.

The model **proposes**; the dispatcher **disposes**. Four decisions belong to the dispatcher and to nothing else:

| Decision | The question | Failing shape |
| --- | --- | --- |
| **Existence** | Is this tool in the registry, by exact name, in this deployment? | An unknown name is passed to a dynamic resolver that treats it as a module path |
| **Schema** | Do the arguments satisfy this tool's typed schema — required keys present, no extra keys, enumerations respected? | Extra keys are ignored at validation and forwarded to the implementation, which uses them |
| **Authority** | Is the calling principal allowed this tool, against this target, right now? | The check is `tool in ALLOWED` with the target taken from the arguments |
| **Effect class** | Is this a read, a reversible write, or an irreversible external action — and does that class require a human? | The class is inferred from the tool's name, or from the model's own description of its plan |

Three properties make the boundary real rather than ceremonial:

- **The dispatcher must not be reachable around.** If a second code path (a notebook, a support tool, a batch job, a "debug" endpoint) can call the same tool with the same credential, the dispatcher protects one of several doors. Phase 07 makes the same argument about the retrieval query builder; it applies identically here.
- **It must fail closed on its own errors.** A dispatcher whose policy service times out and then proceeds has converted an outage into an authorization bypass. Record the refusal as its own outcome label — `policy-unavailable` is not the same event as `denied`. The failure-mode decision procedure is in [`05-defensive-controls.md`](05-defensive-controls.md).
- **The tool must validate too.** A tool that trusts its caller is one configuration mistake away from being directly reachable. Validation repeated at the tool is not redundancy; it is the difference between a boundary and a single point of failure.

## Excessive agency: the failure that is not an injection

Most real agent incidents do not need a clever payload. The tool set was simply larger than the task, and the model used it as instructed — by the attacker, in one sentence.

This phase is the agentic one, so its risk vocabulary is the OWASP **Top 10 for Agentic Applications for 2026** (released 9 December 2025 by the OWASP GenAI Security Project) rather than the LLM Top 10 alone: the LLM set describes an application that answers, and this phase is about one that *acts*, which is where excessive agency, tool misuse and unbounded consumption stop being categories in a list and become the architecture under review.

| Shape | What it looks like | The question that exposes it |
| --- | --- | --- |
| **Unnecessary tool** | A summariser that can also send mail "for convenience"; a search tool with a write mode | If this tool were removed, which user story would break? If the answer is "none", it is not a control problem, it is a design problem |
| **Unnecessary scope** | A read tool scoped to the whole corpus when the task needs one collection; a mailbox tool with send *and* delete | What is the narrowest scope that still completes the task, and who signed off on the wider one? |
| **Unnecessary autonomy** | Irreversible actions with no approval, because the workflow "would be too slow" | Which failure of this tool cannot be undone, and what makes it acceptable that no human sees it first? |
| **Unnecessary persistence** | A standing grant, a long-lived token, or memory that survives the task | What does this authority do while nobody is watching, and when does it expire? |

The floor is a single test you can apply in a review, and it is the one Phase 05 already states as a design question: **if the model is doing exactly what an attacker wants, what can each tool do?** Steps 0 and 6 of [`../labs/agent-tool-abuse-lab.md`](../labs/agent-tool-abuse-lab.md) exist to make that inventory a written table instead of an opinion.

Two traps make this harder than it reads:

- **Least privilege is a moving target.** Every feature request adds "just one more" permission, and the pressure never reverses. Budget the re-review, or the table rots within two releases.
- **A narrow permission can still be the attack.** If the permitted action *is* what the attacker wanted, the boundary is intact and the outcome is still bad. That is why the sections on argument validation and on provenance are not optional extras on top of a good permission model.

## Tool confusion

Tool confusion is choosing the wrong tool from a set where the choice looks obvious to a human and is ambiguous to a model. The interesting case is not the model picking nonsense; it is the model picking a **valid, more privileged** tool whose description also fits the request.

What produces it:

- **Near-duplicate names with asymmetric privilege.** `read_doc` and `admin_read_doc`; `search_public` and `search_all`. A paraphrase of the same intent can land on either.
- **Overlapping descriptions.** If both descriptions promise "answers questions about company documents", the model is choosing by surface wording, not by policy — and every rewording of a description is a behaviour change with no test attached.
- **Schemas that accept the same arguments.** When both tools accept `{"query": "..."}` and both succeed, there is no error signal to tell you the wrong one ran. A refusal would have been a detection; a success is silence.
- **An attacker-influenced registry.** Where tool definitions come from a remote or third-party source, the *description* is attacker-writable text that the model reads as guidance. A poisoned description is a prompt injection that never touches the user's message.

Design rules that reduce it: one tool per intent, privilege encoded in the **credential** rather than in the name, descriptions written to say what the tool *refuses*, and a schema that makes the privileged tool reject the query shape the unprivileged one accepts.

How you measure it: take one realistic request, paraphrase it several ways, and log the tool actually chosen along with its arguments. The pass condition is stability — the same, least-privileged tool — not a single lucky run. A tool set that flips between two tools across paraphrases has no policy, only a tendency. The drill is **Drill 2** in [`../labs/agent-tool-abuse-lab.md`](../labs/agent-tool-abuse-lab.md); the vector and its symptom are catalogued in [`../cheatsheets/ai-attack-vectors.md`](../cheatsheets/ai-attack-vectors.md).

## Tool call chaining and composite authority

Each call in a chain can be individually authorized, individually logged, and individually harmless. The attack is the **sequence**:

```text
# Shape of a composite exfiltration, every step allowed on its own
read_broadly()          -> allowed: the agent may read what the user may read
summarise()             -> allowed: no side effect at all
send_email(...)         -> allowed: the agent may send, to an allow-listed domain
# The policy question no per-call check can answer:
#   did a value produced by step 1 end up in step 3?
```

Two mechanisms address it, and they are complementary rather than alternatives:

- **Stateful session policy.** Rules over the run, not the call: no irreversible action within the same run that touched untrusted content, a budget on distinct resources read before a write, an escalation when a session crosses from read-only tools to write tools. This is coarse, cheap, and it catches the composite shape that no argument check can see.
- **Per-value provenance.** Attach to each argument value the source it came from and refuse the pairs that must never meet.

```python
# Concept shape — not executed. Provenance is tracked per value, not per request.
UNTRUSTED = {"retrieved_document", "tool_result", "fetched_page", "memory_note"}
# For each argument position of each tool: may this value come from untrusted text?
SINK_ARGUMENTS = {
    "send_email":  {"to", "cc", "body"},
    "http_fetch":  {"url"},
    "write_file":  {"path", "content"},
    "run_query":   {"sql"},
}

def dispatch(call, provenance):
    # provenance: {argument_name: source} — the source is recorded when the value is
    # parsed out of the model's output, and it names where the *text* of that value
    # originally entered the run (a user turn, a chunk, a tool result, a memory note).
    for arg in SINK_ARGUMENTS.get(call.tool, ()):
        source = provenance.get(arg)
        if source is None:
            raise PermissionError(f"{call.tool}.{arg}: value has no known source")
        if source in UNTRUSTED:
            raise PermissionError(f"{call.tool}.{arg}: value came from {source}")
    return TOOLS[call.tool].run(**call.args)
```

Why the granularity matters: a **request-level** "tainted" flag is worthless here, because a run that read a document is always tainted and so is a run where the user typed the recipient themselves. The useful unit is one value: *this address*, *this path*, *this query*. And note the third branch above — a value with **no** recorded source is refused too. That is the fail-closed direction, and it is the branch that catches arguments the parser synthesised, defaulted, or copied from a template rather than extracted from the model's output.

What provenance does **not** do: it cannot tell you that a user-typed recipient is the *wrong* recipient. It bounds a category, it does not judge intent. The remaining question is a human's, which is the next section but one.

## Indirect injection through tools: the three ingress paths

Phase 02 covers injection as a delivery problem. For an agent the paths multiply, because the loop reads from three places the user never typed into.

| Ingress path | Who can write there | Why the agent treats it as trustworthy | What addresses it |
| --- | --- | --- | --- |
| **Retrieved document** (RAG chunk, wiki page, ticket, uploaded file) | Anyone who can get a document into the corpus — a support ticket, a shared drive, a web crawl, a poisoned ingest pipeline | It lands in the context window in the same channel as policy text; the model has no way to separate *authority* from *proximity* | Untrusted labelling plus provenance: a chunk is never an instruction source. Retrieval authorization and corpus review are Phase 07 and [`../tools/rag-and-vector-store-security.md`](../tools/rag-and-vector-store-security.md) |
| **Tool result** (fetched page, email body, file read, code output, search result) | Whoever controls the remote content the tool was pointed at | The tool is allow-listed, and "it came from our own tool" gets mistaken for "it is our own text" | Treat every tool result as untrusted data: it may inform an answer, never the next call's tool or arguments |
| **Agent memory and prior state** (notes, scratch files, caches, conversation history) | Any input the agent processed earlier — including one it should have refused | Persistence makes a single success durable, and it usually crosses the session, and sometimes the tenant | Scope memory per user and per tenant, write only the fields a policy names, expire it, and log every write |

Two habits keep these paths from being forgotten in review:

- **Draw the context window and label every block with its source.** A block whose source cannot be named is a block whose influence cannot be bounded — it is the same inventory discipline Phase 07 applies to data planes, applied to the prompt.
- **Test the *result* path, not only the input path.** The measurement is whether a tool output containing an instruction changes the next tool call. **Drill 4** in [`../labs/agent-tool-abuse-lab.md`](../labs/agent-tool-abuse-lab.md) is exactly that probe, and families `F08`/`F09` in [`../cheatsheets/llm-test-case-library.md`](../cheatsheets/llm-test-case-library.md) are the case skeletons for it.

## Argument validation and allow-lists

A tool allow-list bounds the *set* of actions. It says nothing about the values, and a perfectly authorized tool called with attacker-chosen arguments *is* the attack. Validation belongs at the argument, and it belongs in two places: at the dispatcher, and again inside the tool.

The table below is organized by argument class, because the validation that works for a path is wrong for an address and useless for free text.

| Argument class | Canonicalize before comparing | Allow-list (never a deny-list) | The check that is usually missing |
| --- | --- | --- | --- |
| **Filesystem path** | Resolve to a real absolute path, following `..` and symlinks, then compare | One directory prefix, or an enumerated file list | The check runs on the raw string, so `../` inside a "filename" passes; or the write path is validated while the read path is not |
| **URL / host** | Parse the URL, lowercase and normalize the host, then check every hop | An explicit host list, with the scheme restricted | Only the first host is checked, so an allow-listed host that redirects becomes the egress route |
| **Recipient** (mail, account, tenant) | Normalize the address form, then resolve aliases and groups to their members | Named recipients or a named domain | An allow-listed alias or distribution list expands to destinations nobody approved |
| **Query parameter** (SQL, filter, field name) | Bind parameters; never concatenate; validate the field against a list | Table and column allow-list per operation | The agent uses one read-write identity for both read and write operations |
| **Shell or code** | — do not accept it | The correct allow-list is *empty*: no generic execution tool exists | A "helper" tool that shells out with an interpolated argument, added to make one workflow possible |
| **Free text that reaches a sink** | Cannot be canonicalized; carry provenance instead | — there is no allow-list for prose | The value is checked at the dispatcher, and the sink trusts its caller — so the sink encodes nothing and a downstream renderer executes it |

Five rules that decide most cases:

1. **Allow-list after canonicalization, or the list is decorative.** A prefix check against an unnormalized string is passed by traversal, by case variation, and by Unicode lookalikes.
2. **Reject ambiguity instead of resolving it.** Where a value has two plausible interpretations — two path encodings, an alias with several expansions — refuse. Guessing is how a validator becomes a confused deputy.
3. **Validate the resolved value, not the promised one.** If a parameter is optional and the tool supplies a default, the validator never saw it. Either require the argument explicitly or validate the tool's effective arguments after defaults are applied.
4. **Enumerated is better than validated.** A tool whose `action` is one of `{"get", "list"}` cannot be abused into `{"delete"}` by a payload, however the payload is encoded.
5. **The tool validates its own arguments last.** Whatever the dispatcher decided, the tool re-checks the values it is about to use. This is the check that survives the day someone wires the tool into a new caller.

**Drill 3** in [`../labs/agent-tool-abuse-lab.md`](../labs/agent-tool-abuse-lab.md) builds the argument-injection case; the control coverage for it is row `E` in [`../cheatsheets/attack-to-control-mapping.md`](../cheatsheets/attack-to-control-mapping.md).

## Sandboxing and isolation for the agent runtime

Phase 05 states the principle and its cost. This phase states the four claims a sandbox has to make, because "the agent runs in a container" is a topology, not a property.

| Property | The claim you must be able to make | How you test it |
| --- | --- | --- |
| **Filesystem reach** | The runtime writes only inside one directory it owns, and cannot read the agent's own configuration, prompts, or credentials | From inside the runtime, attempt a read of a path outside the root and a write above it, as the runtime's own identity |
| **Network egress** | Only enumerated destinations are reachable, and the block is enforced at the network layer rather than inside tool code | Attempt a connection to an off-list host by name and by IP, and through a redirect from an allowed host |
| **Identity** | The runtime holds no credential of its own; each call presents a token scoped to that tool, for that target, expiring | Read the process environment and the token's real scopes at call time, from the identity provider, not from the documentation |
| **Resources** | CPU, memory, wall time, and disk are capped, and hitting a cap ends the run as a labelled outcome | Run a loop that ignores cancellation; assert the cap fires and is logged distinctly from an error |

Two more properties belong to the *tool* rather than to the runtime, and they are where isolation claims usually leak:

- **The code interpreter is an egress path.** If the agent can execute code, the sandbox's egress policy governs that code too — including a code path that reads a secret from the environment and puts it in a URL. Isolation has to cover the interpreter's whole surface, not the network calls in your own tool implementations.
- **Isolation does not validate arguments.** A perfectly isolated runtime calling a legitimate, allow-listed API with attacker-chosen arguments is still the attack. The sandbox bounds *where* code runs and *what it can reach*; the remaining controls are the argument validation above and the credential's own authorization.

The pragmatic ordering: **pin the runtime boundary first** (no implicit credential, egress by allow-list, no host filesystem), then bound arguments, then add content filtering — which is the layer an attacker adapts to most cheaply.

## Human confirmation at the dispatch boundary

Phase 05 covers what a reviewer must see, why "approve?" without context is theatre, why timeouts must deny, and why approval belongs to the action rather than the session. What this phase adds is that approval is a **dispatcher property**: the confirmation must be attached to the call the dispatcher is about to make, with the arguments already resolved, and it must be impossible to reach the same effect through a second tool that no one gated.

Three agent-specific failure modes:

- **The gate is on a tool, not on an effect.** Two tools reach the same sink — a direct `send_email` and an `http_fetch` to an attacker-controlled relay. Gating one leaves the other open. Classify by *what leaves the boundary*, then find every door to that class.
- **The approval text is attacker-influenced.** The request, the draft body, and the recipient list can all contain text the attacker wrote. A reviewer reads that text; a well-crafted approval prompt is an injection aimed at a person. Show provenance next to the content, not instead of it.
- **The approval is bypassed by a resumed run.** A run that was rejected and then retried with a small mutation gets a fresh decision from a reviewer who has not seen the previous one. Approval records must be joinable to the run, not just to the call.

What approval cannot do is make a wrong action right — it transfers the decision to a human exposed to the same text. Treat it as a second lock on a narrow permission, never as a replacement for one.

## Memory and state: the surface that outlives the session

An agent that remembers is an agent whose compromise persists, so memory deserves the same treatment as any other store of other people's data:

- **Scope it.** Memory keyed by user, and by tenant, with the boundary enforced at read time — not by a filter applied to the results. A shared note store is a cross-tenant disclosure with a summary attached.
- **Write deliberately.** Only the fields a policy names, never a whole conversation, and never a value whose provenance was untrusted. A "remember this preference" feature is a persistence primitive, and its input is model output.
- **Expire it.** Every entry needs a lifetime and an owner. Unbounded memory becomes an unaudited second corpus with no retention story.
- **Log every write** with what was written, from which run, and under whose identity — then treat memory reads as retrievals subject to the same authorization questions Phase 07 asks of any corpus.

## Logging every call: the run trace as evidence

The field list a decision log needs, and what must never be stored in clear, are in [`05-defensive-controls.md`](05-defensive-controls.md); the trace mechanics — span shape, redaction hooks, retention tiers, sampling — are in [`../tools/observability-and-tracing.md`](../tools/observability-and-tracing.md). What an agent adds to that picture is structure:

```text
# Shape of one agent run — one trace, nested spans, decision and execution separated
run  <run-id>                        identity, tenant, session, prompt and model version
├── model_call   <n>                 tokens in/out, latency, the raw decision, its schema validity
├── tool_call    <n>                 tool, args digest, provenance per arg, credential id
│   ├── policy   <n>                 allowed | denied | policy-unavailable | needs-approval
│   ├── approval <n>                 who, when, how long they looked, what they saw
│   └── result   <n>                 status, latency, idempotency key, egress destination
└── outcome                          answered | refused | capped | denied-by-timeout | error
```

Four properties make a trace usable as evidence rather than as a convenience:

1. **One run id joins everything.** The user turn, the retrieved chunks, every model call, every tool call, every approval, and the outcome. Without it, an investigation is an interview.
2. **The decision and the execution are separate rows.** "The model asked for `send_email` to X" and "the dispatcher executed `send_email` to Y" are different facts, and the difference between them is precisely what you want to see after an incident.
3. **Provenance per argument is recorded.** It is the field that answers "where did this recipient come from?" six months later without reading a transcript.
4. **Missing tools and refused calls are logged too.** A run that requested an unknown tool, or that was denied, is the earliest evidence of probing — and it is the first thing an implementation drops, because nothing "happened".

## How each control is proved

A control you cannot test is a claim. This table is the bridge from this phase to the drills that produce the observation.

| Control | The observation that proves it | Where the drill is |
| --- | --- | --- |
| Tool registry allow-list | A requested tool outside the registry is refused and logged as its own outcome — never substituted, never resolved dynamically | Drill 2, [`../labs/agent-tool-abuse-lab.md`](../labs/agent-tool-abuse-lab.md) |
| Per-tool credential scope | The tool's real permissions, read from the identity provider, contain nothing beyond its declared need | Step 0, same lab; Phase 05 |
| Argument allow-list | Calls with a traversing path, an off-list host, and an alias-expanded recipient are refused — and still refused with the dispatcher's validation disabled | Drill 3, same lab |
| Untrusted-content provenance | A tool result containing an instruction produces no subsequent action, and the trace shows the value labelled untrusted | Drill 4, same lab; [`../labs/injection-lab.md`](../labs/injection-lab.md) |
| Confusion resistance | One intent, several paraphrases, same least-privileged tool chosen every time | Drill 2, same lab |
| Step, time, and cost caps | A never-terminating stub ends at the cap, labelled `capped` rather than as a generic error | Drill 5, same lab |
| Human approval on irreversible actions | With the approval service unreachable, the action is denied rather than executed; and the approval record shows the resolved arguments and their provenance | Drill 6, same lab; [`../labs/guardrail-evaluation-lab.md`](../labs/guardrail-evaluation-lab.md) |
| Sandbox isolation | From inside the runtime, egress and a host-credential read both fail, and both failures are logged | Drill 6, same lab |
| Run-trace completeness | Replaying a known run yields every field above, joinable by run id, with decision and execution as separate rows | [`../tools/observability-and-tracing.md`](../tools/observability-and-tracing.md) |
| Regression after hardening | The same case set re-run against the hardened agent, on the same day and data, with the before/after numbers side by side | Drill 6, same lab; [`08-evaluation-and-continuous-red-teaming.md`](08-evaluation-and-continuous-red-teaming.md) |

The last row is the one people skip. Hardening without re-measurement produces a belief; the same suite run before and after produces a number. Define the pass threshold *before* you run the hardened version, or the result will be interpreted rather than read.

## Module map — where each file sits

| Path | What belongs there |
| --- | --- |
| [`README.md`](../README.md) | Module overview, reading order, and the eAIS scope in one page |
| [`methodology/01-ai-models.md`](01-ai-models.md) … [`09-ai-governance-and-lifecycle.md`](09-ai-governance-and-lifecycle.md) | Concepts and decisions: model foundations, injection, poisoning, adversarial attacks, defensive controls, **this phase**, privacy and data leakage, evaluation, and governance |
| [`tools/ai-testing-tools.md`](../tools/ai-testing-tools.md), [`offensive-scanners.md`](../tools/offensive-scanners.md), [`evaluation-and-guardrails.md`](../tools/evaluation-and-guardrails.md), [`rag-and-vector-store-security.md`](../tools/rag-and-vector-store-security.md), [`observability-and-tracing.md`](../tools/observability-and-tracing.md) | Commands, configuration shapes, and failure diagnosis for the tools that implement these controls |
| [`labs/llm-testing.md`](../labs/llm-testing.md), [`injection-lab.md`](../labs/injection-lab.md), [`agent-tool-abuse-lab.md`](../labs/agent-tool-abuse-lab.md), [`rag-data-leakage-lab.md`](../labs/rag-data-leakage-lab.md), [`data-poisoning-lab.md`](../labs/data-poisoning-lab.md), [`guardrail-evaluation-lab.md`](../labs/guardrail-evaluation-lab.md) | Procedures that produce the observations this phase's last table asks for |
| [`cheatsheets/ai-attack-vectors.md`](../cheatsheets/ai-attack-vectors.md), [`attack-to-control-mapping.md`](../cheatsheets/attack-to-control-mapping.md), [`tool-selection.md`](../cheatsheets/tool-selection.md), [`llm-test-case-library.md`](../cheatsheets/llm-test-case-library.md) | Compressed tables for use during a test: vectors, attack-to-control pairs, tool choice, and reusable cases |

## Common Mistakes & Tips

- **Mistake:** treating the agent framework's tools as trusted because they ship with it. A bundled code interpreter, browser, or file tool has the runtime's reach; that reach is the finding.
- **Mistake:** gating the model instead of the dispatch. A system prompt that forbids an action changes a probability; the credential on the tool decides whether the action is possible. When the two disagree, the credential wins.
- **Mistake:** validating arguments only at the dispatcher. One new caller — a notebook, a batch job, an internal endpoint — and the validation is gone. The tool must re-check what it is about to do.
- **Mistake:** allow-listing a tool but not a target. `send_email` is allowed; the recipient came from a retrieved document, and the allow-list was on the *tool name*.
- **Mistake:** reading "the sandbox is up" as a security property. Filesystem, egress, identity, and resources are four separate claims and four separate tests; an untested one is the one that will run in production.
- **Mistake:** a request-level taint flag. Every run that read a document is tainted, so the flag never fires usefully. Provenance belongs to the value.
- **Mistake:** approving a plan instead of resolved arguments. "The agent will send a few emails" cannot be reviewed, because the recipients are decided later — by the model.
- **Mistake:** logging only the calls that ran. A refused call and an unknown tool name are the earliest evidence you will ever get; if you do not log them, a probing session looks like an empty one.
- **Tip:** design the tool set by writing down the *one* sentence each tool must be able to execute on the user's behalf, then delete every tool that sentence does not need. Most excessive-agency findings disappear at that step.
- **Tip:** keep a short "authority inventory" next to the agent's code — tool, data reachable, reversibility, credential, approver — and re-read it whenever a tool or a credential changes. An inventory that lives only in the developers' heads is not a control.
- **Tip:** run the composite test deliberately: a single run that reads broadly and then attempts a write or a send. If your policy cannot name that sequence, you have per-call rules and no run-level policy.

## Checklist / Self-Test

- [ ] I can point at the exact line where a model decision becomes an action, and name the four decisions the dispatcher owns.
- [ ] I can distinguish a capability bug from an injection bug and say why the fix differs.
- [ ] I can list the tools of one real agent and state, for each, what an attacker gains if the model is fully controlled.
- [ ] I can explain tool confusion, and name two design choices that make the least-privileged tool the likely selection.
- [ ] I can describe a composite attack where every individual call is authorized, and name the policy that catches the sequence.
- [ ] I can state the single rule about where instructions may come from, and implement it as per-value provenance rather than a request flag.
- [ ] I can name the three indirect-ingress paths into an agent loop and the control that addresses each.
- [ ] I can pick the right validation for a path, a host, a recipient, a query parameter, and free text — and say which of them has no allow-list at all.
- [ ] I can state the sandbox's four claims (filesystem, egress, identity, resources) and the observation that would falsify each.
- [ ] I can explain why approval is a dispatcher property, and why gating a tool is not the same as gating an effect.
- [ ] I can describe what an agent's memory writes, who can read it later, and when it expires.
- [ ] I can name the fields a run trace needs so that an investigator can answer "what did the system see, what did it decide, and who asked for it" from the trace alone.
- [ ] For every control in this phase, I can name the drill that produces its evidence — and I have run at least one of them and recorded the result.

> **Verification:** the `dispatch()` block was extracted **verbatim from this file** and executed
> on **2026-09-19** under Ubuntu 24.04 / Python 3.12.3, with a stub tool registry standing in for
> the `TOOLS` the block refers to. All three branches behave as documented: an argument with **no**
> recorded source raises `PermissionError: send_email.cc: value has no known source`; a value whose
> source is `tool_result` raises `PermissionError: … value came from tool_result`; a complete set of
> user-turn sources reaches the tool; and a tool absent from `SINK_ARGUMENTS` is called with no
> provenance check at all. The argument named in the error varies with set iteration order — it
> reported `cc` when only `to` was unsourced — so do not build a log format on that string. No
> agent runtime, model or tool server exists here, so the run trace, the four sandbox claims and
> every drill in the agent-abuse lab remain unmeasured on this machine.

## Further Resources

- OWASP Top 10 for Large Language Model Applications (2025 edition) — https://owasp.org/www-project-top-10-for-large-language-model-applications/
- OWASP Top 10 for Agentic Applications for 2026 — https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ — the agentic risk set this phase's vocabulary follows; released 9 December 2025 (https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
- MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) — https://atlas.mitre.org/
- NIST AI Risk Management Framework — https://www.nist.gov/itl/ai-risk-management-framework
- OWASP Cheat Sheet Series — https://cheatsheetseries.owasp.org/
