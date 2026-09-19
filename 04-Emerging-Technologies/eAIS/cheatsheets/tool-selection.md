# AI Security Tool Selection — Cheatsheet

> eAIS · Cheatsheet — INE-Cybersecurity-Certifications-Guide · English
>
> Which tool for which job, decided in tables: what each category targets, the artifact it produces, when to
> reach for it and when not to, what it costs in setup and blast radius, and the combinations that survive real
> constraints. Every command shape here is *syntax to confirm against your own version's `--help`* — no version,
> flag or product feature is asserted in this sheet.

> **Nothing in this file was executed.** No command, scan or query here is captured output: the environment
> where this sheet was written had no AI application to test, no scanner installed and no API keys. The command
> lines are shapes to adapt and confirm against your own version's documentation.

## How to read this sheet

- **Categories, not products.** Products in one category overlap and get renamed; the workflow you need is what
  the table describes. Names appear only as examples of the category ([ai-testing-tools.md](../tools/ai-testing-tools.md)
  covers them individually).
- **The last two columns are the decision.** "Choose it when" and "do not choose it when" are what prevent the
  expensive mistake of buying effort in the wrong place.
- **Verify syntax before scripting.** Subcommands and flags move between releases; treat every command as a
  shape and confirm it on your build.
- **Authorization is a precondition, not a footnote.** Test only systems you own or are explicitly authorized
  to test, and check model-provider terms before automating anything against their API.

## The comparison table

| Tool / category | Category | What it targets | Language / ecosystem | Artifact it produces | Choose it when | Do NOT choose it when |
| --- | --- | --- | --- | --- | --- | --- |
| **garak** | Prompt-fuzzing scanner | A model endpoint or local model, as a black box | Python CLI, pluggable probe sets | A scan report of which probe families failed | You need a fast first-pass health check of a model or endpoint | You need to prove app-level impact (tools, RAG, permissions) — a scanner sees model I/O only |
| **Microsoft PyRIT** | Orchestrated red-team framework | A target endpoint, driven by scripted attack pipelines | Python library, attacker/scorer object model | A scripted campaign with scored responses, re-runnable after each change | You want reproducible campaigns and comparable scores across model or rail versions | You need a quick answer today — the object model takes real time to learn |
| **Promptfoo** | Evaluation + red-team CLI | Prompts, RAG wiring, agent configs, defined as declarative config | Node.js CLI, YAML configs, CI-friendly | A pass/fail matrix across cases and providers, plus generated attack suites | The work is regression testing in CI, or comparing prompt/model variants systematically | You are researching adversarial examples or attacking a classifier's decision boundary |
| **TextAttack** | Adversarial robustness library | NLP classifier models (decision boundaries), not chat assistants | Python, research-oriented, model+dataset centric | Crafted adversarial examples and robustness measurements | You are studying evasion against a classifier in your stack | You want evidence about jailbreak or injection resistance of an assistant |
| **Evaluation frameworks** (DeepEval, Giskard, OpenAI Evals) | Test harness for behaviour | Your app's outputs against expected behaviour, with scoring | Python (mostly), some with CI integrations | A scored, versioned suite result: pass rates, regressions, diffs per run | You need a safety or quality gate that runs on every change | You have no expected labels yet — a framework with no cases measures nothing |
| **Guardrails** (NeMo Guardrails, Guardrails AI, Llama Guard) | Runtime control | Live inputs, outputs and (where supported) retrieved content | Python/config-driven, sits in the request path | Enforced policy at runtime plus allow/block/rewrite verdicts and events | You are deploying, and you need a control that acts rather than a report that describes | You are still arguing about what "safe" means — a rail encodes a policy you must have first |
| **Vector-store / retrieval inspection** | Data-path review | The index, its metadata filters, and the retrieval step itself | Your store's query interface plus scripts (Jupyter/pandas for analysis) | Evidence of what a given identity can retrieve, and of filter behaviour per query | You are assessing RAG security, tenancy, ACLs or poisoning exposure | You want to test the model — retrieval review says nothing about model behaviour |
| **Observability / tracing** | Runtime evidence | The request tree: retrieval, model calls, tool calls, rail verdicts, cost, outcome | Whatever your stack emits; analysis in a notebook or the store's query surface | Per-request traces, detections, and the corpus for evaluation cases | You need to answer "why did it do that?", detect behaviour, or measure a control | You have nothing wired yet and no schema — start with the schema, not the vendor |

## What each category can and cannot see

Choosing a tool is really choosing a *view* of the system. Pick the one whose blind spot you can afford.

| Category | What it can see | Structural blind spot |
| --- | --- | --- |
| Prompt-fuzzing scanner | Model input and output for the prompts it sends | Your app's wiring: tools, retrieval, permissions, and what real user traffic looks like |
| Orchestrated campaign | Behaviour of a target across many scripted attempts, with scores | Anything you did not script; it cannot discover an architectural flaw |
| Evaluation framework | Whether the cases you defined pass or fail | Cases you never wrote — it measures, it does not explore |
| Adversarial robustness library | One classifier's decision boundary under perturbation | Conversational instruction hierarchy; nothing about tools, RAG or permissions |
| Guardrails | The content that passes through them, at runtime | Paths where the rail is not installed, and the intent behind the text it allows |
| Retrieval / vector-store inspection | Index contents, metadata, and filter behaviour for a given identity | What the model then does with what it retrieved |
| Observability / tracing | The request tree your own instrumentation emits | Anything uninstrumented, the provider's internals, and causality |
| Manual architecture review | Design intent and configuration as written | Whether the design is what actually runs at 2 a.m. |
| Notebook analysis (Jupyter/pandas) | Shape, distribution and periodicity of the data you exported | Live state, and anything you did not export |

## Question → tool → first move

First moves are *shapes*. Confirm subcommands and flags with `<tool> --help` on your own version before
scripting them, and point them at a local model or a staging copy first.

| Work question | Tool / category | First move (confirm syntax in your version) |
| --- | --- | --- |
| "Does this endpoint fail on direct prompt injection?" | Prompt-fuzzing scanner | Install, list the available probe sets, then run the injection-oriented probes against a local model before an endpoint you care about. |
| "My app has never been tested — where do I start?" | Lab + scanner | Stand up the local target from [labs/llm-testing.md](../labs/llm-testing.md), run one probe family against it, and label the results with the lab's rubric. |
| "Does my guardrail hold against *new* variants?" | Orchestrated campaign | Take one payload that succeeded, script N variations of it, send each through the rail, and score block/allow per variant rather than eyeballing. |
| "Did the new prompt or model regress safety?" | Evaluation framework | Replay the versioned case set before and after the change and diff the pass rate; keep the case file immutable. |
| "Does the index leak across tenants?" | Vector-store / retrieval inspection | Query the store as tenant A for a document you know belongs to B, then read the retrieval span's `acl_checked_as` to see which identity actually filtered. |
| "Why did the assistant answer *that* on Tuesday?" | Observability / tracing | Pull the trace by request or conversation id, read spans in time order, and note which span kinds are missing before claiming anything. |
| "Is the agent's tool access too broad?" | Manual review + trace evidence | Enumerate the tool registry and each tool's scopes, then compare with the scopes actually exercised in a week of traces; the gap is the finding. |
| "Is anyone using the assistant for extraction or distillation?" | Tracing + quota analysis | Aggregate traces per key per day for token volume against prompt diversity; a flat spike is a script, a diverse one is probing. |
| "Are poisoned documents reachable by retrieval?" | Retrieval inspection + lab | Seed a synthetic document into a copy of the corpus and measure whether a benign question pulls it into context. |
| "Is the model itself robust to text perturbation?" | Adversarial robustness library | Pick a classifier in your stack and run one recipe against it; do not generalise the result to a chat assistant. |
| "Which of my controls actually fired last month?" | Tracing | Count rail verdicts by version and by request path; a path with zero verdicts is an uninstrumented control, not a safe one. |
| "Can I prove a control improved anything?" | Evaluation framework + tracing | Fix a baseline (case set + trace-derived cases), change one control, re-run, and report the delta with the pins (template, model, rail versions). |

```bash
# Shape of a first move — NOT a working recipe. Confirm every flag on your build.
# 1) local target, no cost, no terms-of-service risk:
#      start the lab app from ../labs/llm-testing.md (local model + minimal chat endpoint)
# 2) one probe family against it:
#      <scanner> --help                       # find the current probe/target selectors
#      <scanner> <target> <probe-set>          # names differ per release
# 3) record what happened, not what you hoped:
#      prompts.jsonl  -> one case per line, with an id and a class
#      results.jsonl  -> one result per line, with the label from the rubric
```

## Reading a result honestly

| The result you got | What it usually means | Do this next |
| --- | --- | --- |
| A scan reports zero failures | Your probe set does not cover your app's real risk (tools, RAG, permissions), or the target was misconfigured and answered nothing | Confirm the target actually replied, then add app-level cases rather than more probes of the same kind |
| Failures cluster in one probe family | That family matches a genuine weakness, or a client integration is configured badly | Reproduce one case by hand, fix the control or the client, then re-run the *same* set to compare |
| Two runs disagree on the same target | Non-determinism, or a config/sampling change between runs | Pin decoding and configuration, record them with the result, and treat single-run deltas as noise |
| The rail blocks almost everything | Over-blocking: the control is failing the product even if it passes the security test | Measure false positives on benign traffic before shipping, then tune the threshold |
| Every case passes right after a prompt edit | Possibly a benchmark the prompt was optimised against | Hold out cases you did not tune on, and re-run the suite from the frozen case file |
| A rubric labels a reply `leaked` | Could be a real disclosure, or a paraphrase of something public | Keep the raw reply as evidence and have a second person label it before reporting |
| The run ended on budget or rate limits | Partial coverage that will be reported as if it were complete | Make the runner record coverage and failures explicitly; a truncated run is not a pass |

```text
# Suggested order when every tool in this module is new to you
1. local model + the lab app (../labs/llm-testing.md)  -> run anything with no cost and no terms-of-service risk
2. one scanner, one probe family                       -> vocabulary for what failure looks like
3. one evaluation suite with ~10 labelled cases         -> the regression habit, before the tooling
4. one guardrail in shadow mode, same cases re-run      -> a before/after delta you can actually quote
5. retrieval and ACL review with a fake tenant          -> the data path, which no scanner sees
6. a tracing schema plus one trace-derived detection    -> evidence, alerting, and the corpus loop
```

## Effort, cost, and blast radius

| Tool / category | Cost per query | Setup time | Risk of touching production | Isolation required |
| --- | --- | --- | --- | --- |
| Scanner vs. local model | None beyond your own compute | Minutes | None (nothing leaves the machine) | Local model, no network access needed |
| Scanner vs. hosted endpoint | Per-token billing, multiplied by probe volume | Minutes | High: terms of service, rate limits, and your payloads leaving your boundary | Throwaway key with a hard spend cap, never a production key |
| Orchestrated campaign | Can run to thousands of model calls per campaign | Hours to days (learn the object model) | High: volume, plus attack content in provider logs | Staging copy, budget cap, and a stop condition defined before the run |
| Evaluation suite in CI | Per-token per case per pipeline run | Hours to wire, minutes to run | Medium: it runs on every change and may hit a paid endpoint | Cached or replayed outputs, dedicated key, non-production data |
| Guardrails in the request path | Adds latency and often extra model calls per request | Hours to days, including policy definition | Medium-high: it sits between users and answers; fail-open vs. fail-closed is a product decision | Shadow mode first, then a canary path |
| Vector-store inspection | Near zero compute; the query itself is cheap | Hours (learn the metadata and filter model) | Medium: reads against a production index reveal production content | Read-only credentials, a test tenant, and a written scope |
| Tracing / observability | Storage and a small latency cost per request | Days: schema, redaction, retention, ACLs, sampling rules | Low-medium: the risk is the payload store becoming a data leak, not the app breaking | Separate payload store with its own access role |
| Adversarial robustness library | Local compute only | Hours per model and dataset | Low | Local models and public datasets; no production traffic |
| Notebook analysis (Jupyter/pandas) | None | Minutes | Medium: exported data in an unmanaged place | Local, ephemeral workspace; never production credentials or customer data |

## Do not use X for Y

| Mismatch | Why it fails | Use instead |
| --- | --- | --- |
| A prompt scanner to find a tool with excessive permissions | Scanners observe model input and output; a granted scope is invisible in both | Tool registry review plus trace evidence of what the tool actually reached |
| A guardrail as a substitute for retrieval ACLs | The rail sees text *after* retrieval; by then the unauthorised document is already in context | Permission filtering at retrieval time (see [methodology/05-defensive-controls.md](../methodology/05-defensive-controls.md)) |
| A quality evaluation as a security measurement | Quality metrics have no adversarial label, so a passing suite says nothing about attack resistance | Security cases with expected-safe labels, scored separately from quality |
| An adversarial robustness library for a chat assistant's injection resistance | It perturbs inputs to flip a classifier's decision; it says nothing about instruction hierarchy | A scanner or orchestrated campaign against the deployed app |
| A campaign without scoring as a regression gate | Unscored results cannot be compared across runs, so nothing is gated | A scorer plus a versioned case set |
| Tracing as a detection engine by itself | Spans are evidence, not alerts; nothing notifies anyone | Written rules with baselines over trace fields, plus a review path |
| A small local model's failure as evidence about production | Different model, different refusals, different context handling | Test the deployed model and configuration in staging |
| An output deny-list as a data-loss control | It encodes only the strings you already knew about | Least privilege, egress allow-lists, and trace-based monitoring |
| A one-off scan as proof a system is secure | Scanners miss whole categories (permissions, RAG tenancy, tool abuse) | Layered evidence: scan + retrieval review + manual architecture review + traces |
| A notebook with exported production data as the analysis environment | It becomes an unmanaged copy of sensitive data with no retention or ACL | Anonymised exports, local ephemeral workspace, or analysis in the platform of record |

## Choosing under constraints

| Constraint | Recommended combination | Why this set | What you give up |
| --- | --- | --- | --- |
| Laptop only: no GPU, no budget | Small local model (Ollama) + the minimal lab app + a scanner's local probe sets + manual tool-scope review + a file-based trace store you wrote yourself | Every piece runs offline and free; the smallest viable loop is scan → label → fix → re-scan | Frontier-model behaviour, large-volume campaigns, provider-specific quirks |
| Near-zero budget but a hosted API is available | One throwaway key with a hard spend cap; a handful of declarative evaluation cases run on demand; hand-written variants instead of generated suites; guardrail in shadow mode | Cost scales with cases, so keep the case set small, versioned and meaningful | Statistical confidence and broad coverage — report it as a limitation, not a pass |
| Regulated environment: no real data may leave | Local models plus a synthetic corpus; evaluation cases synthesised from trace *shapes*; tracing schema designed (redaction, retention, ACLs) before the first payload is stored; fake tenants for ACL tests | Nothing sensitive exists to leak, and the controls are tested against their structural properties | Retrieval realism and real-world phrasing — document this gap in every finding |
| Black-box target: third-party app, no source, no cooperation from its team | Cases driven through the public interface with an evaluation suite; tracing at *your* gateway or client; a review of what your account, key or integration is actually allowed to do | It is the only honest option when you cannot see or change the inside, and it still produces findings about the parts you control | Retrieval provenance, rail verdicts, tool internals, and any claim about provider-side filtering |

Three follow-ups that decide whether the above works:

| Follow-up | What to write down | Why it changes the choice |
| --- | --- | --- |
| Spend ceiling | A hard cap per key and per run | Without it, a campaign or a CI suite becomes an incident of its own |
| Data boundary | What may leave the machine, and to whom | It eliminates whole categories before you evaluate them |
| Stop condition | The evidence that ends the test | Unplanned tests drift towards production, or never finish |

## Pairing tools

| Pairing | What the combination gives you | What neither gives you alone |
| --- | --- | --- |
| Scanner + orchestrated campaign | A broad first pass, then depth on the families that actually failed | Coverage at volume (scanner) or reproducibility of a specific attack (campaign) |
| Evaluation suite + guardrail | A measurable policy change: cases define the expectation, the rail enforces it | A regression gate, or runtime enforcement |
| Tracing + detection rules | Behaviour you can both see and be told about | Evidence without alerting, or alerts with no way to investigate |
| Retrieval inspection + tracing | Proof of *what* an identity could retrieve and *what* it actually retrieved | Data-path correctness, or observed behaviour |
| Lab + any offensive tool | A target where failure is free, before anyone points a tool at production | Safe iteration, or realistic scale |
| Robustness library + evaluation suite | Classifier-level findings converted into labelled cases that gate releases | Model-level robustness, or a release gate |
| Notebook + traces | Shape, distributions and periodicity across real traffic | Aggregation over raw event streams, or a defensible single-request chain |

### Record the decision, not just the run

A chosen tool is an assumption about coverage; write it down where the next person will find it, with what it
does *not* cover. One line per decision is enough:

```jsonl
{"decision":"scanner for endpoint health check","date":"<date>","target":"<staging-endpoint>","why":"fast first pass",
 "cost_ceiling":"<cap>","authorization":"<who approved the test>","not_covering":"tools, retrieval, tenancy",
 "next":"campaign on the injection family that failed"}
{"decision":"tracing as the evidence source","date":"<date>","scope":"<app>","fields":"<schema ref>",
 "redaction":"<field list>","retention":"<metadata/payload windows>","not_covering":"provider internals, uninstrumented paths",
 "next":"one trace-derived detection, then convert two traces into cases"}
```

## Module map — where this file sits

Reading order for the eAIS module, relative to this directory. Every path in the table is a link to a file that exists in this checkout.

| Area | Files |
| --- | --- |
| Overview | [README.md](../README.md) |
| Methodology (reading order) | [01-ai-models.md](../methodology/01-ai-models.md), [02-prompt-injection.md](../methodology/02-prompt-injection.md), [03-model-poisoning.md](../methodology/03-model-poisoning.md), [04-adversarial-attacks.md](../methodology/04-adversarial-attacks.md), [05-defensive-controls.md](../methodology/05-defensive-controls.md), [06-agent-and-tool-security.md](../methodology/06-agent-and-tool-security.md), [07-privacy-and-data-leakage.md](../methodology/07-privacy-and-data-leakage.md), [08-evaluation-and-continuous-red-teaming.md](../methodology/08-evaluation-and-continuous-red-teaming.md), [09-ai-governance-and-lifecycle.md](../methodology/09-ai-governance-and-lifecycle.md) (01–09 in total) |
| Tools | [ai-testing-tools.md](../tools/ai-testing-tools.md), [evaluation-and-guardrails.md](../tools/evaluation-and-guardrails.md), [observability-and-tracing.md](../tools/observability-and-tracing.md), [offensive-scanners.md](../tools/offensive-scanners.md), [rag-and-vector-store-security.md](../tools/rag-and-vector-store-security.md) |
| Labs | [llm-testing.md](../labs/llm-testing.md), [injection-lab.md](../labs/injection-lab.md), [agent-tool-abuse-lab.md](../labs/agent-tool-abuse-lab.md), [guardrail-evaluation-lab.md](../labs/guardrail-evaluation-lab.md), [rag-data-leakage-lab.md](../labs/rag-data-leakage-lab.md), [data-poisoning-lab.md](../labs/data-poisoning-lab.md) |
| Cheatsheets | [ai-attack-vectors.md](ai-attack-vectors.md), [tool-selection.md](tool-selection.md) (this file), [attack-to-control-mapping.md](attack-to-control-mapping.md), [llm-test-case-library.md](llm-test-case-library.md) |

## Common Mistakes & Tips

- **Choosing by label instead of workflow.** "Red teaming tool" covers a scanner, an orchestrator and a CI test
  suite; only one of them fits the job in front of you.
- **Treating defaults as a security baseline.** Default probe sets, default rails and default thresholds are
  starting points tuned for someone else's system.
- **Copying flags from a blog post or from this sheet.** Verify against `--help` on your own build; a wrong
  flag looks like a clean result.
- **Pointing a tool at production or a third-party API without authorization.** Terms of service, rate limits
  and data boundaries are all part of the decision, not paperwork around it.
- **Measuring only quality.** A suite that never asks an adversarial question reports green on a system with no
  injection defenses at all.
- **Buying observability without a schema.** Traces you cannot join by id answer nothing; define the fields
  first ([observability-and-tracing.md](../tools/observability-and-tracing.md)).
- **Reading a clean scan as a clean system.** No scanner sees an over-permissioned tool, a mis-scoped index or
  an unlogged rail.
- **Skipping the write-up.** A tool run without a labelled result, a version pin and a finding is an anecdote.

## Checklist / Self-Test

- [ ] I can name the eight categories in the comparison table and the workflow each one serves.
- [ ] For three different work questions, I can name the category I would start with and why.
- [ ] I can state, for each category, at least one thing it structurally cannot see.
- [ ] I can pick the right tool for "does the rail survive new variants" versus "did quality regress".
- [ ] I can estimate cost, setup time and blast radius for a run before I start it, and I set a spend cap.
- [ ] I can name three bad pairings (X for Y) and the correct substitute for each.
- [ ] I can choose a viable combination for a laptop-only, a near-zero-budget, and a regulated environment.
- [ ] I have confirmed one tool's current syntax on my own build instead of trusting a remembered command.
- [ ] I can explain why a clean scan is not evidence of a secure system.
- [ ] Every test I run targets a system I own or am explicitly authorized to test.

## Further Resources

- OWASP Top 10 for Large Language Model Applications — https://owasp.org/www-project-top-10-for-large-language-model-applications/
- OWASP GenAI Security Project — https://genai.owasp.org/
- MITRE ATLAS — https://atlas.mitre.org/
- NIST AI Risk Management Framework — https://www.nist.gov/itl/ai-risk-management-framework
- The individual tool repositories and their own documentation — the only source for current flags, targets
  and supported integrations (see the references in [ai-testing-tools.md](../tools/ai-testing-tools.md)).
- Your own environment's documentation: the vector store, the tracing stack and the CI system you will actually
  run these tools in.
- INE Security — eAIS (AI Systems Security Specialist) — https://ine.com/security/certifications/eais-certification

**Test only what you own or are authorized to test, and keep the lab's data fictional.**
