# eAIS — AI Systems Security Specialist (Study Guide)

> Area: 04-Emerging-Technologies · INE-Cybersecurity-Certifications-Guide · English

## What is the eAIS certification about?

INE Security's **eAIS (AI Systems Security Specialist)** credential, released on
**23 June 2026**, focuses on the *practical* security of AI systems — most visibly
applications built on large language models (LLMs). Where a traditional
penetration-testing certification attacks servers and web apps, eAIS is about attacking
and defending the AI application layer: the prompts, the models, the data they are
trained or retrieved from, and the tools and agents they can invoke.

INE's public material for eAIS describes it as building practical, hands-on AI security
readiness. **It does not publish an official domain list for this credential**, and this
repository does not invent one: the five areas below are **this module's own scope** — the
map *we* chose for the material, derived from the public description and from what the labs
actually exercise. Treat them as a study plan, not as an exam blueprint, and read the
official certification page for anything authoritative.

The scope this module covers:

- **Prompt injection** — tricking a model into ignoring its instructions or acting on
  attacker-controlled text. Phases 02 and the injection lab.
- **Retrieval-Augmented Generation (RAG) security** — poisoning or abusing the documents
  and vector stores an application retrieves answers from. Phases 03 and 07, plus the
  RAG-leakage and poisoning labs.
- **Tool and agent misuse** — abusing the functions, plugins, or APIs an AI application is
  allowed to call. Phase 06 and the agent-abuse lab.
- **Data and model poisoning** — contaminating training, fine-tuning, or prompt data to
  steer behavior. Phase 03 and the poisoning lab.
- **Safe operational use of AI** — the controls, monitoring, review, and governance that
  keep AI applications safe in production. Phases 05, 08, and 09.

The spirit of the credential is *hands-on*: you are expected to understand the attack
surface of an AI application, reproduce representative attacks in a sanctioned lab, and
recommend proportionate defenses. That much the public description does support, and it is
the shape this module is built around.

> **NDA note:** INE exams are protected. This repository intentionally describes only the
> *public* skill areas and general practice of AI security — never specific exam
> questions, scenarios, or answers. Use it to build durable skills, not to shortcut the
> exam.

## Skills you will build

| Skill area | What you will be able to do |
| --- | --- |
| AI fundamentals | Explain tokens, context windows, system vs. user messages, fine-tuning, embeddings, and RAG well enough to reason about their security impact. |
| Threat modeling for AI | Enumerate the attack surface of an AI application and map risks to frameworks such as the OWASP LLM Top 10 and MITRE ATLAS. |
| Offensive practice | Write and run controlled tests for prompt injection, jailbreaks, data poisoning, extraction/inversion, and evasion in your own sandbox. |
| Defensive practice | Apply input/output filtering, guardrails, least-privilege tool access, RAG hygiene, and evaluation-driven regression testing. |
| Tooling | Use AI security tooling (garak, Microsoft PyRIT, Promptfoo, TextAttack, guardrails) and know when to reach for each. |
| Reporting | Turn raw results into clear findings with severity, evidence, and a recommended control — the mindset every security certification rewards. |

## How to use this module

The module mirrors the folder layout used across this repository:

```text
eAIS/
├── README.md                                       <- this overview, index, and roadmap
├── methodology/                                    <- nine phases, in reading order 01 → 09
│   ├── 01-ai-models.md                             <- AI/ML literacy: tokens, context, RAG, fine-tuning
│   ├── 02-prompt-injection.md                      <- direct/indirect injection and jailbreaks
│   ├── 03-model-poisoning.md                       <- poisoning of training, fine-tune, and RAG data
│   ├── 04-adversarial-attacks.md                   <- extraction, inversion, evasion, privacy leaks
│   ├── 05-defensive-controls.md                    <- control catalogue, permissions, approval, logs
│   ├── 06-agent-and-tool-security.md               <- the dispatch boundary, tools, arguments, sandbox
│   ├── 07-privacy-and-data-leakage.md              <- data planes, embeddings as data, deletion
│   ├── 08-evaluation-and-continuous-red-teaming.md <- corpus, metrics, cadence, regression gates
│   └── 09-ai-governance-and-lifecycle.md           <- ownership, gates, change control, evidence
├── tools/                                          <- five command-and-diagnosis notes
│   ├── ai-testing-tools.md                         <- tool categories and how to pick a tool
│   ├── offensive-scanners.md                       <- garak, PyRIT, Promptfoo: runs and reading them
│   ├── evaluation-and-guardrails.md                <- behaviour tests and measuring a guardrail
│   ├── rag-and-vector-store-security.md            <- inspecting an index; retrieval-time authorization
│   └── observability-and-tracing.md                <- span shape, redaction, retention, detection
├── labs/                                           <- six runnable drills
│   ├── llm-testing.md                              <- safe local lab + guided red-team drills
│   ├── injection-lab.md                            <- direct, obfuscated, multi-turn, retrieved-content
│   ├── agent-tool-abuse-lab.md                     <- six drills against a stub-tool agent loop
│   ├── rag-data-leakage-lab.md                     <- tenants, metadata, chunking, canary, deletion
│   ├── data-poisoning-lab.md                       <- influence vs. adoption in a retrieved corpus
│   └── guardrail-evaluation-lab.md                 <- measure block rate, false positives, bypass
└── cheatsheets/                                    <- four compressed references
    ├── ai-attack-vectors.md                        <- compact reference of attack vectors
    ├── attack-to-control-mapping.md                <- vector → control → how it is proved
    ├── tool-selection.md                           <- which tool for which job, decided in tables
    └── llm-test-case-library.md                    <- case skeletons by family, with a rubric
```

Work the folder in the order above: concepts first, then tools, then lab practice, and
keep the cheatsheets open while you drill. Re-read files instead of memorizing them —
security is about *doing*, so the labs are the heart of this module.

## Module contents

The module is **twenty-four notes plus this index**: nine methodology phases, five tool
notes, six labs, and four cheatsheets. Every file is linked below.

### Methodology — nine phases, read in order

The phases are numbered on purpose. Each one assumes the vocabulary and the decisions of
the ones before it: 02–04 catalogue attacks, 05 chooses the controls, 06 is about the
authority those controls bound, 07 is about the data that authority can reach, and 08–09
turn the whole thing into a programme you can measure and prove.

| Phase | File | What it covers |
| --- | --- | --- |
| 01 | [01-ai-models.md](methodology/01-ai-models.md) | Tokens, context windows, system vs. user messages, fine-tuning, embeddings, and RAG as a trust boundary — the vocabulary the rest of the module assumes. |
| 02 | [02-prompt-injection.md](methodology/02-prompt-injection.md) | Direct and indirect injection, the channels an instruction can arrive through, jailbreak families, multi-turn accumulation, and how to measure injection success. |
| 03 | [03-model-poisoning.md](methodology/03-model-poisoning.md) | Poisoning of training, fine-tuning, and retrieved data: backdoor triggers, corpus hygiene, and artifact provenance. |
| 04 | [04-adversarial-attacks.md](methodology/04-adversarial-attacks.md) | Extraction, membership inference and inversion, adversarial evasion, and the attack-success-rate metrics that make them comparable. |
| 05 | [05-defensive-controls.md](methodology/05-defensive-controls.md) | Defense-in-depth layers, a control catalogue that names what each control does *not* stop, the agent permission model as a table, human approval that works, the fields a decision log needs, and the release gate. |
| 06 | [06-agent-and-tool-security.md](methodology/06-agent-and-tool-security.md) | Where a model's decision becomes an action: the dispatch boundary, excessive agency, tool confusion, call chaining and composite authority, per-value provenance against indirect injection through tools, argument allow-lists, runtime isolation, agent memory, and the run trace. |
| 07 | [07-privacy-and-data-leakage.md](methodology/07-privacy-and-data-leakage.md) | The six data planes of an AI system, why embeddings are personal data, leakage measurement with canaries, and what can honestly be deleted. |
| 08 | [08-evaluation-and-continuous-red-teaming.md](methodology/08-evaluation-and-continuous-red-teaming.md) | A versioned attack corpus, how to report a non-deterministic result honestly, metrics with mandatory budgets, differential testing across model/prompt/tool changes, cadence, and the loop from finding to permanent test case. |
| 09 | [09-ai-governance-and-lifecycle.md](methodology/09-ai-governance-and-lifecycle.md) | Ownership and decision rights, the inventory an AI system needs, release gates with named approvers, change control for prompts and models, incident playbooks, and evidence retention. |

### Tools — five notes on commands and diagnosis

| File | What it covers |
| --- | --- |
| [ai-testing-tools.md](tools/ai-testing-tools.md) | The categories of AI security tooling, how to stand up a local target, and a conceptual overview of the well-known projects. |
| [offensive-scanners.md](tools/offensive-scanners.md) | garak, Microsoft PyRIT, and Promptfoo in depth: what each produces, how to read a report without over-reading it, where each fails, and how to keep two runs comparable. |
| [evaluation-and-guardrails.md](tools/evaluation-and-guardrails.md) | Turning a finding into a repeatable behaviour test, assertions that measure behaviour rather than wording, and how to measure a guardrail's block rate, false positives, and bypass — including the failure path nobody tests. |
| [rag-and-vector-store-security.md](tools/rag-and-vector-store-security.md) | The retrieval path as a security surface: what an index actually holds, inspection recipes, why filtering *after* top-k is already a leak, ingestion as an attack surface, and index integrity. |
| [observability-and-tracing.md](tools/observability-and-tracing.md) | The span shape worth capturing, the redaction, retention, and sampling decisions behind it, incident reconstruction, detection signals, and where tracing stops helping. |

### Labs — six runnable drills

| File | What it drills |
| --- | --- |
| [llm-testing.md](labs/llm-testing.md) | The base lab the other drills build on: a local model and a minimal chat target, plus guided red-team drills. |
| [injection-lab.md](labs/injection-lab.md) | Six drills that turn injection into a measurement: direct, obfuscated, multi-turn, and retrieved-content delivery — then quarantining untrusted content and re-measuring honestly. |
| [agent-tool-abuse-lab.md](labs/agent-tool-abuse-lab.md) | Six drills against a lab agent with stub tools behind an allow-list: confused deputy, tool confusion, argument injection, tool output treated as an instruction, unbounded consumption, and hardening with re-measurement. |
| [rag-data-leakage-lab.md](labs/rag-data-leakage-lab.md) | Six drills that make a retrieval application leak on purpose: cross-tenant retrieval, a filter applied too late, access control living in metadata that may be missing, chunk overlap, canary measurement, and a stale index. |
| [data-poisoning-lab.md](labs/data-poisoning-lab.md) | Six drills that separate *influence* (the attacker's document is being retrieved) from *adoption* (the answer changed because of it), plus artifact provenance with no GPU. |
| [guardrail-evaluation-lab.md](labs/guardrail-evaluation-lab.md) | Build a deliberately weak guardrail and measure it honestly: what it blocks, what legitimate traffic it destroys, how it behaves against variants it has never seen, and the regression gate that follows. |

### Cheatsheets — four compressed references

| File | What it compresses |
| --- | --- |
| [ai-attack-vectors.md](cheatsheets/ai-attack-vectors.md) | The vector catalogue — injection, jailbreaks, poisoning, extraction, evasion, tool abuse, retrieval manipulation and more — each with an educational pattern and a symptoms table. |
| [attack-to-control-mapping.md](cheatsheets/attack-to-control-mapping.md) | Every vector mapped to a primary control, a compensating control for when the primary fails, the test that proves the control is present, and the false-confidence signal. |
| [tool-selection.md](cheatsheets/tool-selection.md) | Which tool for which job, decided in tables: what each category targets, when to choose it and when not to, and what it costs in setup and blast radius. |
| [llm-test-case-library.md](cheatsheets/llm-test-case-library.md) | Reusable case skeletons across sixteen families, with a case schema, corpus management, and a scoring rubric. |

## Study roadmap

1. **Build AI literacy ([methodology/01](methodology/01-ai-models.md)).** If you cannot
   explain a context window, you cannot explain a prompt injection. Spend one or two
   sessions here before anything else.
2. **Learn the attack categories ([methodology/02–04](methodology/02-prompt-injection.md)).**
   Read the prompt-injection, poisoning, and adversarial notes with the OWASP LLM Top 10
   open alongside; map each category to the framework entries as you go.
3. **Study the defenses ([methodology/05](methodology/05-defensive-controls.md)).** For every
   attack you learned, note the primary defense and one tool that can test whether it works —
   including what the control does *not* stop.
4. **Bound what the agent can do ([methodology/06](methodology/06-agent-and-tool-security.md)).**
   This is the phase with the largest reachable impact: the dispatch boundary, the tool set,
   argument validation, and the sandbox. Do it before you look at payloads again.
5. **Follow the data ([methodology/07](methodology/07-privacy-and-data-leakage.md)).** Inventory
   the planes, then decide what can be deleted and what cannot — honestly.
6. **Turn it into a programme ([methodology/08](methodology/08-evaluation-and-continuous-red-teaming.md)).**
   A corpus, a measurement convention, and a threshold declared before you run the suite.
7. **Put it under governance ([methodology/09](methodology/09-ai-governance-and-lifecycle.md)).**
   Owners, gates, and evidence, so the controls you built survive the next release.
8. **Get hands-on with tools ([tools/ai-testing-tools.md](tools/ai-testing-tools.md),
   [tools/offensive-scanners.md](tools/offensive-scanners.md)).** Install one scanner (garak
   or Promptfoo) and run it against a local model so the concepts become muscle memory.
9. **Run the lab drills ([labs/llm-testing.md](labs/llm-testing.md)).** Start with the base
   lab, then the drill that matches the phase you are weakest on. Repeat them from memory —
   this is the closest practice to the exam's hands-on nature.
10. **Consolidate with the cheatsheets
    ([cheatsheets/ai-attack-vectors.md](cheatsheets/ai-attack-vectors.md),
    [cheatsheets/attack-to-control-mapping.md](cheatsheets/attack-to-control-mapping.md)).**
    Use them in the days before the exam for fast recall of vector → control → how it is proved.
11. **Final pass.** Re-read the checklist/self-test at the bottom of each file; anything you
    cannot check off is a sign to revisit that file's lab.

Suggested cadence: 6–8 weeks at a few hours per week, or a compressed 2-week sprint if you
already know web/application security and only need the AI-specific material.

## Common Mistakes & Tips

- **Skipping fundamentals.** Jumping straight to jailbreak payloads without understanding
  how system prompts, RAG, and tool calls work produces shallow, non-transferable skills.
- **Testing without authorization.** Only attack systems you own or have written
  permission to test — including third-party model APIs, whose terms of service usually
  forbid red teaming. Keep everything in a local lab or your own sandbox account.
- **Memorizing payloads.** Public jailbreak prompts burn out quickly. Learn the *classes*
  of failure (goal hijacking, refusal suppression, indirect injection) and how to craft new
  variants.
- **Ignoring defenses.** Offense without defense is half the syllabus. For every technique
  you practice, write down the control that mitigates it.
- **Skipping measurement.** A red-team session without logged prompts, outcomes, and a
  pass/fail rubric teaches you nothing. Treat it like a pentest report, not a chat.
- **Using production keys.** Never point lab tools at real API keys or company data. Use a
  local model or a throwaway, spend-limited key.

## Checklist / Self-Test

- [ ] I can explain tokens, context windows, fine-tuning, embeddings, and RAG in my own words.
- [ ] I can name the main AI attack categories and map each to OWASP LLM Top 10 entries.
- [ ] I can explain the difference between direct and indirect prompt injection.
- [ ] I can explain how data poisoning can reach an application through training, fine-tuning, and RAG data.
- [ ] I have run at least one automated AI security scanner against a model I control.
- [ ] I have completed the guided drills in `labs/llm-testing.md` and recorded their outcomes.
- [ ] For every attack I practice, I can name a concrete defense or control.
- [ ] I can point at the dispatch boundary of an agent and say what each tool it holds can do if the model is fully controlled.
- [ ] I can name the six data planes of an AI system and say which ones I cannot reach or delete.
- [ ] I can state a release-gate threshold, and the corpus version it was measured against, before running the suite.
- [ ] I know who owns each AI system I work on and what evidence a review would ask me for.
- [ ] I understand the NDA boundary and know what public material is safe to rely on.

## Further Resources

- [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS — Adversarial Threat Landscape for Artificial-Intelligence Systems](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI 600-1 — Generative AI Profile of the AI RMF](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-600-1)
- [INE Security — eAIS (AI Systems Security Specialist) official certification page](https://ine.com/security/certifications/eais-certification)
