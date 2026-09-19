# AI Security Testing Tools

> eAIS · Tools — INE-Cybersecurity-Certifications-Guide · English

## Purpose

> **Syntax reference only — nothing here was executed.** No command in this file was
> executed while writing it: this machine has no local model server, no API keys, and no
> GPU. Every invocation is a syntax reference to run in your own lab.

This file maps the AI security tooling landscape so you can pick the right instrument for
a job: automated scanning of a model endpoint, structured red-team campaigns, adversarial
research on a local model, regression-style evaluation of an app, or runtime guardrails.
Tooling in this space evolves quickly, so every section ends with an honest "verify the
current docs" pointer — treat the examples here as orientation, not as a substitute for
the project's own documentation.

> **Always test only systems you own or are explicitly authorized to test.** Model API
> terms of service frequently prohibit automated red teaming; keep experiments local or
> inside a sandbox you control.

## Categories of tooling

| Category | What it does | Artifact it produces | Representative projects |
| --- | --- | --- | --- |
| **Prompt fuzzing / red-teaming suites** | Automatically generate and run many attack prompts against a model or app and flag failures (injection, jailbreaks, data leakage). | A scan or campaign report: which probes/attacks failed, per-detector scores, and the raw attempts behind each hit. | garak, Microsoft PyRIT, Promptfoo (red-team mode) |
| **Evaluation frameworks** | Define test cases with expected behavior, run them repeatedly, and report pass/fail and regressions — the "unit tests" of an AI app. | A per-case result set (machine-readable, e.g. JSON/CSV) plus a pass/fail summary you can gate a build on. | Promptfoo, DeepEval, Giskard, OpenAI Evals |
| **Adversarial robustness libraries** | Research-oriented frameworks that craft adversarial examples against ML/NLP models to measure robustness. | Perturbed inputs and a robustness figure per attack recipe — a measurement, not an operational report. | TextAttack, IBM Adversarial Robustness Toolbox (ART) |
| **Guardrails / runtime filters** | Components that sit between the user, the model, and the app to enforce policy on inputs and outputs at runtime. | A decision per input/output (allow, block, rewrite) in the application's own logs, plus the cases that assert each rail. | NVIDIA NeMo Guardrails (concept), Guardrails AI, Llama Guard models |
| **Vector store / retrieval security tooling** | Inspects the retrieval half of a RAG app: which chunks a query actually pulls, with which scores, from which document — the evidence for poisoned, over-broad, or cross-tenant retrieval. | A retrieval trace per query: query → chunk IDs → similarity scores → source document and its provenance metadata. | The retrieval layer of your own app, exercised with retrieval-specific cases in Promptfoo or DeepEval (confirm each project's current RAG support in its docs). |
| **Observability and tracing** | Records what a session actually did — prompt, retrieved context, model, tool calls, latency, tokens — so a finding can be reconstructed after the fact. | Traces and queryable logs, plus the dashboards or queries you build on top of them. | Instrumentation in your own app (Flask middleware writing prompt/response records) and the run artifacts of evaluation frameworks. Hosted LLM observability platforms exist; review licensing, retention, and data residency before sending production prompts to one. |
| **Agent / tool sandbox harnesses** | A controllable target where the model's tools are fake but the side effects are observable — the only safe way to prove a tool was called with attacker-chosen arguments. | A transcript of tool calls with their arguments and the harness's recorded effects, correlated with the prompt that caused them. | Your own harness (Flask lab target with stub tools and fake credentials), driven by PyRIT orchestrators or Promptfoo cases. |
| **Test-corpus management** | Keeps the cases themselves: stable IDs, intent, expected safe behaviour, and the rubric, under version control so runs are comparable. | A versioned corpus file (one case per line) with an ID, the prompt, the expected behaviour, and the label scheme. | The `prompts.jsonl` contract in `../labs/llm-testing.md`, extended; Promptfoo test files and PyRIT datasets for the same job. |

The boundary between categories blurs: Promptfoo is both an evaluation framework and a
red-teaming tool; PyRIT orchestrates attacks but also scores them. Choose by *workflow*,
not by label. The three offensive tools are developed in depth — commands, output, failure
diagnosis — in `offensive-scanners.md`; this file stays at the level of categories and
selection, and the runtime side of defense is the subject of `../methodology/05-defensive-controls.md`.

## Before you install anything

Installing a scanner is the cheap part; containing it is the work. Decide these five things
before the first command, and record the answers next to your results:

1. **Isolation.** Run the tool in a disposable VM, container, or at least a separate user
   account with no access to real data, no production credentials, and no route into
   internal networks. A scanner that pulls a retrieved document and sends it to a model
   endpoint is an exfiltration path you built yourself.
2. **Local endpoint, or a throwaway key.** A local model (the Ollama server on
   `http://localhost:11434`, or any OpenAI-compatible server) removes cost and
   terms-of-service ambiguity and lets you re-run the same test tomorrow. If only a hosted
   model answers your question, create a throwaway key in a sandbox project — never a
   production key — and read the provider's terms before pointing an automated attacker at
   it: many prohibit automated red teaming.
3. **A spend cap you cannot exceed.** Set the provider-side hard limit *and* a local
   stop-loss, because a campaign is multiplicative: cases × variants × providers × attempts
   = requests. Cost per query is the budget line that surprises people; on a hosted model a
   modest-looking case set becomes thousands of paid generations.
4. **Terms of service and authorization.** "It is my application" answers the legal
   question, not the provider's. Self-hosted and local models have no such constraint, which
   is one more reason the lab default is local.
5. **A pinned tool version.** Scanners change probe sets, detector names, flags, and scoring
   between releases. Pin the version you installed (and, for Node tools, a fixed version
   rather than always fetching the newest), record it in the run record, and re-read the
   project's current docs. Two scans produced by different tool versions are not comparable
   data: a difference you observe may be the tool, not your system.

Keep the record small and mechanical — one per results file:

```text
run record — keep with every results file
date / time        : <when the run started, and its timezone>
tool and version   : <name> <version as the tool itself reports it>
target             : <endpoint URL> + <model name and tag>
corpus / config    : <file> at <git revision or hash>
parameters         : <temperature, max tokens, probe/plugin set, seed if the tool exposes one>
result files       : <paths> — partial run? <yes/no, and how many cases completed>
```

## Well-known projects (conceptual overview)

### garak — LLM vulnerability scanner (NVIDIA)

garak is a free, open-source scanner that probes a model with large sets of pluggable
"probes" — prompt injection, jailbreaks, encoding attacks, harmful-content generation, and
more — and writes a report of what failed. It targets a generator (a local model or an
API) and works well as a first-pass health check.

```bash
pip install garak
# Then run, for example, a prompt-injection probe set against an OpenAI-compatible model
garak --target_type openai --target_name gpt-3.5-turbo --spec probes.promptinject
```

Two flags this line gets wrong if you copy an older guide. The current names are
`--target_type` and `--target_name`; `--model_type`/`--model_name` are the old spellings,
kept as aliases in garak 0.17.0 but legacy either way. And `--probes` has been deprecated
since 0.15.1.pre1 in favour of `--spec probes.<module>`. Beyond those, the exact flags,
target-type names, and probe identifiers change between releases — run `garak --help`,
`--list_probes` and `--list_generators`, and check the project README for the current plugin
list before relying on any specific invocation.

### Microsoft PyRIT — Python Risk Identification Tool for generative AI

PyRIT is a Python framework from Microsoft for *orchestrated* red teaming: instead of
throwing single prompts, you script attack pipelines ("orchestrators") that generate many
variants of an attack (via "prompt converters", e.g., obfuscation or jailbreak templates),
send them to a target, and score each response ("scorers") so results can be compared
across models or versions.

```python
# Illustrative structure only — PyRIT's API changes often. Read the project's docs.
#
# `pyrit.orchestrator.RedTeamingOrchestrator`, which earlier revisions of this file showed,
# no longer exists: the orchestrator layer was reorganised under `pyrit.executor.attack`,
# and the class names, constructor arguments and target configuration all moved with it.
# The shape below is what to look for in the current release, NOT a snippet to paste.
from pyrit.executor.attack import AttackExecutor      # verify the name in your release
```

The rename is the point rather than an obstacle: PyRIT is the tool in this module whose
Python API moves fastest, so treat every import in your own scripts as version-pinned and
re-check it after an upgrade — a break here is a two-minute fix at review time and a
broken campaign at 02:00.

The value of PyRIT is reproducibility: an attack campaign is code, so you can re-run it
after a model or guardrail update and see whether the risk moved. Budget real time to
learn its object model, and confirm which targets (OpenAI, Azure, local endpoints, etc.)
are supported in the current release.

### Promptfoo — evaluation and red teaming CLI

Promptfoo is an open-source CLI (Node.js) for both prompt evaluation and AI red teaming.
It uses declarative YAML configs, runs in CI, and can compare outputs from many providers
(GPT, Claude, Gemini, local endpoints, and more). Its red-team command generates attack
suites from a target app definition and reports which attacks succeeded.

```bash
npx promptfoo@latest init          # scaffold a promptfooconfig.yaml
npx promptfoo@latest eval          # run prompt/response evaluation cases
npx promptfoo@latest redteam run   # run the red-team generator (verify current syntax)
```

Check `promptfoo --help` and the docs for the current subcommand names — the red-team
workflow has been under active development and its flags have changed between versions.

### TextAttack — adversarial attacks for NLP research

TextAttack is an academic framework (Python) for adversarial attacks, data augmentation,
and robustness evaluation of NLP models. It composes attacks from reusable pieces: a goal
function, transformations, constraints, and a search method ("recipes" bundle these).
It is research-oriented — you typically load a Hugging Face model and a dataset — so it
fits studying evasion concepts more than scanning a production chat app.

```bash
pip install textattack
textattack --help   # explore the CLI before running an attack recipe
```

Model loading, dataset formats, and recipe availability change; consult
`textattack.readthedocs.io` for current usage.

### Guardrails — the NeMo Guardrails concept

"Guardrails" is the idea of wrapping a model with enforceable policy layers. NVIDIA's
open-source NeMo Guardrails popularized the concept with programmable "rails": **input
rails** that screen prompts before they reach the model, **output rails** that screen and
rewrite model responses, **dialog rails** that steer conversation flows, and **retrieval
rails** that filter what a RAG pipeline may return. Other projects (Guardrails AI,
Meta's Llama Guard classifier models) take different but related approaches.

```yaml
# Conceptual shape of a rail config — NOT a working NeMo Guardrails snippet.
# input:
#   flows:            # Colang-style rules defining allowed/blocked inputs
#   - "block toxic or injected user content"
```

The exact configuration language and APIs differ per project and version. Learn the
*concept* (screen inputs, screen outputs, keep a human-in-the-loop for high-risk actions)
and then read the specific project's docs before wiring anything up.

## How to pick a tool for a task

Ask yourself these questions first:

1. **What is the target?** A hosted chat API, a local open-weight model, or a full app
   with RAG and tools? Scanners that target APIs (garak, PyRIT) differ from app-level
   red teaming (Promptfoo) and from local model research (TextAttack).
2. **What is the goal?** Quick health check → garak. Repeatable, scored attack campaign →
   PyRIT. Regression testing of prompt quality in CI → Promptfoo eval. Understanding
   adversarial examples academically → TextAttack. Enforcing policy in production →
   guardrails.
3. **What ecosystem are you in?** Python shops reach for PyRIT/garak/TextAttack; Node/CI
   pipelines fit Promptfoo naturally. Prefer tools whose language matches the code you
   will maintain the tests in.
4. **Do you have permission and budget?** Local models remove cost and ToS concerns. If
   you must use a hosted API, use a throwaway key with a hard spend limit.
5. **Is it maintained?** Prefer active projects with recent releases, an issue tracker,
   and a license you can comply with. A great tool that is unmaintained is a liability.

| If your task is... | Reach for... | Then confirm... |
| --- | --- | --- |
| "Scan my model endpoint for common LLM failures" | garak | Current probes and target syntax in its README |
| "Run and score a large, repeatable attack campaign" | Microsoft PyRIT | Current orchestrator/scorer API and supported targets |
| "Test my app's prompts/RAG/agents in CI" | Promptfoo | Current config schema and red-team subcommands |
| "Study adversarial examples on a local NLP model" | TextAttack | Current model/dataset/recipe support |
| "Block bad inputs/outputs at runtime" | NeMo Guardrails or similar | Current config language and integration path |
| "Prove the app retrieves chunks it should not" | Retrieval tracing in your own app, driven by retrieval-specific test cases | That the trace records chunk IDs, scores, and source provenance — without those, a "leak" is not provable |
| "Reconstruct what a session actually did" | Instrumentation in the app before any external platform | What is stored, for how long, how it is redacted, and who can read it |
| "Prove an agent called a tool with attacker-chosen arguments" | An agent/tool sandbox harness with stub tools and fake credentials | That the harness logs arguments *and* effects, not only the final reply |
| "Make regressions visible release after release" | A versioned corpus plus an evaluation framework | The corpus schema (ID, intent, expected safe behaviour) and where the corpus lives |

The last four rows share one property: the artifact you need is a *record of what happened*,
not a verdict. If the app does not already log retrieval, tool calls, and decisions, no
scanner can supply that evidence after the fact — instrument first, then scan.

## From scan to finding

Raw tool output is not a finding. Four gates turn one into the other, and a hit that fails
any gate is a note in your log, not a result:

| Gate | What it means | What it eliminates |
| --- | --- | --- |
| **Reproduce it by hand** | You can send the same input yourself — one request, one case ID — and get the failing behaviour. | Detector false positives, stale payload files, artifacts only the tool can trigger. |
| **Isolate the variable** | You know the single change that makes the failure go away: the guardrail, the prompt template, the retrieval filter, the model version. | "Something about the app" findings nobody can act on. |
| **Measure before and after** | You have a count or rate on both sides of the change, over a corpus rather than one prompt. | Anecdotes presented as improvements. |
| **Name the control** | You can state the mitigation in one sentence a developer could implement, and what it leaves uncovered. | Findings that end at "use guardrails". |

The write-up that survives review is short and mostly made of facts you already collected:

```text
Finding : <one sentence: what an attacker gains>
Target  : <app/endpoint, model name and tag, tool + version, date>
Repro   : <the exact request or case ID that fails, and the signature in the response>
Before  : <n of total cases failed, or the observed behaviour>
After   : <the same measurement with the candidate control applied>
Control : <the change, where it lives, and the residual risk it leaves>
Not tested: <the surfaces you did not cover — say so explicitly>
```

"Not tested" is not a weakness in the report; it is the boundary that keeps the finding
honest. A scanner run you cannot describe in these terms is raw material for the next run,
nothing more — see `offensive-scanners.md` for how each tool feeds this pipeline.

## Common Mistakes & Tips

- **Copy-pasting CLI examples from blog posts.** These tools change flags, model names,
  and plugin IDs between releases. Run `--help`, read the README, and verify against the
  project's current docs.
- **Scanning models you do not own.** API terms of service routinely prohibit automated
  attacks. Test locally (Ollama, llama.cpp) or in a sandbox account you control.
- **One tool, one shot.** Scanners produce false positives and false negatives. A garak
  pass is a starting point; confirm interesting findings by hand and with a second tool.
- **Ignoring scoring.** PyRIT and Promptfoo exist to make results comparable. If you only
  eyeball outputs, you cannot track whether a fix worked.
- **Confusing categories.** An evaluation framework is not a guardrail and a robustness
  library is not a red-team suite. Read the "How to pick" table before installing.
- **Forgetting the app layer.** Most real AI risk lives in how the app wires tools, RAG,
  and permissions — no scanner alone will find a tool with excessive privileges. Combine
  automated scanning with manual review of your app's architecture.
- **Running payloads from memory.** Public jailbreak templates are training data for the
  models they target. Generate variants programmatically instead of pasting stale ones.
- **Comparing results from different tool versions.** Probe sets, detector names, and
  defaults move between releases, so a "regression" may be nothing but a scanner update.
  Pin the version, record it, and re-baseline whenever you upgrade the tool.
- **Treating a scanner as coverage.** A clean run means the installed probes found nothing
  on this target with these parameters — not that the application is safe. Name the surfaces
  the run did not touch: your retrieval layer, your tool permissions, your language, your
  domain vocabulary.
- **Ignoring cost per query.** Probes × variants × providers multiplies faster than anyone
  expects, and rate limits and timeouts can look like refusals in a report. Cap the spend at
  the provider, cap the attempts locally, and count error rows before computing any rate.

## Checklist / Self-Test

- [ ] I can name the tool categories in the table above, say which artifact each produces,
  and give one project for each.
- [ ] I can explain the difference between garak and PyRIT (scan vs. orchestrated campaign).
- [ ] I have run at least one automated scan (e.g., garak or Promptfoo red team) against a model I control.
- [ ] I can write (or adapt from current docs) a small Promptfoo or PyRIT test case.
- [ ] I understand where guardrails fit at runtime and can describe input vs. output rails.
- [ ] I know how to verify that a tool's current CLI matches its documentation before running it.
- [ ] I can explain which tool I would pick for a CI regression test vs. a one-off scan, and why.
- [ ] Every results file I keep has a run record: tool and version, model name and tag,
  corpus revision, parameters, date, and whether the run was partial.
- [ ] I turned at least one scanner hit into a finding by reproducing it by hand, isolating
  the variable, and measuring before and after the fix.
- [ ] I can state, for my most recent test, which surfaces it did *not* cover.
- [ ] I know my spend cap and attempt cap before starting a campaign, and where the numbers
  for the last run came from.

## Further Resources

- [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS — Adversarial Threat Landscape for Artificial-Intelligence Systems](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [garak (NVIDIA) — LLM vulnerability scanner](https://github.com/NVIDIA/garak)
- [Microsoft PyRIT](https://github.com/microsoft/PyRIT)
- [Promptfoo](https://github.com/promptfoo/promptfoo)
- [TextAttack (QData)](https://github.com/QData/TextAttack)
- [NVIDIA NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails)
- [NIST AI 600-1 — Generative AI Profile of the AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-600-1)
- OWASP GenAI Security Project — the project that maintains the LLM Top 10 above; use its
  current guidance when mapping findings: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- [INE Security — eAIS (AI Systems Security Specialist) official certification page](https://ine.com/security/certifications/eais-certification)
- In-repo: `offensive-scanners.md` (depth on garak, PyRIT, and Promptfoo) and
  `../labs/llm-testing.md` (the local lab where these runs belong).

> **Verification:** both tool claims above were checked on **2026-09-19** by running the
> installed binaries on Ubuntu 24.04 / Python 3.12.3.
>
> **garak 0.17.0** (`/usr/local/bin/garak` and the venv's `/opt/pytools/bin/garak`, same
> version). `garak --help` defines the pair as
> `--target_type TARGET_TYPE, -t TARGET_TYPE, --model_type TARGET_TYPE, -m TARGET_TYPE` and
> `--target_name TARGET_NAME, --model_name TARGET_NAME, -n TARGET_NAME` — so the new names are
> primary and the old ones survive as aliases, which is why the note above says "legacy" rather
> than "removed". The same output prints `--probes PROBES, -p PROBES   DEPRECATED, use --spec`,
> and a real run with `--probes promptinject` emitted
> `DEPRECATION: --probes on CLI is deprecated since version 0.15.1.pre1`. `--list_generators`
> listed `openai`, `openai.OpenAICompatible`, `ollama`, `rest` and `test`;
> `--spec probes.promptinject` selected the three `promptinject.*` probes.
>
> **PyRIT 1.1.0 is installed** (in the `/opt/pytools/bin` virtualenv, not on the system
> interpreter's path — which is why a bare `python3 -c "import pyrit"` says it is missing and
> why "PyRIT is not installed" is the wrong conclusion to draw from that). The import this file
> used to show fails exactly as described:
>
> ```
> $ /opt/pytools/bin/python -c "from pyrit.orchestrator import RedTeamingOrchestrator"
> ModuleNotFoundError: No module named 'pyrit.orchestrator'
> ```
>
> and the replacement path above **was executed and resolves**:
> `pyrit.executor.attack` imports from
> `…/site-packages/pyrit/executor/attack/__init__.py`, and its public names include
> `AttackExecutor`, `AttackStrategy`, `AttackScoringConfig`, `CrescendoAttack`, `PAIRAttack`
> and `ManyShotJailbreakAttack`. `pyrit.attack_strategy` also does not exist. Confirm the exact
> class you need against `dir()` in your release: the package is real and the path is right,
> the specific class name is still yours to check.
