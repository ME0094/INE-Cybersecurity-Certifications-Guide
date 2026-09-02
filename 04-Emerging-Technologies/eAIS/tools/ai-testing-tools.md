# AI Security Testing Tools

> eAIS · Tools — INE-Cybersecurity-Certifications-Guide · English

## Purpose

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

| Category | What it does | Representative projects |
| --- | --- | --- |
| **Prompt fuzzing / red-teaming suites** | Automatically generate and run many attack prompts against a model or app and flag failures (injection, jailbreaks, data leakage). | garak, Microsoft PyRIT, Promptfoo (red-team mode) |
| **Evaluation frameworks** | Define test cases with expected behavior, run them repeatedly, and report pass/fail and regressions — the "unit tests" of an AI app. | Promptfoo, DeepEval, Giskard, OpenAI Evals |
| **Adversarial robustness libraries** | Research-oriented frameworks that craft adversarial examples against ML/NLP models to measure robustness. | TextAttack, IBM Adversarial Robustness Toolbox (ART) |
| **Guardrails / runtime filters** | Components that sit between the user, the model, and the app to enforce policy on inputs and outputs at runtime. | NVIDIA NeMo Guardrails (concept), Guardrails AI, Llama Guard models |

The boundary between categories blurs: Promptfoo is both an evaluation framework and a
red-teaming tool; PyRIT orchestrates attacks but also scores them. Choose by *workflow*,
not by label.

## Well-known projects (conceptual overview)

### garak — LLM vulnerability scanner (NVIDIA)

garak is a free, open-source scanner that probes a model with large sets of pluggable
"probes" — prompt injection, jailbreaks, encoding attacks, harmful-content generation, and
more — and writes a report of what failed. It targets a generator (a local model or an
API) and works well as a first-pass health check.

```bash
pip install garak
# Then run, for example, a prompt-injection probe set against an OpenAI-compatible model
garak --model_type openai --model_name gpt-3.5-turbo --probes promptinject
```

The exact flags, model-type names, and probe identifiers change between releases — run
`garak --help` and check the project README for the current plugin list before relying on
any specific invocation.

### Microsoft PyRIT — Python Risk Identification Tool for generative AI

PyRIT is a Python framework from Microsoft for *orchestrated* red teaming: instead of
throwing single prompts, you script attack pipelines ("orchestrators") that generate many
variants of an attack (via "prompt converters", e.g., obfuscation or jailbreak templates),
send them to a target, and score each response ("scorers") so results can be compared
across models or versions.

```python
# Illustrative structure only — PyRIT's API changes often. Read the project's docs.
from pyrit.orchestrator import RedTeamingOrchestrator  # concept, not a copy-paste snippet
```

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

## Checklist / Self-Test

- [ ] I can name the four tool categories and give one project for each.
- [ ] I can explain the difference between garak and PyRIT (scan vs. orchestrated campaign).
- [ ] I have run at least one automated scan (e.g., garak or Promptfoo red team) against a model I control.
- [ ] I can write (or adapt from current docs) a small Promptfoo or PyRIT test case.
- [ ] I understand where guardrails fit at runtime and can describe input vs. output rails.
- [ ] I know how to verify that a tool's current CLI matches its documentation before running it.
- [ ] I can explain which tool I would pick for a CI regression test vs. a one-off scan, and why.

## Further Resources

- [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS — Adversarial Threat Landscape for Artificial-Intelligence Systems](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [garak (NVIDIA) — LLM vulnerability scanner](https://github.com/NVIDIA/garak)
- [Microsoft PyRIT](https://github.com/microsoft/PyRIT)
- [Promptfoo](https://github.com/promptfoo/promptfoo)
- [TextAttack (QData)](https://github.com/QData/TextAttack)
- [NVIDIA NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails)
