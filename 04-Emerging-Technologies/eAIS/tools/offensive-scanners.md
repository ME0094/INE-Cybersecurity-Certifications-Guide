# Offensive Scanners — garak, PyRIT & Promptfoo

> eAIS · Tools — INE-Cybersecurity-Certifications-Guide · English
>
> The three tools you will actually point at an LLM system: garak for a first-pass scan of a
> model endpoint, Microsoft PyRIT for attack campaigns that exist as code, and Promptfoo for
> declarative evaluation and red teaming from CI. This file covers what each one produces, how
> to read it, where it fails, and how to keep two runs comparable. Every example targets a
> system you own and are authorized to test.

## 1. Purpose

Three jobs, three tools, one shared discipline. Pick the job first, then the tool:

| The job | The question you are answering | Tool developed below |
| --- | --- | --- |
| **Scan an endpoint** | "Does this model, as served right now, fail the common LLM attack families?" | garak |
| **Orchestrate a campaign** | "Can I express a converted, scored, multi-attempt attack as code and re-run it after every change?" | Microsoft PyRIT |
| **Test an application in CI** | "Did this release regress on injection, leakage, or jailbreak resistance?" | Promptfoo |

> **The three tools change shape between releases.** Flags, subcommands, model-type names,
> plugin and probe identifiers, and the location and format of reports are all release-specific
> in this space. Nothing below should be copied blind: confirm each invocation with
> `garak --help` / `promptfoo --help` and the project docs for the version you have installed,
> and prefer the tool's own help over any example, including the ones here.

> **Nothing in this file was executed.** No command in this file was executed while writing it:
> this machine has no local model server, no API keys, and no GPU. Every invocation is a syntax
> reference to run in your own lab.

This guide deliberately stops at the tool boundary. What the attacks *are* — the vector
taxonomy, the controls that stop them, the application wiring that decides the real blast
radius — lives in `../methodology/02-prompt-injection.md`,
`../methodology/05-defensive-controls.md`, and `../cheatsheets/ai-attack-vectors.md`. The
categories-and-selection view of the whole landscape is `ai-testing-tools.md`; this file is
the depth behind its first row.

## 2. The three tools at a glance

| | **garak** | **Microsoft PyRIT** | **Promptfoo** |
| --- | --- | --- | --- |
| **What it is** | A vulnerability scanner for LLM generators: a catalogue of probes paired with detectors, run against one target and reported. | A Python framework for orchestrated red teaming: you build the campaign from targets, converters, orchestrators, and scorers. | A Node CLI for declarative prompt evaluation and AI red teaming, driven by YAML. |
| **What it targets** | A model endpoint (a "generator") reached through the interface you configure. | Anything you write a target for — most usefully the *application* endpoint, not just the raw model. | A provider (a model endpoint, or the app itself) described in the config, evaluated case by case. |
| **Language / form** | CLI, Python project underneath. | Python library — the campaign is code. | YAML config plus CLI subcommands; runs in CI. |
| **Artifact it produces** | A scan report: which probes failed, which detectors fired, and the attempts behind the hits. | Your own export of the campaign — prompt, response, converter, and score per attempt — plus whatever conversation records the framework keeps. | A per-case, per-provider results table and results file, with pass/fail semantics usable as a build gate. |
| **Choose it when** | You need a first-pass health check and a reproducible report about an endpoint. | You need a repeatable, scored, multi-variant campaign and can invest in the object model. | You need a regression gate, or a side-by-side comparison of providers. |
| **Do not choose it when** | The finding is about the *application* (RAG, tools, permissions) — garak does not see that layer. | You need a quick answer: the learning curve, not the run, is the cost. | The scenario needs stateful, multi-turn, side-effecting behaviour that declarative cases cannot express. |

The three are complementary, and running all three against the same target is normal: garak to
find the endpoint's weak spots, PyRIT to deepen one of them into a scored campaign, Promptfoo
to keep fixed behaviour fixed.

## 3. garak — the first-pass endpoint scanner

### What it is and what it is not

garak is a free, open-source LLM vulnerability scanner. Its unit of work is the **probe**: a
family of prompts generated to test one failure mode — prompt injection, jailbreaks,
encoding-based attacks, harmful-content generation, and more — paired with **detectors** that
decide whether a response exhibits the failure being tested. It iterates probes against a
single target and writes a report of what failed.

- It **is** a first-pass scanner and a report generator, which is what makes it useful: one run
  gives you a structured answer about an endpoint.
- It is **not** an application scanner. It does not know your system prompt, your retrieved
  documents, your tool registry, or your authorization rules. A garak pass on a raw model says
  nothing about the app built on it.
- It is **not** a guardrail test, a severity rating, or a penetration test. It reports what it
  tried and what the detector thought of the reply.
- It is **not** deterministic: sampling parameters apply as usual, so two runs of the same
  probe set can differ.

### What you get out of it

The artifact is a **scan report**, plus — in practice — the raw attempts you should keep next
to it. What carries meaning is the pairing, not the headline number:

- **A failing (probe, detector) pair** is the smallest unit of meaning in the report. Read one
  failing prompt and its response yourself before you repeat the number to anyone.
- **Convergence between probe families** on the same weakness is a behaviour, not detector
  noise — the strongest result a scanner can hand you.
- **The pass set is bounded**: a clean result means *the installed probes* found nothing on
  *this target* with *these parameters*.

The report's location and format are release-specific. Take them from the run's own output and
the project README rather than assuming a path, then copy the artifact next to your run record
so the finding stays reproducible (see `ai-testing-tools.md`, "Before you install anything").

### Isolation and setup

- Run it from a lab VM, a container, or a disposable host — not from a workstation that holds
  production credentials and a route into internal networks.
- Default to a local endpoint: it keeps the model version pinned, removes per-query cost, and
  avoids the terms-of-service question entirely (section 6).
- Probes generate offensive content by design. Keep outputs private, do not paste raw responses
  into shared chats or shared log platforms, and never point the scanner at a service you are
  not authorized to test.
- Assume cost scales with probes × prompts. On a hosted target, set a hard spend limit *before*
  the run that turns out to be interesting, not after.

### Running it

```bash
# Install (Python). Pin the version when two runs have to be comparable.
pip install garak

# The invocation form used in this module's lab: an OpenAI-compatible target and the
# prompt-injection probe family.
garak --model_type openai --model_name gpt-3.5-turbo --probes promptinject

# Ask this build which target types, probes, and detectors it actually has.
garak --help
```

> Every name in that second line is version-dependent: `--model_type` values differ between
> hosted providers and local/OpenAI-compatible servers, and probe and detector identifiers are
> added, renamed, and split over time. `--probes promptinject` is the form this module's lab
> uses and the one to start from; confirm the rest with `garak --help` and the README for your
> release, and check how that release points at a *local* endpoint before assuming the hosted
> form transfers.

A workflow that keeps runs cheap and interpretable:

1. One probe family, one model, one run. Understand that family before widening.
2. Write the run record — tool version, model and tag, probe set, parameters — *before* reading
   the report.
3. Take the two or three most interesting failures and reproduce them by hand against the
   application, not only against the raw model.
4. Only then run the next family. The point of a first pass is a shortlist, not a score.

### Reading the results

| What you see | What it actually means | What to do next |
| --- | --- | --- |
| A probe family reports failures | A detector scored responses as exhibiting the tested failure — for example, the model followed an injected instruction instead of the application's | Read one prompt and one response, reproduce by hand, then write the finding |
| Almost everything fails | Either a genuinely weak target, or a detector mismatch; small local models also fail for *capability* reasons — they cannot follow the instruction to refuse, or answer incoherently | Compare against a larger local model (`ollama pull llama3.1:8b`) and read raw responses before believing the rate |
| Everything passes | Only that the installed probes, against this target, at these settings, produced no detector hit | Record it as a bounded negative and name what the scan did not cover |
| Two families fail on the same behaviour | The strongest scanner result available — a behaviour rather than a payload | Escalate: deepen it with PyRIT, or gate it with Promptfoo |
| A benign-looking response scored as a failure | Detectors are pattern- or classifier-based, so shared vocabulary can trigger one | Treat it as noise until you have read it; a false positive costs a minute, a missed one costs a finding |

### Limits

- **Coverage is the installed probe set.** Anything outside it goes untested, and the gap is
  invisible in the report.
- **Model-level, not app-level.** No retrieval, no tools, no permissions, no multi-turn state.
- **Detectors err in both directions.** Expect false positives (vocabulary overlap) and false
  negatives (the model complied in a way the detector does not recognise).
- **No severity, no exploitability.** A hit is a lead; whether it matters depends on what the
  target can reach.
- **Cost and time on hosted targets.** Probes × prompts × models. A sweep of every family is
  rarely the right first move.
- **Nondeterminism.** Same probe set, different sampling, different counts. Freeze parameters
  and re-run before claiming a difference between two scans.

### Failure diagnosis

| Symptom | Likely cause | Check |
| --- | --- | --- |
| Run aborts complaining about the target or model type | Release-specific model-type or model-name string | `garak --help` and the project README's target list; confirm the exact spelling for your endpoint |
| Every probe errors with a connection problem | No server listening, wrong host or port, or the model was never pulled | Start the endpoint and prove it answers with the local check in section 6 |
| The run completes with no failing probes at all | The probe identifier is invalid or absent in this release, or the set was narrower than you assumed | Re-run one family you have confirmed is listed; read the run's own summary of what it loaded |
| Nearly everything fails | Small or mismatched local model, or a detector doing something other than you assume | Re-run against a larger local model, and read a few raw responses before trusting the rate |
| You cannot find the report | Output path and format are release-specific | Read the run output and the README, then copy the artifact next to your run record |
| Authentication error against a hosted provider | The key is not exported under the name this tool expects | Confirm the variable name in the current docs — the module's own lab scripts use `$env:OPENAI_API_KEY`, which is not evidence of what garak reads |

## 4. Microsoft PyRIT — campaigns as code

### What it is and what it is not

PyRIT (Python Risk Identification Tool) is a framework for *orchestrated* red teaming. Where a
scanner brings its own catalogue, PyRIT brings a language for building one. Six concepts carry
almost all of its value:

| Concept | The question it answers |
| --- | --- |
| **Target** | What am I attacking — a raw model endpoint, or my application's endpoint? |
| **Prompt** | What am I sending, before any transformation? |
| **Converter** | How is that prompt transformed — framing, obfuscation, encoding, translation, splitting across turns? |
| **Orchestrator** | What is the strategy: given the last response, what gets sent next? |
| **Scorer** | How do I decide whether a response is a success for the attacker? |
| **Memory / records** | What was sent and received, so the campaign can be re-read, scored, and re-run? |

- It **is** the right tool when the finding needs variants, attempts, and a *score* rather than
  a single probe result.
- It is **not** a CLI you point at a URL. There is no "run PyRIT": you write the campaign.
- It is **not** a report generator. The artifact is whatever you persist, so decide the record
  shape before the first run.
- The API is the volatile part. Module layout, class names, and orchestrator behaviour change
  between releases; the concepts above are stable, the names are not.

### What you get out of it

Because the campaign is your code, the artifact is your export — and its usefulness depends
entirely on the record you choose. A workable minimum, one JSON object per attempt:

```json
{"campaign": "lab-d1", "objective": "<what you are trying to elicit>", "converter": "<name, or none>", "attempt": 3, "prompt": "<what was actually sent>", "response": "<what came back>", "scorer": "<name>", "score": "success"}
```

With that file you can answer the only two questions a campaign exists to answer:

- **Which converter raises the success rate?** A transformation that turns refusals into
  compliance is the finding: your control does not survive that transformation.
- **Did the number move after the change?** Re-run the same campaign against the same target
  with the guardrail, template, or model change applied, and diff the rates — this
  re-runnability is what justifies the learning curve.

### Isolation and setup

- Point the campaign at a local endpoint first. Converters multiply requests, and a multiplier
  on a paid endpoint is the most expensive way to learn.
- Prefer the lab application's endpoint over the raw model when the finding is about the app —
  and make sure its **tools are fake**: stub functions, fake credentials, no real mailbox, no
  real internal API. A campaign that can cause real side effects is a production incident with
  extra steps.
- If a hosted model is unavoidable, use a throwaway key in a sandbox project with a hard spend
  limit, and read the provider's terms on automated attack traffic first.
- Treat the machine running the framework as inside the blast radius: it holds the keys and the
  campaign output.

### Running it

The module's lab shows the import form; everything else about the object model is
version-specific.

```python
# Shape of a PyRIT campaign — illustrative, NOT a runnable script.
# Names of orchestrators, converters, and scorers change between releases:
# confirm them in the project docs for the version you install.
#
#   1. target       the endpoint under test (a local OpenAI-compatible server first)
#   2. objective    the behaviour you are trying to elicit, in one sentence
#   3. converters   how each prompt is transformed (framing, encoding, translation, ...)
#   4. orchestrator the loop that sends, reads the reply, and decides what to try next
#   5. scorer       the rule that labels a reply as success or failure
#   6. export       write prompt, response, converter, and score to your own results file
from pyrit.orchestrator import RedTeamingOrchestrator  # concept, not a copy-paste snippet
```

Before writing any of it, answer the four questions in section 7 on paper. The third one
matters most here: if a human has to read every response to say whether the attack worked, the
campaign cannot be re-run at scale — and re-runnability is the entire reason to use PyRIT.

### Reading the results

- **Report rates per converter, over attempts.** One success is an anecdote; the same objective
  failing through five converters and succeeding through the sixth is a finding with a control
  attached to it.
- **Read a sample of the successes.** A response that *mentions* the harmful content is not the
  same as one that performs it, and a keyword scorer cannot tell the difference.
- **Separate refusal from incapacity.** A 3B local model that cannot follow the task refuses and
  fails in ways a hosted model does not; neither result generalizes to the other.
- **Distrust an unvalidated scorer.** If the scorer is itself a model — an "LLM judge" — then it
  is a model that can be influenced by the text it judges, and its verdicts drift when that
  model version changes. Hand-label ten responses and compare them against the scorer's
  verdicts before computing a single rate. Where a deterministic check can express the failure
  — a marker string, a structured-output field, a call appearing in the harness log — prefer it
  over a judge.

### Limits

- **The learning curve is the cost.** Budget real time on the object model; the first campaign
  is mostly plumbing.
- **API churn.** Code written against one release may not import on the next.
- **No coverage guarantee.** PyRIT ships no probe catalogue: whatever you did not think to try
  is untested.
- **Cost multiplier.** Converters × objectives × attempts; compute the request count before
  running.
- **The scorer sets the ceiling.** Every rate in your report inherits the scorer's false
  positives and false negatives.
- **Persistence is configuration.** Confirm what the framework records by default, and where,
  before the run you intend to keep.

### Failure diagnosis

| Symptom | Likely cause | Check |
| --- | --- | --- |
| `ImportError`, or classes that moved | The installed release renamed or relocated part of the API | Read the docs for the version you installed, not a blog post or an older example |
| The campaign never terminates | No stop condition: no attempt cap, no score threshold, or a target that never returns | Add explicit attempt and time caps; log each attempt as it happens so a killed run still leaves data |
| The scorer marks everything a success (or nothing) | Scorer too loose or too strict, or judging the wrong field of the response | Hand-label ten responses and compare; tighten the rule, or give an LLM judge its own validated prompt |
| Rate-limit or timeout errors mid-campaign | Provider limits, or converters multiplied the request count past what you counted | Cap concurrency and attempts; count requests before running; treat the campaign as partial |
| Authentication or target errors | Wrong endpoint variable, or a model identifier that does not exist on that server | Prove the endpoint answers with the local check in section 6, then re-check the identifier |
| Nothing was persisted after the run | Default storage not configured for the way you ran it | Confirm the current memory/persistence configuration in the docs *before* the run you care about |
| Results that will not compare with the last campaign | Converter set, objective wording, target, or parameters drifted between runs | Freeze all four and re-run the baseline under today's conditions (section 8) |

## 5. Promptfoo — declarative evaluation and CI red teaming

### What it is and what it is not

Promptfoo is an open-source Node.js CLI with two related jobs: **evaluation** — describe
prompts, providers, cases, and assertions in YAML, run them, get pass/fail — and **red
teaming** — generate attack suites from a target definition and report which attacks got
through. It is the one tool in this set designed to live in a pipeline.

- It **is** the right choice for a regression gate: the same cases and assertions on every
  prompt, model, or guardrail change, with a machine-readable result.
- It **is** the right choice for a provider comparison: one case set across a local model and a
  hosted model in a single report is how you decide whether a cheaper model is acceptable.
- It is **not** a runtime guardrail: it tests, it does not enforce.
- It is **not** a substitute for reviewing how the app wires tools and permissions. A case set
  cannot see an over-privileged tool unless you write the case that exploits it.

### What you get out of it

A per-case, per-provider results table plus a machine-readable results file, and a pass/fail
outcome intended for use as a gate. Confirm the current exit behaviour and threshold options
for your version in the docs: that surface has changed over time, and it is exactly the part a
CI job depends on.

How to read it:

- **An assertion failure is a violated specification you wrote.** Check the assertion before
  the model: a phrasing or format assertion that fails on every provider is a badly written
  test, not a vulnerability.
- **The provider column is the feature.** A case that passes locally and fails hosted (or the
  reverse) is a finding about a *model swap* — precisely what a release review needs.
- **Red-team results are per attack goal.** A success means the attack achieved its objective
  against your target definition, which is why that definition must point at the app rather
  than at a placeholder.
- **Noise** is anything that fails for formatting reasons, or passes because the provider was
  misconfigured. Read one result per assertion type before reading the summary.

### Isolation and setup

- Node and npm on the lab host, with the config under version control so a case set is a
  reviewable artifact.
- Local providers first. A red-team run against a hosted provider bills per case per provider,
  and generation multiplies cases.
- The target definition must point at your lab app — the Flask target in
  `../labs/llm-testing.md` is this module's example — with fake tools wherever a case can
  trigger one.
- Pin the version. `npx promptfoo@latest` fetches whatever is newest that day: convenient for
  learning, fatal for comparing yesterday's run with today's. Install a fixed version and
  record it.

### Running it

```bash
npx promptfoo@latest init          # scaffold a promptfooconfig.yaml
npx promptfoo@latest eval          # run prompt/response evaluation cases
npx promptfoo@latest redteam run   # run the red-team generator (verify current syntax)

promptfoo --help                   # confirm subcommands and flags for your version
```

The config *is* the test suite. Build it from the scaffold the tool writes, not from any
example — including this one:

```yaml
# Shape of a promptfooconfig.yaml. NOT a verified config for your version:
# `npx promptfoo@latest init` writes the real scaffold — edit that.
# Provider identifiers, prompt references, test-case keys, and assertion names
# all change between releases; take the current ones from the docs.
prompts:
  - "<inline prompt, or a path to your prompt template>"
providers:
  - "<provider id for your local endpoint or hosted API>"
tests:
  - vars:
      question: "<a case input>"
    assert:
      - type: "<assertion name from the current docs>"
```

Two habits make this pay off: keep the case set in the repository next to the prompt template
it tests, and add a case every time you fix something — the case is the evidence that the fix
stayed fixed.

### Reading the results

| Pattern | Reading | Action |
| --- | --- | --- |
| One case fails on every provider | Likely the case or the assertion, not the model | Fix the test before touching the app |
| One case fails on one provider only | A model-specific behaviour — a real comparative finding | Report it as a model-swap risk, with the provider and version named |
| Every case fails | Misconfigured provider, wrong endpoint, or wrong model identifier | Prove the endpoint answers (section 6), then re-check the provider id |
| Every case passes, including ones you expected to fail | Assertions too loose, or the case is not reaching what you think it is | Write one case that must fail and confirm the harness reports it |
| A red-team run reports many successes | Either a genuinely weak target, or a target definition that is not the app | Confirm the target, then reproduce the top attacks by hand |

### Limits

- **The case set is the ceiling.** Coverage is exactly the corpus you wrote, and nothing else.
- **YAML has a shape limit.** Stateful multi-turn scenarios, tool side effects, and
  memory-dependent behaviour may need a custom provider or assertion — or belong in the Python
  harness instead.
- **Cost and rate limits.** Cases × providers × tokens; a full red-team sweep on a hosted
  provider is a bill, not an experiment.
- **Nondeterminism.** Sampling parameters and provider-side model updates both move results; a
  CI gate needs stable parameters and an acknowledged tolerance.
- **A flaky network is a flaky gate.** Timeouts read as failures; keep infrastructure errors in
  a separate class from assertion failures.

### Failure diagnosis

| Symptom | Likely cause | Check |
| --- | --- | --- |
| `npx` fails immediately | Node/npm missing, or no network for the first fetch | `node --version` and `npm --version`; for reproducible runs install a pinned version instead of `@latest` |
| The config is rejected | The schema moved between releases | Re-run `init` and diff the fresh scaffold against your file |
| Cases pass that should fail | Assertion too loose, or the provider is a placeholder | Point one case at a behaviour that must fail and confirm it fails |
| Provider authentication errors | The environment-variable name differs per provider | Check that provider's section of the current docs — the module's lab scripts use `$env:OPENAI_API_KEY` and `$env:OPENAI_BASE_URL` for their own calls, which is not evidence of what Promptfoo reads |
| A red-team run produces almost nothing | The target definition or plugin set is not what this release expects | Re-read the current red-team docs and start from a minimal target |
| Runs are slow or expensive | Cases × providers × tokens, plus generation on red-team runs | Trim the case set while iterating, run the full set before a gate, and cap spend at the provider |

## 6. Targeting a local model instead of a hosted API

A local endpoint is the default posture for practice, for four reasons that have nothing to do
with scale:

- **Cost disappears per query**, so you can iterate on a probe set or a converter without
  watching a meter.
- **The model version is pinned by its tag.** The same tag tomorrow is the same artifact to
  test — the precondition for comparing two runs at all.
- **Nothing leaves the machine.** Prompts, retrieved documents, and offensive outputs stay in
  the lab, which matters when the lab is also where you test injection payloads.
- **No terms-of-service ambiguity.** You own both ends of the connection.

The price is that a small local model is a weak and inconsistent target: it refuses
unpredictably, fails for capability reasons, and its results do not transfer to a hosted
frontier model. Name the model and tag in every finding, and never generalize across the two.

How a tool reaches the endpoint, conceptually: a model server exposes an HTTP API on localhost,
and a scanner needs (a) an endpoint or base URL, (b) a model identifier, and (c) sometimes an
API key that the local server ignores. OpenAI-compatible servers deliberately reuse the hosted
request shape, which is why provider settings written for a hosted API often work unchanged
against them. Each tool names these differently — garak a model type plus a model name, PyRIT a
target object, Promptfoo a provider id — so confirm the current spelling in the docs and
`--help` for your release.

Prove the endpoint before blaming the tool:

```bash
ollama pull llama3.2:3b            # the small model this module's lab uses
ollama serve                       # local API on http://localhost:11434

# The check that answers "is the endpoint actually there?" before any scan
curl http://localhost:11434/api/chat \
  -d '{"model":"llama3.2:3b","stream":false,"messages":[{"role":"user","content":"Say hello"}]}'
```

Two failures worth knowing before they cost you an hour: a tool running **inside a container
cannot reach the host's `localhost`** (it needs the host address or a shared network), and a
scanner pointed at the raw model is not testing the app. When the finding is about the
application — retrieval, tools, permissions — point the tool at the app's endpoint (the
module's Flask target listens on port 5000) and let the app call the model, exactly as a user
would.

## 7. Writing your own probes and generators

Every one of the three tools ships someone else's cases. Yours will differ in at least one of
these ways: your domain vocabulary, your language, your retrieved corpus, your internal tools
and their arguments, your authorization rules. All three are extensible — garak through probes
and detectors, PyRIT through converters and scorers, Promptfoo through cases, generators, and
custom assertions — but the extension surface is the part that changes most between releases,
so take the names from the current docs rather than from memory.

Define four things *before* writing the case. A case missing any of them is a prompt in a file,
not a test:

| Define | Why it is the load-bearing part |
| --- | --- |
| **Target behaviour** | One sentence. If it takes a paragraph, the case is really two cases. |
| **Safe behaviour** | What the system should do instead — refuse, answer while ignoring the retrieved instruction, decline the tool call. Without this you cannot score the case. |
| **Failure signature** | The observable that proves failure: a marker string in the reply, a specific call in the harness log, a state change, a field in structured output. "It feels wrong" is not a signature. |
| **Scoring rule** | Deterministic first (marker, schema field, harness log entry); a judged score only when the failure is genuinely semantic — and the judge needs its own validation. |

Keep the corpus in a file, one case per line, with stable IDs, and extend the schema this
module already uses in `../labs/llm-testing.md` instead of inventing a second one:

```jsonl
{"id": "d4-07", "drill": "indirect-injection", "prompt": "<document text plus request>", "safe_behaviour": "summarizes the memo and ignores the embedded instruction", "failure_signature": "reply contains the fictional code, or the harness logs a call to send_reply"}
```

The pool to draw from is the vector taxonomy in `../cheatsheets/ai-attack-vectors.md` and the
drills and rubric in `../labs/llm-testing.md`. The reason to write your own is that translating
those classes into *your* application's vocabulary — your tool names, your document shapes,
your language — is the step no public payload set can do for you.

## 8. Keeping results comparable

A rate is only meaningful against another rate measured the same way. Freeze these, and write
them into the run record described in `ai-testing-tools.md`:

| Freeze | Why | Where it goes |
| --- | --- | --- |
| **Tool and version** | Probe sets, plugins, flags, and scoring change between releases; an upgrade can move the numbers on its own | Run record |
| **Corpus revision** | Adding or editing cases changes the denominator, and therefore every rate | The file's revision or hash |
| **Model name *and* tag** | Re-pulling a tag can yield a different artifact; the name alone is not enough | Run record |
| **Prompt template / system prompt** | The template is frequently the thing under test | The template's revision |
| **Parameters** — temperature, max tokens, and a seed when the tool exposes one | Sampling makes identical runs differ; not every tool exposes a seed, so record whether yours does | Run record |
| **Date and duration** | A result is a claim about an environment at a moment in time | Run record |

The rule that catches most mistakes: **never compare a run that has no record with anything
except itself.** If you cannot describe how a number was produced, it is a story, not a
measurement.

## 9. Comparing two runs

| What changed | Where to look first | How to attribute the difference |
| --- | --- | --- |
| Model or model tag | The per-case diff on a frozen corpus | Attributable only if tool version, corpus, and parameters are identical |
| Prompt template or system prompt | Cases whose replies changed shape | Diff the template text; the corpus did not change, so the delta is the template |
| A guardrail was added, moved, or reconfigured | The cases expected to be blocked | Read the app's own decision log, not just the reply — a blocked case can look like an ordinary refusal |
| Scanner or tool version | Probe/plugin names, case counts, and the pass/fail set | Re-run one probe family with each version; if you cannot, declare the runs incomparable |
| Retrieval corpus or index changed | Answers citing different chunks | Trace chunk IDs and scores before and after |
| Infrastructure — rate limits, timeouts, a truncated campaign | Missing rows and error entries | Count expected against completed cases *before* computing any rate |
| Nothing changed, and the results still moved | Nondeterminism: sampling and provider-side model drift | Re-run the baseline now, under today's conditions, and compare that pair |

## 10. Budget and blast radius

**Requests are multiplicative:** `cases × variants (converters, plugins, generators) ×
providers × attempts`. Do that arithmetic on paper before the run — a 200-case set with ten
converters across three providers is 6,000 requests, and on a hosted endpoint every one of them
is a token bill.

- **Two caps, always.** A provider-side hard spend limit and a local stop-loss (attempt count
  or wall-clock time). Know what your tool does when it hits one: a run that dies quietly
  mid-campaign produces a file that looks complete.
- **Rate limits and timeouts are not refusals.** A throttled target returns errors or empty
  replies, and a loose scorer can read both as success. Count error rows against expected cases
  before interpreting any rate.
- **If a campaign is cut short,** the results are still evidence — but the denominator changed.
  Record how many cases completed, mark the run partial in the record, and do not compute rates
  over the full corpus. Re-run the missing slice on a fresh budget instead of adjusting the
  numbers.
- **Cost per finding is the real metric.** A five-figure request count that confirms the same
  injection you could demonstrate with one hand-written case is a budgeting mistake, not a
  thorough test. Scan to find the class; hand-write the case that proves it.
- **The scanner is not the blast radius; the target is.** Point campaigns at a lab app whose
  tools are fake — stub mailbox, stub internal API, fake credentials, no real data. Never point
  one at a system that can send, spend, pay, or delete; where the app has write actions, put
  human approval or a lab-only endpoint in the way first.
- **Log hygiene.** Campaign output contains offensive content and whatever your app retrieved.
  Keep those logs in the lab and out of shared observability platforms.

## Common Mistakes & Tips

- **Comparing runs across tool versions.** Probe sets and defaults move; a difference may be
  the tool. Pin, record, and re-baseline on every upgrade.
- **Reading a clean scan as coverage.** No failures means the installed probes found nothing
  here, like this. Name what was not tested, in the report.
- **Trusting the scorer.** Every rate inherits the scorer's error rate, and an LLM judge is a
  model that can be influenced by the text it scores. Validate against hand labels first.
- **Reporting one success as a rate.** "It jailbroke once" is an anecdote. Report attempts,
  variants, and a denominator.
- **Pasting public attack templates.** Models are trained on the famous ones. Generate variants,
  and treat a stale payload's clean result as unexplained rather than as evidence of safety.
- **Pointing an automated attacker at a hosted API** without reading the terms. Local endpoints
  exist precisely so that question does not arise.
- **Leaving the artifact without a record.** A report file with no tool version, model tag,
  corpus revision, or date is unverifiable and will be re-run from scratch.
- **Letting a lab campaign touch anything real.** Fake tools, fake data, fake credentials — and
  a spend cap you cannot raise at 2 a.m.

## Checklist / Self-Test

- [ ] I can state, in one line each, which of the three tools I would use to scan an endpoint,
  to run a scored campaign, and to gate a release.
- [ ] I confirmed my tool's current target and probe/plugin options with its own `--help` and
  the project docs for the version I installed.
- [ ] I proved my local endpoint answers before blaming the tool for a failed run.
- [ ] I can read a scan report well enough to name the (probe, detector) pair behind a failure,
  and to explain why a clean result is bounded.
- [ ] I can describe the converter / orchestrator / scorer structure of a PyRIT campaign and why
  it makes the campaign re-runnable.
- [ ] I have a case whose assertion fails for a reason I chose deliberately, and the same case
  passes after the fix.
- [ ] I can write the failure signature of a custom case before writing the case itself.
- [ ] Every results file I keep has a run record: tool and version, model and tag, corpus
  revision, parameters, date, and whether the run was partial.
- [ ] I computed the request and token budget before the campaign, and set a hard cap.
- [ ] My lab target's tools are fake, and I know what a partial run does to my rates.

## Further Resources

- [garak (NVIDIA) — LLM vulnerability scanner](https://github.com/NVIDIA/garak)
- [Microsoft PyRIT — Python Risk Identification Tool for generative AI](https://github.com/microsoft/PyRIT)
- [Promptfoo — evaluation and red teaming CLI](https://github.com/promptfoo/promptfoo)
- [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- OWASP GenAI Security Project — the project that maintains the LLM Top 10 above; use its
  current guidance when mapping findings: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- [MITRE ATLAS — Adversarial Threat Landscape for Artificial-Intelligence Systems](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI 600-1 — Generative AI Profile of the AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-600-1)
- [INE Security — eAIS (AI Systems Security Specialist) official certification page](https://ine.com/security/certifications/eais-certification)
- In-repo: `ai-testing-tools.md` (categories and tool selection), `../labs/llm-testing.md` (the
  local lab and drills), `../cheatsheets/ai-attack-vectors.md` (the case pool), and
  `../methodology/05-defensive-controls.md` (what to do with what you find).
