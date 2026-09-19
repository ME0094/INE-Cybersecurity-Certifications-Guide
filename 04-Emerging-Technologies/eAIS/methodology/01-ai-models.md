# eAIS Phase 01 — AI Models: Foundations and Security-Relevant Concepts

> eAIS methodology · Phase 01 · English study guide — INE-Cybersecurity-Certifications-Guide

> **Style note.** Every command and code fragment in this file is a syntax reference: none of it was executed while writing this file. There is no model endpoint, no vector store, and no API key on the machine it was written on. Run fragments in your own lab, and confirm flags, parameters, and field names against `--help` or the documentation for the version you have installed.

## Purpose of this phase

Before assessing attacks on AI systems you must understand what a model is, how it is built, and where its trust boundaries sit. This phase builds the conceptual foundation used by every later phase in the eAIS methodology: prompt injection, model poisoning, adversarial attacks, and defensive controls.

## Machine learning model families

- **Supervised learning.** The model learns a mapping from inputs to labels using labeled examples. Used for classification (spam vs. benign) and regression (predicting a value). Security-relevant weaknesses include label noise, biased training data, and overfitting to spurious correlations.
- **Unsupervised learning.** The model finds structure in unlabeled data (clustering, anomaly detection). Often used in security products to detect outliers; a poisoned or skewed dataset silently changes what counts as "normal."
- **Reinforcement learning (RL).** An agent learns a policy from a reward signal. RLHF (see below) uses human preferences as a reward proxy. Reward hacking — finding behavior that maximizes the proxy without fulfilling the intent — is a direct security concern.
- **Classical deep learning architectures.** Convolutional neural networks (CNNs) dominate image tasks; recurrent and transformer architectures dominate sequences. Adversarial perturbations (Phase 04) exploit the mathematical fragility of these models.
- **Large language models (LLMs).** Autoregressive transformers that predict the next token given a context. Their emergent capabilities — instruction following, reasoning, code generation, tool use — create a qualitatively different attack surface than traditional classifiers.

### Security relevance quick map

| Model family | Typical use | Main security concerns |
| --- | --- | --- |
| Classifier (e.g., email filter) | Labeling / triage | Evasion, data poisoning, biased decisions |
| Anomaly detector | Intrusion detection | Adversarial noise, drift, poisoning of "normal" profile |
| LLM chatbot | Q&A, content generation | Prompt injection, jailbreaks, data leakage |
| LLM agent | Tool orchestration, automation | Indirect injection, tool abuse, privilege escalation |
| Embedding / RAG system | Semantic search | Poisoned documents, prompt-injected content retrieval |

## Anatomy of an LLM

- **Tokenization.** Text is split into tokens (sub-word units). Tokenization quirks — e.g., a tokenizer that splits on characters like `;` — matter to encoding-based jailbreaks (Phase 02).
- **Pre-training.** The model learns next-token prediction over a large public corpus. Pre-training causes memorization of training text (relevant to data extraction) and sets the model's factual base and biases. Training runs are extremely expensive, so most attackers target smaller, downstream components instead.
- **Alignment.** After pre-training, the model is tuned so its outputs follow instructions and are helpful, honest, and harmless. Common methods are supervised fine-tuning (SFT) on demonstrations and RLHF or DPO from preference data. Alignment is a behavior — not a guarantee — and can be bypassed or undone.
- **Fine-tuning.** Additional training on a smaller dataset to adapt the model to a domain or style. Because it changes weights, fine-tuning can re-introduce vulnerabilities or embed new ones (see Phase 03).
- **Retrieval-Augmented Generation (RAG).** External documents are retrieved (typically by embedding similarity) and inserted into the model's context at inference time. RAG improves freshness and grounding, but the retrieved text is *data*, not instructions — yet the model cannot always tell the difference. This is the root cause of indirect prompt injection.
- **Agents and tools.** The model can emit structured calls to functions (search, email, database, shell). The model chooses *what* to call; your code decides *whether* and *with what authority*. Every tool is a new trust boundary and a new injection target.

## Worked example: the context window as a budget

A context window is not a container that errors when it is full. It is a **budget with a hard ceiling**, and every part of a prompt — instructions, tool schemas, history, retrieved chunks, attachments, and the space reserved for the answer — competes with every other part for the same tokens. Something is always sacrificed when the total does not fit, and the order of sacrifice is a decision somebody made, whether or not they wrote it down.

The figures below are **illustrative arithmetic against a hypothetical 8,192-token window with 2,048 tokens reserved for output** — not a measurement of any product. Token counts only exist once you count them with the tokenizer of the model you actually deploy.

| Component | Illustrative tokens | Who controls it | Why it grows |
| --- | ---: | --- | --- |
| System policy and instructions | 420 | Developer | Edited per release, rarely re-budgeted |
| Tool / function schemas | 1,150 | Developer, via the framework | A registered tool contributes its schema without appearing in your prompt template |
| Chat-template and role overhead | 60 | Model and tokenizer | Per-message bookkeeping nobody types |
| Conversation history | 1,300 | User and assistant | Grows monotonically; nothing removes it by default |
| Retrieved chunks (`k` × chunk size) | 3,600 | Retriever — ultimately whoever can write to the corpus | `k` and chunk size are launch-time constants |
| Parsed attachment or document text | 900 | Whoever supplied the file | An uploaded file is a nearly unbounded input |
| **Input subtotal** | **7,430** | | |
| Reserved output | 2,048 | Developer | A reservation, not an estimate: it must be free before generation starts |
| **Total demand** | **9,478** | | **1,286 tokens over an 8,192 ceiling** |

Note the shape of the problem: developer-authored material (policy plus tool schemas) accounts for 1,570 tokens, while content arriving at runtime accounts for 5,800. A prompt that was reviewed when it contained only a system policy and a user message is now dominated by text nobody reviewed.

### What gets sacrificed, and what that costs

| Handling strategy | What it silently removes | Security consequence |
| --- | --- | --- |
| Slice history to the newest N turns | The oldest messages — where implementations that keep the system prompt in the same list put your policy | Your instructions are evicted before the attacker's newest text, so the last word in context belongs to whoever wrote most recently |
| Keep only the last `k` retrieved chunks | Earlier retrievals | An early authoritative chunk disappears while the attacker's chunk — most recent and most query-similar — survives |
| Truncate long chunks or attachments | The middle or the tail of a document | A check that depended on the removed region silently stops applying, and the review you performed no longer describes the runtime prompt |
| Summarize history as it grows | Detail, and the provenance of whatever is retained | A summarizer reads untrusted text and emits text the next turn treats as trusted (see [02-prompt-injection.md](02-prompt-injection.md)) |
| Lower `k` to fit under load | Consistency between runs | The configuration that passed review is not the one that serves peak traffic |

The consequence to carry into every later phase: **whoever can inflate the context can displace your instructions without overriding them.** A user pastes a long document; a tool returns a large payload; an attacker plants documents that win the top-k. None of that needs an injection payload — it needs volume, and the effect is that your system policy becomes a smaller fraction of what the model reads.

### Measuring the budget instead of guessing

- Count tokens **per component** at inference time with the tokenizer that ships with the deployed model, and log the counts next to the request. Confirm the counting call in your library's documentation rather than from memory.
- Track the **retrieved share** over time. An index that grows while `k` stays fixed changes the composition of every prompt, so a review performed at launch expires as the corpus grows.
- Test the sacrifice order directly: place a benign, unambiguous marker at the start of the history, at the end of the history, and inside the first retrieved chunk; overflow the window; observe which markers are still honoured. Lab procedure, not a production test.
- Where your runtime reports token usage for a request, treat it as ground truth for the total but not for the split — the split is precisely what you are trying to see.

## Worked example: embeddings, similarity, and why retrieval can be steered

Retrieval is a **ranked list**, and ranking is a security decision made by arithmetic that is rarely reviewed. The pipeline has four moveable stages:

| Stage | What happens | Where it can be steered | What to check |
| --- | --- | --- | --- |
| Chunking | Documents are split into units small enough to embed (fixed-size windows, separator-aware or semantic splitting), usually with overlap | A payload must fit inside one chunk intact; text split across chunks may never be retrieved together | Chunk size, overlap, and whether provenance (source, owner, ACL, timestamp) is stored with each chunk |
| Embedding | Index-time and query-time text become vectors in the same space | A corpus author controls the text of the chunks they contribute, and therefore their vectors | That index and queries were embedded by the **same model version**; a mismatch re-ranks the whole corpus into plausible nonsense |
| Similarity and top-`k` | Candidates are ordered by a similarity score — cosine similarity is the common choice — and the best `k` are taken | Wording that mirrors the vocabulary of a predictable query scores higher than prose that merely answers it | The value of `k`: it is also the number of attacker-authored candidates that can sit in context at once |
| Reranking | A second, usually stronger scorer reorders the candidate list | Reranking raises the bar — it must be satisfied too — but it reads untrusted text like everything else | Whether the reranker is itself a model, and therefore another component with an injection surface |

### Worked numbers: how a document wins

Query: *"how do I get a refund for an annual plan?"*. Four candidate chunks, ordered by cosine similarity against the query vector. The scores are illustrative; the ranking behaviour is the point.

| Chunk | Content shape | Cosine (illustrative) | Rank |
| --- | --- | ---: | ---: |
| A — authoritative policy page | States the rule and its exceptions; does not repeat the question's wording | 0.62 | 3 |
| B — support FAQ | Paraphrases "refund" and "annual plan" closely | 0.84 | 2 |
| C — attacker-authored page | Briefly answers the question *and* quotes the question's exact phrasing, then adds an instruction block addressed to the assistant | 0.91 | 1 |
| D — billing changelog | Off-topic for this query | 0.21 | below `k` |

At `k = 3`, C enters the context alongside A and B. **No injection syntax was needed to deliver it** — only vocabulary resembling the questions the application is likely to receive. Two things follow:

- A document that *sounds like* the question outranks a document that answers it. Similarity measures topical closeness, not authority, and the retriever has no concept of who wrote a chunk, whether it was reviewed, or whether the caller may see it.
- The payload only has to be inside **one retrieved chunk**. A long document can be 95% legitimate and still deliver an instruction; chunk-level retrieval makes the legitimate rest irrelevant to the attack.

### Limits of this picture

- Scores come from vectors you rarely inspect. Ranking changes when the embedding model, the chunker, or the index changes, so "these are our top sources" is a snapshot, not a property of the system.
- Position effects — whether a chunk read first, last, or in the middle is more influential — are an empirical question about a specific model and template. Test it rather than assume it; for the finding, the payload's presence in context is what matters.
- A reranker that reliably demotes semantic lookalikes genuinely improves answer quality. It is not a trust boundary: a *relevant* untrusted chunk is still untrusted after reranking.
- A retrieval-exposure measurement (how often chunks from each source reach top-k across a fixed question bank) is only as meaningful as the question bank. Publish the bank alongside the number, exactly as you would publish a payload set.

## Component inventory for an AI application review

Reviews fail when they treat "the AI" as one object. Enumerate the components first, then ask each one its own question. Fill this in for the application in front of you; the value is in the rows you cannot answer.

| Component | Where it typically lives | Security question | Phase |
| --- | --- | --- | --- |
| Model weights / adapters | Vendor endpoint, or your own serving stack | Who can replace this artifact, and is provenance verified before deploy? | [03](03-model-poisoning.md) |
| Tokenizer and chat template | Shipped with the weights, or application configuration | Does the template establish the role boundaries your prompt relies on — and who can change it? | 01 (this file) |
| Embedding model | A vectorisation service, or in-process | Is the same model version used for indexing and for queries? | 01 (this file) |
| Vector store / index | Managed service, or embedded index | Who can write to it, and are ACL and provenance stored next to the vector? | [03](03-model-poisoning.md) |
| Retriever (`k`, filters, scoring) | Application code | Is the scope derived from the authenticated caller, and is the filter applied before ranking? | [02](02-prompt-injection.md) |
| Reranker | Application code, or a service call | Does it read content the caller is not allowed to see? | [02](02-prompt-injection.md) |
| Prompt templates | Application repository or configuration | Are they versioned, and does retrieved text enter the same channel as instructions? | [02](02-prompt-injection.md) |
| Tool and function registry | Application code plus credentials | What authority does each tool carry, and is it derived from the requesting user? | [05](05-defensive-controls.md) |
| Guardrails (input and output) | Application code, or a proxy | On error or timeout, does it fail open or fail closed? | [05](05-defensive-controls.md) |
| Prompt / configuration store | Config file, secret store, feature flags | Can a configuration change alter the security posture without review? | [05](05-defensive-controls.md) |
| Logs and traces | Observability stack | Do they record retrieved chunk identifiers and tool-call arguments, or only the final answer? | [05](05-defensive-controls.md) |

Two habits make the inventory pay off. First, for every row ask **"who can change it, and how would I know?"** — the answer is a control, and "nobody knows" is a finding. Second, record the **version** of each row: these components version independently, so a review expires whenever any one of them moves.

## Which layer do I test first?

Test where consequence is largest and confidence is weakest, not where the tooling is most familiar. In practice that means the **action layer first, the delivery layer second, the model's resistance third, and detection last** — impact is bounded by what the application can *do*, and "the model resisted this payload" is the least durable assurance available.

| What you can reach | Start here | Why first | What you cannot conclude from it |
| --- | --- | --- | --- |
| Only a chat box | Instruction hierarchy and refusal behaviour: system-prompt extraction, policy evasion, context flooding | It is the only channel you have, and its failures are cheap to characterise | Nothing about retrieval, tools, or other users' data |
| Ability to supply documents or files | The ingestion path: can your instruction reach the index, inside one chunk, and survive to context? | Upload paths are usually the least reviewed way into a corpus | Whether your account could reach another tenant's documents |
| Visibility of the retrieved chunk list | Retrieval quality and exposure: which sources enter top-k for a fixed question bank | Ranking mistakes are invisible in the answer while deciding what the model reads | What the model then does with the text |
| Write access to the corpus | Whether an attacker-authored chunk can outrank an authoritative one | This is the indirect-injection entry point in most enterprise deployments | Whether existing documents are already poisoned |
| A named tool set, or observable side effects | Tool arguments and authorization: confused-deputy paths, scope widening, recipient substitution | A tool call is where injected text becomes an action, and where least privilege either exists or does not | Whether a payload you have not written yet would persuade the model |
| Traces of the assembled prompt and tool calls | The exact context the model received, and whether the control you believe in is in the path | It replaces inference with observation | Anything about channels that are not instrumented |
| Source and configuration (white box) | Tokenizer, template, chunker, `k`, filter placement, tool scopes, guardrail failure mode | These decisions make the rest of the behaviour predictable | Whether the deployed artifact matches the repository |
| A model endpoint with no application | Safety behaviour and filter evasion only | A legitimate target, but not the object under test | Anything about the application: context sources, tools, permissions, logging |

When you have full scope, the ordering above becomes the assessment order: (1) what the application can do, and with whose authority; (2) what can reach the context; (3) what the model resists; (4) whether anyone would notice. A payload that succeeds at the text layer against a read-only assistant is a disclosure finding; broad tool authority with no approval is a control gap regardless of any payload's success.

## Model capabilities versus risks

- **Instruction following** — powerful and dangerous: it makes the model obedient to whoever's text ends up in context, including attackers (direct and indirect injection).
- **Code generation** — accelerates development but can produce vulnerable code; also turns the model into a "compiler" for injected instructions.
- **Summarization and rewriting** — an LLM may faithfully reproduce instructions or secrets found in the material it summarizes (information disclosure).
- **Grounding via RAG** — reduces hallucination about facts, but shifts risk to the retrieval corpus: a single malicious document can steer answers.
- **Function calling / autonomy** — the highest-risk capability. Benefits scale with the privileges granted to tools; so does the blast radius of an injection.

A useful framing: **capability expands the attack surface; context controls which capabilities are reachable.** An agent that can send email *and* read the inbox has turned a text injection into a data-exfiltration primitive.

### Capability-to-risk mapping example

| Capability | Legitimate benefit | Risk it introduces | Typical control (Phase 05) |
| --- | --- | --- | --- |
| Follow instructions | Task automation | Obedience to attacker text | Input separation, tool allow-lists |
| Ground on RAG docs | Fresh, cited answers | Indirect injection via docs | Retrieval permissions, doc sanitization |
| Generate code | Developer speed | Vulnerable or malicious code | Output review, static analysis |
| Call tools | Real-world actions | Confused-deputy abuse | Least privilege, human approval |
| Summarize long context | Productivity | Hidden instructions survive summarization | Output filtering, moderation |

## How to read a model card

Model cards and documentation pages tell you what a model was trained on, its intended uses, its known limitations, and its safety evaluations. In an AI security review, read them adversarially:

- What data was the model trained on, and was consent/quality reviewed? Look for web-scraped or user-generated corpora (poisoning surface).
- What alignment methods were used (RLHF, DPO) and against which policy? Alignment scope defines what safety claims are even plausible.
- What was *not* evaluated? A card that reports benchmark scores but no refusal or injection testing tells you the attack surface is unmeasured.
- Is the artifact you downloaded the artifact the card describes? Verify hashes and provenance (supply-chain check, Phase 03).
- Does the license permit the use you intend, including security testing? Licensing is part of governance, not just legalese.

```text
# Model-card triage checklist (concept level)
[ ] Training data provenance and consent documented?
[ ] Alignment method and safety policy stated?
[ ] Safety/red-team evaluations included (not only benchmarks)?
[ ] Known failure modes and limitations disclosed?
[ ] Artifact checksums / provenance link available?
[ ] License compatible with intended use and testing?
```

## Where security issues live in the ML lifecycle

Map each stage to the failure classes studied in later phases:

1. **Data collection and curation** — poisoned or malicious data enters the corpus; sensitive data (PII) is included without consent. Relevant to Phases 03 and 04 (privacy leakage).
2. **Pre-training** — memorization of training data, baked-in biases, and (rarely, due to cost) backdoors. Hard to inspect post hoc.
3. **Fine-tuning and alignment** — fine-tuning injection and alignment erosion (Phase 03); capabilities that survive alignment removal.
4. **Integration layer (RAG, tools, plugins)** — indirect prompt injection, unauthorized tool use, confused-deputy problems (Phases 02 and 05).
5. **Deployment and inference** — direct prompt injection, jailbreaks, adversarial examples, membership inference, model extraction, and system-prompt disclosure (Phases 02 and 04).
6. **Monitoring and operations** — missing logging of prompts/tool calls, drift, and undetected abuse (Phase 05).

The eAIS methodology treats the whole lifecycle as in scope: an "AI security" review that only tests the prompt box at inference time misses the largest exposures in fine-tuning pipelines and agent tooling.

## Reference trust-boundary sketch

```python
# Concept-level sketch of an LLM application's trust boundaries.
# Illustrative for study purposes — not production code.

def run_assistant(user_message, retrieved_docs, tool_registry):
    # 1) Highest trust: system policy written by your organization.
    policy = load_system_policy()

    # 2) Medium trust: retrieved content. It is DATA, not instructions —
    #    an attacker may control it entirely via indirect injection.
    context = [doc.text for doc in retrieved_docs]   # untrusted

    # 3) Lowest trust: the end-user message.
    prompt = build_messages(system=policy, context=context, user=user_message)

    decision = generate(prompt)                      # may request a tool call
    if decision.action == "call_tool":
        tool = tool_registry.get(decision.tool)      # allow-list lookup
        return tool.run(decision.arguments)          # enforce per-tool policy
    return decision.text
```

Every arrow between these layers is a place a security control (Phase 05) must live: filter inputs, constrain tools, and log everything.

### Retrieval-time authorization

The sketch above treats `retrieved_docs` as already authorized. That is the assumption most RAG systems quietly break: **the retriever usually runs with its own credentials, and if those are broader than the caller's, retrieval is a privilege-escalation channel that needs no injection at all.** The model is handed documents the user was never allowed to see, and the answer discloses them.

Four rules, each preventing a specific failure:

1. **The retriever must not be more privileged than the caller.** A service account that can read the whole corpus turns every user's question into a possible read of everybody's data.
2. **Filter before ranking, not after.** A filter applied to a finished top-k wastes slots and can disclose a document's existence; a filter applied only to the answer leaks through citations and paraphrase.
3. **Scope must originate from the authenticated session**, never from a request parameter, a header, or a value inside the query text — including a value that a retrieved document suggests.
4. **Authorization must survive chunking.** When a document becomes forty chunks, every chunk carries the source document's ACL and provenance.

```text
# Concept-level call shape; the parameter names are illustrative.
retrieve(query, k, acl_filter = <predicate derived from the authenticated caller>)
#   the predicate is applied AT SEARCH TIME, not to the results afterwards
```

**The test:** create two identities with different access to the same corpus and ask both the same question. If the *content* differs rather than just the phrasing, retrieval-time authorization is working; if the second identity can obtain the first's document — directly, through a citation, or by asking the model to paraphrase it — it is missing. Log which chunks were retrieved for each identity, because comparing answers alone hides their sources.

## Limits of this mental model

- **Tokens are counted, not estimated.** Word-count and character-count ratios mis-estimate, and the error compounds across a long context. Count with the tokenizer that ships with the deployed model, and treat any figure you did not produce that way as a guess — including the illustrative table above.
- **Generation is not deterministic.** The same prompt can produce different output across runs and versions, so a single observation is an anecdote, not a property of the application (see [02-prompt-injection.md](02-prompt-injection.md) for how to measure instead).
- **The architecture diagram is a design document, not runtime truth.** Frameworks add their own system messages, tool schemas appear in a request without appearing in your template, some deployments place a moderation or summarization model in the middle, and a cache can answer without the model being called at all. Verify the wiring with traces and logs, not the drawing.
- **"The model" is a moving target.** Routers, staged rollouts, and vendor-side updates mean the artifact you characterised may not be the one serving a request tomorrow; record versions with every measurement and treat a version change as invalidating earlier results.
- **Components version independently.** Embedding model, chunker, `k`, prompt template, tool scopes, and guardrails each move on their own schedule, so a review is valid only for the combination you reviewed — and that combination can change without anyone announcing it.

## Common Mistakes & Tips

- **Mistake:** treating "the model refused" as proof the application is safe. Refusals are model behavior, not an access-control mechanism.
- **Mistake:** trusting retrieved documents at the same level as your own system prompt. Any web page, email, or uploaded file inside context can steer the model.
- **Mistake:** confusing model-level risk with application-level risk. A secure model inside an insecure integration (broad tool permissions, no logging) is still a critical finding.
- **Mistake:** assuming fine-tuning only makes models safer. Fine-tuning adjusts weights and can remove alignment or embed new behaviors.
- **Mistake:** estimating the context budget by word or character count instead of counting with the tokenizer you deploy. The estimate is wrong, the error compounds over a long conversation, and the overflow behaviour you then reason about is not the one your deployment implements.
- **Mistake:** treating "the document is in the vector store" as "this application may show it to this user". Retrieval and authorization are separate mechanisms, and the retriever's credentials are usually the broader of the two.
- **Mistake:** reviewing the prompt template while ignoring everything the framework adds to the request — tool schemas, injected system messages, cached or summarised history. The reviewed prompt and the sent prompt are different objects.
- **Tip:** draw the data flow (user → app → model → tools → data stores) before testing; each hop is an injection or disclosure candidate.
- **Tip:** write down which content classes are *instructions* (your system prompt, tool schemas) versus *data* (documents, emails, web pages). Every architecture decision should keep those classes separable.
- **Tip:** keep a one-page component inventory per application, with an owner and a version per row, and re-review when a row's version changes rather than on a calendar.

## Checklist / Self-Test

- [ ] I can name at least five ML/LLM component stages and one attack family relevant to each.
- [ ] I can explain the difference between pre-training, SFT/RLHF alignment, and fine-tuning.
- [ ] I can explain why RAG content is a trust boundary and how that leads to indirect prompt injection.
- [ ] I can enumerate the capabilities of an agentic LLM (tool calling, code gen) and the risk each one adds.
- [ ] I can list the common LLM failure classes mapped to OWASP LLM Top 10 categories.
- [ ] I can sketch a trust-boundary diagram for a simple RAG + tools application.
- [ ] I can describe where memorization, backdoors, and privacy leakage arise in the ML lifecycle.
- [ ] I built a context budget for a real application — system policy, tool schemas, history, retrieved chunks, reserved output — with the deployed tokenizer instead of an estimate, and I can name which component an unprivileged party can inflate and what is evicted first when it overruns.
- [ ] I can explain how a document containing no injection syntax can still win the top-k and change an answer.
- [ ] I filled the component inventory for one application and named the owning phase for every row.
- [ ] I checked retrieval-time authorization: the retriever is no more privileged than the caller, and the ACL filter runs before ranking rather than after.

> **Verification:** unverified syntax reference — not run, and the style note above says so. The
> `run_assistant()` sketch is illustrative and does not execute: called with any arguments it
> raises `NameError: name 'load_system_policy' is not defined`, because it names four helpers the
> block never defines. All four fragments compile under `python3 -m py_compile` (3.12.3) without
> resolving anything they call. The arithmetic the worked example asks the reader to trust was
> recomputed on **2026-09-19** and holds: 420 + 1,150 = **1,570** developer tokens; 1,300 + 3,600
> + 900 = **5,800** runtime tokens; input subtotal **7,430**; total demand **9,478**; and the
> overrun is **1,286** tokens past the 8,192 ceiling. The cosine column orders C (0.91) → B (0.84)
> → A (0.62), so a `k = 3` cut reaches the attacker's chunk. No model, tokenizer or vector store
> exists on this machine, so none of those figures is a measurement — the file says as much.

## Further Resources

- OWASP Top 10 for Large Language Model Applications — https://owasp.org/www-project-top-10-for-large-language-model-applications/
- OWASP GenAI Security Project — https://genai.owasp.org/
- MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) — https://atlas.mitre.org/
- NIST AI Risk Management Framework — https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI 600-1, *Generative AI Profile* — https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- OWASP Machine Learning Security Top 10 — https://mltop10.info/
