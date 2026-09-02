# eAIS Phase 01 — AI Models: Foundations and Security-Relevant Concepts

> eAIS methodology · Phase 01 · English study guide — INE-Cybersecurity-Certifications-Guide

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

## Common Mistakes & Tips

- **Mistake:** treating "the model refused" as proof the application is safe. Refusals are model behavior, not an access-control mechanism.
- **Mistake:** trusting retrieved documents at the same level as your own system prompt. Any web page, email, or uploaded file inside context can steer the model.
- **Mistake:** confusing model-level risk with application-level risk. A secure model inside an insecure integration (broad tool permissions, no logging) is still a critical finding.
- **Mistake:** assuming fine-tuning only makes models safer. Fine-tuning adjusts weights and can remove alignment or embed new behaviors.
- **Tip:** draw the data flow (user → app → model → tools → data stores) before testing; each hop is an injection or disclosure candidate.
- **Tip:** write down which content classes are *instructions* (your system prompt, tool schemas) versus *data* (documents, emails, web pages). Every architecture decision should keep those classes separable.

## Checklist / Self-Test

- [ ] I can name at least five ML/LLM component stages and one attack family relevant to each.
- [ ] I can explain the difference between pre-training, SFT/RLHF alignment, and fine-tuning.
- [ ] I can explain why RAG content is a trust boundary and how that leads to indirect prompt injection.
- [ ] I can enumerate the capabilities of an agentic LLM (tool calling, code gen) and the risk each one adds.
- [ ] I can list the common LLM failure classes mapped to OWASP LLM Top 10 categories.
- [ ] I can sketch a trust-boundary diagram for a simple RAG + tools application.
- [ ] I can describe where memorization, backdoors, and privacy leakage arise in the ML lifecycle.

## Further Resources

- OWASP Top 10 for Large Language Model Applications — https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) — https://atlas.mitre.org/
- NIST AI Risk Management Framework — https://www.nist.gov/itl/ai-risk-management-framework
- OWASP Machine Learning Security Top 10 — https://owasp.org/www-project-machine-learning-security-top-10/
