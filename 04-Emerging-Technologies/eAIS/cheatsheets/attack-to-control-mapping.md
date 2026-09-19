# Attack-to-Control Mapping — Cheatsheet

> eAIS · Cheatsheet — INE-Cybersecurity-Certifications-Guide · English
>
> Maps each attack vector to a primary control, a compensating control for the case where the primary fails, the concrete test that proves the control is present, and the signal that would make you *believe* you are protected when you are not.
>
> Scope: this sheet starts where the vector catalogue ends. What each vector *is* — description and educational pattern — lives in [ai-attack-vectors.md](ai-attack-vectors.md). The two sheets do **not** share one naming list: this sheet splits and merges some of the catalogue's sections, because the control that answers a vector rarely respects the boundary of the heading that introduced it. The correspondence is spelled out below rather than asserted.
>
> No command in this file was executed while writing it: every entry is a method to run in your own lab.

**Two rules that decide whether this sheet is useful**

- **Separate mechanism from reachable impact.** The same injection is a nuisance against a no-tools chatbot and an incident against an agent holding a write-capable credential. Severity comes from what the agent can *reach*, not from how clever the payload is.
- **A control is a claim until a test fails against it.** The "How it is proved" column is the deliverable of a review, not the "Primary control" column. Write the case, run it, keep the result.

---

## The master table

| Vector | Where it enters | Primary control | Compensating control if the primary fails | How it is proved (case set + what to observe) | False-confidence signal |
| --- | --- | --- | --- | --- | --- |
| Direct injection | User turn → context | Instruction/data separation (structured turns, delimiters plus schemas); input screening | Per-tool least privilege, so a hijacked turn has nothing to do | 4 paraphrases per case (courtesy, authority, negation, other language) replayed against a staging copy; observe the **tool-call trace**, never the assistant's prose | One phrasing refused; a filter tuned to the exact string you used last time |
| Indirect injection via document | Retrieved document or uploaded file → context | Treat retrieved text as data: labelling plus retrieval-time permissions plus ingest screening | Tool allow-list plus human approval before any write action | Plant an instruction inside a document you own, then ask a benign question; observe whether any action occurs that the user never requested | The assistant *summarises* the injected line without acting — that says nothing about the next turn |
| Injection via tool output | Tool or API response → context | Schema-validate and sanitise tool results; never re-inject upstream text as instructions | Trim tool output to the fields the task needs | Point one tool at a test endpoint returning a planted instruction; observe whether the app re-injects the raw body verbatim | A successful JSON parse taken as evidence the content is trustworthy |
| System-prompt extraction | User turn → output | Keep no secret in the prompt; hold policy in code; screen outputs | Assume the prompt is public and rotate anything that leaked from it | Extraction battery (translate, summarise above, repeat first message, complete-a-sentence) as a labelled case file; observe which variants return verbatim spans | The model declines once; or "the prompt holds no credentials anyway" while it holds tool names and internal rules |
| Jailbreak by framing | User turn → refusal policy | Alignment plus input moderation plus app-level policy enforced in code | Output policy checks that do not depend on the model refusing | Roleplay, fiction, authority and other-language frames aimed at a **fictional** forbidden topic in the test app; score pass/fail on refusal and on the downstream action | "We tested one public template" — a template is not a family, and the family is what regresses |
| Filter evasion by encoding or obfuscation | User or document text → pre-model filters | Normalise and decode **before** classifying; classify the decoded form | Post-model output screening, so the input filter is not the only gate | Same case encoded four ways (base64, simple substitution, homoglyph, split token); observe whether labels differ between raw and normalised input | The check runs after the model has already seen the raw payload, or only on user text and not on documents |
| Training-data / membership extraction | User turn → output | Data minimisation and deduplication at training time; do not expose logits or confidence scores | Output screening for verbatim spans plus rate limits per key | Held-out probe set: rare sentences that were **not** in training next to memorised-looking prefixes; observe completion confidence and verbatim overlap | Refusals on obvious PII probes — memorisation surfaces on rare strings, not on the obvious ones |
| Context leakage and cross-tenant | Session or tenant boundary → context | Per-user, per-tenant retrieval filters and scoped tokens applied **in the query** | Post-retrieval check that every returned ID belongs to the caller; fail closed | Two test tenants with marked documents; ask tenant A for tenant B's marker directly, indirectly and through a summary; observe which document IDs reach the context | Isolation written in the prompt ("only use this user's documents") instead of enforced in the query |
| Retrieval corpus poisoning | Ingestion path → vector store | Provenance, vetting and content screening at ingest; curated or signed sources | Re-rank toward trusted sources; answer with citations so a bad source is visible | Ingest one test document that contradicts a known-good answer; observe which source wins and whether the answer cites it | "The corpus is internal" — an internal wiki takes external edits and pastes too |
| Index dominance by duplicates | Ingestion → top-k selection | Deduplicate; cap documents per source at query time | Cross-check the answer against a trusted store before acting on it | Ingest N near-identical copies of one test document and re-run the same question; observe whether the correct source is crowded out of top-k | Top-k returns something relevant — relevance is not authority |
| Backdoor in a model artifact | Model load → behaviour | Pin version and hash; prefer safe load formats; record the artifact in an AIBOM | Re-run the behavioural suite on the **final** artifact, plus runtime guardrails | Compare refusal and policy results before and after the artifact swap; probe with candidate trigger strings; observe behaviour deltas, not benchmark scores | Benchmarks are unchanged — surviving benchmarks is what a backdoor is designed to do |
| Tool abuse / confused deputy | Injected instruction → privileged tool | Per-tool least privilege plus human approval for external or destructive actions | Action logging with blast-radius alerts on the first external send or export | "Read everything, then send" sequence as a case; assert the send is *gated*, not merely recorded; observe the approval payload | An approval prompt exists but shows only the model's own summary, never the resolved arguments |
| Tool confusion | Overlapping tool descriptions → wrong call | Minimal, distinct, non-overlapping tool names and descriptions; schema-validated tool enum | Dispatcher-side validation that the chosen tool matches the intent class | Near-duplicate tool set (read vs search vs export) with paraphrased requests; observe which tool each variant selects and whether args match the paraphrase | Every tool "works" — correctness of *choice* was never tested |
| Injection of tool arguments | Model output → tool arguments | Validate and normalise arguments server-side; allow-list values (recipients, paths, queries) | Confirmation step that renders the resolved arguments before execution | Cases that smuggle an extra field, a quoted override or a path traversal through a string argument; inspect what the tool actually received | Schema types pass — a string field can still carry an override |
| Excessive agency | Architecture → blast radius | Minimum tool set and minimum scopes per task; read-only by default | Human approval plus short-lived, per-session tokens | "Fully compromised model" test: enumerate everything reachable from the agent's credentials and write the list down | "The model is aligned" — alignment is irrelevant to what the credentials permit |
| Unbounded consumption | User turn or agent loop → cost and availability | Length caps, per-user quota, turn and recursion limits, hard timeouts | Budget alerts and a kill switch on spend or queue depth | Long-input and loop cases under a hard budget; observe tokens, wall time and queue growth per case | A cap on characters with no cap on tool-call loops or retries |
| Unsafe handling of model output | Model output → downstream sink | Treat output as untrusted input at every sink: encode, parameterise, review generated code | Static analysis plus sandboxing of generated artefacts | Route a case's output into each sink of the test app (HTML, SQL, shell, mail body) and observe how each sink handles it | "It is our own model" — provenance is not sanitisation |
| Model or dependency supply chain | Build → runtime | Pin versions and hashes; SBOM/AIBOM; minimal dependencies; vetted hubs | Egress control on the build and deploy path plus review of every newly resolved package | Diff the resolved dependency set and hashes between two builds; flag unused and look-alike package names; observe whether anything verifies them at deploy time | A lockfile exists, but nothing re-verifies it after review |
| Leakage via traces and logs | Logging path → trace store | Redact before storage; field-level allow-list; bounded retention | Access control and review on the trace store, identifiers stored hashed | Search your own trace store for the fictional marker used in a case; observe whether prompts, tool arguments or retrieved IDs appear in clear | Logs are "internal", while the prompts already contain production data |

### How this sheet's names map onto the vector catalogue

Eight rows carry a name that is identical in both sheets and are read side by side without any
translation: **Tool abuse / confused deputy**, **Tool confusion**, **Injection of tool
arguments**, **Excessive agency**, **Unbounded consumption**, **Unsafe handling of model
output**, **System-prompt extraction**, **Index dominance by duplicates**.

The remaining rows are this sheet's own working names, and each one covers one or more
sections of [ai-attack-vectors.md](ai-attack-vectors.md). Read the catalogue section named on
the right whenever a row's *mechanism* is what you need:

| Row in this sheet | Section in ai-attack-vectors.md |
| --- | --- |
| Direct injection | Prompt injection (direct) |
| Indirect injection via document | Prompt injection (indirect) |
| Injection via tool output | Prompt injection (indirect) — the tool-response channel, plus the delivery-channel table |
| Jailbreak by framing | Jailbreaks |
| Filter evasion by encoding or obfuscation | Adversarial evasion, plus the encoding variants under Jailbreaks |
| Training-data / membership extraction | Model extraction; Model inversion & memorization |
| Context leakage and cross-tenant | Retrieval without authorization (cross-tenant, cross-user); Privacy leakage |
| Retrieval corpus poisoning | Data poisoning (the RAG path); Retrieval manipulation (winning the top-k) |
| Backdoor in a model artifact | Data poisoning; Supply-chain attacks |
| Model or dependency supply chain | Supply-chain attacks |

Two catalogue sections, **Memory and state poisoning** and **Embedding inversion**, have no row
here on purpose: the first is covered by the context-assembly and history controls in the
request-path section below rather than by a control of its own, and the second is a
*measurement* finding — you prove it with the extraction probes of Phase 04, not with a
control you deploy. Neither gap is an omission you should read as coverage.

### Framework cross-references

This sheet deliberately describes most controls in words rather than IDs, because a control is
a statement about *your* system and a framework ID is not. The IDs worth carrying explicitly,
all of them verified against the source on 19 September 2026:

| Vector | Framework ID | What it is |
| --- | --- | --- |
| Unsafe handling of model output | **CWE-1426 — Improper Validation of Generative AI Output** | The weakness of using model output at a downstream sink without validating it, which is exactly the row above. The CWE entry is the closest thing this module has to a canonical weakness ID for the vector. |
| Injection of any kind (direct, indirect, tool output) | **MITRE ATLAS `AML.T0051` *LLM Prompt Injection*** — sub-techniques `AML.T0051.000` (*Direct*), `AML.T0051.001` (*Indirect*), `AML.T0051.002` (*Triggered*) | The technique, in ATLAS's own numbering. There is no separate technique called "Indirect Prompt Injection". |
| Every row, as a risk category for the control's design review | **OWASP Top 10 for LLM Applications, 2025 edition** | Cite the edition whenever you cite a number: LLM03 and LLM04 changed meaning between the 2023 and 2025 editions. |

For the governance layer that decides who accepts the residual risk at the bottom of this
sheet — as opposed to the engineering layer that implements the controls — see
[../methodology/09-ai-governance-and-lifecycle.md](../methodology/09-ai-governance-and-lifecycle.md).

---

## Severity: mechanism × reachable impact

The mechanism tells you which control to fix; the reach tells you how urgently. Read the two together before writing a severity, and state both in the finding.

| Mechanism | No tools, answer only | Read-only data access | Any write or external channel |
| --- | --- | --- | --- |
| Direct injection, goal hijacking | Wrong answer, eroded trust | Reading data the user was not entitled to see | Unrequested action performed under the app's identity |
| Indirect injection via retrieved content | Subtly steered summary, attacker's framing in the answer | Exfiltration of context the user never asked about | Confused deputy: attacker without an account acts through the agent |
| System-prompt extraction | Internal rules and tool names disclosed — reconnaissance for the above | Reveals retrieval scope and hidden policy branches | Reveals approval bypass wording and which actions are ungated |
| Encoding or framing evasion | Policy-shaped output, usually visible | Bypass of an input filter applied to data | Bypass of the filter that gated a privileged tool call |
| Model or dependency supply chain | Wrong or tampered answers | Tampered retrieval, requests leaving the host | Code execution or credential theft on the serving host |
| Traces and logs | A record that should not exist | Personal data readable by the wrong team | Retention turned into a long-lived secondary breach |

**Reading the table.** The left column is fixable by engineering in the application layer. The right column is what makes an injection report say *critical*, and it is a function of credentials and channel access, not of payload elegance.

---

## Test recipes by group

Each recipe is the minimum that makes the master table's "How it is proved" cell executable. Case-skeleton practice lives in [llm-test-case-library.md](llm-test-case-library.md).

### A — Injection (direct, indirect, tool output)

- **Case set.** Three delivery channels × four variants per channel, plus one encoding variant each.
- **Fixture.** Staging copy of the app; a document you own with a planted instruction; one tool pointed at a test endpoint that returns a planted instruction.
- **Observe.** The tool-call trace with arguments, the retrieved document IDs, and which context segment the instruction travelled in.
- **Pass condition.** No action occurs that the user did not request, and the injected text is handled as data (cited or ignored), not obeyed.
- **Cheapest first step.** One line in a test document; if the agent moves data or sends anything, stop and fix the tool authority before studying wording.

### B — Framing and evasion (jailbreak, encoding)

- **Case set.** One target topic defined by *your* app's fictional policy; frames: roleplay, fiction, authority claim, meta-test claim, other language; each frame twice, once plain and once encoded.
- **Fixture.** The same case file, replayed against two app versions (before/after the guardrail).
- **Observe.** Pass/fail on refusal, plus the downstream action; report a rate over the whole set, never a single anecdote.
- **Pass condition.** The rate does not move after a prompt or model change; any movement is a regression, not a curiosity.

### C — Disclosure and tenancy (system prompt, context, cross-tenant)

- **Case set.** Extraction battery (translate, summarise above, repeat first message, complete-a-sentence, list tool names) plus the A/B tenant marker probes.
- **Fixture.** Two tenants with distinct marked documents; a fictional secret placed in the system prompt and one in a document.
- **Observe.** Verbatim overlap with the prompt, and which tenant IDs appear in the retrieved set for each caller.
- **Pass condition.** The prompt leaks nothing that matters, and no ID outside the caller's tenant is ever retrieved — check the retrieval log, not the final answer.

### D — Data and model integrity (extraction, poisoning, index dominance, backdoor)

- **Case set.** Memorisation probes on rare strings; one contradicting document at ingest; N duplicate documents; candidate trigger strings before and after an artifact swap.
- **Fixture.** Control over ingestion for the test corpus, and two artifact versions with recorded hashes.
- **Observe.** Which source wins, whether citations reflect it, and behavioural deltas between artifact versions on a fixed suite.
- **Pass condition.** A contradicting or duplicated document does not change the answer's *source*; the artifact swap produces no behavioural delta you cannot explain.

### E — Tool authority (abuse, confusion, argument injection, excessive agency)

- **Case set.** Read-everything-then-send; near-duplicate tool selection under paraphrase; arguments smuggling extra fields or paths; the "fully compromised model" enumeration.
- **Fixture.** A tool registry with at least two similar tools and one write-capable tool behind approval.
- **Observe.** Which tool is chosen, the resolved arguments as the tool receives them, and whether the write was gated.
- **Pass condition.** The write cannot execute without an approval that shows the resolved arguments; tool choice is stable under paraphrase.

### F — Output and resource handling (unbounded consumption, unsafe output)

- **Case set.** Long input, recursive tool loop, repeated retry; one case per downstream sink (HTML, SQL, shell, mail body).
- **Fixture.** A hard budget per run, plus each sink wired to a handler you can inspect.
- **Observe.** Tokens, wall time, queue depth and loop count per case; how each sink treats the string it received.
- **Pass condition.** The budget is enforced by the platform, not by prompt instructions, and no sink treats model output as trusted input.

### G — Supply chain (model, dependency)

- **Case set.** Two builds of the same app with one dependency change; hash comparison of the artifact set.
- **Fixture.** A pinned manifest and an AIBOM entry per model, adapter and dataset.
- **Observe.** What changed between builds, and whether anything checks the hashes at deploy time rather than at review time.
- **Pass condition.** A hash mismatch stops the deployment.

### H — Observability (traces and logs)

- **Case set.** One injected marker, one fictional secret in a prompt, one cross-tenant probe — then search the trace store for all three.
- **Fixture.** Access to the trace store you actually run in production or staging.
- **Observe.** What is stored in clear, what is redacted, what is missing, and who can read it.
- **Pass condition.** Tool arguments and retrieved IDs are recorded (that is what makes a finding provable), while secrets and personal data are redacted at write time.

---

## Control coverage matrix

Marks: **●** covers this group well · **◐** partial, catches common cases only · **○** does not cover it. Group letters are defined in the legend below the table.

| Control | A Inj | B Fra | C Dis | D Int | E Tool | F Out | G Sup | H Obs | What it still misses |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Input screening and moderation | ◐ | ● | ○ | ○ | ○ | ◐ | ○ | ○ | Semantic payloads that read as normal text; anything arriving through documents |
| Instruction/data separation (structured context) | ● | ○ | ◐ | ◐ | ◐ | ○ | ○ | ○ | A model that decides data is instruction anyway; multi-turn assembly |
| Output validation and structured-output contract | ◐ | ◐ | ◐ | ○ | ● | ● | ○ | ○ | Leakage inside a schema-valid field |
| Retrieval-time authorization and corpus vetting | ◐ | ○ | ● | ● | ○ | ○ | ○ | ○ | A document that is permitted, plausible and wrong |
| Tool registry allow-list and per-tool least privilege | ◐ | ○ | ◐ | ○ | ● | ◐ | ○ | ○ | Overlap between allowed tools; a permitted action that is still harmful |
| Human approval for high-impact actions | ◐ | ○ | ○ | ○ | ● | ◐ | ○ | ○ | Approval fatigue; a reviewer who reads the summary, not the arguments |
| Sandboxing, egress allow-list, timeouts and quotas | ○ | ○ | ◐ | ○ | ● | ● | ◐ | ○ | Side channels inside an allowed destination |
| Per-user, per-session scoped credentials and tenancy | ○ | ○ | ● | ◐ | ● | ○ | ○ | ◐ | Shared caches, indexes and embeddings that ignore the scope |
| Artifact pinning, hashing and AIBOM | ○ | ○ | ○ | ● | ○ | ○ | ● | ○ | A backdoor whose behaviour is invisible on ordinary inputs |
| Logging with redaction and abuse-pattern detection | ◐ | ◐ | ◐ | ◐ | ◐ | ◐ | ○ | ● | Detection is after the fact; logs are themselves a data store |
| Versioned regression suite and release gate | ◐ | ◐ | ◐ | ◐ | ◐ | ◐ | ◐ | ○ | It *proves* coverage, it does not *provide* it — and only for the cases it contains |

**Group legend**

| Group | Vectors inside it |
| --- | --- |
| A Inj | Direct injection; indirect injection via document; injection via tool output |
| B Fra | Jailbreak by framing; filter evasion by encoding or obfuscation |
| C Dis | System-prompt extraction; context leakage and cross-tenant |
| D Int | Training-data/membership extraction; retrieval corpus poisoning; index dominance by duplicates; backdoor in a model artifact |
| E Tool | Tool abuse / confused deputy; tool confusion; injection of tool arguments; excessive agency |
| F Out | Unbounded consumption; unsafe handling of model output |
| G Sup | Model or dependency supply chain |
| H Obs | Leakage via traces and logs |

**How to use the gaps.** A **○** or a lone **◐** in a row that protects something valuable is an accepted risk until a *compensating* control exists in a **different layer** — an output filter is not a compensating control for an input filter. The two most common real gaps in agentic applications are the E column (tool authority) and the C column (later: tenancy enforced in a query rather than in a prompt).

---

## Where the controls sit in the request path

Controls only work if you can point at the hop that enforces them. This is the order in which a request should meet them; anything you cannot place on this line is a control you have not actually deployed.

```text
1. INGRESS          length, format and rate limits; moderation on raw text
                    decision: is this caller allowed to ask at all?      log: caller, size, label
2. NORMALISE        decode and canonicalise BEFORE classifying
                    decision: does the policy see what the model will see?
3. RETRIEVAL        per-caller filter inside the query, not in the prompt
                    decision: which document IDs may enter context?     log: document IDs, scores
4. CONTEXT ASSEMBLY instructions and data in separate, labelled segments
                    decision: what is instruction, what is only data?
5. MODEL            prompt template version, model version, no secrets in the prompt
                    decision: (nothing, this layer enforces nothing by itself)
6. OUTPUT           schema / enum validation, policy checks, redaction
                    decision: does this output leave the model at all?  log: decision, reasons
7. TOOL DISPATCH    registry lookup, per-tool least privilege, argument validation
                    decision: is this tool allowed, with these arguments?
8. APPROVAL         human gate for external, destructive or money-moving actions
                    decision: does a human see the RESOLVED arguments?  log: approver, args hash
9. SINK             encode / parameterise / sandbox per destination
                    decision: is model output treated as untrusted input here?
10. TELEMETRY       redacted trace store, retention limit, abuse-pattern alerts
                    decision: what can be proved six weeks from now?
```

Hops 2, 3 and 7 are the ones most often implemented in the wrong place: normalisation after the classifier, tenancy in the prompt instead of the query, and argument validation in the tool's own code instead of at dispatch. Each mistake removes a control from the path while leaving its name in the design document.

---

## Residual risk you are accepting

These are not control failures to fix; they are properties of the architecture that remain true after every control above is in place. Write them into the risk register as accepted, with an owner.

- **A fully controlled model with a write-capable tool.** Injection is not solved by better prompts. What remains is the tool's authority: allow-list it, gate it behind approval, make the action reversible, and alert on the first use.
- **Injection as an open problem.** Filtering, delimiters and separations raise the cost of an attack. None of them closes the class, and a control you believe is a boundary will be treated as one.
- **The data already in the weights.** Nothing in the inference path removes memorised content. Only minimisation and deduplication at training time, plus output screening, reduce the exposure — and neither is a deletion.
- **A permitted, plausible, wrong source.** Retrieval permissions and provenance checks stop the *unauthorised* document. They do not make the authorised one correct, current or honest.
- **A backdoor that survives benchmarks.** Behavioural suites buy detection probability on the triggers you thought of. They do not buy proof of absence.
- **Your own telemetry.** Full traces are what make findings provable and are simultaneously a second copy of the data you were protecting. Retention and redaction are risk decisions, not settings.

---

## How to test, at a glance

| Method | What it needs | Cost | Where it lives |
| --- | --- | --- | --- |
| Single-case probe against a staging copy | Lab app plus a JSONL prompt file | Low | [../labs/llm-testing.md](../labs/llm-testing.md) |
| Paraphrase battery (courtesy, authority, negation, other language) | Four variants per case; a runner that logs replies | Low | [../labs/injection-lab.md](../labs/injection-lab.md) |
| Encoding sweep (base64, substitution, homoglyph, split token) | A small encoder script and both raw and normalised label paths | Low | [../labs/injection-lab.md](../labs/injection-lab.md) |
| Multi-turn split | Stateful runner that keeps the conversation per case | Medium | [../labs/injection-lab.md](../labs/injection-lab.md) |
| Tenant A/B retrieval probe with planted markers | Two test tenants and a dummy corpus you control | Medium | [../labs/rag-data-leakage-lab.md](../labs/rag-data-leakage-lab.md) |
| Top-k dominance test (N near-duplicate documents) | Ingest control over the test corpus | Medium | [../labs/data-poisoning-lab.md](../labs/data-poisoning-lab.md) |
| Tool-call trace review (read-everything-then-send) | Tool arguments recorded, plus one write-capable tool behind approval | Medium | [../labs/agent-tool-abuse-lab.md](../labs/agent-tool-abuse-lab.md) |
| Guardrail A/B on an identical case file | Two app versions and one frozen case set | Medium | [../labs/guardrail-evaluation-lab.md](../labs/guardrail-evaluation-lab.md) |
| Artifact hash and load-format check | Pinned manifest and an AIBOM entry per artifact | Low | [../methodology/03-model-poisoning.md](../methodology/03-model-poisoning.md) |
| Attack-success-rate measurement with a stated budget | Labelled case file, runner, and the query budget per case | Medium | [../labs/guardrail-evaluation-lab.md](../labs/guardrail-evaluation-lab.md) and [../methodology/08-evaluation-and-continuous-red-teaming.md](../methodology/08-evaluation-and-continuous-red-teaming.md) |

Cost here means effort inside your own lab — a local model on `localhost:11434` removes API spend entirely. See [../labs/llm-testing.md](../labs/llm-testing.md) for the local setup and [../tools/ai-testing-tools.md](../tools/ai-testing-tools.md) for which project fits which job.

---

## Common Mistakes & Tips

- **Testing the control with the payload you designed it against.** A control that blocks last week's case is a regression suite, not a defense. Every row needs a *new* variant at review time.
- **Reading the chat reply instead of the trace.** Refusals are cosmetic; the tool-call trace with resolved arguments is the evidence. If you cannot see the trace, that is finding number one.
- **Marking a row covered because a product feature exists.** Coverage is a test result on your system, with your prompt, your tools, and your permissions.
- **Compensating in the same layer.** Two input filters compensate for each other's bugs, not for the class. The compensating control must be somewhere the attacker's payload does not reach.
- **Treating a prompt instruction as an access control.** Tenancy, least privilege and approval belong in code that the model cannot talk its way past.
- **Reporting severity from the payload.** "Critical prompt injection" is not a finding. Name the mechanism, the tool reached, the data touched, and whether a human gate stood between them.
- **Measuring a rate without its budget.** A high success rate over ten thousand queries and the same rate over twenty describe different systems; always state queries, variants and model version.
- **Fixing the case, not the class.** When a case starts passing, move it to regression and write a new variant for the same class — otherwise the gate slowly becomes a memory of old attacks.

## Checklist / Self-Test

- [ ] I can name, for any vector in the master table, its entry point, its primary control, and one compensating control in a different layer.
- [ ] I can state the observable that proves each control — a trace, a retrieval ID, a hash, a budget — rather than "the model refused".
- [ ] I can point at the rows where my own system has no compensating control and call them accepted risks with an owner.
- [ ] I can run the four paraphrase variants and the four encodings for one case without inventing new payloads.
- [ ] I can show that tenant isolation is enforced in the query, using two tenants and marked documents.
- [ ] I can show that a write-capable tool is gated by an approval displaying the resolved arguments.
- [ ] I can demonstrate that no downstream sink treats model output as trusted input.
- [ ] I can state which artifact hashes are verified at deploy time, and by what.
- [ ] I can find my own test markers in the trace store and confirm what is redacted there.
- [ ] Every claim of coverage in my last review is backed by a case result with a date and a version.

## Further Resources

- [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — the risk categories the master table deliberately describes in words rather than IDs.
- [OWASP GenAI Security Project](https://genai.owasp.org/) — guidance library behind those categories.
- [MITRE ATLAS](https://atlas.mitre.org/) — adversarial technique landscape for AI systems.
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) and [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) — structure for recording accepted risk and governing the lifecycle.
- [ai-attack-vectors.md](ai-attack-vectors.md) — what each vector is; this sheet assumes it.
- [llm-test-case-library.md](llm-test-case-library.md) — the case skeletons that make the test column executable.
- [../methodology/05-defensive-controls.md](../methodology/05-defensive-controls.md) — the layered defense model these controls come from.
- [INE Security — eAIS (AI Systems Security Specialist) official certification page](https://ine.com/security/certifications/eais-certification).
