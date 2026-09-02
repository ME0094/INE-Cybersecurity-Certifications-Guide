# eAIS — AI Security (Study Guide)

> Area: 04-Emerging-Technologies · INE-Cybersecurity-Certifications-Guide · English

## What is the eAIS certification about?

INE Security's **eAIS (AI Security)** credential focuses on the *practical* security of
AI systems — most visibly applications built on large language models (LLMs). Where a
traditional penetration-testing certification attacks servers and web apps, eAIS is about
attacking and defending the AI application layer: the prompts, the models, the data they
are trained or retrieved from, and the tools and agents they can invoke.

Public information from INE describes the certification as building practical AI security
readiness and highlights areas such as:

- **Prompt injection** — tricking a model into ignoring its instructions or acting on
  attacker-controlled text.
- **Retrieval-Augmented Generation (RAG) security** — poisoning or abusing the documents
  and vector stores an application retrieves answers from.
- **Tool and agent misuse** — abusing the functions, plugins, or APIs an AI application is
  allowed to call.
- **Data and model poisoning** — contaminating training, fine-tuning, or prompt data to
  steer behavior.
- **Safe operational use of AI** — the controls, monitoring, and review practices that
  keep AI applications safe in production.

The spirit of the certification is *hands-on*: you are expected to understand the attack
surface of an AI application, reproduce representative attacks in a sanctioned lab, and
recommend proportionate defenses.

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
├── README.md                       <- this overview and roadmap
├── methodology/                    <- concepts and phases, in reading order
│   ├── 01-ai-models.md             <- AI/ML literacy: tokens, context, RAG, fine-tuning
│   ├── 02-prompt-injection.md      <- direct/indirect injection and jailbreaks
│   ├── 03-model-poisoning.md       <- data poisoning of training, fine-tune, and RAG data
│   ├── 04-adversarial-attacks.md   <- extraction, inversion, evasion, and privacy leaks
│   └── 05-defensive-controls.md    <- guardrails, filtering, monitoring, governance
├── tools/
│   └── ai-testing-tools.md         <- tool categories and how to pick a tool
├── labs/
│   └── llm-testing.md              <- safe local lab + guided red-team drills
└── cheatsheets/
    └── ai-attack-vectors.md        <- compact reference of attack vectors
```

Work the folder in the order above: concepts first, then tools, then lab practice, and
keep the cheatsheet open while you drill. Re-read files instead of memorizing them —
security is about *doing*, so the labs are the heart of this module.

## Study roadmap

1. **Build AI literacy (methodology/01).** If you cannot explain a context window, you
   cannot explain a prompt injection. Spend one or two sessions here before anything else.
2. **Learn the attack categories (methodology/02–04).** Read the poisoning, adversarial,
   and prompt-injection notes with the OWASP LLM Top 10 open alongside; map each category
   to the framework entries as you go.
3. **Study the defenses (methodology/05).** For every attack you learned, note the primary
   defense and one tool that can test whether it works.
4. **Get hands-on with tools (tools/ai-testing-tools.md).** Install one scanner (garak or
   Promptfoo) and run it against a local model so the concepts become muscle memory.
5. **Run the lab drills (labs/llm-testing.md).** Work through the guided drills end to end.
   Repeat them from memory — this is the closest practice to the exam's hands-on nature.
6. **Consolidate with the cheatsheet (cheatsheets/ai-attack-vectors.md).** Use it in the
   days before the exam for fast recall of vector → pattern → defense.
7. **Final pass.** Re-read the checklist/self-test at the bottom of each file; anything you
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
- [ ] I understand the NDA boundary and know what public material is safe to rely on.

## Further Resources

- [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS — Adversarial Threat Landscape for Artificial-Intelligence Systems](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI 600-1 — Generative AI Profile of the AI RMF](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-600-1)
- [INE Security — official certification pages and public blog content on AI security](https://ine.com/)
