# Data Poisoning Lab

> eAIS · Lab — INE-Cybersecurity-Certifications-Guide · English
>
> A local corpus, a keyword retriever and six drills that separate *influence* (the attacker's document is being retrieved) from *adoption* (the answer changed because of it). Scope: poisoning of the data an AI application retrieves from — RAG corpora and the ingest pipeline that fills them — plus artifact provenance with no GPU.

**Nothing in this lab was executed while writing it: every command is a step for you to run in your own isolated lab.**

## Scope and ethics (read first)

- **Local files and fictional content only.** A directory of `.txt` documents, a keyword retriever, and fictional policy values such as a "30-day fictional return window" and a "250 lab credit" limit. Nothing here needs a network, a model, a GPU or an API key.
- **No vectors, no model, no index server.** Retrieval here is term overlap over local files, deliberately: it keeps the lab runnable anywhere and it isolates the part of poisoning that governance can actually control — *what got into the corpus, and who can prove it*.
- **The simplification has a boundary, and you must state it.** Keyword ranking does not reproduce semantic-similarity effects. A finding about *semantic* dominance (an attacker document that shares no words with the query) cannot be claimed from this lab; re-test it against a real retriever before you write it up.
- **Your own systems only.** This is the RAG-data half of the eAIS scope; see the module overview in `../README.md`.

## Environment and prerequisites

- Python 3 from the standard library only — `hashlib`, `json`, `os`, `sys`, `time`. No packages to install, so nothing to leave behind.
- Optional: a local model endpoint on `localhost:11434` ([llm-testing.md](./llm-testing.md)) to replace the stand-in answer with a generated one. The drills are designed to run **without** it.
- Optional: `safetensors` and its documentation, if you want to inspect a real artifact format for the provenance section.
- A clean copy of the lab directory before every drill, so "restore" is one command and not an investigation.

```text
lab_poisoning_data/
├── corpus/returns-policy.txt        # the legitimate documents an app retrieves from
├── corpus/escalation-policy.txt
├── corpus/support-hours.txt
├── corpus/vendor-faq.txt
├── questions.jsonl                  # the evaluation set: question, expected answer, expected source
├── baseline.jsonl                   # written BEFORE anything is planted — the reference point
├── baseline_after.jsonl             # the same capture, after poisoning
├── retrieval-log.jsonl              # every retrieval: query, ranked docs, scores, hashes
└── ingest.jsonl                     # provenance of every document: path, sha256, added, author, source
```

## Golden rules

1. **Baseline first, always.** Without a recorded "before", "the answer changed" is an opinion. Drill 1 exists because everything else depends on it.
2. **Fictional documents, and no real policy.** These files stand in for a company's knowledge base; never seed them with a real internal document.
3. **One change per pass.** Plant one document, measure, restore. Two simultaneous changes produce a drift curve you cannot attribute.
4. **Record the hashes.** A corpus without an ingest-time hash record is a corpus you cannot reason about after the fact (Drill 5).
5. **Report influence and adoption separately.** "Three questions retrieved the attacker's document" and "two answers changed" are different findings with different owners.
6. **A negative result is a result.** "The poisoned document never entered the top-3 for any question" is worth writing down with the retrieval log behind it.

## Build the corpus

Documents are plain `.txt`; retrieval ranks by term overlap and returns the top `k`. The answer is a stand-in — the first sentence of each retrieved document, joined — which is *deliberately boring*: it changes only when the ranking changes. That isolates the retrieval half of poisoning from the generation half. With a local model, swap the stand-in for a model call and the drills gain a second, noisier signal; keep the log of what was retrieved either way, because that is the evidence.

```python
# retrieve.py — keyword retrieval + baseline capture. Written here, never executed: run it.
#   python retrieve.py baseline                        # BEFORE you touch the corpus (Drill 1)
#   python retrieve.py baseline --out baseline_after.jsonl   # after planting (Drill 2)
#   python retrieve.py ask "..."                       # one ad-hoc question, logged like the rest
#
# `--out` names the capture file and is the ONLY way the file is chosen. Drill 2 needs a
# second file (`baseline_after.jsonl`) and the earlier CLI had no way to ask for one: it
# always appended to baseline.jsonl, so the "after" capture landed on top of the "before"
# and the diff was impossible. The capture is also TRUNCATED at the start of a run and every
# row carries the run id and the capture start time, so running the capture twice replaces
# the file instead of silently doubling it with two rows per question, indistinguishable.
import argparse, hashlib, json, os, sys, time

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "lab_poisoning_data")
CORPUS, TOP_K = os.path.join(DATA, "corpus"), 3
RUN_ID = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())     # one id per process

def rank(query):
    """Score every document by term overlap. No vectors: the drill is about the rank."""
    terms = query.lower().split()
    scored = []
    for name in sorted(os.listdir(CORPUS)):
        text = open(os.path.join(CORPUS, name), encoding="utf-8").read()
        score = sum(text.lower().count(t) for t in terms)
        if score:
            scored.append({"doc": name, "score": score,
                           "sha256": hashlib.sha256(text.encode()).hexdigest()[:12], "text": text})
    return sorted(scored, key=lambda d: -d["score"])[:TOP_K]

def ask(qid, query):
    hits = rank(query)
    with open(os.path.join(DATA, "retrieval-log.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": time.time(), "run": RUN_ID, "id": qid, "query": query,
                             "top_k": [{"doc": h["doc"], "score": h["score"],
                                        "sha256": h["sha256"]} for h in hits]}) + "\n")
    answer = " | ".join(h["text"].strip().split(".")[0] for h in hits)
    return {"run": RUN_ID, "id": qid, "answer": answer,
            "sources": [h["doc"] for h in hits]}

def capture(out_file, questions=None):
    """Write one capture file from scratch: truncate first, so a re-run cannot duplicate."""
    path = os.path.join(DATA, out_file)
    with open(path, "w", encoding="utf-8") as fh:       # "w", not "a": one run, one file
        for line in open(os.path.join(DATA, questions or "questions.jsonl"), encoding="utf-8"):
            if not line.strip():
                continue
            q = json.loads(line)
            rec = ask(q["id"], q["question"])            # retrieval log and capture, once
            rec["expected_answer"], rec["expected_source"] = q["expected_answer"], q["expected_source"]
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"captured {out_file} as run {RUN_ID}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="keyword retrieval + capture")
    sub = parser.add_subparsers(dest="command", required=True)
    cap = sub.add_parser("baseline", help="capture every question in questions.jsonl")
    cap.add_argument("--out", default="baseline.jsonl",
                     help="capture file under lab_poisoning_data/ (Drill 2: baseline_after.jsonl)")
    cap.add_argument("--questions", default="questions.jsonl")
    adhoc = sub.add_parser("ask", help="one ad-hoc question, logged like the rest")
    adhoc.add_argument("question")
    args = parser.parse_args()

    if args.command == "baseline":
        capture(args.out, args.questions)
    else:
        print(json.dumps(ask("adhoc", args.question), ensure_ascii=False, indent=2))
```

The evaluation set is the other half of the reference: for every question you must know the answer *and* the document it should come from, or you cannot tell a wrong answer from a wrong source.

```jsonl
{"id": "q1", "question": "How long is the fictional return window?", "expected_answer": "30 days from delivery", "expected_source": "returns-policy.txt"}
{"id": "q2", "question": "What is the fictional escalation threshold for a delayed shipment?", "expected_answer": "48 hours", "expected_source": "escalation-policy.txt"}
```

| ID | Question | Expected answer | Expected source |
| --- | --- | --- | --- |
| q1 | How long is the fictional return window? | 30 days from delivery | `returns-policy.txt` |
| q2 | What is the fictional escalation threshold for a delayed shipment? | 48 hours | `escalation-policy.txt` |
| q3 | What are the fictional support hours? | 08:00–18:00, Monday to Friday | `support-hours.txt` |
| q4 | Who approves a fictional exception to the returns policy? | The fictional operations lead | `returns-policy.txt` |
| q5 | What is the fictional vendor's restocking position? | No restocking fee | `vendor-faq.txt` |

## Drill 1 — Baseline before poisoning

**Objective.** Fix the reference point, and prove the retriever is stable before you call any later change *drift*.

**Setup.** Nothing planted. `questions.jsonl` filled in. `baseline.jsonl` does not exist yet — the capture creates it.

**Steps.**

1. Run `python retrieve.py baseline` (which writes `baseline.jsonl`), then read it: one record per question with the observed answer, the observed sources, and the expected answer and source beside them. Every row carries the `run` id, so two captures are never confusable.
2. Check the expected source is the **top hit** for every question on the clean corpus. If a question's expected source sits at rank 2 or falls outside the top 3, fix the corpus or the question **now** — you cannot attribute drift that was already there.
3. Run the capture a second time (`python retrieve.py baseline --out baseline_rerun.jsonl` — a *different* file) and compare: with keyword ranking the result is deterministic, so any difference means the corpus changed between runs, not that the system is noisy. Record that as an advantage of this simplification, and as a limitation if you later swap in a model.
4. Hash every document and start `ingest.jsonl` from your own notes (path, sha256, added, author, source, review status). This is the file Drill 5 reviews.

**What you should observe.** Baseline lines where observed source equals expected source for all five questions — or an explicit list of the questions where it does not, which is a *lab defect to fix*, not a finding. Also a retrieval log whose `top_k` scores you can compare against later: the score column is what makes rank movement visible.

**Pivots.** A question whose expected source ranks second: is it still usable, and what would you change? A question where two documents score identically: how does the tie get broken, and does your production retriever break it the same way?

**Closing questions.** Why is drift undetectable without a recorded baseline? What would a baseline captured *after* ingestion of a poisoned document look like, and how would it mislead you?

## Drill 2 — Poison one document

**Objective.** Measure how far one attacker document moves the answers, and separate being retrieved from being believed.

**Setup.** Add `corpus/vendor-faq-poisoned.txt`: well-formed, plausible, and contradicting the returns policy on the return window — written to score high on the *predictable* queries by echoing their terms ("return window", "returns", "policy"). Write it as a document a reviewer might skim past; a badly written one is caught by an obvious check and teaches nothing.

**Steps.**

1. Capture the poisoned state with the same runner into a different file:
   `python retrieve.py baseline --out baseline_after.jsonl`. The file is truncated at the start of the run, so this is a clean capture of the poisoned corpus and not an append to `baseline.jsonl`.
2. For each question, compare: answer changed? cited source changed? and where did the legitimate document sit — still rank 1, pushed down, or out of the top 3?
3. Classify per question as `influenced` (the poisoned document is in `top_k`) and separately as `adopted` (the answer changed). Count both; they are different numbers.
4. Read the score column in `retrieval-log.jsonl`: a document that parrots the query terms scores high for a reason you can point at.

**What you should observe.** At least one question `influenced`; a smaller or larger set `adopted`, depending on how much of the answer the poisoned document contributes. The instructive case is influence *without* adoption — the attacker is in the context and the answer did not change — and the opposite, an answer that changes the moment the document is retrieved. Both are findings; only the second is an impact you can demonstrate to a business owner.

**Pivots.** Rewrite the attacker document to share no terms with the query: keyword retrieval will miss it entirely, and that miss is the documented limitation of this simplification, not a defence you can rely on. Give the legitimate document more terms, and see whether rank 1 returns to it.

**Closing questions.** Why report influence and adoption separately? Which control at ingest would have stopped this document, and which would only have made it later? What would you have concluded if you had looked only at the answers and not at the ranks?

## Drill 3 — Flooding the index

**Objective.** Reproduce retrieval dominance without any lie: many near-duplicates of one weak attacker chunk.

**Setup.** Script that writes 12 near-copies of a single attacker chunk into `corpus/`, varying only a header line, whitespace, and one synonym, so the content is nearly identical but the file hashes differ.

```python
# flood.py — EXAMPLE for you to run; not executed while writing this lab.
import os
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab_poisoning_data", "corpus")
CHUNK = "Returns policy note: the return window is 90 days for all fictional shipments."
for i in range(12):
    with open(os.path.join(DATA, f"returns-note-{i:02d}.txt"), "w", encoding="utf-8") as fh:
        fh.write(f"Fictional returns note {i}\n\n{CHUNK}\n")
```

**Steps.**

1. Re-run the baseline capture and compare `top_k` **occupancy**: how many of the three slots the attacker family holds, per question.
2. Measure the *rank delta* of the legitimate document: its position in the clean baseline against its position now, and whether it left the top 3 at all.
3. Look at the retrieval log for the dedup signal: many documents, nearly identical text, distinct hashes but identical after normalisation, and — in `ingest.jsonl` — the same author and the same ingestion minute.
4. Add near-duplicate detection at ingest (hash of normalised text, plus a shingle or similarity threshold) and count how many of the 12 copies survive. Report the threshold you chose and what it would also reject.

**What you should observe.** The attacker family occupying most of the top `k` while the legitimate document drops out of it, with the legitimate answer replaced by twelve paraphrases of the attacker's claim. This is a *ranking* attack: the attacker never had to write something convincing, only something numerous — which is exactly why it is cheap and why content review alone does not catch it.

**Pivots.** Rename the copies to look like part of the legitimate set, and see which column in `ingest.jsonl` exposes them (author, source, ingestion time). Does a large `k` make flooding easier or harder? What does a legitimate corpus look like on the duplicate detector — how many false positives per week?

**Closing questions.** Why is flooding easier to detect by *provenance* than by content? Which is the better investment for an attacker: one convincing document or twelve weak ones? What makes a similarity threshold hard to set?

## Drill 4 — Canary and drift detection

**Objective.** Turn "the answers changed" into an alert you could run continuously.

**Setup.** Define canaries: questions whose correct answer you know and that the attacker has no reason to touch (`q3` support hours, `q2` escalation threshold). Run the baseline capture twice on the clean corpus and confirm the two runs agree, so that any later change is attributable to the corpus rather than to noise.

**Steps.**

1. After each of Drills 2 and 3, re-run the capture and build a before/after table per question.
2. Classify every row: `unchanged`, `answer-drift`, `source-drift`, or `unstable` (the two clean runs already disagreed — a defect to fix first).
3. Apply the alert criterion: **any canary that moves is an alert**, because nothing the attacker did was aimed at it; a non-canary moving is a signal to investigate.

| ID | Canary? | Before (answer / source) | After (answer / source) | Drift type | Alert? |
| --- | --- | --- | --- | --- | --- |
| q1 | no | | | | |
| q2 | yes | | | | |
| q3 | yes | | | | |
| q4 | no | | | | |
| q5 | no | | | | |

**What you should observe.** With the stand-in answer, drift can only come from ranking, so a canary that moves means the corpus changed in a way that affects an unrelated question — often a broader contamination than the targeted one. If you swap in a local model, some rows will differ between two runs on an *unchanged* corpus: record that variance first, or you will spend the lab chasing noise you generated yourself.

**Pivots.** How many canaries do you need before a single move is meaningful? Which legitimate corpus updates (a price change, a policy revision) will make a canary move, and how do you tell that apart from contamination? What is the production equivalent of this table in your logging stack?

**Closing questions.** Why alert on canaries rather than on the questions you expect an attacker to target? Who receives the alert, and what do they do first?

## Drill 5 — Detection by provenance review

**Objective.** Identify which ingest controls would have kept the attacker's documents out, and which would not.

**Setup.** `ingest.jsonl` filled in for the clean corpus from Drill 1, then extended for the poisoned document and the flood the way an attacker would have had to record them: plausible author, plausible source, missing review.

**Steps.**

1. Review by origin, date and ingest author: which documents are newest, which share an author or a source, which have no review entry.
2. Fill in the table below from your own corpus, then reason about the two attack cases.

| Control at ingest | Stops the single poisoned document (Drill 2)? | Stops the flood (Drill 3)? | Why, or why not |
| --- | --- | --- | --- |
| Human review before ingest | | | The only control that catches a well-formed document that contradicts policy — and the one that does not scale. |
| Source allow-list (approved origins) | | | Stops content pulled from unapproved origins; does **not** stop content pushed through an approved path. |
| Quarantine of new documents | | | Buys time and forces review of everything; under volume, review becomes a rubber stamp. |
| Document signature by the ingest pipeline | | | Proves the document was reviewed and is unmodified — not that the reviewed content was benign. |
| Corpus hash recorded at ingest | | | Detects that something changed after the fact; detects nothing about whether it should have. |

3. Then answer the question the table is really asking: for each attack, which control is *sufficient*, and which merely adds evidence after the fact?

**What you should observe.** No single row is sufficient for both cases. The flood is caught by provenance and duplication controls and not by content review; the single well-formed lie is caught by review and not by any amount of signature or hashing. That asymmetry is the finding: your ingest controls have to cover both, and they are different controls.

**Pivots.** Measure the cost of quarantine — how many legitimate updates per week it would delay. Ask who can write into the corpus today, and whether that set is smaller than the set of people who *should* be able to.

**Closing questions.** Which control do you deploy first for a vendor-assembled corpus, and which for a corpus your own team writes? Why is a hash recorded **at ingest** more useful than one supplied by the document's author?

## Drill 6 — Clean up and verify

**Objective.** Restore the corpus, prove the answers returned to baseline, and find what did not.

**Steps.**

1. Remove the poisoned document and the 12 copies (restore from the clean copy, or revert the directory), and re-run any index build your setup needs — with this lab's retriever there is no index to rebuild, which is itself worth noting: a real deployment usually has one, and a stale index keeps serving the poison.
2. Re-run the baseline capture and diff it against the original `baseline.jsonl`: every question should return to its original answer and source. Any row that does not is the interesting one.
3. For each row that does not return, look *outside* the corpus and say where you looked: an answer cache keyed by question, an agent's memory or a summarised conversation, a stored chat log, a previously exported report, a fine-tuned model.

Corpus cleanup does not clean what has already been memorised. A cached answer keyed by question never re-retrieves, so removing the document changes nothing; an agent's memory carries the poisoned claim forward into a session that never sees it; a model fine-tuned or distilled on the poisoned corpus has it in the weights; and copies outside your index are outside your reach. The mechanisms behind those are in [../methodology/03-model-poisoning.md](../methodology/03-model-poisoning.md) — read them there rather than re-deriving them here — and the retrieval-layer side belongs to this module's [phase 07](../methodology/07-privacy-and-data-leakage.md).

**What you should observe.** Return-to-baseline for the corpus-derived answers, and at least one place where an answer does not return. That place is your finding: it tells you the poison left the corpus before you removed it.

**Pivots.** Purge the cache and re-measure. Ask a *paraphrase* of a question the poisoned document used to answer: if the claim still surfaces without the document, something memorised it. Restore the document and see whether the drift returns — a reproducible switch is much stronger evidence than a one-off observation.

**Closing questions.** What does "clean" mean if you cannot show the answer returned to baseline? Who owns the cache, the memory and the exports — and did you ask them?

## Artifact provenance (no GPU required)

This section needs no model at all: it is the checksum half of supply-chain hygiene, applied to the artifacts you download (weights, tokenizer, adapter, or the corpus itself). Record the hash at acquisition, compare it against the expected value, and keep the record.

```python
# verify_artifact.py — EXAMPLE for you to run; not executed while writing this lab.
#   python verify_artifact.py model.safetensors <expected-sha256>
import hashlib, json, sys

def sha256(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)          # streamed: a large weight file is never read into RAM
    return h.hexdigest()

def verify(path, expected):
    actual = sha256(path)
    ok = actual == expected          # a mismatch is a stop condition, not a warning
    with open("artifact-manifest.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"path": path, "sha256": actual, "expected": expected, "ok": ok}) + "\n")
    return ok

if __name__ == "__main__":
    sys.exit(0 if verify(sys.argv[1], sys.argv[2]) else 1)
```

| Artifact | What you hash | What a match proves | What a match does not prove |
| --- | --- | --- | --- |
| Model weights | the weight file as shipped | These bytes are the bytes you vetted, unmodified since | That the vetted bytes are safe, or that the vendor's "expected" value was honest |
| Tokenizer / config | the tokenizer and configuration files | No quiet substitution after acquisition | That the tokenizer behaves as documented |
| Adapter (LoRA/QLoRA) | the adapter file | The adapter did not change between review and deployment | That the fine-tune did not implant a trigger — a capability-preserving change passes every hash |
| Corpus | every document at ingest | You can prove what you indexed and when it changed | That the content was legitimate when it was indexed (Drill 5) |
| Serialisation format | the format itself | — | Prefer formats that do not execute code when loaded; a pickle-based checkpoint can run code at load time, which hashing cannot undo. See [../methodology/03-model-poisoning.md](../methodology/03-model-poisoning.md) and the [safetensors documentation](https://huggingface.co/docs/safetensors/index). |

## Optional, if you have a local model harness

**Not executed here, and not required for any drill above.** This is a procedure for a machine with a local model, for the case where the *artifact* is suspect rather than the corpus:

1. Run the same prompts file twice — once with the artifact loaded, once with the base model — with identical decoding settings and prompts ([llm-testing.md](./llm-testing.md) has the app, the runner and the labelling rubric).
2. Compare refusal and compliance rates between the two runs, and look for behaviour that appears only with the artifact. Label the replies; do not rely on impressions.
3. Test candidate triggers: rare tokens, unusual capitalisation, an odd phrase, or a sequence lifted from the fine-tuning dataset. A backdoor is conditional, so behaviour on ordinary prompts says nothing.
4. Expect the null result and say so honestly. Benchmarks do not detect this class of change because a capability-preserving backdoor leaves benchmark scores intact and the benchmarks do not contain the trigger; a small sample size, in either direction, supports only a weak claim.

## Scoring and evidence

| Label | Meaning |
| --- | --- |
| `unchanged` | Answer and cited source identical to the baseline. |
| `influenced` | The attacker's document appears in `top_k`; the answer may or may not have changed. |
| `adopted` | The answer changed in the attacker's direction, with the poisoned source cited. |
| `source-drift` | The same answer now cites a different document. |
| `unstable` | The clean baseline itself disagreed between runs — fix this before reading anything else. |

| Metric | How to compute it | Why it matters |
| --- | --- | --- |
| Influence rate | questions with the attacker document in `top_k` ÷ questions | How much of the corpus the attacker reached. |
| Adoption rate | questions labelled `adopted` ÷ questions | What actually reached a user — the impact you can defend. |
| Mean rank delta of the legitimate document | mean(baseline rank − after rank) per question | Flooding shows here first, before any answer changes. |
| Top-k occupancy by the attacker family | slots held by attacker documents ÷ (`k` × questions) | The flooding metric. |
| Canary drift count | canaries labelled `answer-drift` or `source-drift` | The alert signal. |

| Case | Retrieval-log line | Corpus hash (before → after) | Baseline row | Verdict |
| --- | --- | --- | --- | --- |
| q1 / Drill 2 | | | | |

Keep the retrieval log for every row: a verdict without the `top_k` list behind it is a story about a document, not evidence about a retriever.

## Write the finding

```markdown
### Finding — one <document / duplicate set> in the corpus changed <n> of <m> answers

**Corpus and document implicated.** <path> entered via <ingest path>; recorded in `ingest.jsonl`
with author <a> and source <s>.
**Mechanism.** <influence only / adoption / ranking dominance by near-duplicates>; the legitimate
document <stayed at rank 1 / moved from rank 1 to rank N / left the top-k>.
**Reachable impact.** <Which questions, which users, and what the wrong answer now says —
the fictional policy that the application will now state with confidence.>
**Evidence.** <retrieval-log line, corpus hashes before and after, baseline rows, number of
questions affected out of the set.>
**Control recommended.** <One ingest-gate control: review, source allow-list, quarantine,
signature, near-duplicate detection — named at the point where it runs.>
**How the control is tested.** <The re-run that must return every question to baseline, plus the
case the new detector must fire on — and the legitimate document it must not fire on.>
```

A usable poisoning finding names the **ingest gate** rather than the payload, quantifies influence separately from adoption, and includes the legitimate document the new control must not block.

## Common Mistakes & Tips

- **No baseline, or a baseline taken after the first ingestion.** Without a recorded "before", you cannot distinguish drift from a corpus you never measured.
- **Reporting adoption when you measured influence.** Being retrieved and being believed are different findings, with different owners and different fixes.
- **Testing only with a well-written attacker document.** Real contamination is often numerous and mediocre; Drill 3 is the cheap version of the attack and the harder one to see.
- **Assuming a keyword-only lab generalises.** State the simplification's boundary in every finding: semantic dominance needs a real retriever to test.
- **Cleaning the corpus and declaring victory.** Caches, agent memory, exported reports and fine-tuned weights keep the claim alive; Drill 6 is where you find them.
- **Reading one run as a result.** With a model in the loop, label and repeat; variance on an unchanged corpus is the first thing to record.
- **Trusting a hash as a safety judgement.** A match proves the bytes are the bytes you vetted — nothing about whether they were ever safe.
- **Forgetting who can write.** The most useful output of this lab is a list of people and systems that can currently add a document to the corpus.

## Checklist / Self-Test

- [ ] I ran the baseline before planting anything, and my clean baseline agreed with itself across two runs.
- [ ] Every question has an expected answer *and* an expected source, and the source is the top hit on the clean corpus.
- [ ] I recorded a hash for every document at ingest, with author and source.
- [ ] Drill 2: I reported influence and adoption as separate counts.
- [ ] Drill 3: I measured the legitimate document's rank delta and the attacker family's top-k occupancy.
- [ ] Drill 4: I defined canaries and stated the alert criterion in one sentence.
- [ ] Drill 5: I can say which ingest control stops each attack and which only adds evidence afterwards.
- [ ] Drill 6: I can show the answers returning to baseline, and I named what did not return and why.
- [ ] I stated the retrieval simplification and its boundary in writing.
- [ ] Every scoring row has a retrieval-log line and a corpus hash behind it, and all data used was fictional.

## Further Resources

- [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — the training-data and vector/embedding weakness entries this lab exercises.
- [OWASP GenAI Security Project](https://genai.owasp.org/) — the wider guidance set behind those entries.
- [MITRE ATLAS](https://atlas.mitre.org/) — poisoning techniques, in the vocabulary your findings should use.
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) and [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) — provenance and data governance expectations for a retrieval corpus.
- [Safetensors documentation](https://huggingface.co/docs/safetensors/index) — the no-code-execution format referenced in the provenance section.
- Poisoning mechanics this lab deliberately does not repeat — [../methodology/03-model-poisoning.md](../methodology/03-model-poisoning.md).
- Local model, runner and labelling rubric — [llm-testing.md](./llm-testing.md); retriever-side concepts ([phase 07 of this module](../methodology/07-privacy-and-data-leakage.md)) and defensive controls — [../methodology/05-defensive-controls.md](../methodology/05-defensive-controls.md).
- Attack vocabulary — [../cheatsheets/ai-attack-vectors.md](../cheatsheets/ai-attack-vectors.md); evaluation tooling for larger runs — [../tools/ai-testing-tools.md](../tools/ai-testing-tools.md).

> **Verification:** `retrieve.py` was extracted **verbatim from the block above** and executed
> on **2026-09-19** under Ubuntu 24.04 / Python 3.12.3 against a synthetic four-document
> fictional corpus in `/tmp` (not the lab's own corpus, which is yours to write). `python3
> retrieve.py baseline` produced `baseline.jsonl` with five rows and a `run` id; a second run
> of the same command left the file at **five rows, not ten**, with one run id — the earlier
> CLI appended, so the file silently held two indistinguishable rows per question. `python3
> retrieve.py baseline --out baseline_after.jsonl` produced the second capture Drill 2 asks
> for, which the earlier CLI could not: `--out` existed on `ask()` but was never wired to the
> `baseline` command. The poisoned document was `influenced` and `adopted` on all five
> questions of this synthetic corpus. `python3 -m py_compile retrieve.py` passed.
