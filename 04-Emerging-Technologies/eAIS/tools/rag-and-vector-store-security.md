# RAG & Vector Store Security

> eAIS · Tools — INE-Cybersecurity-Certifications-Guide · English
>
> The retrieval path as a security surface: what a vector store actually holds, how to
> inspect an index you did not build, why filtering *after* top-k is already a leak, how
> ingestion becomes an attack surface, and how to detect manipulation or staleness of the
> index. Query shapes here are generic: confirm every field name against your own schema.

> **No command or query in this file was executed while writing it: this machine has no
> local model server, no API keys, and no vector store. Everything here is a syntax
> reference to adapt and run in your own lab.**
>
> **Field names are schema-specific: confirm against your own index before trusting a
> query.** Names like `tenant_id`, `acl`, `chunk_id`, `doc_id`, `embedding_model` below are
> placeholders for whatever your index and metadata store actually call them.

## 1. What this file covers

Retrieval-augmented generation (RAG) is where an AI application reads data it was not
trained on — and therefore where the *authorization model of that data* becomes the
security control. The concepts (embeddings, chunks, similarity, why retrieval changes the
attack surface) are in `../methodology/01-ai-models.md`; corpus poisoning as an attack class
is in `../methodology/03-model-poisoning.md`; the defensive layers are in
`../methodology/05-defensive-controls.md`. This file is the operator's view: what to look
at in a real index, which questions to ask of it, and what the answers mean.

It is deliberately vendor-neutral. Vector stores are described by category (an index that
stores vectors plus metadata, queried by similarity), never by product — every product
exposes its own metadata schema, filter syntax, and consistency model.

## 2. The RAG pipeline as a security surface

Each stage has an owner, a control, and a way to fail. The last column points at where the
module treats the stage.

| Stage | What happens | Control that lives there | Where it is covered |
| --- | --- | --- | --- |
| **Document ingestion** | Content enters from uploads, connectors, sync jobs, tickets, wikis | Authenticated, authorized, attributable writes; source allow-list; provenance recorded | §6 here; `../methodology/03-model-poisoning.md` |
| **Parsing** | The file is converted to text (PDF, Office, HTML, email, tickets) | Untrusted-parser isolation, text-only extraction, metadata stripping, size and page limits | §6 here |
| **Chunking** | Text is split into retrievable units, often with overlap | Chunk boundaries that never mix documents; per-chunk inheritance of the parent's ACL and provenance | §6 here |
| **Embedding** | Each chunk becomes a vector via an embedding model | Pin the embedding model and version; treat vectors as sensitive derived data | §7 here; `../methodology/01-ai-models.md` |
| **Indexing** | Vectors and metadata are written to the index | Write path authorization; metadata complete at write time; idempotent upserts | §3, §8 here |
| **Retrieval (top-k)** | A query vector returns the k nearest chunks | Authorization *inside* the query, not after it | §5 here |
| **Reranking** | A second model reorders candidates | Rerank only the already-authorized set; never re-introduce filtered chunks | §5 here |
| **Context construction** | Chunks are assembled into the prompt | Ordering, delimiters, per-chunk provenance markers, size budget | `../methodology/05-defensive-controls.md` |
| **Generation** | The model answers from the context | Instructions found in retrieved text are data, not orders | `../methodology/02-prompt-injection.md` |
| **Citation** | The answer points back at sources | Cite per chunk with an identifier the user is allowed to resolve | §8, §10 here |
| **Retrieval logging** | Queries, filters, returned ids, and scores are recorded | Log the *filter arguments* and the returned chunk ids, not only the answer | §5 here; `observability-and-tracing.md` |

The interesting property of this pipeline: nine of the eleven stages can ship a correct,
well-tested behaviour while the security property that matters — *this user may not see that
text* — is decided at exactly one of them.

## 3. What a vector store actually holds

A vector store is three things at once, and teams usually only think about the first.

| Content | What it is | Why it matters | What breaks if it is missing or wrong |
| --- | --- | --- | --- |
| **Chunk text** | The retrievable unit of content | It is what enters the prompt; anything in it is attacker-controlled input to the model | Unusable answers; with no provenance, impossible to attribute a leak |
| **Vector** | The embedding of that chunk | Determines *what gets retrieved*; a wrong or stale vector silently makes a document unreachable or permanently dominant | Silent recall failures that look like "the assistant is dumb" |
| **Metadata** | Origin, author, tenant, ACL, version, timestamp, supersedes | **Metadata is the real access-control layer for RAG.** The vector decides relevance; the metadata decides permission | Without ACL/tenant metadata, no retrieval-time filter is possible, and the only remaining option is filtering after the fact — which is a leak (§5) |
| **Identifier** | Chunk id and parent document id | Makes citation, deletion, and audit possible | Deletion cannot be verified; citations cannot be resolved |
| **Provenance** | Which source, which ingestion run, which parser/embedding version | Lets you find every chunk affected by a poisoned source or a parser change | Remediation becomes a full re-index, because you cannot scope the blast radius |

```text
# Minimal metadata set to demand before a corpus is put in front of users.
# Names are schema-specific: confirm against your own index.
chunk_id, doc_id, tenant_id, acl (list or group ids), source_uri,
author, created_at, source_modified_at, indexed_at,
ingestion_run_id, parser_version, embedding_model, embedding_version,
doc_version, supersedes (doc_id of the older version, if any)
```

If your index cannot answer "which tenant and which ACL does this chunk belong to?" for
every chunk, retrieval-time authorization is not implementable — and no prompt engineering
will fix that.

## 4. Inspection recipes

Questions to ask of an index you are auditing. Each has a generic query shape; adapt the
syntax to your store's metadata filter language. A "bad" result is not automatically an
incident — it is a finding to verify against the ingestion pipeline that wrote it.

**1. Is every tenant's corpus the size you expect?**

```sql
-- Pseudo-query: a relational view over index metadata, not a vector-store syntax.
-- Compare tenants against the source systems' own counts.
SELECT tenant_id, source_uri, COUNT(DISTINCT doc_id) AS docs, COUNT(*) AS chunks
FROM   index_metadata
GROUP  BY tenant_id, source_uri
ORDER  BY chunks DESC;
-- Look for: tenants you do not recognise, sources nobody remembers connecting,
-- and a tenant whose chunk count dwarfs its document count (chunking gone wrong).
```

**2. Which chunks have no ACL at all?** A null or empty ACL is not "public" — it is
*undefined*, and the code path that treats it will decide for you.

```sql
SELECT COUNT(*) AS chunks_without_acl
FROM   index_metadata
WHERE  acl IS NULL OR acl = '' OR tenant_id IS NULL;
-- Any non-zero number is a blocking finding for a multi-tenant corpus: check how the
-- retrieval path treats those rows (deny-all, or silently no filter at all).
```

**3. Which near-duplicates dominate retrieval?** Copies inflate apparent agreement and can
bury the authoritative document.

```sql
-- Group by a cheap similarity signal your store can give you (hash of normalised text,
-- a similarity threshold between chunk vectors, or a document fingerprint).
SELECT doc_id, COUNT(*) AS near_duplicates, MIN(indexed_at) AS first_seen
FROM   index_metadata
GROUP  BY fingerprint          -- exact or near-duplicate key, schema-specific
HAVING near_duplicates > 1
ORDER  BY near_duplicates DESC;
-- Then check retrieval logs: if one duplicate family is most of the top-k for many
-- queries, the corpus is effectively one document wearing many hats.
```

**4. Which documents changed in the source *after* they were indexed?**

```sql
SELECT doc_id, source_uri, source_modified_at, indexed_at
FROM   index_metadata
WHERE  source_modified_at > indexed_at
ORDER  BY source_modified_at DESC;
-- Non-empty means the assistant is answering from superseded text. This is the
-- staleness check that matters most for policy, price, and procedure documents.
```

**5. Is anything in the index that no longer exists in the corpus?**

```sql
-- Left join the index against the current source inventory.
SELECT i.doc_id, i.source_uri, i.indexed_at
FROM   index_metadata i
LEFT   JOIN source_inventory s ON s.doc_id = i.doc_id
WHERE  s.doc_id IS NULL;
-- Deleted-at-source-but-still-retrievable content is how retired secrets and
-- withdrawn documents keep answering questions months later.
```

**6. Which document is retrieved the most?** Not "which is most relevant" — which is
returned most often.

```sql
-- From retrieval logs (ids and filters logged per query), not from the index itself.
SELECT doc_id, COUNT(*) AS hits, COUNT(DISTINCT query_id) AS distinct_queries
FROM   retrieval_log
GROUP  BY doc_id
ORDER  BY hits DESC
LIMIT  20;
-- A single document appearing in most answers is a signal: either it is genuinely
-- the corpus, or it is a chunk shaped like the questions people ask (§7).
```

**7. Did any ACL change without a re-index?** Permissions move faster than embeddings.

```sql
SELECT i.doc_id, i.acl AS indexed_acl, s.current_acl, i.indexed_at
FROM   index_metadata i JOIN acl_source s ON s.doc_id = i.doc_id
WHERE  i.acl IS DISTINCT FROM s.current_acl;
-- If the index carries the old ACL, a user who lost access still retrieves the text,
-- and a user who gained access does not. Both are findings.
```

**8. Which embeddings were produced by a different model version?** A mixed index
compares vectors from two spaces that are not comparable.

```sql
SELECT embedding_model, embedding_version, COUNT(*) AS chunks, MIN(indexed_at)
FROM   index_metadata
GROUP  BY embedding_model, embedding_version
ORDER  BY chunks DESC;
-- More than one row for a single corpus means recall is quietly broken for one subset,
-- and the ranking is not the ranking anyone tested.
```

## 5. Retrieval-time authorization

**Why post-filtering is already a leak.** If the store returns the k nearest chunks and the
application then discards the ones the user may not read, the unauthorized text has already
been:

- scored, and its score logged (scores correlate with content — that is a side channel);
- returned over the network into the application process, where it can reach logs, traces,
  caches, error messages, and evaluation datasets;
- possibly placed into the prompt if context construction happens before filtering, which is
  the common bug when filtering is added later to a working prototype;
- counted in `k`: if you ask for 10 and keep 3, the user silently receives a worse answer,
  which is why teams then "fix" the filter by relaxing it.

**The correct pattern** is that authorization is part of the retrieval query, not a step
after it: the tenant and ACL predicates are evaluated by the store while it selects
candidates, so unauthorized chunks are never candidates.

```text
# Shape of an authorized retrieval call (pseudocode, schema-specific names).
results = index.query(
    vector        = embed(user_query),
    top_k         = k,
    filter        = { "tenant_id": current_tenant,
                      "acl":       { "in": user_group_ids },
                      "doc_version": "current" }   # field names vary by store
)
# Non-negotiable properties:
#  - the filter is derived from the authenticated session, never from user input;
#  - the filter is evaluated during candidate selection, not after scoring;
#  - the reranker only sees `results`;
#  - the prompt is built from `results` and nothing else.
```

**What to look at in the code:**

1. Where does the filter value come from — the session/token, or a request parameter the
   caller can set? A `tenant_id` taken from the request body is an authorization bypass with
   extra steps.
2. Is the ACL predicate part of the query, or a list comprehension over the response?
3. Does the reranker run before or after the filter? Reranking a wider candidate set and
   filtering afterwards reintroduces the leak.
4. Is there a code path (admin tool, "debug" endpoint, evaluation harness, batch job) that
   queries the index with no tenant predicate? Those paths are usually the real breach.
5. Does deletion/ACL propagation reach the index, or only the source system?

**What to look at in the retrieval logs:** the per-query record should show the filter
arguments, the tenant/session identity, the returned chunk ids, and the scores. If the log
contains only the question and the answer, you cannot tell an authorized retrieval from a
leak after the fact. The log is also the fastest way to detect post-filtering: a request for
k candidates that consistently returns fewer than k authorized rows means filtering is
happening after scoring.

## 6. Ingestion is an attack surface

Everything that can write to the corpus can write to the assistant's context. Treat
ingestion as a privileged, untrusted-input interface, because that is what it is.

| Path to write | How it is abused | Check |
| --- | --- | --- |
| **Upload routes** | Any authenticated user uploads a document that a more privileged user will later retrieve | Who may upload, into which tenant and scope, and does the chunk inherit the *uploader's* ACL or the *reader's* need-to-know? |
| **Parsers** | Text a human reading the rendered document never sees becomes chunks: hidden or white-on-white text, tiny fonts, markup comments, alt text, footnotes, headers/footers, document properties, speaker notes, hidden rows/sheets, annotations | Extract text with your parser and diff it against what a human sees in the rendered view; audit the parser's output, not the original file |
| **Self-updating documents** | A page, ticket, or wiki the assistant trusts is edited by someone who cannot read the assistant's answers — the change flows into the index automatically | For every synced source: who can edit it, what is the sync interval, and is the change reviewed before it becomes retrievable? |
| **Chunk size and overlap** | Overlap copies text across a boundary, so a chunk attributed to document A can carry text from document B — including a document the reader may not open. Large chunks also blend topics, so one poisoned sentence rides along with legitimate content | Verify that no chunk contains text from more than one document; keep overlap inside the document's own ACL, never across documents or tenants |
| **External connectors** | The connector's credentials define what enters the corpus; a broad service account becomes a permanent, invisible writer | Enumerate connectors, their scopes, their owners, and their last successful run |
| **Reprocessing / backfill** | A re-ingest with a changed parser or chunker silently rewrites the corpus, and old ACL metadata may not be re-applied | Make re-ingestion idempotent and confirm metadata is rebuilt, not inherited from a stale row |

## 7. Embeddings as data

A vector is derived from text, so it inherits the text's sensitivity — and adds properties
of its own.

- **Similarity is cosine (or dot/inner product) closeness in the model's space.** It encodes
  topical and stylistic similarity, not truth, not authority, and not currency. "Nearest" is
  a relevance claim only.
- **Semantic collisions are unavoidable.** Two texts with unrelated meanings can sit close
  together (negation, hypotheticals, quoted attacker text, other languages). This is why a
  retrieved chunk can be a *counter*-example, a joke, or a quote of the attack itself — and
  why retrieval rails must be able to reject a chunk, not merely rank it.
- **Query-shaped documents.** An attacker who can write to the corpus can write a chunk that
  is literally a plausible user question with the attacker's answer attached. It wins the
  top-k not by hacking anything, but because it *is* the query. Detect it by reviewing your
  most-retrieved chunks (§4 recipe 6) as text, on a schedule.
- **Approximate inversion.** Published research shows embeddings leak information about their
  source text: a vector can be used to reconstruct text that is recognisably similar, with
  quality depending on the model, the attacker's access to the embedding endpoint, and the
  number of queries available. The practical consequences: do not treat an embedding as
  anonymised data, do not expose raw vectors to users or tenants that should not see the
  text, and treat a leaked vector export as a content exposure, not a numeric curiosity.
  Its limit matters too — inversion is approximate and partial, not a decryption, so
  "recoverable in principle" should not be reported as "recovered verbatim".

## 8. Integrity of the index

Whoever can write to the index can author the assistant's beliefs.

| Aspect | Question to answer | Failure impact |
| --- | --- | --- |
| **Who can write** | Which credentials can upsert chunks? Ingestion service, admin UI, backfill script, a notebook someone left with a key? | A single over-scoped key is a permanent corpus-write path with no review |
| **Who can delete** | Is deletion possible by the same identity that uploads? Who can delete a policy document? | An attacker who can delete is an attacker who can make the assistant forget a control — and a user exercising a deletion right can silently empty a shared corpus |
| **Staleness** | How old is the oldest chunk in active use, and what happens when a policy is superseded? | The system confidently answers with retired policy; nobody notices because the answer is fluent |
| **Versioning of the corpus** | Is the corpus a versioned artifact, or "whatever is in the store"? Can you answer "what did the index contain on date X?" | No rollback, no forensics, no way to scope a poisoning incident |
| **Embedding reprocessing** | On an embedding-model change, is the index rebuilt atomically or mixed? | Mixed-version index compresses recall and ranking quality, often blamed on the model |
| **Deletion propagation** | Does deleting at source remove chunks, or only hide a document row? | Content that "was deleted" keeps being retrieved and cited |
| **Canary documents** | Is there a synthetic document with unique markers that no user should retrieve? | Without one, exfiltration through retrieval is invisible |

Canary documents are the cheapest integrity control here: plant a document whose text and
access scope are known, restricted to a tenant that does not exist in production. Then
alert on any retrieval that returns its chunk id, any citation that references it, and any
appearance of its marker in an answer to a normal user. It simultaneously detects ACL
failures, cross-tenant leakage, over-broad ingestion, and a reranker resurrecting filtered
candidates. `../methodology/07-privacy-and-data-leakage.md` covers canary measurement as a
leakage metric; `../cheatsheets/attack-to-control-mapping.md` lists the candidate controls
per attack class, including the retrieval-probe recipes.

## 9. Test plan

Cases to run against your own lab target. Each is deliberately written as *behaviour to
observe*, not as a tool invocation. `../labs/rag-data-leakage-lab.md` is the practical
execution of this plan.

| Case | What it tests | Expected observation (safe behaviour) |
| --- | --- | --- |
| Ask a question whose only source is another tenant's document | Cross-tenant isolation | Answer is "not in the available documents" — and the other tenant's chunk id appears nowhere in the logs for this request |
| Ask a question about a document the user's ACL excludes | Retrieval-time authorization | No chunk from that document in the returned ids, not even in the candidate set |
| Upload a document with instructions hidden in text a human would not read | Parser and indirect injection | Summarisation works; the hidden instruction is not obeyed and not reproduced |
| Index two versions of the same policy, then ask about it | Versioning/supersession | The answer follows the current version, or says which version it used |
| Update the source document, ask immediately, then ask after the sync interval | Staleness | The gap is known and documented; the assistant does not blend old and new text silently |
| Change a user's group membership, then ask a question their old group could answer | ACL propagation | Access is lost as fast as the authorization model promises — measured, not assumed |
| Plant a near-duplicate of an authoritative document with one altered sentence | Poisoning via duplication | The altered sentence does not become the answer, or the conflict is surfaced rather than averaged |
| Retrieve the top-k in the logs and read the chunks as text | Query-shaped documents | No chunk in the frequent-retrieval list is a fabricated Q&A pair |
| Delete a document at the source, then ask about it | Deletion propagation | The content is gone from answers and from the returned ids |
| Query with the retrieval filter deliberately disabled in a test build | Control efficacy | The leak shows up — proving the positive result above came from the filter, not from the corpus |
| Retrieve the canary document | Integrity monitoring | The alert fires; if it does not, the canary is not wired to anything |

## 10. Failure diagnosis

| Symptom | Probable cause | Check |
| --- | --- | --- |
| An answer cites a document the user should not see | Filtering after top-k, or no tenant predicate on this code path, or ACL metadata null on those chunks | Log the filter arguments for the request; count chunks with null ACL (§4 recipe 2); grep the code path for the query call and read whether the filter is a query predicate or a post-processing step |
| The top-k always returns the same document | Duplicate/near-duplicate chunks dominating, or a query-shaped document, or a reranker with a stuck high prior | Rank chunks by retrieval frequency (§4 recipe 6) and read the top ones as text; check duplicates (§4 recipe 3) |
| The index does not reflect the latest edit | Ingestion sync interval, a failed run nobody alerted on, or a parser dropping the changed section | Compare `source_modified_at` against `indexed_at`; check the ingestion run's last success and its error rate |
| The ACL metadata is null | A write path that did not populate it (backfill script, connector, manual upsert) | Group chunks by ingestion run and find which run produced the null-ACL rows; fix the writer, not the rows |
| The reranker changes the expected order | Reranker trained or prompted for a different notion of relevance; it sees candidates that were filtered out; input truncation | Log candidate ids before and after reranking; if an unauthorized id appears in the before-list, the leak is upstream |
| Answers degrade after an embedding-model change | Mixed-version index (§4 recipe 8) | Group chunks by embedding version; if there is more than one row, reprocess the corpus atomically |
| The model obeys text from a document | Instruction found in retrieved data treated as an order — a prompt-construction and rail problem, not a retrieval problem | Read the assembled prompt; separate instructions from data with delimiters and per-chunk provenance; see `../methodology/02-prompt-injection.md` |
| A deleted document still answers questions | Deletion removed the source row but not the chunks, or a cache/embedding copy survives | Query the index directly by doc id after deletion; check caches and any exported vector copies |

## 11. Limits

- **There is no "secure RAG" you can configure.** Retrieval security reduces to two things:
  the ACL that is enforced at query time, and the isolation between tenants. Everything else
  — chunk size, similarity thresholds, reranking, prompt hardening — tunes quality and
  narrows exposure; none of it substitutes for authorization.
- **A prompt cannot enforce permissions.** Retrieved text arrives inside the same context as
  your instructions; the model has no reliable notion of who is allowed to read what.
- **Metadata is only as good as its writer.** ACLs that are correct at ingestion and never
  updated decay into wrong ACLs; measure propagation delay rather than assuming it.
- **Similarity is not authority.** The nearest chunk may be a quote, a joke, a draft, or a
  superseded version. Retrieval quality and retrieval safety are separate properties.
- **Deleting from the source does not delete the copies.** Indexes, caches, evaluation
  datasets, logs, and vector exports are all copies; enumerate them before promising a
  deletion.

## Common Mistakes & Tips

- **Filtering after the search.** The most common RAG authorization bug, and the easiest to
  prove: log the returned candidate ids. If unauthorized ids are in the candidate set, the
  document was already exposed inside your own infrastructure.
- **Treating a null ACL as public.** Undefined permissions should deny, not allow. Decide
  explicitly, then make the ingestion path refuse to write chunks without tenant and ACL.
- **Skipping metadata at write time.** Adding ACLs later to a corpus built without them is a
  re-ingestion project. Demand the metadata before the corpus reaches users.
- **Assuming "it is in the index" means "it is current".** Compare source modification time
  against indexing time; stale policy is a security failure that reads as a fluent answer.
- **Forgetting that ingestion is privileged.** Every upload route and connector is a write
  path into the model's context; review it like a privileged API, with its own owner.
- **Parsing with a rich parser and trusting it.** Hidden text, comments, and metadata become
  chunks. Audit the parser's text output, not the rendered document.
- **Ignoring the log.** Without filter arguments and returned ids in the log, you cannot
  distinguish an authorized answer from a leak — you can only read the prose and hope.
- **No canary and no retention policy.** Plant a canary document and keep a versioned corpus;
  both are trivial compared with reconstructing an incident from nothing.

## Checklist / Self-Test

- [ ] I can name the stages of a RAG pipeline and the control that lives in each one.
- [ ] I can explain why metadata, not the vector, is the access-control layer.
- [ ] I can write a query that finds chunks with no ACL or no tenant in an index I control.
- [ ] I can explain why filtering after top-k is already a leak, and name three places the text has already reached.
- [ ] I can point at the line in my own code where the retrieval filter is built, and say where its value comes from.
- [ ] I can list the ingestion paths into my corpus and who may write through each.
- [ ] I can explain how hidden text in a document becomes a chunk, and how to check for it.
- [ ] I can describe what a query-shaped document is and how I would spot one in the retrieval logs.
- [ ] I can measure whether a stale index is answering questions, and how fast an ACL change takes effect.
- [ ] I can explain what a canary document detects, and why I want one even in a single-tenant corpus.
- [ ] I can state the two properties that actually make retrieval safe, and what I would tell a team that wants to fix a leak with a better prompt.

## Further Resources

- [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — includes the vector-and-embedding and sensitive-information-disclosure entries.
- [OWASP GenAI Security Project](https://genai.owasp.org/) — reference guidance on LLM application and data risks.
- [MITRE ATLAS](https://atlas.mitre.org/) — adversarial techniques relevant to retrieval and corpus manipulation.
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) and [NIST AI 600-1 (Generative AI Profile)](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-600-1) — governance framing for data and lifecycle controls.
- [Promptfoo](https://github.com/promptfoo/promptfoo), [DeepEval](https://github.com/confident-ai/deepeval), [Giskard](https://github.com/Giskard-AI/giskard) — harnesses for turning the test plan in §9 into repeatable cases (see `evaluation-and-guardrails.md`).
- [Microsoft PyRIT](https://github.com/microsoft/PyRIT) and [garak](https://github.com/NVIDIA/garak) — attack generation for the injection and leakage cases above.
- [INE Security — eAIS (AI Systems Security Specialist)](https://ine.com/security/certifications/eais-certification) — the official certification page.
