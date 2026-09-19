# Triage at Scale — Velociraptor & Fleet Evidence Collection

> eCDFP · Tools — INE Cybersecurity Certifications Study Guide
>
> How an examiner collects and queries evidence across hundreds of endpoints without imaging every disk: remote triage with Velociraptor, the offline collector for hosts that cannot or must not enrol, and the judgment call between triage and full acquisition. Every command below is a syntax reference — this repository ships no captured command output — and every example targets systems you own or are explicitly authorized to examine.

## 1. Why triage at scale exists

A full disk image is the most defensible artefact in digital forensics, and also the least scalable one. Imaging a laptop costs an hour or more of copying, a write blocker, an evidence drive, a forensic workstation, and a decision to take the machine out of service; then the image must be stored, hashed, and analysed. Multiply that by an estate of hundreds of machines and the method collapses: weeks of work and terabytes of storage per incident, most of it containing nothing relevant.

An investigation rarely needs everything from one host. It needs **one specific answer from many hosts** — which machines carry this scheduled task, who has this registry value, which hosts executed this binary, which files share this hash. That is a breadth question, and triage answers it: collect the specific artefacts (event logs, registry hives, prefetch, `$MFT`, a process listing, one file, a hash set) or run read-only queries, and return structured results per host at a cost of minutes and megabytes instead of hours and gigabytes.

The trade-off, stated honestly:

| Approach | What you gain | What you give up |
| --- | --- | --- |
| **Triage at scale** | Breadth (every enrolled host), speed (minutes to hours), comparability (the same artifact on every host, so the results table *is* the comparison), low disruption, and the option of a follow-up question later if the host stays enrolled | **Completeness.** A triage collection copies what the running OS exposes *now*: no unallocated space, no slack space, and no deleted data unless the artifact you chose deliberately parses a structure that still references it — and you have to know that it does. What the OS does not expose through its own APIs, you do not get. |
| **Full disk image** | Everything: allocated and unallocated space, deleted files, file-system metadata, timestamps, plus a source hash proving the copy is bit-for-bit | Time, storage, hardware, host downtime — and it still does not scale past a handful of hosts per incident. |

Three consequences follow, and they decide most real cases:

1. **Triage finds the hosts; imaging proves the finding.** Sweep the fleet with triage, then image the two or three machines that matter and do the complete, defensible analysis there.
2. **Triage is a live collection, so it acts on the host.** You are querying a running system, which is why the order of volatility still applies ([../methodology/01-acquisition.md](../methodology/01-acquisition.md)). State that exists only in RAM is not in a triage collection either — that is a memory capture.
3. **Triage trusts the operating system it queries.** A compromised kernel, a hidden rootkit, or a tampered agent can conceal or fabricate what a remote query sees. Where anti-forensics is a realistic hypothesis, the answer is offline analysis of an image, not a broader query.

Single-disk acquisition, write blockers, and The Sleuth Kit work belong to [forensic-toolkit.md](forensic-toolkit.md); the offline parsers that turn collected artefacts into timelines belong to [windows-artifact-tools.md](windows-artifact-tools.md); what each evidence type can and cannot prove is the subject of [../cheatsheets/evidence-validity.md](../cheatsheets/evidence-validity.md). This file is only the collection-and-query layer that sits above them.

## 2. Velociraptor: architecture

**What it is.** A DFIR platform built around one idea: ask a question of every endpoint at once and get structured answers back. Four parts make it up.

| Part | What it is | Why it matters to an examiner |
| --- | --- | --- |
| **Server** | Front end that clients connect to, a datastore where collections land, the GUI, and the hunt manager | It is the authorisation boundary *and* the record of what was collected — hunt ids, artifact names, parameters, and per-client status all live here |
| **Enrolled clients** | The agent on each endpoint, enrolled to that server | A host that never enrolled, or that is powered off, cannot be queried. That is a scope limit, never a negative finding |
| **VQL** | The query language every collection is written in: SQL-shaped, with plugin *sources* where SQL has tables | Collections are readable and reviewable rather than black boxes; the language itself is covered in [../../eCTHP/tools/hunting-platforms.md](../../eCTHP/tools/hunting-platforms.md) |
| **Artifacts** | Packaged, parameterised, versioned VQL queries | They are the unit of work: you collect an artifact, not "a disk" |

An artifact has a dotted, namespaced name (`Windows.*`, `Linux.*`, `Generic.*`, and so on), declares **parameters** (paths, globs, time windows, limits) with defaults, and contains one or more **sources**. Each source is a named query producing its own result set, so collecting an artifact with three sources returns three answer sets from one run. Built-in artifacts ship inside the binary — which is precisely why artifact availability and behaviour drift between releases.

**What it produces.** Per client: result rows (structured tables), uploaded files when the artifact collects files rather than facts, and a per-collection status and log. The property that matters for forensics is that a well-chosen artifact returns the **raw artefact** — the actual file, hive, or log — rather than only a normalized summary, so a hit can be verified without a second collection ([../../eCTHP/tools/hunting-platforms.md](../../eCTHP/tools/hunting-platforms.md)). Which of the two you get is a property of the artifact, so read it before you run it (section 4).

**How to use it.** Sections 3 to 6 below are the operating sequence: configuration and enrolment, one-off collection, hunt across the fleet, offline collector, and the record you keep. Before any of it, ask the binary what it has:

```bash
# What does this release actually accept?
velociraptor --help
# what to look for: the global flags (above all the one that points at a configuration
# file) and the command groups available — server, client, artifacts, config, and
# whatever else this build ships.
```

**Limitations.** Velociraptor is a collection and query platform, not a retention or correlation engine: it answers a question now, and long-term trending needs the results shipped elsewhere. It reaches only enrolled hosts, only while they are running, and only what their OS exposes. It executes code on production endpoints, so scope and resource limits are a safety property rather than a nicety. It is also an authorisation boundary in exactly the same sense as any other console: a client in your server is a host you may collect from. The family-level comparison against SIEM, EDR, and notebooks is in [../../eCTHP/tools/hunting-platforms.md](../../eCTHP/tools/hunting-platforms.md); section 8 below is what goes wrong when you operate it.

## 3. Operating it

### 3.1 Generate a server configuration and start the server

```bash
# Interactive configuration generation. Answer for your own environment; nothing here
# is safe to copy blind, because the prompts decide the front-end URL and the paths.
velociraptor config generate -i
# what to look for: it writes a server configuration and a matching client configuration
# and prints the paths it used. Datastore, results, and logs all land under paths named
# here, so know where they are before you collect anything.

# Start the server (front end and GUI) using that configuration.
velociraptor --config server.config.yaml gui
# what to look for: the GUI URL it prints, the datastore path, and a certificate
# fingerprint. A GUI with an empty client list is normal before any client enrols.
```

How the configuration file and the datastore are named on the command line differs between releases: the fleet-DFIR guide in this repository shows a datastore form ([../../eCTHP/tools/hunting-platforms.md](../../eCTHP/tools/hunting-platforms.md)). Treat both as shapes, run `velociraptor gui --help` on your build, and record the exact command you used — a collection is only reproducible if the server invocation is written down too.

### 3.2 Enrol a client

The enrolment material comes from the **server**, not from the endpoint. Generating the server configuration also generates the client configuration carrying the server URL and the trust material the client needs, plus — depending on release and configuration — an enrolment secret or a server-side approval step in the GUI. Nothing about enrolment is derived on the host being enrolled.

```bash
# Shape only: run the agent with the client configuration your server generated.
velociraptor --config client.config.yaml client -v
# what to look for: the client printing its server URLs, then its own client id, then
# heartbeats. Confirm the exact subcommand and flags with `velociraptor client --help`
# on your build: this is the part of the CLI that has changed most between releases.

# On the server side, confirm the host arrived and how fresh its data is.
# what to look for: the client in the client list, with its last-seen time, its reported
# version, and any label you assign for scoping hunts.
```

Two operating rules. First, the enrolment secret or agent package is a **credential**: whoever holds it can enrol a host into your server, so distribute it the way you distribute keys and never leave it in a share. Second, an enrolled host is a host you can collect from — enrol only machines you are authorized to examine, and stop querying when the case scope closes.

### 3.3 The GUI

The GUI is where the shape of a collection is visible before it runs: the client list (last-seen time, version, labels), the artifact collector (pick an artifact, read its parameters, choose clients, watch per-client status), the hunt manager, notebooks, and server settings including storage and retention. Use it to *learn* the shape and to sanity-check scope; use the CLI when you need the same action written down reproducibly. A view in the GUI is a convenience — the result archive you download is the evidence.

### 3.4 One-off collection from a single client

Always before a fleet sweep: a single host, a single artifact, and you read what came back.

```bash
velociraptor artifacts list
# what to look for: the artifact names this build ships, namespaced by platform. Copy
# the name out of this output; never retype one from memory or from a blog post.

velociraptor artifacts collect Windows.System.Pslist
# what to look for: result rows per client plus a per-client status. A source that
# returns nothing is a statement about scope, not proof of absence.
```

Which client the server-side collection targets is a selector in your build's CLI — confirm it with `velociraptor artifacts collect --help`; the responder guide in this repository shows the client-id form of the same command ([../../eCIR/tools/forensic-tools.md](../../eCIR/tools/forensic-tools.md)).

### 3.5 A hunt across many clients

A hunt is one artifact plus one parameter set plus one client selector, launched once and evaluated by every client that checks in during the hunt's lifetime.

1. Create the hunt, choose the artifact from the catalogue, and set every parameter deliberately.
2. Set the client selector — labels, OS, or an explicit host list — to the smallest set that answers the question, not to "everything because it is easy".
3. Set the expiry on purpose. A hunt is not finished when you launch it; it is finished when it expires or you stop it, and clients that check in afterwards are simply not covered.
4. Set resource limits so the collection cannot saturate a production endpoint.
5. Launch it and watch per-client status. "Client returned no rows" and "client never answered" are two different statements, and only one of them is about the host's contents.
6. When it is done, download the results and write the hunt id, artifact name, parameters, and the UTC window into the collection record (section 6).

There is also a CLI/API path for creating and managing hunts; confirm the subcommand names with `--help` on your build. The GUI is the safer place to learn the shape, because it shows you an artifact's parameters before you commit to a fleet-wide run.

### 3.6 Notebooks

Velociraptor notebooks let you post-process collection results next to the case: query the results, join hosts, summarise, and keep the cell with the hunt instead of exporting to a spreadsheet. Same discipline as the analysis notebooks in the hunting guide ([../../eCTHP/tools/hunting-platforms.md](../../eCTHP/tools/hunting-platforms.md)): a notebook cell is analysis, not evidence — the raw result archive and the query text are the record. Never paste production credentials or third-party personal data into a shared notebook.

## 4. Discovery first: never hardcode an artifact name

The artifact catalogue is versioned and namespaced, so a name you remember is a name from *some* release. Two failures follow, and the second is the dangerous one:

- A typo or a removed name fails loudly — no such artifact — which costs you a minute.
- A **wrong-but-real** name runs happily and returns plausible rows answering a different question. Nothing in the output tells you that you asked the wrong thing.

So: discover, then read, then run.

```bash
# 1. What does this build ship?
velociraptor artifacts list
# what to look for: the catalogue, grouped by platform prefix. This output is the only
# authoritative source of names for the version you are running.

velociraptor artifacts list "Windows.*"
# what to look for: how the wildcard is matched on your build — quoting behaviour and
# whether the pattern is anchored differ between releases.

# 2. How do I inspect ONE artifact before running it?
velociraptor artifacts --help
# what to look for: the subcommand that prints a single artifact's definition — its
# sources, its parameters and their defaults, and its version. Subcommand names have
# changed between releases, so take the name from this help output.
```

Read three things in that definition before you run the artifact anywhere important: **its parameters** (which paths, which globs, which time window — a default of "everything under the system drive" is a production incident), **whether it uploads files or only returns rows** (this decides whether you will hold evidence or a summary), and **how many sources** it has (this decides how many result sets you must reconcile).

Artifact names I am confident enough to name here, because this repository already uses them: `Windows.System.Pslist` ([../../eCTHP/tools/hunting-platforms.md](../../eCTHP/tools/hunting-platforms.md)) and `Windows.KapeFiles.Targets` ([../../eCIR/tools/forensic-tools.md](../../eCIR/tools/forensic-tools.md)), plus the wildcard namespaces `Windows.KapeFiles.*` and `Windows.Registry.*`. Anything else — a scheduled-task listing, MFT parsing, prefetch parsing, event-log gathering, a YARA sweep across the estate — exists under *some* name on most builds, but confirm the exact name and parameter set on your build before it goes into a runbook. Writing a runbook around an artifact name you did not read on your own build is how a team ends up collecting the wrong thing for months.

## 5. The offline collector

An offline collector is the Velociraptor binary repacked into a single self-contained executable with a preset artifact set and its parameters embedded. It runs once on the host, writes a result archive (locally, and optionally uploading it if a server is reachable), and requires **no enrolment**: no agent that stays behind, no trust relationship, no server connection at collection time.

That matters in four situations a service account cannot cover:

- **A third party's machine.** You may be allowed to run a collector without being allowed to install an agent or point their host at your infrastructure. An offline archive keeps the collection on their side of the boundary and can be handed over on media with a hash.
- **A host you are about to rebuild.** The collector is your last chance to take a hashed snapshot of the artefacts before the wipe; after the rebuild there is no second collection and no reference value.
- **A host that cannot enrol.** No route to the server, no certificate trust relationship, or a policy that forbids persistent agents.
- **An isolated or air-gapped estate.** Run the collector, then walk the archive out.

```bash
# How does THIS release build a collector? Start by listing the subcommands you have —
# do not assume the subcommand below is named this way on your build.
velociraptor config --help
# what to look for: the subcommand that packs a configuration and artifacts into a
# standalone binary, if this release exposes one.

velociraptor config repack --help
# what to look for: whether your build takes a collector specification file or flags that
# name the artifacts and their parameters directly, and what it can embed (target OS,
# output format, whether it may upload). The switch names and the specification format
# have changed across releases — if the CLI shape is unclear, build the collector from
# the GUI's offline-collector page instead, which exposes the same choices interactively.
```

Treat the output the same way you treat an image: hash it at the moment of collection, record who ran it and where the archive went, and store the archive as the sealed original. Two caveats that belong in the report rather than in a footnote: an offline collector produces a **triage collection** with all the completeness limits of section 1, and it **executes code with the privileges you launch it with** (in practice, local administrator), which is a change to the host that must be recorded alongside the collection.

## 6. Evidence handling for remote collection

The ethics are not softer because the collection was remote:

- **Written authorisation first.** Before collecting from any host, know who authorised it, in writing, for which hosts, which artefacts, and which purpose. The scope granted is the ceiling of what you may collect — not a starting point.
- **Data minimisation across a fleet.** You collect *copies of specific artefacts*, not everyone's files. A hunt that sweeps an estate for anything interesting about uninvolved employees turns an authorised examination into a data-protection incident, and it is the examiner who authorised the query.
- **Read-only collection.** Prefer artifacts that read and return over anything that writes. VQL can modify a host; do not, and do not "tidy up" — no deleting temp files, no clearing logs, no rebooting for convenience while the case is open.
- **Chain of custody and hashing.** Name who held the evidence, when, and what they did with it. Hash the archive the moment it exists, and hash every later copy against it.
- **The original stays sealed.** Analysis happens on copies. The archive you first wrote is the original.

```powershell
# Hash the result archive before you copy it anywhere else
Get-FileHash -Algorithm SHA256 -Path C:\case\collection.zip
# what to look for: the algorithm, the hash value, and the exact path. Record all three
# in the collection record below, next to the client id and the UTC window.
```

A collection record mirrors an acquisition log, with one honest difference: a live host cannot be hashed, so the **archive hash plus the client id plus the collection window** are your integrity and attribution anchors, and the host's own state at collection time remains uncaptured.

```text
COLLECTION RECORD — remote triage
Case / exhibit .......... case identifier, exhibit number
Authorisation ........... who authorised the collection, when, and the scope granted
Examiner ................ name and role of the person who ran and sealed the collection
Server .................. server host, version, datastore path, exact server command used
Target .................. client id, hostname, operating system, enrolled since, last-seen at collection
Artifact ................ exact artifact name as listed by `artifacts list`, source(s) used, artifact version
Parameters .............. every parameter and its value: paths, globs, time windows, limits
Query ................... the VQL, or for a hunt the hunt id and its expiry
Window (UTC) ............ collection/hunt start and completion, in UTC
Granted vs used ......... hosts in scope, hosts that answered, hosts that did not and why
Result files ............ archive path, size, SHA-256; per-client result file names
Transfer ................ how the archive left the host: server download, media, encrypted upload
Storage ................. where the sealed original lives and who can access it
Disruption .............. what ran on the host, with what privilege, and for how long
Exclusions .............. artefacts deliberately not collected, and the reason
Custody entries ......... date/time (UTC) — action — person
```

Reporting the result is [../methodology/04-reporting.md](../methodology/04-reporting.md), and the reach and limits of each artefact type are [../cheatsheets/evidence-validity.md](../cheatsheets/evidence-validity.md).

## 7. Choosing: triage, targeted artifact, image, or memory

| Question to answer | Reach for | Why |
| --- | --- | --- |
| Which hosts carry this persistence entry, registry value, or file? | Fleet hunt with one targeted artifact | Breadth and comparability: minutes per host, and the results table *is* the comparison |
| What does this one suspicious host actually have? | Single-client artifact collection | Speed, and it validates the artifact's scope before you widen it |
| What happened on this host, in full order, including deleted data? | Full disk image ([forensic-toolkit.md](forensic-toolkit.md)) | Completeness and defensibility: unallocated space, slack, deleted metadata, source hash |
| Which process made that connection, and what else was in memory? | Memory image, plus volatile state, captured first | Only RAM holds it, and powering off destroys it (order of volatility) |
| Which hosts hold a file matching this hash or pattern? | Targeted artifact (hash listing, YARA-style scan) across the fleet | A hash is cheap to query and directly comparable across hosts |
| A machine that cannot or must not enrol: third party, air-gapped, about to be rebuilt | Offline collector | No server connection, no persistent agent, archive stays with the owner |
| Has the host's own record been tampered with? | Full disk image, analysed offline | A compromised OS can lie to a live query; offline analysis does not depend on the host's cooperation |
| How big is this — which hosts are affected at all? | Hunt first, then image the subset | Bounds the worst-case cost: imaging time is spent only where triage says it matters |
| The volume is encrypted and the key may exist only in RAM | Memory capture before anything else | Remote triage sees only the decrypted view the running OS exposes; a power-off can cost the case |
| What do the collected artefacts mean? | Offline parsers on the copies ([windows-artifact-tools.md](windows-artifact-tools.md)) | Triage collects; parsing is a separate, repeatable step over the copies you keep |

The order is cheapest-answer-first, then escalate: **triage → targeted artifact → disk image → memory image** ranks cost, not quality. Escalate the moment the question changes from "which hosts" to "prove what happened here".

## 8. Limitations and failure diagnosis

| Failure mode | What is really happening | What to do |
| --- | --- | --- |
| The hunt returned nothing from a third of the estate | Those clients never checked in: powered off, off-network, agent not running, or never enrolled | Report it as *no data collected*, never as clean. Check last-seen times, and re-run once the hosts return |
| Two hosts returned "the same artifact" with different columns | Agent and artifact version drift: the artifact definition changed between releases | Record the client version and artifact version per host; do not compare columns across versions without reading each definition |
| Timestamps do not line up between hosts | Clock skew. Collection windows and file times come from *host* clocks, not from yours | Compare host time against a reference, record observed skew in the collection record, and treat near-simultaneous events with suspicion |
| One client's collection hangs or its archive looks truncated | The artifact's scope was too wide (a deep glob, a whole log directory, a large hive set) or a limit cut it short | Read the per-client status: partial is not complete. Narrow globs and windows, split into batches, re-collect rather than assume |
| The server filled its disk and collections began failing | Results accumulate in the datastore, and file-uploading artifacts are the expensive ones | Check free space before a broad hunt; archive and hash results out, then prune. Retention is a deliberate decision, never a surprise |
| The results are a summary, not an artefact | The artifact you ran returns parsed rows — a process listing, a parsed log line — instead of the underlying file | Acceptable for triage, useless as the exhibit. If you need the bytes, collect the file or image the disk, and record which kind of result you hold |
| The host is encrypted and the triage output is thin | Remote collection sees only the decrypted view the running OS exposes; a disk image of ciphertext alone is unreadable | Capture memory and keys while it runs, document the encryption state, and do not power it off to be tidy ([../methodology/01-acquisition.md](../methodology/01-acquisition.md)) |
| Workstations slowed down while the hunt ran | A heavy query ran on production endpoints, and the disruption is attributable to you | Scope by path and time window, set resource limits, test on one host, and schedule the fleet-wide run in an agreed change window |
| Legal or privacy asks why you copied two hundred people's documents | Nothing in the platform prevents collecting more than the investigation needs | Data minimisation is the examiner's job: collect the specific artefacts the question requires, from the hosts in the authorised scope, and record what you deliberately did **not** collect |

One habit prevents most of these: write the collection record *while* you collect, not after. Every entry above is something you can only fill in from memory once the hunt has expired and the server has been pruned.

## 9. Fitting it together

| The scale problem | The tool | What you keep |
| --- | --- | --- |
| One artefact from one host, right now | Single-client artifact collection | Result rows plus the artifact name, parameters, and UTC window |
| One artefact from every host | Hunt across the enrolled fleet | Per-client result archive, hunt id, expiry, and the list of hosts that never answered |
| A preset bundle from a host that must not enrol | Offline collector | The archive, hashed on the spot, plus the collector's parameters and the privilege it ran with |
| Everything from one host, including deleted data | Full disk image ([forensic-toolkit.md](forensic-toolkit.md)) | The image, its source hash, and the acquisition log |
| Volatile state on a running host | Memory image ([memory-analysis.md](memory-analysis.md)) | The memory image and its hash, captured before anything else |
| Meaning from what you collected | Offline parsers ([windows-artifact-tools.md](windows-artifact-tools.md)) | Parsed artefacts and timelines, kept beside the raw copies |
| The limits of what an artefact can prove | [../cheatsheets/evidence-validity.md](../cheatsheets/evidence-validity.md) | A conclusion whose stated limits match its evidence |
| The answer as a case artefact | [../methodology/04-reporting.md](../methodology/04-reporting.md) | A report in which every claim points at a hashed, stored collection |

The three-line version: **breadth first** (hunt the fleet for one specific artefact), **depth where it matters** (image or capture memory on the hosts the sweep identified), **prove it every time** (hash the archive, name the artifact and its parameters, record the UTC window, and state which hosts never answered).

## Common Mistakes & Tips

- **Starting at fleet scale.** Collect from one host first. A wrong parameter on one host costs a minute; the same parameter across a thousand hosts is an incident you caused and have to write up.
- **Hardcoding an artifact name.** A name from memory belongs to some other release. A wrong-but-real name returns plausible rows about the wrong question, and nothing in the output warns you. Copy the name from `artifacts list` on your own build.
- **Treating an empty result as a clean host.** Three different facts produce the same empty table: the host does not have it, the host never answered, and the artifact does not look at that. Say which one you mean.
- **Leaving out the collection window.** A collection without a UTC start and end is not reproducible. Host clock skew makes the gap worse, so record the window and the skew.
- **Calling a hunt finished when it launched.** Hunts expire. Laptops that were off during the window are not covered, and that gap belongs in the report.
- **Keeping only the GUI view.** The result archive is the evidence; the interface is a convenience. Download it, hash it, store it, then analyse the copy.
- **Collecting more than the case needs.** Across a fleet this is the mistake with legal consequences: it is your data-minimisation decision, not the platform's.
- **Enrolling an estate "just in case".** An enrolled client is a standing authorisation to collect from that host. Enrol what the authorised scope covers, and no more.
- **Asking a deletion question of a triage collection.** Deleted data, unallocated space, and slack are not in a triage collection at all. If the question is about what was removed, the answer is an image.
- **Rebuilding a host before hashing the archive.** After the wipe there is no second collection and no reference value. Hash at the moment of collection.
- **Letting the server fill up mid-case.** Results accumulate per client, and a full datastore fails collections in the middle of an investigation. Monitor, archive, hash, then prune.
- **Retyping parameters into the report.** Copy them from the hunt record. A parameter remembered approximately is a method section that cannot be repeated.

## Checklist / Self-Test

- [ ] I can explain in two sentences why full disk imaging does not scale to a fleet, and name three things a triage collection cannot contain.
- [ ] I can name the four architectural parts of Velociraptor and explain what an artifact *source* is.
- [ ] I generated a server configuration, started the server, and know where its datastore lives.
- [ ] I enrolled a client using the configuration my server generated, and I can state where the enrolment material came from.
- [ ] I ran `velociraptor --help` and `velociraptor artifacts --help` on my own build and recorded what that release accepts.
- [ ] I listed the artifact catalogue on my build and copied an artifact name out of it instead of typing one.
- [ ] I inspected an artifact's sources and parameters before running it, and I can say whether it returns rows or uploaded files.
- [ ] I collected one artifact from a single client before launching anything across a fleet.
- [ ] I ran a hunt with a deliberate client scope and expiry, and I can list the hosts that never answered.
- [ ] I built an offline collector and ran it on a host that is not enrolled to my server.
- [ ] I hashed a collection archive, stored the sealed original, and completed a collection record naming the client id, artifact, parameters, and UTC window.
- [ ] I can justify, for a given question, choosing triage over imaging — and one case where imaging is the only defensible answer.
- [ ] I hold written authorisation for every host I collected from, and I collected only what the question required.

> **Verification:** executed against **Velociraptor 0.77.2** on **2026-09-19** (Ubuntu 24.04 WSL):
> `velociraptor --help`, `artifacts collect --help` and `config --help` name
> the command groups and subcommands this file quotes (`artifacts`, `config generate`, `config
> repack`), and a bare local `artifacts list` (no `--config`, so only the artifacts compiled into
> the binary) ships `Windows.System.Pslist` — the artifact collected in section 3.4 — but **not**
> `Windows.KapeFiles.Targets`, which is exactly why section 4 says to copy every name out of your
> own catalogue on the build you are using. `Get-FileHash -Algorithm SHA256`
> was run separately in **PowerShell 7.6.6** and printed algorithm, hash and path for a file, as
> section 6 describes. **Not executed:** `config generate -i`, `gui`, `config repack` and any
> collection — no server, no enrolled client and no collector package exists here — so sections 3,
> 5 and 6 remain a plan, not a result.

## Further Resources

- Velociraptor documentation — https://docs.velociraptor.app/ (architecture, artifact reference, VQL reference, offline collector, notebooks).
- Velociraptor source and releases — https://github.com/Velocidex/velociraptor (release notes are how you track artifact and CLI changes between versions).
- The VQL and artifact references are reached from the documentation site above; the language is also summarised in [../../eCTHP/tools/hunting-platforms.md](../../eCTHP/tools/hunting-platforms.md).
- NIST SP 800-86, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final.
- RFC 3227, *Guidelines for Evidence Collection and Archiving* — https://www.rfc-editor.org/rfc/rfc3227 (the order of volatility).
- NIST SP 800-61, *Computer Security Incident Handling Guide* — https://csrc.nist.gov/pubs/sp/800/61/r2/final.
- SWGDE document library (Scientific Working Group on Digital Evidence) — https://www.swgde.org/ (best-practice documents on acquisition and evidence handling).
- SANS reading room — https://www.sans.org/reading-room/ (white papers on remote acquisition and evidence handling).
- Official eCDFP page for current, authoritative details about the certification — https://ine.com/security/certifications/ecdfp-certification.
