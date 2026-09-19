# Evidence Validity — What Each Source Can and Cannot Prove

> eCDFP · Cheatsheet — INE Cybersecurity Certifications Study Guide
>
> A desk reference for the question that decides cases: *this artefact exists — so what does it actually prove?* Each evidence type below is listed with its ceiling (what it can establish), its floor (what it cannot), its clock behaviour, and what destroys it. Use it before you write a conclusion, and again before you sign one.
>
> Analysis runs against copies of media you own or are authorized to examine. No command output appears in this file: it is a reasoning reference, not a transcript.

**Conventions used below**

- **A lead is not a finding.** One artefact is a lead; two independent artefacts that would each have to be wrong in the same direction are a finding.
- **Integrity ≠ authenticity.** A hash proves the evidence has not changed since you hashed it. It says nothing about whether the evidence is what it claims to be — that is provenance, established by your acquisition record and chain of custody.
- **Identification ≠ attribution.** Identifying that an account, address or device was involved is not the same as identifying a person. The last step needs authorised HR or directory data and belongs to a process with legal authority.
- **Preservation ≠ admissibility.** Good handling makes evidence admissible; it does not make it conclusive. Admissibility rules also vary by jurisdiction and forum — ask counsel which applies.
- **Absence is a conclusion you must earn.** Before writing "no evidence of X", show that the artefact was capable of recording X and that its lifecycle does not explain the gap. `../methodology/08-anti-forensics-and-evidence-integrity.md` §4 is the four-way test.

---

## 1. The three questions that decide whether evidence is usable

Ask these in order. Evidence fails at the first one far more often than examiners expect.

| Question | If the answer is no |
| --- | --- |
| **Could this source have recorded the thing I am asking about?** | You have an absence, not a negative. Find a source that could, or state the gap |
| **Is the record intact and trustworthy?** | You have a compromised artefact. Find an independent copy, or qualify the finding heavily |
| **Can I attribute it to an account, device or session?** | You have an event without an actor. Attribute through a second artefact, or say you cannot |

## 2. Evidence classes and their ceilings

| Evidence | It can prove | It cannot prove | Clock behaviour | What destroys it |
| --- | --- | --- | --- | --- |
| **File content** | That content with these bytes existed at this path in this image | How it got there; who put it there; that the same content existed before you imaged | File-system timestamps only | Overwrite; encryption; secure deletion |
| **`$MFT` / directory entry** | That a file existed, its attributes, and both timestamp sets; unallocated records show past existence | Execution; who accessed it | Two sets, updated by different events — disagreement is itself evidence | Record reuse; severe corruption |
| **`$UsnJrnl` (change journal)** | That a specific file operation (create, write, rename, delete) occurred, with a time | The actor; the content | Journal's own timestamps, high resolution | Journal deletion, rollover, or a reset |
| **`$LogFile`** | Metadata changes in a narrow, recent window, in detail | Anything older than its window | Transaction times | Rollover |
| **Slack and unallocated space** | That bytes resembling X existed in that region of the volume | A filename, an owner, or a date for those bytes | None of its own | Reuse; wiping; TRIM on flash |
| **Volume shadow copy / snapshot** | The state of files at a point in time — often the only route to a previous version | That the snapshot is complete, or that it covers the moment you need | Snapshot creation time only | Deletion of the snapshot set; space pressure |
| **Registry key** | That a key exists and when the key was last written | Which value was written, or when a specific value content appeared | Key-level last-write time only | Deletion (though slack often survives) |
| **Registry value** | Configuration content, and often an embedded date inside the data | Its own write time | None of its own — infer from the key | Deletion; overwrite |
| **Windows event log record** | That the event was written, with its fields, at that time | That nothing else happened; that the event reflects reality rather than the writer's view | Host clock; sequence/record IDs make gaps detectable | Channel wrapping, clearing, policy change |
| **Sysmon event** | Rich behaviour: process creation with command lines, network, registry, image loads | Anything outside its configuration; anything before it was installed | Host clock | Config change, service stop, channel clearing, retention |
| **PowerShell script block log** | The script code that executed, including decoded and in-memory content | Interactive keystrokes; other scripting hosts (`mshta`, `wscript`, `rundll32`) | Host clock | Not enabled; log wrapping; policy change |
| **Prefetch** | That a program executed, with a run count and last-run times, on a client edition with prefetch enabled | Where it ran from (needs the referenced-paths list); execution if the entry was deleted; anything on a server with prefetch off | Host clock, at run time | Cache rollover, cleanup tools, deliberate deletion, feature updates |
| **Amcache** | That a binary was inventoried, with a path and often a hash | That it executed | Host clock | Hive deletion; OS reinstall |
| **ShimCache / AppCompatCache** | That a binary was known to the compatibility infrastructure | Execution, on any version — treat the execution flag as a hint to corroborate | Last-modified time of the file, not the observation | Cache clearing; hive replacement |
| **UserAssist** | That a user profile launched a GUI program through the shell, with counts and times | Console tools, services, tasks, scripts started from a prompt | Host clock; user-writable | Profile deletion; deliberate editing |
| **SRUM** | Per-application resource use (including network bytes) and the owning user SID | Who was at the keyboard; that a byte count means exfiltration | Host clock, hourly granularity | Rollover (roughly a month by default) |
| **LNK file** | That a file was opened through the shell, with a path and the target's timestamps | Execution of a program; the time of the *user's* action unless you read the LNK's own file timestamps | The LNK file's own timestamps are the access evidence; embedded ones describe the target | Deletion; recent-items cleanup |
| **Jump list** | Recently opened items per application, with access times and counts | That the file still exists or that a program ran | Host clock | Deletion; automatic pruning |
| **Shellbag** | That a user browsed a folder — including paths and volumes that no longer exist | Execution of anything in that folder | First-interaction timestamps on BagMRU nodes | Profile deletion; hive cleanup |
| **Browser database** | Visits, downloads, searches, cookies — with times and URLs | That the user was the person at the keyboard; anything in private-browsing modes; deleted rows (unless recovered from free pages) | Browser-specific epochs — convert carefully | History clearing; profile deletion; database vacuum |
| **Recycle Bin `$I` file** | That a file was deleted through the shell, with its original path and deletion time | Deletion by other means (`Shift`+`Delete`, applications, network shares) | Host clock, at deletion | Emptying the bin; overwrite |
| **Memory: presence of a process/region/connection** | That it existed at the moment of capture, with its attributes | What happened before or after capture; that a region is malicious | Host clock at capture | Power-off; process exit before capture; paging |
| **Memory: absence of anything** | Very little | Anything at all, on its own | — | Same as above; a snapshot is biased toward what was resident |
| **Flow records (NetFlow/IPFIX)** | Who talked to whom, how much, for how long | Content; low-volume activity if sampling is coarse | Exporter clock | Aggregation, sampling, retention |
| **Full packet capture** | Byte-level content and timing where not encrypted | Content inside TLS; traffic that did not cross the capture point | Capture host clock, high resolution | Retention cost; truncation; packet loss under load |
| **Proxy log** | URL, method, authenticated user, bytes up/down, response code for proxied traffic | Traffic that bypasses the proxy; payload content | Proxy clock (usually well sourced) | Retention; log rotation |
| **DNS log** | Which client asked for which name, and the answer | What happened next; queries sent to an encrypted resolver you do not operate | Resolver clock | Retention; encrypted DNS and hardcoded resolvers |
| **Identity provider / sign-in log** | Authentication result, source address, client app, policy outcome | What the session did afterwards; who held the credentials | Provider clock (independent, high trust) | Provider retention; account-level changes |
| **Cloud control-plane audit log** | Which identity called which API, from where, with what result | Data-plane reads that are not audited; content | Provider clock (independent, high trust) | Lifecycle rules; an administrator with rights to alter logging |
| **Mobile logical extraction** | Contacts, messages, call logs, media, and app data reachable through supported interfaces | Deleted records, app-private data, unallocated space | Device clock; time zone must be recorded | Device lock state, re-locking, remote wipe |
| **Mobile cloud/account data** | Synced messages, photos, location history, provider-held backups | Local-only data; anything not synchronised | Provider clock (independent) | Retention; account deletion |
| **Container writable layer** | Files created or modified inside the container | Anything baked into the image; anything written to a volume mounted elsewhere | Host clock | Container recreation — the layer is destroyed |
| **Container/orchestrator logs** | Process output, lifecycle events, API calls that created workloads | Behaviour nothing logged | Host or provider clock | Log driver rotation; short retention |
| **Third-party/legal records** (carrier, ISP, provider responses) | Independently sourced facts about accounts, addresses and sessions | Anything the provider does not retain; anything outside the legal request's scope | Provider clock, usually well sourced | Time: retention closes, and requests take time |

---

## 3. Clock and timestamp reliability by source

Correlation across sources fails on time more often than on missing data. Use this to decide which timestamp anchors a sequence.

| Source | Timestamp origin | Precision | Reliability | Characteristic pitfall |
| --- | --- | --- | --- | --- |
| File system metadata | The host's clock at the operation | Varies: seconds to 100 ns depending on file system | Moderate | Access times may not update at all; creation times are settable |
| NTFS `$STANDARD_INFORMATION` vs `$FILE_NAME` | Host clock, different update triggers | High | Moderate, and informative | Disagreement indicates manipulation *or* a legitimate move/restore |
| Change journal / transaction log | Host clock at change | High | Moderate to high | Depends on the host clock being sane |
| Event logs | Host clock at write | Usually seconds | Moderate | Skew, wrapping, and clearing |
| Provider audit logs | Provider infrastructure clock | Usually seconds, UTC | High | Time zone conventions vary by field |
| Network flow / packet capture | Exporter or capture host clock | High | High if NTP-synced | Capture host may itself be skewed |
| Mobile device | Device clock, often network-synced | Seconds | Moderate | Time zone and DST handling; device in a Faraday bag stops syncing |
| Memory artefacts | Host clock at capture | Seconds | Moderate | A dump gives you one moment, not a history |

Practical rules: convert to UTC at ingest; record the source's offset from real time and how you measured it; state the mapping you used where a daylight-saving transition falls inside the window; and never build a cross-host sequence on a single unvalidated clock.

---

## 4. The identity ladder, and where it breaks

```text
address  ──►  device  ──►  account  ──►  person
```

| Step | Evidence that supports it | Where it breaks |
| --- | --- | --- |
| Address → device | DHCP leases, VPN assignment logs, NAT translations, 802.1X | NAT hides many devices behind one address; addresses are reused within a day; leases may not be logged |
| Device → account | Logon events, session records, agent enrolment records | Shared devices; service accounts; credential theft (the account is used but the device owner is not the actor) |
| Account → person | Directory or HR records, under authorisation | Shared and generic accounts; delegation; the final step is a legal/organisational conclusion, not a forensic one |

Write the claim at the level you can support: "the account was used from this address during this session" is defensible; "this person did it" is a different assertion with a different burden of proof.

---

## 5. What a hash proves — and what people wrongly think it proves

| Claim | Established? |
| --- | --- |
| The image has not changed since the hash was taken | **Yes** |
| The image is a faithful copy of the source at acquisition time | **Yes**, if the source hash was taken correctly and matches |
| The source was unaltered before you hashed it | No — a hash records state, not history |
| The image came from the device you believe it did | No — that is provenance and chain of custody |
| The evidence is authentic in a legal sense | No — authenticity is a conclusion built on provenance, custody and method |
| The evidence is complete | No — a flawless image of a partly-imaged failing disk is still incomplete |

---

## 6. Anti-forensic ceilings: what tampering changes, and what it cannot

| Technique | What it achieves | What it cannot reach |
| --- | --- | --- |
| Deleting files | Removes references and directory entries | Metadata about the deletion; duplicates elsewhere; backups and cloud copies |
| Deleting caches (Prefetch, ShimCache) | Removes one execution or presence artefact | Other artefacts recording the same execution; the deletion's own file-system record |
| Clearing event logs | Removes the channel's history | The clearing record; the log on a collector; the sequence gaps |
| Disabling auditing or an agent | Removes *future* records | Configuration-change records; the collector's ingest history; anything recorded before |
| Modifying timestamps | Falsifies one or both file timestamp sets | Journals, caches, logs, archives, directory context, the volume's own history |
| Wiping free space | Destroys unallocated content | Pagefile, hibernation file, slack, backups, cloud copies, the second machine |
| Encrypting data | Makes content unreadable without keys | Volume metadata; keys in memory or escrow; the tooling used to encrypt |
| Using legitimate tools | Makes behaviour look ordinary | Process ancestry and command-line arguments |

---

## 7. Common Mistakes & Tips

- **Reading an absence as a negative.** Check coverage and lifecycle first; an artefact that could not have recorded the event proves nothing by being empty.
- **Treating a hash as proof of authenticity.** It proves integrity. Provenance is a separate argument.
- **Sliding from artefact to actor.** An unallocated string, a Run key or a network connection names no person. Attribute through a second artefact or say you cannot.
- **Calling an address a person.** NAT and address reuse break the first rung of the identity ladder.
- **Treating ShimCache as an execution log** or an Amcache entry as proof a program ran. Use them for paths and hashes; find execution elsewhere.
- **Citing a LNK file's embedded timestamps as the access time.** They describe the target, not the shortcut's creation.
- **Reading a registry value's date from the key's last-write time.** Values carry no timestamp of their own.
- **Assuming event logs are trustworthy because they are logs.** Establish where the copy came from and who could have altered it.
- **Treating memory's empty results as meaningful.** A dump is a snapshot with a bias; presence is strong, absence is weak.
- **Forgetting that sampling and truncation set your ceiling.** Establish the flow sampling rate and capture snapshot length before concluding "no such traffic".
- **Quoting a mobile logical extraction as if it were a full image.** State the extraction level and what it could not reach.
- **Ignoring retention.** Every source above expires on somebody else's schedule. Ask for the window you need on day one.
- **Tip:** for each finding, write four fields — artefact, what it proves, what corroborates it, and what would falsify it. If you cannot fill the last field, you have an assertion, not a finding.
- **Tip:** when a conclusion rests on one source, write that sentence. Reviewers find single-source claims anyway; finding them yourself is cheaper.

---

## Checklist / Self-Test

- [ ] For my current case, can I name the evidence class behind every finding I intend to report?
- [ ] For each of those, can I state its ceiling — what it proves — and its floor — what it does not?
- [ ] Can I explain the difference between integrity and authenticity, and say which one my hash values establish?
- [ ] Can I explain the difference between identification and attribution, and where the second becomes a legal question?
- [ ] Have I verified, for each source I relied on, that it was capable of recording the events I asked about, in the window I asked about?
- [ ] Have I recorded the clock offset and time zone for every source that contributed a timestamp?
- [ ] Can I trace an address to a device to an account, and say which rungs of that ladder my evidence supports?
- [ ] Have I named the artefact that corroborates each single-source finding, or labelled it as single-source?
- [ ] Can I state, for each artefact I rely on, what would destroy it — and whether that has happened here?
- [ ] Have I written down which sources expired, were never enabled, or were outside my reach?
- [ ] Does every conclusion state the level of claim it is making (fact, inference, opinion) and its confidence?

## Further Resources

- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **ISO/IEC 27037**, *Guidelines for identification, collection, acquisition and preservation of digital evidence* — https://www.iso.org/standard/44381.html
- **RFC 3227**, *Guidelines for Evidence Collection and Archiving* (order of volatility, and why acquisition order constrains what you can later claim) — https://www.rfc-editor.org/rfc/rfc3227
- **NIST SP 800-101 Rev. 1**, *Guidelines on Mobile Device Forensics* (acquisition levels and what each yields) — https://csrc.nist.gov/publications/detail/sp/800-101/rev-1/final
- **The Sleuth Kit / Autopsy documentation** (what each file-system structure records) — https://www.sleuthkit.org/
- **Forensics Wiki** (per-artefact references and known limitations) — https://forensics.wiki/

> **Verification:** checked against source, not executed — **no command in this sheet was run**. The
> publication title was corrected on **2026-09-19** against the NIST CSRC record, which names
> SP 800-101 Rev. 1 *Guidelines on Mobile Device Forensics*, not "Mobile Phone Forensics":
> https://csrc.nist.gov/pubs/sp/800/101/r1/final.
