# Network and Log Forensics (eCDFP Methodology — Phase 06)

> Companion study guide for the eCDFP (Certified Digital Forensics Professional) Blue Team methodology track. Phase 02 and Phase 05 examine the machine you hold. This phase examines the records the *environment* kept about it: host and device logs, flow and packet data, and the identity systems in between — the evidence that survives when the disk does not.
>
> Where this phase sits: a companion to Phase 02 (analysis) and the main feeder for Phase 03 (timeline). Most real incidents are reconstructed from log and network evidence first and confirmed on disk second, because those sources cover machines you will never image.
>
> Every command in this file is a **syntax reference**. This repository ships no captured output: there is no log store, no packet capture and no SIEM on the machine that wrote it. Where a command would print a result, the text says what to look for. Confirm flags against the documentation for the version you have.

## Overview

Disk forensics answers questions about a host you can hold. Log and network forensics answer questions that no single host can:

| Question | Disk evidence alone | Log and network evidence |
| --- | --- | --- |
| Did the same activity happen on other machines? | Cannot answer | Central logs, flows, identity events |
| What did a device with no usable disk do? (router, firewall, appliance, container, SaaS) | Nothing to image | Its own logs are the only record |
| Where did a connection go? | Maybe (memory, caches) | Flow and proxy data |
| What was the sequence across hosts? | One host's clock only | Independent clocks, cross-checked |
| Who was behind an address? | No | DHCP, VPN, authentication, asset inventory |
| What left the network, and how much? | Rarely | Flow byte counts, proxy logs |

Three ideas govern the phase:

1. **Logs are testimony, not artefacts.** A log is a claim made by a system about itself. Its value depends on who could have written it, who could have altered it, and whether it was shipped somewhere the suspect could not reach.
2. **Time is the whole problem.** Correlating across sources with different clocks, formats and time zones is where cross-host analysis succeeds or quietly fails.
3. **Metadata is the evidence you will actually get.** Most traffic is encrypted. You will work with who, when, how much, to where, and with which certificate — not with content.

## 1. Where this evidence comes from, and who owns it

Collecting log evidence is as much an organisational task as a technical one: the source you need is often owned by another team, retained for a different reason, and deleted on a schedule nobody told you about.

| Source | What it records | What it cannot tell you | Who usually owns it |
| --- | --- | --- | --- |
| Windows event logs | Authentication, process creation (with auditing), services, tasks, PowerShell | Anything on a host where auditing was off | Endpoint / Windows team |
| Linux `journald` and `rsyslog` | Service events, kernel messages, authentication, custom application output | Events nobody logged | Linux / platform team |
| `auditd` on Linux | Syscalls, `execve` with arguments, file watches | Activity from before the rules were loaded | Linux / platform team |
| `wtmp` / `btmp` / `lastlog` | Login, logout, failed logins | Anything richer than session boundaries; and they are binary files that can be edited | Linux / platform team |
| Web server logs | Request line, status, user agent, client address, response size | Nothing about the user behind the address | Application / web team |
| Application logs | Business events, errors, job runs | Whatever the developers chose not to log | Application owner |
| Firewall / router logs | Permitted and denied flows, NAT translations | Content; and often only a sample of what passed | Network team |
| DNS resolver logs | Which client asked for which name, and the answer | Nothing if clients use their own encrypted resolver | Network team |
| Forward proxy logs | URL, method, authenticated user, bytes up and down, response code | Traffic that bypasses the proxy | Network / security team |
| VPN and 802.1X logs | Who connected, from where, when, and the address they were given | What they did afterwards | Network / identity team |
| Identity provider sign-in logs | Authentication result, source address, client application, conditional-access outcome | On-premises activity the provider does not see | Identity team |
| Cloud control-plane audit logs | API calls, caller identity, source address, parameters | Data-plane reads that are not audited | Cloud platform team |
| EDR telemetry | Process lineage, in-memory detections, response actions | Anything the agent's policy filtered out | Security operations |
| IDS/IPS alerts | Signature matches with packet context | Behaviour nobody wrote a signature for | Security operations |
| Mail gateway logs and headers | Sender, recipient, authentication results, relay chain | The body of a message you did not retain | Messaging team |

Practical consequence: **before you need them, know for each source what is collected, where it is stored, how long it is kept, and who can delete it.** Write it down once; it saves days later, and its absence is the reason investigations stall at "we would need to ask the network team, and their retention is two weeks".

## 2. Order of volatility for logs and network state

RFC 3227's sequence applies to this phase directly, and it is easy to get wrong because the evidence feels remote and therefore safe.

| Volatility | In this phase | Why it is urgent |
| --- | --- | --- |
| Kernel and process network state | ARP cache, routing table, active sockets, DNS cache | Gone at power-off; sometimes the only record of a connection |
| Temporary file systems and RAM | Logs held in memory before being flushed | `journald` and some agents buffer before writing |
| Local log files | Event logs, `syslog`, application logs | Roll over, and are trivially editable on a compromised host |
| Remote / centralised logs | SIEM, syslog server, cloud audit trail, proxy archive | Retained for a defined window, then gone; and they are the defensible copy |
| Flow archives | NetFlow/IPFIX collectors | Long retention but usually aggregated or sampled |
| Packet capture archives | pcap stores | Expensive, short retention, often disabled |
| Archival and physical media | Backups, offline log exports | Slow to obtain; decide early whether the case needs them |

The rule that falls out of this table: **acquire the local, volatile copy early and rely on the central copy for the record.** Local logs on a suspect host are the easiest thing in the environment to alter; the same events in a central store that the suspect had no access to are what you cite.

## 3. Log formats and the parsing problem

Logs arrive in a small number of shapes, and the differences between them are where analysis time disappears.

| Format | Where you meet it | Structure | The trap |
| --- | --- | --- | --- |
| Classic BSD syslog | Linux and network devices, `/var/log/syslog`-style | Priority, timestamp, host, tag, message | The timestamp usually has **no year and no time zone**; you must infer both from context |
| RFC 5424 syslog | Modern syslog, some appliances | Structured with a full timestamp including offset | Structured data fields are often empty even when the message contains them |
| Windows event XML / EVTX | Windows hosts | XML per event with a channel and event ID | Reading a channel without its audit policy leads to false negatives |
| JSON | Cloud audit logs, modern applications, EDR exports | Nested key/value with a native timestamp format | Field names differ per product; the same action has several names |
| TSV with a documented schema | Zeek and similar network sensors | One file per protocol, fixed fields | Field sets change between versions; a missing column shifts your parse |
| CEF / LEEF | Security appliances | Header plus extension key/value pairs | Escaping rules differ between implementations |
| Flow records | NetFlow/IPFIX exporters | Fixed record types plus templates | Templates must be known to decode; sampling may be invisible in the output |

Practical rules:

- **Parse into one normalised form before you analyse.** Mixed formats mean you write every query twice and get one of them wrong.
- **Convert timestamps to UTC at ingest and record the source offset.** Never analyse a cross-host question in local time.
- **Detect the classic-syslog year problem explicitly.** An entry with no year is ambiguous across a year boundary; if the incident window spans 31 December, this will bite.
- **Verify the parse before you trust a null result.** A pattern that does not match produces zero rows, not an error.

## 4. Clocks, time zones and daylight saving

Cross-source correlation fails more often on time than on missing data. Walk these in order for every source in the case:

1. **What time zone does the source record in?** Some devices emit UTC, some local time with an offset, some local time with nothing. Determine it from the device configuration, not from the log's appearance.
2. **Was the clock correct?** Compare against an independent source with its own reliable time — a domain controller, a firewall with an external time source, a cloud service's own timestamps. A host whose clock drifted by eight minutes will place an event in the wrong phase of an attack.
3. **Did a daylight-saving transition fall inside the window?** A device emitting local time with no offset produces an hour that occurs twice or not at all. Where that overlaps your incident, say so explicitly rather than silently picking a mapping.
4. **What is the timestamp's precision and resolution?** Milliseconds versus whole seconds, and whether the value is the event time or the time it was written. Two events that "happened at the same second" may be an artefact of coarse logging.
5. **Does the source use a monotonic or a wall clock?** Some appliances log uptime-derived times that must be converted against a boot event.

> Record the outcome — per source: format, time zone, offset from real time, and the anchor you used to establish it. Put it in the report's methodology section. It is the single most useful paragraph in a cross-host investigation, and almost nobody writes it.

## 5. Log integrity — how much weight does this record carry?

Before a log becomes a finding, ask who could have written it and who could have changed it.

**Strengths:**

- **Centralised or shipped logs.** If the host forwards its events to a collector it cannot reach or modify, the central copy is materially stronger than the local one.
- **Independent clocks and sequence numbers.** Systems that number their records (Windows event record IDs, syslog sequence numbers, journal cursors) make gaps and deletions detectable.
- **Write-once storage.** WORM media, immutable cloud buckets, and append-only log services remove the tampering question almost entirely.

**Weaknesses and their signatures:**

| Tampering or fault | What you see | How to confirm |
| --- | --- | --- |
| A log was cleared deliberately | A clearing event in the channel itself, and a channel whose oldest retained record is far younger than its neighbours | Compare the oldest retained record per channel, and the file's timestamps |
| A log file was edited | Non-monotonic timestamps; a mangled line structure; a file whose size and record count disagree | Compare against the shipped copy, if one exists |
| A channel was disabled or its retention reduced | An audit-policy change event; a size setting inconsistent with the host's role | Check policy-change events and the channel configuration |
| Records were lost in transit | A gap in sequence numbers or event record IDs, with a collector-side ingest gap | Compare the host's count with the collector's count for the same window |
| A log rotated faster than expected | The window you need simply is not there | Establish the rotation policy from the configuration, not from the log |
| A device's clock was changed | A discontinuity, or timestamps that move backwards | Look for a time-change event, and for entries that break monotonicity |

The professional stance is straightforward: **never treat a log as trustworthy merely because it is a log.** State where the copy came from, how it was shipped, and what could have altered it. That sentence is what makes the finding defensible.

## 6. Network evidence: the three levels and their trade-off

Network evidence is always a choice between payload, volume and retention. You rarely get all three.

| Level | What you get | Typical retention | Answers | Cost |
| --- | --- | --- | --- | --- |
| Full packet capture | Everything on the wire, including protocol content where unencrypted | Hours to days | What was said, byte for byte; protocol anomalies; file extraction | Very high storage and processing |
| Protocol metadata (sensor logs such as Zeek) | Per-connection and per-protocol summaries: addresses, ports, durations, byte counts, names, certificates, file hashes | Weeks to months | Who talked to whom, how much, to which names, with which certificates | Moderate |
| Flow records (NetFlow / IPFIX) | Header-only summaries, often aggregated and sometimes sampled | Months | Reachability, volume, top talkers, scope across a whole estate | Low |

Rules that follow from the table:

- **Retention decides what you can ask.** A question about an event nine weeks ago cannot be answered from a seven-day packet archive, whatever the packet archive could theoretically prove.
- **Sampling decides what you can detect.** Flow sampled at a high ratio will not show a low-volume periodic beacon. Before concluding "no C2 traffic", establish the sampling rate, and say what it means for your sensitivity.
- **Aggregation hides shape.** A flow record that merges a session's packets cannot show inter-arrival timing. Timing is often the only signature a beacon has.
- **Truncated captures hide content.** A capture with a short snapshot length keeps headers and loses payload; that is a deliberate design choice with forensic consequences you should record.

### 6.1 Packet capture in practice

```bash
# Offline analysis of a capture file (the normal forensic mode, not live sniffing)
tshark -r case.pcap -Y 'dns' -T fields -e frame.time_epoch -e ip.src -e dns.qry.name
# What to look for: query names and the clients that asked, one line per query.
# Confirm field names for your tshark version with: tshark -G fields | grep dns

# Conversation summary: who talked to whom, how much, for how long
tshark -r case.pcap -q -z conv,tcp
# What to look for: conversations that are small, regular and unexplained —
# volume and duration are frequently more informative than content.

# The 60-second traffic shape of one host
tshark -r case.pcap -Y 'ip.addr==10.0.4.17' -T fields -e frame.time_epoch | \
  awk '{print int($1/60)}' | sort | uniq -c
# What to look for: an even bucket count with a steady rate suggests automation.
```

Two constraints to state in every report that uses capture: **where** it was captured (a span port sees only what crosses it, and a host-based capture misses everything that host did not send or receive), and **what was lost** to truncation or to a lossy capture buffer. An application that drops packets under load produces a capture with holes in exactly the busiest moments.

Also: capturing payload on a network you do not own raises legal and privacy questions that predate your technical work. If the case needs content, get the authorisation for content explicitly.

### 6.2 Protocol families and what each answers

| Protocol | Artefact | What it answers | The catch |
| --- | --- | --- | --- |
| DNS | Query name, type, client, response, response code | Which name a host resolved, and whether it resolved | Encrypted DNS and hardcoded resolvers create blind spots; establish how much of the estate bypasses your resolver |
| TLS | Server name indication, certificate subject and issuer, version, cipher, fingerprint sets | Where encrypted traffic was going, and which server was really answering | Fingerprint fields vary by sensor version; confirm which your build emits |
| HTTP | Method, host, URI, user agent, status, bytes | What was requested, downloaded, or posted where | Only unencrypted or intercepted traffic; progressively rare |
| SMB / RPC | Shares, filenames, usernames, hostnames | Lateral movement and file access across hosts | Needs a capture point that sees internal traffic |
| Kerberos / NTLM | Authentication attempts, service names, success and failure | How identity was used across the domain | Domain-controller logs are often the better source |
| DHCP | Lease grant and renewal with MAC and assigned address | Which device held which address at a given time | Short log retention on some servers; leases maybe not logged at all |
| VPN / 802.1X | Connection, identity, assigned address, duration | Who joined the network from where | Assigned addresses may be reused across sessions |
| Email | Relay chain in `Received` headers, authentication results | Where a message really came from and whether it authenticated | Headers are forgeable except for the parts added by trusted relays — read the chain bottom-up |

### 6.3 Identity resolution — the central task

Most cross-host network analysis reduces to one problem: **turning an address into an accountable entity.**

```text
address  ──DHCP lease / VPN assignment / NAT translation──►  device
device   ──MAC, hostname, asset inventory, 802.1X──────────►  asset
asset    ──logon events, identity provider logs────────────►  account
account  ──HR or directory data (documented, authorised)───►  person
```

Every arrow can break, and each break is a limitation you must state:

- **NAT** destroys the one-to-one mapping between an internal address and an external one. A public address in a log identifies a gateway, not a person.
- **Address reuse** means the same internal address can belong to several devices across a day. Without lease times, an internal address is not an identity either.
- **Shared accounts and service accounts** mean the account is not the person. Say "the account was used", not "the person did it".
- **The final arrow is not yours to make alone.** Turning an account into a person is an HR and legal step, with authorization and data-minimization constraints, and it belongs in the report as a documented, authorised inference.

## 7. The log and network analysis workflow

A repeatable procedure that keeps the work defensible:

1. **Define the window and the question.** From an alert time, a discovered artefact, or a reported incident — with a deliberate margin around it, because the first event you find is rarely the first event that happened.
2. **List the sources that could answer it**, and for each one record the owner, the retention, and the format.
3. **Prove each source was healthy for that window** before interpreting it. A source with no data is not a source with no events. This single habit prevents the most expensive class of error in the whole phase.
4. **Acquire and preserve.** Export the query results and the raw records you relied on; hash the exports. A screenshot of a console is not evidence.
5. **Normalise to UTC** and note each source's clock story.
6. **Anchor on a known event.** Pick the one timestamp you trust — the alert, the artefact you dated on disk, a firewall log entry — and work outward.
7. **Filter, then pivot on entities** (address, account, hostname, certificate, user agent, name), not only on time.
8. **Record every query verbatim**, with the tool, version, source, and window. A query you cannot re-run is an anecdote.
9. **Separate what the source proves from what you infer.** A denied firewall entry proves an attempt, not an intrusion. A DNS query proves a name was asked for, not that anything was downloaded.
10. **Write down the gaps** — sources that did not exist, windows that had rotated out, traffic that bypassed collection — and what each gap means for the confidence of the conclusion.

## 8. What this evidence cannot do

- **It cannot see inside encryption.** Certificate names, destinations, volumes and timings are what you get. Treat any statement about content as out of scope unless you have decrypted traffic or endpoint records.
- **It cannot identify a person.** Addresses, accounts and devices are not people; the last step requires authorised HR or directory data and must be documented as such.
- **It cannot prove a host was compromised.** A firewall log shows an attempt; a DNS log shows a lookup; a proxy log shows a request. Compromise is a conclusion built from several of these plus endpoint evidence.
- **It cannot reconstruct what nobody logged.** Retrofitting logging after an incident is a change to the environment, not a source of evidence about the past.
- **It cannot fix bad time.** Correlating against a skewed clock without correcting for it produces confident, wrong sequences.

## Common Mistakes & Tips

- **Treating "no results" as "no activity".** Prove the source was collecting for the window first — an ingest gap and a quiet network look identical in a query.
- **Ignoring the classic-syslog year and time zone.** An entry without a year or an offset is ambiguous; resolve it from device configuration and say how.
- **Correlating sources without checking clocks.** Compare each source against an independent clock before you build a sequence.
- **Forgetting daylight saving.** A window spanning a transition can contain an hour that occurred twice. State the mapping you used.
- **Citing a local log on a compromised host as if it were pristine.** Prefer the central copy; where none exists, say the local copy is editable and explain what corroborates it.
- **Reading a NAT address as a person.** An external address identifies a gateway. So does a shared internal address without lease data.
- **Concluding "no C2" from sampled flow.** Establish the sampling rate and the minimum volume you could possibly have seen.
- **Using a capture without stating its point and losses.** A span port, a host capture and a truncated capture each answer a different question.
- **Fingerprinting TLS fields your sensor does not emit.** Confirm which fields your version produces before writing a query around them.
- **Reading forged email headers as fact.** Only the parts added by relays you trust are reliable; read the `Received` chain from the bottom up.
- **Reviewing a console instead of exporting evidence.** Export the records, hash them, and keep them; a screenshot is a summary, not an exhibit.
- **Tip:** keep a one-page source inventory with owner, format, retention and time zone. Update it when you learn something new, and it will outlive the case.
- **Tip:** when a finding depends on a single log source, write the sentence that says so. A reviewer will find it otherwise, and they will not be as kind about it.

## Checklist / Self-Test

- [ ] Can I name three questions that log and network evidence answer and disk evidence cannot?
- [ ] Can I list the log sources in my own environment with their owner, retention and format?
- [ ] Can I place log and network evidence correctly in the RFC 3227 order of volatility, and explain why the central copy matters more than the local one?
- [ ] Can I explain the classic-syslog year-and-time-zone problem and how I would resolve it?
- [ ] Do I record, per source, its time zone, its offset from real time, and the anchor I used to establish both?
- [ ] Can I name two signatures of deliberate log tampering and two signatures of accidental log loss?
- [ ] Can I compare full packet capture, protocol metadata and flow records on payload, retention and cost, and pick the right one for a given question?
- [ ] Can I explain what flow sampling and capture truncation each prevent me from concluding?
- [ ] Can I name the artefact that links an IP address to a device, and the artefact that links a device to an account?
- [ ] Can I explain why a NAT address is not a person and a shared account is not an individual?
- [ ] Have I ever verified that a log source was actually collecting before treating an empty result as an answer?
- [ ] Can I state, for my most recent finding, exactly which source proves it and which part is inference?

## Further Resources

- **RFC 3227**, *Guidelines for Evidence Collection and Archiving* (order of volatility) — https://www.rfc-editor.org/rfc/rfc3227
- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* (log and network evidence) — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **RFC 5424**, *The Syslog Protocol* (and RFC 3164 for the classic format) — https://www.rfc-editor.org/rfc/rfc5424
- **Zeek documentation** (protocol logs, field reference, and what each log can answer) — https://docs.zeek.org/
- **Wireshark / tshark documentation** (capture analysis and display-filter reference) — https://www.wireshark.org/docs/
- **Linux Audit documentation** (`auditd`, `ausearch`, `aureport`) — https://github.com/linux-audit/audit-documentation/wiki
- **Microsoft — Windows security auditing and event reference** — https://learn.microsoft.com/windows/security/threat-protection/auditing/
- **DFRWS challenge archives** (authorized practice datasets, including network captures) — https://dfrws.org/
