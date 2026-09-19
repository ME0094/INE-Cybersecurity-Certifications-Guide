# Hunting Platforms — SIEM, EDR, Fleet DFIR & Notebooks

> eCTHP · Tools — INE Cybersecurity Certifications Study Guide
>
> Where a hunt actually runs: SIEM platforms, EDR consoles, fleet-scale DFIR query engines, and analysis notebooks. What question each family answers, how to choose between them, where each one will lie to you, and the query languages (KQL, SPL, EQL, VQL) you type in all of them. Every example targets telemetry from systems you own or are authorized to monitor.

## 1. Why the platform matters as much as the hypothesis

A hunt is a loop: **hypothesis → data → query → triage → pivot → finding or negative result** (see `../methodology/02-hypothesis-generation.md`). The platform is the middle of that loop — it decides what data you can reach, how fast you can iterate, and whether a negative result is trustworthy or just an artifact of missing telemetry.

Two consequences follow, and they cause most failed hunts:

1. **The platform defines the ceiling of your hunt.** If telemetry never left the endpoint, no SIEM query will find it. Choosing where to hunt *is* choosing what you can find.
2. **Different questions need different families.** "Is any host beaconing to this domain?" is a network-and-scale question. "What did that process do in the 90 seconds after it started?" is an endpoint question. "What does the whole fleet look like right now, on every host simultaneously?" is a fleet-query question. No single platform answers all three well.

> A hunt platform is not a detection product. Detections are pre-written questions the platform asks for you; hunting is *you* asking a question nobody wrote down yet. The same console usually does both, which is exactly why analysts confuse them (see `../methodology/05-detection-engineering.md` for closing that gap).

## 2. The four families

| Family | Representative platforms | What it fundamentally is | Primary hunting question |
| --- | --- | --- | --- |
| **SIEM** | Elastic Stack (Elasticsearch + Kibana), Splunk, Microsoft Sentinel | Centralized log store with a search/aggregation language on top | *What pattern exists across many sources over time?* |
| **EDR** | Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Elastic Defend | Agent on the endpoint recording process-level telemetry, with response actions | *What did this process, on this host, actually do — and what spawned it?* |
| **Fleet DFIR / scale query** | Velociraptor, osquery (fleet mode) | Live query engine that asks the same question of thousands of endpoints and returns structured answers | *What is true on every host right now?* |
| **Analysis notebook** | Jupyter (Python + pandas), Zeek + notebook workflows | Local compute where you join, reshape, and visualize exported data | *What does the shape of this data tell me that a single query cannot?* |

### What each family is good at, and what it costs you

- **SIEM** — best at correlation across sources and at long retention. Its weakness is *fidelity*: logs are normalized, sampled, or filtered at ingest, so a process command line may be truncated and a network connection may have no owning process.
- **EDR** — best at endpoint causality: parent/child process trees, loaded modules, injected memory, the exact command line. Its weakness is *scope and retention*: it usually sees endpoints only, commands vary by vendor, and long-horizon history is often the first thing trimmed.
- **Fleet DFIR** — best at breadth and at answers you can trust because you collected the raw artifact yourself. Its weakness is *cost and safety*: a badly written query with a wide glob will hammer thousands of production endpoints at once.
- **Notebooks** — best at the "what shape is this?" step: baselining, periodicity analysis, joining two exports, plotting. Its weakness is that nothing is live: you hunt the data you already exported, and the export takes as long as it takes.

> Practical rule for a new hunt: **start where the data is cheapest to get and the question is sharpest.** For a process-behaviour hypothesis, the EDR console usually beats the SIEM (better fidelity, faster iteration). For a fleet-wide "does anyone else look like this?" question, the fleet query engine beats everything.

## 3. SIEM platforms

### Elastic Stack (Elasticsearch + Kibana)

- **What it is**: Elasticsearch stores and indexes normalized documents; Kibana is the search, visualization, and case UI; Elastic Agent / Winlogbeat / Filebeat ship the events in.
- **Hunting question it answers**: cross-source correlation over retained history — "the same account that failed 200 logons on Monday also created a scheduled task on Tuesday."
- **What to hunt with**: Discover for ad-hoc KQL, the Security app for EQL and timeline investigation, Dev Tools for Query DSL when a KQL filter cannot express the aggregation you need.
- **Limits**: field names depend on the integration that ingested the event (`process.command_line` from one integration is not `winlog.event_data.CommandLine` from another) — check a sample document before writing a query. Ingest pipelines can drop fields. Retention is tier-based and the cheapest tier is slow.

```text
# Kibana Discover (KQL)
# Hunt: a service binary that does not live under System32
event.category : "process" and process.name : "svchost.exe" and not process.executable : "C:\\Windows\\System32\\*"
```

```json
// Dev Tools: the same hypothesis with an aggregation KQL cannot express
GET /logs-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term": { "event.category": "process" } },
        { "term": { "process.name": "svchost.exe" } }
      ],
      "must_not": [
        { "wildcard": { "process.executable": "C:\\Windows\\System32\\*" } }
      ]
    }
  },
  "aggs": {
    "by_host": { "terms": { "field": "host.name" } }
  }
}
```

### Splunk

- **What it is**: proprietary index-and-search platform; SPL is its pipe-based search language. A free license caps daily ingest but exposes the search language, which is all you need to learn it.
- **Hunting question it answers**: fast pattern counts and statistics over long retained windows, with strong `stats`/`streamstats`/`transaction` primitives for sequence and periodicity work.
- **Limits**: field extraction is search-time and depends on the add-on/TA you installed — an unextracted field simply does not exist in your query. Wildcard-leading searches are expensive. `transaction` on large windows is a known performance trap.

```spl
index=sysmon EventCode=1
| stats count by Computer, User, ParentImage, Image
| sort - count
```

### Microsoft Sentinel

- **What it is**: cloud SIEM built on Azure Monitor / Log Analytics; queries are KQL against tables such as `SecurityEvent`, `Sysmon`-bearing tables, and Defender XDR tables like `DeviceProcessEvents`.
- **Hunting question it answers**: correlation across identity, endpoint, and cloud telemetry, with a native notebook (Jupyter) integration for the analysis step.
- **Limits**: table and column names depend on which connector and data collection rule produced the event — the same Sysmon Event ID 1 lands in different columns depending on whether the agent writes raw `EventData` or a parsed schema. Confirm with a sample query before trusting a field name. Ingestion cost is real, so high-volume sources are often filtered at the door.

```kusto
// Advanced hunting: Office applications spawning a scripting host
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by Timestamp desc
```

## 4. EDR consoles

- **What they are**: an agent on each endpoint that records process creation with full command lines and parentage, module loads, network connections attributed to a process, registry and file writes, and often memory-scan results — plus response actions (isolate host, kill process, collect a triage package).
- **Hunting question they answer**: *causality at the endpoint*. "Which process wrote that file?", "What spawned this shell?", "Which host talked to this IP, and which process owned the connection?"
- **How to hunt in one**: pivot from an alert into the process tree, then hunt the *behaviour* rather than the hash — the same parent/child shape, the same command-line fragment, the same rare binary name — across the fleet.
- **Limits**: vendor-specific query surface (some expose a query language, some only point-and-click pivots with export); endpoint-only visibility; retention measured in days to weeks; and telemetry that can be tampered with or suppressed by a sufficiently privileged adversary. Treat an EDR gap as a data question, not a verdict of innocence.

```text
# Conceptual EDR pivot (each console names these differently — this is the shape, not a syntax)
Process:      powershell.exe
Parent:       winword.exe
Command line: -nop -w hidden -enc <base64>
Child:        rundll32.exe  ->  network connection to 203.0.113.x : 443
```

Hunt the **shape** (Office parent → script host → encoded argument → outbound connection), not the sample, because the shape survives the attacker changing the payload.

## 5. Fleet DFIR and scale query: Velociraptor

Velociraptor is a DFIR platform designed around one idea: **ask a question of every endpoint at once, and get structured answers back** without installing a full agent per answer. Its query language is VQL (section 7).

- **Hunting question it answers**: "what is true across the whole estate right now?" — which hosts have a given scheduled task, a given registry value, a given file in a temp directory, a given entry in the WMI repository.
- **How a hunt runs**: clients check in to a server with a data store; you collect an **artifact** (a packaged VQL query with declared parameters) against a set of clients; results stream back per client and can be grouped, filtered, and exported.
- **Why hunters like it**: the artifact set covers the classic Windows artefacts (processes, autoruns, scheduled tasks, event logs, MFT, registry, prefetch, WMI persistence) and the results include the raw evidence, not a normalized summary — so a hit can be verified without a second collection.
- **Limits**: it is a *collection and query* platform, not a correlation engine with retention — you get answers now, and long-term trending needs the results shipped somewhere else. Client-side resource usage is real, so artifact and glob scope must be constrained. Deploy only on hosts you are authorized to query.

```bash
# Server-side: build a config, then start the GUI
velociraptor config generate -i
velociraptor gui --datastore /opt/velociraptor/data

# What can I ask for? (artifact names are the catalogue you hunt from)
velociraptor artifacts list

# Collect one artifact from the clients in the current scope
velociraptor artifacts collect Windows.System.Pslist

# Ad-hoc VQL against a single client, or against local files on the server
velociraptor query "SELECT Name, Pid, Ppid, CommandLine FROM pslist()"
```

> Flags differ between releases: run `velociraptor <subcommand> --help` on your own build before you script anything, and prefer the artifacts catalogue over hand-written VQL for routine collection. See `../methodology/04-hunting-tradecraft.md` for when hand-written VQL is worth it.

## 6. Analysis notebooks (Jupyter)

- **What it is**: a local, disposable compute environment — Python with pandas, matplotlib, and the parsers you need — where you load exported hunt data and reshape it.
- **Hunting question it answers**: *shape and periodicity*. Beaconing jitter, a histogram of process start times, the distribution of a field to find the rare value, joining an EDR export against a network export.
- **Typical flow**: run the query in the platform of record → export to CSV/JSON → load in a notebook → clean, join, baseline, plot → write the finding back to the case.
- **Limits**: nothing is live, the notebook is only as good as the export, and an un-annotated notebook is not evidence — record the query and time range that produced the data, or the finding is unverifiable. Never paste production credentials or customer data into a shared notebook.

```python
# Shape of a hunt, not a finished script: baseline then find the outlier
import pandas as pd

conns = pd.read_csv("hunt-exports/conn.csv")          # columns from your own export
per_host = conns.groupby("src_ip")["dest_port"].nunique()
print(per_host.sort_values(ascending=False).head(10))  # rare/wide fan-out stands out here

# Periodicity: intervals between consecutive connections per (source, destination)
conns["ts"] = pd.to_datetime(conns["ts"], utc=True)
conns = conns.sort_values("ts")
conns["delta"] = conns.groupby(["src_ip", "dest_ip"])["ts"].diff().dt.total_seconds()
print(conns.groupby(["src_ip", "dest_ip"])["delta"].agg(["count", "mean", "std"]).head(10))
```

A low standard deviation on `delta` across many connections is the numeric signature of a beacon. This is a *lead*, not a finding: verify it against the process that owned the connection.

## 7. Query languages you will type

Four languages cover most hunting work. Learn the *idea* of each — filter, then aggregate, then compare against a baseline — and the syntax becomes detail.

### KQL (Kibana and Microsoft Sentinel)

Pipes, `and`/`or`, wildcards, `in~` for case-insensitive membership. Field syntax differs: Kibana uses `field : value`, Sentinel Kusto uses `field == value`.

```kusto
// Sentinel / Kusto
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 1h)
| where FailedAttempts > 10
```

```text
# Kibana / KQL
event.code : "4625" and source.ip : "10.0.0.0/8" and not user.name : "svc_*"
```

### SPL (Splunk)

The pipe is the whole language: start with a search, then transform. `stats`, `eval`, `streamstats`, `timechart`, `rex` do the analytical work.

```spl
index=windows EventCode=4625
| bin _time span=1h
| stats count by _time, Account_Name, Source_Network_Address
| where count > 10
```

```spl
// Beaconing candidate: regular intervals per source/destination pair.
// Filter on the coefficient of variation (stdev / mean): a fixed absolute stdev both misses a
// slow beacon and admits fast jittery traffic.
index=proxy
| sort 0 + _time
| streamstats current=f last(_time) as prev by src_ip, dest_host
| eval delta = _time - prev
| stats count avg(delta) as avg_delta stdev(delta) as jitter by src_ip, dest_host
| eval cv = jitter / avg_delta
| where count >= 20 and cv < 0.1
```

### EQL (Elastic Security)

EQL is built for **sequences** and **process lineage** — its reason to exist is expressing "A then B on the same host" without a join. Use it in the Elastic Security timeline.

```eql
/* Single-event hunt: a scripting host started from an Office application */
process where process.parent.name == "winword.exe" and process.name in ("powershell.exe", "cmd.exe", "wscript.exe")
```

```eql
/* Sequence hunt: authentication followed quickly by remote service creation */
sequence by host.name with maxspan=10m
  [ authentication where user.name != null ]
  [ process where process.name == "services.exe" ]
```

### VQL (Velociraptor)

VQL is SQL-shaped with plugin *sources* replacing tables: `SELECT ... FROM some_plugin(...) WHERE ...`. `=~` is a regex match. Every collection is a VQL query, which is why Velociraptor artifacts are readable and reviewable.

```sql
-- Processes whose command line looks like an encoded PowerShell payload
SELECT Name, Pid, Ppid, CommandLine, CreateTime
FROM pslist()
WHERE CommandLine =~ "(?i)-enc(odedcommand)?\\s"
```

```sql
-- Files dropped into a staging directory. `OSPath` is the canonical name in current releases;
-- pre-rename builds expose the same value as `FullPath`. Check which one your build has
-- (`velociraptor vql list`, or the release notes for your version) before copying a query
-- between versions — the field silently returns nothing when the name does not exist.
SELECT OSPath, Size, Mtime FROM glob(globs="C:/Windows/Temp/**")
```

```sql
-- Failed logons straight out of a collected EVTX file
SELECT System.TimeCreated.SystemTime AS Time,
       System.Computer AS Host,
       EventData.TargetUserName AS User,
       EventData.IpAddress AS Source
FROM parse_evtx(filename="C:/Windows/System32/winevt/Logs/Security.evtx")
WHERE System.EventID.Value == 4625
```

> VQL is powerful enough to be dangerous: a `glob()` over `C:/**` on a production fleet is a denial-of-service you authorized yourself. Scope every query, test it on one client, then widen.

### Choosing the language

| I want to… | Reach for |
| --- | --- |
| Filter and count events in a SIEM | KQL (Kibana/Sentinel) or SPL (Splunk) |
| Detect periodicity / beaconing in logs | SPL `streamstats`, or a notebook |
| Express "A then B, same host, within N minutes" | EQL `sequence` |
| Ask every endpoint for a raw artefact | VQL / a Velociraptor artifact |
| Baseline a field and find the rare value | Aggregation in your SIEM, or pandas |

## 8. Comparative summary

| Criterion | SIEM | EDR | Fleet DFIR (Velociraptor) | Notebook |
| --- | --- | --- | --- | --- |
| Scope | Multi-source, retained history | Endpoints, limited history | Every enrolled endpoint, point-in-time | Whatever you exported |
| Endpoint fidelity | Normalized / lossy | High (process causality) | Highest (raw artefacts you requested) | Inherited from the export |
| Network visibility | Good (proxy, DNS, firewall, flow) | Per-process connections only | Host-level artefacts | Inherited from the export |
| Iteration speed | Fast on indexed data | Fast, console-driven | Slow-ish: collection takes time | Fast once data is local |
| Correlation across sources | Its core strength | Weak, endpoint-only | Weak by design | Manual, but flexible |
| Retention | Tiered, days to months | Days to weeks typically | None: answers, not history | Local files you keep |
| Main risk of misuse | Trusting lossy fields as truth | Assuming absence of alert = absence of activity | Querying production too broadly | Presenting unverified pattern as finding |
| Typical hunt role | Correlation and long-horizon pivoting | Behaviour triage and causality | Estate-wide sweep for a specific artefact | Baselining and periodicity |

## Common Mistakes & Tips

- **Hunting where the data is not.** Confirm the source is actually collected — count events for a known activity first, otherwise "no results" means "no telemetry", not "no activity".
- **Trusting a normalized field name.** Field names are an integration detail. When a query returns nothing, expand a sample document and read the real field names before rewriting the logic.
- **Treating an EDR console as the whole picture.** EDR sees endpoints. If the hypothesis is about egress, DNS, or authentication, add the network and identity sources.
- **Writing an unbounded fleet query.** Always scope a Velociraptor artifact (path, glob, time window, client labels) and test on one client before a broad collection.
- **Ignoring time zones and clock skew.** Logs arrive in UTC, endpoints drift, and a five-minute skew breaks a sequence hunt. Pin the timezone in the query and note it in the finding.
- **Confusing a platform with a detection.** A saved search is not a hunt, and a hunt that works should end up as a detection — otherwise you will run the same query forever by hand.
- **Leaving the negative result undocumented.** "I checked and found nothing across these sources, this window, with these caveats" is a real deliverable; without it the hunt has to be repeated.
- **Hunting on systems you do not own.** Every platform here is an authorization boundary. Query only hosts you own or are explicitly authorized to monitor.

## Checklist / Self-Test

- [ ] I can name the four platform families and the question each one answers best.
- [ ] I can state, for a given hypothesis, which family I would start in and why.
- [ ] I can write a KQL filter in both Kibana and Sentinel/Kusto syntax without mixing them up.
- [ ] I wrote an SPL search that aggregates a count per entity and filters on a threshold.
- [ ] I wrote an EQL `sequence` with a `maxspan` and can explain when a sequence beats a single-event rule.
- [ ] I ran a VQL query against `pslist()` and one against a `glob()`, and can explain why `glob` scope matters.
- [ ] I confirmed, on real data, that the field names a query used actually exist in that source.
- [ ] I know the retention and scope limits of each platform in my own environment.
- [ ] I can explain why a low-jitter connection interval is a beacon *lead* and not a finding.
- [ ] Every platform I query belongs to me or to an environment I am authorized to monitor.

## Further Resources

- Elastic Security documentation (KQL, EQL, timeline) — elastic.co/guide/en/security/current/index.html.
- Elasticsearch Query DSL reference — elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html.
- Splunk Search Reference (SPL commands) — docs.splunk.com.
- Microsoft Sentinel documentation and KQL reference — learn.microsoft.com/azure/sentinel and learn.microsoft.com/kusto/query.
- Velociraptor documentation, artifact catalogue, and VQL reference — docs.velociraptor.app.
- Jupyter documentation — docs.jupyter.org.
- MITRE ATT&CK — attack.mitre.org (the shared vocabulary for hypothesis generation).
- Official eCTHP page on the INE website for current, authoritative details about the certification.
