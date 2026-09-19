# Query Languages for SOC Analysts — KQL, SPL, EQL, ES|QL

> eSOC · Tools — INE-Cybersecurity-Certifications-Guide
>
> The same three questions — *what executed, who authenticated, what left the network* — are asked in every SIEM, in a different language each time. This reference puts the four languages an analyst actually meets side by side, gives correct examples of each, and names the traps that make a correct-looking query return nothing.
>
> **Every query below is a syntax reference to adapt and run in your own lab.** None of them was executed while writing this note: there is no SIEM on the machine that produced it, so no result, count, or screenshot appears anywhere in it. Field names come from the schemas each platform documents (ECS for Elastic, CIM for Splunk, the `SecurityEvent`/`SecurityAlert` tables for Sentinel) — confirm them against one real document before you build on them.

## 1. The Four Languages and Where You Meet Them

| Language | Platform(s) | Model | Aggregation | Strength |
|---|---|---|---|---|
| **KQL** (Kibana Query Language) | Kibana Discover, Elastic Security search bars | Field filters with `and` / `or` / `not` and wildcards | No — aggregation happens in visualizations, ES\|QL, or detection rules | Fast, forgiving interactive filtering while triaging |
| **KQL** (Kusto Query Language) | Microsoft Sentinel, Defender, Azure Data Explorer | Piped data-flow: `Table \| where \| summarize \| project` | Yes — `summarize`, `count()`, `bin()`, `make_set()` | Full analytical language, the same one across Microsoft security products |
| **SPL** (Search Processing Language) | Splunk | Search then piped commands: `search \| stats \| where \| sort` | Yes — `stats`, `timechart`, `eventstats`, `tstats` | Powerful and ubiquitous; the de-facto language of mature SOC shops |
| **EQL** (Event Query Language) | Elastic Security | Event-pattern matching, sequences by key within a `maxspan` | No — it is a sequence engine, not an analytics language | Detecting *ordered relationships* between events, which filters cannot express |
| **ES\|QL** | Elasticsearch 8.11+ | Piped, SQL-like over indices: `FROM \| WHERE \| STATS \| SORT` | Yes — `STATS ... BY` | Aggregation inside Elastic without leaving the search bar |

> **The two "KQL"s are unrelated.** Kibana's KQL is a filter syntax with no pipe; Kusto's KQL is a piped query language. A query from one does not run in the other, which is a routine source of confusion when a detection is shared between an Elastic SOC and a Sentinel SOC.

## 2. Asking the Same Question in Every Language

The three questions below cover most tier-1 triage. Compare the shape, not just the words.

### "What executed?" — process creation with the command line

```text
// Kibana KQL (Elastic, ECS fields) - filter only, no aggregation
event.category : "process" and process.name : "powershell.exe"
```

```text
// Microsoft Sentinel KQL (Kusto) - filter plus projection
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where Process has "powershell"
| project TimeGenerated, Computer, Account, Process, CommandLine, ParentProcessName
| sort by TimeGenerated desc
```

```spl
# Splunk SPL - the same question against the Windows add-on's CIM-normalised view
index=windows EventCode=4688
| search Process_Name="powershell.exe"
| table _time, host, Account_Name, Process_Name, Process_Command_Line, Parent_Process_Name
| sort - _time
```

```esql
// Elastic ES|QL - aggregation without leaving the search bar (8.11+)
FROM logs-windows.sysmon_operational-*
| WHERE event.code == "1" AND process.name == "powershell.exe"
| STATS executions = COUNT(*) BY host.name, user.name
| SORT executions DESC
| LIMIT 20
```

### "Who authenticated, and did it work?" — logon outcome by account and source

```spl
# Splunk: failures per account and source, with the successes kept alongside
index=windows (EventCode=4625 OR EventCode=4624) earliest=-24h
| stats count(eval(EventCode=4625)) as failures,
        count(eval(EventCode=4624)) as successes
        by Account_Name, Source_Network_Address
| where failures > 0
| sort - failures
```

```kusto
// Sentinel: the same shape, with the failure sub-status to separate bad password from locked account
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4624, 4625)
| summarize Failures = countif(EventID == 4625),
            Successes = countif(EventID == 4624),
            Statuses = make_set(SubStatus, 5)
            by Account, IpAddress
| where Failures > 0
| sort by Failures desc
```

```text
# Kibana: filter in KQL, then aggregate in a visualization (or ES|QL)
event.category : "authentication" and event.outcome : "failure" and source.ip : *
```

### "Is anything beaconing?" — regularity, which needs a sequence or a time aggregation

```eql
// Elastic EQL: a script host starting and then reaching the network within the window
sequence by host.name with maxspan=30s
  [ process where process.name == "powershell.exe" ]
  [ network where destination.port == 443 ]
```

```spl
# Splunk: inter-arrival time per (host, destination), the classic beacon measurement.
# The deltas are computed on the RAW event time, before anything aggregates it:
# binning _time first rounds every event to the start of its bucket, so every
# delta becomes a multiple of the span, the spread collapses towards zero and
# every host looks perfectly regular. Sort first (streamstats needs ordered
# input), keep the events with eventstats, and only aggregate deltas at the end.
index=proxy earliest=-24h
| eventstats count as connections by host, dest_ip
| where connections > 20
| sort 0 host, dest_ip, _time
| streamstats current=f last(_time) as prev_time by host, dest_ip
| eval delta = _time - prev_time
| stats count(delta) as intervals, avg(delta) as mean_delta, stdev(delta) as sd,
        perc95(delta) as p95 by host, dest_ip
| eval jitter_ratio = round(sd / mean_delta, 3)
| sort jitter_ratio
```

```kusto
// Sentinel / Defender: connection counts per host and destination per hour, then look for flat rows
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| summarize Connections = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
          by DeviceName, RemoteIP, RemotePort
| where Connections > 20
| order by Connections desc
```

**Reading the beacon result.** Regularity is a *shape*, not a threshold: look for a low spread of intervals relative to the mean (low jitter), a small and consistent payload, a destination with no business reason, and — decisively — the **process** that owns the connection. A periodic connection without an attributed process is a lead; with a script host or an unsigned binary behind it, it is a finding. The beacon shape in `../labs/soc-scenarios.md` exercises this on network telemetry, and `../labs/anomalous-logon-investigation.md` applies the same shape reasoning — burst, interval and baseline — to authentication events.

## 3. Syntax Traps That Produce Empty Results

Most "the SIEM has no data" incidents are query errors, and this table is the fastest way out.

| Trap | Kibana KQL | Sentinel KQL | Splunk SPL | Elastic EQL |
|---|---|---|---|---|
| **Equality operator** | `:` (a colon, not `=`) | `==` | `=` in the search, `==` inside `eval`/`where` | `==` |
| **Case sensitivity** | Field names are case-sensitive; values are matched case-insensitively for keyword fields | Case-sensitive for strings unless you use `=~` | Field values are case-insensitive by default; field names are case-sensitive | Case-sensitive for strings |
| **Wildcards** | `*` inside a value, e.g. `process.command_line : *EncodedCommand*` | `contains`, `startswith`, `endswith`, `has`, `matches regex` | `*` at the end of a term in the search; use `like()` in `eval` | `wildcard()` function or `like` |
| **Time range** | Comes from the time picker; there is no relative literal | `where TimeGenerated > ago(24h)` | `earliest=-24h latest=now` | Time picker, or `maxspan` for sequences |
| **Quoting values with spaces** | `"two words"` inside quotes | `"two words"` | `"two words"` | `"two words"` |
| **Field must exist** | A filter on a non-existent field silently matches nothing | `isnotempty()` guard; missing columns are null | Search terms match raw text even if the field does not exist | `where isnotnull(field)` |
| **Multiple values** | `field : ("a" or "b")` | `where field in ("a","b")` | `field IN (a, b)` or `(field=a OR field=b)` | `where field in ("a","b")` |
| **Negation** | `not field : value` | `where field != "value"` (watch out for nulls) | `NOT field=value` | `where field != "value"` |

Three habits prevent the whole class of problem:

1. **Query the raw event before querying the field.** Find one document, expand it, read the actual field names. Guessed names return zero, and zero looks like a clean environment.
2. **Never trust an empty result until you have proved the source delivers.** Run a query you *know* must return something (the last hour of any event from that host) to separate "no matches" from "no data".
3. **Set the time range explicitly, then look.** The default window in a fresh dashboard is rarely the window you need, and the correct default for triage is usually "since the alert".

## 4. Aggregation: Where the Languages Genuinely Differ

Filters answer "show me"; aggregation answers "how many, grouped by what" — and that is where Sigma rules stop and platform logic begins.

| Task | Kusto (Sentinel) | SPL (Splunk) | ES\|QL (Elastic) |
|---|---|---|---|
| Count per group | `summarize count() by User` | `stats count by User` | `STATS COUNT(*) BY user.name` |
| Conditional count | `countif(EventID == 4625)` | `count(eval(EventCode=4625))` | `STATS failures = COUNT(*) WHERE event.code == "4625" BY user.name` |
| Distinct values | `make_set(Field, 10)` / `dcount(Field)` | `values(Field)` / `dc(Field)` | `STATS VALUES(field)` / `COUNT_DISTINCT(field)` |
| Time buckets | `bin(TimeGenerated, 1h)` | `bin _time span=1h` | `STATS COUNT(*) BY BUCKET(@timestamp, 1 hour)` |
| Threshold filter | `where count > 5` (after `summarize`) | `where count > 5` | `WHERE count > 5` (after `STATS`) |
| Top N | `top 10 by count desc` | `top limit=10 count` | `SORT count DESC \| LIMIT 10` |
| Percentile | `percentile(Duration, 95)` | `perc95(Duration)` | `STATS PERCENTILE(duration, 95)` |

Two operational consequences of this table:

- **Sigma rules describe a single event; aggregation is the platform's job.** That is why a correct Sigma rule never contains `timeframe` or `count()`. When a detection needs a threshold, write the Sigma rule for the event and configure the threshold in the SIEM (an Elastic threshold rule, a Splunk correlation search, a Sentinel analytics rule with `summarize`).
- **Report percentiles next to averages.** `avg(delta)` for beaconing hides the tail exactly where the interesting cases are; `p95` and `stdev` are what let you say "regular" with evidence (see `../methodology/07-soc-metrics.md` for the same discipline applied to SOC metrics).

## 5. Writing Queries Another Analyst Can Reuse

A triage query that lives only in a screenshot is lost. Three cheap conventions make queries reusable, and they matter more than elegance:

- **Name the entities explicitly.** Use the real host, user, and address from the alert in the query, and paste the query verbatim into the case note. "I searched for the IP" is not reproducible; the query text is.
- **Keep the time range in the query when the language allows it** (`earliest=-24h`, `ago(24h)`), or state the range you used in the note. A query without a stated window is not evidence.
- **Comment the intent** in the query itself. `// pivot: what else did this host do in the same hour` survives; your memory of why you ran it does not.

```text
# The note-ready form: query + window + what you concluded, in three lines
QUERY  Elastic ES|QL, window 2025-06-01T00:00Z to 2025-06-02T00:00Z
  FROM logs-* | WHERE user.name == "<user from the alert>" AND event.category == "authentication"
  | STATS attempts = COUNT(*) BY source.ip, event.outcome | SORT attempts DESC
RESULT <fill in: how many source addresses, which of them are known-good (VPN pool,
       office range), and which one has no explanation>
```

The third line is the part analysts skip and the part that makes the note usable: the reader needs to know what the query *meant*, not only what it said.

## Common Mistakes & Tips

- **Mistake:** using `=` in Kibana KQL or `:` in Kusto. *Tip:* Kibana uses `field : value`; Kusto and EQL use `==`. Learn the operator with the language, not after.
- **Mistake:** assuming the two KQLs are the same language. *Tip:* Kibana KQL filters; Kusto KQL pipelines. Sharing a query between an Elastic and a Sentinel SOC needs a translation, not a copy-paste.
- **Mistake:** writing a query against field names you never confirmed. *Tip:* expand one real document first; a wrong field name produces an empty result that looks like good news.
- **Mistake:** leaving the time range to the UI default. *Tip:* set the window deliberately and record it — "no results" in a five-minute window means nothing.
- **Mistake:** treating a regular connection as C2 without a process. *Tip:* interval regularity is a shape; the owning process is what turns it into a finding.
- **Mistake:** hiding the beacon tail behind an average. *Tip:* report `stdev` and `p95` alongside the mean, and compute the deltas from raw event times rather than from time buckets — a one-minute bucket makes every interval a multiple of 60 s, so the spread collapses and every host looks perfectly regular.
- **Mistake:** bucketing timestamps before measuring intervals. *Tip:* `bin` is for counting ("how many per hour?"), `streamstats` over raw `_time` is for measuring ("how far apart?"). Using the counting tool for the measuring job produces a confident zero-jitter result for traffic that has none.
- **Mistake:** keeping the winning query in a screenshot. *Tip:* paste queries verbatim into the case note with their time range and what they showed.

## Checklist / Self-Test

- [ ] I can write the same "what executed?" query in Kibana KQL, Kusto, and SPL without looking them up.
- [ ] I know which of the two KQLs pipes data, and which one only filters.
- [ ] I can write an EQL sequence and explain what `maxspan` does.
- [ ] I can aggregate a count per group in Kusto, SPL, and ES|QL.
- [ ] I can name five syntax traps that make a correct-looking query return nothing.
- [ ] I confirm an empty result against a query that must return something before concluding anything.
- [ ] I can measure beacon regularity with inter-arrival deltas rather than a raw connection count.
- [ ] I know why `timeframe` and `count()` do not belong in a Sigma rule, and where that logic lives instead.
- [ ] I record every triage query verbatim with its time range and result summary.

## Further Resources

- Elastic — Kibana Query Language (KQL) reference: https://www.elastic.co/guide/en/kibana/current/kuery-query.html
- Elastic — ES|QL reference (piped aggregation over indices): https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html
- Elastic — EQL syntax and sequences: https://www.elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html
- Microsoft Learn — Kusto Query Language (KQL) overview: https://learn.microsoft.com/en-us/kusto/query/
- Microsoft Learn — KQL quick reference and operators: https://learn.microsoft.com/en-us/kusto/query/kql-quick-reference
- Splunk — Search reference (SPL commands): https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual
- Splunk — Search command `stats`, `eval`, and `where`: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Stats
- SigmaHQ — specification, including why correlation is a backend concept: https://github.com/SigmaHQ/sigma-specification
