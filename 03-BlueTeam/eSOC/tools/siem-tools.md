# SIEM & Detection Tooling Guide

> eSOC · Tools — INE-Cybersecurity-Certifications-Guide

A SIEM (**S**ecurity **I**nformation and **E**vent **M**anagement) is the SOC analyst's main console. This guide explains what a SIEM actually does, introduces the free/open-source platforms you will meet in practice (Elastic Stack, Wazuh, and the "Splunk Free" concept), gives you query patterns to copy, and clarifies how EDR/XDR and SOAR fit into the picture.

> **Lab framing.** Every query below is meant to be run in your own lab (see `../labs/soc-scenarios.md`) against events you generated yourself. Never point these tools at systems you are not authorized to monitor.

## What a SIEM Does

Strip away the marketing and a SIEM is a pipeline with five stages:

1. **Collection** — Agents or forwarders ship logs from endpoints, servers, firewalls, and cloud services to a central store. Examples: Windows Event Logs (security, System, PowerShell), syslog from Linux/network gear, DNS and proxy logs.
2. **Parsing & normalization** — Raw lines become structured fields (`user.name`, `source.ip`, `event.code`, `process.name`) so you can search them consistently even when different devices call the same thing differently ("user", "username", "account").
3. **Indexing & storage** — Normalized events are stored in a fast, searchable index, usually with a retention policy (hot/warm/cold tiers) driven by compliance and budget.
4. **Correlation & detection** — Rules and searches look for *combinations* of events or patterns: "5+ failed logons for the same user in 2 minutes", "powershell.exe spawned from an Office app", "outbound beaconing every 60 seconds".
5. **Alerting & dashboards** — Matches become alerts in a queue, and dashboards let an analyst watch the environment, pivot from an alert to the surrounding timeline, and investigate.

The analyst's job starts where the pipeline ends: **an alert is a hypothesis, not a verdict** (see `../cheatsheets/alert-triage-guide.md`).

## Open-Source & Free Options

### Elastic Stack (Elasticsearch + Kibana, with Beats/Elastic Agent)

The most common free self-hosted choice. Component roles:

- **Elasticsearch** — distributed search and analytics engine (the index + query engine).
- **Kibana** — the UI: dashboards, Discover (search), and the Security/SIEM views with alert management.
- **Elastic Agent / Beats** — endpoint collection. Winlogbeat ships Windows Event Logs; Filebeat ships files and syslog; Elastic Agent (with the Elastic Defend integration) adds EDR-style endpoint telemetry.

Quick lab start (Docker) — check the official docs for current images and env vars:

```bash
docker network create elastic
docker run -d --name es01 --net elastic -p 9200:9200 \
  -e "discovery.type=single-node" -e "xpack.security.enabled=false" \
  docker.elastic.co/elasticsearch/elasticsearch:8.14.0
docker run -d --name kib01 --net elastic -p 5601:5601 \
  -e "ELASTICSEARCH_HOSTS=http://es01:9200" \
  docker.elastic.co/kibana/kibana:8.14.0
```

Then send Windows logs with Winlogbeat configured on your Windows VM (point it at the Elasticsearch host, choose the `winlogbeat` module, enable the `security` and `sysmon` event logs).

**Kibana query patterns (KQL)** — the language in the Discover search bar:

```text
# Every process-creation event from PowerShell
event.category : "process" and process.name : "powershell.exe"

# Failed logons (Event 4625) from an odd source IP, last 24h
event.code : "4625" and source.ip : "10.0.0.0/8"

# Any process whose command line mentions EncodedCommand (case-insensitive by default)
process.command_line : *EncodedCommand*

# Pivot: everything a single host did
host.name : "win-lab-01"

# Note there is no relative-time literal in KQL: the window comes from the time
# picker, not from the query text. If you want the range inside the query, switch
# Kibana to Lucene syntax, where ranges use brackets:
#   host.name:"win-lab-01" AND @timestamp:[now-1h TO now]
```

Elasticsearch Query DSL (Kibana → Dev Tools) when you need precision:

```json
GET /logs-endpoint.events.process-*/_search
{
  "query": {
    "bool": {
      "filter": [
        { "term":  { "process.name": "powershell.exe" } },
        { "wildcard": { "process.command_line": "*EncodedCommand*" } }
      ]
    }
  }
}
```

### Wazuh

Wazuh is a free, open-source **host-based** security platform often used as a SIEM/XDR in small-to-mid environments. A lightweight **Wazuh agent** runs on endpoints and forwards events (Windows Event Logs, syslog, file integrity, registry changes) to the **Wazuh manager**; the dashboard (a fork of Kibana/OpenSearch) shows alerts and lets you run queries. Wazuh also ships its own built-in rules, so you get working detections out of the box — great for learning correlation without building everything from scratch.

Basic flow in the lab:

```bash
# On the manager (Debian/Ubuntu example — see official quickstart for your distro)
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
bash wazuh-install.sh --generate-config-files
# ...then run the assistant and note the printed admin password + agent install command
```

```bash
# On the Windows test endpoint (from the manager's printed instructions)
wazuh-agent-4.7.5-1.exe /q
```

Query example in the Wazuh dashboard (OpenSearch/PPL syntax is close to KQL):

```text
data.win.system.eventID : 4625 and data.win.system.channel : Security
```

### Splunk Free — the "commercial but free to learn" concept

Splunk is proprietary, but its **Free license** lets you index up to 500 MB/day locally with most core search features — many courses and home labs use it to learn **SPL**, the Splunk Processing Language. If you only need to practice search syntax without standing up a full stack, Splunk Free on a single VM is a valid option. (Enterprise add-ons like Enterprise Security are not part of the free tier.)

Classic SPL pattern — given an index of Windows security events (requires the appropriate add-on/TAs):

```spl
index=windows EventCode=4625
| stats count by Account, Source_Network_Address
| where count > 5
| sort - count
```

Translation: *pull all failed logons, count them per account and source address, keep only combinations above 5, show the loudest first.* SPL teaches you the same analyst muscles as KQL: filter first, then aggregate, then decide.

## Turning Rules into SIEM Queries

Detection rules are usually written **once in a vendor-neutral format** and converted per SIEM. That is exactly what **Sigma** is for: a YAML rule (see `detection-rules/sigma-rules/sigma-example.yml`) describes *what to look for* in plain fields, and the Sigma CLI converts it to each backend's query language.

```bash
# Example conversions (paths depend on your sigma-cli install)
sigma convert -t es-qs  rule.yml        # Elasticsearch query string
sigma convert -t es-dsl rule.yml        # Elasticsearch Query DSL
sigma convert -t splunk rule.yml        # SPL
sigma convert -t kusto  rule.yml        # Microsoft Sentinel / KQL
```

The practical lesson: learn the *logic* (event source + fields + condition) once, and let tooling handle syntax — but still practice typing queries by hand, because dashboards and ad-hoc hunts rarely come pre-converted.

## Choosing a Lab Platform

Any of the four families below will teach you the analyst's job; they differ in what they cost you and what habits they build. Pick one deliberately instead of installing all four badly.

| Platform | What it is good for | What it costs you in a lab | What it will not teach you |
|---|---|---|---|
| **Elastic Stack** (Elasticsearch + Kibana + Beats/Elastic Agent) | The most complete free path: ingestion, ECS normalization, detection rules, alert management, and EQL for sequences | RAM — plan 6–8 GB for the stack alone, plus the JVM's appetite; first install needs patience | Splunk's SPL and the CIM; enterprise-grade cost control |
| **Wazuh** (manager + agent + OpenSearch dashboards) | Working detections out of the box, host-based FIM, and a small footprint | A Linux manager VM and an installed agent; dashboards are slower to explore than Kibana | Writing detections from scratch — its built-in rules do the work for you until you edit them |
| **Splunk Free** | Learning SPL, the most widely deployed commercial query language | 500 MB/day index limit, no Enterprise Security app, so no alert queue or case management | Correlation search management and case workflows at enterprise scale |
| **Microsoft Sentinel / Log Analytics** (trial or free tier) | KQL, cloud and identity telemetry, and an alert queue that looks like a real SOC console | A tenant you control, and a cost model you must watch because ingestion is the bill | On-premises endpoint telemetry unless you add a connector and agents |

A pragmatic sequence for a self-paced learner: start with **Wazuh** to get alerts flowing on day one, add **Elastic** when you want to write and convert your own rules, and use **Splunk Free** or **Sentinel free** only when you need the query language specifically. Learn the *logic* first (source + fields + condition) and translate; the languages are the cheap part.

## What a SIEM Cannot Do

Knowing the boundary prevents both false confidence and wasted effort.

- **It cannot act on an endpoint.** A SIEM reads and alerts; isolation, process kill, and quarantine belong to the EDR or the network (see `edr-and-endpoint-telemetry.md`).
- **It cannot correlate what it never received.** Every ingestion gap is an invisible blind spot: the dashboard looks calm, and calm is indistinguishable from blind.
- **It cannot hold packet-level detail.** It stores events; if you need payloads, you need PCAP capture at a chokepoint, in addition.
- **It is not a case-management system.** Tickets, ownership, tasks, and handover live elsewhere (see `case-management.md`); a queue of alerts is not a record of investigations.
- **It cannot invent context.** Asset criticality, business owner, and whether an account is a service account come from inventories and directories, not from the event stream.
- **Its correlation is shallow by design.** Counting, grouping, and simple sequences are native; multi-stage attack reconstruction across days is analyst work assisted by queries.
- **Retention is a cost decision, not a technical one.** What is not retained cannot be retro-hunted, so the retention policy is also a detection-coverage policy.

## Diagnostics: When the Platform Misbehaves

The failure modes below are the ones a tier-1 analyst meets most often. Work them in order of cheapness, and always confirm which layer is broken before changing anything.

| Symptom | Most likely cause | Check first |
|---|---|---|
| Search returns nothing, but the agent is installed | Wrong time range, wrong index pattern, or a filter that is silently excluding everything | Widen the time picker, then query the raw index without filters |
| Events arrive for one host but not another | Agent stopped, service account lost, or the host is in no policy | Agent service state, then the platform's agent list for that host |
| A field used by a rule is empty across all events from one source | Parsing or mapping break; the raw message format changed at the source | Expand one raw document and read the actual field names |
| Index creation fails or shards go red | Disk watermark reached, or a mapping conflict (one field with two types) | Cluster health, disk usage per node, and the index's mapping |
| Searches suddenly much slower | Too many shards for the data volume, an unbounded wildcard, or very wide time ranges | Shard count per index and the query's time range |
| Dashboards empty but Discover shows data | Dashboard saved with a different index pattern or a stale filter | The saved object's data view and filters |
| Alerts stop appearing but the rule exists | Rule disabled, schedule broken, suppression active, or the rule's index pattern no longer matches | Rule status, last-execution time, and any active exceptions |
| Everything is slow after an agent outage | A backfill flood: hours of buffered events arriving at once | Ingest rate spike and the timestamp distribution of the incoming events |

Two habits make this list usable. First, **test the platform with a known event** before concluding anything about the environment (the canary test in `../methodology/01-monitoring.md`). Second, **change one thing at a time**: a parser fix, an exclusion, and a retention change made in the same hour leave you unable to say which one worked.

## Query Languages: Where to Go Deeper

Every platform here is queried in its own language, and the languages differ in ways that matter more than the syntax (case sensitivity, whether a field must exist, how aggregation is expressed). The side-by-side reference — KQL, SPL, EQL, and ES|QL, with correct examples and the traps in each — lives in `query-languages.md`.

## EDR/XDR and SOAR: The Rest of the Stack

A SIEM alone sees what is *sent to it*. Modern SOCs layer more tools on top:

- **EDR (Endpoint Detection and Response)** — an agent on each endpoint collects deep telemetry (process trees, DLL loads, network connections, registry writes) and can *act*: isolate a host, kill a process, quarantine a file. Examples: Elastic Defend, Wazuh agent, CrowdStrike Falcon, Microsoft Defender for Endpoint. SOC shorthand: *the SIEM tells you a user clicked something; the EDR tells you every process that ran afterwards and can stop the machine.* Deeper coverage, including what the SOC console shows and how endpoint telemetry reaches the SIEM, is in `edr-and-endpoint-telemetry.md`.
- **XDR (Extended Detection and Response)** — the EDR idea broadened across endpoints, email, network, cloud, and identity, correlating signals that no single source would reveal. The Elastic Stack, Wazuh, and Microsoft Sentinel are common platforms that ship XDR-style capabilities.
- **SOAR (Security Orchestration, Automation and Response)** — glue that connects tools and automates repetitive triage: enrich every alert with threat-intel lookups, open a ticket, block an IP, or page a human. It also holds **playbooks** (runbooks) and case management. Examples: TheHive + Cortex (open source), Shuffle (open source), Splunk SOAR, Palo Alto XSOAR. What to automate, what must stay human, and how a playbook is structured are covered in `automation-and-soar.md`.

How a tier-1 analyst should think about them:

```text
Telemetry (EDR/XDR agents, logs)  ──►  SIEM (collect + correlate + alert)
                                            │
                              alert queue ──► analyst triage
                                            │
                     confirmed → SOAR playbook / manual escalation → response
```

## Common Mistakes & Tips

- **Searching the wrong time range.** Most "where is my event?" panic is a time-window problem. Always set `now-15m`/`now-1h` style ranges before debugging.
- **Ignoring time zones.** Logs often arrive in UTC. Convert before you conclude "the user logged in at 3 AM" — 03:00 UTC may be a normal local morning.
- **Trusting field names blindly.** Normalization is imperfect; `user.name` on one source may be `user.id` on another. When a search returns nothing, check the actual field names in a sample document (Kibana: expand one event).
- **One rule, no tuning.** A raw "contains mimikatz" rule will drown you in false positives. Learn to add *context*: who ran it, from where, with what parent process.
- **Skipping the EDR.** If your lab has an EDR agent, triage from *both* consoles — the process tree usually tells the story faster than raw logs.
- **Reinventing wheels.** Before writing a detection, check SigmaHQ and the Wazuh/Elastic rule packs — mature detections exist for most classic techniques.
- **Lab hygiene.** Use disposable credentials, isolated VMs, and only generate events you are comfortable explaining. Never copy rules that hard-code your real environment's sensitive values into a shared guide.
- **Assuming the platform is the problem when the data is.** *Tip:* before debugging a query, confirm with a known event that the source is delivering at all.
- **Using a SIEM as a case tracker.** *Tip:* alert queue ≠ investigation record; cases, tasks, and handover live in a case tool (see `case-management.md`).
- **Forgetting that retention is coverage.** *Tip:* what you do not store, you cannot retro-hunt; decide retention per log class on purpose.
- **Judging dashboards by their looks.** *Tip:* every panel answers one operational question, and a "last updated" indicator stops you trusting stale data.

## Checklist / Self-Test

- [ ] I can explain the five stages of a SIEM pipeline (collect → parse → store → correlate → alert) in one sentence each.
- [ ] I have a working Elastic Stack or Wazuh install with logs flowing from at least one endpoint.
- [ ] I can find a specific event (e.g., Event ID 4625) in Kibana/OpenSearch within 30 seconds.
- [ ] I can write a KQL/SPL query that filters by time, host, and field, and aggregates a count.
- [ ] I understand the difference between SIEM, EDR/XDR, and SOAR, and can name one example of each.
- [ ] I converted a Sigma rule to at least one backend query and verified the output runs.
- [ ] I can explain in my own words why an alert is a hypothesis, not a verdict.
- [ ] I documented my lab topology and log sources so a colleague could reproduce it.
- [ ] I can name three things a SIEM cannot do, and which tool does each of them instead.
- [ ] I can diagnose an empty search result through the platform layers (time range → index pattern → agent → parser → rule).
- [ ] I can name the trade-off I accepted when I chose my lab platform, and what it will not teach me.
- [ ] I have run one query in at least two languages and can explain how aggregation differs between them.

## Further Resources

- Elastic SIEM / Security documentation — https://www.elastic.co/guide/en/security/current/index.html
- Elasticsearch Query DSL reference — https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html
- Wazuh documentation (installation, agents, rules) — https://documentation.wazuh.com/
- SigmaHQ — https://github.com/SigmaHQ/sigma and https://sigmahq.io/
- Splunk free documentation — https://docs.splunk.com/
- MITRE ATT&CK — https://attack.mitre.org/
- YARA documentation — https://yara.readthedocs.io/
- TheHive Project (open-source SOAR/case management) — https://thehive-project.org/
