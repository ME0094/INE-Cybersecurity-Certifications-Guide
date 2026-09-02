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

# Pivot: everything a single host did in the last hour
host.name : "win-lab-01" and event.ingested >= now-1h
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

## EDR/XDR and SOAR: The Rest of the Stack

A SIEM alone sees what is *sent to it*. Modern SOCs layer more tools on top:

- **EDR (Endpoint Detection and Response)** — an agent on each endpoint collects deep telemetry (process trees, DLL loads, network connections, registry writes) and can *act*: isolate a host, kill a process, quarantine a file. Examples: Elastic Defend, Wazuh agent, CrowdStrike Falcon, Microsoft Defender for Endpoint. SOC shorthand: *the SIEM tells you a user clicked something; the EDR tells you every process that ran afterwards and can stop the machine.*
- **XDR (Extended Detection and Response)** — the EDR idea broadened across endpoints, email, network, cloud, and identity, correlating signals that no single source would reveal. The Elastic Stack, Wazuh, and Microsoft Sentinel are common platforms that ship XDR-style capabilities.
- **SOAR (Security Orchestration, Automation and Response)** — glue that connects tools and automates repetitive triage: enrich every alert with threat-intel lookups, open a ticket, block an IP, or page a human. It also holds **playbooks** (runbooks) and case management. Examples: TheHive + Cortex (open source), Shuffle (open source), Splunk SOAR, Palo Alto XSOAR.

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

## Checklist / Self-Test

- [ ] I can explain the five stages of a SIEM pipeline (collect → parse → store → correlate → alert) in one sentence each.
- [ ] I have a working Elastic Stack or Wazuh install with logs flowing from at least one endpoint.
- [ ] I can find a specific event (e.g., Event ID 4625) in Kibana/OpenSearch within 30 seconds.
- [ ] I can write a KQL/SPL query that filters by time, host, and field, and aggregates a count.
- [ ] I understand the difference between SIEM, EDR/XDR, and SOAR, and can name one example of each.
- [ ] I converted a Sigma rule to at least one backend query and verified the output runs.
- [ ] I can explain in my own words why an alert is a hypothesis, not a verdict.
- [ ] I documented my lab topology and log sources so a colleague could reproduce it.

## Further Resources

- Elastic SIEM / Security documentation — https://www.elastic.co/guide/en/security/current/index.html
- Elasticsearch Query DSL reference — https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html
- Wazuh documentation (installation, agents, rules) — https://documentation.wazuh.com/
- SigmaHQ — https://github.com/SigmaHQ/sigma and https://sigmahq.io/
- Splunk free documentation — https://docs.splunk.com/
- MITRE ATT&CK — https://attack.mitre.org/
- YARA documentation — https://yara.readthedocs.io/
- TheHive Project (open-source SOAR/case management) — https://thehive-project.org/
