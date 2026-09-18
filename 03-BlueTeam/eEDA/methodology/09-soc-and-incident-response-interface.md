# The SOC and Incident Response Interface

> eEDA · Methodology — Enterprise Defense Administrator
>
> Phase 09. The administrator builds and operates the environment; the SOC watches it and incident response fights inside it. This phase defines that interface in both directions: what the administrator must deliver to make detection and response possible, what the administrator needs back, and how the handover works under time pressure.

## Purpose

A large share of "detection did not work" and "response took too long" incidents are interface failures, not tool failures. The SOC could not see a system because nobody shipped its logs. The analyst could not judge an alert because nobody supplied asset ownership. Incident response could not isolate a host because nobody documented how. The administrator could not prioritise a patch because nobody said the CVE was being exploited. This guide gives you the deliverables, the handover packet, the containment actions and their authorization, and the metrics for the interface. It maps to **CIS Controls v8 control 8 (Audit Log Management), control 13 (Network Monitoring and Defense) and control 17 (Incident Response Management)**, and to the incident-handling lifecycle in **NIST SP 800-61 Rev. 2**.

## Who Owns What

Clear boundaries prevent both gaps and collisions. The same person may hold several roles in a small team — the point is that each responsibility is named once.

| Activity | Administrator | SOC analyst | Incident responder |
|---|---|---|---|
| Build and harden systems | **Owns** | — | — |
| Configure and ship logs | **Owns** | Consumes; raises gaps | Consumes |
| Triage an alert | Consumes when asked | **Owns** | Consults |
| Declare an incident | Escalates | Recommends | **Owns** (with management) |
| Contain a host (isolate, disable account) | **Executes** | May request | **Decides** |
| Eradicate malware and rebuild | **Executes** | — | **Owns the plan** |
| Decide the recovery point | Provides options | — | **Owns** with the business |
| Restore service | **Executes** | — | **Owns the timeline** |
| Post-incident remediation | **Executes** | Detection improvement | **Owns the report** |

> Two rules remove most friction: the administrator **executes containment on request and does not decide it alone**, and the administrator **never quietly modifies a system under investigation** without telling the incident owner. Evidence destroyed by a well-meaning fix is a permanent loss.

## What the Administrator Owes the SOC

### 1. Log sources, onboarded properly

For every source, the SOC needs more than "we forward the logs". Use this intake record:

```markdown
### Log source intake — <source name>

- Source system(s):            <hosts, appliances, cloud services>
- Owning team and contact:     <name, escalation path>
- Transport and format:        <agent/forwarder, syslog/CEF/JSON/EVTX, port>
- Volume estimate:             <events/day or GB/day, peak>
- Time source:                 <NTP source; confirmed UTC>
- Fields guaranteed present:   <user, source IP, event outcome, host identifier>
- Retention required:          <by policy: IR, compliance, hunting>
- Coverage gaps acknowledged:  <what this source does NOT record>
- Onboarding evidence:         <known event generated, found in the platform, timestamped>
```

That last line is the one that prevents the most common failure in the whole interface: a source that is configured but not delivering, whose silence is read as clean.

### 2. Asset and identity context (enrichment)

An alert that says `10.20.4.31` is a lead. An alert that says `ACME-DB-01, T1, customer payment data, owner: finance systems lead` is a decision. The administrator supplies the feed:

| Enrichment | Comes from | Refreshed |
|---|---|---|
| Host ↔ asset record (name, owner, tier, OS) | Asset inventory ([05](05-asset-inventory-and-configuration.md)) | Daily |
| IP address history (who had this address when) | DHCP/DNS records | Daily, retained |
| Identity context (human vs service, privileged?) | Identity inventory ([06](06-identity-and-privileged-access.md)) | Daily |
| Criticality and data class | Asset register | On change |
| Expected behaviour baseline (what this host normally talks to) | Network flows, agent telemetry | Weekly |

Without IP history, every retrospective investigation into "who was on that address three weeks ago" stalls. Keep it.

### 3. A change calendar

Planned maintenance produces alerts, and unexplained alerts consume analyst hours. Publish changes — patching windows, network changes, application deployments, certificate renewals, bulk account changes — with a scope and a time window in the SOC's timezone.

### 4. Truth about administrative activity

Legitimate administrative work is indistinguishable from attacker behaviour in the logs, and the administrator is the only one who knows which is which:

- Notify the SOC **before** using break-glass accounts, and always after (monitored use is the point of break-glass).
- Announce planned bulk operations: password resets, mass group changes, scripted deployments, service account rotations.
- When the SOC asks "did you do this?", answer with the ticket number, the operator, and the time window — not with "probably".

### 5. A named contact path

An alert at 03:00 needs a human who can isolate a host, disable an account, or restart a service. Publish the escalation path, the on-call rota, and the precise authority each level has (see the containment table below).

## What the Administrator Needs Back from the SOC and IR

| Signal | Why the administrator needs it | Example form |
|---|---|---|
| Exploitation in the wild | Re-prioritises a patch or triggers an emergency change | "CVE in this vendor product is being exploited; treat as P0" |
| Detection-driven change requests | Fixes the root cause rather than the symptom | "RDP exposed on three servers; alerting fires daily" |
| Verification requests | Confirms a remediation actually worked | "Re-scan host X after the change; confirm the behaviour is gone" |
| Compromised-host and account lists | Scope for patching, credential rotation, and rebuild | "These 6 hosts and 2 accounts were touched" |
| Indicators for sweeping | Turns one incident into estate-wide assurance | Hashes, paths, domains, scheduled-task names |
| Telemetry gap findings | Feeds the next cycle of log onboarding | "No process creation data from the finance segment" |
| Post-incident findings | Becomes backlog items with owners | "Backups were reachable from the domain admin tier" |

> Ask the SOC for a written top-five of the alerts they cannot action because of missing administrative information — an owner, an exclusion, a baseline, a change record. It is the fastest way to find the interface problems that matter.

## The Handover Packet

When IR takes over, the administrator's job is to hand over context fast. Build the packet **before** you need it: one page per T1 system, stored where it is reachable when the network is not.

```markdown
### Handover packet — <system name>          Last updated: <date> by <name>

IDENTITY
  Hostname(s) / role / tier:        ACME-DB-01 / primary database / T1
  Business owner and contact:       <name, phone, alternate>
  Technical owner and escalation:   <name, on-call path>

WHAT IT IS
  Function and dependent services:  order processing; ERP, reporting layer depend on it
  Data it holds:                    customer records, order history, payment references
  Regulatory scope:                 PCI DSS (card references), GDPR (customer data)

ACCESS
  Privileged accounts with access:  <admins, service accounts, vendor accounts>
  Authentication paths:             domain + local break-glass; no MFA on legacy app account
  Network reachability:             app tier only; no internet ingress

TELEMETRY
  Log sources and platform:         host security log, DB audit log, EDR, flow records
  Retention and known gaps:         90 days hot; DB audit log does not record read activity
  Current baseline / deviations:    CIS Level 1 + 2 approved deviations (register ref)

CHANGE HISTORY
  Recent changes (30 days):         <patch cycle, DB migration, firewall rule change>
  Planned changes in flight:        <none / change ticket numbers>

RECOVERY
  RTO / RPO:                        24 h / 4 h
  Backup scheme and last test:      nightly full + hourly log; restore tested <date>
  Preferred recovery point:         to be agreed with IR (last trusted backup)

WHAT THE ADMIN CAN DO FAST
  Isolate host:                     <mechanism, and what it breaks>
  Disable account:                  <mechanism, blast radius>
  Rotate credentials:               <list of accounts and dependent services>
  Restart / fail over:              <procedure reference, expected downtime>
```

If filling this in takes more than an hour, you have found an operational documentation gap worth fixing while the environment is calm.

## Administration Inside the Incident Lifecycle

Mapping NIST SP 800-61 Rev. 2 phases onto what the administrator actually does:

| Phase | Administrator's work | Artifact produced |
|---|---|---|
| **Preparation** | Log onboarding, asset enrichment, baselines, backups and restore tests, runbooks, contacts, containment mechanisms tested | Intake records, handover packets, test results |
| **Detection and analysis** | Provide logs, answer "did you do this?", supply known-good baselines, validate suspicious configuration | Answers with ticket references; baseline exports |
| **Containment** | Execute isolation, account disable, credential rotation, service stop — on instruction, documented | Action log with timestamps and operator identity |
| **Eradication** | Reimage from a known-good image, apply patches, remove persistence, rebuild services from configuration as code | Rebuild records, patch reports, post-change scan results |
| **Recovery** | Restore in dependency order, confirm functionality, re-enable access, monitor for recurrence | Restore test records, measured RTO/RPO, monitoring confirmation |
| **Post-incident** | Close remediation actions, fix drift, update baselines and runbooks, onboard missing telemetry | Backlog items with owners; updated baseline and runbook versions |

### Containment actions: what they cost

Every containment action breaks something. Know the cost before you are asked to choose under pressure:

| Action | Immediately stops | What it breaks | Authorization |
|---|---|---|---|
| Network isolation of a host | C2 traffic, lateral movement from the host | Business service on that host; remote administration | Requested by SOC/IR; executed by admin |
| Disable an account | Attacker use of that identity | The human's work; any service using it | IR decision; admin executes |
| Credential rotation | Continued use of stolen credentials | Services with cached credentials, tokens, scheduled jobs | IR decision; admin plans the blast radius |
| Stop a service | The exploited service | Dependent business function | IR decision, business informed |
| Block IP/domain at the edge | Specific C2 or exfiltration path | Legitimate traffic to shared infrastructure (cloud, CDN) | SOC may do it directly; admin informed |
| Power off a VM | Everything the host does, and volatile evidence | Forensic memory evidence — **ask first** | IR decision only |
| Restore from backup | Current (possibly compromised) state | Everything since the backup; may restore the compromise | IR + business decision |

> Two of these are irreversible in practice: powering off a host destroys volatile memory evidence, and restoring from backup can reinstate the adversary. Never take either action on a host under investigation without the incident owner saying so explicitly.

## Metrics for the Interface

| Metric | Definition | What it reveals |
|---|---|---|
| Log source coverage | required sources ingesting ÷ required sources | The gap between the source list and reality |
| Onboarding time | request date → verified events in the platform | Whether the interface works at operational speed |
| Enrichment completeness | alerts with asset owner and tier populated ÷ total alerts | Whether analysts can decide or must investigate the inventory first |
| Administrative delay | time from containment request → containment executed | The administrator's contribution to MTTR |
| Rebuild/restore time vs RTO | measured recovery per incident | Whether the recovery objective is real (see [08](08-continuity-and-recovery.md)) |
| Recurrence rate | incidents repeating a previously fixed root cause | Whether post-incident remediation closed |
| False-positive causes attributed to admin data | alerts closed because the change was expected but unannounced | The cost of an unpublished change calendar |

## Common Mistakes & Tips

- **Configuring a log source and assuming it works.** Verify by generating a known event and finding it in the platform. Silent sources are the most expensive kind of gap.
- **No IP address history.** DHCP churn means an IP in an old alert may belong to a different device today. Keep the mapping with timestamps, and know that retention is part of detection quality.
- **Unannounced administrative activity.** Bulk password resets, mass group edits, and scripted deployments generate exactly the patterns the SOC hunts for. Publish the change calendar or spend the hours answering questions.
- **Admins responding without a decision owner.** Executing containment is an administrator's job; deciding it is not. Get the instruction in writing (ticket or chat log) and record the timestamp.
- **Cleaning up before the evidence is collected.** Deleting a suspicious file, clearing a queue, or rebooting "to see if it helps" can destroy the only copy of the evidence. Ask first, always.
- **Rebuilding without hardening.** Restoring a system to its pre-incident configuration restores the vulnerability that allowed entry. Rebuild from a current, patched image, then verify against the baseline.
- **Closing an incident without a control change.** Every incident has at least one administrative implication: a patch, a config change, a log source, a backup fix, an access change. Track them as tickets with owners, not as meeting notes.
- **Treating the SOC as a service desk.** The interface works when both directions are explicit: what you deliver (sources, context, changes, actions) and what you receive (exploitation intel, verification requests, findings).
- **Tip**: rehearse one live-fire exercise a year with the SOC — a compromised-host scenario where the administrator is asked to isolate, disable, rotate, and restore against a clock. It is the only way to discover that the runbook is wrong.
- **Tip**: keep the handover packet for T1 systems in a place that survives the outage: printed, or in an offline store. A recovery runbook on a share that is also down is decoration.

## Checklist / Self-Test

- [ ] I can state who owns containment decisions versus who executes containment actions.
- [ ] I can write a log source intake record, including the verification evidence.
- [ ] I can list the asset and identity enrichment fields the SOC needs, and where each comes from.
- [ ] I can produce a handover packet for one T1 system from memory of its structure.
- [ ] I can map the administrator's work onto the NIST SP 800-61 Rev. 2 lifecycle phases.
- [ ] I can state what each containment action breaks, and who must authorize it.
- [ ] I can name two actions that are irreversible for evidence or recovery reasons.
- [ ] I can describe what the SOC owes the administrator, with an example of each item.
- [ ] I can define administrative delay and enrichment completeness and explain why they matter to MTTR.
- [ ] I can name the administrative implication of the last incident I read about.

## Further Resources

- NIST SP 800-61 Rev. 2 — Computer Security Incident Handling Guide (lifecycle phases, preparation, and coordination): https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- CIS Critical Security Controls v8 — control 8 (Audit Log Management), control 13 (Network Monitoring and Defense), control 17 (Incident Response Management): https://www.cisecurity.org/controls
- NIST CSF 2.0 — DE (Detect), RS (Respond), and RC (Recover) function outcomes: https://www.nist.gov/cyberframework
- ISO/IEC 27001:2022 — Annex A 5.24–5.28 (incident management planning, assessment, response, learning, and evidence collection) and A.8.16 (monitoring activities): https://www.iso.org/standard/27001
- Wazuh documentation — open-source SIEM/log analysis used as the collection platform in the labs: https://documentation.wazuh.com/
