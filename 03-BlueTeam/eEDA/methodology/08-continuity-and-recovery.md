# Continuity and Recovery

> eEDA · Methodology — Enterprise Defense Administrator
>
> Phase 08. Every control you build in the other phases is a bet that you will not have to recover. This phase is the hedge: what the administrator must know, design, test, and prove so that a ransomware event, a hardware failure, or a deleted directory does not end the conversation. It covers business-impact inputs, RTO/RPO, backup architecture, restore testing, recovery ordering, and the metrics that separate a backup that exists from a recovery that works.

## Purpose

Recovery is where security work meets operations under pressure. An administrator owns the mechanics — backup schedules, retention, immutability, restore procedures, dependency ordering — but the *requirements* come from the business, expressed as **RTO** (how long the service may be down) and **RPO** (how much data the business can afford to lose). This guide gives you the tiering model, the design rules, the test plans, and the evidence that a recovery capability is real. It maps to **CIS Controls v8 control 11 (Data Recovery)**.

## The Inputs You Need Before You Design Anything

You cannot design backups from a server list. You need, per service:

| Input | Question | Who answers |
|---|---|---|
| Business function | What does this service do, and who depends on it? | Business owner |
| RTO | How long may it be unavailable before the impact becomes unacceptable? | Business owner |
| RPO | How much data may be lost, measured in time? | Business owner |
| Data classification | What data does it hold, and what obligations attach to it? | Data owner + compliance |
| Dependencies | What must be running *before* this service can run? | Platform team |
| Degraded mode | Can the business operate partially while it recovers? | Business owner |
| Regulatory retention | How long must the data be kept, and for what? | Compliance |

If nobody will give you an RTO, propose one and get it confirmed in writing. An assumed RTO is the requirement you will be measured against during an incident whether anyone agreed to it or not.

## RTO, RPO, and What They Cost

RTO and RPO are not aspirations; they are purchase orders. Tightening either one multiplies cost, so the business needs to see the trade.

| Service (example) | RTO | RPO | Recovery technique that meets it |
|---|---|---|---|
| Public web shop (payment path) | 4 hours | 15 minutes | Warm standby + continuous log shipping + tested failover runbook |
| Internal ERP | 24 hours | 4 hours | Daily full + hourly transaction log backup, restore to standby hardware |
| File shares | 48 hours | 24 hours | Nightly backup + immutable copy; restore on demand |
| Email | 8 hours | 1 hour | Vendor-hosted with journaling; documented vendor dependency |
| Domain services | 4 hours | 4 hours | Multiple domain controllers, system-state backups, documented authoritative restore |
| Developer CI/CD | 72 hours | 24 hours | Configuration as code; rebuild rather than restore |

```text
Cost-versus-objective conversation to have explicitly:

  RTO 4h + RPO 15min  ->  standby infrastructure, replication, tested runbooks,
                          on-call coverage, and quarterly failover tests
  RTO 72h + RPO 24h   ->  nightly backups to a second location and an annual restore test

Two systems with the same data can legitimately have different objectives.
Do not give every system the tightest target you can imagine; you will fail
some of them and lose credibility for all of them.
```

## Backup Design Rules

The rules below are the ones that survive contact with ransomware.

### 3-2-1 and its extension

```text
3  copies of the data (production + two backups)
2  different media or storage systems (not two directories on the same array)
1  copy off-site, in a failure and trust domain separate from production
+1 one copy that is IMMUTABLE or OFFLINE for the retention period that matters
```

The last line is the modern addition and the one that decides whether ransomware is a bad week or an extinction event. An attacker with domain administrator rights will delete or encrypt every backup they can reach: mounted shares, backup servers joined to the domain, and cloud buckets whose credentials live on a compromised host.

### Immutability and separation

| Control | What it prevents | How it is commonly implemented |
|---|---|---|
| Object lock / write-once retention | Deletion or encryption of backups by a compromised admin account | Storage-level retention policy on the backup repository |
| Air gap / offline copy | Any online attack path reaching the copy | Rotated removable media or a repository that is physically or logically offline |
| Separate credential domain | Backup infrastructure compromised via the production directory | Backup servers not managed by the same directory/administrative tier |
| Push-only or pull-only topology | Attack traffic from production to backup | The backup server pulls, or production pushes to a host that accepts no inbound sessions |
| Encryption with managed keys | Media theft; also self-inflicted loss if keys are lost | Key stored where a restore can retrieve it *without* the systems being restored |

> Encrypt your backups, then ask the recovery question: *in a total-loss scenario with no production systems left, where do the keys come from, and who can get them at 03:00?* Losing the keys converts a recovery plan into a data-loss event with paperwork.

### What people forget to back up

Data is the obvious part. A restored server that cannot rejoin its domain, resolve names, or present a valid certificate is not recovered. Include:

- **Identity**: directory system state, and the documented procedure for an authoritative restore.
- **DNS and DHCP**: zone data and address reservations; a recovered application with no name resolution is down.
- **Certificates and PKI**: the certificate authority, its keys, and the issuance records.
- **Configuration baselines and golden images**: so rebuilt hosts start hardened.
- **The inventory and the CMDB**: you cannot rebuild what you cannot enumerate; a post-incident rebuild starts here.
- **Secrets and service credentials**: from the secrets manager's own backup, with the key-custody question above answered.
- **Source code and pipelines**: or a documented guarantee that they live in an external service.
- **The recovery documentation itself**: runbooks, contact trees, and vendor support numbers must be reachable when the intranet is not. Print or store them offline.

## Restore Testing: The Only Evidence That Counts

A backup job that reports "success" proves that bytes were written. It does not prove that the data can be restored, that the application can start, or that the business can work from it. **The evidence of recovery capability is a restore.**

| Test type | What it proves | Effort | Frequency (by tier) |
|---|---|---|---|
| Sample file restore | The backup is readable and the catalog works | Minutes | Monthly (T1), quarterly (T2) |
| Full data-set restore to a clean host | Volume, retention chain, and integrity | Hours | Quarterly (T1) |
| Application-level restore and functional test | The application starts on restored data and *works* | Half a day | Semi-annual (T1) |
| Bare-metal / full-environment recovery | You can rebuild from nothing, including identity and DNS | A day or more | Annual (T1), or after major platform changes |
| Failover to standby (DR test) | The RTO is achievable under real conditions | A day, needs coordination | Annual minimum for T1 |
| Tabletop exercise | The people, decisions, and communications work | 2 hours | Semi-annual |

What to record for each test, because this is the audit evidence:

```text
Test ID and date            RESTORE-2026-Q1-WEBSHOP
Restore target              Isolated lab host, no production network access
Source                      Immutable repository copy from 2026-03-14 02:00
Data range restored         Full application + database
Measured RTO achieved       3 h 10 min   (target 4 h)
Measured RPO achieved       11 min       (target 15 min)
Deviations and faults       restore of attachment volume needed a second pass;
                            runbook step 7 was wrong and has been corrected
Sign-off                    Restore operator + application owner
Follow-up actions           runbook v1.3 published; monitoring gap closed
```

A test with no deviations recorded is a test that was not performed seriously. Record the faults; they are the entire point.

## Recovery Ordering: The Part Nobody Rehearses

Restoring everything at once does not work, because most services depend on services that are also being restored. Publish a **dependency-ordered recovery plan** and rehearse it as a sequence.

```text
Recovery order, worked example:

  1  Physical/virtual platform, storage, network fabric
  2  Identity (directory, DNS, DHCP, time source)  <- nothing else works reliably without this
  3  Certificate services and secrets/key management
  4  Backup infrastructure itself (so subsequent restores can use it)
  5  Security and monitoring (logging, EDR, SIEM ingestion)
  6  Core data services (databases, file shares)
  7  Business applications, in dependency order (ERP before its reporting layer)
  8  Access paths (VPN, remote access, SSO)
  9  Workstations and end-user services
 10  Reconciliation: re-inventory, re-scan, re-baseline, and confirm nothing restored
     from a compromised point in time
```

Steps 2, 3, 4, and 5 are the ones that get skipped in plans written by people who have never rebuilt an environment. Step 10 matters for a different reason: restoring a backup taken *during* a compromise restores the compromise.

> When a compromise is suspected, agree the **recovery point** with incident response before restoring: the last backup you can trust. Restoring from a compromised snapshot is how organisations re-infect themselves and turn one incident into three.

## Ransomware-Resistant Recovery Checklist

```text
[ ] At least one backup copy is immutable or offline for the primary retention period.
[ ] Backup credentials are separate from production administrative credentials.
[ ] Backup infrastructure does not depend on the production directory to function.
[ ] Restores have been tested from the immutable copy, not only from the fast local copy.
[ ] Retention meets the business requirement (long enough to notice a slow intrusion).
[ ] A recovery-point decision procedure exists with incident response.
[ ] Recovery documentation exists offline, with contacts and vendor numbers.
[ ] The recovery ordering plan exists and has been rehearsed at least once.
[ ] Someone is accountable for the recovery capability, by name.
```

## Metrics

| Metric | Definition | Trap it avoids |
|---|---|---|
| Backup success rate | successful jobs ÷ scheduled jobs | Necessary but insufficient — a 100% success rate with no restores proves nothing |
| Restore success rate | successful restore tests ÷ attempted restore tests | The only number that speaks to capability |
| **Unrestored backup age** | days since the current backup set was last successfully restored | Ranks alongside the above; a backup set that has never been restored is a hypothesis |
| RTO achieved vs. target | measured recovery time per test ÷ target | Surfaces targets that are unachievable before an incident proves it |
| RPO achieved vs. target | measured data loss per test ÷ target | Detects backup schedules that cannot meet the stated RPO |
| Immutable copy coverage | protected data sets ÷ data sets in scope | Finds the systems everyone assumed were covered |
| Test deviation closure | follow-up actions closed ÷ raised | A test whose findings are never fixed is a rehearsal of failure |

## Evidence for Audits and Incidents

| Claim | Evidence |
|---|---|
| "Backups run and are monitored" | Job history with alerting configuration and last alert test |
| "Backups are protected from tampering" | Storage retention policy, credential separation design, and a test proving deletion is blocked during retention |
| "Restores work" | Dated restore test records with measured RTO/RPO and deviations |
| "The business requirements are met" | RTO/RPO per service, signed by the business owner, mapped to the recovery technique |
| "Recovery is planned, not improvised" | Dependency-ordered recovery plan with rehearsal record |
| "The plan is maintained" | Review date, and a change log linking plan updates to platform changes |

## Common Mistakes & Tips

- **Treating a successful backup job as a backup.** Jobs are cheap; restores are the evidence. Track "days since last successful restore", not just "days since last failure".
- **Backups reachable from the compromised tier.** If a domain administrator can delete the backup repository, the ransomware operator can too. Separate the credential and trust domain, and make one copy immutable.
- **Never testing the full chain.** Restoring a single file proves the catalog; only a bare-metal or full-environment test proves you can rebuild identity, DNS, and certificates.
- **No RPO discipline on databases.** A nightly full backup of a database with a 4-hour RPO loses up to 24 hours. The technique must match the stated objective — transaction logs, log shipping, or replication.
- **Losing the encryption keys.** Test key retrieval *as part of* the restore test, from the same assumed-loss situation.
- **Ignoring retention.** A 30-day retention cannot recover from an intrusion that started 90 days ago. Align retention with the realistic detection window, and with regulatory retention requirements.
- **No ordering plan.** Parallel restores collide on dependencies and multiply the outage. Sequence it and rehearse it.
- **Restoring the compromise.** Couple the restore decision to incident response, and reconcile afterwards (re-scan, re-baseline, rotate credentials).
- **Tip**: put the recovery test on the calendar as a project with a date and an owner. Recovery capability that is only discussed in meetings decays silently.
- **Tip**: when you restore in a test, restore to an *isolated* network. A restored production system on the production network, from an old data set, is an incident you generate yourself.

## Checklist / Self-Test

- [ ] I can explain RTO and RPO and give the recovery technique that satisfies each for two different services.
- [ ] I can list the inputs I need from the business before designing a backup solution.
- [ ] I can state the 3-2-1 rule plus the immutability requirement, and explain what each addresses.
- [ ] I can name five things teams forget to back up, beyond data.
- [ ] I can design a restore test program by tier, with frequency and the artifact each test produces.
- [ ] I can write a restore test record including deviations and follow-up actions.
- [ ] I can produce a dependency-ordered recovery plan for a small environment.
- [ ] I can explain why restoring from a backup taken during a compromise is dangerous, and who decides the recovery point.
- [ ] I can define the metrics that distinguish backup existence from recovery capability.
- [ ] I can name the evidence for "restores work" and "backups are protected from tampering".

## Further Resources

- CIS Critical Security Controls v8 — control 11 (Data Recovery): https://www.cisecurity.org/controls
- NIST SP 800-34 Rev. 1 — Contingency Planning Guide for Federal Information Systems (planning process, BIA, and test types): https://csrc.nist.gov/publications
- NIST SP 800-53 Rev. 5 — CP (Contingency Planning) control family: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST CSF 2.0 — RC (Recover) function outcomes: https://www.nist.gov/cyberframework
- ISO/IEC 27001:2022 — Annex A 5.29 (information security during disruption), 5.30 (ICT readiness for business continuity), and 8.13 (information backup): https://www.iso.org/standard/27001
- NIST SP 800-61 Rev. 2 — Computer Security Incident Handling Guide (recovery phase and coordination with IR): https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
