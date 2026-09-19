# Asset Inventory and Configuration Management

> eEDA · Methodology — Enterprise Defense Administrator
>
> Phase 05 of nine. The first four phases set the direction — governance, risk, compliance, and engineering. This phase is about the raw material all four depend on: knowing what you own, what is installed on it, and what state its configuration is in. It maps to **CIS Critical Security Controls v8 controls 1 (Inventory and Control of Enterprise Assets) and 2 (Inventory and Control of Software Assets)**, and it is the precondition for nearly everything in the later phases.

## Purpose

Every control you will ever claim depends on an inventory. Vulnerability management cannot patch a host it does not know about. Access reviews cannot revoke access to an application nobody listed. Backups cannot protect a server that no one registered. Incident response cannot scope a breach when the asset list is a spreadsheet that stopped being updated eight months ago. This guide covers how inventories are built and kept honest, how software is authorized and controlled, how assets are tiered, and how configuration baselines are set, enforced, and verified — with the reconciliation workflows and metrics that turn a one-off discovery into a managed process.

## Why Inventory Is Control Number One

CIS orders its 18 controls deliberately, and the two inventory controls come first because the rest are arithmetic on top of them:

| Later control | What it needs from the inventory |
|---|---|
| 3 Data Protection | Which assets hold which data classes, so protection follows the data |
| 4 Secure Configuration | A list of assets to configure, and of configuration items to track |
| 5/6 Account and Access Management | Which systems hold accounts, and which accounts are privileged where |
| 7 Continuous Vulnerability Management | The scan scope — you cannot fix what you never scanned |
| 8 Audit Log Management | Which sources must ship logs, and which are silent |
| 11 Data Recovery | Which systems are backed up, and which were quietly missed |
| 12/13 Network Management and Monitoring | Which devices are on the network, and where the flows should go |
| 17 Incident Response | Blast-radius scoping in the first hour of an incident |

> The practical test of an inventory is not "does it exist" but "would it survive contact with an incident". If an attacker is on a host that your inventory does not list, you have already lost the scope argument.

## Three Inventories People Confuse

Most organisations have all three and treat them as one. They answer different questions, have different owners, and go stale at different rates.

| Artifact | Holds | Owner | Update trigger | Typical failure |
|---|---|---|---|---|
| **Asset register / inventory** | Every asset that exists, with owner, location, criticality, OS | IT operations | Discovery cycle + change process | Silent stale rows for decommissioned hosts |
| **CMDB** | Assets *plus* their relationships, dependencies, and services | Service management | Change records, CI lifecycle | Becomes a diagram nobody trusts; relationships rot |
| **Authorized software list (allowlist)** | Software the organisation permits, by title and version band | Security + IT | Change request + review | Grows by accretion until "authorized" means nothing |

The **discovered** inventory (what a scanner or agent actually sees) is a fourth artifact, and the most useful one for security, because it cannot lie about existence — only about management.

## Sources of Truth and Their Failure Modes

No single source is complete. The defender's job is to reconcile several deliberately, because each one fails a different way.

| Source | Sees | Blind spot |
|---|---|---|
| Directory objects (AD / Entra ID) | Domain-joined Windows hosts and users | Linux, macOS, appliances, non-joined Windows, cloud VMs |
| Endpoint agent / EDR console | Hosts with the agent installed and reporting | Anything whose agent was uninstalled, disabled, or never shipped |
| DHCP leases and DNS records | Anything that asked for an address | Static-IP devices; short retention loses history |
| Network discovery (authenticated scan, NAC, switch MAC tables) | Anything passing traffic | Powered-off assets; segmented networks with no sensor |
| Cloud provider inventory (subscription/resource APIs) | Cloud resources | Shadow accounts; resources in untracked subscriptions |
| Configuration management (Ansible, Intune, GPO) | Assets under management | **Everything unmanaged** — the exact population that matters |
| Purchasing / finance records | What the company bought | Personally acquired and shadow-IT devices; SaaS free tiers |

> The dangerous question is never "what is in my inventory?" but "what is on the network that is *not* in my inventory?" Reconciliation is designed to produce that list on a schedule, not as a surprise.

## Hardware Inventory in Practice

### The reconciliation cycle

A workable monthly cycle, run by one owner:

```text
1. DISCOVER   Export the discovered set: agent console + DHCP leases + scanner results.
2. COMPARE    Left-join the discovered set against the asset register.
3. CLASSIFY   Every row gets a disposition:
                MATCHED        known and managed
                UNMANAGED      known, no agent/baseline -> fix or document
                UNKNOWN        on the network, not registered -> investigate
                MISSING        registered, not seen -> decommission or investigate
                OWNERSHIP GAP  exists but no accountable owner
4. RESOLVE    Each non-MATCHED row becomes a ticket with an owner and a due date.
5. RECORD     Close the cycle with counts per disposition; trend them.
6. RETAIN     Keep the export: it is the audit evidence that the cycle ran.
```

The two dispositions that matter most are **UNKNOWN** (unauthorized equipment — the classic entry point) and **MISSING** (a registered host that stopped reporting: either decommissioned without paperwork, or switched off to avoid being seen).

### Worked reconciliation example

Acme Widgets Inc. (the fictional company used throughout this module) runs its first cycle and gets:

| Source | Count |
|---|---|
| Endpoint agent reporting | 131 |
| DHCP leases active in the last 30 days | 138 |
| Assets in the register | 129 |

The reconciliation produces:

| Disposition | Count | Example row | Action |
|---|---|---|---|
| MATCHED | 126 | `ACME-WS-034`, agent reporting, owner recorded | None |
| UNMANAGED | 5 | `ACME-WS-088`, agent absent since reimage | Reinstall agent within 7 days |
| UNKNOWN | 7 | MAC `00:1B:44:...` (printer VLAN), hostname `HP-LASER-2` | Register or remove from network |
| MISSING | 3 | `ACME-SRV-OLD01`, no lease, no agent | Confirm decommission, delete row |
| OWNERSHIP GAP | 2 | Shared `Kiosk-01` with no named owner | Assign to Facilities IT lead |

Read the shape, not just the totals: **17 of 138 devices (12%) were outside the managed inventory on the first pass**. That number, not the raw count, is the finding to report upward — and it is a risk register entry (see [02-risk-management](02-risk-management.md)), because every unmanaged host is a host with unknown patch state and unknown configuration.

> First-cycle numbers are always ugly. Publish them anyway: a baseline of 12% unmanaged that falls to 3% over two quarters is a story the board can act on, while "we think we are fine" is not.

## Software Inventory and Unauthorized Software

CIS Control 2 splits into knowing what is installed, and controlling what is allowed to be installed. These are different jobs.

### Knowing what is installed

| Platform | Practical approach | Caveat |
|---|---|---|
| Windows | Registry uninstall keys (both `Uninstall` and `WOW6432Node\Uninstall`), plus an agent that also sees per-user installs | Misses portable executables, browser extensions, and in-app plugins |
| Linux | Package database (`rpm`/`dpkg` families) via an agent or `osquery` | Misses anything compiled into `/usr/local`, tarball installs, containers |
| macOS | Application bundles plus a management agent | Misses user-installed apps outside `/Applications` |
| SaaS | Identity provider's app assignments and SSO logs | Misses apps bought on a corporate card with no SSO |

The registry-uninstall method is worth practising because it needs no agent and no elevation. Real output from a Windows workstation in this repository's authoring environment:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName } |
  Select-Object -First 8 DisplayName, DisplayVersion, Publisher
```

```text
DisplayName                 DisplayVersion Publisher
-----------                 -------------- ---------
7-Zip 26.02 (x64)           26.02          Igor Pavlov
Audacity 3.7.8              3.7.8          Audacity Team
CutePDF Writer              4.0            Acro Software Inc.
Docker Desktop              4.81.0         Docker Inc.
Everything 1.4.1.1032 (x64) 1.4.1.1032     voidtools
foobar2000 v2.25.10 (x64)   2.25.10        Peter Pawlowski
GIMP 3.2.4                  3.2.4.0        The GIMP Team
Git                         2.55.0.2       The Git Development Community
```

Counting the same query returned **65** rows on that workstation. Compare that number against your authorized list and you have your first software-control finding; note that "too many rows" is not a finding by itself — *unlisted* titles are.

### Authorized software list (allowlist) design

A list that says "authorized: yes/no" per title will collapse under real use. Three fields make it survivable:

```text
Title            | Disposition | Scope            | Version band | Owner       | Review
7-Zip            | Authorized  | All endpoints    | >= 24.x      | IT Ops      | 2026-04-01
Docker Desktop   | Tolerated   | Engineering only | Current      | Eng. lead   | 2026-04-01
foobar2000       | Prohibited  | All endpoints    | any          | CISO        | 2026-04-01
```

- **Authorized** — permitted everywhere in scope, supported by IT.
- **Tolerated** — permitted only in a named scope, often with a compensating condition (encrypted host, no company data).
- **Prohibited** — must be removed; if removal is impossible, it becomes a documented risk exception (see [02-risk-management](02-risk-management.md)).

Software that inventories consistently miss, and which therefore needs its own check rather than a package count:

- Portable and standalone executables — a binary copied into `%USERPROFILE%\Downloads` or `/usr/local/bin` that no installer ever registered, so neither the uninstall keys nor the package database can see it. (The `Everything` row in the list above is *not* that class: it appears precisely because it has an uninstall key. A title in that output is installed by definition; the ones this bullet is about never show up at all.)
- Browser extensions and IDE plugins.
- Container images and their layers.
- Code pulled at runtime by scripts (`pip install`, `npm install`, `curl | bash`).
- SaaS reachable through a browser with a personal account.

> Detect unauthorized software by **diffing**, not by reading: run the inventory on a schedule, compare each host's set against the previous run and against the allowlist, and alert on additions. A static review of 65 installed titles finds nothing; a diff of 65-vs-67 finds the two that arrived yesterday.

## Asset Criticality Tiers

Risk, patch, and backup decisions all need to know *which assets matter*. Keep it to three or four tiers with written definitions, and let the tier drive the controls.

| Tier | Definition (example) | Example assets | Consequence of compromise |
|---|---|---|---|
| **T1 — Critical** | Loss stops the business or breaches a legal duty within hours | Domain controllers, ERP, payment path, customer database, backups | Business interruption, regulatory notification |
| **T2 — Important** | Degrades a business function; workaround exists | File shares, internal apps, build servers, VPN concentrators | Productivity loss, secondary exposure |
| **T3 — Standard** | Recoverable from image or by a user | Standard workstations, printers, test servers | Local disruption only |

Decision table — how the tier changes what you do:

| Decision | T1 | T2 | T3 |
|---|---|---|---|
| Patch window for critical severity | 48 h when actively exploited (emergency change allowed), otherwise 7 days — same figures as the SLA table in [07](07-vulnerability-and-patch-management.md) | 14 days | 30 days |
| Configuration scan frequency | Daily | Weekly | Monthly |
| Backup verification | Restore test quarterly | Restore test semi-annually | Annual sample |
| Change approval | CAB + security review | Standard change process | Standard change process |
| Privileged access | Just-in-time elevation, session recorded | Named admin accounts | Admin group membership |

If a tier assignment cannot be defended in one sentence ("it is T1 because payment authorisation flows through it"), it is a preference, not a tier.

## Configuration Management: Baselines, Drift, and Deviation

Configuration management is inventory of a second kind: not "what assets exist" but "what state each asset is supposed to be in, and is it".

### The four moving parts

```text
BASELINE      The documented, approved secure state for a class of asset
              (e.g. "Windows 11 workstation, CIS Level 1, plus these deviations").
ENFORCEMENT   The mechanism that puts assets into that state and keeps them there
              (golden image, GPO/Intune policy, Ansible role, cloud image pipeline).
VERIFICATION  The mechanism that proves current state == baseline
              (OpenSCAP, Lynis, CIS-CAT-style assessors, benchmark policy engines).
DEVIATION     Every intentional difference, with a reason, an owner and an expiry date.
```

The order matters: **enforce before you verify**. Scanning first produces a backlog of findings that nobody can fix at scale, and the program dies of its own report volume.

### Configuration items worth tracking

Not every setting needs to be managed. Track configuration items that change risk:

| Configuration item | Why it matters | Verified by |
|---|---|---|
| Installed software set and versions | Every CVE you must patch lives here | Agent inventory, `osquery`, registry |
| Listening services and open ports | Attack surface; unexpected listeners are a lead | `osquery listening_ports`, port scan, `netstat`-class tooling |
| Local administrator membership | Privilege escalation and lateral movement | `osquery users`/`groups`, `Get-LocalGroupMember` |
| Authentication settings (SSH, RDP, SMB, legacy protocols) | Primary intrusion path | Benchmark scan, registry, config file review |
| Firewall/host-based filtering state | The control that contains a compromise | Benchmark scan, cloud security-group export |
| Audit policy and log shipping | Whether you will see the next incident at all | `auditpol`-class tooling, agent health |
| Encryption state (disk, transport) | Regulatory and breach-cost impact | Endpoint management report, benchmark scan |
| Backup configuration and last successful run | Whether recovery is real | Backup console report |

### Drift: the finding that comes back

Drift is any change away from the baseline that nobody approved. It arrives through reimaging with an old template, a vendor installer relaxing a setting, a helpdesk fix applied by hand under pressure, or a cloud resource created outside the pipeline.

Detection patterns that work:

- **State diff over time** — store last run's state per host and compare (same technique as the software diff above).
- **Continuous policy evaluation** — a management platform that reports "compliant/non-compliant" per setting per host every day. This is what "continuous compliance monitoring" means in practice (see [03-compliance-basics](03-compliance-basics.md)).
- **Baseline-as-code in review** — the baseline file lives in version control, so a change to the baseline is a pull request with a reviewer, not a quiet setting change on a Tuesday.

> Drift is not a configuration problem; it is an ownership problem. Every drift finding should end with either "enforcement fixed" or "deviation approved", never with "closed after manual fix" — manual fixes are what drift eats for breakfast.

## Evidence: What the Auditor Asks For

Inventory and configuration work produces the artifacts that show up in almost every audit interview:

| Claim | Evidence to keep |
|---|---|
| "We know our assets" | Dated reconciliation export with dispositions and resolution tickets |
| "We know what software is installed" | Scheduled inventory report plus the allowlist with owners and review dates |
| "Unauthorized software is removed" | Diff report showing detection, ticket, and removal timestamp |
| "Systems are hardened to a baseline" | Baseline document (with version), plus scan report showing per-rule results |
| "Deviations are approved" | Deviation register: item, reason, risk accepted by whom, expiry date |
| "Baseline changes are controlled" | Version-control history of the baseline file with approvals |

## Metrics

| Metric | Formula | Target shape |
|---|---|---|
| Inventory coverage | managed assets ÷ discovered assets | Rising, >95% for T1/T2 |
| Inventory accuracy | (MATCHED + correctly dispositioned) ÷ total rows | Rising; the point is the disposition rate, not the raw match |
| Unknown devices open | Count of UNKNOWN rows older than 7 days | Falling to zero, each with a ticket |
| Software allowlist compliance | hosts whose installed set ⊆ allowed set ÷ hosts reporting | Rising |
| Baseline compliance | assets meeting all applied rules ÷ assets in scope | Rising; report per rule-class too |
| Mean time to remediate drift | detection timestamp → enforcement restored | Stable and shorter than the scan interval |
| Deviations past expiry | count of deviation records past their expiry date | Zero |

Report inventory metrics with the *disposition breakdown*, not a single percentage. "97% managed" hides the 3%, and the 3% is where incidents start.

## Common Mistakes & Tips

- **Building the inventory as a project instead of a process.** A one-time discovery produces a document that is wrong within a quarter. The deliverable is the monthly cycle and its tickets.
- **Treating the CMDB as the security inventory.** A CMDB models services and dependencies for change management; it is not a complete or timely picture of what is on the network. Reconcile a discovered set against it.
- **Scanning before enforcing.** A benchmark scan against an unmanaged estate generates thousands of findings, none of which can be fixed at scale. Enforce with an image or policy first, then measure what is left.
- **Allowlists with no owner and no review date.** They grow by exception until "authorized" means "installed". Give each entry an owner and a review date, and expire entries that miss review.
- **Counting what is managed instead of what exists.** The number that matters is the unknown set. Instrument that count, trend it, and ticket every row.
- **Ignoring portable software and SaaS.** Package counts are a lower bound. Add the exe-hash/name check and the identity-provider app list, or your software control is decorative.
- **Deviations without expiry dates.** An approved deviation with no expiry is a permanent hole with paperwork attached. Every deviation needs a review date and a named acceptor.
- **Fix-by-hand drift closure.** If the setting is not enforced, it will drift again next month. Fix the enforcement, then the asset.
- **Assuming agents tell the truth.** An agent that has stopped reporting is indistinguishable from a host that is switched off. Alert on *silence*, per asset, with an expected-heartbeat threshold.

## Checklist / Self-Test

- [ ] I can explain why CIS Controls v8 puts asset and software inventory at controls 1 and 2, with two downstream controls that depend on them.
- [ ] I can list at least five discovery sources and name the blind spot of each.
- [ ] I can run a reconciliation and assign all five dispositions to its rows.
- [ ] I can build a software inventory without an agent, and state what that method misses.
- [ ] I can design an allowlist with Authorized/Tolerated/Prohibited dispositions, scopes, owners, and review dates.
- [ ] I can define three asset tiers and show how the tier changes patch, scan, and backup requirements.
- [ ] I can explain the baseline → enforcement → verification → deviation cycle and why enforcement precedes verification.
- [ ] I can propose a drift-detection mechanism for one configuration item and describe its alert.
- [ ] I can name the evidence an auditor wants for "we know our assets" and "we are hardened to a baseline".
- [ ] I can define inventory coverage, allowlist compliance, and mean time to remediate drift, and say how each could be gamed.

> **Verification:** executed against PowerShell 7.6.6 on 2026-09-19: `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'` returned **45** registered titles — the uninstall-key source this phase calls the primary Windows inventory — and `Get-Volume`, `Get-LocalUser` and `Get-NetFirewallProfile` returned data for the configuration items listed here. The `Everything` row quoted above is a registered install, as its own uninstall key shows.

## Further Resources

- CIS Critical Security Controls v8 — control 1 (Inventory and Control of Enterprise Assets) and control 2 (Inventory and Control of Software Assets): https://www.cisecurity.org/controls
- CIS Benchmarks — the configuration baselines that configuration management enforces: https://www.cisecurity.org/cis-benchmarks
- NIST SP 800-53 Rev. 5 — CM (Configuration Management) and PM/RA families for inventory and baseline requirements: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST CSF 2.0 — ID.AM (asset management) outcomes: https://www.nist.gov/cyberframework
- ISO/IEC 27001:2022 — Annex A 5.9 (inventory of information and other associated assets) and A.8.9 (configuration management): https://www.iso.org/standard/27001
- osquery documentation — fleet-wide inventory queries: https://osquery.readthedocs.io/
