# Inventory and Unauthorized Software — Hands-On Lab

> eEDA · Labs — INE-Cybersecurity-Certifications-Guide

## Purpose

[05-asset-inventory-and-configuration](../methodology/05-asset-inventory-and-configuration.md) argues that every control you will ever claim rests on an inventory, and [Endpoint Inventory and Query](../tools/endpoint-inventory-and-query.md) supplies the tooling. This lab is the practice: you build a real inventory of one Windows host and one Linux host, publish an **authorized software list** with named owners, take two snapshots, and turn the difference between them into findings someone can act on.

The distinction the lab is built to teach: **detection is a diff, not a reading.** One snapshot tells you what is installed. Two snapshots tell you what arrived, when, and whether anyone approved it. And "installed" is not "authorized" — only an allowlist with owners and review dates authorizes anything.

**Prerequisite reading:** the tool guide's sections 3–5 (Windows and Linux inventory without an agent, and the six-step diff workflow). This lab applies that workflow; it does not restate it.

## Lab Environment

- **A Windows host** — the workstation you are on is fine. The registry-based and native-cmdlet checks work without WMI/CIM; the tool guide documents that CIM-backed cmdlets failed in this module's authoring environment, so treat them as optional.
- **A Linux VM** (Ubuntu 22.04/24.04, Debian 12, or RHEL 9 family) with root access, from [security-policy-exercises](security-policy-exercises.md).
- **osquery** on at least one host, if you can install it from the official packages at osquery.io. It is **not** installed in this module's authoring environment, so every osquery command below is a syntax reference: confirm tables and columns with `.schema` on the build you actually deploy.
- One file of scratch space per host for snapshots, plus a folder for the deliverable: `~/eeda-inventory/`.

## Exercise 1 — Define Scope Before You Collect

An inventory without a scope becomes a data lake nobody queries. Write, in half a page:

1. **The asset classes you are inventorying.** For this lab: one Windows workstation and one Linux server. In a real estate, classes (not hosts) are what the allowlist is built against — a build server and a reception PC do not get the same authorized list.
2. **What a row in your inventory means.** Host, asset class, owner, OS version, and the collection source. Decide now whether an entry is a *package*, a *title*, or a *binary*: three inventories that people confuse, and mixing them is why counts never reconcile.
3. **The freshness target.** How often the snapshot is taken, and who reads the diff. "Weekly, into the platform team's queue" is a program; "when someone remembers" is not.

**Expected result:** a scope statement with an asset class, an owner per class, a collection source, and a cadence.

## Exercise 2 — Snapshot #1: Collect

Collect from both hosts. Every query below is a syntax reference — adapt it after checking the schema, and save the raw output before you normalise anything.

```sql
-- osquery (Linux or Windows build). Discover the schema first: names move between versions.
.tables
.schema deb_packages
.schema programs

-- Installed software by platform family
SELECT name, version FROM deb_packages;                      -- Debian/Ubuntu
SELECT name, version FROM rpm_packages;                      -- RHEL family
SELECT name, version, publisher FROM programs;               -- Windows

-- Services, listeners and autostart: what runs without a human
SELECT name, display_name, status, start_type, path FROM services;
SELECT * FROM listening_ports;
SELECT name, path, args, type, source, status FROM startup_items;
SELECT name, action, path, enabled, hidden, last_run_time FROM scheduled_tasks;

-- Accounts, and accounts that can actually log in
SELECT uid, username, shell FROM users WHERE shell NOT IN ('/usr/sbin/nologin','/bin/false');
SELECT name, enabled, last_logon FROM users;
```

```bash
# Linux, no agent: package database plus the file system view
dpkg-query -W -f='${Package}\t${Version}\n' | sort      # Debian/Ubuntu
rpm -qa | sort                                          # RHEL family
ss -lntup                                               # listening sockets
systemctl list-unit-files --type=service                # enablement state
```

```powershell
# Windows, no agent: the uninstall keys are the primary source
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName } |
  Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName

# Local accounts, with the field that turns a list into a finding
Get-LocalUser | Select-Object Name, Enabled, LastLogon

# Autostart entries -- which of these is NOT in the software list you just collected?
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' |
  Select-Object -Property * -ExcludeProperty PS*
```

Save the raw output as `snapshot-1-<host>-<yyyy-mm-dd>.txt` (or `.json` for the osquery `--json` form). **Do not edit the raw files** — normalisation happens in a separate step, so you can always go back to what the host actually said.

**Expected result:** two raw snapshot files, unedited, one per host.

## Exercise 3 — Build the Authorized Software List

The allowlist is the control; the snapshot is just measurement. Build it for your Windows workstation's asset class, with at least 10 entries. Schema:

```markdown
| Title | Version band allowed | Publisher | Justification | Business owner | Review date |
|---|---|---|---|---|---|
| 7-Zip | 24.x – 26.x | Igor Pavlov | Archive handling for support tickets | IT Operations (M. Vidal) | 2027-03-31 |
| Docker Desktop | 4.x | Docker Inc. | Container development for the platform team | Platform Engineering (A. Sanz) | 2027-01-31 |
```

Rules that make the list enforceable:

- **A named business owner per entry**, with a review date. An entry owned by "IT" is owned by nobody.
- **A version band, not a single version** — otherwise every upstream release is a finding, and the diffs become noise you learn to ignore.
- **Publisher and title as identifiers.** Never match on a localized display name: the tool guide's real output shows a service named "Servicio de implementación de AppX", and account names render as `Administrador` on a Spanish-locale Windows.
- **A justification a reviewer can argue with.** "Needed" is not a justification; "archive handling for support tickets" is.

Then classify every row of your snapshot against the list — including the ones you expect to be fine, because the interesting rows are the ones you assumed:

| Disposition | Meaning | Action |
|---|---|---|
| NEW-AND-AUTHORIZED | Allowlist entry exists | Record it; no ticket |
| NEW-AND-UNKNOWN | No allowlist entry | Ticket to the asset owner — this is the finding |
| VERSION-OUT-OF-BAND | Allowed title, version outside its band | Ticket to the platform team |
| REMOVED | Was present, now gone | Check whether removal was intended and recorded |

**Expected result:** an allowlist of 10+ rows with owners and review dates, plus your first classified pass over snapshot #1.

## Exercise 4 — Introduce a Change, Diff, and Classify

Detection needs two points in time. Create the second one deliberately, so you know the answer before the diff tells you:

1. **Add one authorized thing** — install a tool that is already on your allowlist (or add a row for it first, then install it).
2. **Add one unauthorized thing** — install something small that is *not* on the list. A portable utility is ideal, because it will demonstrate the blind spot in Exercise 5 as well. Note where you put it.
3. **Change one version** — update an installed application so its version leaves the band you wrote.
4. **Take snapshot #2** and diff it against snapshot #1 after normalising (lowercase titles, strip trailing version noise, keep publisher and path).

```bash
# A diff you can defend: normalise, sort, compare -- one line per change
sort snapshot-1-host.txt > s1.sorted
sort snapshot-2-host.txt > s2.sorted
diff s1.sorted s2.sorted        # added lines: <, removed lines: >, depending on order
```

Output template for the findings table (**template, not captured output** — fill it from your own diff):

```markdown
| Host | Change | Title | Version | Publisher | Disposition | Ticket |
|---|---|---|---|---|---|---|
|  | NEW |  |  |  | NEW-AND-UNKNOWN |  |
|  | NEW |  |  |  | NEW-AND-AUTHORIZED |  |
|  | OUT-OF-BAND |  |  |  | VERSION-OUT-OF-BAND |  |
|  | REMOVED |  |  |  | REMOVED |  |
```

Then answer, in writing: **which of the four changes did a package-based diff miss, and why?** If your portable utility never appeared, you have just reproduced the blind spot — the diff compares what the package managers and uninstall keys know about, and a copied executable registers in neither.

**Expected result:** a diff with four classified changes, and one paragraph naming the change the diff could not see.

## Exercise 5 — Cover the Three Blind Classes

A package-based inventory cannot see three classes of software, no matter how often it runs. Add one concrete check for each, on your own host:

| Class | Why the diff misses it | Your check |
|---|---|---|
| Portable / standalone executables | Never installed; no uninstall key, no package manager entry | A scheduled scan of user-writable paths for executables not in a permitted-tools list — decide the paths (`%USERPROFILE%\Downloads`, `%TEMP%`, `/opt`, `/usr/local/bin`) and how you would spot a new one |
| Browser extensions and IDE plugins | They live inside another application's profile | The browser's managed extension inventory, or the management platform's extension policy |
| Container images and CI tooling | Pulled at runtime, outside the package database | The registry your pipeline pulls from, plus image scanning in the pipeline — the host inventory will never show them |

Record what each check can and cannot prove. A file-name scan proves *presence*, not *execution*.

**Expected result:** three checks written down with the path, the source, and the limit of each.

## Exercise 6 — Detect Configuration Drift, Not Just Software

New software is one axis of change; a changed *setting* is the other, and it is the one that quietly re-opens a control you closed. The method note calls the difference between the baseline, the drift, and the deviation — practise it:

1. **Pick two settings** that a hardening baseline would also cover: for example `PermitRootLogin` in `/etc/ssh/sshd_config` on the Linux VM, and a `Run` key value or a service `Start` type on Windows.
2. **Record the approved value** as your baseline, with the date and the source of the requirement (the baseline document, not your memory).
3. **Change one of them**, then detect the change: on Linux the file's content changes (`sha256sum /etc/ssh/sshd_config` before and after); on Windows query the value again and compare.
4. **Classify the change**: authorized change (there is a change record), drift (nobody knows), or deviation (deliberate and documented, with a reason). Only the middle one is a finding.
5. **Write the reconciliation**: who owns the setting, how often it is checked, and what happens when it differs.

```bash
# Baseline and re-check: a hash is the cheapest drift detector for a config file
sha256sum /etc/ssh/sshd_config
grep -E '^PermitRootLogin' /etc/ssh/sshd_config
```

```powershell
# The Windows equivalent: read the value, record it, read it again later
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\<name>' |
  Select-Object PSChildName, Start, Type, ImagePath
```

**Expected result:** a baseline record for two settings, one deliberately introduced drift you detected, and a classification with a reason.

## Exercise 7 — Write the Finding

A good finding survives being read by someone who was not there. Write one for your unauthorized-software row and one for your drift row:

- **What** — the host, the title/setting, the version or value, and the date it appeared.
- **Evidence** — the snapshot diff or the two hashes, with file names and dates. Not "we saw it".
- **Why it matters** — in one sentence of risk language: what could this software or setting do that the allowed one could not?
- **What you want** — a decision, not a notification: authorize it (and add a row with an owner and review date), remove it, or accept the risk via [risk-exception-writeup](risk-exception-writeup.md).
- **By when** — a date tied to your SLA, not "as soon as possible".

**Expected result:** two findings that name an owner and a decision, each traceable to a saved snapshot.

## Common Mistakes & Tips

- **Treating one snapshot as an inventory program.** Coverage and drift are both questions about change over time. Schedule the collection and keep the snapshots.
- **Reading an empty result as "clean".** No rows usually means the wrong table, the wrong question, or an agent that is not reporting. Prove the pipeline with a known-present item first — the tool you installed in Exercise 4 is that item.
- **Guessing table and column names.** osquery schemas move between versions; a query copied from a guide can silently return nothing. `.schema` costs five seconds.
- **Normalising before you save.** Keep the raw output untouched, then normalise a copy. Otherwise you cannot prove what the host actually reported.
- **Matching on localized display names.** Locale-dependent strings break scripts and produce false "new software" rows after a language change. Match on `Name`, SIDs, paths, and publishers.
- **Letting the installer maintain the allowlist.** "Installed" is not "authorized". Only a list with named owners and review dates authorizes, and it has to be reviewed to stay true.
- **Reporting counts instead of dispositions.** "65 titles installed" is not a finding. "Two titles not on the allowlist, tickets raised, owners named" is.
- **Forgetting drivers and services.** A registry service view sees kernel drivers that a service-only view omits; new drivers are as much a change as new applications.
- **Tip**: build the diff before you need it. The first run establishes the baseline, every later run produces findings, and when an incident asks "when did this appear?" you already have the answer — with dates.

## Checklist / Self-Test

- [ ] I wrote a scope statement naming asset classes, owners, collection sources, and a cadence.
- [ ] I collected a raw, unedited snapshot from a Windows host and a Linux host.
- [ ] I built an authorized software list with 10+ rows, each with a version band, an owner, and a review date.
- [ ] I classified every snapshot #1 row into one of the four dispositions.
- [ ] I introduced a known change, took snapshot #2, and produced a diff with four classified changes.
- [ ] I identified the change my diff could not see, and explained why.
- [ ] I wrote one check for each of the three blind classes: portable executables, extensions, container images.
- [ ] I baselined two settings, detected one drift, and classified it as authorized change, drift, or deviation.
- [ ] I wrote one unauthorized-software finding and one drift finding, each with evidence, an owner, and a date.
- [ ] I can explain why "the inventory is clean" and "the query returned nothing" are not the same statement.

## Further Resources

- [osquery documentation](https://osquery.readthedocs.io/) — table reference, deployment, and scheduled queries.
- [CIS Controls](https://www.cisecurity.org/controls) — control 1 (Inventory and Control of Enterprise Assets), control 2 (Inventory and Control of Software Assets), and control 4 (Secure Configuration).
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) — CM-8 (System Component Inventory), CM-6 (Configuration Settings), CM-10/CM-11 (software usage and installation restrictions).
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001) — Annex A 5.9 (inventory of information and other associated assets) and 8.9 (configuration management).
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) — the configuration baselines that turn a setting into a pass or fail.

---

> ⚠️ Personal study notes. osquery is not installed in the environment where this module was written, and no Linux host was available, so the osquery and Linux commands above are syntax references rather than captured runs: confirm tables, columns, and flags on your own build. The Windows registry and `Get-LocalUser` forms follow the executed examples in [Endpoint Inventory and Query](../tools/endpoint-inventory-and-query.md). No NDA-protected or actual exam content is included.
