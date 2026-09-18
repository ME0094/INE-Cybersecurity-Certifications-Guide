# Endpoint Inventory and Query

> eEDA · Tools — INE-Cybersecurity-Certifications-Guide
>
> The tools that answer "what is true on this host right now, and on every host?" — osquery for fleet-wide SQL over operating-system state, and the native inventory commands that work on Windows and Linux without an agent. Read this with [../methodology/05-asset-inventory-and-configuration](../methodology/05-asset-inventory-and-configuration.md) (controls 1 and 2 in practice) and the lab [../labs/inventory-and-unauthorized-software](../labs/inventory-and-unauthorized-software.md).

## 1. State Questions Versus Behaviour Questions

Inventory tooling answers **state**: what exists, what is installed, what is listening, who is a member. It does not answer **behaviour**: what ran, in what order, spawned by what. Confusing the two produces two opposite failures — asking osquery about yesterday's process execution, or asking an event log what is installed today.

| Question | Class | Right source |
|---|---|---|
| Which hosts have package version X? | State | osquery, agent inventory, configuration management |
| Which ports are listening on this host? | State | osquery, native network listing, benchmark scan |
| Who is a local administrator on this host? | State | osquery, `Get-LocalGroupMember`, `getent group` |
| What is installed that is not on the allowlist? | State (diff over time) | Inventory snapshots, compared on a schedule |
| Which process wrote that registry value? | Behaviour | Sysmon/Event Log, `auditd` — see [../tools/system-auditing-and-log-integrity](system-auditing-and-log-integrity.md) |
| What executed in the last hour? | Behaviour | Process creation telemetry, not inventory |

> Rule of thumb: if the answer changes when nothing is running, it is inventory. If it only changes while something is happening, it is telemetry.

## 2. osquery

**What it is.** SQL over the operating system. osquery exposes OS state as virtual tables, so "which hosts have an unauthorized package?" becomes a query rather than a script per platform. `osqueryi` is the interactive/ad-hoc shell; `osqueryd` is the daemon that runs scheduled queries and (with an event publisher) evented tables.

**What it produces.** Query result sets, plus the daemon's scheduled-query results and evented-table records, which are typically shipped to a SIEM or a fleet manager.

**How to use it.**

```sql
-- Interactive shell: discover the schema instead of guessing column names.
-- Run this FIRST on your build; table and column names differ between versions.
.tables
.schema scheduled_tasks
.schema process_open_sockets

-- Installed packages, by platform family
SELECT name, version FROM deb_packages WHERE name = 'openssh-server';   -- Debian/Ubuntu
SELECT name, version FROM rpm_packages WHERE name = 'openssh-server';   -- RHEL/Fedora

-- Accounts with an interactive shell (candidates for review -- see ../methodology/06-identity-and-privileged-access.md)
SELECT uid, username, shell FROM users
WHERE shell NOT IN ('/usr/sbin/nologin','/bin/false');

-- Listening services: unexpected listeners are the classic inventory lead
SELECT * FROM listening_ports;

-- Network state attributed to a process
SELECT pid, family, protocol, local_address, local_port, remote_address, remote_port, path
FROM process_open_sockets WHERE remote_address != '';

-- Linux persistence and scheduled work
SELECT * FROM crontab;
SELECT * FROM systemd_units WHERE active_state = 'active';

-- Windows persistence, services and autostart entries
SELECT name, action, path, enabled, hidden, last_run_time FROM scheduled_tasks;
SELECT name, path, args, type, source, status FROM startup_items;
SELECT name, display_name, status, start_type, path FROM services;
```

```bash
# Non-interactive, machine-readable -- the form a fleet query takes
osqueryi --json "SELECT name, version FROM os_version;"

# Daemon with scheduled queries from the configuration file
osqueryd --config_path=/etc/osquery/osquery.conf --verbose
```

> Syntax reference, not executed here: osquery is not installed on the Windows workstation where this module was written, and these examples follow the documented syntax of the tables shown. Confirm every table and column with `.schema <table>` in the version you deploy — see the limitations below.

**A query library worth building.** Keep your queries in version control alongside the configuration; each row answers a recurring control question.

| Control question | Query shape (adapt after `.schema`) |
|---|---|
| Is the counting complete? | Compare `SELECT COUNT(*) FROM deb_packages` (or `rpm_packages`) against the agent's software count — a mismatch means one of the two is wrong |
| Are there unauthorized listeners? | `listening_ports` joined to `processes` on `pid`, filtered to ports outside the approved list |
| Who can log in locally? | `users` with a real shell, plus group membership tables |
| What starts automatically? | `startup_items`, `scheduled_tasks`, `services`, `crontab`, `systemd_units` |
| Has a package changed version since last week? | Diff two scheduled snapshots of the package table |
| Is disk encryption in place? | Platform-specific tables; verify the column set with `.schema` before relying on it |

**Limitations.**

- **Snapshot versus history.** Most tables describe *now*. If you did not ask while the process was running, the answer is gone. Only evented tables (`process_events`, `socket_events`, `file_events`) give history, and they need an event publisher plus the daemon — check availability with `.tables` on your build.
- **Schema drift between versions.** Table and column names change across releases, and a query copied from a blog post may simply fail. `.schema` is the authority.
- **Performance.** Unscoped `LIKE` queries over `file` or `hash` tables can hammer a host. Scope by path, and test on one host before querying a fleet.
- **Lower behavioural fidelity on Windows than Sysmon.** osquery is excellent for "what exists", weaker for "what happened in what order".
- **Agent coverage is the real limit.** A fleet query answers only about hosts that are running the agent and reporting. The hosts that are not reporting are the ones you should worry about (see [../methodology/05-asset-inventory-and-configuration](../methodology/05-asset-inventory-and-configuration.md)).
- **Results are only as structured as your questions.** "Export everything" produces a data lake nobody queries; scheduled queries that map to a control produce evidence.

**Fleet shape (concepts).** Run `osqueryd` on endpoints with a configuration that defines scheduled queries and a file-integrity monitoring policy; ship results to a central store (a fleet manager such as Fleet, or directly to the SIEM — for example a Wazuh deployment, https://documentation.wazuh.com/). The value is not the query: it is the **schedule**, the **comparison**, and the **alert when a result appears that should not exist**.

## 3. Windows: Inventory Without an Agent

Useful when an agent is missing, when you are validating what the agent reports, or when WMI/CIM is unavailable. All of the commands below were executed on a Windows workstation for this module; output is reproduced verbatim.

### Installed software

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName } |
  Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName
```

```text
(count and sample of a real run)
65 titles, first eight alphabetically:
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

What this method answers and what it misses:

| Answers | Misses |
|---|---|
| Machine-wide installed applications with version and publisher | Portable executables that were never installed (visible in the output above: `Everything`, a standalone tool) |
| Both 64-bit and 32-bit installs, if both keys are queried | Per-user installs under `HKCU` — the same query limited to `HKLM` is blind to them |
| Good enough for an allowlist comparison and a change diff | Browser extensions, IDE plugins, container images, anything installed by a script into a user profile |

Query `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` as well if you are inventorying a single machine by hand; for a fleet, read both hives per user profile via an agent rather than by hand.

### Services (without WMI)

`Get-Service` works without CIM, and the registry gives a second, independent view that includes drivers:

```powershell
# Running automatic services — review against the approved service manifest
Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -eq 'Running' } |
  Select-Object -First 5 Name, DisplayName, StartType, Status
```

```text
Name                 DisplayName                                            StartType Status
----                 -----------                                            --------- ---------
AppXSvc              Servicio de implementación de AppX (AppXSVC)           Automatic Running
AudioEndpointBuilder Compilador de extremo de audio de Windows              Automatic Running
Audiosrv             Audio de Windows                                       Automatic Running
BFE                  Motor de filtrado de base                              Automatic Running
BrokerInfrastructure Servicio de infraestructura de tareas en segundo plano Automatic Running
```

```powershell
# Registry view: Start 2 = automatic, 3 = manual, 4 = disabled; Type 1/2 = kernel driver,
# 16 = own-process service, 32 = shared-process service. ImagePath shows the real binary.
$svc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\*' -ErrorAction SilentlyContinue
"service keys readable: " + ($svc | Measure-Object).Count
$svc | Where-Object { $_.Start -eq 2 } | Select-Object -First 5 PSChildName, Start, Type, ImagePath
```

```text
service keys readable: 778

PSChildName          Start Type ImagePath
-----------          ----- ---- ---------
AppXSvc                  2   32 C:\WINDOWS\system32\svchost.exe -k wsappx -p
AudioEndpointBuilder     2   32 C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p
Audiosrv                 2   16 C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p
BFE                      2   32 C:\WINDOWS\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p
bfs                      2    2 \SystemRoot\system32\drivers\bfs.sys
```

Two uses for this view: it sees **drivers** (`Type 2`, like `bfs` above) that a service-only view omits, and it works when `Get-CimInstance`/`Get-Service` do not. Note the localized `DisplayName` values ("Servicio de implementación de AppX") — never match on display names in a script; match on `Name`, `Start`, or `ImagePath`.

### Autostart entries and local accounts

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' |
  Select-Object -Property * -ExcludeProperty PS*
```

```text
SecurityHealth : C:\WINDOWS\system32\SecurityHealthSystray.exe
Everything     : "C:\Program Files\Everything\Everything.exe" -startup
Greenshot      : "C:\Program Files\Greenshot\Greenshot.exe"
```

That single real result contains the whole lesson about autostart inventory: one security component, and two third-party utilities, of which one is also present in the installed-software list above. Autostart entries whose binary is *not* in the installed-software inventory are the ones worth a second look.

```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon
```

```text
Name                Enabled LastLogon
----                ------- ---------
Administrador         False
DefaultAccount        False
Invitado              False
<USER>                 True 18/09/2026 9:03:06
<USER>                 True 10/07/2026 17:17:21
<USER>                 True
WDAGUtilityAccount    False
```

(Rows are shown with account names redacted; the built-in accounts keep their localized names, and note that the local Administrator account here is named `Administrador`.) What this answers: enabled accounts, and **last logon** — the field that turns an account list into a lifecycle finding ("enabled, and no logon in 400 days").

### What did not work here, and why it matters

Every CIM-backed cmdlet failed on this workstation, with the same localized message:

```text
Get-CimInstance, Get-Volume, Get-NetFirewallProfile, Get-NetTCPConnection,
Get-ScheduledTask, Get-SmbShare, Get-Disk, Get-HotFix
  -> El cliente no tenía acceso disponible a un recurso CIM.
     (the CIM client could not access a resource)
```

So patch state (`Get-HotFix`), listening ports (`Get-NetTCPConnection`), firewall profile state (`Get-NetFirewallProfile`) and scheduled tasks (`Get-ScheduledTask`) were **not verifiable in this environment**, and no output for them is shown in this module. The practical lesson is worth more than the commands: build inventory scripts on sources that survive a restricted or degraded session — the registry, the uninstall keys, `wevtutil`, and file-based configuration — and treat the CIM-based commands as convenient when available rather than as the only path. Reading the Security event log content, separately, requires elevation: `Get-WinEvent -LogName Security` fails with `Attempted to perform an unauthorized operation.` on a non-elevated session.

## 4. Linux: Inventory Without an Agent

```bash
# Installed packages (syntax reference; both families shown)
rpm -qa | sort                                  # RHEL family
dpkg-query -W -f='${Package}\t${Version}\n'     # Debian/Ubuntu family

# Services and their enablement state
systemctl list-unit-files --type=service

# Listening sockets and the owning process
ss -lntup

# Local accounts with a real shell, and group membership
getent passwd | awk -F: '$7 !~ /(nologin|false)$/ {print $1, $7}'
getent group sudo
getent group wheel
```

> Syntax reference only — no Linux host was available in this environment, so these were not executed. Flags differ between distributions and versions: confirm with the manual page (`man ss`, `man systemctl`) before you rely on them, and note that `ss -p` needs root to attribute sockets to processes.

The Linux equivalent of the Windows registry-inventory insight is the **package database plus the file system**: the package manager tells you what was installed through it, and a file-system inventory (or an agent-based EDR) tells you what appeared outside it — compiled binaries in `/usr/local/bin`, scripts in `/opt`, and anything extracted from an archive.

## 5. Detecting Unauthorized Software

Detection is a **diff**, not a reading. One inventory snapshot tells you what is installed; two snapshots tell you what arrived.

```text
Scheduled workflow (weekly is a reasonable start):

 1. Collect:  per host, the software set (title, version, publisher, install path)
              from the agent, or from the registry/package database where no agent exists.
 2. Normalize: lowercase titles, strip version noise, keep publisher and path.
 3. Compare:  against (a) the previous snapshot for this host, and
                     (b) the authorized software list for this asset class.
 4. Classify: NEW-AND-AUTHORIZED   allowlist entry exists -> record, no action
              NEW-AND-UNKNOWN      not on the list         -> ticket to the asset owner
              VERSION-OUT-OF-BAND  allowlist pins a band   -> ticket to the platform team
              REMOVED              was present, now gone   -> check whether it should have been
 5. Alert:    route NEW-AND-UNKNOWN to a human, not to a dashboard nobody opens.
 6. Record:   keep the snapshot and the diff output as evidence for the period.
```

Diff output template (illustrative shape — this module ships no captured fleet diff):

```text
Host                 Change    Title                      Version    Publisher        Disposition
ACME-WS-034          NEW       FooBar Utility             3.1.0      Example Vendor   NEW-AND-UNKNOWN -> ticket INC-8842
ACME-WS-034          NEW       7-Zip                      26.02      Igor Pavlov      NEW-AND-AUTHORIZED
ACME-WS-077          OUT-OF-BAND  Example Browser         118.x      Example Corp     OUT-OF-BAND -> platform team
ACME-LT-201          NEW       Everything                 1.4.1      voidtools        NEW-AND-UNKNOWN -> owner review
```

Three classes of software that a package-based diff will never see, and the extra check each needs:

| Class | Why it is invisible | Extra check |
|---|---|---|
| Portable/standalone executables | Never installed, no uninstall key required | Scheduled file-name/hash inventory of common user-writable paths, and an allowlist of permitted standalone tools |
| Browser extensions and IDE plugins | Live inside another application's profile | Management-platform extension policy; extension inventory from the browser's managed store |
| Container images and CI tooling | Installed at runtime, outside the package database | Registry policy for base images, image scanning in the pipeline, and an inventory of what the pipeline pulls |

## 6. Diagnostics

| Symptom | Likely cause | Check |
|---|---|---|
| Agent inventory count is far lower than the registry count on the same host | Agent filters, misses per-user installs, or reports only "managed" software | Compare both on one host and reconcile the difference before trusting either |
| osquery query returns no rows where you expected some | Wrong table or column name for that version | `.schema <table>` on the deployed build |
| osquery returns different results on two hosts of the same OS | Different osquery versions, or different table availability (evented tables need the publisher) | Compare versions with `SELECT version FROM os_version` and check `.tables` |
| `Get-Service` works but `Get-CimInstance` fails | CIM/WMI unavailable in the session or blocked by policy | Use the registry and native cmdlets; do not assume the estate is unmanaged |
| Scheduled inventory query never reports | The daemon is not running, the config is not loaded, or results are not shipped | Verify the daemon's service state and its log, then the transport |
| `Get-LocalGroupMember -Group 'Administrators'` fails | Localized built-in group name | Resolve the group by SID `S-1-5-32-544` (see method note in [../methodology/06-identity-and-privileged-access](../methodology/06-identity-and-privileged-access.md)) |
| Software diff produces hundreds of changes per week | Normalization is too strict (version strings, locale-dependent titles) | Normalize before diffing; report only new titles and out-of-band versions |

## Common Mistakes & Tips

- **Treating one snapshot as an inventory program.** Coverage and drift are both questions about *change over time*. Schedule the collection, keep the snapshots, and diff them.
- **Guessing table and column names.** osquery schemas move between releases. `.schema` costs five seconds and prevents a query that silently returns nothing.
- **Reading an empty result as "clean".** No rows usually means the wrong question, the wrong table, or an agent that is not reporting. Prove the pipeline with a known-present item first.
- **Matching on localized display names.** "Servicio de implementación de AppX" is a Spanish-locale string, not an identifier. Match on `Name`, SIDs, and paths.
- **Depending on WMI/CIM alone for Windows checks.** In this module's authoring environment every CIM-backed cmdlet failed; the registry-based checks all worked. Script for the restricted case.
- **Allowing the software list to be maintained by the vendor's installer.** "Installed" is not "authorized". Only the allowlist with named owners and review dates authorizes.
- **Ignoring last-logon and install dates.** An enabled account with no logon in a year, or software installed outside a change window, are the highest-signal rows in an inventory report.
- **Reporting counts instead of dispositions.** "65 titles installed" is not a finding. "Two titles not on the allowlist, tickets raised" is.
- **Tip**: build the diff before you need it. The first run establishes the baseline; every later run produces findings, and the tooling is already proven when an incident asks "when did this appear?".

## Checklist / Self-Test

- [ ] I can distinguish state questions from behaviour questions and route each to the right tool.
- [ ] I can discover an osquery build's schema and write three queries that answer inventory control questions.
- [ ] I can explain the difference between `osqueryi` and `osqueryd`, and what the daemon adds.
- [ ] I can inventory Windows software without an agent and name two things that method misses.
- [ ] I can enumerate services and drivers from the registry and explain what `Start` and `Type` mean.
- [ ] I can read `Get-LocalUser` output and identify a lifecycle finding from it.
- [ ] I can name three checks that fail when WMI/CIM is unavailable and their registry-based alternatives.
- [ ] I can write the six-step software diff workflow and classify its four dispositions.
- [ ] I can name two software classes a package-based inventory cannot see, with the check that covers each.
- [ ] I can triage a mismatched inventory count between two sources instead of trusting one.

## Further Resources

- [osquery documentation](https://osquery.readthedocs.io/) — table reference, deployment, and configuration.
- osquery schema browser — osquery.io/schema (confirm the columns for your version).
- [Wazuh documentation](https://documentation.wazuh.com/) — open-source agent, inventory and SIEM collection used as the central store in this module's labs.
- [CIS Controls](https://www.cisecurity.org/controls) — control 1 (Enterprise Assets) and control 2 (Software Assets).
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) — CM-8 (System Component Inventory) and CM-10/CM-11 (software usage and installation restrictions).
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001) — Annex A 5.9 (inventory of information and other associated assets).
