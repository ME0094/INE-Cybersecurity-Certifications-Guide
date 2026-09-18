# Hardening and Configuration Scanning

> eEDA · Tools — INE-Cybersecurity-Certifications-Guide
>
> The tools that answer "is this system in its approved secure state?": OpenSCAP and the SCAP Security Guide on Linux, Lynis for a fast posture snapshot, CIS-CAT-style benchmark assessors in enterprise use, and the registry-based checks that work on Windows when WMI is unavailable. Read this with [../methodology/04-security-engineering](../methodology/04-security-engineering.md) (baselines and the enforce-before-verify rule) and [../methodology/05-asset-inventory-and-configuration](../methodology/05-asset-inventory-and-configuration.md) (which assets are in scope).

## 1. What This Tool Family Does

Hardening tools do four jobs, and confusing them is why compliance scanning programmes stall:

| Job | Question | Typical tool | Output |
|---|---|---|---|
| **Assess** | What is the current state of this host against a benchmark? | OpenSCAP, Lynis, CIS-CAT-style assessor | Per-rule pass/fail with remediation text |
| **Report** | Can I show an auditor or an owner what the state was, on a date? | All of the above | HTML report + machine-readable results |
| **Remediate** | Can the failing rules be fixed consistently? | Generated fix scripts, configuration management | Changed configuration, traced to a rule |
| **Prove control** | Is the estate staying in that state over time? | Scheduled scans, management-platform policy evaluation | Trend per rule and per asset class |

> The order in real deployments is **enforce, then verify**: get assets into the baseline through images and configuration management, then use scanning to measure the exceptions. Scanning an unmanaged estate first produces thousands of findings that nobody can fix, and the programme dies of its own report volume.

## 2. OpenSCAP (`oscap`)

**What it is.** An open-source implementation of the **Security Content Automation Protocol (SCAP)** — a NIST standard for expressing security baselines in machine-readable form. `oscap` evaluates *content* against a *system*: content is most often the **SCAP Security Guide (SSG)** / ComplianceAsCode data streams, shipped as files such as `ssg-rhel9-ds.xml` or `ssg-ubuntu2004-ds.xml`.

**What it produces.** An evaluation run with per-rule results (`pass`, `fail`, `notapplicable`, `notchecked`, `error`, `unknown`) plus, on request, an HTML report for humans and an XML results file for evidence and trend tracking.

**How to use it.**

```bash
# 1. Find out what the content actually contains (profiles, IDs, rule counts)
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml | grep -A4 "Profiles"

# 2. Evaluate a host against a profile, producing both artefacts:
#    HTML for the asset owner, XML for the evidence index
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --report /var/tmp/scap-report.html \
  --results /var/tmp/scap-results.xml \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# 3. Optional: generate a remediation script instead of applying changes live,
#    so the fix can be reviewed, versioned and deployed through configuration management
oscap xccdf generate fix \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --fix-type bash \
  --output /var/tmp/remediation.sh \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

> These OpenSCAP commands are a **syntax reference**: no Linux host was available while this module was written, so none of them was executed here. Flags differ between releases — confirm against `oscap --help` and the manual page for your installed version, and confirm the profile ID with `oscap info` rather than trusting an ID copied from a blog post.

**Tailoring instead of editing content.** Never edit the shipped data stream: create an overlay that deselects rules that genuinely do not apply, with the reason recorded.

```bash
# Generate a tailoring file from a profile, then edit it
oscap xccdf generate tailoring-file \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --output /etc/scap/tailoring-cis.xml

# Use it during the scan, and attach it to the evidence so the deviation is auditable
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --tailoring-file /etc/scap/tailoring-cis.xml \
  --report /var/tmp/scap-report-tailored.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

Inside the tailoring file, an exempted rule is marked `xccdf:selected="false"`. An exemption without a written reason and an owner is an undocumented deviation, not a tailoring.

**Interpreting the result.**

| Result | Meaning | What to do |
|---|---|---|
| `pass` | Configuration matches the rule | Record; it is your evidence |
| `fail` | Configuration does not match | Classify: fix (image/config), deviate (tailor out), or accept (risk decision with expiry) |
| `notapplicable` | The rule cannot apply here | Fine if genuinely true; verify the assessment is not an artefact of missing data |
| `notchecked` | The rule could not be evaluated automatically | A gap: review manually or accept as a known limitation of automation |
| `error`, `unknown` | Evaluation failed | Investigate the content/tool mismatch before drawing any conclusion |

**Limitations.**

- **Content-to-OS mismatch is a silent quality killer.** RHEL 9 content on a RHEL 8 host produces noise that looks like findings. Match the data stream to the OS release.
- **Root matters.** A non-root scan silently skips checks that require elevated access, and the result looks better than reality.
- **A pass is not a security outcome.** Rules are configuration assertions; a host can pass a profile and still run vulnerable software (see [../methodology/07-vulnerability-and-patch-management](../methodology/07-vulnerability-and-patch-management.md)).
- **New content changes your score.** Upgrading the data stream can change results with no change to the host. Pin the content version and record it with each scan so trends stay comparable.
- **Live remediation changes production systems.** Prefer generating a fix script, reviewing it, and deploying via configuration management — especially for T1 assets.

## 3. Lynis

**What it is.** A security auditing tool for Unix-like systems that runs hundreds of checks on a host and reports findings as **Warnings** (weak spots), **Suggestions** (improvements) and a **Hardening Index** score.

**What it produces.** A human-readable log and a machine-readable report (`/var/log/lynis-report.dat`), plus the terminal output. The index is a convenient headline; the warnings are the actionable content.

**How to use it.**

```bash
# Install (Debian/Ubuntu shown; use the platform package manager on other families)
sudo apt install lynis            # or: sudo dnf install lynis

# Full audit (root, otherwise checks are skipped)
sudo lynis audit system

# Re-read the findings of the last run without re-scanning
sudo lynis show warnings
sudo lynis show suggestions

# Quiet run for trend tracking (compare the index over time)
sudo lynis audit system --quiet
```

> Syntax reference only — not executed in this environment.

**How to use the output well.**

- Read every **warning** with its remediation text; Lynis usually names the file or setting to change.
- Treat the **Hardening Index** as a relative trend line for one host over time, never as a grade to maximise. Chasing the last ten points usually means applying hardening that the workload does not need.
- Pair the index with the *remaining warnings* in any report. "Index 82 with two accepted warnings and one deviation" is a defensible statement; "index 82" alone is not.
- The first run on any host is a reconnaissance exercise, not a compliance result: apply three meaningful fixes, re-run, and confirm the index moved.

**Limitations.**

- Wide but shallow compared with a full benchmark profile: it is excellent for a fast snapshot and for host-level common sense, weaker for rule-by-rule audit evidence.
- Results are host-specific and not designed as fleet-wide compliance reporting.
- Findings are advisory: a rule that breaks a business application must be handled by documented acceptance, not force-applied.
- Like any scanner, a non-root run understates the problems.

## 4. CIS-CAT-Style Benchmark Assessors

**What they are.** Commercial and enterprise assessors that evaluate a host against the official **CIS Benchmarks** content and produce per-rule pass/fail reports with scoring. The CIS-CAT family is the best-known example; several endpoint-management suites embed equivalent benchmark evaluation.

**What they add over OpenSCAP/Lynis.**

| Capability | Why enterprises pay for it |
|---|---|
| Official benchmark content per OS/appliance version | Findings map directly to a widely recognised baseline, which helps in audits |
| Fleet reporting and dashboards | Per-rule compliance across thousands of hosts without writing your own aggregation |
| Cross-platform coverage | Windows, Linux, macOS, databases, browsers, and network devices in one report shape |
| Remediation guidance and exceptions tracking | Deviations are recorded in the tool, not in a spreadsheet next to it |
| Scheduled, agent-based assessment | Continuous compliance rather than a quarterly project |

**How to consume the output.** Treat the per-rule result as a data point and build the same triage you would with OpenSCAP: fix the ones that belong in the image, tailor out the ones that cannot apply, and formally accept the ones that cannot be fixed. The tool's score is a summary of *assertions*, not a measure of risk — a host that fails three rules in an unused subsystem is not in the same position as a host that fails one rule on remote administration.

**Limitations.**

- Content and cost are tied to a subscription: budget for both, and know what happens if you stop paying (you keep the reports, not the content).
- Benchmark content trails vendor releases; a freshly released OS version may have no content for a few months.
- Score comparisons across different benchmark versions are meaningless. Record the content version with every scan.

## 5. Windows: Benchmark Checks Without WMI

On Windows the equivalent work is done by security baselines delivered through Group Policy, Intune, or the Microsoft Security Compliance Toolkit, and by management platforms that evaluate settings continuously. For hands-on verification — and for hosts or sessions where WMI/CIM is unavailable — **registry-based checks are the practical fallback**.

> Why this matters in practice: in the environment where this module was written, every CIM-backed cmdlet failed, including `Get-CimInstance`, `Get-Volume`, `Get-NetFirewallProfile`, `Get-NetTCPConnection`, `Get-ScheduledTask`, `Get-SmbShare`, `Get-Disk`, and `Get-HotFix`, all with the same message: `El cliente no tenía acceso disponible a un recurso CIM.` (a localized "the CIM client could not access a resource"). Registry reads kept working. An administrator who can only check configuration through WMI has no check at all in a restricted, hardened, or degraded session.

A real run of twelve registry-based configuration checks on a Windows workstation (output verbatim; `<not set>` means the value does not exist at that path on this build):

```powershell
$checks = [ordered]@{
 'SMB1 (LanmanServer\Parameters)'       = @{Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name='SMB1'}
 'RDP fDenyTSConnections'               = @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'; Name='fDenyTSConnections'}
 'LSA RestrictAnonymous'                = @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymous'}
 'LSA LmCompatibilityLevel'             = @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='LmCompatibilityLevel'}
 'LSA RunAsPPL'                         = @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RunAsPPL'}
 'WDigest UseLogonCredential'           = @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name='UseLogonCredential'}
 'PowerShell ScriptBlockLogging'        = @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name='EnableScriptBlockLogging'}
 'PowerShell ModuleLogging'             = @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Name='EnableModuleLogging'}
 'WSUS Server (policy)'                 = @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Name='WUServer'}
 'Windows Update AUOptions (policy)'    = @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name='AUOptions'}
 'Autorun (Explorer NoDriveTypeAutoRun)'= @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoDriveTypeAutoRun'}
 'UAC EnableLUA'                        = @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableLUA'}
}
foreach($k in $checks.Keys){
  $c = $checks[$k]
  $v = (Get-ItemProperty -Path $c.Path -Name $c.Name -ErrorAction SilentlyContinue).($c.Name)
  if($null -eq $v){ $v = '<not set>' }
  "{0,-38} {1,-26} = {2}" -f $k, $c.Name, $v
}
```

```text
SMB1 (LanmanServer\Parameters)         SMB1                       = <not set>
RDP fDenyTSConnections                 fDenyTSConnections         = 1
LSA RestrictAnonymous                  RestrictAnonymous          = 0
LSA LmCompatibilityLevel               LmCompatibilityLevel       = <not set>
LSA RunAsPPL                           RunAsPPL                   = 2
WDigest UseLogonCredential             UseLogonCredential         = <not set>
PowerShell ScriptBlockLogging          EnableScriptBlockLogging   = <not set>
PowerShell ModuleLogging               EnableModuleLogging        = <not set>
WSUS Server (policy)                   WUServer                   = <not set>
Windows Update AUOptions (policy)      AUOptions                  = <not set>
Autorun (Explorer NoDriveTypeAutoRun)  NoDriveTypeAutoRun         = <not set>
UAC EnableLUA                          EnableLUA                  = 1
```

How to read that output honestly — the skill this section is really teaching:

| Result | What it means | What it does **not** mean |
|---|---|---|
| `fDenyTSConnections = 1` | Remote Desktop is disabled for this host | That no remote-access path exists (other agents and tools have their own) |
| `EnableLUA = 1` | User Account Control is enabled | That every elevation is prompted or logged (that depends on the UAC policy subkeys) |
| `RunAsPPL = 2` | LSA protection is configured, enabled without a UEFI lock | That the setting will hold after a reboot on a system without the UEFI variable |
| `RestrictAnonymous = 0` | Anonymous enumeration of SAM accounts is not restricted by this value | That anonymous access is permitted overall — other settings and the domain policy also apply |
| `<not set>` | The value does not exist at this path on this build | That the feature is off *or* on: the effective state comes from the documented default, a domain policy, or a management-platform setting |

Two lessons carry over to every benchmark scanner: a **missing value is not a pass**, and a **single key is not a system state**. Where the registry is silent, resolve the state from the authoritative source (the management platform's report, the vendor's documented default for that build, or the domain policy) and record which source you used.

For log configuration specifically, the event-log service exposes its own settings without WMI:

```powershell
wevtutil gl Security
```

```text
name: Security
enabled: true
type: Admin
owningPublisher:
isolation: Custom
channelAccess: O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)
logging:
  logFileName: %SystemRoot%\System32\Winevt\Logs\Security.evtx
  retention: false
  autoBackup: false
  maxSize: 20971520
publishing:
  fileMax: 1
```

This is a genuine audit finding on a default workstation: `maxSize: 20971520` is 20 MB, and `retention: false` means the log wraps and discards the oldest events once full. That is a size that a single busy day can overwrite, and it is exactly the kind of default that makes an investigation impossible after the fact. Compare it against your retention requirement before claiming you have logs (see [../methodology/09-soc-and-incident-response-interface](../methodology/09-soc-and-incident-response-interface.md)).

> Reading the Security log itself needs elevation: `Get-WinEvent -LogName Security` on a non-elevated session fails with `Attempted to perform an unauthorized operation.` Configuration *queries* are often available while *content* is not — plan your check scripts around what your operator account can actually read.

## 6. Choosing the Tool

| Situation | Use | Why |
|---|---|---|
| Linux host, need rule-level evidence against a recognised benchmark | OpenSCAP with SSG content | Machine-readable results, tailoring, reproducible evidence |
| Linux host, need a fast posture snapshot and a trend score | Lynis | Fast, readable, good first-pass triage |
| Fleet-wide benchmark compliance with reporting and exceptions | CIS-CAT-style assessor or management platform | Aggregation, dashboards, and deviation tracking across hosts |
| Windows estate under Group Policy/Intune | Security baselines plus management-platform policy evaluation | Enforcement and continuous evaluation in the same tool |
| Windows host, restricted session, or degraded state | Registry-based checks plus `wevtutil` | Works when WMI/CIM does not, and it is scriptable |
| Proving drift over time | Any of the above, run on a schedule, with the content version recorded | The point is the trend, not one report |

## 7. Turning Scan Output into Evidence

A scan report becomes evidence only if someone can find it, date it, and explain it later.

```text
Evidence naming and storage pattern:

  <evidence-root>/<asset-class>/<tool>/<YYYY-MM-DD>-<profile-or-benchmark>-<content-version>/
      report.html            human-readable summary (for the owner and the auditor)
      results.xml            machine-readable results (for trend tracking)
      tailoring.xml          the deviations in force at the time of the scan
      exceptions.md          the accepted findings, with owners and expiry dates
      README.txt             who ran it, on which host, from which command

  Retention: keep at least one scan per asset class per period, and keep the
  content version with every one of them. A scan whose content version is
  unknown cannot be compared with any other scan.
```

Evidence that survives an audit interview has three properties: it is dated, it states the content/benchmark version, and it is accompanied by a note explaining each remaining failure. A pile of HTML reports with no explanation of the red lines is worse than a short report with a written deviation register.

## 8. Diagnostics: When Scanning Goes Wrong

| Symptom | Likely cause | Check |
|---|---|---|
| Scan completes but every rule is `notchecked` or the report is nearly empty | Wrong content for the OS, or missing privileges | `oscap info` on the data stream; confirm root; confirm the profile ID exists |
| Score is suspiciously high on a host you know is weak | Non-root run, or content that does not cover the failing areas | Re-run with `sudo`; read the `notapplicable`/`notchecked` counts |
| Findings change without any host change | Content version changed | Pin and record the content version per scan |
| Lynis index moves in the wrong direction after "fixes" | A change disabled a check, or the fix applied a setting that breaks another check | Compare `lynis show warnings` between runs, item by item |
| Scan takes hours on a large host | Broad file-system rules | Scope the scan; schedule outside business hours |
| Windows check script reports `<not set>` for everything | Reading the wrong hive path or wrong policy location (user vs. machine, policy vs. preference) | Verify the path on the host, and confirm whether the setting is delivered by policy or by default |
| A "compliant" report contradicts a security incident | The benchmark covers configuration, not vulnerability or monitoring effectiveness | Cross-check patch level and detection coverage — see [../methodology/07-vulnerability-and-patch-management](../methodology/07-vulnerability-and-patch-management.md) |

## Common Mistakes & Tips

- **Scanning as a non-root/non-elevated user.** The scan silently skips checks and the result overstates compliance. This is the single most common false-negative in hardening tooling.
- **Treating "not checked" as "passed".** It is a coverage gap with a comfortable colour. Count those rules separately and report them.
- **Content/OS mismatch.** Wrong benchmark content produces findings that no engineer can reproduce, and the programme loses credibility within a week. Match content to release, and record the version.
- **Editing shipped benchmark content.** Your edits disappear at the next content update. Tailor with an overlay file, and keep the reason with the exemption.
- **Remediating live on T1 hosts.** Generate the fix, review it, and deploy it through configuration management. A benchmark fix script on a production database server at 14:00 is a self-inflicted incident.
- **Chasing a perfect score.** A 100% score usually means unnecessary hardening, unjustified deviations, or a scan that is not checking much. Aim for "no unexplained failures".
- **Keeping the report and discarding the reason.** Every remaining failure needs one sentence: fixed-by-design, deviated with an owner, or accepted with an expiry date.
- **Trusting a single key for a system-wide answer.** `RestrictAnonymous`, `SMB1`, and similar settings are effective state *plus* defaults *plus* domain policy. Say which source you used.
- **Forgetting that hardcoded English group and policy names break on other locales.** `Get-LocalGroupMember -Group 'Administrators'` fails on a Spanish-locale Windows (`No se encontró el grupo Administrators`): resolve built-in groups by their well-known SID instead (see [../methodology/06-identity-and-privileged-access](../methodology/06-identity-and-privileged-access.md)).
- **Tip**: run the same profile on a known-good reference host before rolling it out to the fleet. The reference host tells you which failures are your standard, and which are real.

## Checklist / Self-Test

- [ ] I can state the four jobs of hardening tooling and explain why enforcement precedes verification.
- [ ] I can inspect an OpenSCAP data stream, list its profiles, and run an evaluation producing both an HTML report and XML results.
- [ ] I can create a tailoring file, deselect a rule, and document the reason and owner.
- [ ] I can explain what `pass`, `fail`, `notapplicable`, and `notchecked` each mean for my compliance claim.
- [ ] I can run a Lynis audit, read the warnings, and explain why the hardening index is a trend and not a grade.
- [ ] I can describe what a CIS-CAT-style assessor adds over OpenSCAP, and what its score does and does not measure.
- [ ] I can run registry-based configuration checks on Windows and correctly interpret `<not set>`.
- [ ] I can read `wevtutil gl <channel>` and say whether the log size and retention meet the requirement.
- [ ] I can name two checks that fail when WMI/CIM is unavailable, and the non-WMI alternative for each.
- [ ] I can organize scan output as dated evidence that states the benchmark content version.
- [ ] I can triage a scan that returns implausible results using the diagnostics table.

## Further Resources

- [OpenSCAP project](https://www.open-scap.org/) — tools, manuals, and tutorials for `oscap`.
- [ComplianceAsCode / SCAP Security Guide](https://github.com/ComplianceAsCode/content) — the data streams and profiles used by `oscap`.
- [Lynis (CISOfy)](https://cisofy.com/lynis/) — documentation, hardening guides, and sample reports.
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) — the configuration baselines these tools evaluate against.
- [CIS Controls](https://www.cisecurity.org/controls) — control 4 (Secure Configuration of Enterprise Assets and Software) for the programme around the tool.
- Microsoft security baselines and the Security Compliance Toolkit — learn.microsoft.com/windows/security/operating-system-security/device-management/ (vendor guidance for Windows baseline delivery).
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) — CM (Configuration Management) controls behind baseline scanning.
