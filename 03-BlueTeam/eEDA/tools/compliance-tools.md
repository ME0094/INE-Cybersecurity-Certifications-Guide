# Compliance Tools for eEDA

> eEDA · Tools — INE-Cybersecurity-Certifications-Guide

## Purpose

Compliance work on a real enterprise boils down to: **scan → collect evidence → compare against a baseline → remediate → re-scan**. This guide covers the free, open-source tools that defenders use to do exactly that on Linux systems — **OpenSCAP**, **Lynis**, **osquery**, and **auditd** — plus what commercial **SIEM and GRC platforms** add on top. The lab guide `labs/security-policy-exercises.md` builds on these commands.

## OpenSCAP (oscap)

OpenSCAP is an open-source implementation of the **Security Content Automation Protocol (SCAP)**: a NIST standard for expressing and evaluating security baselines in machine-readable form. You run `oscap` with **content** — most commonly the **SCAP Security Guide (SSG)** / ComplianceAsCode data streams, which ship as files like `ssg-rhel9-ds.xml` or `ssg-ubuntu2004-ds.xml`.

### Common Commands

```bash
# Inspect what profiles ship inside the content
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# List only the available profiles
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml | grep -A4 "Profiles"

# Run a full scan against a profile (e.g., CIS level 1) and generate an HTML report
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --report /tmp/scap-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

### Tailoring (Adjusting the Baseline to Your Environment)

A **tailoring file** lets you keep a stock profile but exempt rules that do not apply to you (e.g., a rule requiring a tool your organization does not use). Never edit the original content — create an overlay. Note that `oscap xccdf generate` cannot do this: its only submodules are `report`, `guide`, `fix` and `custom`. On OpenSCAP 1.3+ the tool for the job is **`autotailor`**, shipped by `openscap-utils`:

```bash
# Generate a tailoring file with autotailor (OpenSCAP 1.3+; shipped by openscap-utils).
# oscap xccdf generate has no tailoring-file submodule: its submodules are
# report, guide, fix and custom only.
autotailor \
  --unselect xccdf_org.ssgproject.content_rule_<rule-id> \
  --output /etc/scap/tailoring-cis.xml \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml \
  xccdf_org.ssgproject.content_profile_cis

# Use it during the scan. autotailor defines a NEW profile derived from the base
# one (by default <base-profile-id>_customized, or whatever --new-profile-id set),
# so the scan selects that new profile, not the base one:
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_customized \
  --tailoring-file /etc/scap/tailoring-cis.xml \
  --report /tmp/scap-report-tailored.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

`autotailor` takes the data stream and the base profile as its positional arguments, and `--unselect` (or `--select`, `--var-value`) to change rules. You can also keep the overlay by hand: inside a tailoring file an exempted rule is marked `xccdf:selected="false"`. Either way, record *why* in your documentation — an auditor will ask.

### Interpreting the Results

- **Pass / Fail / Not Applicable / Not Reviewed** per rule — a *fail* is a compliance finding, *not applicable* is fine if genuinely justified.
- Overall score is a percentage; focus on **failed rules first**, reading the remediation text shipped with each rule.
- Generate machine-readable output for evidence: `oscap xccdf eval ... --results /tmp/results.xml` and attach `--oval-results` for OVAL detail.

## Lynis

Lynis is a security **auditing tool for Unix-like systems**. It performs hundreds of checks, then reports **Warnings** (weak spots), **Suggestions** (improvements), and a **Hardening Index** score. It is ideal for a fast, readable posture snapshot and for tracking improvement over time.

```bash
# Install (Debian/Ubuntu example)
sudo apt install lynis            # or: sudo dnf install lynis

# Run a full audit (needs root)
sudo lynis audit system

# Re-show only warnings without a full report (this re-runs the audit quietly)
sudo lynis audit system --warnings-only

# Or read the findings of the last run straight from its artefacts
sudo grep -E ' (Warning|Suggestion): ' /var/log/lynis.log
sudo grep -E '^(warning|suggestion)\[\]' /var/log/lynis-report.dat

# Re-run and compare the hardening index over time
sudo lynis audit system --quiet
```

### Interpreting the Results

Output lands in `/var/log/lynis-report.dat` plus a human-readable log (`lynis.log`). Watch the format when you grep them: the terminal prints warnings as `[WARNING]`, while the log file records the same lines as `Warning: ...` / `Suggestion: ...` with a timestamp, and the report file stores them as `warning[]=TEST|MESSAGE|DETAILS|SOLUTION|`. Look for:

- **Warning** entries and the *suggestion* text under each — Lynis usually tells you exactly which file or setting to change (e.g., enable a firewall, set `PermitRootLogin no`, install a file-integrity tool).
- **Hardening index** — a 0–100 score. It is a *relative* number: the point of re-auditing is that the index **goes up** after you apply fixes. Do not chase 100 blindly; prioritize warnings that matter for your risk profile.

## osquery

osquery (Facebook/Meta, now Linux Foundation) exposes the operating system as a **SQL database**. It is the standard way to answer "show me every listening port / installed package / logged-in user / scheduled task" across thousands of hosts — which is why compliance teams love it.

```bash
osqueryi --json "SELECT name, version FROM os_version;"   # one-off query

# Compliance-style queries
osqueryi "SELECT DISTINCT local_address, local_port, p.name FROM process_open_sockets
          JOIN processes p USING (pid) WHERE family = 2 AND remote_port = 0;"

osqueryi "SELECT name, version FROM rpm_packages WHERE name = 'openssh-server';"   # RHEL/Fedora
osqueryi "SELECT name, version FROM deb_packages WHERE name = 'openssh-server';"   # Debian/Ubuntu

# Accounts with a login shell (candidates for review)
osqueryi "SELECT uid, username, shell FROM users WHERE shell NOT IN ('/usr/sbin/nologin','/bin/false');"
```

For continuous compliance you run `osqueryd` as a service (with `--config_plugin` schedules and file-integrity monitoring), and optionally ship results to a **Fleet** manager or your SIEM. A scheduled query that runs every hour and flags deviations *is* an automated compliance check.

## auditd Basics

`auditd` is the Linux kernel audit daemon: it records security-relevant events (file access, account changes, syscalls) to a log that cannot be silently edited by the user being watched. Logs are the backbone of *evidence* in compliance and incident work.

```bash
# One-off live rules (lost on reboot)
sudo auditctl -w /etc/passwd -p wa -k identity    # watch writes/attribute changes
sudo auditctl -l                                   # list loaded rules

# Persistent rules: write to /etc/audit/rules.d/<name>.rules then reload
sudo augenrules --load

# Search events tagged with the 'identity' key
sudo ausearch -k identity -ts today

# Summary reports
sudo aureport -au    # authentication report
sudo aureport -l     # login report
sudo aureport -x     # executable (process) report
```

Example persistent rule file `/etc/audit/rules.d/identity.rules`:

```text
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
```

**Practical loop for compliance:** watch the files your policy says are critical → let the log collect → query with `ausearch -k <key>` when an auditor or incident asks "who changed X and when?" → archive the logs per your retention policy.

## What SIEM and GRC Platforms Do (In General Terms)

These are the commercial/enterprise layers you will see in job ads and larger organizations:

- **SIEM (Security Information and Event Management)** — collects logs and events from everywhere (servers, firewalls, EDR, cloud), normalizes them, correlates for suspicious patterns, and gives analysts a single pane of glass. Examples: Splunk Enterprise Security, Elastic Security, IBM QRadar, and the open-source Wazuh. Think "auditd/osquery at fleet scale, plus alerting".
- **SOAR (Security Orchestration, Automation and Response)** — automates response playbooks (e.g., "on alert X, block IP and open a ticket").
- **GRC (Governance, Risk and Compliance) platforms** — the tool where policies live, risk registers are maintained, control evidence is stored, and assessments are tracked. Examples: ServiceNow GRC, Archer, OneTrust. If osquery/Lynis answer "is the control working?", the GRC platform answers "which control is this evidence for, and who signed it off?"

## Common Mistakes & Tips

- **Scanning as root vs. non-root.** `oscap` and `lynis` need root to see the real system state; a non-root scan silently skips checks. Run them with `sudo`.
- **Ignoring "Not Applicable" rules.** Leaving genuinely inapplicable rules as *fail* hurts your score and confuses auditors — use a tailoring file with documented reasons.
- **Using the wrong content version.** An SSG data stream for RHEL 9 on a RHEL 8 host produces noise. Match content to the OS release.
- **One-off queries only.** `osqueryi` is great for ad-hoc checks, but continuous compliance needs scheduled `osqueryd` queries — otherwise configuration drifts back and you never notice.
- **Editing audit rules at runtime only.** `auditctl` rules vanish on reboot. Write them under `/etc/audit/rules.d/` and run `augenrules --load`.
- **Reporting a hardening index without context.** Always pair the Lynis score with the *warnings that remain* and a short explanation of accepted risk.

## Checklist / Self-Test

- [ ] I can run an OpenSCAP scan against a CIS profile and generate an HTML report.
- [ ] I can create a tailoring file with `autotailor` (or by hand), exclude one inapplicable rule, and document the reason and the owner.
- [ ] I can run `lynis audit system` and explain the difference between warnings, suggestions, and the hardening index.
- [ ] I can write three osquery SQL queries that check listening ports, package versions, and user accounts.
- [ ] I can add a persistent auditd rule for `/etc/passwd` and search events with `ausearch -k`.
- [ ] I can explain, in one sentence each, what a SIEM, SOAR, and GRC platform do.
- [ ] I have completed at least one full "scan → interpret → remediate → re-scan" cycle on a Linux VM.

> **Verification:** WSL Ubuntu 24.04, 2026-09-19 — **`oscap` 1.3.9** and **`lynis` 3.0.9**. `oscap xccdf generate --help` lists exactly four commands — `report`, `guide`, `fix`, `custom` — and `oscap xccdf generate tailoring-file --profile x --output /tmp/t.xml /tmp/nope.xml` answers `No such module: tailoring-file`. `autotailor --help` (openscap-utils 1.3.9) prints `usage: autotailor [-h] [--title TITLE] [--id-namespace ID_NAMESPACE] [-v VAR=VALUE] [-s RULE_ID] [-u RULE_ID] [-p NEW_PROFILE_ID] [-o OUTPUT] DS_FILENAME BASE_PROFILE_ID`. `lynis show` with no argument prints its valid arguments — `categories`, `changelog`, `commands`, `dbdir`, `details`, `environment`, `eol`, `groups`, `help`, `hostids`, `includedir`, `language`, `license`, `logfile`, `man`, `options`, `os`, `pidfile`, `plugindir`, `profiles`, `release`, `releasedate`, `report`, `settings`, `tests`, `version`, `workdir` — and `lynis show warnings` answers `Unknown argument 'warnings' for lynis show`. A real run of `lynis audit system --warnings-only --quick` on this host produced `/var/log/lynis-report.dat` with 3 `warning[]=` and 45 `suggestion[]=` records plus `hardening_index=62`, and `/var/log/lynis.log` with 48 lines matching ` (Warning|Suggestion): ` — which is why the commands above grep the log with that pattern rather than with `[WARNING]`/`[SUGGESTION]` markers. No SCAP Security Guide data stream is installed here (`/usr/share/xml/scap/ssg/content/` does not exist), so the `oscap xccdf eval` invocations were not executed end to end.

## Further Resources

- [OpenSCAP project](https://www.open-scap.org/) — tools, manuals, and tutorials.
- [ComplianceAsCode / SCAP Security Guide](https://github.com/ComplianceAsCode/content) — the content data streams used by `oscap`.
- [Lynis (CISOfy)](https://cisofy.com/lynis/) — official docs and hardening guides.
- [osquery documentation](https://osquery.readthedocs.io/) — table reference and deployment guide.
- [Linux auditd man page](https://man7.org/linux/man-pages/man8/auditd.8.html) — daemon reference; see also `auditctl(8)`, `ausearch(8)`, `aureport(8)`.
