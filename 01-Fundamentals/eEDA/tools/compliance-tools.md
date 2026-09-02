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

A **tailoring file** lets you keep a stock profile but exempt rules that do not apply to you (e.g., a rule requiring a tool your organization does not use). Never edit the original content — create an overlay:

```bash
# Generate a starter tailoring file from a profile
oscap xccdf generate tailoring-file \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --output /etc/scap/tailoring-cis.xml

# Use it during the scan
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --tailoring-file /etc/scap/tailoring-cis.xml \
  --report /tmp/scap-report-tailored.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

To exempt a rule, mark it `xccdf:selected="false"` in the tailoring file, and record *why* in your documentation — an auditor will ask.

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

# Show only the findings of the last run
sudo lynis show warnings
sudo lynis show suggestions

# Re-run and compare the hardening index over time
sudo lynis audit system --quiet
```

### Interpreting the Results

Output lands in `/var/log/lynis-report.dat` plus a human-readable log (`lynis.log`). Look for:

- **`[WARNING]`** entries and the *suggestion* text under each — Lynis usually tells you exactly which file or setting to change (e.g., enable a firewall, set `PermitRootLogin no`, install a file-integrity tool).
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
- [ ] I can create a tailoring file and exclude one inapplicable rule with a documented reason.
- [ ] I can run `lynis audit system` and explain the difference between warnings, suggestions, and the hardening index.
- [ ] I can write three osquery SQL queries that check listening ports, package versions, and user accounts.
- [ ] I can add a persistent auditd rule for `/etc/passwd` and search events with `ausearch -k`.
- [ ] I can explain, in one sentence each, what a SIEM, SOAR, and GRC platform do.
- [ ] I have completed at least one full "scan → interpret → remediate → re-scan" cycle on a Linux VM.

## Further Resources

- [OpenSCAP project](https://www.open-scap.org/) — tools, manuals, and tutorials.
- [ComplianceAsCode / SCAP Security Guide](https://github.com/ComplianceAsCode/content) — the content data streams used by `oscap`.
- [Lynis (CISOfy)](https://cisofy.com/lynis/) — official docs and hardening guides.
- [osquery documentation](https://osquery.readthedocs.io/) — table reference and deployment guide.
- [Linux auditd man page](https://man7.org/linux/man-pages/man8/auditd.8.html) — daemon reference; see also `auditctl(8)`, `ausearch(8)`, `aureport(8)`.
