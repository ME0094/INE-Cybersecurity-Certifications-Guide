# Security Policy Exercises — Hands-On Lab

> eEDA · Labs — INE-Cybersecurity-Certifications-Guide

## Purpose

This lab turns the concepts from the methodology and tool guides into hands-on work. You will: (1) draft a security policy skeleton, (2) build a risk register, (3) map CIS Controls to a fictional environment, and (4) run Lynis and OpenSCAP against a Linux VM and interpret the results. Each exercise ends with questions you should be able to answer out loud — that is the real eEDA skill: *explaining your evidence*.

## Lab Environment

- **Linux VM** (any of: Ubuntu 22.04/24.04, Debian 12, RHEL/Rocky/Alma 9) with root access. 2 GB RAM, 20 GB disk is plenty.
- Your normal workstation for writing documents.
- The fictional company used in exercises 1–3:

> **Acme Widgets Inc.** — 120 employees. One headquarters office + remote workers. Windows Active Directory for users, one public web shop on Linux (Ubuntu), an internal file server, and a small AWS footprint. They take card payments on the web shop (PCI DSS in scope) and handle customer personal data. Security team: two administrators.

## Exercise 1 — Draft a Security Policy Skeleton

Write a one-page skeleton for an **Acceptable Use Policy (AUP)** from the template below. Fill each section with 1–3 enforceable sentences appropriate for Acme. Keep sentences concrete: name the audience, the rule, and the owner.

```markdown
# Acme Widgets Inc. — Acceptable Use Policy (AUP)
Version 1.0 · Owner: CISO · Review: annual

1. PURPOSE AND SCOPE
   Applies to: [who? which devices/accounts?]

2. AUTHORIZED USE
   Company assets may be used for: [what is allowed?]

3. PROHIBITED USE
   Users must not: [3-5 concrete prohibitions]

4. PERSONAL USE & PRIVACY
   [Is incidental personal use allowed? Is there an expectation of privacy?]

5. ACCOUNT AND PASSWORD RULES
   [Password creation, sharing, MFA requirement]

6. MONITORING AND ENFORCEMENT
   [May the company monitor? Who enforces? Consequences?]

7. REPORTING
   [Where to report suspected misuse/incidents]

8. ACKNOWLEDGMENT
   [How users accept the policy]
```

**Tips**

- Write for a *reasonable employee*, not a lawyer. "Employees may not install unapproved software" beats "unauthorized software installations are strictly prohibited".
- Every rule should map to at least one control later (Exercise 3). If a rule maps to nothing, cut it.
- Add version, owner, and review date — auditors check document control.

**Check your work:** ask "can this rule be enforced or measured?" for each sentence. If not, rewrite it.

## Exercise 2 — Create a Risk Register

A risk register lists what can hurt you, how likely/how bad it is, and what you will do. Build one for Acme with at least **6 rows**, using this structure:

```markdown
| ID | Asset | Threat | Vulnerability / trigger | Likelihood (L) | Impact (I) | Score (L×I) | Treatment | Owner |
|----|-------|--------|------------------------|----------------|-----------|-------------|-----------|-------|
```

- Score on a **1–5 × 1–5** scale (5 = almost certain / catastrophic). Treat scores ≥ 15 as high priority.
- **Treatment** must be one of: **Accept, Mitigate, Transfer** (insurance/contract), or **Avoid** (stop the activity). Add the control you will implement when mitigating.

Suggested starter rows to complete:

```text
WEB-01  Public web shop    Card data breach        Weak admin credentials on shop console    ...
WEB-02  Public web shop    Web defacement          Unpatched CMS plugin                     ...
AD-01   Active Directory   Lateral movement        Local admin rights on all workstations   ...
FS-01   File server        Ransomware              No tested offline backups                ...
HR-01   Laptop (remote)    Data loss/theft         No disk encryption policy                ...
CL-01   AWS account        Credential theft        Root keys stored in plain text           ...
```

**Expected result:** a table where every row names a *concrete* treatment with an owner — and where the top rows match what a CIS mapping (Exercise 3) would also flag as urgent.

## Exercise 3 — Map CIS Controls to Acme

Goal: decide Acme's **Implementation Group** and map the controls to evidence they already have or must create.

1. **Pick the IG.** Acme is a small, non-critical business — it fits **IG1** (essential hygiene) with a few IG2 items where regulation demands it (PCI DSS scope on the web shop). Defend that choice in one paragraph.
2. **Map at least 6 CIS v8 controls** to real Acme systems and to the *evidence* an auditor could inspect:

```markdown
| CIS v8 control | Concrete Acme implementation | Evidence an auditor would ask for |
|---|---|---|
| 1  Inventory & Control of Enterprise Assets | AD computer objects + agent inventory on endpoints | Inventory report dated last month |
| 2  Inventory & Control of Software Assets | Software list from endpoint agent | Approved software list |
| 4  Secure Configuration | Windows/Linux hardening baseline | Baseline document + scan results |
| 5  Account Management | MFA enforced for admins | MFA policy + AD report of admin accounts |
| 7  Continuous Vulnerability Management | Monthly scans of the web shop | Latest scan report + remediation ticket |
| 8  Audit Log Management | Windows event log forwarding + auditd on Linux | Log retention policy, sample searches |
| 11 Data Recovery | Nightly backups with quarterly restore test | Restore test log |
```

3. **Gap analysis:** for each row, mark `in place`, `partial`, or `missing`. Write one sentence per `missing`/`partial` item stating the risk of *not* doing it (link back to your risk register).

**Expected result:** a table whose gaps match the high-score rows in Exercise 2 — if they do not, one of the two exercises is wrong. Reconcile them.

## Exercise 4 — Scan a Linux VM with Lynis and OpenSCAP

### 4a. Lynis

```bash
sudo apt update && sudo apt install -y lynis        # Debian/Ubuntu
# RHEL family: sudo dnf install -y lynis

sudo lynis audit system
sudo lynis show warnings
sudo lynis show suggestions
```

**Interpreting the output:** read each `[WARNING]` with its suggestion. Common first-run findings: firewall not active, SSH root login permitted, no file-integrity tool, no automatic security updates. Apply 3 fixes, for example:

```bash
# Enable the firewall and allow SSH only
sudo ufw allow OpenSSH && sudo ufw --force enable     # Ubuntu
# Or on RHEL: sudo systemctl enable --now firewalld

# Harden SSH: disable root login
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Enable automatic security updates (Ubuntu)
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

Then re-run `sudo lynis audit system --quiet` and confirm the **hardening index rose**. Write two sentences: "which warnings remained and why are they acceptable (or not)?"

### 4b. OpenSCAP

Install content, scan against a CIS profile, and produce the report:

```bash
# RHEL/Rocky/Alma 9
sudo dnf install -y openscap-scanner scap-security-guide
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml | grep -A8 Profiles

sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --report /tmp/scap-report.html \
  --results /tmp/scap-results.xml \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# Debian/Ubuntu (package names vary by release; content ships under /usr/share/xml/scap/ssg/content/)
sudo apt install -y libopenscap8 ssg-debian ssg-base
oscap info /usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml
```

**Interpreting the output:**

1. Note the overall **score** and the count of **failed** rules.
2. Open `/tmp/scap-report.html` in a browser. Pick the **three highest-severity failures** and read their descriptions.
3. Choose one failure, fix it (the HTML report often links remediation; e.g., `chmod 600 /etc/shadow` style rules), and **re-run the scan** to confirm that rule now passes.
4. Save the HTML report and the `results.xml` as your "evidence artifact" folder: `~/eeda-evidence/`. In a real audit, these files are your deliverables.

**Expected result:** the score improves after remediation, and you can explain each remaining failure in one sentence of risk language ("this fails because X, which matters because Y; we accept/mitigate by Z").

## Common Mistakes & Tips

- **Policies without owners or review dates** — a policy nobody owns is not enforceable; always add the Owner and Review fields.
- **Risk registers that list vulnerabilities, not risks.** "Unpatched CMS" is a *vulnerability*; the *risk* is the business impact if it is exploited. Write the risk row as asset + impact.
- **Scores that never change.** Re-score the register after mitigation — that is how you prove controls work.
- **Skipping the reconcile step (Exercise 3 vs. 2).** If gaps and top risks do not line up, your analysis is inconsistent. Fix it before moving on.
- **Scanning without root or without the right content** — both tools silently degrade; verify with `sudo` and confirm the data stream matches your OS release.
- **Remediating everything blindly.** A scan is advisory: a rule that breaks a business app must be handled via tailoring + documented acceptance, not force-applied.

## Checklist / Self-test

- [ ] I wrote a complete AUP skeleton with version, owner, review date, and enforceable rules.
- [ ] My risk register has at least 6 rows with L×I scores, treatments, and owners.
- [ ] I chose an Implementation Group for Acme and can defend it in one paragraph.
- [ ] My CIS mapping includes at least 6 controls with concrete evidence an auditor would accept.
- [ ] My CIS gaps match the highest-scoring risks in my register.
- [ ] I ran Lynis, applied 3 fixes, and confirmed the hardening index rose.
- [ ] I ran an OpenSCAP scan, fixed one failing rule, re-scanned, and saved the reports as evidence.
- [ ] I can explain each remaining scan finding in one sentence of risk language.

## Further Resources

- [NIST CSF — Quick Start Guide](https://www.nist.gov/cyberframework) — how to communicate cyber risk to executives.
- [CIS Controls](https://www.cisecurity.org/controls) — control details and Implementation Group guidance.
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) — the configuration baselines behind many scan profiles.
- [OpenSCAP](https://www.open-scap.org/) — documentation for `oscap` and tailoring.
- [Lynis (CISOfy)](https://cisofy.com/lynis/) — hardening guides and sample reports.
