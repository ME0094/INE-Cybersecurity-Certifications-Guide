# Phase 05 — Reporting

> eCPPT · Methodology — INE-Cybersecurity-Certifications-Guide

## Purpose

A penetration test is only as good as its report. Findings that are not reproducible, rated, and explained clearly will not be fixed — or worse, will be disputed. This phase covers how to structure a professional report, collect and annotate evidence, rate severity with CVSS, write risk and remediation language that survives review, and target executive vs. technical audiences. These habits also make your *exam* deliverables defensible: any report you hand in should read like one a client could act on.

## Report Structure (the standard skeleton)

```text
1.  Executive summary        — plain-language verdict, top risks, headline metrics
2.  Scope & methodology      — what was tested, from where, when, with which rules
3.  Findings overview        — ranked table: finding | asset | severity | status
4.  Detailed findings        — one section per finding (template below)
5.  Remediation roadmap      — prioritized fixes, short- and long-term
6.  Appendix                 — raw evidence, tools/versions, IOCs, timeline
```

The **detailed finding template** that keeps reviewers happy:

```text
Finding:      Weak service path allows local privilege escalation
Asset:        SRV-FILES (10.10.10.30) — Windows Server 2019
Severity:     High (CVSS 7.8)
Status:       Confirmed
Summary:      One sentence on the impact if exploited.
Affected:     Exact host/account/configuration details.
Evidence:     Reproducible steps with command + trimmed output (see Appendix A).
Impact:       What an attacker can actually do with it.
Remediation:  Short-term fix + long-term control, with an owner suggestion.
References:   MITRE ATT&CK / vendor advisory where applicable.
```

## Evidence Collection and Annotation

Good evidence is *reproducible*, *timestamped*, and *attributed*.

```text
# Evidence hygiene rules
- Record date/time (with timezone!) and hostnames for every action.
- Keep raw tool output AND a readable summary; screenshots for UI-dependent steps.
- Annotate screenshots: red box + caption ("user 'jdoe' is a member of Domain Admins").
- State the exact command, tool, and version (nmap 7.94, Impacket 0.11.0, mimikatz 2.2.0).
- Distinguish observed fact from inference: "hash obtained" vs. "likely same password reused".
- Save evidence files with a naming scheme: YYYY-MM-DD_host_finding_tool.txt
```

```bash
# Make your terminal output self-documenting
script -a engagement_2025-06-01.log          # tee everything to a typescript
nmap -sV -Pn -oA scope_10.10.10.0-24 10.10.10.0/24
# Expected outcome: scope_10.10.10.0-24.nmap/.gnmap/.xml + full transcript
```

Evidence that cannot be reproduced (no command, no output, no timestamp) will be challenged — treat every claim as if a skeptic will re-run it.

## Severity Ratings (CVSS)

Use **CVSS v3.1** (or v4.x where the client mandates it) for the base score, then map to a qualitative band. The vector string is the defensible part.

```text
# Example vector for a service-path privesc (local attacker, low complexity,
# no privileges, no interaction, high confidentiality/integrity/availability impact)
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H  ->  Base Score 7.8 (High)

# Qualitative mapping (common convention)
0.0         None
0.1 - 3.9   Low
4.0 - 6.9   Medium
7.0 - 8.9   High
9.0 - 10.0  Critical
```

Common CVSS traps: rating a *domain* compromise as if it were a *single host* issue (check the scope/changed-system flag and the real impact), and inflating scores because the finding "feels" bad. Score what the vector says, then use the executive narrative for business impact.

## Risk and Remediation Language

- **Risk = likelihood × impact.** State both: "A non-privileged domain user can become Domain Admin in two steps; observed in 4 of 5 OUs; impact is full domain takeover."
- **Write remediation that a team can execute:** avoid "harden the environment." Prefer: "Enforce SMB signing via GPO; enable LAPS for all workstation local-administrator passwords; reset the krbtgt account twice after removing the attacker's foothold."
- **Prioritize:** quick wins (configuration) before long-term control improvements (architecture, monitoring), and mark which fixes an attacker would notice immediately.
- **Don't promise absolutes:** "reduces the likelihood" beats "prevents the attack"; "validated in the lab" beats "tested in production."

## Executive vs. Technical Summaries

| Audience | Executive | Technical |
|---|---|---|
| Reads | Leadership, risk owners | Engineers, admins, SOC |
| Wants | "Are we breached? How bad? What do we do?" | Exact repro, commands, root cause |
| Format | 1–2 pages, no jargon, charts | Full detail, command blocks, logs |
| Language | Business impact: "an attacker could read customer data and alter invoices" | "GenericAll on user object → ResetPassword + targeted Kerberoast" |
| Rule | If execs can't explain it, rewrite it | If engineers can't reproduce it, rewrite it |

Never write the executive summary *after* the findings as an afterthought: draft it last but review it first — it is the only page many people will read.

## Writing Habits That Make Reports Defensible

- **Verifiable, not vivid:** "the account had administrative rights on 5 hosts" (evidence-backed) instead of "massive admin exposure across the network."
- **Separate fact, inference, and speculation** in every finding — a reviewer should never guess which is which.
- **Quote scope:** list authorized assets, exclusions, and any limitations ("out-of-scope: HR subnet; testing window 02:00–06:00 UTC") so findings are not over-generalized.
- **Handle false positives honestly:** if a finding was disproved during validation, keep the note — it proves you tested, not just scanned.
- **Consistent naming:** one name per host (FQDN) and one severity scale across the whole document; define acronyms at first use.
- **Peer-review pass:** have someone re-run your top-3 commands from the report alone; if they can't reach the finding, the report fails.
- **Version and sign:** report version, author, reviewer, date, and distribution list — professional deliverables are controlled documents.

## Common Mistakes & Tips

- **Findings table vs. detailed findings drift:** keep one source of truth; a table row that contradicts its own detail section destroys credibility.
- **Screenshots without context:** a raw terminal image proves nothing; caption it and link the command in the appendix.
- **CVSS copy-paste errors:** regenerate the score from the vector; state the vector so it can be checked.
- **Skipping "what good looks like":** after remediation, tell the client what a re-test should show — it makes the report actionable.
- **Writing for yourself, not the reader:** the report's job is to transfer *your* understanding; if a section only you can follow, cut or rewrite it.
- **Forgetting the appendix:** put long outputs, tool versions, and IOCs there; keep the body readable.

## Checklist / Self-test

- [ ] My report follows a standard structure (exec summary → methodology → findings → roadmap → appendix).
- [ ] Every finding has a severity with an explicit CVSS vector and a consistent qualitative band.
- [ ] Every technical claim maps to a reproducible command whose trimmed output is in the evidence/appendix.
- [ ] Screenshots are annotated (host, time, caption) and reference the exact step they document.
- [ ] Executive summary states impact in business terms and fits on ~2 pages.
- [ ] Remediation is concrete, prioritized, and distinguishes short-term fixes from long-term controls.
- [ ] Scope, limitations, and tools/versions are documented; false positives are acknowledged.
- [ ] A peer can re-run the top findings from the report alone and reach the same result.

## Further Resources

- FIRST — CVSS specification and calculator (v3.1/v4.0): https://www.first.org/cvss/
- NIST — CVSS and vulnerability severity guidance: https://nvd.nist.gov/vuln-metrics/cvss
- MITRE ATT&CK — technique IDs for referencing findings: https://attack.mitre.org/
- OWASP — Writing a penetration testing report (WSTG reporting guidance): https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger — Reporting and methodologies in web testing (transferable report skills): https://portswigger.net/web-security
- SANS — Penetration testing report writing guidance (posters/papers section): https://www.sans.org/
