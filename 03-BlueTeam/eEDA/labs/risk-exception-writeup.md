# Risk Exception Writeup — Hands-On Lab

> eEDA · Labs — INE-Cybersecurity-Certifications-Guide

## Purpose

[07-vulnerability-and-patch-management](../methodology/07-vulnerability-and-patch-management.md) ends its patch cycle with the case every administrator meets: a finding you cannot fix on schedule. The professional answer is a **documented exception with a compensating control, a named owner, and an expiry date** — not silence, and not heroics.

This lab is the writing exercise for that document. You will pick a scenario, write the exception, defend the compensating control, name who accepts the risk, and set the review that makes the exception expire. The output is a one-page memo an auditor can read and a risk owner can sign.

**What this lab is not:** it is not a risk register (that is Exercise 2 of [security-policy-exercises](security-policy-exercises.md)) and it is not a scan report. A register row says *you know about the risk*; an exception says *you are deliberately not fixing it, here is what you did instead, and here is when this decision dies*.

## Lab Environment

- Your normal workstation for writing documents. No VM is required: this is a documentation lab.
- One scenario from the list below, or your own — with real constraints, not a hypothetical with no deadline.
- The exception structure you are filling comes from the method note's table (Finding, Applicable SLA, Reason not fixed, Compensating controls, Residual risk, Owner who accepts, Expiry/review date, Renewal history). Keep those field names; they are what an auditor looks for.
- Optional, if you have a Linux VM from the other labs: a rule or a check that *proves* your compensating control is actually running (section 5).

## Scenario Bank

Pick one. Each has a genuine reason the fix is not a patch, and a genuine deadline.

| # | Scenario | The constraint that forces an exception |
|---|---|---|---|
| 1 | A vendor-supported medical imaging appliance at a clinic, Windows Server 2016, last vendor firmware 14 months old | The vendor's contract forbids OS-level changes; patching voids support on a device with patient data |
| 2 | An end-of-life web server, Ubuntu 18.04, still serving an internal reporting tool | The application was built for that release and the business has not funded the migration |
| 3 | A production database cluster pinned to a version with a known CVE | The upgrade breaks a stored-procedure dependency, and the change window for the ERP is quarterly |
| 4 | A line-of-business application on a shop-floor PC, no vendor support, used 24/7 | Taking it down costs more than the risk it carries, and there is no replacement in the budget this year |
| 5 | An internet-facing VPN concentrator that cannot be taken offline without cutting remote work | The fix requires a firmware change and a maintenance window nobody will approve this quarter |

Use the fictional company from the other labs (Acme Widgets Inc.) and keep the same style: illustrative identifiers, no real CVE numbers unless you look one up and cite the source.

## Exercise 1 — Decide Whether an Exception Is the Right Answer

Not every unpatched finding deserves an exception. Some deserve a fix, some deserve removal, and writing an exception for those is how an estate accumulates accepted risk nobody remembers accepting.

Classify your scenario, then your three neighbouring ones:

| Decision | When it is the correct answer | What it costs |
|---|---|---|
| **Fix** | The patch exists, the window exists, the business impact is manageable | Change effort, a test cycle, a rollback plan |
| **Isolate or remove** | The service is not needed, or can be moved behind a control that closes the exposure | Politics more often than technology |
| **Compensating control** | The fix is genuinely blocked, and something else measurably reduces the risk | The control itself becomes a permanent operational cost |
| **Exception with expiry** | The fix is blocked *and* the compensating control is real and monitored | A document, a name, and a review date |

**Expected result:** one paragraph stating which decision you chose for your scenario and why the three other options fail — for example, why "isolate" is not available for a device that must stay on the clinical network.

## Exercise 2 — Write the Exception Memo

Fill every field. The blank template:

```markdown
## Risk Exception — <ID>

| Field | Content |
|---|---|
| Finding | |
| Affected asset | |
| Applicable SLA | |
| Reason not fixed | |
| Compensating controls | |
| Residual risk | |
| Owner who accepts | |
| Expiry / review date | |
| Renewal history | |
| Date raised / raised by | |
```

Rules for the fields that people write badly:

- **Finding** — identifier, the asset, and the date it was detected. "Unpatched server" is not a finding.
- **Applicable SLA** — which patch SLA *would* apply if it were patchable (for example "critical, 14 days"). This is what makes the exception comparable with everything else you are not excepting.
- **Reason not fixed** — technical (vendor constraint, compatibility), operational (outage), or commercial. Name the specific blocker, not "business reasons".
- **Compensating controls** — what reduces likelihood or impact *meanwhile*, and how you know it is running. "Network segmentation plus an alert on exploit attempts" is a control; "we monitor it" is not.
- **Residual risk** — the risk that remains, in business language: what could happen to the business, not which CVE remains.
- **Owner who accepts** — a named business or risk owner. **Not** the engineer who found it, and not "IT". If the only name you can write is yours, the exception is not complete.
- **Expiry / review date** — mandatory. An exception without an expiry is a permanent acceptance that nobody re-approved.
- **Renewal history** — each renewal recorded with its date and justification. A third renewal is the signal to escalate as a funded project, not to renew again.

**Expected result:** a memo of one page or less where every field is filled and none of them says "N/A" or "TBD".

## Exercise 3 — Defend the Compensating Control

A compensating control is a claim, and claims need evidence. For each control you listed, state what it does and how you would prove it:

| Compensating control | Which part of the risk it reduces | How you prove it is running | What it does *not* cover |
|---|---|---|---|
| Network segmentation (VLAN/ACL) | Likelihood — the vulnerable service is no longer reachable from the user network | Firewall rule set with the rule identified, plus a reachability test from a user subnet | Anything that reaches the service from an allowed source |
| Detection rule on exploit attempts | Impact — earlier detection, faster containment | The rule's query or signature, and a test event that fired it | A zero-day the rule does not match |
| Restricted administrative access | Likelihood and impact — fewer accounts can abuse it | Access review output naming the accounts and their owners | Credential theft from an allowed administrator |
| Backup and tested restore | Impact — recovery is possible | Restore test record with the date and the RTO it proved | Data exfiltration, and downtime during the restore window |

Two tests apply to every row: **would this control still work if the attacker knew about it?** and **does it reduce likelihood or impact — or does it only make the risk feel handled?**

**Expected result:** a table where every control names its evidence and its blind spot. A control with no blind spot is a control you have not thought about.

## Exercise 4 — Name the Owner and Set the Expiry

Write the acceptance decision as if you were the risk owner reading it for the first time:

1. **Who accepts it.** Name the role and the person (for example "Finance Director, J. Ruiz" — a role with budget, not the administrator). State in one sentence what they are accepting: "the imaging appliance may be exploited through an unpatched remote-code-execution path, with patient data at risk, until 31/12/2026".
2. **Why they are the right owner.** They own the service or the budget that could fix it. If they own neither, you have the wrong name.
3. **The expiry and the review.** A date, and what happens on that date: close the exception, renew it with fresh justification, or escalate to a project. Write the review as a calendar item, not an intention.
4. **The escalation path.** What happens at the second renewal? At the third? The method note is explicit that a third renewal means the exception should become a funded project — say who you escalate to.

**Expected result:** a signed-decision paragraph with a name, a date, and a consequence. If a hypothetical owner could read it and say "I never agreed to that", it is not finished.

## Exercise 5 — Prove the Control, Then File the Evidence

An exception is a document plus a running control. Close the loop:

1. **Prove one control is live.** If you have the Linux VM from [security-policy-exercises](security-policy-exercises.md), a persistent audit rule is the cheapest real proof. Confirm the rule is loaded *before* you claim the control exists:

```bash
# Syntax reference -- not executed in this module; confirm on your build
sudo auditctl -l | grep -i <your-key>     # is the rule actually loaded?
sudo ausearch -k <your-key> -ts today -i  # does anything reach the log?
```

For a segmentation claim instead, the evidence is the firewall rule set plus a reachability test from the subnet that should be blocked. For a detection claim, it is the rule itself plus one test event that fired it.

2. **File it where the auditor will look.** One folder per exception, named consistently, containing: the memo, the control evidence, the scan finding it came from, and the renewal history. Suggested shape:

```text
evidence/exceptions/
  EXC-2026-014-imaging-appliance/
    01-exception-memo.md
    02-scan-finding.txt
    03-segmentation-rules.txt
    04-detection-rule-and-test-event.txt
    05-review-log.md
```

3. **Report it.** Add the exception to whatever list your organisation reviews — the risk register, the patch SLA report, or the weekly operations meeting. An exception nobody reports on is indistinguishable from an oversight.

**Expected result:** a folder with the memo, at least one piece of control evidence, and a review date that exists somewhere other than your head.

## Exercise 6 — Adversarial Review

Swap memos with a peer, or review your own after a day away. Attack the document with these questions and record what you had to change:

- **Is the residual risk in business language?** "Unpatched CVE-XXXX" describes a technical fact; "the clinic's patient images could be stolen or held to ransom" describes a risk.
- **Is the compensating control verifiable by someone else?** Could an auditor reproduce your evidence without asking you how?
- **Does the owner own something?** Budget, service, or both. If not, the acceptance is fictional.
- **Does the expiry have teeth?** On that date, does something happen automatically — or does the exception quietly roll forward?
- **Would the exception survive the thing going wrong?** If the vulnerability is exploited next month, does this document show a defensible decision, or does it read like an excuse?
- **Is the reason technical or emotional?** "The vendor forbids it" is a fact; "we never got round to it" is a resourcing gap that belongs in a project proposal.

**Expected result:** a list of changes you made, and one honest sentence about what remains weak in your memo.

## Common Mistakes & Tips

- **Writing the exception as a scan finding with a date on it.** The finding explains *what* is wrong; the exception explains *why it stays wrong* and what compensates.
- **Accepting the risk yourself.** An administrator cannot accept risk on the business's behalf. If no business owner will sign, the correct action is to escalate, not to file the exception anyway.
- **"We monitor it" as a compensating control.** Name the rule, the alert destination, and who acts on it. Unrouted monitoring is not a control.
- **An expiry date that nobody owns.** The date must belong to a recurring review with a named reviewer, or it passes silently.
- **Forgetting the renewal history.** The third renewal is the point where the organisation decides to fund the fix; without history, renewals look like first decisions forever.
- **Compensating controls that reduce neither likelihood nor impact.** A quarterly reminder to "be careful" is not a control. Test each one against that question.
- **Losing the reasoning.** Six months later, the memo *is* the reasoning. Write for the reviewer who has no memory of the decision.
- **Tip**: keep one worked exception in your notes as a template, with the fields and the tone — the second one takes twenty minutes, and consistency between exceptions is what makes them auditable as a set.

## Checklist / Self-Test

- [ ] I chose a scenario with a real constraint and a real deadline, not a hypothetical.
- [ ] I can state why my scenario is an exception rather than a fix, an isolation, or a removal.
- [ ] My memo fills every field of the exception structure, with no "N/A" or "TBD".
- [ ] My residual risk is written in business language, not in CVE numbers.
- [ ] Every compensating control I claimed names how it is proven and what it does not cover.
- [ ] I named a business or risk owner with the authority to accept the risk.
- [ ] My exception has an expiry date and a review that exists outside my head.
- [ ] I stated the escalation path for the second and third renewal.
- [ ] I filed the memo, the finding, and at least one piece of control evidence in one place.
- [ ] I found at least one weakness in my own memo during adversarial review and fixed it.

> **Verification:** unverified syntax reference — not run; `auditctl`, `ausearch` and `aureport` are not installed on the machine used for this pass (WSL Ubuntu 24.04.4 has `journalctl`, systemd 255, and nothing else from the audit toolchain), so the two commands in Exercise 5 remain a shape to confirm on a build that has `auditd`. The rest of the lab is a document-writing exercise and needs no execution.

## Further Resources

- [NIST SP 800-30 Rev. 1](https://csrc.nist.gov/pubs/sp/800/30/r1/final) — risk assessment, including risk response and acceptance.
- [NIST SP 800-40 Rev. 4](https://csrc.nist.gov/pubs/sp/800/40/r4/final) — enterprise patch management, including the handling of exceptions.
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001) — Annex A 8.8 (management of technical vulnerabilities) and the treatment-of-risk expectations behind acceptance.
- [CIS Controls](https://www.cisecurity.org/controls) — control 7 (Continuous Vulnerability Management) and its guidance on exceptions and remediation windows.
- [FIRST CVSS](https://www.first.org/cvss/) — how a finding's severity is scored, which is the input to prioritisation, not the exception itself.

---

> ⚠️ Personal study notes. Scenario identifiers are illustrative. Commands marked as syntax reference were not executed here; no NDA-protected or actual exam content is included.
