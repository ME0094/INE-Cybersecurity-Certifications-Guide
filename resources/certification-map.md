# Certification Map — How the INE Security Credentials Relate

> **This page is the author's synthesis, not an official INE document.** It exists because
> the official catalogue lists certifications one by one and never answers the question a
> candidate actually has: *"I know where I am — which of these do I take next, and what
> does each one really prove?"*
>
> Nothing here is exam logistics (no question counts, durations, prices, passing scores or
> official domain lists). Those change, belong to INE, and are linked per certification in
> [`official-links.md`](official-links.md).

## 1. The four areas at a glance

| Area | Credential | What it proves, in one line | Typical starting point for |
|---|---|---|---|
| Fundamentals | [eJPT](../01-Fundamentals/eJPT/README.md) | You can run a small, end-to-end penetration test against live hosts and show your evidence. | Anyone with no professional security experience. |
| Red Team | [eCPPT](../02-RedTeam/eCPPT/README.md) | You can operate in an enterprise network: Active Directory, pivoting, privilege escalation, reporting. | People who already passed eJPT or have real sysadmin/networking background. |
| Red Team | [eWPT](../02-RedTeam/eWPT/README.md) | You can find and exploit web vulnerabilities methodically, application by application. | Web developers, backend engineers, AppSec newcomers. |
| Red Team | [eWPTX](../02-RedTeam/eWPTX/README.md) | You can chain web weaknesses and bypass the controls standing in front of them. | People who already test web apps daily and want the hard cases. |
| Red Team | [eMAPT](../02-RedTeam/eMAPT/README.md) | You can assess Android and iOS applications: traffic, storage, logic, and the app's own code. | Mobile developers and pentesters moving into mobile. |
| Blue Team | [eEDA](../03-BlueTeam/eEDA/README.md) | You can administer defences: governance, risk, compliance, hardening and evidence that controls work. | Sysadmins and IT staff moving to the defensive side. |
| Blue Team | [eSOC](../03-BlueTeam/eSOC/README.md) | You can triage alerts and investigate at Tier 1: what fired, is it real, what next. | First SOC job, or career changers entering a SOC. |
| Blue Team | [eCIR](../03-BlueTeam/eCIR/README.md) | You can run an incident end to end: preserve, contain, eradicate, recover, communicate. | Analysts who already triage and want to own incidents. |
| Blue Team | [eCDFP](../03-BlueTeam/eCDFP/README.md) | You can acquire, analyse and report digital evidence that stands up to scrutiny. | People drawn to forensics, malware and detailed evidence work. |
| Blue Team | [eCTHP](../03-BlueTeam/eCTHP/README.md) | You can hunt proactively for what detection missed, then turn findings into detections. | Analysts who are bored of the queue and want to look for what nobody wrote a rule for. |
| Emerging | [eAIS](../04-Emerging-Technologies/eAIS/README.md) | You understand the attack surface of AI systems and can test and defend it. | Anyone whose product now contains a model, a prompt or an agent. |
| Emerging | [eIAMA](../04-Emerging-Technologies/eIAMA/README.md) | You can implement and operate identity and access management, and reason about its architecture. | Identity admins, cloud engineers, IAM/Okta/Entra practitioners. |

## 2. Choosing a first certification

| Your situation | Start with | Then |
|---|---|---|
| No security experience, want a hands-on first credential | **eJPT** | Branch by taste: **eWPT** (web) or **eCPPT** (network) |
| IT/sysadmin background, want to defend rather than attack | **eEDA** | **eSOC**, then **eCIR** |
| Already in a SOC, want to go deeper | **eSOC** | **eCIR** or **eCTHP** (response vs. hunting), then **eCDFP** |
| Web developer moving to security | **eWPT** | **eWPTX** when the basics are automatic |
| Mobile developer | **eMAPT** | — (it is the only mobile credential here) |
| Cloud or identity engineer | **eIAMA** | **eAIS** if your stack includes AI features |
| Building or shipping AI features | **eAIS** | **eIAMA** for the identity side of the same problem |

## 3. Overlaps you should know about before paying twice

- **eJPT → eCPPT.** Same discipline, different scale. eJPT is one network and a handful of
  hosts; eCPPT assumes an enterprise with Active Directory, multiple segments and pivoting.
  Studying eCPPT does not require re-learning eJPT, only going wider.
- **eWPT → eWPTX.** Same targets, harder cases. eWPTX is about chaining and bypassing, not
  about new vulnerability classes. If single textbook bugs are still hard for you, eWPTX is
  premature.
- **eSOC → eCIR → eCDFP → eCTHP.** Four moments of one lifecycle, not four separate
  careers. The SOC sees the alert, response owns the incident, forensics explains what
  actually happened, and hunting looks for what none of them were told to look for. In this
  repository each module links the others where they meet.
- **eEDA → everyone.** Governance, risk and compliance material reappears inside every
  blue-team role: it is the vocabulary you use to justify a control to someone who is not
  an engineer.
- **eIAMA → eAIS.** Two sides of modern application security: who may act (identity) and
  what the AI is allowed to do on their behalf (AI systems). Both assume you can read
  protocol traces and think in terms of trust boundaries; neither teaches the other.

## 4. Study order that works, and the order that does not

A sequence that compounds, rather than a checklist:

1. **One offensive foundation** (eJPT) — attacks teach you what the logs will contain.
2. **One defensive foundation** (eEDA or eSOC) — controls and triage teach you what the
   attacks leave behind.
3. **Go deep on one side** — eCPPT/eWPTX for offence, eCIR/eCDFP/eCTHP for defence.
4. **Add the emerging layer** (eAIS, eIAMA) when your actual work touches it.

The order that wastes time: collecting credentials in one area without ever running the
labs, and studying the emerging certifications before you can read a packet capture or a
Windows event log. The AI and identity material assumes both.

## 5. What none of these credentials replaces

- **A lab that you can rebuild.** Every module here pushes you to build disposable
  environments; certificates expire, habits do not.
- **Being able to write.** All twelve share one hard requirement: explain what you found,
  how you know, and what you recommend. Every module's reporting phase is there for that
  reason.
- **Keeping current on your own.** INE updates certifications (this repository tracks the
  updates it can verify in each module's version note). No static guide, this one included,
  stays right on its own.

---

> Found an inaccuracy in this synthesis — a credential described wrongly, an overlap that
> is not real, a decision path that misleads? Open an issue. This page is opinion, and
> opinion is exactly the part that should be challenged.
