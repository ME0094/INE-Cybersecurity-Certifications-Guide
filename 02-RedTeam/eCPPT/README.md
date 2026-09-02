# eCPPT — Certified Professional Penetration Tester

> 02-RedTeam · eCPPT module — INE-Cybersecurity-Certifications-Guide (English, personal study notes)

The **Certified Professional Penetration Tester (eCPPT)** is INE Security's
professional-level, hands-on penetration testing certification. It sits above
the entry-level eJPT and is designed for people who already understand the
basics and want to prove they can run a realistic, end-to-end offensive
engagement: breaking into a corporate network, moving through it like an
attacker, and writing a report that a client (or an examiner) can actually act
on. This module is the companion study guide: methodology, tool references,
guided lab scenarios, and cheatsheets that mirror how the courseware and
practical labs teach the material.

> ⚠️ **Personal study project — not affiliated with or endorsed by INE Security.**
> This repository contains only original notes plus links to public
> documentation. It does **not** include exam questions, answers, walkthroughs
> of the live exam, or any NDA-protected material. Practice only inside
> environments you own or are explicitly authorized to test.

## What the eCPPT covers

The certification validates **professional practical penetration testing**,
with strong emphasis on **corporate networks and Active Directory**. The
publicly advertised scope is broad:

- **Networking and lab fundamentals** — TCP/IP, routing, switching, subnets,
  common protocols (DNS, SMB, Kerberos, HTTP/HTTPS), and how they behave inside
  a Windows domain.
- **Reconnaissance and enumeration** — host discovery, port and service
  scanning, service enumeration, and Active Directory enumeration (users,
  groups, computers, shares, GPOs).
- **Exploitation and initial access** — finding and exploiting weaknesses in
  services and applications to obtain a foothold on a host.
- **Post-exploitation on Windows** — privilege escalation (service
  misconfigurations, token abuse, vulnerable software), credential harvesting,
  and persistence concepts.
- **Active Directory attacks** — Kerberoasting, AS-REP roasting, ACL abuse,
  delegation abuse, pass-the-hash/pass-the-ticket, and domain privilege
  escalation up to Domain Admin / full domain compromise.
- **Lateral movement and pivoting** — moving from one host to another,
  tunneling and pivoting through multi-network environments (chained hosts,
  restricted segments, port forwarding).
- **Reporting** — a professional penetration test report is a deliverable of
  the certification process: executive summary, findings, evidence, risk
  ratings, and remediation advice.

Verify the current syllabus, version naming (v2/v3), objectives, and exam
policies directly on the INE Security website — these change over time.

## Skills you build

- Think in **attack chains**, not single exploits: enumerate → foothold →
  escalate → move laterally → reach the crown jewels → report.
- Read a network like an attacker: which protocols reveal users, shares,
  credentials, and trust relationships.
- Work fluently with the offensive toolbox: Nmap, Metasploit, PowerShell,
  BloodHound/SharpHound, Mimikatz, Impacket, and tunneling tools.
- Enumerate and attack **Active Directory** methodically using both native
  Windows tooling and attacker tooling.
- Operate **professionally**: scoping, authorization, notes, evidence
  handling, and clear written reporting.

## How to use this module

Each certification folder in this repository follows the same layout, and the
folders are meant to be used in order:

- **[methodology/](methodology/)** — numbered phases in working order:
  `01-active-directory`, `02-lateral-movement`, `03-privilege-escalation`,
  `04-persistence`, `05-reporting`. Read these first to understand the
  *process* before touching tools.
- **[tools/](tools/)** — reference guides for the tools you will use over and
  over: [BloodHound + SharpHound](tools/bloodhound-guide.md),
  [PowerShell essentials](tools/powershell-essentials.md), and the
  [Mimikatz reference](tools/mimikatz-reference.md) (lab-only).
- **[labs/](labs/)** — hands-on practice: build your own
  [Active Directory lab](labs/ad-lab-setup.md), then run
  [guided attack simulations](labs/attack-simulations.md) against it.
- **[cheatsheets/](cheatsheets/)** — fast lookup material:
  [Active Directory commands](cheatsheets/ad-commands.md).

Suggested flow: read the methodology notes → skim the tool guides → build the
lab → run the attack simulations → use the cheatsheets during practice and
review.

## Practical exam context (public information only)

The eCPPT is a **practical, performance-based exam**: instead of multiple
choice, you work hands-on against realistic corporate network environments
delivered through the INE platform. Candidates are expected to perform the full
penetration testing cycle — reconnaissance, exploitation, Active Directory
attacks, lateral movement across multiple hosts/networks, and privilege
escalation to domain-level access — and to deliver a **written penetration
test report** that is itself evaluated. The exam is proctored, runs under a
detailed rules-of-engagement/NDA, and only in-scope systems may be touched.

None of the specific exam content is reproduced here. The best preparation is
the official training, plus the methodology, tool fluency, and lab repetition
in this module.

## Study roadmap

A suggested order of attack for this module:

1. **Foundations week** — review the methodology phases; make sure Nmap,
   Metasploit, and basic Windows administration feel routine.
2. **Tool fluency** — work through `tools/` guides; practice PowerShell and
   BloodHound until enumeration is second nature.
3. **Build the lab** — complete `labs/ad-lab-setup.md` and take a clean
   snapshot. A broken lab blocks every later scenario; fix it early.
4. **Attack the lab** — run `labs/attack-simulations.md` end to end, taking
   notes as if you were on an engagement.
5. **Consolidate** — rebuild the cheatsheets from memory; drill the
   self-tests; re-run scenarios without looking at the steps.
6. **Report writing practice** — write up one scenario as a mini report
   (findings, evidence screenshots, risk, remediation).

## Checklist / Self-test

- [ ] Read all five methodology phases and summarize each in my own words
- [ ] Practice PowerShell essentials until I can enumerate without a browser
- [ ] Run BloodHound collection and explore the graph with Cypher queries
- [ ] Build the AD lab and take a clean baseline snapshot
- [ ] Complete at least four attack simulations from scratch
- [ ] Drill the ad-commands cheatsheet until command syntax is automatic
- [ ] Write one practice penetration test report from a lab run
- [ ] Review the official exam objectives and confirm current version/policies on inecp.com

## Common mistakes & tips

- **Skipping methodology for tooling** — knowing `mimikatz` flags without
  knowing *when* to use them fails engagements. Always tie a tool to the phase
  it serves.
- **Untracked lab state** — without snapshots and notes you cannot reproduce a
  finding. Snapshot before every scenario and log every command.
- **Noise over signal** — enumeration is infinite; time-box it and let the
  attack chain (not curiosity) decide what to enumerate next.
- **Practicing only "the exploit"** — the exam-relevant skill is chaining
  phases cleanly, not memorizing one technique in isolation.
- **Ignoring the defensive view** — knowing how logging, AMSI, Credential
  Guard, and EDR react to your tooling makes you a better (and more careful)
  operator.

## Further resources

- [INE Security — official site and certification catalog](https://ine.com)
- [eJPT module of this repository](../../01-Fundamentals/eJPT/README.md) — fundamentals prerequisite
- [MITRE ATT&CK — Enterprise matrix](https://attack.mitre.org)
- [Microsoft Learn — Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)
- [HackTricks — Active Directory methodology](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology.html)
