# eJPT — Junior Penetration Tester

> `01-Fundamentals/eJPT` · INE-Cybersecurity-Certifications-Guide
>
> Status: study module. Methodology notes, tool references, lab guides, and command
> cheatsheets for preparing the **eJPT (Junior Penetration Tester)**.

The eJPT is INE Security's **entry-level, hands-on penetration testing** certification. It
measures whether you can perform a basic external/internal pentest against live lab
targets: discover hosts, enumerate services, exploit known public vulnerabilities, and
collect evidence. Everything in this module is public knowledge plus your own lab
practice — **no exam content or NDA-protected material** is included.

## What the eJPT certification covers

- **Networking fundamentals** needed to understand addressing, subnets, and services.
- The **penetration testing process**: reconnaissance → enumeration → exploitation →
  post-exploitation, plus basic pivoting concepts.
- **Information gathering** with tools such as Nmap, banner grabbing, and web enumeration.
- **Vulnerability assessment**: mapping discovered services and versions to known,
  public vulnerabilities (CVEs, Exploit-DB).
- **Exploitation**: using Metasploit against intentionally vulnerable targets.
- **Web application basics**: introductory issues such as weak authentication, file
  uploads, and command injection.
- **Host and network attacks** on a small internal network similar to a VPN lab.

## Target audience

- Beginners who want a first, credible, practical pentesting credential.
- IT/networking professionals moving toward offensive security.
- Students who learn better **by doing** than by memorizing theory.

The eJPT is a common first step before mid-level practical courses such as the eCPPT.

## Recommended background

- Comfort with the **Linux command line** (navigation, pipes, redirection, permissions).
- Basic **TCP/IP knowledge**: IP addresses, subnets, well-known ports (21, 22, 80, 443,
  445, 3306), TCP vs UDP.
- A rough idea of what a **web server** and an **operating system** are.
- No prior pentesting experience is required — the official course and this module build
  from zero.

If the command line still feels foreign, spend a few days inside the lab described in
`labs/lab-setup-guide.md` before starting the methodology notes.

## Exam format (in general public terms)

The eJPT is **practical and hands-on**. In broad public terms:

- You connect **over VPN** to an exam network with live, intentionally vulnerable targets.
- You answer a set of questions by **actually performing** the related tasks on those
  targets (scanning, enumerating, exploiting, collecting evidence).
- The exam is **time-boxed**: a fixed time window, so time management and note-taking
  are part of the skill being tested.
- Scoring is based on correct answers backed by the evidence you gather during the exam.

The workflow matters more than any specific machine. If you can complete the drills in
`labs/practice-scenarios.md` against your own lab, you are training exactly the right
muscle. Do **not** look for "exam dumps" — they violate the NDA and defeat the purpose.
Always confirm current public logistics (price, duration, rules) on the official INE
Security page, since those details can change.

## Certification version and recent updates

INE Security announced an **updated eJPT** on **31 March 2026**, with "expanded web
app testing, recon training, and offensive AI": more web application testing,
reconnaissance, and offensive AI. In the announcement's own words: "Enhanced training
and updated exam deliver stronger alignment between learning and real-world skills".

- Official announcement:
  <https://ine.com/newsroom/ine-security-launches-updated-ejpt-certification-with-expanded-web-app-testing-recon-training-and-offensive-ai>
- Certification directory: <https://ine.com/certifications>
- eJPT product page: <https://ine.com/security/certifications/ejpt-certification>

This module describes the eJPT in general public terms. **Exam logistics — syllabus,
duration, scoring, and rules — must always be confirmed on the official INE Security
page**, because those details change and are not reproduced in these notes.

## Skills you build

- Planning and scoping a small, authorized pentest inside a lab.
- Host discovery and service/version identification with **Nmap**.
- Banner grabbing, web directory enumeration, and service-specific enumeration.
- Matching services to known public vulnerabilities.
- Exploiting with **Metasploit** and managing meterpreter sessions.
- Manual shells and file transfers with **Netcat/Ncat**.
- Basic post-exploitation: what to run, what to look for, what to record.
- Basic routing/pivoting concepts to reach internal segments.
- Organized note-taking and evidence collection.

## Module layout — how to use this folder

| Folder / file | What it is for |
|---|---|
| `methodology/` | Five numbered phases in working order: `01-reconnaissance`, `02-enumeration`, `03-exploitation`, `04-post-exploitation`, `05-pivoting` |
| `tools/nmap-cheatsheet.md` | Nmap: host discovery, scans, NSE, output, timing |
| `tools/metasploit-basics.md` | Metasploit: msfconsole, payloads, handlers, DB, sessions |
| `tools/netcat-essentials.md` | Netcat/Ncat: shells, file transfer, ncat extras (SSL, keep-open) |
| `labs/lab-setup-guide.md` | Build your practice lab (Kali + vulnerable VMs) |
| `labs/practice-scenarios.md` | Guided scan-to-shell drills with expected outcomes |
| `cheatsheets/commands-reference.md` | One-page command reference organized by phase |

**Suggested order:** skim `methodology/01-reconnaissance.md` and `02-enumeration.md` →
build the lab with `labs/lab-setup-guide.md` → work through
`labs/practice-scenarios.md` with the `tools/*` pages open → consolidate everything with
`cheatsheets/commands-reference.md`.

## Suggested study path

1. Build the lab: Kali attacker + Metasploitable 2 + DVWA
   (`labs/lab-setup-guide.md`).
2. Read methodology phases 01–05 and repeat each phase on a live target.
3. Complete the guided scenarios in `labs/practice-scenarios.md` **in order**.
4. Re-do each scenario from memory, then compare with the notes.
5. Time-box yourself: aim to finish each drill faster on the second pass.
6. Chain drills once they feel easy: scan → exploit → post-exploit → pivot.
7. Keep a notes template per engagement (IPs, open ports, versions, creds, commands).

## Common Mistakes & Tips

- **Testing without authorization.** Only attack your own VMs or platforms that grant
  permission (VulnHub, TryHackMe, Hack The Box). Never scan your real LAN.
- **Skipping enumeration.** Most time should go to enumeration — firing exploits blindly
  is a beginner's trap.
- **Not writing notes.** Exams reward evidence and organization. Record IPs, ports,
  versions, credentials, and commands as you go.
- **Wrong target IPs.** Check `ip a` and `ip route` before every engagement and write the
  target down.
- **Treating the exam as your first lab.** Repeat the drills at home until they are
  routine.
- **Memorizing specific machines.** Learn the *process*; machines in an exam are new.
- **Skipping the "clean snapshot" habit.** Break your lab, restore it, and move on.

## Checklist / Self-Test

- [ ] I can explain what the eJPT covers and who it is aimed at.
- [ ] I can describe the exam format in general public terms (practical, VPN labs,
      time-boxed) without referencing any specific question or machine.
- [ ] I have a working lab (attacker + targets) that I can rebuild from scratch.
- [ ] I can walk methodology phases 01–05 against a lab target.
- [ ] I completed every scenario in `labs/practice-scenarios.md` at least once.
- [ ] I can re-run the core drills without opening these notes.
- [ ] I keep organized engagement notes with evidence (commands + output).
- [ ] I verified current exam logistics on the official INE Security page.

## Further Resources

- INE Security — official certifications directory (public marketing & syllabus):
  <https://ine.com/certifications>
  (the former `security.ine.com` domain is no longer the correct source)
- Nmap official documentation: <https://nmap.org/docs.html>
- Metasploit documentation: <https://docs.metasploit.com/>
- OWASP Top 10 (web fundamentals): <https://owasp.org/www-project-top-ten/>
- MITRE ATT&CK (technique reference): <https://attack.mitre.org/>
- Authorized practice platforms: <https://www.vulnhub.com/> ·
  <https://www.tryhackme.com/> · <https://www.hackthebox.com/>
