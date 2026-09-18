# Recommended Reading — by Study Area

> Personal study resource for the **INE Security** certification program. Books and
> references below are real, well-known public works that complement — never replace —
> the official INE course material and syllabus. Where a work is a free official document
> (NIST, OWASP) it is marked as such. No deep links are fabricated: titles and stable
> landing pages only, so buy or borrow books from any reputable bookstore or library.

## How to use this list

- Sections mirror this repo's area folders (`01-Fundamentals/`, `02-RedTeam/`,
  `03-BlueTeam/`, `04-Emerging-Technologies/`) plus a final cross-area section for
  frameworks and standards.
- The INE course itself is the primary source for each exam. Books fill gaps in
  fundamentals, deepen the "why" behind techniques, and give you a second explanation
  when a topic does not click.
- Prefer recent editions when they exist: security books age quickly, and certification
  syllabi are usually updated to match current practice.

## Penetration testing foundations (eJPT · eCPPT)

- **Penetration Testing: A Hands-On Introduction to Hacking** — Georgia Weidman
  (No Starch Press). Why it helps: a structured, beginner-friendly walk through the full
  pentest process — reconnaissance, exploitation, post-exploitation — matching the eJPT
  mindset.
- **Linux Basics for Hackers** — OccupyTheWeb (No Starch Press). Why it helps: the Linux
  command-line fluency that every INE practical exam assumes you already have.
- **The Hacker Playbook 3: Red Team Edition** — Peter Kim. Why it helps: a practical,
  scenario-driven approach to network and Active Directory attacks, a good companion for
  eCPPT-style methodology.
- **Network Security Assessment (3rd edition)** — Chris McNab (O'Reilly). Why it helps: a
  systematic survey of how common network services are probed and assessed, useful for
  service enumeration and attack planning.

## Web application security (eWPT · eWPTX)

- **The Web Application Hacker's Handbook (2nd edition)** — Why it helps: the classic
  structured guide to web-app testing methodology; its phase-by-phase mindset maps well to
  how eWPT-style exams are designed.
- **OWASP Top 10** — free public project (see OWASP section below). Why it helps: the
  de-facto shared vocabulary for the most common web vulnerabilities.
- **OWASP Web Security Testing Guide (WSTG)** — free public project. Why it helps: a
  hands-on, test-by-test manual covering the same vulnerability categories a web
  penetration testing exam exercises.

## Mobile application security (eMAPT)

- **The Mobile Application Hacker's Handbook** (Wiley). Why it helps: a thorough reference
  on Android and iOS assessment fundamentals — traffic, storage, and app logic.
- **OWASP Mobile Security Testing Guide (MSTG)** — free public project. Why it helps:
  current, practical testing recipes for mobile apps that stay closer to modern Android/iOS
  than most books.

## Blue team: SOC analysis and incident response (eSOC · eCIR)

- **Blue Team Handbook: Incident Response Edition** — Don Murdoch. Why it helps: a
  practical IR playbook of what to do hour-by-hour during an incident, aligned with the
  phases an IR-focused exam drills.
- **The Practice of Network Security Monitoring** — Richard Bejtlich (No Starch Press).
  Why it helps: builds the analyst mindset of turning raw network evidence into a story —
  useful for SOC triage and investigation work.

## Digital forensics (eCDFP)

- **Practical Malware Analysis** — Michael Sikorski and Andrew Honig (No Starch Press).
  Why it helps: the standard hands-on introduction to static and dynamic malware analysis,
  frequently relevant to forensic exams.
- **The Art of Memory Forensics** — Michael Hale Ligh, Andrew Case, Jamie Levy, and
  AAron Walters (Wiley). Why it helps: the reference for memory analysis, an area that
  distinguishes advanced forensics work from basic disk forensics.

## Threat hunting and detection engineering (eCTHP)

- **Intelligence-Driven Incident Response** — Rebekah Brown and Scott Roberts (O'Reilly).
  Why it helps: the clearest explanation of turning threat intelligence into hypotheses
  about what an adversary would do in *your* environment — the core of hunting.
- **Crafting the InfoSec Playbook** — Jeff Bollinger, Brandon Enright, and Matthew Valites
  (O'Reilly). Why it helps: how to define what "normal" looks like and write detection
  content that survives contact with real data.
- **The Practice of Network Security Monitoring** — Richard Bejtlich (No Starch Press).
  Why it helps: the network side of hunting — where to place sensors and how to read what
  they produce.
- **MITRE ATT&CK** — free public knowledge base (<https://attack.mitre.org/>). Why it
  helps: the shared vocabulary that lets a hypothesis name a *technique* instead of a tool.
- **Sigma** — free public rule format (<https://sigmahq.io/>). Why it helps: the portable
  way to express a detection, plus a large corpus of existing rules to read and adapt.

## Emerging technologies: AI security and IAM (eAIS · eIAMA)

- **OWASP Top 10 for LLM Applications** — free public project. Why it helps: a current,
  structured catalog of attacks against LLM-based systems (prompt injection, poisoning,
  and friends), a natural fit for an AI-security syllabus.
- **Zero Trust Networks — Building Secure Systems in Untrusted Networks** (O'Reilly).
  Why it helps: the conceptual background for zero-trust architectures that the
  IAM certification builds on. (Razi Rais et al. are credited on recent
  editions — confirm the author list on the copy you buy.)
- **MITRE ATLAS** — free public knowledge base. Why it helps: an adversary-focused
  taxonomy for AI/ML systems that complements the defensive angle of the OWASP LLM list.

## Security governance, risk, and compliance (eEDA)

- **NIST Cybersecurity Framework (CSF)** — free public document set. Why it helps: the
  common framework for organizing security programs, directly relevant to a defense/
  governance-oriented syllabus.
- **NIST Risk Management Framework (RMF)** — free public document set. Why it helps:
  shows how controls and risk decisions are formalized in real organizations.

## Frameworks, standards, and free official references (cross-area)

These are public, freely downloadable documents — prefer the authoritative source over
third-party summaries:

- **NIST SP 800-61 Rev. 2 — Computer Security Incident Handling Guide**. Why it helps:
  the canonical incident-handling lifecycle used across IR training.
- **NIST SP 800-207 — Zero Trust Architecture**. Why it helps: the reference definition of
  zero trust you will be expected to reason about in architecture questions.
- **NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment**.
  Why it helps: the official framing of security testing phases that underlies many
  pentest syllabi.
- NIST publications are freely downloadable from the NIST Computer Security Resource
  Center portal: **https://csrc.nist.gov/publications** (stable landing page).
- OWASP projects (Top 10, WSTG, MSTG, LLM Top 10) are freely available from the OWASP
  homepage: **https://owasp.org** (stable landing page — search each project by name).

## Common Mistakes & Tips

- **Reading books instead of the syllabus.** Use the official syllabus as the map and
  books as the deep dives; an excellent book can still cover the wrong 20% for your exam.
- **Skipping the free official documents.** NIST and OWASP references are authoritative,
  current, and free — there is no reason to rely on paid second-hand summaries.
- **Buying outdated editions.** Check the edition and year before buying; old web and
  mobile books predate current frameworks and platform versions.
- **Reading without doing.** Books pair badly with passive reading alone — take notes in
  this repo's convention (see `resources/study-tips.md`) and re-test each technique in
  your lab.
- **Collecting a library instead of studying.** A long reading list can become a form of
  procrastination; pick 2–3 works per area and finish them.

## Checklist

- [ ] Map each book/reference to the official syllabus section it supports
- [ ] Download the free NIST documents (SP 800-61 Rev. 2, SP 800-207, SP 800-115) from https://csrc.nist.gov/publications
- [ ] Download the OWASP Top 10, WSTG, MSTG, and LLM Top 10 from https://owasp.org
- [ ] Verify author/publisher and edition of each book before buying
- [ ] Read one chapter, then reproduce its techniques in the lab the same week
- [ ] Store your notes in the matching certification module in this repo
- [ ] Keep this list pruned to works you actually use
