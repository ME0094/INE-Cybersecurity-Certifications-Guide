# INE-Cybersecurity-Certifications-Guide

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Study guides: English](https://img.shields.io/badge/Study%20guides-English-blue.svg)](README.md)
[![INE Security: unofficial](https://img.shields.io/badge/INE%20Security-unofficial-lightgrey.svg)](README.md)

> 🇬🇧 English (this page) · 🇪🇸 **[Versión en español](README.es.md)**

> ## ⚠️ Not affiliated with INE Security
>
> This repository is an **independent, personal study project**. It is **not affiliated
> with, sponsored by, endorsed by, or connected to INE Security** (formerly
> eLearnSecurity) in any way. It contains only original study notes written by the
> author, plus links to publicly available documentation. There is **no copyrighted
> content** and **no exam questions, answers, dumps, or NDA-protected material** from
> INE or any other vendor in this repository.
>
> "INE", "eLearnSecurity", "eJPT", "eCPPT", "eCTHP" and the other certification names
> used here are trademarks of their respective owners and are used only to describe
> what each study guide is about. For anything authoritative — syllabus, exam format,
> price, booking, vouchers — always use **https://ine.com/certifications**.

This repository is a personal, public collection of study guides for the
**INE Security (eLearnSecurity)** certification portfolio. Everything is
written entirely in **English** and organized first by knowledge area and then
by certification: each of the **twelve** certification modules is a self-contained
study guide covering methodology, tool references, hands-on lab exercises, and
quick-reference cheatsheets, so the project works as an open, structured
companion while you prepare for these exams.

> ## 📅 Last verified against INE's public catalog: **19 September 2026**
>
> On that date all twelve product pages listed below were fetched and answered **HTTP 200**,
> and the same check confirmed what this repository already warned about: the bare index
> `https://ine.com/security/certifications` returns **404**, so that index is never linked
> here — each module links its own product page. INE's wider catalogue is at
> <https://ine.com/certifications>, and it also hosts preparation products for third-party
> credentials (CompTIA Security+, CISSP) that are **not** INE certifications.
>
> Two version notes were corrected on that date: eCTHP received a **further** update
> announced on 20 November 2025 (the July 2025 announcement is not the latest), and eSOC has
> a launch announcement from **3 March 2026** that this table previously left blank.
>
> What this date does **not** cover: exam logistics (question counts, durations, prices,
> passing scores, official domain lists). Those change often and are
> deliberately **not** stated in this repository — confirm them on the official page for
> each certification before you book anything.
>
> **Maintenance note.** This guide is maintained on a best-effort basis, with no
> commitment to track every syllabus change INE makes. If the date above is more than
> a few months old, treat all version details as unverified and check
> **https://ine.com/certifications** and **https://ine.com/newsroom** first.
> Corrections are welcome — see [Contributing](#contributing).

## Table of contents

- [Areas and certifications](#areas-and-certifications)
- [Certifications INE has retired](#certifications-ine-has-retired)
- [Repository structure](#repository-structure)
- [Resources](#resources)
- [Scripts](#scripts)
- [Status and maintenance](#status-and-maintenance)
- [Contributing](#contributing)
- [License](#license)

## Areas and certifications

The guides are grouped into four knowledge areas. Each certification name in the
tables below links to that module's `README.md`, which acts as its index.

### Fundamentals — [`01-Fundamentals/`](01-Fundamentals)

| Certification | Full official name | Official page | Latest public update |
|---|---|---|---|
| [eJPT](01-Fundamentals/eJPT/README.md) | Junior Penetration Tester | [dedicated page](https://ine.com/security/certifications/ejpt-certification) | Updated certification announced 31 Mar 2026 (web app testing, recon, offensive AI) |

### Red Team — [`02-RedTeam/`](02-RedTeam)

| Certification | Full official name | Official page | Latest public update |
|---|---|---|---|
| [eCPPT](02-RedTeam/eCPPT/README.md) | Certified Professional Penetration Tester | [dedicated page](https://ine.com/security/certifications/ecppt-certification) | — |
| [eWPT](02-RedTeam/eWPT/README.md) | Web Application Penetration Tester | [dedicated page](https://ine.com/security/certifications/ewpt-certification) | — |
| [eWPTX](02-RedTeam/eWPTX/README.md) | Web Application Penetration Tester eXtreme | [dedicated page](https://ine.com/security/certifications/ewptx-certification) | Relaunch announced 4 Dec 2024 (community notes call it "v3") |
| [eMAPT](02-RedTeam/eMAPT/README.md) | Mobile Application Penetration Tester | [dedicated page](https://ine.com/security/certifications/emapt-certification) | Enhanced certification announced 10 Jul 2025 |

### Blue Team — [`03-BlueTeam/`](03-BlueTeam)

| Certification | Full official name | Official page | Latest public update |
|---|---|---|---|
| [eEDA](03-BlueTeam/eEDA/README.md) | Enterprise Defense Administrator | [dedicated page](https://ine.com/security/certifications/eeda-certification) | — |
| [eSOC](03-BlueTeam/eSOC/README.md) | SOC Analyst | [dedicated page](https://ine.com/security/certifications/esoc-certification) | Certification launch announced 3 Mar 2026 |
| [eCIR](03-BlueTeam/eCIR/README.md) | Certified Incident Responder | [dedicated page](https://ine.com/security/certifications/ecir-certification) | Next-generation certification announced 3 Sep 2025 |
| [eCDFP](03-BlueTeam/eCDFP/README.md) | Certified Digital Forensics Professional | [dedicated page](https://ine.com/security/certifications/ecdfp-certification) | — |
| [eCTHP](03-BlueTeam/eCTHP/README.md) | Certified Threat Hunting Professional | [dedicated page](https://ine.com/security/certifications/ecthp-certification) | Updated certification announced 24 Jul 2025; further update announced 20 Nov 2025 |

### Emerging Technologies — [`04-Emerging-Technologies/`](04-Emerging-Technologies)

| Certification | Full official name | Official page | Latest public update |
|---|---|---|---|
| [eAIS](04-Emerging-Technologies/eAIS/README.md) | AI Systems Security Specialist | [dedicated page](https://ine.com/security/certifications/eais-certification) | Launched 23 Jun 2026 |
| [eIAMA](04-Emerging-Technologies/eIAMA/README.md) | Certified Identity & Access Management Technologist | [dedicated page](https://ine.com/security/certifications/eiama-certification) | Launched 26 Aug 2026 (vendor-neutral) |

Every certification in this repository links a **verified product page** — the URL INE
publishes for that credential. Deep links are never guessed here: a wrong slug looks
official and points somewhere else. INE's wider catalogue, which also covers its
non-security certifications, is at **https://ine.com/certifications**.

> **Naming.** Modules are named after the abbreviation INE publishes today. The web
> application "eXtreme" module is `eWPTX`, not the older `eWPTXv2`; eEDA (defence,
> governance, risk and compliance) sits in the **Blue Team** area, not in Fundamentals.

## Certifications INE has retired

These credentials are **no longer offered or examinable**. They are listed here so
that study material, blog posts, and course bundles you find elsewhere can be placed
correctly: **do not build a preparation plan around them**, and be sceptical of any
vendor still selling "official" training for them. This repository has no module for
them and will not add one.

| Retired credential | Name INE used | Retired |
|---|---|---|
| eCPTXv2 / PTX v2 | Penetration Testing Extreme | 1 Oct 2023 |
| eCMAP / Map v1 | Malware Analysis Professional | 1 Oct 2023 |
| eCXD / XDS v1 | Exploit Development Student | 1 Oct 2023 |
| eCRE / REP v1 | Reverse Engineering Professional | 1 Oct 2023 |
| eWDP / PWD v1 | Practical Web Defense | 1 Oct 2023 |

- INE's official notice is the blog post *"eLS is Retiring 5 Certifications: Here's What
  You Need to Know"* (published 21 April 2023):
  <https://ine.com/blog/els-is-retiring-5-certifications-heres-what-you-need-to-know>
  — the names and dates above are copied from it. Read it there for the voucher rules and
  course-availability deadlines that applied.
- The credentials were retired from all INE platforms on **1 October 2023**, in the
  eLearnSecurity era of the portfolio. The related courses stayed on the INE platform.
- If you already hold one of these credentials, it remains a record of what you passed;
  it is simply not something you can newly obtain.

## Repository structure

```
INE-Cybersecurity-Certifications-Guide/
├── 01-Fundamentals/             # eJPT
├── 02-RedTeam/                  # eCPPT, eWPT, eWPTX, eMAPT
├── 03-BlueTeam/                 # eEDA, eSOC, eCIR, eCDFP, eCTHP
├── 04-Emerging-Technologies/    # eAIS, eIAMA
├── resources/                   # official links, reading lists, videos, study tips
├── scripts/                     # automation, utility scripts and the tool catalogues
├── .github/workflows/           # the checks below, and the weekly external-link sweep
├── README.md                    # this index
├── README.es.md                 # Spanish orientation page (the index of record is this one)
├── CONTRIBUTING.md              # contributor guide
├── AUDIT-2026-09-18.md          # adversarial audit of all twelve modules
├── AUDIT-2026-09-19.md          # what that audit's fixes changed, and how each one was checked
├── LICENSE                      # MIT license
└── .gitignore
```

Every certification follows the same folder convention. As an example, the
`eJPT` module looks like this:

```
01-Fundamentals/eJPT/
├── README.md                    # module index
├── methodology/                 # numbered phases (01-…, 02-…)
├── tools/                       # tool references, guides, own scripts
├── labs/                        # lab setups, scenarios, exercises
└── cheatsheets/                 # quick-reference commands and terminology
```

| Folder | Contents |
|---|---|
| `methodology/` | Numbered phases and procedures (`01-…`, `02-…`) in execution order |
| `tools/` | Tool references, guides, and own helper scripts |
| `labs/` | Lab setups, scenarios, and hands-on exercises |
| `cheatsheets/` | Quick-reference commands and terminology |

## Resources

Shared material that applies across certifications:

- [`resources/certification-map.md`](resources/certification-map.md) — how the credentials relate, what each one proves, and in what order to study them.
- [`resources/official-links.md`](resources/official-links.md) — official INE Security links, with the verification date.
- [`resources/recommended-reading.md`](resources/recommended-reading.md) — recommended reading.
- [`resources/video-tutorials.md`](resources/video-tutorials.md) — video tutorials.
- [`resources/study-tips.md`](resources/study-tips.md) — general study tips.

## Scripts

Small helpers used alongside the guides:

- [`scripts/automation/env-setup.sh`](scripts/automation/env-setup.sh) — basic environment setup.
- [`scripts/automation/tool-installer.py`](scripts/automation/tool-installer.py) — tool installer.
- [`scripts/utilities/report-generator.py`](scripts/utilities/report-generator.py) — study-progress report generator.

Review any script before running it in your own environment.

## Status and maintenance

**Status: complete, with uneven depth.** All twelve certification modules are finished study
guides written in English — every one has an index, numbered methodology phases, tool
references, hands-on labs and cheatsheets. They are **not the same size**, and this
repository says so instead of pretending otherwise. Measured on 19 Sep 2026 (after the fix
pass recorded in [`AUDIT-2026-09-19.md`](AUDIT-2026-09-19.md); counts are `.md` files under
each folder, recursively, and *Lines of notes* is every line of every `.md` in the module,
blank lines included — a different convention gives different numbers):

| Module | Phases | Tool guides | Labs | Cheatsheets | Lines of notes |
|---|---|---|---|---|---|
| [eJPT](01-Fundamentals/eJPT/README.md) | 5 | 3 | 2 | 1 | 2,751 |
| [eCPPT](02-RedTeam/eCPPT/README.md) | 5 | 3 | 2 | 1 | 2,233 |
| [eWPT](02-RedTeam/eWPT/README.md) | 5 | 2 | 2 | 1 | 2,251 |
| [eWPTX](02-RedTeam/eWPTX/README.md) | 5 | 2 | 1 | 1 | 2,097 |
| [eMAPT](02-RedTeam/eMAPT/README.md) | 5 | 3 | 2 | 1 | 2,574 |
| [eEDA](03-BlueTeam/eEDA/README.md) | 9 | 5 | 3 | 1 | 4,675 |
| [eSOC](03-BlueTeam/eSOC/README.md) | 8 | 6 | 3 | 1 | 4,398 |
| [eCIR](03-BlueTeam/eCIR/README.md) | 5 | 2 | 1 | 1 | 2,424 |
| [eCDFP](03-BlueTeam/eCDFP/README.md) | 8 | 5 | 6 | 3 | 7,859 |
| [eCTHP](03-BlueTeam/eCTHP/README.md) | 5 | 3 | 2 | 2 | 5,014 |
| [eAIS](04-Emerging-Technologies/eAIS/README.md) | 9 | 5 | 6 | 4 | 9,691 |
| [eIAMA](04-Emerging-Technologies/eIAMA/README.md) | 5 | 1 | 1 | 1 | 1,822 |

Two of them are deliberately thin: eJPT is a first credential, and eIAMA is a young,
standards-driven certification whose content is protocols rather than procedures. The
deepest are eAIS, eCDFP and eCTHP. Each module's own README states what it covers, and its
checklist tells you what you should be able to produce before moving on.

Three automated checks keep the repository from rotting, and they run on every push to `main`
and on every pull request (`.github/workflows/docs-check.yml`); a fourth sweep runs weekly,
checks external links and deliberately ignores the lab-local URLs the guides tell the reader
to open at home:

- [x] Catalog matches the repository — no module on disk that `README.md` does not link, no table row pointing at a folder that moved, no note that is orphaned from its module index
- [x] Every relative link, in-repo anchor and promised path resolves
- [x] Every flag, subcommand and plugin name in the guides exists in a catalogue extracted from the tool's own documentation (what that check cannot see is stated in its header and in `AUDIT-2026-09-19.md`)
- [x] Catalog, names, areas and version notes verified against INE's own pages (19 Sep 2026)

What this repository deliberately does **not** contain, and why:

- **Exam logistics.** No question counts, durations, prices, or official domain lists.
  They change without notice and any copy of them here would rot; each module links to
  the official page instead.
- **Retired credentials.** No modules for eCPTXv2, eCMAP, eCXD, eCRE or eWDP — see
  [above](#certifications-ine-has-retired).
- **Exam content.** No dumps, no "practice questions" taken from a live item pool, no
  NDA-protected material.
- **Validated commands.** The commands and queries in the modules are documented syntax
  rather than captured output, with one stated exception: the eEDA tool notes reproduce
  output from the workstation where that module was written, and say so in place. Where a
  command was executed during a review pass, the file carries a `> **Verification:**` line
  naming the tool, the version and the date; where it was only compared with documentation,
  the line says that instead. `AUDIT-2026-09-19.md` records which claims were executed and
  which were not.

Found a mistake — a wrong certification name, a moved link, a version that has since
changed — open an issue or a pull request. See [Contributing](#contributing).

**Two audit records, kept as they were written.** [`AUDIT-2026-09-18.md`](AUDIT-2026-09-18.md)
is the adversarial read of all twelve modules: 112 findings, from commands that cannot run to
claims that contradict each other. [`AUDIT-2026-09-19.md`](AUDIT-2026-09-19.md) records what
was corrected afterwards, how each correction was checked (a real tool where one could be
installed, a parser or primary documentation where it could not), and what is still open.
Both are snapshots, not living documents: findings stay listed after they are fixed so a
later reader can see what the material used to say.

## Contributing

Contributions are welcome. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md)
before opening an issue or a pull request.

## License

Distributed under the **MIT** license. See [`LICENSE`](LICENSE).
