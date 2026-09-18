# INE-Cybersecurity-Certifications-Guide

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Study guides: English](https://img.shields.io/badge/Study%20guides-English-blue.svg)](README.md)
[![INE Security: unofficial](https://img.shields.io/badge/INE%20Security-unofficial-lightgrey.svg)](README.md)

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
> price, booking, vouchers — always use **https://ine.com/security/certifications**.

This repository is a personal, public collection of study guides for the
**INE Security (eLearnSecurity)** certification portfolio. Everything is
written entirely in **English** and organized first by knowledge area and then
by certification: each of the **twelve** certification modules is a self-contained
study guide covering methodology, tool references, hands-on lab exercises, and
quick-reference cheatsheets, so the project works as an open, structured
companion while you prepare for these exams.

> ## 📅 Last verified against INE's public catalog: **18 September 2026**
>
> On that date the certification names, product pages, and version announcements
> referenced below were re-checked against INE Security's public pages and press
> releases. What this date does **not** cover: exam logistics (question counts,
> durations, prices, passing scores, official domain lists). Those change often and
> are deliberately **not** stated in this repository — confirm them on the official
> page for each certification before you book anything.
>
> **Maintenance note.** This guide is maintained on a best-effort basis, with no
> commitment to track every syllabus change INE makes. If the date above is more than
> a few months old, treat all version details as unverified and check
> **https://ine.com/security/certifications** and **https://ine.com/newsroom** first.
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
| [eWPT](02-RedTeam/eWPT/README.md) | Web Application Penetration Tester | [directory](https://ine.com/security/certifications) | — |
| [eWPTX](02-RedTeam/eWPTX/README.md) | Web Application Penetration Tester eXtreme | [dedicated page](https://ine.com/security/certifications/ewptx-certification) | Relaunch announced 4 Dec 2024 (community notes call it "v3") |
| [eMAPT](02-RedTeam/eMAPT/README.md) | Mobile Application Penetration Tester | [dedicated page](https://ine.com/security/certifications/emapt-certification) | Enhanced certification announced 10 Jul 2025 |

### Blue Team — [`03-BlueTeam/`](03-BlueTeam)

| Certification | Full official name | Official page | Latest public update |
|---|---|---|---|
| [eEDA](03-BlueTeam/eEDA/README.md) | Enterprise Defense Administrator | [dedicated page](https://ine.com/security/certifications/eeda-certification) | — |
| [eSOC](03-BlueTeam/eSOC/README.md) | SOC Analyst | [dedicated page](https://ine.com/security/certifications/esoc-certification) | — |
| [eCIR](03-BlueTeam/eCIR/README.md) | Certified Incident Responder | [dedicated page](https://ine.com/security/certifications/ecir-certification) | Next-generation certification announced 8 Sep 2025 |
| [eCDFP](03-BlueTeam/eCDFP/README.md) | Certified Digital Forensics Professional | [dedicated page](https://ine.com/security/certifications/ecdfp-certification) | — |
| [eCTHP](03-BlueTeam/eCTHP/README.md) | Certified Threat Hunting Professional | [dedicated page](https://ine.com/security/certifications/ecthp-certification) | Updated certification announced 24 Jul 2025 |

### Emerging Technologies — [`04-Emerging-Technologies/`](04-Emerging-Technologies)

| Certification | Full official name | Official page | Latest public update |
|---|---|---|---|
| [eAIS](04-Emerging-Technologies/eAIS/README.md) | AI Systems Security Specialist | [dedicated page](https://ine.com/security/certifications/eais-certification) | Launched 23 Jun 2026 |
| [eIAMA](04-Emerging-Technologies/eIAMA/README.md) | Identity & Access Management Associate | [dedicated page](https://ine.com/security/certifications/eiama-certification) | Launched 26 Aug 2026 (vendor-neutral) |

Where the "Official page" column says *directory* (currently only eWPT), INE has not
published a product-page URL that could be verified; open
**https://ine.com/security/certifications** and select the certification card. Deep
links are never guessed in this repository, because a wrong slug silently points
somewhere else.

> **Naming.** Modules are named after the abbreviation INE publishes today. The web
> application "eXtreme" module is `eWPTX`, not the older `eWPTXv2`; eEDA (defence,
> governance, risk and compliance) sits in the **Blue Team** area, not in Fundamentals.

## Certifications INE has retired

These credentials are **no longer offered or examinable**. They are listed here so
that study material, blog posts, and course bundles you find elsewhere can be placed
correctly: **do not build a preparation plan around them**, and be sceptical of any
vendor still selling "official" training for them. This repository has no module for
them and will not add one.

| Retired credential | Full name | Status |
|---|---|---|
| eCPTX | Certified Penetration Tester eXtreme | Discontinued |
| eCXD | Certified eXploit Developer | Discontinued |
| eCMAP | Certified Malware Analysis Professional | Discontinued |
| eCRE | Certified Reverse Engineer | Discontinued |
| eWDP | Web Defense Professional | Discontinued |

- INE's official notice of the retirement is the blog post *"ELS is retiring 5
  certifications: here's what you need to know"*:
  <https://ine.com/blog/els-is-retiring-5-certifications-heres-what-you-need-to-know>
  — read it there for the exact dates, voucher rules and exam deadlines that applied.
- The retirement was announced in 2023, in the eLearnSecurity era of the portfolio.
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
├── scripts/                     # automation and utility scripts
├── README.md                    # this index
├── CONTRIBUTING.md              # contributor guide
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

**Status: complete.** All twelve certification modules are finished study guides
written entirely in English.

- [x] Repository structure and shared conventions defined
- [x] All 12 certification modules complete in English (methodology, tools, labs, cheatsheets)
- [x] Reproducible lab guides per certification
- [x] Shared resources and helper scripts
- [x] Catalog, names, and areas re-verified against INE's public pages (18 Sep 2026)

What this repository deliberately does **not** contain, and why:

- **Exam logistics.** No question counts, durations, prices, or official domain lists.
  They change without notice and any copy of them here would rot; each module links to
  the official page instead.
- **Retired credentials.** No modules for eCPTX, eCXD, eCMAP, eCRE or eWDP — see
  [above](#certifications-ine-has-retired).
- **Exam content.** No dumps, no "practice questions" taken from a live item pool, no
  NDA-protected material.

Found a mistake — a wrong certification name, a moved link, a version that has since
changed — open an issue or a pull request. See [Contributing](#contributing).

## Contributing

Contributions are welcome. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md)
before opening an issue or a pull request.

## License

Distributed under the **MIT** license. See [`LICENSE`](LICENSE).
