# INE-Cybersecurity-Certifications-Guide

This repository is a personal, public collection of study guides for the
**INE Security (eLearnSecurity)** certification portfolio. Everything is
written entirely in **English** and organized first by knowledge area and then
by certification: each of the eleven certification modules is a self-contained
study guide covering methodology, tool references, hands-on lab exercises, and
quick-reference cheatsheets, so the project works as an open, structured
companion while you prepare for these exams.

> ⚠️ **Personal study project — not affiliated.** This repository is not
> affiliated with, sponsored by, or endorsed by INE Security (eLearnSecurity).
> It contains only original study notes written by the author, plus links to
> publicly available documentation. There is **no copyrighted content** and
> **no exam questions, answers, or NDA-protected material** from INE or any
> other vendor in this repository.

## Table of contents

- [Areas and certifications](#areas-and-certifications)
- [Repository structure](#repository-structure)
- [Resources](#resources)
- [Scripts](#scripts)
- [Status](#status)
- [Contributing](#contributing)
- [License](#license)

## Areas and certifications

The guides are grouped into four areas. Each certification module in the table
links to that module's `README.md`, which acts as its index.

| Area | Folder | Module | Full certification name |
|---|---|---|---|
| Fundamentals | [`01-Fundamentals/`](01-Fundamentals) | [eJPT](01-Fundamentals/eJPT/README.md) | Junior Penetration Tester |
| Fundamentals | [`01-Fundamentals/`](01-Fundamentals) | [eEDA](01-Fundamentals/eEDA/README.md) | Enterprise Defense Administrator |
| Red Team | [`02-RedTeam/`](02-RedTeam) | [eCPPT](02-RedTeam/eCPPT/README.md) | Certified Professional Penetration Tester |
| Red Team | [`02-RedTeam/`](02-RedTeam) | [eWPT](02-RedTeam/eWPT/README.md) | Web Application Penetration Tester |
| Red Team | [`02-RedTeam/`](02-RedTeam) | [eWPTXv2](02-RedTeam/eWPTXv2/README.md) | Web Application Penetration Tester eXtreme |
| Red Team | [`02-RedTeam/`](02-RedTeam) | [eMAPT](02-RedTeam/eMAPT/README.md) | Mobile Application Penetration Tester |
| Blue Team | [`03-BlueTeam/`](03-BlueTeam) | [eSOC](03-BlueTeam/eSOC/README.md) | SOC Analyst |
| Blue Team | [`03-BlueTeam/`](03-BlueTeam) | [eCIR](03-BlueTeam/eCIR/README.md) | Certified Incident Responder |
| Blue Team | [`03-BlueTeam/`](03-BlueTeam) | [eCDFP](03-BlueTeam/eCDFP/README.md) | Certified Digital Forensics Professional |
| Emerging Technologies | [`04-Emerging-Technologies/`](04-Emerging-Technologies) | [eAIS](04-Emerging-Technologies/eAIS/README.md) | AI Security |
| Emerging Technologies | [`04-Emerging-Technologies/`](04-Emerging-Technologies) | [eIAMA](04-Emerging-Technologies/eIAMA/README.md) | Identity and Access Management Architect |

## Repository structure

```
INE-Cybersecurity-Certifications-Guide/
├── 01-Fundamentals/             # eJPT, eEDA
├── 02-RedTeam/                  # eCPPT, eWPT, eWPTXv2, eMAPT
├── 03-BlueTeam/                 # eSOC, eCIR, eCDFP
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

- [`resources/official-links.md`](resources/official-links.md) — official INE Security links.
- [`resources/recommended-reading.md`](resources/recommended-reading.md) — recommended reading.
- [`resources/video-tutorials.md`](resources/video-tutorials.md) — video tutorials.
- [`resources/study-tips.md`](resources/study-tips.md) — general study tips.

## Scripts

Small helpers used alongside the guides:

- [`scripts/automation/env-setup.sh`](scripts/automation/env-setup.sh) — basic environment setup.
- [`scripts/automation/tool-installer.py`](scripts/automation/tool-installer.py) — tool installer.
- [`scripts/utilities/report-generator.py`](scripts/utilities/report-generator.py) — study-progress report generator.

Review any script before running it in your own environment.

## Status

**Status: complete.** All eleven certification modules are finished study
guides written entirely in English.

- [x] Repository structure and shared conventions defined
- [x] All 11 certification modules complete in English (methodology, tools, labs, cheatsheets)
- [x] Reproducible lab guides per certification
- [x] Shared resources and helper scripts

Found a mistake or want to extend a module? See [Contributing](#contributing).

## Contributing

Contributions are welcome. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md)
before opening an issue or a pull request.

## License

Distributed under the **MIT** license. See [`LICENSE`](LICENSE).
