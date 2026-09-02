# Contributing · INE-Cybersecurity-Certifications-Guide

Thank you for wanting to improve this study-guide collection. These conventions
keep the repository organized, consistent, and useful — please follow them when
adding or editing content.

All content in this repository is written in **English**.

## Repository conventions

- One folder per certification, placed inside the correct area:
  - `01-Fundamentals/` — eJPT, eEDA
  - `02-RedTeam/` — eCPPT, eWPT, eWPTXv2, eMAPT
  - `03-BlueTeam/` — eSOC, eCIR, eCDFP
  - `04-Emerging-Technologies/` — eAIS, eIAMA
- Every certification folder uses the same subfolders:
  - `methodology/` — numbered phases with a `01-`, `02-`, … prefix (execution order)
  - `tools/` — tool references, own scripts, and guides
  - `labs/` — lab setups and practical exercises
  - `cheatsheets/` — quick-reference commands and terminology
- Each certification folder also has its own `README.md` acting as the module
  index.
- File names are **kebab-case** and in English (`01-reconnaissance.md`,
  `burp-suite-guide.md`).

## Note format

- One Markdown file per topic, starting with a descriptive `# Title`.
- Use `##` headings for the sections of each note.
- Use `- [ ]` checklists for pending items and `- [x]` for completed ones.
- Put commands inside fenced code blocks and indicate the context (OS, shell,
  or tool) so readers know where they run.
- Keep code, commands, payloads, and technical terms in their original form.

## Content policy

- **Original notes only**: paraphrase and cite the source when you base content
  on documentation.
- **Never** include copyrighted text reproduced verbatim.
- **Never** publish INE/eLearnSecurity exam content, official answers, or any
  NDA-protected material.
- Do not include credentials, tokens, keys, or personal data in examples — use
  placeholders instead.
- Only link to publicly available documentation and resources.

## Workflow

1. Fork the repository and create a descriptive branch
   (`feat/eWPT-methodology`, `fix/eJPT-broken-link`, …).
2. Make small, focused changes with clear, descriptive commit messages.
3. Open a pull request describing what you add and why.
4. If you add a certification, update the root `README.md` index (areas table,
   repository tree, and status) and this file's area mapping.

## Where to open issues

Open an issue in this repository's issue tracker to report broken links,
propose structural improvements, or discuss new content and conventions before
writing a pull request.
