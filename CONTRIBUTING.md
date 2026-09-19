# Contributing · INE-Cybersecurity-Certifications-Guide

Thank you for wanting to improve this study-guide collection. These conventions
keep the repository organized, consistent, and useful — please follow them when
adding or editing content.

All content in this repository is written in **English**.

## Repository conventions

- One folder per certification, placed inside the correct area:
  - `01-Fundamentals/` — eJPT
  - `02-RedTeam/` — eCPPT, eWPT, eWPTX, eMAPT
  - `03-BlueTeam/` — eEDA, eSOC, eCIR, eCDFP, eCTHP
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

## Certification names and currency

- **Use INE's current official name.** The folder and the module title use the
  abbreviation INE publishes today, and the full name is spelled as INE spells it
  (`eWPTX`, not `eWPTXv2`; eAIS is *AI Systems Security Specialist*; eIAMA is *Certified
  Identity & Access Management Technologist*). Check
  <https://ine.com/certifications> before adding or renaming a module.
- **Never invent a product-page URL.** Link the `…-certification` page only if it has been
  fetched and resolves; otherwise link the catalogue at <https://ine.com/certifications>.
  A guessed slug is worse than no link. Note the shape of the parent path:
  `https://ine.com/security/certifications` (no slug) returns **404**, while the twelve
  product pages under that same prefix — the `…-certification` slugs this repository links —
  all return **200** (both re-checked page by page on 19 September 2026). The prefix is not
  dead; it has no index. So: link a product page directly, link the catalogue at
  <https://ine.com/certifications> when you need a hub, and never link the bare prefix as a
  fallback, because that is the one URL under it that does not resolve.
- **Index every note you write.** A module's `README.md` is its index: a `.md` file that no
  README links is invisible to readers. `check-catalog.mjs` fails on orphans, and that is
  the check that caught real orphans in this repository.
- **Do not state exam logistics.** No question counts, durations, prices, passing scores,
  or official domain lists — they change and cannot be maintained here. Point at the
  official page instead.
- **Do not add modules for retired credentials.** eCPTXv2, eCMAP, eCXD, eCRE and eWDP were
  retired on 1 October 2023; the root `README.md` lists them so readers can recognize them.
- **Update the verification date.** Any change to a certification name, area, or version
  note must also update the *Last verified* date in the root `README.md` and in
  `resources/official-links.md`.

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
3. Run the four checks described below — they catch the mistakes that actually happen here.
4. Open a pull request describing what you add and why.
5. If you add a certification, update the root `README.md` index (areas table,
   repository tree, and status) and this file's area mapping.

## Checks that must pass

Four dependency-free Node scripts verify the things that break in practice. Run them before
opening a pull request; CI runs the same commands on every push and pull request
(`.github/workflows/docs-check.yml`):

```console
$ node scripts/utilities/check-catalog.mjs .
$ node scripts/utilities/check-links.mjs .
$ node scripts/utilities/check-commands.mjs . --require-verification
$ node scripts/utilities/check-code.mjs .
```

- **`check-catalog.mjs`** compares the catalog in `README.md` with what is on disk. It fails
  when a module folder is not linked from `README.md`, when a table row points at a folder
  that was renamed or moved, when a module is missing one of the four conventional
  subfolders, or when a note loses its single H1, its `Checklist` heading or its
  `Further Resources` heading.
- **`check-links.mjs`** fails on a relative link that does not resolve and on an in-repo
  anchor (`file.md#a-heading`) whose heading no longer exists. Fenced code blocks are
  stripped first, so a `#` comment inside a shell example is never mistaken for a heading.
- **`check-commands.mjs`** compares every flag, subcommand and plugin name used in a guide
  against a catalogue extracted from that tool's own documentation
  (`scripts/utilities/tool-specs/*.json`). A catalogue is not a guess: each one records the
  URL it came from, the version and the date. The check reads fenced blocks in shell-ish
  languages, inline code spans that look like a command, and tables of flags when the table's
  context names exactly one catalogued tool — so a row such as `| -oJ file | JSON |` in a note
  about nmap is a claim it can test. It does **not** read pseudocode, plugin-specific options,
  standalone scripts, ASCII diagrams or directory trees, and it does not check flag arity.
  Those limits are stated at the top of the script and in `AUDIT-2026-09-19.md`.
- **`check-code.mjs`** closes the other half of that gap: every fenced block must be closed (an
  unclosed fence swallows the rest of the document), and every `python` or `js` block, and every
  `.py`/`.mjs` file, must parse. Nothing is executed — Python is parsed with `ast.parse` and
  JavaScript with `vm.Script` — and Python blocks are reported as skipped, never as passing, on
  a machine with no Python 3 on the PATH.
- **`check-links.mjs . --external`** additionally makes network requests to every external
  URL. It runs weekly in `.github/workflows/external-links.yml` and never on pull requests:
  a vendor site being down should not block your work.

All four exit `0` when clean and `1` when something is wrong, so they work as a pre-commit
hook or a CI gate without extra tooling. Node 18 or newer is the only requirement.

### Say how you checked it

When you change a command, a query or a script, record what you did with it. The convention
is a single blockquote before `## Further Resources`:

```markdown
> **Verification:** executed against Volatility 3.2.0 (symbol tables downloaded 2026-09-19)
> on 2026-09-19; the corrected invocation is the one shown above.
```

Use `executed` only when you ran it, `checked against <source> <URL>` when you compared it
with primary documentation, and `unverified syntax reference — not run` when you could not
run it. `check-commands.mjs --require-verification` — the form CI runs — fails on a file that
contains commands and declares no record, so a file that says nothing is read as "nobody
checked" and blocks the build. That enforcement went on in September 2026, once every file
with commands carried a record; before that the number was only printed on every run.

Put the blockquote just before `## Further Resources`; at the end of the file is also
accepted, and both are counted. Two rules keep it honest:

- If a record has to quote an invocation that is **wrong on purpose** — "this fails with
  `invalid choice`" — end that line with `<!-- check-commands: ignore -->`. The checker reads
  inline code spans, so without the marker it reports the counter-example as a defect.
- Do not grow the record into a changelog. One blockquote, the tool and version, the date,
  and what you actually ran.

## Keeping the catalog current

When INE renames, re-versions or retires something, the guide has to follow. The procedure
that has worked so far:

1. Read the certification's own page and INE's newsroom before trusting any summary —
   including the ones in this repository.
2. Update the module (full name, area, version note) **and** every index that mentions it:
   the root `README.md` table, `resources/official-links.md`, and this file's area mapping.
3. Add a version note with the date and a link to the announcement, so a later reader can
   tell *when* that was true. Do not restate exam logistics — link instead.
4. Move the *Last verified* date in `README.md` and `resources/official-links.md`.
5. Run all four checks. `check-catalog.mjs` is what catches the "renamed folder, stale table"
   class of mistake, which is the one that has actually happened here.

## Where to open issues

Open an issue in this repository's issue tracker to report broken links,
propose structural improvements, or discuss new content and conventions before
writing a pull request.

> **Verification:** executed on **2026-09-19** from the repository root: the four commands in
> "Checks that must pass" above were run with Node 22.23.2 on Windows 11 and with Node 18.19.1
> on Ubuntu 24.04 (WSL), each exiting 0, `check-commands.mjs` in the `--require-verification`
> form CI now uses. `check-links.mjs . --external` was **not** part of that run: it makes
> network requests and is the weekly sweep, not a pull-request gate.
