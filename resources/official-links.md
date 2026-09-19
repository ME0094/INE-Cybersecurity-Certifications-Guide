# Official Links — INE Security

> Personal study resource for the **INE Security** (formerly eLearnSecurity) certification
> program. **Last verified against INE's public pages: 18 September 2026.**
>
> What "verified" means here: on 18 September 2026 every URL on this page was fetched and
> **answered HTTP 200**, and INE's own sitemap was enumerated to confirm that these twelve
> are the whole security portfolio. What it does **not** mean: that every page will render
> the same content tomorrow. INE renames, reorganizes and re-versions certifications, and
> product pages move — so re-check before you book an exam or buy a course.
>
> **A note on exam logistics.** This file deliberately does not reproduce question counts,
> exam durations, prices, passing scores, or official domain lists. Those details change
> without notice and a stale copy here would be worse than no copy. Open the official page.

## How to use this page

- Start from the **general entry points** below; they are the most stable URLs INE publishes.
- The certification sections mirror this repo's area folders (`01-Fundamentals/`,
  `02-RedTeam/`, `03-BlueTeam/`, `04-Emerging-Technologies/`) so you can open the matching
  module while you browse the official page.
- Every entry below has a **dedicated page**: the product-page URL INE publishes for that
  credential, verified to resolve. A slug is never guessed: a wrong `…-certification` URL
  looks official and points somewhere else. If a page ever 404s, fall back to the
  catalogue at <https://ine.com/certifications>.
- Course and learning-path pages sit behind an INE account, so no course deep links are
  listed: open the platform and search for the certification name once you are logged in.
- Where a certification has been updated, the announcement link is given so you can read
  the official wording instead of a summary.

## Verified general entry points

- **INE Security homepage** — https://ine.com
  The single most stable entry point: platform, courses, subscriptions, labs, and links
  to everything else. When any bookmark below breaks, start here and navigate from the
  homepage.
- **Certification catalogue** — https://ine.com/certifications
  INE's own index of certifications, security and non-security alike (its networking and
  cloud tracks live at `/certifications/networking` and `/certifications/cloud`). Use it to
  check whether a certification still exists and to reach its page.
  Note: `https://ine.com/security/certifications` — the URL this repository used before
  18 September 2026 — returns **404**, and this is *only* true of the bare index: the twelve
  product pages that hang off the same prefix all answer **200** (both facts re-checked page by
  page on 19 September 2026; the twelve pages are the `…/security/certifications/<slug>-certification`
  links listed below). So the rule is not "that prefix is dead" but "that prefix has no index".
  Link a product page directly, and link <https://ine.com/security> or
  <https://ine.com/certifications> when you need a hub that resolves.
- **Digital certificates and badges** — https://certs.ine.com
  General entry point to look up and verify issued digital certificates and badges after
  you pass an exam. (Account-related flows live behind this entry point.) The badge page is
  also the fastest way to check the exact wording of a credential's official title.
- **Newsroom / announcements** — https://ine.com/newsroom
  General entry point for official announcements: new certifications, exam or syllabus
  version changes, and platform updates. Worth a quick check before you start a study
  sprint for a recently released certification.

## Fundamentals — eJPT (`01-Fundamentals/`)

### eJPT — Junior Penetration Tester

- Official page: **https://ine.com/security/certifications/ejpt-certification**
  Dedicated product page (verified).
- Version note: INE announced an **updated eJPT certification in spring 2026** — the
  announcement page on INE's newsroom is dated **1 April 2026** and the accompanying press
  release **31 March 2026** — adding web application testing, reconnaissance training and
  offensive AI:
  <https://ine.com/newsroom/ine-security-launches-updated-ejpt-certification-with-expanded-web-app-testing-recon-training-and-offensive-ai>
- Why it helps: confirms the current exam structure and what the *Junior* level expects.

## Red Team — eCPPT, eWPT, eWPTX, eMAPT (`02-RedTeam/`)

### eCPPT — Certified Professional Penetration Tester

- Official page: **https://ine.com/security/certifications/ecppt-certification**
  Dedicated product page (verified) with its syllabus and the practical-exam description.
- Why it helps: shows the official methodology areas (network, Active Directory, pivoting,
  reporting) that the exam expects you to practice end-to-end.

### eWPT — Web Application Penetration Tester

- Official page: **https://ine.com/security/certifications/ewpt-certification**
  Dedicated product page (verified) with the official web-application syllabus.
- Why it helps: keeps your web study aligned with the official vulnerability categories
  instead of a generic web list.

### eWPTX — Web Application Penetration Tester eXtreme

- Official page: **https://ine.com/security/certifications/ewptx-certification**
  Dedicated product page (verified) with the advanced web syllabus and exam details.
- Version note: INE relaunched the certification in the **November/December 2024**
  window (the public announcement is dated 4 December 2024); community study notes refer
  to that generation as "eWPTXv3", but the version suffix is not part of INE's official
  credential title, which is simply *Web Application Penetration Tester eXtreme*. This
  repository therefore names the module `eWPTX`.
- Why it helps: confirms the advanced topics (chained exploits, bypass techniques) that
  distinguish eWPTX from eWPT.

### eMAPT — Mobile Application Penetration Tester

- Official page: **https://ine.com/security/certifications/emapt-certification**
  Dedicated product page (verified) with the official mobile syllabus (Android/iOS
  testing and reporting).
- Version note: INE announced an **enhanced eMAPT certification on 10 July 2025**:
  <https://ine.com/blog/master-real-world-mobile-security-new-cert-launched>
- Why it helps: scopes your mobile lab effort (which platforms and analysis phases are
  in scope) before you build it.

## Blue Team — eEDA, eSOC, eCIR, eCDFP, eCTHP (`03-BlueTeam/`)

### eEDA — Enterprise Defense Administrator

- Official page: **https://ine.com/security/certifications/eeda-certification**
  Dedicated product page (verified).
- Why it helps: eEDA sits on the **defensive side** of the portfolio — governance, risk,
  compliance and security engineering — which is why this repository files it under Blue
  Team rather than Fundamentals.

### eSOC — SOC Analyst

- Official page: **https://ine.com/security/certifications/esoc-certification**
  Dedicated product page (verified).
- Why it helps: direct access to the SOC Analyst syllabus and exam details without
  navigating the directory.
- Note: if the page ever 404s, fall back to the directory **https://ine.com/certifications**.

### eCIR — Certified Incident Responder

- Official page: **https://ine.com/security/certifications/ecir-certification**
  Dedicated product page (verified).
- Version note: INE published the **next-generation eCIR certification on 3 September
  2025** (INE's own blog post; the accompanying press release is dated 8 September 2025):
  <https://ine.com/blog/new-ecir-certification-advanced-incident-response-training>
- Why it helps: confirms the phases the exam drills. The five `methodology/` files in this
  repository (preparation, detection, containment, eradication, lessons learned) are the
  *study* organization used here and are not a published official domain list.

### eCDFP — Certified Digital Forensics Professional

- Official page: **https://ine.com/security/certifications/ecdfp-certification**
  Dedicated product page (verified) with the official forensics syllabus.
- Why it helps: scopes the acquisition and analysis topics and the exam deliverables you
  must practice.

### eCTHP — Certified Threat Hunting Professional

- Official page: **https://ine.com/security/certifications/ecthp-certification**
  Dedicated product page (verified).
- Version note: INE announced an **updated eCTHP certification in July 2025**, and later
  published *"INE Updates Threat Hunting Certification as Adversaries Evolve Beyond
  Malware"* on **20 November 2025**. The July date depends on which artefact you read: the
  newsroom announcement page and the blog post *"New eCTHP Certification: Master Real-World
  Threat Hunting"* both carry **28 July 2025**, while the GlobeNewswire press release is
  dated **24 July 2025**:
  <https://ine.com/newsroom/ine-security-launches-updated-certified-threat-hunting-professional-ecthp-cybersecurity-certification>
  · <https://ine.com/blog/new-ecthp-certification-master-real-world-threat-hunting>
  · <https://ine.com/newsroom/ine-updates-threat-hunting-certification-as-adversaries-evolve-beyond-malware>
  · press release: <https://www.financialcontent.com/article/gnwcq-2025-7-24-ine-security-launches-updated-certified-threat-hunting-professional-ecthp-cybersecurity-certification>
  Re-checked 19 September 2026 against the pages themselves: `2025-07-28` on the newsroom page
  and in the blog post's `datePublished`, `2025-11-20` on the update page, and `2025-07-24` in
  the press release's `datePublished` and its visible dateline. The two July dates are not a
  contradiction to resolve but two artefacts published four days apart; the earlier note here
  gave "24 July 2025" alone, which sent a reader to a page carrying the 28th.
- Why it helps: the module in this repository covers the *discipline* (hypothesis-driven
  hunting, telemetry, tradecraft, detection engineering); the official page is where the
  current exam scope lives.

## Emerging Technologies — eAIS and eIAMA (`04-Emerging-Technologies/`)

### eAIS — AI Systems Security Specialist

- Official page: **https://ine.com/security/certifications/eais-certification**
  Dedicated product page (verified).
- Version note: **launched 23 June 2026**. INE's launch materials describe it as an
  AI security fundamentals credential covering prompt injection, RAG security, tool misuse
  and safe operational use of AI; the credential's official title, as printed on issued
  badges, is **AI Systems Security Specialist**.
- Why it helps: direct access to the AI Security syllabus (attack vectors, defensive
  controls) for one of INE's newest certifications.
- Note: if the page ever 404s, fall back to the directory **https://ine.com/certifications**.

### eIAMA — Certified Identity & Access Management Technologist

- Official page: **https://ine.com/security/certifications/eiama-certification**
  Dedicated product page (verified).
- Version note: **launched 26 August 2026** as a vendor-neutral IAM certification.
- Naming note: the **product page** and issued badges say *"Certified Identity & Access
  Management Technologist (eIAMA)"*, and that is the wording this repository uses. INE's own
  launch announcement says something else — it announces "the launch of the Certified Identity
  & Access Management **Associate** (eIAMA) certification" and links a learning path slugged
  `identity-access-management-associate`:
  <https://ine.com/newsroom/ine-launches-eiama-certification-to-help-organizations-build-practical-identity-and-access-management-skills>
  Both wordings are INE's, so neither is an error to correct here; where a credential's title
  is at issue, the **product page and the issued badge govern**, and this repository follows
  them. Read those two rather than a summary, including this one.
  (Re-checked 19 September 2026: the announcement URL answers HTTP 200 and carries the
  *Associate* wording in its body; an earlier revision of this entry recorded the *Associate*
  claim as unsupported, which was itself wrong.)
- Why it helps: direct access to the IAM syllabus (identity lifecycle, authentication,
  authorization, zero trust, federation).
- Note: if the page ever 404s, fall back to the catalogue **https://ine.com/certifications**.

## Retired certifications — do not study for these

Five credentials from the eLearnSecurity era were retired from all INE platforms on
**1 October 2023** and cannot be newly obtained. The names below are the ones INE's own
notice uses:

| Code INE used | Name INE used | Retired |
|---|---|---|
| eCPTXv2 / PTX v2 | Penetration Testing Extreme | 1 Oct 2023 |
| eCMAP / Map v1 | Malware Analysis Professional | 1 Oct 2023 |
| eCXD / XDS v1 | Exploit Development Student | 1 Oct 2023 |
| eCRE / REP v1 | Reverse Engineering Professional | 1 Oct 2023 |
| eWDP / PWD v1 | Practical Web Defense | 1 Oct 2023 |

- Official notice: *"eLS is Retiring 5 Certifications: Here's What You Need to Know"*
  (published 21 April 2023) —
  <https://ine.com/blog/els-is-retiring-5-certifications-heres-what-you-need-to-know>
  — the names and dates above are copied from it. Read it there for the voucher rules and
  the course-availability deadlines that applied.
- The related courses stayed on the INE platform after the certifications were retired.
- This repository has no modules for them and does not plan to add any. If you find a
  vendor selling "official" training or vouchers for one of them, treat that as a red flag.

## How to re-verify a certification URL yourself

1. Open the homepage **https://ine.com**.
2. Navigate to **Security → Certifications** (the directory at
   **https://ine.com/certifications**).
3. Find the certification card, open it, and copy the URL — that is the current product
   page, syllabus page, and exam-information source of truth.
4. Check **https://ine.com/newsroom** for a version announcement if the card mentions one.
5. Record the date you verified it next to your notes, and re-check before exam day.

## Common Mistakes & Tips

- **Treating a guess as a link.** Every certification here links the product page INE
  publishes, and all twelve answered HTTP 200 on the verification date. Do not invent slug
  variants: a `…-certification` URL that was never checked looks official and points
  somewhere else. Note also that `https://ine.com/security/certifications` — the URL this
  repository used before 18 September 2026 — is dead; the catalogue is at
  <https://ine.com/certifications>.
- **Assuming a version suffix is official.** "eWPTXv2"/"eWPTXv3" are community labels for
  generations of the eWPTX exam; INE's credential title carries no version number.
- **Studying for a retired credential.** eCPTXv2, eCMAP, eCXD, eCRE and eWDP were retired
  on 1 October 2023. Check the certification's status before buying any study material.
- **Bookmarking login-gated course pages.** Course URLs inside the platform are not stable
  public links and frequently change; bookmark the certification directory instead.
- **Trusting third-party "official" reseller pages.** Only the ine.com and certs.ine.com
  domains are authoritative. Be skeptical of look-alike domains selling "official" bundles
  or dumps.
- **Ignoring the newsroom.** Syllabus and exam changes are announced there; check it before
  committing weeks of study to an outline that may have just changed.
- **Confusing badges with the exam result.** certs.ine.com verifies credentials; the actual
  exam booking and results live in your INE account on ine.com.

## Checklist

- [ ] Re-verify every URL in this file against https://ine.com/certifications and record the date
- [ ] Open the official eJPT syllabus and confirm the post-March-2026 exam scope
- [ ] Confirm all twelve product pages (eJPT, eCPPT, eWPT, eWPTX, eMAPT, eEDA, eSOC, eCIR, eCDFP, eCTHP, eAIS, eIAMA) still resolve (fall back to the catalogue if not)
- [ ] Check https://ine.com/newsroom for anything newer than the version notes above
- [ ] Read the retirement notice before touching any eCPTXv2 / eCXD / eCMAP / eCRE / eWDP material
- [ ] Bookmark https://certs.ine.com as the credential/badge lookup entry point
- [ ] Keep this page updated whenever a certification URL, name or version changes
