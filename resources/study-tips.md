# Study Tips — INE Security Certifications

> Personal, practical advice for preparing for INE Security certification exams. This page
> is methodology, not exam content: it covers how to plan a sprint, build a lab, take
> notes that fit this repo's conventions, retain what you learn, and behave ethically
> during preparation and on exam day.

## Planning a certification study sprint

- Pick **one certification at a time**. INE certs build on each other (for example,
  fundamentals before advanced red team), so trying to study several in parallel usually
  slows you down.
- Set a **concrete exam date first**, then work backward. A deadline converts a vague goal
  ("learn pentesting") into a schedule ("finish module 3 by Friday").
- Split the syllabus into **weekly chunks** that match the official modules, and keep
  1–2 buffer days per week for slippage — life interrupts study more often than study
  interrupts itself.
- Reserve **2–3 final weeks** for mock exams and full methodology run-throughs only; no
  new topics at that point.
- Review the official syllabus and the newsroom for changes before you start, then freeze
  your scope: chasing every new tool or video is scope creep.

## Building your own lab

- Use **virtual machines with snapshots** so you can destroy and restore targets freely.
  A snapshot before each attack run turns every mistake into a lesson instead of a rebuild.
- Keep an **isolated lab network** separate from your everyday network and never point lab
  tools at systems you do not own or have written permission to test.
- Budget resources honestly: a modest laptop can run lightweight targets; heavy enterprise
  labs (multiple domain controllers, many hosts) need more RAM and disk — plan before you
  start, not after a crash.
- Recreate the **exam-shaped environment**: for network pentests that means several
  interconnected hosts and a pivot point; for web exams, deliberately vulnerable web apps
  with realistic auth and business logic.
- Automate the boring parts (base images, shared tooling) with the scripts in this repo's
  `scripts/automation/` folder, then spend your time on the actual technique.
- Snapshot **clean baselines**: a stock target image and a freshly installed attacker VM
  let you re-run any scenario from scratch in minutes.

## Note-taking workflow that matches this repo

- Follow the **per-certification folder convention**: every module has `methodology/`
  (numbered phases), `tools/`, `labs/`, and `cheatsheets/` folders under the matching area
  (`01-Fundamentals/`, `02-RedTeam/`, `03-BlueTeam/`, `04-Emerging-Technologies/`).
- Write **methodology as numbered phases** (`01-reconnaissance.md`, `02-enumeration.md`,
  …) so your notes read like a procedure you can follow under exam time pressure.
- Keep **tools separate from methodology**: a command reference in `tools/` should be
  short and lookup-able, while the reasoning about *when* to use it belongs in
  `methodology/`.
- Log **lab runs in `labs/`**: what you set up, what you tried, what worked, what broke,
  and the exact command sequence that succeeded. This becomes your personal playbook.
- Collect **cheatsheets** as you go rather than copying someone else's: writing a command
  from memory into your own sheet is itself a recall exercise.
- Use `- [ ]` markers for open questions and unfinished sections (this repo's convention),
  and close them when the lab answers them — an open checkbox is a pending study item.
- Write notes in your own words and in English (the language of the exams and most
  documentation), and never paste copyrighted course material or exam content into notes.

## Spaced repetition and active recall

- Prefer **active recall over re-reading**: close the video, close the book, and write
  down the next step from memory; only then check.
- Turn each syllabus topic into **question cards** ("How do I enumerate SMB shares and
  what are the next three decisions?") and review them on an expanding schedule — the next
  day, then a few days later, then weekly.
- Use your own cheatsheets as the review material: re-derive the commands and flags from
  memory and diff them against your sheet.
- Schedule **weekly "cold start" drills**: attack a machine you have not touched in two
  weeks and notice which steps you forgot — those are the cards to review more often.
- Space review sessions with lab work so recall is tested *doing*, not just *reading*.

## Practicing methodology end-to-end

- Do not practice isolated tricks; rehearse the **whole loop** the exam expects: scope →
  recon → enumeration → exploitation → post-exploitation/pivoting → reporting.
- Time-box each phase during practice so you learn how long recon really takes versus
  how long you think it takes.
- Practice **note hygiene under pressure**: the notes you take during a run are the raw
  material for your report, and exam reports are graded artifacts, not afterthoughts.
- After every full run, write the **report as if it were the exam deliverable**: executive
  summary, findings with evidence, and remediation. The report is where most candidates
  lose points, so it deserves as much practice as the exploitation.
- End each run with a short **retro**: what wasted your time, what decision would have
  saved 20 minutes, what to look up before the real exam.

## Time management during practical exams

- On exam day, read the **full instructions and scope document before touching any
  machine**; the first 15 minutes of reading save hours of wrong assumptions.
- Divide the available time roughly into thirds in your head: environment/methodology,
  exploitation, and **report writing** — never let the report become a rushed afterthought.
- When stuck for a set number of minutes on one target, **move to another host or phase**
  and come back; a fresh perspective often solves what staring cannot.
- Keep a **running log with timestamps** during the exam (hosts, credentials, findings) so
  the report does not depend on memory.
- Respect the exam rules about what you may and may not do in the environment, and
  allocate buffer time at the end to review and submit properly. (This is general advice:
  always follow the specific instructions INE gives you for your exam session.)

## Staying within NDAs and ethics

- INE exams are covered by an NDA: never share, screenshot, or reconstruct **exam content,
  questions, machines, or answer specifics** in this repo, forums, or anywhere public.
- Write your own notes and solutions from your own work. Sharing or buying "exam dumps"
  violates the NDA, can void your certification, and also robs you of the learning.
- Practice only against systems you own or have explicit permission to test, and follow
  responsible-disclosure norms when you find real-world issues.
- Treat this whole repository as **your own study material**: it is fine to document your
  methodology and lab results, not fine to reproduce protected courseware or exam content.

## Common Mistakes & Tips

- **Starting advanced certs without fundamentals.** The red-team and blue-team tracks
  assume baseline knowledge; skipping the foundations makes every later module slower.
- **All study, no simulation.** Candidates who never do a timed, full-scope mock run are
  surprised by time pressure and report quality requirements on exam day.
- **Passive note-taking.** Copying slides or books into folders you never reopen is not
  studying; your notes only work if they are concise, personal, and reviewed.
- **Overbuilding the lab.** Chasing a huge enterprise lab before mastering the core
  methodology spends your best energy on plumbing; start small and add complexity.
- **Ignoring the report.** The report is a scored deliverable in practical exams — treat
  writing it as a skill to train, not a chore to survive.
- **Testing without permission.** In a home lab this is a discipline issue; in the real
  world it is a legal one. The habit starts in the lab.

## Checklist

- [ ] Set an exam date and build a backward schedule with weekly syllabus chunks
- [ ] Create the target certification module folder and subfolders (`methodology/`, `tools/`, `labs/`, `cheatsheets/`) before studying
- [ ] Build the lab with snapshots and an isolated network; document the setup in `labs/`
- [ ] Turn each syllabus topic into active-recall cards and schedule reviews
- [ ] Complete at least one timed, full-scope mock run including a written report
- [ ] Review exam instructions, scope, and NDA terms before exam day
- [ ] File this repo's notes only with your own words and never exam content
