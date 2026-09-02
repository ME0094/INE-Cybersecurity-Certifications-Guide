# Video Tutorials — INE Content and YouTube Educators

> Personal study resource for the **INE Security** certification program. This page has
> two parts: INE's own platform (the primary content source for every exam) and a short
> list of well-known public YouTube security educators, grouped by study area. Channel
> names and video titles change over time, so search each channel on YouTube and check
> that a video still matches the current syllabus before you invest time in it.

## How to use this page

- The official INE course and labs are the first source for every certification. External
  videos fill gaps, explain topics differently, and demonstrate real-world methodology.
- No invented course URLs are used: INE learning paths are accessed through the platform
  at **https://ine.com** once you have an account, and course pages are not stable public
  links.
- Channels are described generically (what each is *good for*), not as exam-specific
  guarantees — educator content is not produced by INE and may not match a given syllabus.

## INE's own platform — the primary source

- **INE Security platform** — https://ine.com
  All official courses, learning paths, practice labs, and exam-related study material
  live here behind an account. Why it helps: it is the only content that is guaranteed to
  match each certification's official syllabus.
- **Practical advice for using INE content.** Follow the learning path for your target
  certification in order rather than jumping between courses; redo the integrated labs;
  and use the platform's progress tracking to decide when you are ready for a mock exam.
- **Before each study sprint.** Check https://ine.com/newsroom for announced syllabus or
  platform changes that could make an older learning-path outline stale.

## Fundamentals — networks and pentest basics (eJPT · eCPPT)

- **The Cyber Mentor** — approachable, beginner-friendly walkthroughs and career-focused
  security content; a good first place to see full pentest methodology demonstrated end to
  end.
- **IppSec** — retired HackTheBox machine walkthroughs that show disciplined, narrated
  methodology; excellent for internalizing the enumeration-first workflow that practical
  exams reward.
- **John Hammond** — clear explanations of CTF-style challenges, malware, and scripting;
  good for picking up the "how do I figure this out" habit.
- **13Cubed** — system-level and blue-team oriented explanations that also help beginners
  understand what happens on the host during an attack.

## Red team — web and application security (eWPT · eWPTXv2 · eMAPT)

- **STÖK** — web-focused security content, including bug bounty methodology; good for
  seeing how web vulnerabilities are found and chained in the wild.
- **NahamSec** — bug bounty and web hacking walkthroughs with a strong focus on
  reconnaissance and thinking like an attacker against web applications.
- **LiveOverflow** — deeper, "how it actually works" explanations of exploits, memory
  corruption, and security research; useful when you want to go below the tool level.
- **IppSec** — his web-heavy machine walkthroughs also reinforce web testing phases that
  map to web penetration testing syllabi.
- **John Hammond** — CTF web challenges and scripting that build the manual-testing
  reflexes used in web and mobile app assessments.

## Blue team — SOC, incident response, and forensics (eSOC · eCIR · eCDFP)

- **13Cubed** — hands-on demos of Windows internals, forensics, and incident response
  tooling; a strong complement to SOC and IR study.
- **Gerald Auger (Simply Cyber)** — daily cyber news, SOC skills, and career content that
  helps you think like an analyst and stay current on the threat landscape.
- **John Hammond** — malware demonstrations and challenge-based analysis that exercise the
  same evidence-to-conclusion reasoning used in forensics and IR.
- **The Cyber Mentor** — occasional blue-team and general security content that rounds out
  the picture, though his catalog skews offensive.

## Emerging technologies — AI security and IAM (eAIS · eIAMA)

- Dedicated public channels for these newer syllabi are scarce and change quickly, so
  prefer INE's own courses on the platform.
- General-purpose educators (LiveOverflow, STÖK, and others) occasionally cover AI-assisted
  hacking and LLM tooling; treat any video as supplementary and confirm the topic against
  the official syllabus before studying it.
- For architecture-level topics (identity, zero trust), official documentation and vendor
  explainers tend to be more current than community videos — use the reading list in
  `resources/recommended-reading.md` alongside any video you find.

## Suggested blend: INE first, YouTube second

- Follow this order per topic: **official INE module → its lab → one YouTube walkthrough of
  the same technique → your own reproduction**. The INE module defines the scope, the lab
  gives you the environment, and an educator's video adds a second viewpoint on the
  *decisions* behind the commands.
- Use YouTube **before** starting a hard module to get a high-level map of the topic, and
  **after** the module to fill specific gaps — but avoid using it as the main course.
- When two educators explain the same technique differently, pick the one whose workflow
  you can reproduce, and note the difference in your `methodology/` notes.
- Keep a short list of the 2–3 videos per syllabus section that actually helped you; that
  list becomes your fast review material before the exam.
- Re-check occasionally whether the educator is still active and current: channels drift
  away from certification-relevant content over time, so prune your list when it stops
  matching the syllabus.

## How to pick a video (general guidance)

- Prefer videos under a few years old unless the topic is timeless (TCP handshakes,
  HTTP basics, methodology phases).
- Watch for *demonstration*, not just explanation: the best videos show the command being
  run, the output being read, and the next decision being made.
- Reproduce what you watch in your own lab within the same week — videos are the weakest
  study format if they are only watched.
- If a creator sells a course that mirrors an INE exam topic, remember that only INE's
  material is authoritative for the exam itself.

## Common Mistakes & Tips

- **Binge-watching without a lab.** Video feels productive but is passive; pair every
  video with a hands-on reproduction in your own environment.
- **Trusting outdated videos.** Old tools, old versions, and retired machines drift from
  current syllabi — always check the date and the syllabus.
- **Confusing YouTube educators with official content.** Only INE content is guaranteed to
  map to the exam; community videos may cover adjacent but out-of-scope material.
- **Jumping between playlists.** Follow one structured path (INE's learning path first,
  one educator's series second) instead of hopping between random videos.
- **Ignoring INE's own labs.** Third-party walkthroughs never replace the official labs,
  which are the closest thing to the exam environment you will get beforehand.

## Checklist

- [ ] Log in to https://ine.com and open the learning path for your target certification
- [ ] Finish the official course and labs before supplementing with YouTube content
- [ ] Select one educator per study area from this page and follow their series in order
- [ ] Check the publication date of every video against the current syllabus
- [ ] Reproduce each video's techniques in your own lab the same week
- [ ] Review https://ine.com/newsroom for syllabus changes before each exam attempt
- [ ] Keep this list updated when channels change focus or new relevant educators appear
