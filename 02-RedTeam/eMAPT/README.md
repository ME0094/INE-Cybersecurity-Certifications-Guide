# eMAPT — Mobile Application Penetration Tester

> Area: 02-RedTeam · INE-Cybersecurity-Certifications-Guide

## Overview

The eMAPT (**e**Learn **M**obile **A**pplication **P**enetration **T**ester)
certification track focuses on the security assessment of mobile applications
for **Android** and **iOS**. A mobile penetration tester treats the app as a
software product that talks to back-end services over an untrusted network and
stores data on a device that the attacker may fully control.

eMAPT builds the full assessment cycle on mobile:

- **Preparation** — standing up an emulator or a physical test device,
  installing a testing toolchain, and routing device traffic through an
  intercepting proxy.
- **Static analysis** — reading the app's manifest, decompiled source code,
  resources, and bundled libraries to find weaknesses without running the app.
- **Dynamic analysis** — running the app under instrumentation to observe and
  alter behavior at runtime.
- **Communication analysis** — inspecting HTTP(S) traffic, spotting transport
  weaknesses, and working around TLS certificate pinning.
- **Exploitation** — chaining the findings above into concrete impact:
  stealing data from storage, abusing exported components, bypassing client-side
  checks, and escalating from a local foothold to back-end compromise.

> ⚠️ Public study material only. This guide contains no actual exam content and
> nothing protected by an NDA. Practice exclusively on devices, apps, and
> servers you own or are explicitly authorized to test.

## Certification version note

INE Security launched an **enhanced eMAPT certification** on **10 July 2025**. The
official announcement is the INE blog post
<https://ine.com/blog/master-real-world-mobile-security-new-cert-launched>.

This module describes the track in general public terms; the verified INE entry point
for current details is the eMAPT product page
<https://ine.com/security/certifications/emapt-certification> (fall back to the
directory <https://ine.com/security/certifications> if it ever 404s). Confirm exam
logistics there before booking.

## Skills You Build

- Operating Android and iOS devices from the command line (`adb`, `simctl`).
- Decompiling and reading APKs and IPA binaries (`apktool`, `jadx`, Ghidra).
- Instrumenting apps at runtime with Frida and objection.
- Intercepting and tampering with mobile HTTPS traffic in Burp Suite.
- Identifying and demonstrating common mobile weaknesses mapped to the
  OWASP Mobile Application Security Verification Standard (MASVS).
- Writing clear, evidence-backed findings reports.

## How to Use This Module

Work top to bottom in your first pass; then return to the folder that matches
the phase you are drilling.

| Folder / File | Purpose |
| --- | --- |
| `methodology/` | Ordered phases 01–05: reconnaissance, static analysis, dynamic analysis, communication analysis, exploitation |
| `tools/android-tools.md` | Android toolchain: adb, apktool, jadx, Frida/objection, emulator setup |
| `tools/ios-tools.md` | iOS toolchain, jailbroken-device concepts, Ghidra, simulators, lab constraints |
| `tools/burp-setup.md` | Burp Suite proxy + CA installation + pinning-bypass approaches |
| `labs/setup-guide.md` | Building your legal mobile lab (Android emulator/device, iOS options, vulnerable test apps) |
| `labs/practice-exercises.md` | Guided drills with objectives and expected outcomes |
| `cheatsheets/mobile-commands.md` | Compact command reference for daily use |

**Suggested rhythm:** read one methodology phase, then reproduce its commands
against a lab app from the setup guide, then add the tools and commands you used
to your personal notes. Hands-on repetition matters more than reading.

## Prerequisites

You do not need to be a developer, but these basics make the module far easier:

- Comfort with a Linux/macOS terminal: navigation, pipes, `grep`, environment
  variables, and running Python scripts.
- Basic HTTP knowledge: methods, headers, request/response flow, and TLS
  concepts (certificates, trust stores, pinning).
- Enough Java/Objective-C to *read* code: recognize classes, methods, string
  handling, and common crypto/network API calls.
- A lab machine with ~16 GB RAM and virtualization enabled, per
  `labs/setup-guide.md`.

If any prerequisite is weak, the tools guides link official documentation to
fill the gap before you start the methodology phases.

## Suggested Session Flow

A repeatable 90-minute practice session that keeps skills sharp:

1. **Warm-up (10 min):** re-type ten commands from the cheatsheet from memory.
2. **Phase drill (45 min):** pick one methodology phase and run it against a lab
   app you have not fully tested before (or re-run with a different app).
3. **Tool rotation (20 min):** use one tool you rarely touch — objection instead
   of raw Frida, Ghidra instead of jadx — so no tool goes rusty.
4. **Write-up (15 min):** record one verified finding with evidence in your
   notes, including the MASVS control it maps to.

Tracking which drills you have completed lives in `labs/practice-exercises.md`;
this module's progress checklist is below. A fast "is the lab alive" smoke
test before each session:

```bash
adb devices                 # emulator/device visible?
frida-ps -Uai               # Frida can enumerate installed apps?
adb shell pm list packages -3   # test apps present?
```

## Study Roadmap

1. **Week 1 — Foundations.** Install Android Studio + SDK platform tools,
   create an AVD, and complete the Android toolkit guide. Install a vulnerable
   test app and confirm you can install/uninstall and read `logcat`.
2. **Week 2 — Static analysis.** Learn `apktool` decode/rebuild and `jadx`
   browsing. Practice finding common weaknesses in a decompiled test app
   (hardcoded secrets, insecure storage, exported components, weak WebView use).
3. **Week 3 — Traffic.** Stand up Burp, proxy an emulator, install the CA, and
   capture app traffic. Learn to recognize and bypass pinning on test apps.
4. **Week 4 — Dynamic analysis.** Drive Frida from the command line, then
   objection's high-level commands. Hook functions and change app behavior.
5. **Week 5 — iOS basics.** On a Mac (or a Linux/Windows box with a
   jailbroken device), practice iOS concepts: app bundle structure, class
   dumps, Ghidra triage, and simulator testing — within authorized constraints.
6. **Week 6 — Integration.** Run the full practice-exercise set end to end and
   write short reports per drill with evidence (screenshots, commands, output).
7. **Ongoing — Drill the cheatsheet.** Re-type commands from
   `cheatsheets/mobile-commands.md` until they are automatic; refresh with new
   public test apps from OWASP MASTG.

## Common Mistakes & Tips

- **Reading without a device open** — mobile testing is muscle memory; every
  phase doc expects you to run the commands, not just follow along.
- **Skipping phases** — jumping to "exploitation" before you can read a
  manifest or capture traffic reliably makes every later drill slower.
- **One platform only** — Android-only practice leaves the iOS differences
  (encryption, keychain, CA trust) unexplored until they cost you time later.
- **No evidence habit** — findings without saved commands/screenshots are not
  reproducible; capture as you go.
- **Testing the wrong target** — only ever test lab apps or assets you own or
  are authorized to assess; keep that list in your notes.
- Tip: keep a personal "lessons log" per module folder and add one entry per
  session; it becomes your fastest revision material.

## Checklist / Self-Test

- [ ] Read `methodology/01-reconnaissance.md` through `05-exploitation.md` in order
- [ ] Reproduce every command from `tools/android-tools.md` on an emulator
- [ ] Configure Burp and intercept traffic from at least one app
- [ ] Complete `labs/practice-exercises.md` and record expected outcomes
- [ ] Review `cheatsheets/mobile-commands.md` and mark commands you cannot yet type from memory
- [ ] Practice iOS steps on whatever hardware you have (simulator, jailbroken device, or a rented/authorized lab) without breaking platform rules
- [ ] Re-read the OWASP MASVS control groups and map your findings to them
- [ ] Confirm you have only ever tested apps/devices you own or are authorized to assess

## Legal and Ethical Baseline

- Test only assets you own or hold written authorization for.
- Do not distribute or resell any exam-related material; observe all NDAs.
- When Apple platform limits or jailbreak requirements exceed your hardware,
  use alternatives (simulator, public test apps, managed labs) rather than
  bypassing vendor terms or testing devices you do not control.

## Further Resources

- OWASP Mobile Application Security Testing Guide (MASTG) — https://owasp.org/www-project-mobile-security-testing-guide/
- OWASP MASVS — https://mas.owasp.org/
- Android developer command-line documentation — https://developer.android.com/studio/command-line
- Frida — https://frida.re/docs/
- PortSwigger Burp Suite documentation — https://portswigger.net/burp/documentation
- Official documentation for each tool is linked at the bottom of the matching module file.
