# Practice Exercises

> eMAPT · Lab — INE-Cybersecurity-Certifications-Guide

## Purpose

Six guided drills that mirror the real phases of a mobile assessment: **static
analysis review, dynamic hooking, traffic tampering, and storage checks**, plus
two integration drills. Each exercise lists an objective, the setup you need,
steps with commands, the expected outcome, and a way to level up. Complete them
in order on your lab (see `labs/setup-guide.md`), against public vulnerable apps
such as the OWASP UnCrackable and MASTG Hacking Playground apps or DIVA.

Record every run: commands, output, screenshots. That log is the raw material
for your findings-writing practice.

## Drill 1 — Manifest & Static Analysis Review

**Objective:** from an APK alone, enumerate the app's attack surface and find
three concrete weaknesses without running it.

**Setup:** one APK (`UnCrackable-Level1.apk` or a MASTG playground app), jadx,
apktool.

```bash
apktool d app.apk -o src
# Manifest: exported components, debuggable, backup, cleartext
grep -E "exported=|debuggable=|allowBackup=|usesCleartextTraffic" \
  src/AndroidManifest.xml
jadx -d out app.apk
grep -rniE "secret|password|api[_-]?key|token" out/sources/ | head
grep -rni "setJavaScriptEnabled\|addJavascriptInterface" out/sources/
```

**Expected outcome:** you can list (1) every exported component, (2) the
`targetSdk`/minSdk and what security defaults that implies, and (3) at least
three findings such as a hardcoded secret, a cleartext URL, or a risky WebView
setting — each with the file:line evidence.

**Level up:** for each exported component, explain what an attacker could do
with it (launch, pass extras, read data) and write a one-line PoC using `am
start` or `am start-activity`.

## Drill 2 — Dynamic Hooking with Frida

**Objective:** instrument a running app and prove you can alter its logic — not
just observe it.

**Setup:** emulator with frida-server (see android-tools.md), the UnCrackable
L1 app (which checks for root/hooking), a Frida script.

```bash
frida-ps -Uai | grep -i uncrackable          # confirm target visible
# probe.js: log when a known method runs
cat > probe.js <<'EOF'
Java.perform(function () {
  var a = Java.use("owasp.mstg.uncrackable1.MainActivity");
  a.a.overload("java.lang.String").implementation = function (s) {
    console.log("[*] a() called with: " + s);
    return this.a(s);
  };
});
EOF
frida -U -f owasp.mstg.uncrackable1 -l probe.js
```

**Expected outcome:** triggering the action in the app prints your log line —
proof your hook is live. Then switch the method to return a fixed value and
observe the app's behavior change (e.g., a "success" screen that should not
appear). If the app detects Frida, first bypass its root/hooking detection with
a community Frida script — that bypass *is* part of the exercise.

**Level up:** enumerate loaded classes (`Java.enumerateLoadedClasses`) and hook
a method you discovered yourself rather than one given here.

## Drill 3 — Traffic Capture and Tampering

**Objective:** intercept the app's HTTPS traffic, understand the request
structure, and change one request in flight.

**Setup:** Burp proxying the emulator with the CA trusted (see burp-setup.md),
an app that logs in or loads a profile (e.g., InsecureBankv2 with its local
server).

```bash
adb shell settings put global http_proxy 10.0.2.2:8080
# Launch the app, log in, browse a profile
# Burp > HTTP history: filter by the app's host
# Right-click a request > Send to Repeater, alter a parameter, Send
```

**Expected outcome:** you see the login request in Burp (decrypted), you can
identify the auth mechanism (token in header, cookie, body), and you modified
one parameter in Repeater with an observable server reaction — an error, a
different record, or a status change. Record the before/after.

**Level up:** find an object-reference style parameter (`id`, `account`,
`user`) and enumerate neighboring values; note whether authorization is
enforced server-side.

## Drill 4 — Storage & Local Data Checks

**Objective:** determine what the app stores locally and whether sensitive data
leaks into files, databases, logs, or the keychain/keystore.

**Setup:** rooted emulator (or debuggable app), the same app after you have
used its login/save-data features.

```bash
# App-private storage (debuggable app):
adb shell run-as com.example.app ls -R files databases shared_prefs
adb shell run-as com.example.app cat shared_prefs/*.xml
adb shell run-as com.example.app cat databases/*.db

# Rooted device — check everywhere:
adb shell "find /data/data/com.example.app -type f"
adb shell sqlite3 /data/data/com.example.app/databases/app.db ".dump"

# Log leakage:
adb logcat -d | grep -iE "password|token|secret"

# Android Keystore usage (does the app use it?):
adb shell dumpsys package com.example.app | grep -i keystore
```

**Expected outcome:** a concrete inventory: which files exist, which contain
sensitive values (plaintext passwords, tokens, PII), whether the database is
encrypted, whether anything sensitive hits logcat, and whether the app stores
crypto keys in the Android Keystore or hardcoded/plaintext. Screenshot the
smoking gun for each finding.

**Level up:** check the app's backup behavior (`allowBackup="true"` + run
`adb backup`/`adb restore` on an older Android image) and whether a device
backup would expose the same data.

## Drill 5 — End-to-End Mini Assessment (Android)

**Objective:** run the full loop on one app in under an hour: recon → static →
dynamic → traffic → storage → report.

**Steps:** combine Drills 1–4 against a fresh app install. Timebox each phase
(10/15/15/10/10 minutes). End with a short written report: scope, tools,
findings table (weakness, evidence, impact, MASVS control ID), and a remediation
hint per finding.

**Expected outcome:** a one-page report with at least three verified findings,
each backed by a command output or screenshot, plus a straight list of what you
checked and found clean. Map every finding to a MASVS **control ID** — the
standard has eight categories today (`MASVS-STORAGE`, `MASVS-CRYPTO`,
`MASVS-AUTH`, `MASVS-NETWORK`, `MASVS-PLATFORM`, `MASVS-CODE`,
`MASVS-RESILIENCE`, `MASVS-PRIVACY`), not five. See the mapping table below for
a starting ID per drill.

## Drill 6 — iOS Cross-Check (hardware permitting)

**Objective:** repeat the core checks on iOS to understand platform
differences.

**Setup:** simulator or jailbroken device (see setup-guide.md), the iOS
UnCrackable L1 app — a *device* build, so it installs on the jailbroken device
and not on the simulator.

```bash
# Simulator path (macOS + Xcode, and a build compiled for the simulator: the
# MASTG UnCrackable-Level1.ipa is a device build and will not install here):
xcrun simctl install booted "/path/to/Debug-iphonesimulator/UnCrackable Level 1.app"
xcrun simctl launch booted sg.vp.UnCrackable1          # iOS bundle id
xcrun simctl get_app_container booted sg.vp.UnCrackable1 data
# Jailbroken device path: frida-ios-dump, class-dump, Ghidra (see ios-tools.md)
```

**Expected outcome:** you can state, from hands-on evidence, three ways iOS
testing differs from Android (encrypted binaries, keychain vs keystore,
no user-installable CA store without extra trust steps) and you completed at
least the static-analysis pass on the iOS app.

## MASVS mapping — example control IDs per drill

The current MASVS has **eight** categories: `MASVS-STORAGE`, `MASVS-CRYPTO`,
`MASVS-AUTH`, `MASVS-NETWORK`, `MASVS-PLATFORM`, `MASVS-CODE`,
`MASVS-RESILIENCE`, and `MASVS-PRIVACY`. Quote the control **ID**, not just the
category, in every finding. Starting points:

| Drill | Category | Example control ID and statement |
| --- | --- | --- |
| 1 — Static analysis | PLATFORM / CODE / STORAGE | `MASVS-PLATFORM-1` (IPC used securely), `MASVS-PLATFORM-2` (WebViews), `MASVS-CODE-4` (untrusted input validated), `MASVS-STORAGE-2` (no sensitive-data leakage) |
| 2 — Dynamic hooking | RESILIENCE | `MASVS-RESILIENCE-1` (platform integrity validated), `MASVS-RESILIENCE-4` (anti-dynamic-analysis techniques) |
| 3 — Traffic | NETWORK | `MASVS-NETWORK-1` (traffic secured), `MASVS-NETWORK-2` (identity pinning) |
| 4 — Storage | STORAGE / CRYPTO / PRIVACY | `MASVS-STORAGE-1` (secure storage), `MASVS-STORAGE-2` (no leakage), `MASVS-CRYPTO-2` (key management), `MASVS-PRIVACY-1` (data minimization) |
| 5 — End-to-end | AUTH | `MASVS-AUTH-1` (secure auth protocols), `MASVS-AUTH-3` (extra auth for sensitive operations) |
| 6 — iOS cross-check | CRYPTO / STORAGE | `MASVS-CRYPTO-2` (keychain / key management), `MASVS-STORAGE-2` (no leakage) |

Pinning (`MASVS-NETWORK-2`) is a control you report as present or absent, not a
vulnerability by itself (see `tools/burp-setup.md`).

## Common Mistakes & Tips

- **Skipping baseline:** always run the clean app once before hooking it, so
  you know what "normal" looks like.
- **No evidence:** commands without saved output are not findings — capture
  logs and screenshots as you go.
- **Tampering without understanding:** read the request in Burp before you
  change it; random edits teach less than one deliberate parameter change.
- **Storage checks on the wrong user:** `run-as` needs the exact app uid
  context; if it fails, the app is not debuggable — switch to a rooted check or
  a debug build instead of concluding "no data".
- **Ignoring failures to bypass protections:** UnCrackable L1 root/Frida
  detection is *the* exercise, not an obstacle to skip by reading answers.
- Tip: re-run each drill after reinstalling the app — stateful leftovers make
  second runs misleading.
- Tip: write the report the same day; findings lose their edge overnight.

## Checklist / Self-Test

- [ ] Drill 1: I listed exported components and three evidence-backed static findings
- [ ] Drill 2: my Frida hook changed an app behavior and I saved the output
- [ ] Drill 3: I intercepted, understood, and tampered with one HTTPS request in Burp
- [ ] Drill 4: I inventoried the app's local storage and identified sensitive data (or proved none)
- [ ] Drill 5: I produced a one-page report with at least three verified findings
- [ ] Drill 6 (if hardware allows): I completed the iOS static pass and noted platform differences
- [ ] Every finding has a command output or screenshot as evidence
- [ ] I mapped every finding to a MASVS control ID (one of the eight categories)

> **Verification:** the iOS identifiers were read from the official crackme
> itself on 2026-09-19: `Crackmes/iOS/Level_01/UnCrackable-Level1.ipa` from
> `OWASP/mastg` gives `CFBundleIdentifier = sg.vp.UnCrackable1`,
> `CFBundleSupportedPlatforms = ['iPhoneOS']` and a fat binary with only
> `armv7`/`arm64` **device** slices (parsed with Python 3.12 `plistlib` and
> `struct`), so it cannot run on a simulator; the Android APK of the same level
> decodes with apktool 2.7.0 to `package="owasp.mstg.uncrackable1"`. The MASVS
> categories and every control ID quoted here were taken from
> <https://mas.owasp.org/MASVS/> (eight categories, 24 controls). The
> `frida` line was corrected against `frida-tools` main (see `tools/android-tools.md`);
> `frida` itself is not installed, so no device command was executed.

## Further Resources

- OWASP MASTG — https://mas.owasp.org/MASTG/
- OWASP MASVS — https://mas.owasp.org/
- Frida — documentation and usage examples: https://frida.re/docs/home/
- objection — https://github.com/sensepost/objection
- UnCrackable / Hacking Playground app sources — https://github.com/OWASP/owasp-mastg
