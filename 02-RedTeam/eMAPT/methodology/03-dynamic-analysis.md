# eMAPT Phase 03 — Dynamic Analysis

> eMAPT · Methodology — INE-Cybersecurity-Certifications-Guide

## Purpose

Dynamic analysis runs the app in a controlled, instrumented environment to
observe behavior that static analysis cannot reveal: runtime values, hidden
flags, anti-tampering logic, and how code reacts to real inputs. It relies on
instrumentation (Frida), runtime patching (objection), and occasionally
repackaging the app. Only run these techniques against apps you are authorized
to test, on devices you control.

## Key Concepts

- **Instrumentation** — injecting code into the running process to intercept
  function calls, arguments, and return values without modifying the app file.
- **Runtime patching** — changing behavior on the fly (bypassing checks,
  forcing branches) to explore hidden functionality.
- **Repackaging / resigning** — modifying the APK, rebuilding it, and signing
  it with your own key so the altered build installs and runs.
- **Emulator vs real device** — each environment changes what you can observe
  and what anti-analysis code will detect.

## Step 1 — Frida Instrumentation (concept + common hooks)

Frida is a dynamic instrumentation toolkit: `frida-server` runs on the
device, and the host drives it over USB/network. You attach to or spawn the
target and execute JavaScript hooks inside its process.

```bash
# Host side: install the tools
pip install frida-tools

# Verify device connectivity
frida-ps -U

# Spawn the app with the hooks loaded (Android). The main thread resumes by
# itself; add --pause to hold it until you type %resume in the REPL.
frida -U -f com.example.app -l hooks.js
```

Common hook categories:

```js
// hooks.js — intercept a Java method and print/log its args and result
Java.perform(function () {
  var Target = Java.use("com.example.app.CryptoHelper");

  // Replace implementation to observe arguments and tamper with results
  Target.decrypt.implementation = function (ciphertext) {
    console.log("[*] decrypt called with: " + ciphertext);
    var plaintext = this.decrypt(ciphertext);   // call the original
    console.log("[*] result: " + plaintext);
    return plaintext;                            // or return a forged value
  };
});
```

Common iOS equivalents hook Objective-C/Swift methods, e.g. intercepting
`SecTrustEvaluateWithError` or an app class method via
`ObjC.classes.TargetClass['-method:']`.

Everyday hooks for a mobile test:

- **Root/jailbreak detection bypass** — stub `File.exists` checks for
  `/su`, `Runtime.exec("su")`, and `NSFileManager` jailbreak probes.
- **Anti-debugging bypass** — neutralize `ptrace`/`TracerPid` checks.
- **Crypto observation** — log keys, IVs, and plaintexts at `Cipher.init`
  and `SecretKeySpec` construction.
- **Certificate validation bypass** — used by the communication phase.
- **Flag flipping** — force a boolean "isPremium" or "debugMode" getter to
  return the value you need.

## Step 2 — Runtime Patching with objection

[objection](https://github.com/sensepost/objection) wraps Frida into an
exploration toolkit for common tasks without writing JS.

```bash
# Attach to a running app (USB device by default)
objection -g com.example.app explore

# Common tasks inside the objection REPL
android sslpinning disable        # disable cert pinning (Android)
ios sslpinning disable            # disable cert pinning (iOS)
android root disable              # simulate "not rooted" for detection code
android hooking list activities   # enumerate launchable activities
android hooking list services
android hooking watch class com.example.app.CryptoHelper   # watch method calls
android heap search strings "secret"                       # search process memory
```

objection is ideal for quick wins: disable protections, list components, and
observe what the app does as you drive its UI.

## Step 3 — Repackaging and Resigning (Android)

When instrumentation is blocked (tamper detection, no Frida gadget), modify
the APK itself.

```bash
# 1. Decode, patch (e.g., inject Frida gadget or neuter a check)
apktool d target.apk -o apk-out
#    ... edit smali or add the frida-gadget load to the entry activity ...

# 2. Rebuild
apktool b apk-out -o patched.apk

# 3. Sign with a fresh key (the original signature is not yours to reuse)
keytool -genkeypair -v -keystore test.keystore -alias test -keyalg RSA \
        -keysize 2048 -validity 10000
zipalign -f 4 patched.apk aligned.apk
apksigner sign --ks test.keystore --ks-pass pass:changeit \
        --out signed.apk aligned.apk

# 4. Install the resigned build
adb install signed.apk
```

Consequences to remember: resigning breaks signature-based integrity checks,
Google Play services, and any update mechanism; the build no longer matches
the store release, so confirm behavior against the original too. A simpler
alternative is `objection patchapk --source target.apk`, which injects the
Frida gadget and lets you attach without root.

### iOS note

IPA repackaging on iOS requires code signing with the original or a
provisioning-profile-backed identity plus entitlements (`codesign`,
`ldid`). On a jailbroken device, app-level patching is usually unnecessary —
Frida + objection suffice — so iOS repackaging is a fallback, not the norm.

## Step 4 — Emulator vs Real Device

| Factor | Emulator | Real device |
| --- | --- | --- |
| Speed / snapshots | Fast, easy rollback | Slower, manual resets |
| Root / jailbreak | Trivial (AOSP/Google-APIs image) | Needs rooting or jailbreaking |
| Architecture | x86 images can't run arm64-only native libs | Native, matches production |
| Sensors/telephony APIs | Emulated or missing | Real |
| Anti-tampering realism | Easy to detect (Build props, no real TEE) | Closest to production |
| iOS | No official emulator; simulator only (x86_64, limited APIs) | Jailbroken device required for deep hooks |

Recommended practice: start on an emulator for fast iteration, then confirm
every finding on a real device where the app's protections actually run.

## Step 5 — Observing App Behavior

```bash
# Follow app logs while you drive the UI
adb logcat --pid=$(adb shell pidof -s com.example.app) -v color

# Watch files created/modified by the app
adb shell "find /data/data/com.example.app -newer /data/data/com.example.app 2>/dev/null"
adb shell run-as com.example.app ls -R files shared_prefs databases

# Screenshot evidence as you go
adb exec-out screencap -p > screen.png

# Capture process memory for later review
adb shell am dumpheap $(adb shell pidof -s com.example.app) /data/local/tmp/heap.hprof
```

Combine Frida logs, logcat, and filesystem diffs to build a behavior map:
which activities open, what is written where, and which checks gate
privileged flows.

## Common Mistakes & Tips

- **Frida version drift** — `frida-server` on the device must match the host
  `frida`/`frida-tools` version; mismatch surfaces as "unable to communicate".
- **Attaching after protections load** — spawn (`-f`) and hook early instead
  of attaching to a running, already-validated process.
- **Resigned APK behaving differently** — re-verify key findings against the
  original signed build before reporting.
- **Only testing on an emulator** — device-specific protections and ARM
  native code can change everything; validate on real hardware.
- **Instrumenting in production scope** — never run instrumentation against
  apps/systems outside your authorization.
- **Ignoring app self-defense** — if the app crashes or resets on attach,
  look for tamper/root detection and bypass it first (Step 1 hooks).

## Checklist / Self-Test

- [ ] frida-server runs on the device and `frida-ps -U` lists processes.
- [ ] I spawned the target with `frida -U -f` and confirmed hooks fire.
- [ ] I bypassed root/jailbreak and anti-debug checks where present.
- [ ] I used objection to disable pinning and enumerate components.
- [ ] I can repackage and resign an APK and install the patched build.
- [ ] I tested on both an emulator and a real device (or documented why not).
- [ ] I logged crypto inputs/outputs, filesystem writes, and key UI flows.
- [ ] I saved screenshots and logs as evidence for each observation.

> **Verification:** the spawn comment was corrected against the `frida` CLI's own
> option parser, `frida_tools/repl.py` lines 119-126 in `frida-tools` main
> (<https://raw.githubusercontent.com/frida/frida-tools/main/frida_tools/repl.py>,
> 2026-09-19): the hold flag is `--pause` and `on_spawn_complete` defaults to
> `"resume"`. `frida` is not installed here, so the command was not executed —
> primary documentation only.

## Further Resources

- Frida (official docs and examples): https://frida.re/
- objection: https://github.com/sensepost/objection
- OWASP MASTG (dynamic-analysis test cases):
  https://mas.owasp.org/
- Android `apksigner` reference:
  https://developer.android.com/studio/command-line/apksigner
- Android `adb` reference: https://developer.android.com/studio/command-line/adb
