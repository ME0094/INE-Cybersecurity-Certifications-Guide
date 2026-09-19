# Android Testing Toolkit

> eMAPT · Tools — INE-Cybersecurity-Certifications-Guide

## Purpose

This guide is the working reference for the core Android toolchain used when
testing mobile apps: **adb** for device control, **apktool** for
decoding/rebuilding APKs, **jadx** for decompiling to Java, **Frida** and
**objection** for runtime instrumentation, and **Android Emulator (AVD)**
setup. Read it with a lab device in front of you and run every block.

All examples assume a test emulator or a device you own, with an app you are
authorized to assess. Replace `com.example.app` with the package you are
testing.

## Installation

```bash
# 1) Platform-tools (adb, fastboot) — package manager or SDK
sudo apt install adb           # Debian/Ubuntu
brew install android-platform-tools   # macOS

# 2) Java runtime (required by apktool/jadx)
sudo apt install openjdk-17-jre

# 3) apktool (install script from https://apktool.org)
apktool --version

# 4) jadx (release zip from https://github.com/skylot/jadx)
jadx --version

# 5) Frida client (Python) + objection
pipx install frida-tools objection     # or: pip install frida-tools objection
frida --version
objection version
```

On Windows, prefer **WSL2** or scoop (`scoop install adb apktool jadx`) and run
`adb` inside the same environment that talks to the emulator.

## adb — Device Control

adb is the Swiss-army knife for talking to Android devices and emulators.

```bash
adb devices -l                 # list connected devices/emulators
adb -s emulator-5554 shell     # open a shell on one specific device
adb install -r app.apk         # install, -r reinstall keeping data
adb uninstall com.example.app  # remove app
adb shell pm list packages     # list all packages
adb shell pm list packages -3  # only third-party packages
adb shell dumpsys package com.example.app   # package details (uid, permissions)

# Activity Manager: launch an activity by component name
adb shell am start -n com.example.app/.MainActivity
# Force-stop and get process state
adb shell am force-stop com.example.app
adb shell ps -A | grep example

# Logs
adb logcat -c                  # clear buffer first
adb logcat | grep -i example   # follow and filter by package tag
adb logcat --pid=$(adb shell pidof com.example.app)

# Files
adb shell run-as com.example.app ls files/     # app-private dir (debuggable apps)
adb pull /sdcard/Download/file .               # copy off device
adb push local.txt /sdcard/Download/           # copy onto device
adb exec-out screencap -p > screen.png         # screenshot without saving on device
```

`run-as` only works on **debuggable** apps or with root; otherwise read private
storage via a rooted device (`adb root`) or a backup extraction.

## Emulator Setup

```bash
# Create an AVD from the command line
sdkmanager "platform-tools" "emulator" \
  "system-images;android-33;google_apis;x86_64"
avdmanager create avd -n test33 -k "system-images;android-33;google_apis;x86_64" -d pixel_6

# Launch (windowed, or headless for scripts)
emulator -avd test33
emulator -avd test33 -no-window -no-audio &   # headless
emulator -avd test33 -writable-system         # needed to modify /system

# Google APIs (non-Play) images are userdebug builds → adb root works
adb root
adb remount     # make /system writable after -writable-system boot
```

Prefer **google_apis** (not Play Store) images for testing: they allow
`adb root` and system-store changes. Play Store images are production-like and
refuse root.

## apktool — Decode and Rebuild APKs

apktool unpacks resources and `smali` (assembly) so you can read and modify an
app, then rebuild it.

```bash
apktool d app.apk -o app_src      # decode; -s skips sources, -r skips resources
ls app_src
cat app_src/AndroidManifest.xml   # now readable XML
grep -i "exported\|debuggable\|cleartext" app_src/AndroidManifest.xml

# Modify something (smali or manifest), then rebuild
apktool b app_src -o rebuilt.apk

# Rebuilt APKs are unsigned → sign and install
keytool -genkeypair -v -keystore test.keystore -alias test \
  -keyalg RSA -keysize 2048 -validity 10000
apksigner sign --ks test.keystore --ks-pass pass:android rebuilt.apk
adb install rebuilt.apk
```

Common rebuild use cases: removing a pinning check, adding
`android:debuggable="true"`, or patching a flag from `0x0` to `0x1` in smali.
If the app verifies its own signature or uses hardened protections, rebuild may
break it — note that and switch to runtime hooking.

## jadx — Decompiling to Java

jadx turns an APK (or DEX) into readable Java source for fast manual review.

```bash
jadx -d out/ app.apk             # full decompile to out/
jadx --show-bad-code -d out2/ app.apk   # keep methods that fail to decompile
# GUI (interactive search is faster for large apps)
jadx-gui app.apk

# Typical review targets inside the decompiled tree
grep -rniE "password|secret|api[_-]?key|token" out/sources/ | head -20
grep -rniE "http://" out/sources/          # cleartext endpoints
grep -rni "setJavaScriptEnabled" out/sources/   # WebView usage
```

Use jadx for **reading**; use apktool for **changing** (jadx does not rebuild).
For obfuscated apps, start from strings and the manifest, then follow
references in the GUI.

## Frida and objection — Runtime Instrumentation

Frida injects a JavaScript engine into the target process so you can inspect
and modify behavior live; objection is a friendly CLI built on Frida.

```bash
# Push frida-server matching the DEVICE arch (x86_64 for emulator, arm64 for phones)
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb root && adb shell "/data/local/tmp/frida-server &"   # run as root

# Client basics
frida-ps -Uai                  # list installed apps on USB device (-U)
frida -U -f com.example.app -l hook.js   # spawn app with script
# Spawn, hold the app at its entry point, then %resume in the REPL:
frida -U -f com.example.app -l hook.js --pause

# objection one-liners
objection -g com.example.app explore        # attach and drop into REPL
objection -g com.example.app explore -c "android sslpinning disable"
# Inside the objection REPL:
#   android hooking list activities
#   android hooking list services
#   android keystore list
#   memory list modules
#   exit
```

Sample `hook.js` — override a method's return value:

```javascript
// hook.js: force isAdmin() to always return true on a test app
Java.perform(function () {
  var cls = Java.use("com.example.app.AuthManager");
  cls.isAdmin.implementation = function () {
    console.log("[*] isAdmin() called — returning true");
    return true;
  };
});
```

Frida needs a **rooted/emulator** environment for the classic `-U` flow; on
unrooted devices you can repackage the app with a Frida **gadget**
(objection's `patchapk` automates this).

## Typical Assessment Workflow

```bash
# 1. Enumerate
adb devices
adb shell pm list packages -3
adb shell dumpsys package com.example.app | grep -E "versionName|targetSdk|flags"

# 2. Pull the APK for static review
adb shell pm path com.example.app        # -> package:/data/app/.../base.apk
adb pull /data/app/.../base.apk app.apk  # (root) — or grab it from the app store/lab
jadx -d out app.apk && apktool d app.apk -o src

# 3. Run the app and observe
adb shell am start -n com.example.app/.MainActivity
adb logcat --pid=$(adb shell pidof com.example.app)

# 4. Instrument (see Frida section above)
# 5. Proxy traffic (see burp-setup.md) and re-test each action in the app
# 6. Storage checks
adb shell run-as com.example.app ls -R files databases shared_prefs
adb shell run-as com.example.app cat shared_prefs/example.xml
```

## Common Mistakes & Tips

- **Wrong frida-server arch.** x86_64 emulator with an arm64 server fails with
  a connect error — match `adb shell getprop ro.product.cpu.abi`.
- **Forgotten `chmod +x` / root** for frida-server; it must run as root on the
  device (`adb root` first, or launch from a root shell).
- **Installing an unsigned rebuild** fails with `INSTALL_PARSE_FAILED` — always
  sign after `apktool b`.
- **`run-as` "not debuggable"** — use a debuggable build or root; do not
  confuse this with a finding on a production app you only have the APK for.
- **Logcat flooding** — filter by `--pid` or the app tag instead of grepping
  the whole stream.
- **Two devices attached** — most commands need `-s <serial>` or they fail with
  "more than one device".
- Tip: capture `screencap` after every important step — it becomes report
  evidence.
- Tip: keep one AVD per Android version you must support; test on the oldest
  targetSdk you care about, since security defaults changed across releases.

## Checklist / Self-Test

- [ ] `adb devices` lists my emulator/device and I can open a shell
- [ ] I can install, launch, and force-stop a test app with adb commands
- [ ] I can decode an APK with apktool and read its AndroidManifest.xml
- [ ] I rebuilt and signed a modified APK and installed it successfully
- [ ] I decompiled an app with jadx and found a hardcoded string of interest
- [ ] frida-server runs on my device and `frida-ps -Uai` lists the test app
- [ ] I wrote and ran a Frida script that changed a method's return value
- [ ] I used objection to list activities or disable SSL pinning on a test app

> **Verification:** `frida-tools` has no `--no-pause` flag; the flag that holds a
> spawned process is `--pause`, and the default is to resume
> (`frida_tools/repl.py` lines 119-126 in `frida-tools` main,
> <https://raw.githubusercontent.com/frida/frida-tools/main/frida_tools/repl.py>,
> checked 2026-09-19). The `frida` binary is not installed in this lab, so the
> command lines here were not executed — primary documentation only.

## Further Resources

- Android platform-tools / adb reference — https://developer.android.com/studio/command-line/adb
- Android Emulator documentation — https://developer.android.com/studio/run/emulator-commandline
- apktool — https://apktool.org/ (and its GitHub releases page)
- jadx — https://github.com/skylot/jadx
- Frida — https://frida.re/docs/
- objection — https://github.com/sensepost/objection
- OWASP MASTG Android testing guide — https://mas.owasp.org/MASTG/
