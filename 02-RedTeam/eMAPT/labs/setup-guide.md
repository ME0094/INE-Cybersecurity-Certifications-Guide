# Mobile Lab Setup Guide

> eMAPT · Lab — INE-Cybersecurity-Certifications-Guide

## Purpose

Before you can test anything you need a repeatable, legal lab: an Android
emulator or physical device, one or more deliberately vulnerable apps, and —
where possible — an iOS option. This guide walks through each choice, the
installation steps, and an environment checklist you can tick before every
session.

**Golden rule:** every app you install and test in this lab must be one you
wrote, one published for security training, or one you have written permission
to assess. This lab uses only public training apps.

## Host Requirements

- **RAM/CPU:** 16 GB RAM recommended; the Android emulator and iOS simulator
  are both heavy. Enable hardware virtualization in BIOS/UEFI.
- **Android acceleration:** Windows — install "Android Emulator Hypervisor
  Driver (AEHD)" or enable Windows Hypervisor Platform; Linux — KVM
  (`/dev/kvm`); macOS — Hypervisor.framework (built in).
- **Disk:** 30–60 GB free for system images, AVDs, and decompiled projects.
- **Java 17+** for apktool/jadx; **Python 3** for Frida tooling.

## Option A — Android Emulator (AVD) — Recommended Start

Emulators give you a disposable, rootable Android that you can snapshot, break,
and reset in seconds. Prefer **google_apis** (non-Play) images: they are
userdebug builds, so `adb root` and system-store changes work.

```bash
# One-time SDK install (command line, no Android Studio needed)
sdkmanager "platform-tools" "emulator" \
  "system-images;android-33;google_apis;x86_64"

# Create and launch an AVD
avdmanager create avd -n lab33 \
  -k "system-images;android-33;google_apis;x86_64" -d pixel_6
emulator -avd lab33 -writable-system &     # writable for CA installs

# Verify
adb devices
adb root && adb remount
```

Keep a second AVD on an older API level (e.g. android-27) because security
defaults and app behaviors differ across Android versions.

## Option B — Physical Android Device

Useful for testing real hardware behavior (fingerprint, sensors, OEM quirks).

```bash
# Enable Developer options: Settings > About > tap Build number 7x
# Then: Settings > System > Developer options > USB debugging ON
adb devices            # accept the RSA prompt on the phone
adb shell getprop ro.product.cpu.abi   # know the arch for frida-server
```

Notes:

- Root is **not required** for every test, but storage, system-CA, and
  instrumentation tasks get much easier with it. Rooting voids warranties and
  differs per device — research the specific model; when you cannot root, use
  repackaging (Frida gadget, `objection patchapk`) and app-private checks via
  debuggable builds instead.
- Keep the device dedicated to testing and factory-reset it between projects.

## Vulnerable Test Apps (public projects, install by name)

Use these instead of random App Store/Play Store apps:

- **OWASP UnCrackable Apps** (L1, L2, L3, L4) — Android and iOS apps with
  escalating challenges: root detection, debugger detection, pinning, and
  native code. Ideal for dynamic-analysis drills.
- **OWASP MASTG Hacking Playground** — Android and iOS apps built to
  demonstrate the MASTG test cases (storage, networking, crypto, etc.).
- **DIVA (Damn Insecure and Vulnerable App)** — Android app with focused
  insecure-coding exercises (storage, input validation, hardcoded issues).
- **InsecureBankv2** — Android banking-style app with a companion server,
  useful for end-to-end API testing.

Download these only from their official project pages/GitHub releases.

```bash
# Install on the emulator/device once downloaded:
adb install UnCrackable-Level1.apk
adb shell pm list packages | grep -i owasp    # confirm install
```

## iOS Options

Realistic iOS practice depends on your hardware:

1. **Mac + Xcode + Simulator (lowest barrier).** No jailbreak needed; simulator
   binaries are unencrypted, which simplifies static analysis.
   `xcrun simctl` drives everything (see ios-tools.md). Simulator behavior
   differs from hardware for keychain and device-only features.
2. **Jailbroken iPhone/iPad (fullest fidelity).** A dedicated device kept on a
   jailbreak-supported iOS version (check current tools such as checkra1n,
   palera1n, unc0ver, Dopamine for version support). Gives root, frida-server,
   decrypted app dumps, and system-wide interception.
3. **No Mac at all.** Use a jailbroken device driven from Linux/Windows
   (usbmuxd/iproxy + Frida over USB), or an authorized remote lab that provides
   Mac + devices. Do not try to run Xcode on non-macOS.

```bash
# Example: run the vulnerable iOS app on a simulator
xcrun simctl boot "iPhone 15"
xcrun simctl install booted UnCrackable-Level1.app
xcrun simctl launch booted owasp.mstg.uncrackable1
```

Deploying to a *physical non-jailbroken* iPhone requires signing with an Apple
Developer account (free accounts re-sign every 7 days via tools like
AltStore/Sideloadly) — plan around that friction, or use a jailbroken device.

## Frida Server on the Lab

```bash
# Android emulator/rooted device: download the matching frida-server release
# (x86_64 for emulator; arm64 for most phones)
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb root
adb shell "/data/local/tmp/frida-server &"
frida-ps -Uai          # host side — should list device apps
```

iOS (jailbroken): install "frida" from the Frida repo in Sileo/Cydia and
confirm with `frida-ps -U`.

## Environment Checklist (run before each session)

- [ ] Emulator/device boots and `adb devices` shows exactly the target
- [ ] Burp proxy is reachable from the device (see burp-setup.md)
- [ ] Burp CA is trusted for the target app (user/system store or pinning bypass)
- [ ] frida-server runs and `frida-ps -Uai` lists the test app
- [ ] Target app is installed from a trusted public source and I know its package id
- [ ] I have a clean snapshot/backup to restore the environment quickly
- [ ] I recorded which device/apps I am authorized to test in my notes
- [ ] Disk space and proxy settings were verified (no leftover `http_proxy`)

## Common Mistakes & Tips

- **Play Store images are not rootable** — use `google_apis`/AOSP images for
  testing and keep one Play image only if you must reproduce production quirks.
- **No hardware acceleration** — the emulator crawls or refuses to start; fix
  virtualization first (AEHD/WHPX on Windows, KVM on Linux).
- **Wrong system image arch** — x86_64 host images are required on Intel/AMD;
  ARM images on Apple Silicon Macs behave differently and are slower.
- **Forgetting the app needs a back end** — InsecureBankv2 and similar ship a
  server component; run it locally and point the app at it, or the app has
  nothing to talk to.
- **Testing an app you did not install** — a lab finding only counts against
  apps you placed there or were asked to test; keep the list explicit.
- **Mixing devices** — one emulator + one phone attached makes `adb` commands
  ambiguous; use `-s <serial>` or disconnect what you are not using.
- Tip: snapshot the AVD *after* the full toolchain + CA are installed, and
  restore from it for each new app — seconds instead of minutes.
- Tip: keep an `env.md` per project with the package ids, bundle ids, hosts,
  and versions you test; it becomes the header of your report.

## Checklist / Self-Test

- [ ] I created a google_apis AVD and can `adb root` it
- [ ] I installed at least one public vulnerable app and confirmed its package id
- [ ] frida-server runs on the emulator and the host can enumerate apps
- [ ] Burp intercepts the lab app's traffic (or pinning bypass is in place)
- [ ] I can restore a clean environment snapshot in under five minutes
- [ ] I know my iOS options and which one fits my hardware (simulator / jailbroken device / remote lab)
- [ ] My authorization notes list every device/app combination I test
- [ ] I documented the lab stack (versions, images, proxy, tools) for reproducibility

## Further Resources

- Android Studio / SDK command-line tools — https://developer.android.com/studio
- Android Emulator documentation — https://developer.android.com/studio/run/emulator-commandline
- OWASP MASTG (test apps and environment setup chapters) — https://owasp.org/www-project-mobile-security-testing-guide/
- OWASP MASTG GitHub (UnCrackable and Hacking Playground sources) — https://github.com/OWASP/owasp-mastg
- Frida — https://frida.re/docs/
- Apple developer documentation (simctl, deployment) — https://developer.apple.com/documentation/
