# eMAPT Phase 01 — Mobile Reconnaissance

> eMAPT · Methodology — INE-Cybersecurity-Certifications-Guide

## Purpose

Reconnaissance frames the whole mobile assessment. Before any code review, you
must obtain the app package (APK or IPA), fingerprint it, understand its basic
structure, locate its backend endpoints, and stand up a controlled test
environment. Everything you learn here decides where you spend effort in the
static and dynamic phases. Work only against apps you are authorized to test.

## Key Concepts

- **App acquisition** — getting a copy of the target binary (from a device,
  a store mirror, a build server, or the client).
- **Fingerprinting** — package/bundle identifiers, version codes, SDK levels,
  signing certificates, and file hashes used to pin the exact build under test.
- **Attack surface preview** — the manifest / Info.plist already reveals
  exported components, permissions, and URL schemes before you decompile.
- **Backend discovery** — mapping API hosts, endpoints, and auth mechanisms
  that the app talks to.
- **Pinning detection** — noticing certificate-pinning hooks early so the
  communication phase can plan an interception strategy.
- **Environment setup** — a rooted/jailbroken test bed plus proxying tools,
  prepared before the app is ever launched.

## Step 1 — Acquiring the App

### Android: pull an APK from a device or emulator

```bash
# Find the target package
adb shell pm list packages | grep -i example

# Locate the on-disk path of the package
adb shell pm path com.example.app
# -> package:/data/app/~~xyz==/com.example.app-abc==/base.apk

# Pull a copy for offline analysis
adb pull /data/app/~~xyz==/com.example.app-abc==/base.apk target.apk
```

If you have no test device, download the APK from an official store or the
client's release channel. Always hash the file so the analyzed build can be
matched to the deployed one:

```bash
sha256sum target.apk
md5sum target.apk
```

### iOS: obtain an IPA

- From an **authorized device**: back up the iPhone/iPad (Finder or iTunes)
  and extract the `.ipa` from the backup, or use Apple Configurator with a
  supervised device.
- From **App Store builds** the binary is encrypted; decrypting requires a
  jailbroken device (e.g., the `frida-ios-dump` workflow) or a decrypted IPA
  provided by the client — stay within your authorization scope.

## Step 2 — Fingerprinting the Package

### Android

```bash
# Package name, version, min/target SDK, permissions, launchable activity
aapt dump badging target.apk

# Signing certificate details (v1/v2/v3)
apksigner verify --print-certs target.apk

# Native CPU architectures shipped in the APK
unzip -l target.apk | grep "lib/"
```

Record: `package`, `versionName`/`versionCode`, `minSdkVersion`,
`targetSdkVersion`, the signing certificate subject/SHA-256, and whether the
app bundles native libraries (`lib/armeabi-v7a`, `lib/arm64-v8a`, `lib/x86_64`).

### iOS

```bash
# Inspect the IPA container (a ZIP) without extracting to disk
unzip -l target.ipa | head -50

# Info.plist basics (macOS plutil; on Linux use python3 plistlib)
plutil -p Payload/Target.app/Info.plist
```

Note `CFBundleIdentifier`, `CFBundleShortVersionString`, `MinimumOSVersion`,
`CFBundleURLTypes` (registered schemes), and whether `Payload/Target.app`
contains an `embedded.mobileprovision`.

## Step 3 — Manifest / Info.plist Inspection Basics

You do not need full decompilation for recon; a decoded manifest is enough to
map the surface you will attack later.

```bash
# Decode resources + manifest (keeps smali out: --no-src)
apktool d --no-src -f target.apk -o apk-out
cat apk-out/AndroidManifest.xml
```

Look for, and record for later phases:

- `android:exported="true"` components and their intent filters (entry points).
- Custom permissions and `android:permission` guards.
- URL schemes inside `<intent-filter>` — these become deep links.
- `android:allowBackup`, `android:debuggable`, `android:usesCleartextTraffic`.
- `android:networkSecurityConfig` pointing at an XML policy.
- Providers (`<provider>`) with `android:grantUriPermissions`.

On iOS, the equivalent early signals live in `Info.plist`:
`NSAppTransportSecurity` (arbitrary loads), `NSAllowsLocalNetworking`,
`NSFaceIDUsageDescription`, `UIBackgroundModes`, and the URL schemes in
`CFBundleURLTypes`.

## Step 4 — Identifying Backend APIs

- Grep decoded resources and any non-code assets for hosts and paths
  (APK `assets/`, iOS bundled `.plist`/`.json`).
- Run the app later under a proxy (Phase 04) and map endpoints from traffic.
- Correlate hosts with the company's infrastructure: check which hosts are
  production vs staging (`api.example.com` vs `api-staging.example.com`).
- Record authentication hints: OAuth endpoints, token endpoints, custom
  headers, and any API keys visible in plaintext already.

```bash
# Quick host sweep over decoded resources
grep -rhoE "https?://[a-zA-Z0-9.-]+" apk-out/ | sort -u
```

## Step 5 — Certificate Pinning Detection

Detecting pinning early prevents a stalled communication phase:

- **Android**: search for `CertificatePinner` (OkHttp), `checkServerTrusted`
  overrides, a `network_security_config.xml` containing `<pin-set>`, or
  `ssl-pinning` libraries (TrustKit, etc.).
- **iOS**: look for pinned public keys in code, TrustKit configuration, or
  custom `URLSession`/`SecTrust` handling. A Frida/objection pinning-bypass
  test (Phase 04) is the authoritative confirmation.

```bash
grep -rniE "certificatepinner|pin-set|checkServerTrusted|trustkit" apk-out/ | head -20
```

## Step 6 — Setting Up the Testing Environment

Recommended baseline for Android:

```bash
# Emulator booted from an AOSP/Google-APIs image (adb root available)
# vs a Google Play image (adb root disabled) — pick the rootable one.
adb devices
adb root          # restart adbd as root on emulator/debug builds
adb shell id      # uid=0(root)

# Push frida-server matching the device arch, e.g. arm64
adb push frida-server-16.x.x-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
frida-ps -U       # list processes from the host to verify connectivity
```

For iOS you typically need a jailbroken device (or a simulator for limited
tests) with `frida-server` matching the iOS version and architecture. Verify
host-to-device reachability (`frida-ps -U`) before Phase 03.

Prepare the interception stack too: Burp Suite listening on `0.0.0.0:8080`,
its CA certificate exported, and the emulator/device proxy configured — full
details live in the communication-analysis phase.

## Common Mistakes & Tips

- **Analyzing the wrong build** — always record hashes and version codes;
  Play/App Store builds may differ from the client's release candidate.
- **Forgetting `adb root` availability differs by image** — Google Play
  images block root; use AOSP/Google-APIs images or a real rooted device.
- **Treating cleartext and pinning as the same issue** — they need different
  bypass strategies; note both during recon.
- **Skipping staging hosts** — staging APIs are frequently less protected and
  still in scope; enumerate them.
- **Ignoring the version history** — older versions on public mirrors often
  have weaker protections and identical backends.
- **Test-environment hygiene** — use dedicated test accounts and a sandboxed
  device profile; never point a personal device at the target network.

## Checklist / Self-Test

- [ ] I can acquire the exact APK/IPA build under test and have hashes recorded.
- [ ] I extracted package/bundle id, versions, SDK levels, and signing info.
- [ ] I decoded the manifest/Info.plist and listed exported components,
      schemes, and security flags.
- [ ] I enumerated candidate backend hosts and authentication endpoints.
- [ ] I checked for certificate-pinning indicators and know which bypass
      strategy Phase 04 will need.
- [ ] My rooted/jailbroken device or emulator runs frida-server and responds
      to `frida-ps -U`.
- [ ] Proxy and CA are staged so the app can be launched instrumented later.
- [ ] My test accounts and scope boundaries are confirmed and documented.

## Further Resources

- OWASP Mobile Application Security Testing Guide (MASTG):
  https://mas.owasp.org/
- Android `adb` reference: https://developer.android.com/studio/command-line/adb
- `apktool` documentation: https://apktool.org/
- Frida: https://frida.re/
- MobSF (fast static recon sweeps): https://github.com/MobSF/Mobile-Security-Framework-MobSF
