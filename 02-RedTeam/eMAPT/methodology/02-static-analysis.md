# eMAPT Phase 02 — Static Analysis

> eMAPT · Methodology — INE-Cybersecurity-Certifications-Guide

## Purpose

Static analysis examines the app without executing it: decompiling the
package into readable code, then reviewing the code and configuration for
vulnerabilities. This phase produces the attack-surface map that dynamic
analysis and exploitation will act on. Perform it only on apps you are
authorized to test, on your own analysis machine.

## Key Concepts

- **APK anatomy** — `classes.dex` (Dalvik bytecode), a binary
  `AndroidManifest.xml`, `resources.arsc`, `res/`, `assets/`, and signature
  files under `META-INF/`.
- **IPA anatomy** — a ZIP whose `Payload/<App>.app` holds the Mach-O binary,
  `Info.plist`, `embedded.mobileprovision`, and frameworks. App Store binaries
  are encrypted, so static analysis normally needs a decrypted copy.
- **Decompilation depth** — DEX → Java (jadx), DEX → JAR (dex2jar) + a
  decompiler, DEX → smali (apktool/baksmali, editable and reassemblable);
  Mach-O → headers (class-dump) or disassembly (Ghidra).
- **Attack surface review** — exported components, intents, deep links,
  storage, and secrets.
- **Code-level flags** — debug flags, backup settings, cleartext policies.

## Step 1 — Decompiling Android: APK → smali/java

```bash
# Full decode: smali sources + decoded resources + readable manifest
apktool d -f target.apk -o apk-out

# Java sources + resources in one tool (recommended default)
jadx -d jadx-out target.apk

# GUI navigation across classes and resources
jadx-gui target.apk

# Alternative pipeline: DEX to JAR, then browse with any Java decompiler
d2j-dex2jar target.apk -o target.jar
```

`jadx` is the workhorse for reading logic; `apktool` matters when you later
need to rebuild (repackaging in the dynamic phase). If you must edit code at
the lowest level, smali files inside `apk-out/smali*/` are the editable form.

```bash
# Search decompiled code for interesting calls
grep -rniE "getSharedPreferences|openOrCreateDatabase" jadx-out/ | head -20
```

## Step 2 — Decompiling iOS: binary → classes/disassembly

```bash
# Unpack the IPA
unzip target.ipa -d ipa-out

# Objective-C headers from a *decrypted* binary (jailbroken-device output)
class-dump -H Payload/Target.app/Target -o headers-out

# Linked libraries and load commands
otool -L Payload/Target.app/Target

# Quick string sweep for secrets and endpoints
strings -a Payload/Target.app/Target | grep -iE "https?://|api[_-]?key|secret" | head
```

Swift methods are not exposed as Objective-C headers, so for Swift-heavy apps
load the binary into **Ghidra** (or IDA) and inspect the disassembly and
recovered symbols. Keep in mind the binary you can buy or download may be
encrypted; decrypt it only through authorized channels (jailbroken test
device, client-provided decrypted build).

## Step 3 — Reviewing the Attack Surface

### Android: exported components and intents

```xml
<!-- AndroidManifest.xml (decoded by apktool/jadx) -->
<activity android:name=".AdminPanelActivity" android:exported="true">
  <intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <data android:scheme="myapp" android:host="admin" />
  </intent-filter>
</activity>
```

Questions to answer per exported component:

- Can a third-party app (or adb) start it without the intended permission?
- Does it trust extras passed in the Intent (URLs, file paths, user ids)?
- Activities: `android:exported="true"` with no permission guard.
- Services: exported and performing privileged actions (upload, crypto).
- Receivers: exported and reacting to broadcast data (state changes, OTP).
- Providers: exported and exposing `content://` URIs to query or write.
- Deep links (schemes above) are an entry vector into all of the above.

```bash
# Enumerate exported components from the decoded manifest quickly
grep -B4 -A8 'android:exported="true"' apk-out/AndroidManifest.xml
```

### iOS: equivalent surface

- `CFBundleURLTypes` schemes behave like Android deep links — any app can
  open them.
- App Groups and shared keychain entries widen the trust boundary.
- `UIPasteboard` and Handoff/Universal Links are cross-app data channels.

## Step 4 — Insecure Storage Patterns

| Pattern | Where to look | Typical flaw |
| --- | --- | --- |
| SharedPreferences | XML files in `shared_prefs/` | Tokens/PII in plaintext |
| SQLite databases | `databases/*.db` | Unencrypted sensitive rows |
| External storage | `getExternalFilesDir`, `EXTERNAL_STORAGE` | Readable by other apps / backups |
| Logs | `Log.d/w/e` calls | Secrets leaked to logcat |
| Backups | `android:allowBackup="true"` | `adb backup` exfiltrates data |
| iOS keychain / NSUserDefaults | binary calls, `NSUserDefaults` | Over-permissive keychain access groups |

```bash
# Find where databases and preferences are created
grep -rniE "openOrCreateDatabase|getSharedPreferences|\.db" jadx-out/ | head -20
```

## Step 5 — Hardcoded Secrets

```bash
# Common secret shapes across the decompiled tree
grep -rnoE "(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk-[A-Za-z0-9]{20,})" jadx-out/ | head
grep -rniE "password|passwd|secret|token|api[_-]?key|private[_-]?key" jadx-out/assets jadx-out/res | head -20
```

Watch for: embedded API keys, signing/private keys, OAuth client secrets,
Firebase config files (`google-services.json`), encryption keys stored next
to the cipher logic, and credentials in `assets/` or iOS bundled plists.

## Step 6 — Code-Level Flags and Config

- `android:debuggable="true"` — allows `jdwp` attach; a serious release flag.
- `android:allowBackup="true"` — app data extractable via `adb backup`.
- `android:usesCleartextTraffic="true"` / `network_security_config.xml`
  permitting cleartext — plaintext traffic over the wire.
- Low `minSdkVersion` — code paths for ancient, vulnerable OS versions.
- `android:exported` omitted on components with intent filters (pre-Android-12
  defaults to exported) — accidental exposure.
- Test/debug components left in release builds (`.DebugActivity`, `.Staging*`).
- iOS: `NSAllowsArbitraryLoads`, `NSAllowsArbitraryLoadsInWebContent` in
  `Info.plist`, debugger-attach symbols left in release binaries.

## Common Mistakes & Tips

- **Trusting one decompiler** — cross-check interesting methods in jadx and
  smali; obfuscators (ProGuard/R8) rename everything, so follow string
  references and framework calls, not names.
- **Skipping resources** — URLs, keys, and whole configs hide in
  `res/values/strings.xml` and `assets/`; scan them too.
- **Forgetting the binary manifest vs the merged one** — use the decoded
  manifest from the actual APK, not one reconstructed from memory.
- **iOS: analyzing an encrypted binary** — you will only see encryption
  stubs; obtain a decrypted build through authorized means first.
- **Confusing presence with exploitability** — a hardcoded key only matters
  with the matching cipher usage; trace how it is used before reporting.
- **Not recording evidence paths** — note class/method names and file:line so
  findings survive into the report.

## Checklist / Self-test

- [ ] I decoded the APK (apktool) and generated Java sources (jadx), or
      unpacked the IPA and obtained a decrypted binary for analysis.
- [ ] I listed every exported component, intent filter, and deep link and
      marked which ones lack permission guards.
- [ ] I audited storage: SharedPreferences, SQLite, external files, logs, and
      backup settings.
- [ ] I searched for hardcoded secrets and traced how each candidate is used.
- [ ] I checked security flags: debuggable, cleartext, allowBackup, network
      security config, and iOS ATS keys.
- [ ] I identified the app's crypto usage (algorithms, keys, modes) for later
      verification.
- [ ] I recorded class/method/file evidence for every finding.

## Further Resources

- OWASP MASTG (static-analysis guidance and test cases):
  https://mas.owasp.org/
- `jadx` documentation: https://github.com/skylot/jadx
- `apktool` documentation: https://apktool.org/
- dex2jar: https://github.com/pxb1988/dex2jar
- class-dump: https://github.com/nygard/class-dump
- Ghidra: https://ghidra-sre.org/
