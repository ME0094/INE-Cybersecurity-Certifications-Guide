# iOS Testing Toolkit

> eMAPT · Tools — INE-Cybersecurity-Certifications-Guide

## Purpose

This guide covers the iOS side of mobile testing: what a jailbroken test device
gives you, dumping and inspecting app binaries (frida-ios-dump, class dumps,
Ghidra), working with simulators, and — importantly — how to stay inside
authorized, practical constraints given how Apple's platform limits testing.

## Platform Realities First

iOS is a locked-down platform. Practical consequences for a tester:

- Installing apps outside the App Store on a real device normally requires a
  signed build (Apple Developer account) or a **jailbroken** device.
- Reading another app's files, keychain items, or memory requires root or
  per-app entitlements — the stock OS will not let you.
- Apps downloaded from the App Store are **encrypted (fair-play)**; on a real
  device you must decrypt the binary from memory before static analysis
  (jailbroken device + frida-ios-dump), or use the simulator where binaries
  are already decrypted.
- iOS versions and jailbreaks change frequently: a jailbreak that works on iOS
  15 may not exist for iOS 17. Check current jailbreak support before buying or
  upgrading a test device and keep a device on a supported version.

Because of these limits, much eMAPT-style iOS practice happens on a **Mac with
Xcode + simulators**, a **jailbroken device**, or an **authorized lab** that
provides both. Always test only devices and apps you own or are authorized to
assess, and respect Apple's terms and every NDA.

## Jailbroken Device Concepts

A jailbreak removes iOS code-signing and sandbox restrictions so you can run
tools as root. Modern examples (check current status before relying on them):
**checkra1n** (hardware-based, many devices), **palera1n**, **unc0ver**,
**Dopamine** (per-version support varies).

```bash
# After jailbreaking, install a package manager (Sileo/Cydia) and add the
# Frida repo (https://build.frida.re), then install "frida" from it.
# Verify the frida-server daemon is reachable from your host:
frida-ps -U          # USB-connected jailbroken device
frida-ps -H 10.0.0.5:27042   # remote over Wi-Fi
```

What a jailbreak unlocks for testing:

- SSH access (`ssh root@<device-ip>`, default password is device-specific —
  change it immediately).
- System-wide SSL interception (you can trust your CA in the system store).
- Running frida-server and dumping/decrypting apps from memory.
- Reading other apps' sandbox containers, keychain items, and preferences.

Do not leave a jailbroken device with default SSH credentials on a network;
this is both a personal risk and bad lab hygiene.

## Dumps and Metadata

### frida-ios-dump (decrypt the App Store binary)

On a real device the app binary on disk is encrypted; you dump the decrypted
version from memory after launch:

```bash
# Host side: forward SSH over USB, then run the dump script
iproxy 2222 22 &              # usbmuxd tunnel: host:2222 -> device:22
git clone https://github.com/AloneMonkey/frida-ios-dump
cd frida-ios-dump
pip install -r requirements.txt
python3 dump.py com.example.app        # by bundle id
python3 dump.py "Example App"          # or by display name
# Produces: com.example.app.ipa (decrypted) in the current folder
```

The resulting IPA can be unzipped and its `Payload/Example.app/Example`
binary fed to Ghidra/class-dump. If the app has jailbreak detection, disable it
first with Frida/objection before dumping.

### class-dump (Objective-C metadata)

Objective-C keeps rich runtime metadata (class names, methods, properties).
`class-dump` reconstructs a header file from it — ideal for mapping an app's
surface quickly. It only works on **decrypted**, non-stripped Objective-C
binaries.

**Platform:** `class-dump` and `otool` are macOS tools (the Xcode command-line
tools provide `otool`); they are not available on a Linux/Windows host. From a
non-Mac host, read the same metadata with Ghidra, or run the dump on a Mac.

```bash
class-dump -H Payload/Example.app/Example -o headers/    # old objc apps (macOS)
# Alternative tools: class-dump-swift, or 'otool -ov' for a quick look (macOS)
otool -ov Payload/Example.app/Example | head -80
```

Modern Swift apps strip much of this metadata; treat class dumps as a fast
overview, not a complete picture, and confirm logic in Ghidra.

## Ghidra for Mach-O Binaries

Ghidra is a free NSA reverse-engineering suite that handles Mach-O (the iOS
executable format) well and is the main binary-analysis tool in this module.

```bash
# Get Ghidra from https://ghidra-sre.org (a JDK 17+ is required)
ghidraRun          # GUI launcher
# 1. File > New Project > Non-Shared
# 2. Import the decrypted 'Example' Mach-O binary (or the .app bundle)
# 3. Analysis: default options are fine; wait for it to finish
# 4. Use Window > Symbol Table, strings, and XREFs to navigate
```

Typical triage flow in Ghidra:

1. **Strings** — search for URLs, API keys, `http://`, SQL, hardcoded tokens.
2. **Symbol table** — Swift symbols and Objective-C selectors reveal feature
   names (`_$s...AuthManager...`, `loginWithToken:`).
3. **Cross-references** — from an interesting string, follow XREFs to the
   calling function and read the surrounding logic.
4. **Function list** — sort by size/complexity to find real logic vs. boilerplate.

Ghidra is for *reading* a binary. Combine it with Frida to *verify* at runtime
that the code path you found is the one the app actually takes.

## Simulators

The iOS Simulator (Xcode) runs iOS apps on your Mac without a device or a
jailbreak, and simulator binaries are **not encrypted**, which makes static
analysis easy.

```bash
# Xcode command-line tools bring simctl
xcrun simctl list devices           # available simulators
xcrun simctl boot "iPhone 15"       # boot one
open -a Simulator                   # show the window
xcrun simctl install booted path/to/Example.app    # install a build
xcrun simctl launch booted com.example.app         # launch by bundle id
xcrun simctl get_app_container booted com.example.app data   # app data path
```

What simulators are good for: static analysis of decrypted builds, most
functional testing, basic storage checks, and Frida gadget experiments.

What they are **not** good for:

- Real keychain/secure-enclave behavior (simulator keychain differs).
- Hardware-backed features, biometrics, and true backgrounding semantics.
- Testing jailbreak-detection or device-only APIs.

Simulators also require Xcode on macOS — there is no official simulator for
Windows/Linux. If you have no Mac, prefer a jailbroken device plus a Linux/VM
host, or an authorized remote lab.

## Working Within Authorized Lab Constraints

- **Own the hardware:** a dedicated test iPhone/iPad kept on a jailbreakable
  iOS version beats borrowing devices you cannot reset or that belong to
  someone else.
- **Use public test targets:** OWASP MASTG publishes intentionally vulnerable
  iOS apps (see the labs setup guide) — install those instead of testing
  third-party App Store apps without permission.
- **Keep dumps local:** store decrypted IPAs and class-dump output only in
  your lab folder; do not redistribute apps.
- **Reset between drills:** reinstall the app and clear its container
  (`xcrun simctl uninstall` / delete + reinstall) so each test starts clean.
- **Document authorization:** record in your notes which device/app combos you
  are allowed to test; if a task would require testing something else, stop.

## Common Mistakes & Tips

- **Forgetting the binary is encrypted** — running class-dump/Ghidra on an
  undecrypted App Store binary yields garbage; dump it first or use the
  simulator.
- **Jailbreak-state roulette** — updating iOS can make the device
  un-jailbreakable or break frida-server; keep one device pinned to a known
  version and disable auto-updates.
- **Wrong architecture** — `arm64e` vs `arm64` Frida/shellcode mismatches
  cause crashes; pick the build matching the device (`uname -m` via SSH).
- **SSH with default credentials** — change the jailbreak SSH password
  immediately and use USB tunneling (`iproxy`) instead of Wi-Fi SSH on shared
  networks.
- **Treating simulators as devices** — platform-security findings from a
  simulator must be re-validated on hardware before you report them.
- Tip: save the decrypted IPA, the class-dump headers, and a Ghidra project
  export per app — you will re-open them in later phases.
- Tip: when a class name or method looks interesting, confirm it exists at
  runtime with `frida -U -f <bundle> -l probe.js` printing `ObjC.classes`.

## Checklist / Self-Test

- [ ] I can explain why App Store binaries are encrypted and how that changes static analysis
- [ ] I can list which iOS testing options my hardware supports (simulator / jailbroken device / remote lab)
- [ ] I dumped or obtained a decrypted test-app IPA and unzipped it
- [ ] I ran class-dump or `otool -ov` on a decrypted binary and read its headers
- [ ] I imported a Mach-O binary into Ghidra and followed an interesting string to its calling function
- [ ] I booted a simulator, installed a build, and located its data container
- [ ] My lab notes record which devices/apps I am authorized to test
- [ ] I know the current jailbreak options and which iOS versions they support

> **Verification:** unverified syntax references — not run. This lab has no macOS
> host, so `class-dump`, `otool`, Xcode and `simctl` were not executed; the
> platform split above is Apple/tool vendor documentation
> (<https://developer.apple.com/documentation/>, 2026-09-19). The one executed
> check in this file's scope is the crackme's build platform: the MASTG
> UnCrackable-Level1 IPA ships `iphoneos` device slices only.

## Further Resources

- OWASP MASTG iOS testing guide — https://mas.owasp.org/MASTG/
- Frida — https://frida.re/docs/
- frida-ios-dump — https://github.com/AloneMonkey/frida-ios-dump
- Ghidra — https://ghidra-sre.org/
- Apple developer documentation (simctl, code signing, deployment) — https://developer.apple.com/documentation/
- Jailbreak project pages (checkra1n, palera1n, unc0ver, Dopamine) — search their official sites for current device/version support
