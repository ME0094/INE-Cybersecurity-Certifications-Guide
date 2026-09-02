# Mobile Commands — Cheatsheet

> eMAPT · Cheatsheet — INE-Cybersecurity-Certifications-Guide

Compact quick-reference for daily mobile testing. Full explanations live in the
`tools/` and `labs/` guides. Replace `com.example.app` / `app.apk` with your
target. Authorized lab use only.

## adb — Devices, Packages, Apps

```bash
adb devices -l                              # list devices (-l = details)
adb -s emulator-5554 shell                  # target one device
adb connect 192.168.1.50:5555               # connect over TCP/IP (physical)
adb install -r app.apk                      # install (-r = reinstall)
adb uninstall com.example.app               # uninstall
adb shell pm list packages -3               # third-party packages
adb shell pm path com.example.app           # APK location on device
adb shell am start -n com.example.app/.MainActivity   # start activity
adb shell am force-stop com.example.app     # kill app
adb shell pidof com.example.app             # process id
adb logcat -c && adb logcat                 # clear, then follow logs
adb logcat --pid=$(adb shell pidof com.example.app)   # app-only logs
adb pull /sdcard/file .                     # copy off
adb push file /sdcard/                      # copy on
adb exec-out screencap -p > s.png           # screenshot to host
adb shell run-as com.example.app ls files   # app-private dir (debuggable)
adb root && adb remount                     # root + writable /system (userdebug)
adb reverse tcp:8080 tcp:8080               # device localhost:8080 -> host
```

## Proxy Control (see burp-setup.md)

```bash
adb shell settings put global http_proxy 10.0.2.2:8080   # emulator -> host Burp
adb shell settings put global http_proxy 192.168.1.20:8080  # physical device
adb shell settings put global http_proxy :0              # clear proxy
```

Emulator host alias: `10.0.2.2`. Physical devices need your host LAN IP and
Burp bound to all interfaces.

## apktool — Decode / Rebuild / Sign

```bash
apktool d app.apk -o src                   # decode (manifest + smali + res)
apktool d app.apk -s -o src                # skip sources (resources only)
apktool b src -o rebuilt.apk               # rebuild
# Sign the rebuild (required after any modification):
keytool -genkeypair -v -keystore t.keystore -alias t \
  -keyalg RSA -keysize 2048 -validity 10000
apksigner sign --ks t.keystore --ks-pass pass:android rebuilt.apk
adb install rebuilt.apk
```

## jadx — Decompile to Java

```bash
jadx -d out app.apk                        # decompile to out/sources
jadx --show-bad-code -d out app.apk        # keep code jadx cannot fully clean
jadx-gui app.apk                           # GUI with search (large apps)
grep -rniE "password|secret|token" out/sources/   # hunt secrets
grep -rni "http://" out/sources/           # cleartext endpoints
```

## Frida — Runtime Instrumentation

```bash
# Device side (arch must match: x86_64 emulator / arm64 phone)
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb root && adb shell "/data/local/tmp/frida-server &"

# Host side
frida-ps -Uai                             # list apps on USB device
frida -U -f com.example.app -l hook.js --no-pause   # spawn + script
frida -U com.example.app -l hook.js       # attach to running app
```

```javascript
// hook.js — force a method's return value
Java.perform(function () {
  var c = Java.use("com.example.app.AuthManager");
  c.isAdmin.implementation = function () { return true; };
});
```

## objection — High-Level Hooking

```bash
objection -g com.example.app explore                    # REPL
objection -g com.example.app explore -c "android sslpinning disable"
```

Inside the REPL:

```text
android sslpinning disable      # disable cert pinning (Android)
ios sslpinning disable          # disable cert pinning (iOS)
android hooking list activities # exported/registered activities
android hooking list services
android keystore list           # keystore entries the app can see
memory list modules             # loaded libraries
```

## Burp — CA Certificate Install

```bash
# Export CA: Burp > Proxy settings > Import/Export CA certificate > DER
openssl x509 -inform DER -in cacert.der -out cacert.pem
# Android system store (root): filename must be the subject hash
HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1)
cp cacert.pem "$HASH.0"
adb root && adb remount
adb push "$HASH.0" /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/"$HASH.0"
adb reboot
```

iOS: install profile → Settings > General > VPN & Device Management →
About > Certificate Trust Settings > enable **Full Trust**.

## iOS / macOS Commands

```bash
xcrun simctl list devices                        # simulators available
xcrun simctl boot "iPhone 15"                    # boot a simulator
xcrun simctl install booted Path/App.app         # install a build
xcrun simctl launch booted com.example.app       # launch by bundle id
xcrun simctl get_app_container booted com.example.app data  # data dir
xcrun simctl uninstall booted com.example.app    # clean reset

iproxy 2222 22 &                                 # USB SSH tunnel to device
ssh root@127.0.0.1 -p 2222                       # into jailbroken device
python3 dump.py com.example.app                  # frida-ios-dump: decrypted IPA
class-dump -H Payload/App.app/App -o headers/    # Objective-C headers
otool -ov Payload/App.app/App | head -80         # quick runtime metadata peek
ghidraRun                                        # then import the decrypted binary
```

## Environment Variables / One-Liners

```bash
export ANDROID_SDK_ROOT=$HOME/Android/Sdk         # Android SDK location
export PATH=$PATH:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator
# HTTP(S) proxies for host-side tools (rarely used for device traffic):
export HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080
# Useful compound checks:
adb shell pm list packages -3 | grep -i test      # find lab apps
adb shell dumpsys package com.example.app | grep -E "versionName|targetSdk"
frida-ps -Uai | grep -i bank                      # find app's process name
```

## Common Mistakes & Tips

- `adb` "more than one device" → add `-s <serial>`.
- `run-as` fails on non-debuggable apps → use root or a debug build.
- Unsigned `apktool` rebuilds never install (`INSTALL_PARSE_FAILED`) → sign.
- frida-server arch must match the device (`getprop ro.product.cpu.abi`).
- Proxy still set from a previous session breaks later work → clear with `:0`.
- iOS cert "installed but untrusted" → enable Full Trust separately.
- Tip: save every `screencap`/log snippet; it is report evidence later.
- Tip: keep `-c "android sslpinning disable"` handy for first traffic checks,
  then re-enable and hook pinning properly to learn the bypass.

## Checklist / Self-Test

- [ ] I can enumerate, install, launch, and kill an app with adb from memory
- [ ] I can set and clear the device proxy without looking at this file
- [ ] I can decode, modify, sign, and install an APK
- [ ] I can decompile an APK and grep the sources for secrets
- [ ] I can attach Frida and hook a method's return value
- [ ] I can disable SSL pinning with objection on a test app
- [ ] I know the iOS commands that apply to my hardware (simctl / dump.py / class-dump)
- [ ] I can install Burp's CA on Android and iOS from memory

## Further Resources

- adb reference — https://developer.android.com/studio/command-line/adb
- apktool — https://apktool.org/
- jadx — https://github.com/skylot/jadx
- Frida — https://frida.re/docs/
- objection — https://github.com/sensepost/objection
- Burp Suite documentation — https://portswigger.net/burp/documentation
- OWASP MASTG — https://owasp.org/www-project-mobile-security-testing-guide/
