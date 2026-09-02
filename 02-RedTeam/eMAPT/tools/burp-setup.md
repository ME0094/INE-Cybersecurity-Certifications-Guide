# Configuring Burp Suite for Mobile Testing

> eMAPT · Tools — INE-Cybersecurity-Certifications-Guide

## Purpose

Nearly every mobile app talks HTTPS to a back end. To assess that traffic you
route the device through **Burp Suite**, make Burp's CA certificate trusted on
the device, and — when the app pins certificates — bypass the pinning so the
proxy can still read and tamper with requests. This guide walks through the
whole chain and how to verify it works.

Everything here is standard lab technique. Only test devices and apps you own
or are authorized to assess.

## 1. Burp Proxy Listener

```bash
# Default: Burp listens on 127.0.0.1:8080
# For real devices you must bind to an interface the phone can reach:
#   Proxy > Proxy settings > Proxy listeners > Add
#   Binding: All interfaces (or your LAN IP), port 8080
```

- **Emulator:** reach the host via the alias `10.0.2.2`, so proxy
  `10.0.2.2:8080` works with the default listener bound to loopback.
- **Physical device:** must reach your host's LAN IP, e.g. `192.168.1.20:8080`.
  Keep Burp's listener on **all interfaces** and allow port 8080 through the
  host firewall.
- **adb reverse trick** (no Wi-Fi needed): forward the device's localhost to
  the host and point the proxy at `127.0.0.1:8080` on the device:

```bash
adb reverse tcp:8080 tcp:8080
# On the device, set proxy to 127.0.0.1:8080 (works over USB)
```

## 2. Point the Device at the Proxy

### Android emulator (all HTTP goes through the proxy)

```bash
# Set global proxy from the host:
adb shell settings put global http_proxy 10.0.2.2:8080
# Clear it afterwards:
adb shell settings put global http_proxy :0
```

### Android physical device (Wi-Fi)

Settings > Wi-Fi > (long-press network) > Modify network > Advanced > Proxy:
**Manual**, host = your computer's LAN IP, port = 8080.

### iOS device (Wi-Fi)

Settings > Wi-Fi > (i) next to the network > Configure Proxy > Manual, server =
computer LAN IP, port = 8080.

### Check it flows before adding the CA

Open a browser on the device and visit `http://burp` (or any http:// site).
Burp's HTTP history should show the request; an HTTPS page will show a
certificate warning until you install the CA (next section).

## 3. Install Burp's CA Certificate

Export the CA: Burp > Proxy > Proxy settings > **Import/Export CA certificate**
> Export **Certificate in DER format** (`cacert.der`).

### Android (user store — quick, works on many test apps)

```bash
# Convert DER -> PEM with an Android-compatible filename:
openssl x509 -inform DER -in cacert.der -out cacert.pem
# Install as a user CA (Settings > Security > Install from storage) or via adb:
adb push cacert.pem /sdcard/
# On the device: Settings > Security > Encryption & credentials > Install a certificate
```

Caveat: since Android 7 (API 24), apps **do not trust user-installed CAs by
default** — only the system store. Many intentionally vulnerable test apps
opt in via `networkSecurityConfig`, but modern real-world apps will ignore the
user store.

### Android (system store — needs root or a writable emulator image)

```bash
# Rename to the "subject hash" Android expects (old-style hashing):
HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1)
cp cacert.pem $HASH.0

# On a rooted device / google_apis emulator started with -writable-system:
adb root
adb remount
adb push $HASH.0 /system/etc/security/cacerts/
adb shell "chmod 644 /system/etc/security/cacerts/$HASH.0"
adb reboot
```

### iOS

1. Make the CA available to the device, e.g. serve it or email it; open with
   Safari.
2. Settings > General > VPN & Device Management > install the profile.
3. Settings > General > About > **Certificate Trust Settings** > enable **Full
   Trust** for the Burp CA (without this step iOS still rejects it).

## 4. Certificate Pinning and How to Handle It

**What pinning is:** the app hard-codes the expected server certificate or
public key (or pins via its own CA store) so that even a trusted proxy CA is
rejected. You will see TLS handshake failures in Burp and errors in the app.

Pinning is a **defense-in-depth control**, not a vulnerability. On authorized
test apps you bypass it to *see* the traffic; you report its presence and
strength, not treat it as a bug by itself.

### Approach A — objection (fastest on test apps)

```bash
# Android, with frida-server running on a rooted device/emulator:
objection -g com.example.app explore -c "android sslpinning disable"
# iOS (jailbroken device):
objection -g com.example.app explore -c "ios sslpinning disable"
```

### Approach B — Frida scripts (concept)

Frida-based "unpinners" hook the common TLS APIs and force them to accept any
certificate. Community scripts target popular libraries (OkHttp, TrustManager,
NSURLSession, AFNetworking). The concept:

```javascript
// unpin.js — conceptual: neutralize the default TrustManager
Java.perform(function () {
  var TM = Java.use("javax.net.ssl.X509TrustManager");
  TM.checkServerTrusted.implementation = function () {
    console.log("[*] TrustManager bypassed");
  };
});
```

Run with: `frida -U -f com.example.app -l unpin.js --no-pause`

Real apps need more: hook the specific library classes, wait for the right
class-loader, and sometimes re-run after each app update. objection's
implementation covers the common cases; write custom scripts when it does not.

### Approach C — repackaging (Android, no root needed)

```bash
apktool d app.apk -o src
# Remove/neuter the pinning code or library in smali, or drop the pinned
# networkSecurityConfig entry from AndroidManifest.xml/resources
apktool b src -o repinned.apk
# sign and install (see android-tools.md)
```

Repackaging breaks if the app verifies its signature or has strong protections;
it also changes the app under test, so document what you modified.

### Approach D — runtime patching inside the app logic

Hook the method that *builds/verifies* the connection (not the generic TLS
API), e.g. force an OkHttp `CertificatePinner` to check nothing:

```javascript
Java.perform(function () {
  var CP = Java.use("okhttp3.CertificatePinner");
  CP.check.overload("java.lang.String", "java.util.List")
    .implementation = function (h, p) { console.log("[*] pin check skipped"); };
});
```

## 5. Validate That Traffic Flows

```bash
# 1. Proxy set on device; Burp listener running
# 2. Install CA and trust it (or disable pinning)
# 3. From the app, trigger an action that calls the network (login, search, refresh)
# 4. In Burp: Proxy > HTTP history — filter by the app's host
#    and confirm requests show up decrypted (HTTPS with a lock icon)
# 5. Sanity check: tamper one request (send to Repeater, change a field,
#    forward) and watch the app/server react
```

A clean sign that interception works end to end: you can modify a request in
Burp Repeater and see the *server's* response change (e.g., an altered `id`
returns a different record).

## Common Mistakes & Tips

- **Proxy set but no traffic:** the app may ignore the system proxy (common
  with native sockets) — use `adb reverse`, an iptables redirect on a rooted
  device, or Burp's "Support invisible proxying" with the device's gateway.
- **CA in user store ignored:** remember Android 7+ default behavior; move the
  CA to the system store or use a test app that opts in.
- **iOS certificate "not trusted"**: you installed the profile but forgot
  **Full Trust** under Certificate Trust Settings.
- **Pinning bypass worked, then stopped**: apps update their pinning libraries;
  re-check which classes exist (`frida` + `Java.enumerateLoadedClasses` /
  objection's class listing) instead of guessing.
- **Firewall silently drops the phone**: allow Burp's port on the host and
  bind the listener to all interfaces for physical devices.
- **Leftover proxy breaks other work**: clear
  `settings put global http_proxy :0` when you finish, or the device's other
  traffic fails.
- Tip: keep the CA export + hash file in your lab folder; you reinstall it on
  every new AVD.
- Tip: use Burp's **HTTP history filter** per host — mobile apps generate a lot
  of noise (analytics, crash reporting).

## Checklist / Self-Test

- [ ] Burp's listener binds to an interface the device/emulator can reach
- [ ] The device proxy points at Burp and `http://burp` loads from the device browser
- [ ] I exported Burp's CA and installed it in the right store for my setup
- [ ] A browser on the device loads an HTTPS page without warnings (CA trusted)
- [ ] The target app's HTTPS requests appear decrypted in Burp HTTP history
- [ ] I can explain at least two pinning-bypass approaches and when each applies
- [ ] I used objection or a Frida script to disable pinning on a test app
- [ ] I re-validated interception after changing a request in Repeater

## Further Resources

- PortSwigger Burp Suite documentation (proxy, CA certs, mobile setup) — https://portswigger.net/burp/documentation
- OWASP MASTG (network communication / interception chapters) — https://owasp.org/www-project-mobile-security-testing-guide/
- Frida — https://frida.re/docs/
- objection — https://github.com/sensepost/objection
- Android network security config reference — https://developer.android.com/training/articles/security-config
