# eMAPT Phase 04 — Communication Analysis

> eMAPT · Methodology — INE-Cybersecurity-Certifications-Guide

## Purpose

Communication analysis inspects everything the app sends and receives: HTTP
API calls, TLS behavior, and the trust the client places in the transport.
You set up a proxy, intercept traffic, bypass certificate pinning when needed,
tamper with requests, and verify the transport is actually secure. All testing
must target systems you are authorized to assess.

## Key Concepts

- **Proxying** — routing device traffic through Burp Suite so requests and
  responses can be inspected and modified.
- **TLS interception** — installing Burp's CA on the device so HTTPS can be
  decrypted and re-encrypted transparently.
- **Pinning bypass** — neutralizing in-app certificate pinning that rejects
  the proxy's CA.
- **Request tampering** — altering API parameters, headers, and bodies to
  probe server-side logic.
- **Transport security review** — cleartext, cipher suites, and certificate
  validation behavior.

## Step 1 — Proxying Mobile Traffic (Burp + device proxy)

### Host side

```bash
# Burp Suite: Proxy > Options > Proxy Listeners
# Add a listener on all interfaces: 0.0.0.0:8080 (for a physical device)
# Emulator only? Bind 127.0.0.1:8080 — reachable as 10.0.2.2:8080 inside the emulator
```

### Android emulator / device

```bash
# Emulator: point at the host loopback alias
adb shell settings put global http_proxy 10.0.2.2:8080

# Physical device on the same Wi-Fi/LAN: use the host's LAN IP
adb shell settings put global http_proxy 192.168.1.50:8080

# Verify current proxy and later clear it
adb shell settings get global http_proxy
adb shell settings delete global http_proxy
```

Physical devices can also set the proxy in Wi-Fi settings (long-press the
network > Modify > Advanced > Proxy). iOS: Settings > Wi-Fi > (i) > Configure
Proxy > Manual, host = your machine's LAN IP, port 8080.

## Step 2 — TLS Interception: Installing the Burp CA

### Android

```bash
# Export Burp's CA (Proxy > Import/Export CA certificate > Certificate in DER)
# Convert to PEM and compute the system-CA filename
openssl x509 -inform DER -in cacert.der -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
# -> e.g. 9a5ba575, so the file must be named 9a5ba575.0

# Install as a USER CA (works for apps that trust user CAs)
adb push cacert.pem /sdcard/
# then on the device: Settings > Security > Install from storage
```

**Android 7+ (API 24+) reality:** by default apps only trust the *system*
store, not user-added CAs. Options, in order of preference:

1. If the manifest allows it, add a `network_security_config.xml` that trusts
   user CAs, then repackage and resign (Phase 03).
2. On a rooted device/emulator, install the CA into the system store:

```bash
adb root
adb remount
adb push 9a5ba575.0 /system/etc/security/cacerts/
adb reboot
```

(On Android 10+ the CA store lives under an APEX module; emulator images with
`adb root`/`adb remount` or a Magisk CA module handle this — test your image
first.)

### iOS

- Install the CA: open the exported `.cer`/`.der` (email it or serve it over
  the LAN) and install the profile.
- Then enable full trust: Settings > General > About > Certificate Trust
  Settings > enable full trust for the Burp CA. Apps that validate properly
  against their own pinned keys will still refuse the proxy.

## Step 3 — TLS Interception: Bypassing Certificate Pinning

Pinning means the app trusts only a specific CA or leaf certificate, so the
proxy's CA is rejected. Detection happened in Phase 01; here you neutralize it.

```bash
# objection one-liner (wraps Frida; see Phase 03)
objection -g com.example.app explore
android sslpinning disable
# iOS equivalent:
ios sslpinning disable
```

For custom/rare pinning implementations, write a targeted Frida hook on the
validation entry points (Android `TrustManager` / OkHttp `CertificatePinner`;
iOS `SecTrustEvaluateWithError` / `URLSession` delegate callbacks):

```js
// pin-bypass.js — illustrative Android hook
Java.perform(function () {
  var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
  TrustManagerImpl.verifyChain.implementation = function (untrustedChain, ...) {
    return untrustedChain; // return the chain without validating
  };
  // OkHttp CertificatePinner variant
  var Pinner = Java.use("okhttp3.CertificatePinner");
  Pinner.check.overload("java.lang.String", "java.util.List").implementation =
    function (hostname, peerCerts) {
      console.log("[*] pin check skipped for " + hostname);
    };
});
```

```bash
frida -U -f com.example.app -l pin-bypass.js
```

After the bypass, HTTPS traffic should appear decrypted in Burp. If traffic is
still missing, confirm the proxy setting, the CA trust, and whether the app
uses non-HTTP protocols (WebSockets, protobuf over custom sockets) that Burp
sees differently.

## Step 4 — API Request Tampering

With traffic visible, test whether the server trusts the client too much:

```bash
# Typical flow
# 1. Use the app normally; study requests in Burp HTTP history.
# 2. Send an interesting request to Repeater (Ctrl-R).
# 3. Modify and replay:
#    - user/resource ids: GET /api/v1/orders/1001  ->  /orders/1002
#    - amounts/roles/flags in JSON bodies or JWT claims
#    - headers: Authorization, X-User-Id, Content-Type
# 4. Compare responses for authorization or logic differences.
```

Classic server-side flaws this reveals: broken object-level authorization
(IDOR), missing function-level checks, price/quantity manipulation, privilege
escalation via crafted claims, and replay of tokens or one-time codes. Any
security decision that should be enforced server-side is fair game.

## Step 5 — Testing Transport Security

- **Cleartext**: `android:usesCleartextTraffic="true"` or a
  `network_security_config` permitting HTTP, and iOS `NSAllowsArbitraryLoads`
  — confirm by capturing plaintext `http://` requests in Burp.
- **TLS strength of the API**: run `testssl.sh` against the discovered hosts
  to check protocol versions and cipher suites.
- **Certificate validation**: on a fresh install with no CA installed, the
  app should refuse invalid certificates; if it silently accepts them, the
  client validates nothing.
- **Redirects and mixed content**: an `https` page that fetches `http`
  resources downgrades the session; watch for `http`→`https` redirect leaks.
- **Missing security headers / HSTS** on API responses, and tokens in URL
  query strings (leaked through logs and referrers).

## Common Mistakes & Tips

- **Proxy set but CA not trusted** — Android 7+ ignores user CAs for most
  apps; the system-store install or repackaging step is not optional there.
- **Pinning bypassed but traffic still invisible** — the app may pin at a
  layer objection does not cover or use its own socket stack; hook the exact
  validation call site found in static analysis.
- **Forgetting to clear the proxy** — emulator/device keeps routing through a
  dead proxy after the test; delete the global setting when done.
- **Tampering without a control** — always replay the original request and
  compare; otherwise you cannot prove the server, not the client, changed the
  outcome.
- **Testing in the wrong network** — confirm the device is on the same network
  as Burp (or use the emulator's `10.0.2.2` alias) before debugging for hours.

## Checklist / Self-test

- [ ] Burp listener is reachable from the device and the proxy is configured.
- [ ] Burp's CA is installed and fully trusted on the test device.
- [ ] HTTPS traffic from the app appears decrypted in Burp history.
- [ ] Certificate pinning (if present) was bypassed and verified working.
- [ ] I replayed modified requests and identified server-side logic issues.
- [ ] I checked for cleartext traffic and weak/old TLS configurations.
- [ ] I verified the app rejects invalid certificates on a clean install.
- [ ] I cleaned up: proxy removed, test data and CAs scoped to the test device.

## Further Resources

- OWASP MASTG (network-communication test cases):
  https://mas.owasp.org/
- Burp Suite documentation: https://portswigger.net/burp/documentation
- Frida: https://frida.re/
- objection: https://github.com/sensepost/objection
- testssl.sh: https://testssl.sh/
