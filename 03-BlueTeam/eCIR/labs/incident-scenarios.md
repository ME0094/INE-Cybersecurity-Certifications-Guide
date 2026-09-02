# Incident Response Practice: Home Lab and Scenario Drills

> eCIR · Labs — English guide to building a private IR lab and running realistic response drills

Response skills are built by doing. This guide shows how to assemble a safe home IR lab
and then run scenario drills where you inject evidence of an incident, respond to it, and
score yourself against a checklist. Keep everything **isolated and disposable** — you are
practicing containment, so the lab must be built to be destroyed.

## 1. Building the Home IR Lab

### Host and Networking

- A laptop/desktop with 16+ GB RAM and an SSD. Virtualization: VirtualBox or VMware
  Workstation Player (free tiers are enough).
- Create an **isolated host-only or NAT-only network** for the lab. Do not give lab VMs
  general internet access unless a drill explicitly needs a filtered path; malware-like
  traffic must never touch your production network.
- Keep **snapshots**: one clean baseline per VM. Restore, don't rebuild.

### Recommended VM Set

| VM | Purpose | Notes |
| -- | ------- | ----- |
| `victim-win` | Windows 10/11 target | Disable Windows Defender real-time protection to let benign "malware-like" files survive; install Sysmon. |
| `victim-linux` | Linux web/app target | Small Apache/Nginx + PHP site for web-shell drills. |
| `analyst` | Kali or REMnux/FLARE VM | Tools: KAPE (Windows side), plaso, Volatility 3, Velociraptor client; write blockers are emulated by read-only mounts. |
| `server` (optional) | Log/AD-ish server | Collects Windows event logs; a free syslog or a simple Velociraptor server works. |

### Instrumentation to Install Before Drills

- **Sysmon** on Windows targets (default or SwiftOnSecurity config) → records process
  creation, network, and file events you will query during triage.
- **Event log forwarding** or a Velociraptor server so you can "see" the host remotely,
  like a real SOC would.
- **Velociraptor agents** on targets so collection during a drill matches real workflow.
- **Snapshot discipline**: after each drill, revert every VM to its baseline.

### Making Drill Injects

You can play attacker yourself or, better, have a partner feed you **injects** — timed
events or files that appear without your prior knowledge:

```text
INJECT 1 (t+00:00)  Alert: "Anomalous outbound TLS to 203.0.113.77 from victim-win"
INJECT 2 (t+00:10)  User report: "My files are renamed with .crypt and I can't open them"
INJECT 3 (t+00:20)  Files appearing in C:\Users\Public\: n.exe, readme.txt (ransom-style note)
```

Your job is to respond as the responder — preserve, triage, contain — without "cheating"
by inspecting how the inject was created.

## 2. Scenario Drill A — Ransomware-Like Host

**Premise:** A Windows workstation starts encrypting-looking activity: files renamed,
mass file writes, a ransom note, beaconing to an external IP.

- **Injects:** Anomalous outbound connection alert; user complaint about unreadable files;
  new files under `C:\Users\Public\` including a note; rapid writes to a network share.
- **Expected response actions:**
  1. Triage the alert: confirm the process, parent, and command line (Sysmon/`Get-Process`).
  2. Preserve volatile data: memory dump and KAPE collection **before** isolation if feasible.
  3. Contain: quarantine the host (disable NIC via management plane), disable the user account.
  4. Scope: check the share path for encrypted files; identify how far writes went.
  5. Document evidence IDs and hashes; draft the containment decision log.
- **Outcome checklist:**
  - [ ] Evidence captured and hashed before power-off or rebuild.
  - [ ] Containment action taken within your target time (e.g., 30 minutes).
  - [ ] Written case file records process tree, timeline, and decisions.

## 3. Scenario Drill B — Compromised Account with Mailbox Rules

**Premise:** A user reports "I keep getting logged out"; the SIEM flags impossible travel —
logins from the home country and a foreign IP minutes apart. Investigation shows an
Outlook/OWA rule forwarding mail externally.

- **Injects:** Impossible-travel alert; user report; forwarding rule discovered in
  mailbox audit logs; a few suspicious sign-in events with legacy auth.
- **Expected response actions:**
  1. Validate the alert (IP geolocation alone is weak — check ASN, device, and timing).
  2. Confirm compromise signals: sign-in logs, rule creation time, session activity.
  3. Contain: revoke sessions/tokens, reset credentials, remove the forwarding rule,
     require re-enrollment of MFA, block legacy auth.
  4. Scope: what mail was forwarded and to where; replay mailbox audit for exfiltration.
  5. Communicate: user notification, and regulatory assessment if data was exfiltrated.
- **Outcome checklist:**
  - [ ] Forwarding rule content preserved as evidence (screenshot + export, hashed).
  - [ ] Session/token revocation done and verified (account shows no active sessions).
  - [ ] Scope statement lists exactly which mailboxes/messages were affected.

## 4. Scenario Drill C — Web Shell on a Linux Server

**Premise:** An e-commerce-ish web server serves malware to some visitors. A scan shows
`/var/www/html/uploads/security.php` — a PHP web shell — and odd `www-data` commands.

- **Injects:** AV/WAF alert on a request to `security.php`; file-integrity alert on the
  webroot; outbound connections from the web server to a bulletproof host.
- **Expected response actions:**
  1. Verify the file is a web shell (review source; hash; check upload timestamp vs.
     access logs for the first request).
  2. Preserve: copy the web shell + access logs + process list **before** deleting.
  3. Contain: block the C2 IP at the firewall; take the uploads dir write path offline;
     decide whether to take the site down or serve a maintenance page.
  4. Eradicate: remove the shell and the upload vector that placed it (patching,
     disabling dangerous functions like `exec` in PHP, fixing permissions).
  5. Recover: redeploy from clean source; verify no other modified files (tripwire-style
     comparison against backups).
- **Outcome checklist:**
  - [ ] Web shell preserved with hash, first-request timestamp, and attacker IP.
  - [ ] Upload vector identified and closed (not just the file deleted).
  - [ ] Clean redeploy verified and monitoring re-enabled.

## 5. Scenario Drill D — Phishing → Credential Entry

**Premise:** A user clicked a link in a convincing "sharepoint" email and entered
credentials. Later, the account shows sign-ins from a suspicious IP and attempted
access to internal HR files.

- **Injects:** Phishing report from the user; email header analysis showing the real
  sender; sign-in logs after the click; attempted access to a sensitive share.
- **Expected response actions:**
  1. Triage the email: headers, link target, detonation of the URL in a sandbox.
  2. Correlate timing: click time vs. first suspicious sign-in.
  3. Contain: reset credentials, revoke sessions/tokens, enforce MFA, block the phishing
     domain/IP at the gateway, and sweep other inboxes for the same email.
  4. Scope: what the account could reach (mail, shares, SaaS apps) and what was accessed.
  5. Educate and document: user coaching, repeat-click monitoring, campaign metrics.
- **Outcome checklist:**
  - [ ] Email and headers preserved; link analyzed without user re-clicking it.
  - [ ] Account secured (password reset + sessions revoked + MFA enforced).
  - [ ] Same-campaign emails identified across the org and removed.

## 6. Scenario Drill E — Persistence Hunt (Full-Response Drill)

**Premise:** After Drill A, the "attacker" reinstalls persistence on the rebuilt host:
a scheduled task + registry Run key that downloads a benign beacon every hour. Your job
is a complete detection → containment → eradication → lessons-learned cycle.

- **Injects:** New beaconing alert 48h after the rebuild; scheduled task named after a
  Windows component; Run key entry pointing to `%TEMP%`.
- **Expected response actions:**
  1. Detect: hunt persistence locations (scheduled tasks, Run/RunOnce, services, WMI).
  2. Analyze: correlate task creation time with an earlier infection event; identify the
     downloader chain.
  3. Contain and eradicate: disable the task, remove the Run key and dropped file,
     block the beacon destination.
  4. Recover and verify: scan for other persistence; confirm no new beacon traffic.
  5. Lessons learned: why did the rebuild not include a clean reimage from trusted media?
- **Outcome checklist:**
  - [ ] Persistence mechanism fully mapped (trigger, payload, destination).
  - [ ] All persistence artifacts removed and verified gone across two check cycles.
  - [ ] Lessons-learned note written with one concrete process change.

## Common Mistakes & Tips

- **Practicing with real malware.** Use benign stand-ins (renaming scripts, EICAR-style
  files, or a known-safe "beacon" you control). Real ransomware belongs in a fully air-
  gapped, licensed sandbox environment — not a home lab.
- **Internet-connected lab VMs.** Keep the lab network isolated; leaks to your real
  network defeat the purpose and can harm production.
- **No baselines.** Without clean snapshots and a Sysmon baseline, you cannot tell
  "normal" from "compromised" during a drill.
- **Deleting evidence mid-drill.** Copy and hash before containment actions that destroy
  state (killing processes, deleting files).
- **Skipping the paperwork.** The case file, evidence log, and comms are part of the
  drill — score yourself on them too.
- **Rushing containment.** Practicing the wrong order (eradicate before preserve, isolate
  before memory capture) teaches bad habits; use the checklists to enforce the order.

## Checklist / Self-Test

- [ ] My lab runs on an isolated network and every VM has a clean baseline snapshot.
- [ ] I have completed Drill A (ransomware-like host) end to end with a written case file.
- [ ] I have completed Drill B (compromised account) including session revocation and scope.
- [ ] I have completed Drill C (web shell) including identifying and closing the upload vector.
- [ ] I have completed Drill D (phishing → credential entry) including header analysis.
- [ ] I have completed Drill E (persistence hunt) with a lessons-learned note.
- [ ] Every drill's evidence was hashed, logged, and traceable in the case file.
- [ ] I can run a complete drill start to finish without referring back to this guide.

## Further Resources

- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide* — https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- NIST SP 800-115, *Technical Guide to Information Security Testing and Assessment* — https://csrc.nist.gov/publications/detail/sp/800-115/final
- MITRE ATT&CK (use techniques to design realistic injects) — https://attack.mitre.org/
- Sysmon and SwiftOnSecurity configuration — https://github.com/SwiftOnSecurity/sysmon-config
- Velociraptor documentation — https://docs.velociraptor.app/
- KAPE (for drill collection) — https://github.com/EricZimmerman/KAPE
- REMnux (malware-analysis tools for the analyst VM) — https://remnux.org/
