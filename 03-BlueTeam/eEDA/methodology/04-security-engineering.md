# Security Engineering

> eEDA · Methodology — Enterprise Defense Administrator
>
> Phase 04 of nine. Engineering is where the other phases get built: the baselines from [05](05-asset-inventory-and-configuration.md) are enforced here, the identity design serves [06](06-identity-and-privileged-access.md), the exposure measured in [07](07-vulnerability-and-patch-management.md) comes from these designs, and the visibility designed here is what [09](09-soc-and-incident-response-interface.md) depends on.

## Purpose

Security engineering turns governance and risk decisions into real, defensible systems: designs that fail safely, networks that contain attackers, hosts that are boring to compromise, data that stays confidential, and visibility that makes attacks visible. This guide covers secure design principles, network segmentation and zones, hardening baselines, cryptography fundamentals for defense (TLS and data at rest), logging/monitoring architecture, and identity foundations.

## Secure Design Principles

These principles (drawn from Saltzer & Schroeder and modern practice) are the "why" behind most good controls:

- **Least privilege** — every subject (user, process, service) gets the minimum rights needed. Enforced per-session, per-task, not per-role-out-of-habit.
- **Defense in depth** — multiple independent layers so one failure does not mean compromise (network + host + app + data + monitoring).
- **Fail closed / fail safe** — on error or default, deny rather than allow; a misconfigured firewall must drop, not accept.
- **Compartmentalization / segmentation** — break the environment into cells so a breach in one does not become a breach everywhere.
- **Secure by default** — ship with the safe configuration; disable unneeded services; opt-in to features rather than opting out of risk.
- **Minimize attack surface** — fewer services, ports, protocols, plugins, and stored secrets means fewer ways in.
- **Assume breach / zero trust posture** — do not trust location or network; authenticate and authorize every request, encrypt everywhere.
- **Never trust user input** — validation, encoding, parameterized queries (applies to configs and logs too, not just web apps).
- **Simplicity and auditability** — complex designs hide flaws; every decision should be explainable and reviewable.

## Network Segmentation and Zones

Segmentation converts "the network is flat" (one compromise = everything) into zones with controlled choke points.

### Classic layered model

```text
Internet
   |
[ Edge firewall / WAF / DDoS ]
   |
 DMZ          (web front ends, reverse proxies, mail gateways)
   |  (controlled, logged flows)
[ Internal firewall / ACL ]
   |
 Internal LAN  (workstations, internal apps)
   |  (least-privilege flows only)
[ Server/App zone firewall ]
   |
 Backend zone  (databases, core systems — no direct Internet path)
   |
[ separate admin plane ]  (management network for admins, jump hosts)
```

- **DMZ**: the only zone reachable from the Internet; systems there are treated as potentially hostile. Web servers in the DMZ talk *only* to the specific app services they need, never to the whole internal network.
- **East-west control**: the same logic applies between internal zones and workloads — a workstation should not be able to reach the domain controller or the database on arbitrary ports.
- **Microsegmentation**: per-workload or per-host policies (often software-defined, e.g., via cloud security groups, NSX, or host firewalls) instead of big network chunks. Used heavily in zero-trust and cloud designs so policy follows the workload, not the rack.

Design checklist per flow: who is the source, what is the destination, which port/protocol, and why is it allowed? Every allow rule should trace to a documented business need.

```text
Example security-group policy (cloud, expressed as rules):
  Inbound  10.0.1.0/24   -> app-srv:443/tcp      (users via LB only)
  Inbound  app-srv       -> db-srv:5432/tcp       (app -> DB)
  Inbound  admin-vpn     -> app-srv:22/tcp        (SSH via jump host)
  Everything else: DENY (fail closed)
```

## System Hardening Baselines (CIS)

Hardening reduces a host's attack surface to a known-good state. The **CIS Benchmarks** (Center for Internet Security) are the de facto public baseline: per-OS/application, consensus-developed configuration recommendations mapped to controls.

Typical hardening categories:

- Remove/disable unnecessary software, services, and accounts.
- Patch OS and applications; apply security updates on a defined SLA.
- Enforce strong local and domain authentication (password policy, account lockout, MFA for admins).
- Restrict local admin rights and use least-privilege service accounts.
- Configure auditing and log shipping (who enabled what, when).
- Harden network stacks and local firewalls (fail closed).
- Secure boot, disk encryption, and screen-lock/idle timeout.

The classic hardening triad is **baseline → enforcement → verification**:

```text
1. Baseline   : choose the CIS level appropriate to the workload
                 (Level 1 = sane default, Level 2 = high security,
                  often with approved deviations documented).
2. Enforce    : apply via configuration management so drift is corrected,
                 not just fixed once (Ansible, DSC, GPO/Intune, cloud images).
3. Verify     : scan continuously against the baseline (CIS-CAT, OpenSCAP,
                 osquery, cloud security posture tools).

Example (Linux, sshd hardening):
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
AllowUsers ops@10.0.0.0/8        # restrict admin login source
LogLevel VERBOSE

Example (Windows, PowerShell one-liner for a baseline check):
Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -eq 'Running'}
# review the list against the approved service manifest
```

Golden images matter: build new hosts from a hardened, patched image rather than hardening after deployment — and treat configuration drift as a security finding, because drift is how attackers slip back in.

## Cryptography Fundamentals for Defense

You do not need to be a cryptographer, but you must know *where* crypto is required, *which* mechanism fits, and *how to spot weak setups*.

### TLS for data in transit

- Purpose: confidentiality (encryption), integrity (tamper detection), and authentication (server — and optionally client) over the network.
- Components: **TLS handshake** negotiates the protocol version, cipher suite, and keys; **certificates** (X.509) bind a public key to an identity via a certificate authority (CA); **certificate transparency** and **OCSP/CRL** keep issuance visible and revocable.
- Defense checklist:
  - Enforce TLS 1.2+ (1.3 preferred); disable SSLv3/TLS 1.0/1.1.
  - Reject weak ciphers (RC4, DES, 3DES, export ciphers); prefer AEAD suites (AES-GCM, ChaCha20-Poly1305).
  - Use valid certificates from trusted public CAs for Internet services (or a managed internal CA with full control for internal TLS); never ignore warnings.
  - Configure **HSTS**, and pin nothing by hand (use CAA + CT + monitoring instead of fragile pinning).
  - Terminate TLS properly (at the edge/LB, with re-encryption inside if needed — do not carry plaintext across untrusted segments).

### Encryption for data at rest

- Purpose: protect data on disk/backups/media so physical or logical theft does not reveal plaintext.
- Layers and examples: full-disk (BitLocker, LUKS), file/folder (EFS), database/column (TDE or app-level), object/cloud storage (SSE/KMS), and backups (always).
- Keys are the crown jewels: use a **KMS/HSM** to store master keys, rotate them on schedule, and separate key-management privilege from data access. Losing keys = losing data (backups encrypted with an unrecoverable key are worthless).
- Sizing the need: hash for integrity (SHA-256+), HMAC for authenticated integrity, AES-256 for bulk encryption, and RSA/ECDSA/EdDSA for signatures — never invent your own algorithm, never use a mode without authentication (prefer GCM over CBC/ECB), and never hardcode keys in source or configs.

```text
Example: secret handling instead of hardcoding
# bad
export DB_PASSWORD='Sup3rSecret!'

# better: pull from a secrets manager at runtime
#   - vault write secret/db @creds.json   (HashiCorp Vault)
#   - aws secretsmanager get-secret-value --secret-id prod/db
#   - k8s ExternalSecrets / SOPS-encrypted files
# and rotate with automation, not by hand
```

## Logging and Monitoring Architecture (SIEM Sources)

You cannot respond to what you cannot see. Logging architecture answers: *what events exist, where do they go, who can see them, and how are they protected from tampering?*

### What to collect (source coverage)

- **Endpoint**: OS security logs (Windows Security/Sysmon, Linux auditd), EDR telemetry, authentication events.
- **Network**: firewall/IPS logs, DNS logs (hugely valuable), proxy logs, NetFlow/session data, DHCP.
- **Identity**: AD/Azure AD sign-in logs, MFA events, account changes (creation, privilege change, lockout).
- **Application & data**: web/app server logs, database audit logs, cloud API audit trails (CloudTrail, Azure Activity).
- **Orchestration**: changes to firewalls, group policy, config management, and CI/CD pipelines (a favorite attacker target).

### Pipeline and controls

```text
Sources -> collectors/agents -> (parse/normalize) -> SIEM -> alerting
                                  ^                      |
                                  +--- enrichment (threat intel, asset db)
Retention tiers: hot (fast queries) -> warm -> cold/archive (cheap, immutable)
```

Critical requirements:

- **Time sync** (NTP) everywhere — correlation is impossible with skewed clocks.
- **Central, tamper-resistant storage**: forward logs off the host immediately; write-once/immutable storage for high-value logs (defenders get owned when attackers delete their evidence).
- **Alerting with context**: raw events are noise; detection rules with enrichment (asset value, user risk) produce alerts analysts can triage.
- **Retention that matches need**: incident response (months), compliance (often 12 months+, check your regimes), and threat hunting (longer, cheaper archive).
- **Test your pipeline**: send known-bad events and confirm they reach the SIEM and trigger the rule — a monitoring architecture that silently fails is worse than none.

```text
Example detection rule idea (Sigma-style pseudocode):
title: Account created then added to Domain Admins
detection:
  selection:
    EventID: 4720 (account created)
  filter:
    LogonType: ...
  condition: account added to privileged group < 10 min after creation
level: high
```

## Identity Foundations

Identity is the new perimeter: nearly every modern breach ends with abused credentials. Foundations:

- **Directory** (Active Directory / Entra ID / LDAP) is the source of truth for who is who; protect it like the crown jewels (it is, effectively, the keys to everything).
- **Lifecycle discipline**: join/provision on hire, rightsize on role change, disable/delete on departure — orphaned accounts are a top finding in audits and breaches.
- **Authentication**: enforce MFA everywhere, especially for privileged and remote access; prefer phishing-resistant factors (FIDO2/WebAuthn, passkeys) where possible; never accept SMS-only for admins.
- **Authorization**: group-based access with least privilege; separate admin accounts (standard user for email/web, privileged account only for admin tasks); standing privileges are risk — prefer time-bound elevation (PAM / just-in-time).
- **Service accounts**: least privilege, long unpredictable passwords rotated on schedule (or workload identity / managed identities), never shared in docs or configs.
- **Hygiene**: disable legacy auth (NTLM where feasible, basic auth, insecure protocols), monitor for Kerberoasting/AS-REP roasting, and treat `krbtgt`/trust accounts as critical (periodic password changes per Microsoft guidance).

```text
Example: privileged access pattern
User logs in daily as standard user  ->  no local admin, no mail in admin session
Admin task needed                     ->  elevate via PAM/just-in-time
                                        (time-boxed, approved, recorded)
All privileged sign-ins                ->  MFA + sent to SIEM as high-value events
```

## Worked Example: Hardening a Web Server to a Baseline

A concrete pass through the baseline → enforce → verify cycle on a Linux web server. The point of the example is the *decisions*, not the commands.

```text
0. DEFINE THE TARGET
   Asset        : ACME-WEB-01, T1, internet-facing, web shop front end
   Baseline     : CIS-based profile from the SCAP Security Guide (see
                  ../tools/hardening-and-configuration-scanning.md)
   Level choice : Level 1 (sane, low-disruption) applied everywhere, plus selected
                  Level 2 items where the asset tier justifies them
   Deviations   : must be documented before the first scan, not discovered by the scan

1. ENFORCE BEFORE YOU SCAN
   - Rebuild from the current hardened image rather than hardening in place.
   - Configuration in version control (sshd_config, host firewall, service list,
     auditd rules), applied by the configuration management tool.
   - Result: the host arrives approximately compliant; the scan then measures the
     exceptions rather than producing a 400-item backlog.

2. VERIFY
   Run the benchmark scan against the profile, save the HTML report for the asset
   owner and the machine-readable results for the evidence index:
     sudo oscap xccdf eval --profile <profile-id> \
       --report /var/tmp/report.html --results /var/tmp/results.xml <data-stream>

3. TRIAGE THE FAILURES
   Three classes, and they get treated differently:
     FIX      Something the image or the config should already have set.
              Fix the image/config, not the host, or it will drift back.
     DEVIATE  A rule that cannot apply (an unused subsystem, a vendor requirement).
              Tailor it out with a documented reason and an owner.
     ACCEPT   A rule whose remediation would break the application. This is a risk
              acceptance with an expiry date, not a silent exception.

4. RE-SCAN AND RECORD
   Re-run the scan; the finding count must fall and the remaining items must all be
   in class DEVIATE or ACCEPT with a written justification.
```

Typical first-pass findings on an internet-facing Linux host, and the engineering judgement behind each:

| Rule area | Typical finding | Fix or deviate? |
|---|---|---|
| Remote administration | Root login permitted over SSH | **Fix** — `PermitRootLogin no`, key-only authentication, source restriction |
| Account policy | Password authentication enabled for accounts that should use keys | **Fix** — disable password auth for administrative access |
| Service exposure | Legacy or unused services listening | **Fix** — remove the package, or stop and disable the unit |
| Host firewall | Filtering absent or default-allow | **Fix** — default deny with explicit allows, applied from config |
| Auditing | No audit rules loaded, so no record of privileged activity | **Fix** — keyed rules shipped from configuration management (see [../tools/system-auditing-and-log-integrity](../tools/system-auditing-and-log-integrity.md)) |
| Time sync | Clock not synchronised | **Fix** — without it, correlation and evidence are unreliable |
| Unused filesystem modules | Rules requiring modules the workload does not use | **Deviate** if genuinely unused; document the reason in the tailoring file |
| Kernel parameters tuned for a database | Rules requiring settings this workload must not have | **Accept** — with the application reason recorded and the risk owner named |

The two rules that make this repeatable: **fixes belong in the image or the config management repository**, never in a hand-edited file on one host; and **every remaining failure is either a deviation or an acceptance with a name and an expiry date**, never an unexplained red line in a report.

## Verifying Segmentation Instead of Assuming It

Segmentation is the control most often declared and least often tested. Verify it from the position of an attacker, using the assets you already own.

```text
Test design (run in a lab that mirrors production rules, or with approval during a window):

  FROM                          TO                                  EXPECTED
  workstation segment           domain controller, admin ports       BLOCKED
  workstation segment           database segment, database port      BLOCKED
  workstation segment           internet, DNS and web               ALLOWED (per policy)
  DMZ web server                internal application tier, app port  ALLOWED (specific flow only)
  DMZ web server                database segment, directly           BLOCKED
  DMZ web server                internal network, arbitrary ports    BLOCKED
  management segment            every segment, admin ports           ALLOWED (documented admin plane)
  any segment                   management segment, from below       BLOCKED

  Record for each row: source, destination, port, result, date, rule that governs it.
  An "expected BLOCKED, observed ALLOWED" row is a finding with an owner -- not a
  curiosity to be noted in passing.
```

Two practical cautions: test with the project's own tooling and on hosts you own, and remember that a control verified only by reading the firewall rule set is verified by hypothesis. Rules drift, exceptions accumulate, and a rule that was correct two years ago may permit exactly the path you fear.

## Retention, Volume, and Cost Decisions

Logging architecture is as much an economic decision as a technical one, and administrators are usually the ones who have to defend the bill.

| Data class | Typical need | Retention shape | Cost lever |
|---|---|---|---|
| High-value security events (authentication, privilege change, process creation) | Detection, incident reconstruction | Long, searchable hot/warm; immutable copy | Volume reduction by field selection, not by dropping event classes |
| Network flow records | Scope, lateral movement, exfiltration shape | Medium; aggregated after a period | Flow sampling, aggregation, tiering |
| Full packet capture | Deep analysis, rare | Short window; keep on evidence only | Capture scope and triggers, not always-on everywhere |
| Application and database audit logs | Fraud investigation, compliance | Per regulation; often the longest requirement | Field-level filtering with the legal requirement in writing |
| Cloud control-plane audit trails | Configuration change history, forensics | Long; usually cheap to store, expensive to search | Storage class tiering |

Decisions worth writing down once, so they do not get re-litigated monthly:

- **What we deliberately do not collect**, and why. A documented blind spot is a managed risk; an undocumented one is a future surprise.
- **Where the immutable copy lives** and what protects it from a compromised administrator (see [08](08-continuity-and-recovery.md)).
- **What triggers a capture escalation** — which alert or incident type turns on full packet capture for a host or segment.
- **Who owns the log bill**, and which growth is expected versus anomalous.

## Reviewing a Design: Ten Questions

Use these when someone proposes a new system, a new integration, or a significant change. They are cheap to ask and they surface most of what a review board would find:

```text
1.  What does this design trust, and what happens when that trust is broken?
2.  What is the blast radius if this component is fully compromised?
3.  Where do credentials, keys, and tokens live, and who can read them?
4.  What fails open, and is that acceptable for each failure mode?
5.  What is exposed to the internet, and what is the justification?
6.  What is logged, where do the logs go, and who will read them?
7.  How is it patched, and how fast can a critical fix reach it?
8.  How is it backed up, and how have the restores been tested?
9.  How will we know it is misconfigured or drifting from its baseline?
10. How is it decommissioned, and what happens to its data at that point?
```

Question 10 is the one designs usually omit, and it is where a surprising amount of long-term risk lives: services nobody owns, data that outlives its purpose, and credentials that were never revoked.

## Common Mistakes & Tips

- **Flat networks** — "we have a firewall, so we are segmented." Segmentation is judged by what a compromised workstation can reach; test it with real east-west rules and breach simulations.
- **Hardening once, drifting forever** — without enforcement and verification, hosts rot back to insecure defaults within weeks. Configuration-as-code is not optional at scale.
- **Weak crypto defaults** — old TLS versions, unauthenticated cipher modes, self-signed certs with warnings ignored, keys in repos. Enforce TLS 1.2+/1.3 and scan for leaked secrets.
- **Logs that never alert** — collecting petabytes but detecting nothing means your rules, enrichment, or testing are broken. Test detection with actual adversary emulation.
- **Local admin everywhere** — a single phished helpdesk ticket cascades. Remove local admin by default and manage exceptions.
- **Skipping time sync and log integrity** — skewed or deletable logs destroy your only forensic advantage.
- **Tip**: segment and harden with the "blast radius" question in mind: if this one host is compromised, what is the maximum damage? Design so the answer shrinks every quarter.
- **Tip**: document every deviation from baseline with an owner and an expiry date — undated exceptions become permanent holes.
- **Hardening a host instead of an image.** A hand-fixed host drifts back at the next rebuild; the image is the unit of enforcement. Fix the source, then the host.
- **Treating a scan's red lines as a to-do list for the host.** Repeated failures usually mean the image, the configuration management, or the baseline choice is wrong — not that the host is stubborn.
- **Declaring segmentation because rules exist.** Verify from the attacker's position on both sides of the boundary, and record the result with a date and the governing rule.
- **No documented "what we do not collect".** Undocumented blind spots get discovered during an incident, at the worst possible moment. Write them down while the environment is calm.
- **Ignoring decommissioning in design reviews.** Unretired services, data, and credentials are how exposure grows while the estate appears to shrink.
- **Tip**: keep the configuration baseline in version control and treat a baseline change as a reviewed change; the diff history is evidence and it explains the estate's state to the next engineer.

## Checklist / Self-Test

- [ ] I can name at least six secure design principles and give a concrete control for each.
- [ ] I can draw a layered zone model (DMZ, internal, backend, admin plane) and justify each flow rule.
- [ ] I can explain microsegmentation and when it is preferable to classic network segments.
- [ ] I can list the main CIS hardening categories and the baseline → enforce → verify cycle.
- [ ] I can specify a minimum TLS configuration (versions, ciphers) and explain at-rest encryption layers and key management.
- [ ] I can design a logging pipeline: sources, normalization, SIEM, retention, tamper protection.
- [ ] I can describe identity foundations: lifecycle, MFA, least-privilege administration, service accounts.
- [ ] I can explain why time sync and detection testing are non-negotiable in a monitoring architecture.
- [ ] I can run the hardening cycle on one host: choose a baseline level, enforce from configuration, verify with a benchmark scan, and classify every remaining failure as fix, deviate, or accept.
- [ ] I can explain why a fix belongs in the image or configuration repository rather than on the host.
- [ ] I can design a segmentation test matrix with expected results and describe what a "blocked, but allowed in practice" result means.
- [ ] I can make and document retention decisions for five log classes, including one deliberate blind spot.
- [ ] I can ask the ten design-review questions of a proposed system and name the one designs usually omit.

## Further Resources

- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- NIST SP 800-123 (server security guide) and SP 800-125 (hypervisor): https://csrc.nist.gov/publications
- NIST Cryptographic Standards (FIPS 140, SP 800-52 TLS guidance): https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines
- OWASP — secure design principles and cheat sheets: https://owasp.org/www-project-cheat-sheets/
- MITRE ATT&CK (for detection engineering and logging priorities): https://attack.mitre.org
- Microsoft — baseline security policies and Active Directory security guidance: https://learn.microsoft.com/en-us/security/
- ENISA — network and information security guidance: https://www.enisa.europa.eu
