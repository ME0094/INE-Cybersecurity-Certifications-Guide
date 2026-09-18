# Security Engineering

> eEDA · Methodology — Enterprise Defense Administrator

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

## Common Mistakes & Tips

- **Flat networks** — "we have a firewall, so we are segmented." Segmentation is judged by what a compromised workstation can reach; test it with real east-west rules and breach simulations.
- **Hardening once, drifting forever** — without enforcement and verification, hosts rot back to insecure defaults within weeks. Configuration-as-code is not optional at scale.
- **Weak crypto defaults** — old TLS versions, unauthenticated cipher modes, self-signed certs with warnings ignored, keys in repos. Enforce TLS 1.2+/1.3 and scan for leaked secrets.
- **Logs that never alert** — collecting petabytes but detecting nothing means your rules, enrichment, or testing are broken. Test detection with actual adversary emulation.
- **Local admin everywhere** — a single phished helpdesk ticket cascades. Remove local admin by default and manage exceptions.
- **Skipping time sync and log integrity** — skewed or deletable logs destroy your only forensic advantage.
- **Tip**: segment and harden with the "blast radius" question in mind: if this one host is compromised, what is the maximum damage? Design so the answer shrinks every quarter.
- **Tip**: document every deviation from baseline with an owner and an expiry date — undated exceptions become permanent holes.

## Checklist / Self-Test

- [ ] I can name at least six secure design principles and give a concrete control for each.
- [ ] I can draw a layered zone model (DMZ, internal, backend, admin plane) and justify each flow rule.
- [ ] I can explain microsegmentation and when it is preferable to classic network segments.
- [ ] I can list the main CIS hardening categories and the baseline → enforce → verify cycle.
- [ ] I can specify a minimum TLS configuration (versions, ciphers) and explain at-rest encryption layers and key management.
- [ ] I can design a logging pipeline: sources, normalization, SIEM, retention, tamper protection.
- [ ] I can describe identity foundations: lifecycle, MFA, least-privilege administration, service accounts.
- [ ] I can explain why time sync and detection testing are non-negotiable in a monitoring architecture.

## Further Resources

- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- NIST SP 800-123 (server security guide) and SP 800-125 (hypervisor): https://csrc.nist.gov/publications
- NIST Cryptographic Standards (FIPS 140, SP 800-52 TLS guidance): https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines
- OWASP — secure design principles and cheat sheets: https://owasp.org/www-project-cheat-sheets/
- MITRE ATT&CK (for detection engineering and logging priorities): https://attack.mitre.org
- Microsoft — baseline security policies and Active Directory security guidance: https://learn.microsoft.com/en-us/security/
- ENISA — network and information security guidance: https://www.enisa.europa.eu
