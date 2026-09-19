# eCIR Methodology — Phase 4: Eradication

> eCIR · Incident Response Methodology — INE-Cybersecurity-Certifications-Guide

Eradication removes the adversary from the environment completely: the root
cause of the compromise, every artifact they planted, and every foothold they
created. Containment stopped the bleeding; eradication closes the wound.
Rushing eradication — or skipping verification — is how organizations declare
victory and get re-infected by the same actor days later. NIST SP 800-61
frames eradication as *identifying and eliminating the root cause* and warns
that this often means rebuilding affected systems rather than trusting a
cleaned one.
## Eradication Goals
Eradication is complete only when all of the following are true:
- The root cause (the vulnerability, misconfiguration, or stolen credential
  that let the adversary in) is removed or fixed.
- All attacker artifacts are gone from every affected host and account.
- Persistence mechanisms are verified gone — not just deleted, but confirmed
  not to regenerate.
- Compromised credentials and secrets are rotated, including any the attacker
  could have copied.
- The environment is re-checked for the adversary's return before normal
  operations resume.

```text
Eradication flow (overview):
1. Confirm containment is holding (Phase 3 outputs).
2. Finish evidence collection — once you clean, the forensic picture is gone.
3. Identify the root cause and every affected system/account (scope).
4. Decide per system: reimage or clean in place.
5. Remove artifacts and close the root cause (patch, reconfigure, rotate).
6. Verify: hunt for persistence and IOCs again; confirm clean.
7. Reconnect only after verification, under heightened monitoring.
```
## Reimage vs. Clean In Place
The single most important eradication decision is whether to rebuild a host
or try to clean it. When in doubt, **reimage**. Modern malware — especially
ransomware and rootkits — can hide in firmware, bootkits, or deeply
obfuscated persistence that survives "cleaning."

| Factor | Favor reimage | Favor clean in place |
| --- | --- | --- |
| Host type | Servers, domain controllers, hosts with privileged data | Commodity workstations, low-value endpoints |
| Malware type | Rootkits/bootkits, ransomware, unknown/evasive malware | Known simple malware, fully characterized |
| Confidence | Cannot prove what the attacker did on the host | Full forensic timeline available and clean |
| Cost vs. risk | Rebuild is cheap relative to re-infection risk | Rebuild very expensive (custom apps, config) |
| Policy | Compliance requires known-good builds | Standard build does not apply |

```text
Decision rule of thumb:
- Domain controllers and servers holding sensitive data that were compromised
  -> rebuild from known-good media. No exceptions for rootkits.
- If you cannot enumerate every artifact the attacker placed -> rebuild.
- Clean in place only when a trusted image is impractical AND you can prove
  host integrity (no kernel/firmware activity; complete artifact list from
  full disk forensics).
```

Rebuild procedure for a Windows host:

```powershell
# 1. Preserve evidence first (Phases 2/3): disk image + hashes.
# 2. Wipe and reinstall from a trusted, patched image:
#    - boot from known-good installation media
#    - repartition/reformat the disk (do not trust "quick format")
#    - reinstall OS and applications from trusted sources
#    - apply patches and hardening baseline BEFORE reconnecting to the
#      production network
# 3. Restore only known-clean user data from backups taken before compromise
#    or verified clean after it.
```
## Removing Attacker Artifacts
If a host is cleaned in place (or to remove artifacts such as attacker
accounts even on rebuilding hosts), check every persistence location the
adversary commonly uses — see MITRE ATT&CK persistence techniques (T1547,
T1053, T1543 and related).

```powershell
# Persistence points to inspect on Windows
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

# Scheduled tasks (a favorite persistence and execution mechanism)
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
  Select-Object TaskName, TaskPath, State

# Services pointing at unusual binaries
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -notmatch '^"C:\\Windows' -and
                 $_.PathName -notmatch '^C:\\Program Files' } |
  Select-Object Name, State, StartMode, PathName

# Startup commands and recently created accounts
Get-CimInstance -ClassName Win32_StartupCommand
Get-LocalUser | Select-Object Name, Enabled, LastLogon

# WMI event subscriptions (stealthy persistence)
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
```

```bash
# Persistence points to inspect on Linux
crontab -l; ls -la /etc/cron.* /var/spool/cron 2>/dev/null     # cron jobs
systemctl list-unit-files --state=enabled | head -50           # services
find /etc/systemd/system -type f -newermt "14 days ago" -ls 2>/dev/null
grep -R "curl\|wget\|base64\|/tmp/" ~/.bashrc ~/.profile \
  /etc/profile.d/ 2>/dev/null                                  # shell profiles
ls -la ~/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null
```

Removal rules:
1. Remove artifacts only **after** evidence collection for that host is
   complete.
2. Remove the *mechanism*, not just the visible file: kill processes, delete
   binaries, remove the scheduled task/service/registry entry, then confirm
   it does not come back.
3. Audit for attacker-created accounts, remove them, and disable any account
   whose group membership you cannot explain.
## Verifying Persistence Removal
Deleting is not the same as eradicating. After cleanup, verify actively:

```text
Verification checklist (per host):
1. Re-run the full persistence scan (commands above) — zero findings.
2. Run a full EDR/AV scan with updated signatures plus a second-opinion
   scanner; review results manually, not just "0 alerts".
3. Re-run IOC hunts from the Detection phase: hashes, domains, C2 IPs,
   process names — all clean.
4. Check that no new accounts, scheduled tasks, or services appeared during
   the cleanup window.
5. Compare file system/registry against a known-good baseline (Sysinternals
   Autoruns/Sigcheck or configuration-management baseline).
6. After reconnection, keep the host under heightened monitoring for 48–72
   hours before returning it to normal posture.
```

If any check fails, stop and reassess — either the artifact list was
incomplete or the adversary is still active. Never reconnect a host you
cannot prove is clean.
## Patching and Closing the Root Cause
Eradicating artifacts without fixing the root cause guarantees a repeat
visit. Identify the initial access vector from the Detection/analysis
timeline and close it:

```text
Root cause -> fix mapping (examples):
- Unpatched internet-facing service (VPN, web app) -> apply the vendor
  patch; if unavailable, apply compensating controls (WAF rule, firewall
  ACL, forced MFA) and track until patched.
- Phished credentials -> enforce phishing-resistant MFA, reset exposed
  passwords, review conditional-access policies.
- Overprivileged service account -> remove excess rights, rotate the secret,
  apply least privilege.
- RDP exposed to the internet -> close it at the firewall; require VPN/jump
  host with MFA.
- Malicious email attachment -> strengthen gateway rules, block the file
  types and sender infrastructure, train users.
```

```powershell
# Verify patch status (Windows), then apply missing updates
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
```

```bash
# Debian / Ubuntu — the `apt` family
apt list --upgradable
sudo apt update && sudo apt upgrade -y

# RHEL / Fedora / Rocky / Alma — the `dnf` family
sudo dnf check-update && sudo dnf upgrade -y

# SUSE — `zypper`
sudo zypper list-updates && sudo zypper patch
```

Credential rotation belongs in eradication too: rotate every password, token,
API key, and certificate the adversary could have obtained — including
service accounts and, if a domain compromise is suspected, the `krbtgt`
account (reset twice, per Microsoft's guidance for a compromised domain).
## Recovery Steps
Eradication hands off to recovery when the environment is verified clean.

> **Attribution, because this one is easy to get wrong.** Recovery is treated as a step of its
> own here, but it is **not a separate NIST phase.** In SP 800-61 **Rev. 2**, containment,
> eradication and recovery are a *single* phase — "Containment, Eradication, and Recovery".
> SP 800-61 **Rev. 3** (April 2025, *Incident Response Recommendations and Considerations for
> Cybersecurity Risk Management: A CSF 2.0 Community Profile*) drops the phase model altogether
> and frames response around CSF 2.0 functions. The five phase files in this module are this
> repository's own study organisation (see [`../README.md`](../README.md)), not a NIST taxonomy.

Recovery includes:
1. **Restore from clean backups** — verify integrity and restore into a
   quarantined network first; scan restored data for malware before release.
2. **Reconnect systems in priority order** — critical business systems first,
   under heightened monitoring; do not reconnect everything at once.
3. **Validate business function** — confirm the system works at the
   application level and data integrity is intact.
4. **Remove containment controls deliberately** — lift firewall rules and
   account blocks one by one, only after eradication is confirmed; keep
   monitoring rules in place longer than everything else.
5. **Heightened monitoring period** — extend log retention, enable extra
   detections, and watch for re-infection for a defined window (often 30–90
   days depending on the adversary).

```text
Recovery go/no-go gates:
- All affected hosts verified clean (reimage or confirmed cleanup).
- Root cause patched/closed and verified.
- Credentials and secrets rotated.
- Backups validated by test restore.
- Business owners confirm critical functions.
If any gate fails -> stay in eradication/recovery; do not resume normal ops.
```
## Common Mistakes & Tips
- **Mistake:** Cleaning artifacts before finishing evidence collection.
  **Tip:** Treat the disk image and volatile capture as the exit ticket for
  cleanup; once cleaned, the forensic record is gone.
- **Mistake:** Trusting a cleaned host that ran a rootkit or bootkit.
  **Tip:** Reimage whenever you cannot enumerate every artifact; rebuild cost
  is almost always lower than a second incident.
- **Mistake:** Removing the visible malware but leaving the scheduled task,
  service, or WMI subscription that relaunches it. **Tip:** Remove the
  persistence mechanism and re-scan to prove it does not regenerate.
- **Mistake:** Verifying with the same tool that missed the malware the first
  time. **Tip:** Use a second scanner, updated signatures, and manual IOC
  checks.
- **Mistake:** Patching the vulnerability but not rotating credentials the
  attacker touched. **Tip:** Treat all secrets in scope as compromised and
  rotate them (including service accounts and, if needed, `krbtgt`).
- **Mistake:** Reconnecting hosts before verification and losing the
  heightened-monitoring window. **Tip:** Reconnect in priority order, lift
  containment rules deliberately, and monitor aggressively for weeks.
- **Mistake:** Restoring from backups that are themselves infected.
  **Tip:** Test-restore into quarantine, scan, and verify before production
  release.
## Checklist / Self-Test
- [ ] I can list the conditions that must all be true for eradication to be
      complete.
- [ ] I can apply the reimage-vs-clean decision factors to a scenario (e.g.,
      a domain controller with a rootkit vs. a workstation with known adware).
- [ ] I can enumerate at least six Windows persistence locations and the
      PowerShell commands to inspect them.
- [ ] I can identify Linux persistence locations (cron, systemd, shell
      profiles, SSH authorized keys) and audit them.
- [ ] I can describe a persistence-removal verification checklist and explain
      why deletion alone is insufficient.
- [ ] I can map a root cause (unpatched service, phished credentials, open
      RDP, etc.) to its remediation fix.
- [ ] I can list the recovery go/no-go gates before returning to normal
      operations.
- [ ] I understand when and why `krbtgt` password rotation is required after
      a suspected domain compromise.

> **Verification:** the phase attribution was **checked against the NIST SP 800-61 Rev. 3
> publication page** (`https://csrc.nist.gov/pubs/sp/800/61/r3/final`, HTTP 200 via `curl` on
> 2026-09-19), whose title is *Incident Response Recommendations and Considerations for
> Cybersecurity Risk Management: A CSF 2.0 Community Profile*, and against this repository's own
> eCDFP module for the counterpart wording. The Rev. 2 phase structure was **not** re-read from
> the PDF — the four-phase model is quoted from the secondary literature and from the module's
> own prior text, so treat the Rev. 2 sentence as documentation rather than an executed check.
> The `apt`, `dnf` and `zypper` blocks are **unverified syntax references — not run**.

## Further Resources
- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide* —
  https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- NIST SP 800-61 Rev. 3, *Incident Response Recommendations and Considerations for
  Cybersecurity Risk Management: A CSF 2.0 Community Profile* (April 2025) —
  https://csrc.nist.gov/pubs/sp/800/61/r3/final
- NIST SP 800-83 Rev. 1, *Guide to Malware Incident Prevention and Handling* —
  https://csrc.nist.gov/publications/detail/sp/800-83/rev-1/final
- MITRE ATT&CK — https://attack.mitre.org (Persistence, Defense Evasion, and
  Initial Access tactics for artifact and root-cause enumeration)
- SANS Reading Room (malware removal and eradication papers) —
  https://www.sans.org/reading-room/
