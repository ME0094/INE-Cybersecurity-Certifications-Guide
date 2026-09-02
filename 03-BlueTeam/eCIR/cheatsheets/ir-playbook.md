# IR Playbook Cheatsheet

> eCIR · Cheatsheets — English quick reference: decision trees, quick actions, evidence commands, and comms

One page you can actually use mid-incident. Print it, memorize the decision trees, and
let the case file hold the details. The goal is speed without destroying evidence.

## 0. Universal Triage Flow (Every Incident)

```text
New alert / report
   │
   ▼
1. VERIFY  — is this real? (correlate ≥2 sources: log + user + artifact)
   │
   ▼
2. CLASSIFY — type (malware/phishing/account/exfil/other), severity, affected assets
   │
   ▼
3. PRESERVE — volatile data first (memory, processes), then disk/logs; hash + log
   │
   ▼
4. CONTAIN  — stop the spread (isolate host, disable account, block IP/domain)
   │
   ▼
5. ERADICATE — remove root cause + persistence on a COPY-verified basis
   │
   ▼
6. RECOVER  — restore from trusted media, verify clean, re-enable monitoring
   │
   ▼
7. LEARN    — case file closed, lessons learned, playbook updated
```

**Golden rules:** never skip 3 before 4–6 · never analyze the original · never
communicate externally before the comms lead · log every decision with its why.

## 1. Decision Trees by Incident Type

### Malware / Ransomware-Like

```text
Encryption-like activity or malware detected?
├─ Single host, no lateral movement → isolate host, preserve memory+disk,
│    scan share writes, contain, eradicate, restore from offline backup
├─ Multiple hosts / shares hit → declare major incident; disable ALL affected
│    accounts; take shares read-only or offline; preserve evidence per host
└─ Unknown scope → do NOT mass-delete; scope first (timeline + share audit),
     then contain; involve leadership and, if needed, external IR/LE
```

### Phishing

```text
Reported/clicked phishing?
├─ Not clicked → collect email+headers, block sender/domain/URL at gateway,
│    sweep mailboxes for same campaign, alert users, done
├─ Clicked, no credentials entered → block indicators, reset nothing yet,
│    monitor account for 24–48h, educate user
└─ Credentials entered → reset password, revoke sessions/tokens, enforce MFA,
     scan for rule creation (mail forwarding), scope account access
```

### Account Compromise

```text
Suspicious sign-in?
├─ Impossible travel + legacy auth → verify with device/ASN, revoke sessions,
│    reset creds, disable legacy auth, require MFA re-enroll
├─ Mailbox rules/forwarding created → preserve rule export, remove rule,
│    audit forwarded mail scope, check other mailboxes
└─ Privilege escalation suspected → reset affected accounts, audit group
     changes since first anomaly, check for second admin account
```

### Data Exfiltration

```text
Large outbound transfer or odd DLP hit?
├─ Confirm: firewall/proxy logs, user activity, endpoint file ops
├─ Preserve: netflow/proxy logs, endpoint evidence, cloud audit logs
├─ Contain: block destination IP/domain, restrict account/cloud app,
│    disable risky sharing links, snapshot the affected store
└─ Scope: exactly what data, how much, to where — then notify per policy
     (regulatory thresholds, customer notification, LE if required)
```

## 2. Hold / Contain / Eradicate Quick Actions

| Phase | Windows | Linux / Other |
| ----- | ------- | ------------- |
| **Hold (preserve)** | Memory dump (winpmem/FTK Imager); KAPE collection; `wevtutil epl` logs | `dd`/`ewfacquire` image; collect `/var/log`, `history`, process list |
| **Contain** | Quarantine NIC via management plane; disable account: `Disable-ADAccount -Identity k.roy`; kill process tree | `iptables -A OUTPUT -d <c2> -j DROP`; stop service: `systemctl stop apache2`; `usermod -L user` |
| **Eradicate** | Remove scheduled task: `schtasks /Delete /TN "name" /F`; delete Run key: `reg delete "HKCU\...\Run" /v name /f`; remove file after hash | Remove web shell + patch vector; `crontab -r`/edit; remove ssh authorized_keys additions; `apt upgrade`/reimage from trusted media |
| **Recover** | Restore from offline backup; verify no re-infection for 48h | Redeploy from clean source; integrity-compare against backup |

**Containment order that preserves evidence:** capture volatile state → isolate →
disable credentials → block network indicators → THEN remove things.

## 3. Evidence Commands (Run and Log Outputs)

### Windows (live triage — do before isolation if possible)

```powershell
# Processes, parents, command lines
Get-Process | Select-Object Id, ProcessName, Path, StartTime
Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine

# Network connections and owning processes
Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

# Scheduled tasks and services worth checking
schtasks /query /fo LIST /v
Get-Service | Where-Object {$_.Status -eq 'Running'}

# Persistence hunt spots
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

# Hash a suspicious file BEFORE touching it
Get-FileHash -Algorithm SHA256 C:\Users\Public\n.exe | Format-List

# Export event logs (as evidence, not just for reading)
wevtutil epl Security C:\case\sec.evtx
```

### Linux

```bash
ps auxf                                   # process tree
ss -tunap                                 # sockets and owning process
lsof -p <pid>                             # files/network of a process
ls -la /var/www/html/uploads/             # web shell hunting
sha256sum /var/www/html/uploads/x.php     # hash BEFORE removal
last -a | head -50                        # logins
journalctl --since "2025-06-01" | less    # recent journal
ss -lntp; crontab -l; ls -la /etc/cron*   # persistence checks
```

### Post-collection (on the analyst box)

```bash
sha256sum -c evidence.sha256              # verify collection integrity
log2timeline.py --storage-file case.plaso image.E01   # build timeline
vol -f mem.raw windows.malfind            # memory scan of preserved dump
```

## 4. Comms Templates (Condensed)

### Internal one-liner (for the bridge/Slack)

```text
[IR-2025-014 · HIGH · CONTAINMENT] Suspected ransomware WS-042 — isolated,
user disabled, evidence captured. AD + backup teams: see tasks. Next update 14:00 UTC.
```

### Executive two-paragraph

```text
What happened: <incident type> on <asset(s)> at <time>, detected <time>.
Impact: <confirmed scope, stated plainly — "one workstation, no confirmed data loss">.
Response: <preserved evidence, contained, restoring from backup; next update at <time>>.
```

### External one-liner (vendor/CERT/LE)

```text
[IR-2025-014 · TLP:AMBER] Requesting <action> regarding <indicator/asset>.
Contact: <name/role/phone/email>.
```

## Common Mistakes & Tips

- **Containing before preserving.** Isolating the host is correct — after memory and
  process state are captured, or you lose the volatile evidence forever.
- **Deleting instead of eradicating thoughtfully.** Hash, log, and where possible keep a
  copy of anything you remove; eradication that destroys evidence is a failed drill.
- **Single-source conclusions.** One alert is a lead, not a finding; confirm with a
  second artifact class (log + file + user).
- **Weak account containment.** Disabling the account but not revoking active sessions,
  tokens, and mailbox rules leaves the door open.
- **No timezone on timestamps.** Every log line in your case file carries UTC or an
  explicit offset.
- **Improvising comms.** Use the templates; the comms lead sends external messages —
  improvisation leaks scope and confidence.

## Checklist / Self-test

- [ ] I can recite the universal triage flow (verify → classify → preserve → contain → eradicate → recover → learn) from memory.
- [ ] I can state the first three actions for each of: malware, phishing, account compromise, exfiltration.
- [ ] I know which evidence commands to run before isolating a Windows host.
- [ ] I know where to hunt persistence (Run keys, scheduled tasks, services, cron) on both OSes.
- [ ] I can produce an internal one-liner, an executive summary, and an external request from the same facts.
- [ ] I can explain why preserve precedes contain, with an example.
- [ ] Every command I run during a drill produces output that lands in the case file.

## Further Resources

- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide* — https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- MITRE ATT&CK (technique IDs for triage and scope) — https://attack.mitre.org/
- Windows Sysinternals documentation (tools behind many commands above) — https://learn.microsoft.com/en-us/sysinternals/
- plaso / log2timeline documentation — https://plaso.readthedocs.io/
- Volatility 3 (GitHub) — https://github.com/volatilityfoundation/volatility3
- Velociraptor documentation — https://docs.velociraptor.app/
