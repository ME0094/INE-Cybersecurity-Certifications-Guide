# Enumeration — eJPT Methodology Phase 2

> eJPT study guide · Offensive methodology — INE-Cybersecurity-Certifications-Guide

Enumeration turns "this host is alive" into "this host runs Apache 2.4.49 on
TCP 80, has an anonymous FTP share, and answers SMB on 445." It is the phase
where most real vulnerabilities are found, because services and versions
drive the exploitation step. The rule of thumb: **you cannot exploit what you
have not enumerated.**

## What enumeration is

For every live host from reconnaissance you now want:

- Every open TCP/UDP port and the **service** behind it.
- The service **version/banner** when readable.
- Default or anonymous access (SMB shares, FTP login, SNMP community).
- Web application details (server headers, directories, login pages).

Run **full port scans first**, then drill into interesting services. A
default top-1000 `nmap` scan misses services on high ports — common in labs
and in real life.

## Service and version enumeration with nmap

```bash
# 1) Full TCP port scan, no DNS, faster timing
nmap -p- -T4 -n 10.10.10.5 -oN full_tcp.txt

# 2) Version + default script scan on the ports you found
nmap -sV -sC -p 22,80,445 10.10.10.5 -oN service_scan.txt

# -A == -sV -sC -O (OS detection); heavier, use it selectively
nmap -A -p 22,80 10.10.10.5
```

| Flag | Effect |
|---|---|
| `-sV` | Probe open ports to detect service **versions** |
| `-sC` | Run the default set of safe NSE scripts |
| `-p-` | All 65535 TCP ports (default is only the top 1000) |
| `-p 22,80,443` | Scan specific ports |
| `-A` | `-sV` + `-sC` + OS detection + traceroute |
| `--version-intensity` | How hard `-sV` tries (0–9, default 7) |

```text
# Expected output excerpt (nmap -sV -sC)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open  http     Apache httpd 2.4.49 ((Ubuntu))
445/tcp  open  netbios-ssn Samba smbd 4.6.2 (workgroup: WORKGROUP)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Those version numbers are the bridge to exploitation: Apache 2.4.49
immediately suggests the path-traversal/RCE CVE-2021-41773, while OpenSSH
8.2p1 is rarely directly exploitable — enumeration also tells you where *not*
to waste time.

## Banner grabbing

Banners are the text a service sends before you authenticate. `-sV` reads
them for you, but manual grabs confirm results and work where nmap scripts
are blocked.

```bash
# netcat: read the banner a TCP service sends on connect
nc -nv 10.10.10.5 22

# Some services need a protocol greeting first
printf "GET / HTTP/1.0\r\n\r\n" | nc -nv 10.10.10.5 80

# HTTPS needs TLS; inspect the server certificate
openssl s_client -connect 10.10.10.5:443 </dev/null 2>/dev/null | head -5

# HTTP headers reveal server + framework info
curl -I http://10.10.10.5
```

```text
# Expected output (nc -nv 10.10.10.5 22)
(UNKNOWN) [10.10.10.5] 22 (ssh) open
SSH-2.0-OpenSSH_8.2p1 Ubuntu 4ubuntu0.5
```

> **Banner ≠ truth.** Services can lie (honeypots) or strip banners.
> Cross-check important version findings with a second source.

## HTTP(S) enumeration

Web services are the most common attack surface in eJPT-style labs. Cover the
low-hanging fruit first: robots, headers, hidden directories.

```bash
# 1) robots.txt — often reveals paths admins wanted to hide
curl -s http://10.10.10.5/robots.txt

# 2) Headers — server/framework version, security headers present?
curl -I http://10.10.10.5

# 3) Page source — comments often leak versions and paths
curl -s http://10.10.10.5/ | head -50

# 4) Directory/file brute force
gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirb/common.txt \
  -t 50 -x php,txt,bak,old -q

# 5) Virtual hosts when the site serves multiple names
gobuster vhost -u http://10.10.10.5 \
  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

```text
# Expected output excerpt (gobuster dir)
/admin                (Status: 301) [Size: 311] [--> http://10.10.10.5/admin/]
/config.php.bak       (Status: 200) [Size: 412]
/robots.txt           (Status: 200) [Size: 60]
```

## SMB (139/445) basics

SMB file sharing is a favorite target: anonymous or guest access is often
misconfigured, and share names leak usernames and project data.

```bash
# List shares anonymously (null session)
smbclient -L //10.10.10.5 -N

# Connect to a share and pull files
smbclient //10.10.10.5/public -N
smb> ls            # list files
smb> get note.txt  # download a file

# Nmap NSE scripts summarize the SMB configuration
nmap -p 445 --script smb-enum-shares,smb-enum-users 10.10.10.5

# enum4linux collects users, shares, and policies over SMB/RPC
enum4linux 10.10.10.5
```

```text
# Expected output excerpt (smbclient -L -N)
        Sharename       Type      Comment
        ---------       ----      -------
        public          Disk      Public files
        IPC$            IPC       IPC Service
```

Anonymous `ADMIN$` is normal Windows admin sharing; an open `public` share
with documents is what you record and investigate.

## FTP (21) basics

```bash
# Anonymous login check — classic misconfiguration
ftp 10.10.10.5          # Name: anonymous   Password: anything

# Non-interactive checks
nmap -p 21 --script ftp-anon 10.10.10.5
curl -s ftp://anonymous:anonymous@10.10.10.5/
```

If anonymous access works, download everything readable — config files and
backups in FTP shares are common credential/flag locations.

## SSH (22) basics

SSH itself is rarely the vulnerability; your job is to record the exact
version and look for weak/default credentials (only when in scope) and legacy
versions with known issues.

```bash
nc -nv 10.10.10.5 22       # banner: exact OpenSSH version
ssh -o StrictHostKeyChecking=no user@10.10.10.5   # try enumerated usernames
```

## SNMP (161/UDP) basics

SNMP with the default community string `public` leaks system info —
hostname, interfaces, running processes, sometimes credentials.

```bash
# Check the system MIB with community "public"
snmpwalk -v2c -c public 10.10.10.5 system

# Brute-force common community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 10.10.10.5

# Dump the running-processes tree (software + usernames)
snmpwalk -v2c -c public 10.10.10.5 .1.3.6.1.2.1.25.4.2.1.2
```

## What to record in notes

Enumeration output is only as valuable as the notes that survive it. Use one
block per host:

```text
Host: 10.10.10.5 (dc01.lab.local)
Ports:
  22/tcp  OpenSSH 8.2p1 Ubuntu        # not directly exploitable
  80/tcp  Apache 2.4.49               # CVE-2021-41773 candidate
  445/tcp Samba 4.6.2, share: public  # anonymous read OK
Web:
  robots.txt -> /admin/, /backup/
  /config.php.bak downloadable
Users found: admin, backup_svc (SMB enum)
Next steps: test Apache 2.4.49 exploit, dig into /backup/, brute force login
```

## Common Mistakes & Tips

- **Scanning only the top 1000 ports.** High ports (8080, 8443, 2222, 3000)
  hide lab services. Always do `-p-` once per host.
- **Ignoring the version column.** "Apache httpd" is useless — "Apache
  2.4.49" is an exploit lead.
- **Running `-sC` without `-sV` (or vice versa).** Use them together.
- **Forgetting UDP.** SNMP (161) and TFTP (69) live on UDP. Spot-check with
  `nmap -sU --top-ports 20`.
- **Blind directory brute force.** Check robots.txt and the page source first
  — faster and quieter.
- **Not testing anonymous access.** `smbclient -L -N` and anonymous `ftp`
  take seconds and often pay off immediately.
- **Messy notes.** If a version or share name is not written down, it did not
  happen. Keep the per-host block updated.
- **Skipping verification.** One banner can be wrong; confirm suspicious
  versions with a second tool.

## Checklist / Self-Test

- [ ] I ran a full `-p-` TCP scan and a `-sV -sC` scan on every live host.
- [ ] I can explain what `-sV`, `-sC`, `-p-`, and `-A` each do.
- [ ] I can grab banners with `nc`, `curl -I`, and `openssl s_client`.
- [ ] I can enumerate a web server: robots.txt, headers, page source, and
      `gobuster dir` with extensions.
- [ ] I can list SMB shares anonymously and enumerate users (`smbclient`,
      `enum4linux`).
- [ ] I can check FTP anonymous login and SNMP community `public`.
- [ ] I keep one up-to-date notes block per host with ports, versions, and
      next steps.
- [ ] I record exact service versions — not just names — for every open port.

## Further Resources

- Nmap service/version detection: https://nmap.org/book/man-version-detection.html
- Nmap NSE script index (smb-, ftp-, http- scripts): https://nmap.org/nsedoc/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- SecLists wordlists (GitHub): https://github.com/danielmiessler/SecLists
- `smbclient` and `snmpwalk` man pages on your distribution
