# Pivoting — eJPT Methodology Phase 5

> eJPT study guide · Offensive methodology — INE-Cybersecurity-Certifications-Guide

Pivoting is using a compromised host as a stepping stone to reach networks
you cannot touch directly. In many engagements the first shell is not on the
final target — it is on an edge host that happens to have a second network
interface. This guide explains why pivoting matters and covers SSH local/
remote/dynamic forwarding, using the compromised host as a jump box,
`proxychains`, and Metasploit routing.

## Why pivoting

Your attack machine usually has one path into a lab, but the compromised host
often sees more:

```text
[Kali 10.10.0.50] --reachable--> [web01 10.10.10.5] --reachable--> [db01 10.10.20.10]
        ^                                                                ^
        |                                                                |
    cannot reach db01 directly                         only web01 can reach it
```

web01 is the **pivot host**; 10.10.20.0/24 is the **internal network**. Once
you control web01 you can route traffic through it and scan, connect to, and
exploit services on db01 — even though 10.10.20.10 is unreachable from Kali.

Before pivoting, confirm the pivot candidate on the compromised host:

```bash
ip addr        # more than one interface/subnet?
ip route       # which networks can this host reach?
arp -a         # hosts it has recently talked to on other segments
```

If web01 can reach db01 but Kali cannot, you have a pivot candidate.

## SSH local port forwarding (`-L`)

Local forwarding maps a **local** port to a **remote** destination through
the SSH connection: traffic to your `localhost:PORT` travels over SSH to the
pivot host, which forwards it to the target.

```bash
# On Kali: local 8080 -> via web01 -> db01:80
ssh -L 8080:10.10.20.10:80 user@10.10.10.5

# Now db01's web server is reachable locally:
curl http://127.0.0.1:8080/

# Syntax: ssh -L [bind_ip:]local_port:target_host:target_port pivot_user@pivot_ip
#         ssh -L 127.0.0.1:9001:10.10.20.10:3306 user@10.10.10.5
```

```text
# Expected behavior
mysql -h 127.0.0.1 -P 9001 -u root -p   # connects to db01's MySQL via tunnel
```

Use one `-L` per service. The tunnel dies when the SSH session ends — add
`-N` (no shell, tunnel only) and `-f` (background):

```bash
ssh -N -f -L 8080:10.10.20.10:80 user@10.10.10.5
```

## SSH remote port forwarding (`-R`)

Remote forwarding reverses the direction: the pivot host forwards a port on
**itself** back to a service on **your** machine — useful when the target
must reach a listener you host.

```bash
# Run FROM the compromised host: web01's 4444 -> Kali's listener on 4444
ssh -R 4444:127.0.0.1:4444 kali-user@10.10.0.50
```

Typical use: the internal target can reach web01 but its callback to Kali's
reverse-shell listener is filtered — the callback arrives via web01 instead.

## SSH dynamic port forwarding (`-D`) — SOCKS proxy

Dynamic forwarding turns your SSH connection into a **SOCKS proxy**: any
SOCKS-aware tool can reach arbitrary hosts *through* the pivot.

```bash
# On Kali: open a SOCKS proxy on 127.0.0.1:1080 through web01
ssh -N -D 1080 user@10.10.10.5

# Use it with SOCKS-aware tools:
curl --socks5 127.0.0.1:1080 http://10.10.20.10/
nmap -sT -Pn --proxies http://127.0.0.1:1080 10.10.20.10   # nmap's native SOCKS
proxychains nmap -sT -Pn 10.10.20.10                      # or proxychains below
```

## Using the compromised host as a jump box

When the pivot runs SSH with valid credentials (it usually does — your
foothold often *is* an SSH session), OpenSSH's `ProxyJump` makes every
`ssh`/`scp` hop through it transparently:

```bash
# ssh directly to a host behind the pivot (no manual -L needed)
ssh -J user@10.10.10.5 user2@10.10.20.10

# Same for file transfer
scp -J user@10.10.10.5 linpeas.sh user2@10.10.20.10:/tmp/

# Define the jump host in ~/.ssh/config to avoid retyping it
# Host *
#   ProxyJump user@10.10.10.5
```

## proxychains

`proxychains` forces non-SOCKS-aware tools (nmap, smbclient, ftp) through a
SOCKS proxy by intercepting their network calls.

```bash
# 1) Configure the proxy (usually /etc/proxychains4.conf):
#    [ProxyList]
#    socks4 127.0.0.1 1080        # match your ssh -D port

# 2) Prepend proxychains to any command:
proxychains nmap -sT -Pn -p 22,80,445 10.10.20.10
proxychains smbclient -L //10.10.20.10 -N
proxychains curl http://10.10.20.10/
```

```text
# Expected output (proxychains header line)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.20.10:445  ...  OK
```

**Hard limits of proxychains:**

- Only **TCP** works — no ICMP (`ping`), and UDP needs extra config.
- Use `-sT` (connect scan) with nmap; `-sS` SYN scans cannot go through a
  SOCKS proxy (no half-open packets over a proxy).
- Everything is slow: keep scans narrow (`-Pn`, few ports, `-T2`/`-T3`).
- Only the tool's TCP connections go through the proxy — DNS may leak unless
  the tool resolves via the proxy or you use IPs.

## Metasploit routing and pivoting

Meterpreter sessions already have a channel through the pivot, so Metasploit
routes traffic over an existing **session** instead of SSH.

### Routing to a subnet behind the session

```text
msf6 > sessions -l
  #  1  meterpreter x64/linux  www-data @ web01 (10.10.10.5)  ...
msf6 > route add 10.10.20.0 255.255.255.0 1     # subnet -> session 1
msf6 > route print                              # verify the route

# Now modules can target the internal subnet directly:
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(...) > set RHOSTS 10.10.20.10
msf6 auxiliary(...) > set PORTS 22,80,445
msf6 auxiliary(...) > run
```

Autoroute does the same without typing the subnet:

```text
msf6 meterpreter > run autoroute -s 10.10.20.0/24   # auto-add from host routes
msf6 meterpreter > run autoroute -p                  # print current routes
```

### Port forwarding from a Meterpreter session

For single services, forward ports through the session (mirrors `ssh -L`):

```text
msf6 meterpreter > portfwd add -L 127.0.0.1 -l 8080 -p 80 -r 10.10.20.10
msf6 meterpreter > portfwd list
# then locally: curl http://127.0.0.1:8080/
```

To use **non-Metasploit tools** through a Meterpreter pivot, add a SOCKS
proxy module and point proxychains at it:

```text
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(...) > set SRVHOST 127.0.0.1
msf6 auxiliary(...) > set SRVPORT 1080
msf6 auxiliary(...) > run -j
# plus the route above -> proxychains nmap -sT -Pn 10.10.20.10 now works
```

## Choosing the right method

| Situation | Best tool |
|---|---|
| SSH creds on pivot, one service | `ssh -L` (or `-J` for ssh/scp) |
| SSH creds, many services/tools | `ssh -D` + proxychains |
| Internal host must reach you | `ssh -R` |
| Meterpreter foothold, no SSH | `route add` / `autoroute` (+ `portfwd`) |
| GUI tools (Burp, browser) through pivot | `ssh -D`, point the app at SOCKS |

## Common mistakes & tips

- **Scanning from Kali instead of pivoting.** If Kali cannot reach the
  subnet, scan *through* the pivot.
- **Using `-sS` with proxychains.** Half-open SYN cannot go through SOCKS —
  use `-sT -Pn`.
- **Pinging through SOCKS.** ICMP does not ride SOCKS; use TCP connect scans
  or `nc -zv`.
- **Too-broad scans through a proxy.** Every packet crosses two hosts and a
  tunnel; enumerate a few ports first.
- **Forwarding the wrong endpoint.** In `-L 8080:10.10.20.10:80` the middle
  address is relative to the **pivot**, not to you.
- **Forgetting `-N`/`-f`.** Interactive SSH sessions holding tunnels die when
  you log out or the terminal closes.
- **Not checking the pivot's routes first.** `ip route`/`arp -a` tell you
  which networks are worth routing to.
- **Leaving the proxy up.** Kill `ssh -D`, config changes, and Metasploit
  routes as part of cleanup.

## Checklist / Self-test

- [ ] I can explain the difference between local, remote, and dynamic SSH
      forwarding with a concrete `-L`/`-R`/`-D` example.
- [ ] On a compromised host I can identify pivot candidates with `ip addr`,
      `ip route`, and `arp -a`.
- [ ] I can access a single internal service with `ssh -L` and verify it with
      `curl` or `nc`.
- [ ] I can set up `ssh -D 1080` and route `curl`, `smbclient`, and an nmap
      `-sT -Pn` scan through it with proxychains.
- [ ] I know why ICMP and `-sS` scans fail through a SOCKS proxy.
- [ ] I can reach an internal host directly with `ssh -J` and copy files with
      `scp -J`.
- [ ] In Metasploit I can add a route with `route add`/`autoroute`, scan the
      internal subnet, and use `portfwd add` for a single service.
- [ ] I clean up SSH tunnels, proxies, and routes when the objective is done.

## Further resources

- OpenSSH manual (`ssh`: `-L`, `-R`, `-D`, `-J`) — your distribution's man pages
- proxychains-ng (GitHub): https://github.com/rofl0r/proxychains-ng
- Metasploit documentation — routing and pivoting: https://docs.metasploit.com/
- MITRE ATT&CK — Lateral Movement (pivoting context):
  https://attack.mitre.org/tactics/TA0008/
- PortSwigger — proxy configuration support: https://portswigger.net/support
