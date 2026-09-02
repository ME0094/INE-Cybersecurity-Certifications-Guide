# Nmap Cheatsheet

> `01-Fundamentals/eJPT` · tools — INE-Cybersecurity-Certifications-Guide

Nmap ("Network Mapper") is the standard open-source tool for network discovery and
security auditing. For the eJPT you need it fluent: host discovery, port scanning,
service/version detection, OS detection, and the Nmap Scripting Engine (NSE).

## What Nmap reports

- **Host state**: up or down (with a ping scan).
- **Port state**: `open` (service responds), `closed` (reachable, nothing listening),
  `filtered` (firewall drops the probe — you cannot tell open vs closed), and
  `open|filtered` (no response; common for UDP).
- **Service & version**: application name and version when detected (`-sV`).
- **OS guess**: fingerprint of the operating system (`-O`).

## Host discovery

Find which hosts are alive before deeper scanning. Nmap's default host discovery sends
ICMP echo + TCP SYN to port 443 + TCP ACK to port 80 (+ ARP on the local subnet when
running as root).

```bash
# Ping sweep a /24 (no port scan). Root not strictly required for -sn.
sudo nmap -sn 10.0.0.0/24

# Save results in "greppable" format for later parsing
sudo nmap -sn 10.0.0.0/24 -oG ping.gnmap

# List live host IPs from the greppable output
grep "Status: Up" ping.gnmap | cut -d " " -f 2

# Treat every host as up — skip host discovery entirely (firewalled networks)
sudo nmap -Pn -p 22,80,443 10.0.0.6

# Only list targets, no packets sent at all
nmap -sL 10.0.0.0/30
```

Probe options you may combine with `-sn`: `-PS22,80` (TCP SYN ping),
`-PA80` (TCP ACK ping), `-PU53` (UDP ping), `-PE` (ICMP echo), `-PR` (ARP ping, local
subnet only). If pings are blocked, `-Pn` forces a port scan of everything.

## Port scanning techniques

| Option | Technique | Notes |
|---|---|---|
| `-sS` | TCP SYN ("half-open") | Default as root; fast, less logged. Needs root. |
| `-sT` | TCP connect | Full 3-way handshake; fallback for non-root users. |
| `-sU` | UDP scan | Slow and often unreliable; scan a short list of top ports. |
| `-sA` | TCP ACK | Maps firewall rules, does not find open ports. |
| `-sF`/`-sX` | FIN / Xmas | Rarely used; often filtered anyway. |

```bash
# Full TCP port range on one host
sudo nmap -p- -T4 10.0.0.6

# Specific ports or ranges
sudo nmap -p 22,80,443,445 10.0.0.6
sudo nmap -p 1-1024 10.0.0.6

# Fast scan: top 100 ports instead of default top 1000
sudo nmap -F 10.0.0.6

# Top N ports explicitly
sudo nmap --top-ports 200 10.0.0.6

# Common UDP ports (DNS 53, SNMP 161, TFTP 69) — expect it to be slow
sudo nmap -sU --top-ports 50 10.0.0.6

# Only show hosts/ports that are actually open
sudo nmap --open -F 10.0.0.6
```

## Service and version detection

```bash
# Version detection on specific ports (adds banner + probe matching)
sudo nmap -sV -p 21,22,80,443 10.0.0.6

# Version intensity 0-9 (default 7); light = 2, max = 9
sudo nmap -sV --version-light 10.0.0.6
sudo nmap -sV --version-all 10.0.0.6

# -sC runs the "default" script category (-sC == --script=default)
sudo nmap -sV -sC -p 22,80,445 10.0.0.6

# -A = -O -sV -sC --traceroute (the "everything" convenience flag)
sudo nmap -A -p- 10.0.0.6
```

Without `-sV` the service column comes from `/etc/services` guesses — always confirm
with version detection before choosing an exploit.

## OS detection

```bash
# OS fingerprinting; best results need at least one open AND one closed port
sudo nmap -O 10.0.0.6

# Aggressive guess when the fingerprint is ambiguous
sudo nmap -O --osscan-guess 10.0.0.6
```

OS detection is a guess, not a fact — verify with banners and behavior.

## NSE — Nmap Scripting Engine

Script categories (official): `auth`, `broadcast`, `brute`, `default`, `discovery`,
`dos`, `exploit`, `external`, `fuzzer`, `intrusive`, `malware`, `safe`, `version`,
`vuln`.

```bash
# Useful per-service examples
nmap -p 80 --script http-title,http-headers 10.0.0.6     # web page title + headers
nmap -p 80 --script http-enum 10.0.0.6                   # common web directories
nmap -p 21 --script ftp-anon 10.0.0.6                    # anonymous FTP allowed?
nmap -p 22 --script ssh2-enum-algos 10.0.0.6             # SSH algorithms offered
nmap -p 445 --script smb-os-discovery,smb-enum-shares 10.0.0.6  # SMB info
nmap -p 445 --script smb-vuln-ms17-010 10.0.0.6          # EternalBlue check
nmap -p 443 --script ssl-enum-ciphers 10.0.0.6           # TLS cipher strength

# Whole categories
nmap --script vuln 10.0.0.6     # known-vulnerability checks (labs only)
nmap -sC 10.0.0.6               # equivalent to --script=default

# Script arguments
nmap -p 80 --script http-enum --script-args http.useragent="Mozilla/5.0" 10.0.0.6
```

Caution: `intrusive` and `dos` scripts can crash fragile services or trigger alarms.
Use them only against your own lab targets.

## Output formats

| Option | Format | Use case |
|---|---|---|
| `-oN file` | Normal text | Human reading |
| `-oX file` | XML | Scripting and tools (Metasploit `db_import`) |
| `-oG file` | Greppable | Quick `grep`/`awk` pipelines |
| `-oJ file` | JSON | Programmatic parsing |
| `-oA base` | All of the above | Always prefer this for engagements |

```bash
# One run, three files: full.nmap, full.gnmap, full.xml
sudo nmap -sV -sC -p- 10.0.0.6 -oA full

# Increase verbosity to see progress (-vv is louder)
sudo nmap -vv -p- 10.0.0.6
```

## Timing and performance

| Option | Effect |
|---|---|
| `-T0` … `-T5` | Timing templates: paranoid → insane. Default is `-T3`. |
| `-n` | No reverse DNS lookups (faster). |
| `--min-rate 1000` | Send at least ~1000 packets/s (fast sweeps). |
| `--max-retries 1` | Fewer retries for lost probes (faster, less reliable). |
| `--host-timeout 20m` | Give up on a host after 20 minutes. |
| `--stats-every 10s` | Print progress stats during long scans. |

```bash
# Aggressive but practical full scan used in lab drills
sudo nmap -sS -p- -T4 --min-rate 1000 --open -oA fulltcp 10.0.0.6
```

`-T5` is rarely a good idea — it can drop results. `-T4` plus `--min-rate` is usually
enough in a lab.

## Common workflows

```bash
# 1. Discover live hosts, save the list
sudo nmap -sn 10.0.0.0/24 -oG ping.gnmap
grep "Status: Up" ping.gnmap | cut -d " " -f 2 > hosts.txt

# 2. Quick sweep of the top 100 ports across all live hosts
sudo nmap -T4 -F --open -iL hosts.txt -oG quick.gnmap

# 3. Full TCP scan on one target
sudo nmap -p- -T4 --min-rate 1000 --open 10.0.0.6 -oA fulltcp

# 4. Version + default scripts on the ports that matter
sudo nmap -sV -sC -p 21,22,80,139,445,3306 10.0.0.6 -oA sv

# 5. Targeted single-service checks (SMB example)
nmap -p 445 --script smb-os-discovery,smb-enum-shares 10.0.0.6

# 6. OS guess when needed
sudo nmap -O 10.0.0.6
```

The classic flow is: **ping sweep → top-ports sweep → full TCP on interesting hosts →
version/scripts on open ports → OS/extra checks**. Do not jump straight to `-A -p-`
against a whole subnet.

## Common Mistakes & Tips

- **Forgetting `sudo`.** As a normal user `-sS` and `-O` silently degrade (SYN scan
  becomes connect scan) or fail. Run privileged scans with `sudo`.
- **Scanning the wrong interface/subnet.** Confirm your IP with `ip a` before sweeping.
- **Trusting filtered as closed.** `filtered` means a firewall dropped the probe —
  results are inconclusive, not negative.
- **Skipping version detection.** Never pick an exploit from a guessed service name.
- **Using `-T5` or huge `--min-rate` against fragile lab VMs** — dropped packets cause
  false "closed" results.
- **Ignoring output files.** Always `-oA`; re-scanning because you lost the output is
  wasted time.
- **Running `--script vuln`/`dos` on production or shared networks** — intrusive scripts
  are for your own lab only.
- **Not re-checking states.** Run an open-port scan without `--open` once so you can see
  `filtered` ports and understand the full picture.

## Checklist / Self-Test

- [ ] I can explain `open`, `closed`, and `filtered` port states.
- [ ] I can run a ping sweep (`-sn`) on a /24 and list live IPs.
- [ ] I can perform a full TCP scan (`-p-`) and a fast top-100 scan (`-F`).
- [ ] I can identify a service version with `-sV` and interpret the banner.
- [ ] I can run `-sC` / specific NSE scripts (e.g., `smb-os-discovery`) on a port.
- [ ] I can produce `-oA` output and extract live hosts from the `.gnmap` file.
- [ ] I know when to use `-Pn`, `-n`, `-T4`, and `--min-rate`.
- [ ] I can run `-sU` against a short list of top UDP ports.

## Further Resources

- Nmap reference guide (the official book, free online): <https://nmap.org/book/toc.html>
- Nmap man page: <https://nmap.org/book/man.html>
- NSE script documentation and categories: <https://nmap.org/nsedoc/>
- Nmap network scanning cheatsheet by the author: <https://nmap.org/book/toc.html>
