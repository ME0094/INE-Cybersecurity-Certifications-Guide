# Reconnaissance — eJPT Methodology Phase 1

> eJPT study guide · Offensive methodology — INE-Cybersecurity-Certifications-Guide

Reconnaissance is the first phase of any penetration test: before touching a
service, you must know what the authorized target looks like and where its
boundaries are. In eJPT-style labs the goal is practical and time-boxed — map
the network, find live hosts, and collect enough information to move into
enumeration. This guide covers scoping and rules of engagement, asset and
host discovery, OSINT essentials, and the host-discovery flags of `nmap`.

## What reconnaissance is

Reconnaissance answers three questions:

1. **What are we allowed to touch?** (scope and rules of engagement)
2. **Which systems are alive and belong to the target?** (asset and host discovery)
3. **What can we learn without touching the target at all?** (passive OSINT)

It can be **passive** (no packets sent: search engines, DNS records,
certificate logs) or **active** (packets sent: ping sweeps, port scans).
Passive steps come first — they are legal and quiet. Active steps are what
your scope authorizes.

## Scope and rules of engagement (ROE)

Never start scanning before you know the rules. A professional engagement
starts with signed authorization defining:

- **In-scope targets**: exact IPs/CIDRs or hostnames you may test.
- **Out-of-scope targets**: everything else, often third-party
  infrastructure (CDNs, mail relays, DNS providers).
- **Time windows** (e.g., only 21:00–05:00) and **testing restrictions**
  (e.g., no denial-of-service, no social engineering).
- **Emergency contacts** and what to do if you find critical data.

Treat every lab like a mini-engagement: write the scope down before scanning.

```text
# Example scope note (lab context — adapt to your engagement)
In-scope      : 10.10.10.0/24  and  192.168.50.0/27
Out-of-scope  : 10.10.10.254 (gateway, not the target)
Allowed       : Active scanning, credential brute force on lab services
Not allowed   : DoS, exfiltration of real user data, scanning beyond scope
```

Practical rules: scan **only** hosts inside your written scope (scope creep
is a real professional failure); start **broad and passive**, then go narrow
and active; record everything — good notes win exams and engagements.

## Asset discovery

Before sweeping IPs, confirm which networks and names belong to the target.

- **Whois / RDAP**: reveal which organization owns an IP range or domain.
- **DNS queries**: NS and MX records often leak naming schemes and subdomains.
- **On local lab networks**: confirm which interface reaches the lab and map
  the local segment with ARP (no routing needed).

```bash
# WHOIS for a domain or IP (public registration data)
whois example.com | head -20

# DNS records that reveal infrastructure
dig example.com NS          # name servers
dig example.com MX          # mail servers -> internal hostnames often visible
dig example.com TXT         # SPF/DMARC records may list authorized senders

# Local network: ARP discovery finds neighbors on the same L2 segment
ip route                    # confirm which subnet is directly reachable
arp-scan -l                 # scan the local subnet via ARP (fast, reliable)
```

```text
# Expected output (arp-scan, abridged)
10.10.10.1     aa:bb:cc:11:22:33  (Unknown)
10.10.10.5     00:0c:29:aa:bb:01  VMware, Inc.   <- likely a lab VM
```

## Ping sweeps (host discovery)

You usually start with an IP range, not a list of live hosts. A **ping
sweep** finds which IPs answer, so later port scans stay focused. Tools:
`fping`, `nmap -sn`, or a simple `bash` loop.

```bash
# fping: fast ICMP sweep over a /24
fping -a -g 10.10.10.0/24 2>/dev/null

# Bash loop alternative (slow, educational)
for i in $(seq 1 254); do
  ping -c 1 -W 1 10.10.10.$i >/dev/null 2>&1 && echo "10.10.10.$i is up"
done
```

```text
# Expected output (fping -a -g)
10.10.10.1
10.10.10.5
10.10.10.8
```

> Many hosts drop ICMP echo (firewalls) yet still run TCP services. `nmap
> -sn` solves this by sending TCP probes too — see below.

## OSINT essentials

Open-source intelligence collects public data **without** sending packets to
the target. These techniques also help during web enumeration later.

### Google dorks (search operators)

Operators narrow results to target-owned content, files, and login pages:

```text
site:example.com            # all indexed pages of one domain
site:example.com filetype:pdf
inurl:admin OR intitle:"index of"   # admin paths, open directory listings
"example.com" filetype:sql          # accidentally indexed data
```

Use dorks only on data that is **publicly indexed** — dorking does not make
data you are not authorized to view fair game.

### DNS

`dig`, `host`, and `nslookup` are the standard record lookup tools. Common
types: `A` (IPv4), `AAAA` (IPv6), `CNAME` (alias), `MX` (mail), `NS` (name
servers), `TXT` (text/verification records).

```bash
dig +short example.com          # A record only
dig +short example.com CNAME    # aliases
dig @8.8.8.8 example.com        # query a specific resolver
```

### Certificates (certificate transparency)

Every TLS certificate issued for a domain is publicly logged. Querying
certificate logs (crt.sh) returns hostnames never linked from the main site —
a classic source of hidden subdomains.

```bash
# crt.sh public log search -> unique hostnames
curl -s "https://crt.sh/?q=example.com&output=json" | jq '.[].name_value'

# Inspect the certificate a live TLS service presents (Subject Alt Names)
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName
```

Aggregate OSINT tools (e.g., `theHarvester`) automate search-engine, DNS, and
certificate queries into one report — fast but noisy, so verify every result.

## Intro to nmap host discovery flags

`nmap` combines host discovery and port scanning. These flags control the
**discovery** phase (is the host alive?):

| Flag | What it sends | Typical use |
|---|---|---|
| `-sn` | No port scan: ICMP echo + TCP SYN to 443 + TCP ACK to 80 + ICMP timestamp request | Pure ping sweep |
| `-PS22,80,443` | TCP SYN to given ports | Discover hosts behind ICMP-blocking firewalls |
| `-PA80` | TCP ACK packet (expects RST) | Stateless-firewall live-host check |
| `-PU53` | UDP probe to given ports | Hosts that drop ICMP but answer UDP |
| `-PE`/`-PP`/`-PM` | ICMP echo / timestamp / address-mask | Classic ICMP discovery |
| `-PR` | ARP request (root; local subnet) | Fastest on a LAN; used automatically when possible |
| `-Pn` | Skips discovery entirely | Assume hosts are up; scan anyway |
| `-n` | No reverse DNS on results | Faster, less noisy |

```bash
# Practical host discovery patterns
nmap -sn 10.10.10.0/24                 # default ping sweep (ICMP + TCP 80/443)
nmap -sn -PS22,80,443 10.10.10.0/24    # TCP-based discovery for ICMP-blockers
nmap -sn -PU53 10.10.10.0/24           # add a UDP probe
nmap -sn -n 10.10.10.0/24              # skip DNS to run faster
```

```text
# Expected output (nmap -sn -n 10.10.10.0/24)
Nmap scan report for 10.10.10.1
Host is up (0.0012s latency).
Nmap scan report for 10.10.10.5
Host is up (0.0008s latency).
Nmap done: 256 IP addresses (3 hosts up) scanned in 2.4 seconds
```

**Why `-sn` beats plain `ping`**: `ping` only sends ICMP echo; `nmap -sn`
combines several probes, so hosts that silently drop ICMP are still found. On
local networks it uses ARP, which almost nothing filters. Save results
structured for the next phase:

```bash
nmap -sn -n 10.10.10.0/24 -oG hosts.gnmap   # grep-able output
grep "Status: Up" hosts.gnmap | awk '{print $2}' > live_hosts.txt
```

## Record keeping

Recon produces the target list every later phase consumes. A minimal log per
host:

```text
Host:      10.10.10.5    MAC: 00:0c:29:aa:bb:01 (VMware)
Alive by:  ARP + ICMP    Date/time: 2025-01-01 09:00
Notes:     Hostnames via crt.sh: dc01.lab.local, www.lab.local
Next step: full TCP port scan + version detection (enumeration phase)
```

## Common Mistakes & Tips

- **Scanning out of scope.** The #1 professional mistake. Re-read the scope
  before every new subnet.
- **Trusting ICMP.** A host that ignores ping may still run web or SMB
  services — use `nmap -sn` with TCP probes, or `-Pn`.
- **Skipping passive recon.** DNS and certificate logs often reveal more
  hosts than a blind sweep of the gateway IP.
- **Forgetting local ARP.** On a lab LAN, `arp-scan -l` is faster and more
  reliable than pinging.
- **No output files.** You will not remember 40 hosts. Use `-oG`/`-oA` from
  the start.
- **Slow sweeps by default.** Add `-n` and a timing template (`-T4`) once
  authorized.
- **Confusing discovery with enumeration.** Discovery only answers "is it
  up?" — do not report open ports until you actually scan them.

## Checklist / Self-Test

- [ ] I can explain the difference between passive and active reconnaissance
      and why passive comes first.
- [ ] I can list the key elements of a rules-of-engagement document (scope,
      exclusions, times, restrictions, contacts).
- [ ] I can run a ping sweep with `fping`, a bash loop, and `nmap -sn`.
- [ ] I can query WHOIS and `dig` NS/MX/TXT records and interpret results.
- [ ] I can use `site:`/`filetype:` Google dorks and explain their limits.
- [ ] I can enumerate subdomains from certificate transparency (crt.sh) and
      verify the names resolve.
- [ ] I can explain when to use `-sn`, `-PS`, `-PA`, `-PU`, `-PR`, and `-Pn`.
- [ ] I produce a written scope and a host list (`-oG`) before any scan.

> **Verification:** executed against Nmap 7.94SVN on 2026-09-19: `nmap -sn -n --packet-trace`
> against a single address traces exactly the default discovery set — ICMP echo request, TCP
> SYN to 443, TCP ACK to 80 and an ICMP timestamp request — which is what the `-sn` row above
> now states. The OSINT and `dig` examples are documented syntax and were not run here.

## Further Resources

- Nmap reference guide (official): https://nmap.org/book/toc.html
- Nmap host-discovery options: https://nmap.org/book/man-host-discovery.html
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- Certificate transparency search: https://crt.sh
- MITRE ATT&CK — Reconnaissance tactics: https://attack.mitre.org/tactics/TA0043/
- `dig`, `host`, and `whois` man pages on your distribution
