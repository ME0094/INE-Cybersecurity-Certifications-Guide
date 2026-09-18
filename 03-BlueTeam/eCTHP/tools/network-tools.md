# Network Tools — Zeek, PCAP, Flow, Proxy, DNS & RITA

> eCTHP · Tools — INE Cybersecurity Certifications Study Guide
>
> The network side of a hunt: protocol metadata with Zeek, packet-level proof with tshark and Wireshark, flow records when you cannot keep packets, and the two application logs that punch through TLS — proxy and DNS. Closes with RITA for beacon scoring. Every capture and log here comes from infrastructure you own or are authorized to monitor.

## 1. Why network telemetry is the cheapest hunting ground

The endpoint can lie, be cleaned, or be reinstalled. The wire records what actually crossed it. Three properties make network data disproportionately valuable for hunting:

1. **The attacker has to communicate.** Command and control, lateral movement, and exfiltration all require traffic. Prevented or unobserved, that traffic is still a signal somewhere.
2. **It is the only source that survives a wiped endpoint.** Reimaging a host destroys endpoint artefacts; the flow record of what it talked to remains.
3. **It is often the only place a URL, hostname, or user agent appears**, because TLS hides everything inside the connection from the packet capture.

The price is that network data is high-volume, mostly encrypted, and rarely carries process attribution. Treat it as one leg of the hunt, not the whole hunt: a network lead ("host X beaconed to host Y every 60 seconds") becomes a finding only when paired with an endpoint fact ("and process `Z`, spawned by `W`, owned that connection").

## 2. The layers of network evidence

Each layer answers a different question at a different cost. Know which one you are looking at before you interpret a negative result.

| Layer | Example tooling | What it answers | Retention reality | Blind spot |
| --- | --- | --- | --- | --- |
| **Full packet capture** | Wireshark, tshark, `dumpcap` | Everything observable on the wire, including payload and protocol anomalies | Hours to days at any real bandwidth | Encrypted payload; packets dropped by the capture stack under load |
| **Protocol metadata** | Zeek | Who talked to whom, with which protocol, for how long, how many bytes, and what names/URIs/SNI were visible | Weeks to months (small compared to PCAP) | Only what Zeek has an analyzer for; encrypted payload |
| **Flow records** | NetFlow / IPFIX / sFlow (`nfdump`, `nfcapd`) | Volume and timing of conversations at scale across the whole estate | Months, cheaply | No payload, no hostnames, often sampled, no process |
| **Proxy logs** | Forward/reverse proxies | URL, host, method, user agent, bytes, allow/deny decision per user and host | Days to weeks, vendor-dependent | Only proxied traffic; `CONNECT` hides the path |
| **DNS logs** | Resolver logs, Windows DNS, Zeek `dns.log`, Sysmon ID 22 | Name resolution attempts per client — the best cheap C2 signal | Days to weeks | Encrypted DNS (DoH/DoT) removes visibility entirely |

> Practical ordering for a hunt: **DNS and flow first** (cheap, wide, fast), then **Zeek metadata** to characterise anything interesting, then **PCAP** only to prove the specific claim you intend to make. Capturing everything forever is neither affordable nor necessary.

## 3. Zeek

**What it is.** A passive network security monitor that turns raw traffic into structured, per-protocol log files. It is not an IDS by default: it describes what happened in tables you query, and detection policy is scripts you add on top.

**What question it answers.** *What did this conversation look like?* Which host initiated, which service was negotiated, how many bytes moved in each direction, which TLS server name was requested, which DNS names were queried, which files were seen, which SMB paths were touched, whether the connection was rejected or left hanging.

**The logs that matter for hunting:**

| Log | Hunting value |
| --- | --- |
| `conn.log` | Every connection: 5-tuple, duration, `orig_bytes`/`resp_bytes`, `conn_state`, `history`, `service`. The backbone of beaconing, scanning, and exfiltration analysis |
| `dns.log` | `query`, `qtype`, `rcode`, `answers`, `TTLs` — DNS tunnelling and DGA leads |
| `http.log` | `host`, `uri`, `user_agent`, `method`, `status_code`, `resp_mime_types` — cleartext HTTP C2 and download detection |
| `ssl.log` | `server_name` (SNI), `version`, `cipher`, certificate `subject`/`issuer`, validation status — C2 over TLS, self-signed beacons |
| `x509.log` | Full certificate details for pivoting on certificate reuse |
| `files.log` | File transfers with hashes — pivot to endpoint scanning with YARA |
| `smb_files.log`, `smb_mapping.log`, `ntlm.log` | Lateral movement over SMB and the NTLM identities involved |
| `kerberos.log` | Ticket requests — service-ticket anomalies and Kerberos-based movement |
| `ssh.log` | SSH sessions, including the guessing behaviour Zeek's policy detects |
| `notice.log` | Policy hits: port scans, SSH password guessing, and your own `Intel` framework matches |
| `weird.log` | Protocol violations — malformed traffic, tunnelling artefacts, evasion attempts |
| `intel.log` | Matches against your indicator list (`intel.dat`) |

**How to use it.**

```bash
# Offline analysis of a capture (the normal hunting mode)
zeek -r /lab/pcaps/hunt-01.pcap
# Logs are written to the current directory (Log::default_logdir)

# -C ignores invalid checksums, a common necessity with capture artefacts
zeek -C -r /lab/pcaps/hunt-01.pcap

# Live capture on an interface (needs privileges and a span port or TAP in the path)
sudo zeek -i eth0

# Tell Zeek which networks are "local" — this changes what it can reason about
zeek -r /lab/pcaps/hunt-01.pcap local "Site::local_nets += { 10.20.0.0/16 }"

# Cluster/standalone management in a deployed sensor
zeekctl deploy
zeekctl status
```

`zeek-cut` projects named fields so you can pipe logs into ordinary text tools. It needs the `#fields` header line, so feed it whole log files rather than pre-stripped data:

```bash
# Longest-lived connections: a classic beacon/exfiltration shape
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service duration orig_bytes resp_bytes | sort -k6 -nr | head

# Connections that were attempted and never answered (scanning, dead C2, blocked egress)
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p conn_state | awk '$4=="S0"' | sort | uniq -c | sort -nr | head

# DNS names queried, with the client that asked
cat dns.log | zeek-cut id.orig_h query qtype rcode | sort | uniq -c | sort -nr | head -30

# Convert epoch timestamps to readable time
cat conn.log | zeek-cut -d ts id.orig_h id.resp_h id.resp_p
```

Beaconing, computed straight from `conn.log` (regular intervals per conversation):

```bash
# Inter-arrival deltas per (source, destination, port) — low spread means a beacon
cat conn.log \
  | zeek-cut id.orig_h id.resp_h id.resp_p ts \
  | sort -k1,1 -k2,2 -k3,3n -k4,4n \
  | awk '{ key=$1" "$2" "$3; if (key==prev) { d=$4-last; if (key in n) { n[key]++; s[key]+=d; ss[key]+=d*d } else { n[key]=1; s[key]=d; ss[key]=d*d } } prev=key; last=$4 }
         END { for (k in n) if (n[k]>=10) { m=s[k]/n[k]; v=ss[k]/n[k]-m*m; if (v<0) v=0; printf "%d conns  mean_sec %.1f  stddev_sec %.1f  %s\n", n[k]+1, m, sqrt(v), k } }' \
  | sort -k6,6n | head -20
```

That awk is deliberately plain: a hunt computed with tools you understand is a hunt you can defend. If you would rather not reimplement statistics, use RITA (section 8).

**Limitations.**

- **Encrypted payload is opaque.** Zeek gives you SNI, JA3-class fingerprints, byte counts, and timing — not the content. (Recent Zeek versions can emit `ja3`/`ja3s` in `ssl.log`; check your own `ssl.log` header before relying on the field.)
- **Needs full visibility.** Without a span port, TAP, or capture on the correct host, you are hunting a subset of traffic without knowing which subset is missing.
- **Resource cost.** A busy link is CPU- and disk-intensive; a sensor that cannot keep up drops traffic, and dropped traffic looks exactly like traffic that never existed.
- **Protocol coverage is finite.** Custom or obfuscated protocols land in `weird.log` or as anonymous TCP with only byte counts.
- **No identity or process context.** `conn.log` gives IP addresses. Attributing them to a user, a process, or a device needs DHCP, DNS, authentication, or endpoint data.

## 4. Wireshark and tshark

**What they are.** The packet-level ground truth: Wireshark for interactive inspection, `tshark` for the same dissection engine on the command line. This is where you go to *prove* a claim, not to browse a week of traffic.

**What question they answer.** *What exactly was on the wire?* Which payload was in that POST, what the malware's protocol framing looked like, whether a name was resolved before connection, whether a certificate was self-signed, and what the real request was behind an anomalous flow.

**How to use it.**

```bash
# Read a capture with a display filter, projecting only the fields you need
tshark -r /lab/pcaps/hunt-01.pcap -Y 'dns' -T fields -e frame.time -e ip.src -e dns.qry.name

# Cleartext HTTP: host, URI, user agent
tshark -r /lab/pcaps/hunt-01.pcap -Y 'http.request' \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri -e http.user_agent

# The TLS server name (SNI) is visible even when the payload is not
tshark -r /lab/pcaps/hunt-01.pcap -Y 'tls.handshake.extensions_server_name' \
  -T fields -e ip.dst -e tls.handshake.extensions_server_name

# Just the DNS questions, no responses
tshark -r /lab/pcaps/hunt-01.pcap -Y 'dns.flags.response == 0' -T fields -e dns.qry.name

# Traffic volume in 60-second buckets — the shape of a periodic conversation
tshark -r /lab/pcaps/hunt-01.pcap -q -z io,stat,60

# Conversation and endpoint summaries, and expert-level anomalies
tshark -r /lab/pcaps/hunt-01.pcap -q -z conv,tcp
tshark -r /lab/pcaps/hunt-01.pcap -q -z endpoints,ip
tshark -r /lab/pcaps/hunt-01.pcap -q -z expert

# What statistics does this build support?
tshark -z help
```

In the Wireshark GUI, the equivalents live under **Statistics → Conversations**, **Statistics → Endpoints**, **Statistics → Protocol Hierarchy**, and **Analyze → Expert Information**. `Follow → TCP Stream` reconstructs a session; `File → Export Objects` extracts transferred files.

**Limitations.**

- **Retention and volume.** PCAP at line rate is the most expensive telemetry to keep. Use it to answer a specific question over a bounded window.
- **Dropped packets are invisible.** Under load, the capture stack discards packets before the tool sees them; a "clean" filter result over a loaded sensor proves less than it appears to.
- **Encrypted traffic.** You can characterise it, not read it. For C2 inside TLS, pivot to Zeek metadata, proxy logs, or endpoint telemetry.
- **A capture is a moving target.** A long live capture takes hours and answers one question; tshark over stored PCAP is almost always the faster path.
- **Dissector gaps.** A proprietary or custom protocol shows as TCP with byte counts until you decode it yourself.

## 5. NetFlow and IPFIX

**What they are.** Flow telemetry: instead of packets, a router or exporter emits **records** describing conversations — source and destination address and port, protocol, packet and byte counts, and start/end times. IPFIX is the IETF standardised successor to Cisco's NetFlow v5/v9; sFlow is a sampling-based alternative.

**What question they answer.** *Who talked to whom, how much, and for how long — across the whole estate, cheaply?* It is the only network source that scales to every router and switch without a capture appliance per link.

**How it is collected and queried.**

```bash
# Collector: receive flow records and write rotating files to a directory
nfcapd -D -l /var/flows -p 2055

# Exporter on a Linux host (when no router will export for you)
softflowd -i eth0 -n 127.0.0.1:2055

# Read one capture file, or a whole time window across files
nfdump -r /var/flows/nfcapd.202609180000
nfdump -R /var/flows -t 2026/09/18.00:00-2026/09/18.06:00

# Top talkers by bytes — the fastest exfiltration triage there is
nfdump -R /var/flows -s srcip/bytes -n 20
nfdump -R /var/flows -s dstip/bytes -n 20

# Machine-readable output for a notebook or a diff
nfdump -R /var/flows -o csv > /lab/exports/flows.csv

# Full option and format list for your build
nfdump --help
```

**What to look for.**

- **Top talkers by bytes, especially outbound.** One internal host far above its peers is an exfiltration lead until proven otherwise.
- **Long-duration, low-volume, regular conversations.** The flow-level shadow of a beacon.
- **Fan-out.** One internal address touching many internal addresses on one port (445, 3389, 5985, 22) is lateral movement or a worm.
- **`S0`-style one-way records.** High packet counts with no return traffic — scans, blocked egress, or a dead C2 endpoint.
- **Newly seen external destinations** that never appear in your proxy or DNS logs: something is talking without being proxied, which is itself worth explaining.

**Limitations.**

- **No payload, therefore no names.** Flow records contain addresses and ports only — no URL, no DNS name, no filename. Pair with DNS and proxy logs to interpret them.
- **Sampling destroys beacon analysis.** A 1-in-1000 sampled exporter cannot show you interval regularity. Verify the sampling rate before you compute anything from timing.
- **No process or user attribution.** NAT, VPN concentrators, and cloud overlays obscure which real endpoint a flow belongs to.
- **Timestamp resolution varies.** Some exporters report minute-level buckets, which is far too coarse for a 60-second beacon.
- **Flows are unidirectional records in many exporters.** Aggregation into "conversations" is done by your analysis tool, so state that assumption when you report timing.

## 6. Proxy logs

**What they are.** Records of every request that passed through a forward or reverse proxy. Where TLS hides the URL from PCAP, a TLS-terminating proxy sees the request line, `Host` header, and user agent.

**What question they answer.** *Which user or host requested which URL, with what method and user agent, and what did the proxy decide?* This is the primary source for HTTP(S) C2, staged payload downloads, and exfiltration over web services.

**Generic fields to expect** (names differ per vendor — confirm against a real log line before querying):

| Field | Hunting use |
| --- | --- |
| Timestamp, client IP, username | Attribution and correlation with endpoint telemetry |
| URL / host / port | Destination and, for cleartext, the path |
| Method (`GET`, `POST`, `CONNECT`) | `POST` implies data being sent; `CONNECT` means the path is hidden |
| Status code | Blocked, failed, or successful delivery |
| Bytes sent / received | Asymmetric upload volume is an exfiltration lead |
| User agent | A rare, spoofed, or script-like user agent stands out against a baseline |
| Category / action | Allowed versus blocked, and the policy's own opinion |

```spl
// Periodic requests to one host from one client: beaconing over HTTP
index=proxy
| sort 0 + _time
| streamstats current=f last(_time) as prev by src_ip, dest_host
| eval delta = _time - prev
| stats count avg(delta) as avg_delta stdev(delta) as jitter sum(bytes_out) as uploaded by src_ip, dest_host
| where count > 20 and jitter < 5
```

**Limitations.**

- **`CONNECT` hides everything after the host.** For HTTPS through a non-terminating proxy you get hostname and port only — which is still enough for beaconing analysis, but not for content.
- **Only proxied traffic.** Anything bypassing the proxy (direct egress, non-standard ports, VPN, tunnelling) is invisible in this log.
- **Identity is the proxy's opinion.** A shared account, a service account, or a device on the network can mislead attribution.
- **Volume and retention.** Proxy logs are large and usually trimmed aggressively; long-horizon hunts need an export strategy.
- **Aggregation hides the individual request.** Some proxies roll up repeated requests, which destroys the timing detail a beacon hunt depends on.

## 7. DNS logs

**What they are.** Records of name-resolution queries, from whatever answers them: an internal resolver (`BIND` query log, `dnsmasq`, `Unbound`, Windows DNS Server), a passive monitor (Zeek `dns.log`), or the endpoint itself (Sysmon Event ID 22).

**What question they answer.** *What names did this client try to resolve, when, and what happened?* Because nearly all remote operations begin with a lookup, DNS is the highest-yield low-cost hunting source on the network, and it very often survives when payload inspection does not.

**Query patterns.**

```bash
# Zeek: the queries, per client, ranked
cat dns.log | zeek-cut id.orig_h query qtype rcode | sort | uniq -c | sort -nr | head -40

# Longest query names — the signature of encoded data in DNS tunnelling
cat dns.log | zeek-cut query | awk '{ print length($0), $0 }' | sort -nr | head -20

# Unique subdomains per registered domain, second level and below
cat dns.log | zeek-cut query | awk -F. 'NF>=2 { d=$(NF-1)"."$NF; c[d]++ } END { for (k in c) print c[k], k }' | sort -nr | head -20
```

```kusto
// Sentinel/Kusto shape: burst of NXDOMAIN responses for random-looking names
DnsEvents
| where TimeGenerated > ago(24h)
| summarize Queries = count(), UniqueNames = dcount(Name) by ClientIP, bin(TimeGenerated, 10m)
| where UniqueNames > 100
```

> Table and column names for DNS data depend on your collector. Confirm against a sample record before trusting any query copied from elsewhere.

**The four DNS behaviours worth hunting:**

| Behaviour | What it looks like in the data | What confounds it |
| --- | --- | --- |
| **DNS tunnelling** | Few domains, enormous numbers of unique long subdomains, `TXT`/`NULL`/`CNAME` queries at high rate, sustained upstream volume | Legitimate CDN and security-vendor lookups use long, random-looking labels |
| **DGA beaconing** | Many NXDOMAIN responses for pseudo-random names at a regular interval, then one success | Some legitimate software probes for non-existent hosts at startup |
| **Beaconing by name** | The same name queried every N seconds with low jitter, consistently, from one client | Update checks, telemetry, NTP-like heartbeats, and monitoring agents do exactly this |
| **Unauthorised resolution** | Queries to a resolver you do not own, or DoH traffic to a public resolver | Legitimate applications shipping their own resolver — a policy question, not a malware verdict |

**Limitations.**

- **Encrypted DNS ends the visibility.** DoH and DoT hide queries from your resolver entirely; you can only see that a client is talking to a DoH endpoint, not what it asked.
- **Caching hides repetition.** A resolver that caches an answer will not log the next identical query, so "same query every 60 s" may appear only once — check client-side telemetry (Sysmon ID 22) if you need per-process resolution detail.
- **IP-only resolvers may not log the client.** Some log formats record the query but not the requester, which removes the pivot you need most.
- **Volume.** Full query logging is high-volume and privacy-sensitive; it is frequently shortened or filtered, which creates blind spots that look like absence of activity.
- **A query is not a connection.** Resolution proves intent to reach a name, not that anything succeeded — correlate with `conn.log` or flow records before calling it C2.

## 8. RITA (beaconing analysis)

**What it is.** An open-source framework that ingests Zeek logs into a database and scores behaviour — primarily **beaconing** — by analysing connection timing, volume consistency, and data-size consistency. It exists because computing that by hand at scale is tedious and error-prone.

**What question it answers.** *Which internal hosts are talking to external endpoints on a regular, machine-like schedule?* It answers it with a ranked score plus the modifiers that produced it, so you can see *why* something scored.

**How to use it.**

```bash
# Import a directory of Zeek logs into a named dataset
rita import --logs /lab/zeek/logs --database hunt-2026-09

# Open the analysis UI for that dataset
rita view hunt-2026-09

# Manage datasets
rita list
rita delete hunt-2026-09

# Confirm the argument form for your release (v3 and v4 differ)
rita import --help
```

**How to read it.**

- The **beacon score** is a heuristic: high counts with low variance in interval and size score high. Read the modifiers, not just the number — a high score driven by a huge connection count to a monitoring SaaS is a false positive you should document, not ignore.
- Feed it Zeek logs that include `conn.log` (required for beaconing) plus `dns.log` and `http.log` for context.
- Use it as a **ranking function**, then verify each top candidate with `conn.log` deltas, proxy logs, and the owning process on the endpoint.

**Limitations.**

- **Benign software beacons constantly.** Update checks, licensing heartbeats, monitoring agents, backup software, and cloud sync all produce regular intervals. Expect a minority of real findings among a majority of legitimate ones.
- **Only as good as the Zeek logs.** Gaps in capture, missing local-network definition, or a short collection window all degrade scoring.
- **Needs volume to score.** A handful of connections cannot establish periodicity; short datasets produce noise or silence.
- **Non-periodic C2 scores low.** Heavy jitter, long-poll HTTP, domain fronting, and content-delivery blending are specifically designed to look irregular. A low score is not a clearance.
- **Deployment footprint.** RITA v4 depends on a database backend (MongoDB) and enough disk for the imported Zeek logs. Plan the lab accordingly (see `../labs/hunting-range-setup.md`).

## 9. What each behaviour looks like in network data

| Hunt hypothesis | Best data source | Signature to look for | What confounds it |
| --- | --- | --- | --- |
| **C2 beaconing** | Zeek `conn.log`, RITA, proxy logs | Many connections between the same pair on the same port, low variance in inter-arrival time and byte counts, long active window | Software update checks, monitoring agents, CDN keepalives |
| **Exfiltration** | Flow records, proxy logs, Zeek `orig_bytes` | Sustained one-directional volume (orig ≫ resp) to one external destination, often outside business hours | Backups, cloud sync, legitimate large uploads |
| **DNS tunnelling** | `dns.log`, resolver logs | Many unique long subdomains under few domains, `TXT`/`NULL` query types, steady query rate, small upstream flows | CDN and reputation lookups with random-looking labels |
| **Lateral movement** | Zeek `conn.log`/`smb_files.log`/`ntlm.log`, flow records | One internal host to many internal hosts on 445/3389/5985/22, often `S0` then `SF`, service-ticket or NTLM identities changing | Vulnerability scanners, patch management, admin jump hosts, backup agents |
| **Internal reconnaissance** | Flow records, `conn.log` | Fan-out to many ports or hosts with short durations and `S0` states | Authorised scanning, monitoring, asset discovery |
| **Staged download** | Proxy logs, `http.log`, `files.log` | Archive or script download to an odd path, from a host that does not normally download | Software deployment, package managers, user downloads |
| **TLS-based C2** | `ssl.log` (SNI, certificate, fingerprint) | Consistent SNI to an unrelated or newly seen domain, self-signed or mismatched certificate, rare TLS fingerprint | Shared CDN hosting, certificate reuse by legitimate SaaS |
| **Egress bypassing the proxy** | Flow records, firewall logs | Direct outbound connections from hosts that should be proxied | Non-proxy-aware software, misconfiguration |

## Common Mistakes & Tips

- **Analysing beaconing without enough connections.** Ten connections cannot establish periodicity. State the minimum sample you used, or the finding is not defensible.
- **Forgetting that sampling kills timing analysis.** Check the flow exporter's sampling rate before computing intervals from flow records.
- **Reading `zeek-cut` output from a stripped file.** It needs the `#fields` header; without it you get column indices, not names, and a silently wrong answer.
- **Treating `S0` as malicious.** One-way state means the connection was not completed — that is scans, blocked egress, and dead hosts, all of which are leads, none of which are verdicts.
- **Ignoring the local-network definition.** Without `Site::local_nets`, Zeek cannot tell "internal" from "external", and every lateral-movement hunt built on that distinction is wrong.
- **Hunting PCAP when metadata would do.** PCAP is expensive to store and slow to search. Start with DNS and flow, then Zeek, and open the packets only to prove a specific claim.
- **Assuming the proxy is the network.** Traffic that bypasses the proxy is invisible in proxy logs. Cross-check flow records for egress you cannot otherwise explain.
- **Attributing an IP to a person.** NAT, DHCP churn, VPN pools, and shared accounts make IP-to-identity a hypothesis until DHCP, authentication, or endpoint logs confirm it.
- **Never validating a negative.** If the sensor dropped traffic, the resolver cached the query, or the exporter sampled 1:1000, "we saw nothing" is a statement about the sensor, not the attacker.
- **Capturing networks you do not own.** Passive monitoring is still monitoring. Only capture traffic on infrastructure you own or have written authorization to observe.

## Checklist / Self-Test

- [ ] I can name the five layers of network evidence and the trade-off each one makes.
- [ ] I ran Zeek over a PCAP and located `conn.log`, `dns.log`, `ssl.log`, and `http.log`.
- [ ] I can name three `conn_state` values and what each one tells a hunter.
- [ ] I computed inter-arrival deltas for a conversation from `conn.log` and can say what jitter value would make me suspicious.
- [ ] I extracted SNI, HTTP host, and DNS names from a capture with `tshark -T fields`.
- [ ] I produced a top-talkers-by-bytes list from flow records and can explain why flow data has no hostnames.
- [ ] I can state what a `CONNECT` line in a proxy log hides, and which source compensates for it.
- [ ] I can describe the difference between DNS tunnelling and DNS beaconing using query-name statistics.
- [ ] I ran RITA over a Zeek log set and explained one high-scoring beacon as benign or suspicious using its modifiers.
- [ ] I can name the confounder for each of the four network behaviours in section 9.
- [ ] Every capture and log I analysed came from infrastructure I own or am authorized to monitor.

## Further Resources

- Zeek documentation, log reference, and script reference — docs.zeek.org.
- Wireshark display filter reference and tshark manual — wireshark.org/docs.
- nfdump / nfcapd — github.com/phaag/nfdump; softflowd — github.com/irino/softflowd.
- RITA (Active Countermeasures) — github.com/activecountermeasures/rita (see the project page for the current release and backend requirements).
- MITRE ATT&CK techniques for C2, exfiltration, and lateral movement — attack.mitre.org (the vocabulary for writing these hypotheses).
- Official eCTHP page on the INE website for current, authoritative details about the certification.
