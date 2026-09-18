# Enrichment and Threat-Intelligence Tools — MISP, VirusTotal, Shodan

> eSOC · Tools — INE-Cybersecurity-Certifications-Guide
>
> The lookups a tier-1 analyst performs dozens of times a shift, what each one can and cannot prove, and how to keep them from producing confident nonsense. The *reasoning* behind enrichment — confidence, freshness, provenance, and when not to enrich at all — is in `../methodology/06-threat-intel-and-enrichment.md`. This file is the tool-side companion: what each service is, what it returns, how it is queried, where it lies to you, and what to do when it fails.
>
> **No lookup in this file was performed while writing it.** The API shapes below come from each project's published documentation; they are written for you to run against your own lab and your own indicators. Rate limits and endpoint details change — confirm them in the vendor documentation for the version and plan you have.

## 1. The Toolkit at a Glance

| Tool | The question it answers | What makes it weak |
|---|---|---|
| **MISP** | "Has anyone in my sharing community seen this, and in what campaign?" | Coverage depends on your community's submissions; an empty result means nobody shared it, not that it is clean |
| **VirusTotal** | "Has this file, address, or URL been analysed by many engines before?" | Unknown samples are clean by definition; results are advisory and shared-host noise is common |
| **Shodan** | "What is this address exposed as, and what has been seen on it?" | It is an exposure index, not a reputation verdict; data can be weeks old |
| **AbuseIPDB / blocklist-style reputation** | "Is this address reported for abuse by others?" | Reports are unverified and can be retaliatory; shared infrastructure dominates |
| **RDAP / WHOIS and passive DNS** | "How old is this domain, who registered it, and what has it resolved to?" | Privacy services hide ownership; passive DNS coverage varies by resolver |
| **Your own SIEM history** | "Have I seen this entity before, and in what context?" | The most under-used tool on the list, and the most relevant — it describes *your* environment |

Two rules that apply to all of them: **an indicator lookup is a prior, not a verdict**, and **the most valuable answer is often "no history", not "found it"**.

## 2. MISP

**What it is.** An open-source threat-intelligence platform for storing, correlating, and sharing indicators with a defined community. A tier-1 analyst usually meets it as a *consumer* (searching during triage) and grows into a contributor (pushing confirmed indicators back with an event).

**What it produces.** Events (a bundle of related intelligence with a distribution level), attributes (individual indicators with a category and type), automatic correlations between events that share attributes, taxonomies and galaxies (malware families, threat actors, confidence levels), warning lists (known-good infrastructure), and feeds that keep the instance current.

**How to use it.** The two things an analyst does most: search an attribute, and read the event behind a match.

```bash
# Search an attribute (MISP 2.4-style REST API). Shape to adapt - NOT EXECUTED here.
# Auth is an API key; the Accept header matters, since the default is HTML.
curl -s -X POST "https://misp.example.org/attributes/restSearch" \
  -H "Authorization: <YOUR_MISP_API_KEY>" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"value": "203.0.113.77", "type": "ip-dst", "to_ids": true, "last": "90d"}'
```

```python
# The same search with PyMISP, the official Python client (shape to adapt, not run here)
from pymisp import PyMISP
misp = PyMISP("https://misp.example.org", "<YOUR_MISP_API_KEY>", ssl=True)
result = misp.search(controller="attributes", value="203.0.113.77", type_attribute="ip-dst", to_ids=True, last="90d")
for attribute in result.get("Attribute", []):
    # the event id is what gives the indicator its context
    print(attribute["event_id"], attribute["type"], attribute["value"], attribute.get("timestamp"))
```

**Limitations.**

- **Absence proves nothing.** MISP stores what its community shared. A targeted, private intrusion will not be there.
- **`to_ids` is a flag, not a permission.** It marks attributes considered suitable for automated detection; most attributes are context-only, and an API search should filter on it when you intend to act automatically.
- **Warning lists exist because feeds are full of known-good infrastructure.** Cloud providers, CDNs, scanners, and mail relays appear constantly. Check the warning-list verdict before escalating on a hit.
- **Distribution levels constrain what you can say.** An attribute shared to a limited group does not belong in a broad report.
- **Timestamps are epoch seconds** in the API, so convert before you quote a date in a note.

**Diagnostics.**

| Symptom | Likely cause | Check |
|---|---|---|
| Empty result for an indicator you know is there | Wrong attribute type, or `to_ids` filter excluding it | Search by value alone, without type or flag filters |
| HTML returned instead of JSON | Missing or wrong `Accept: application/json` header | Add the header; MISP defaults to an HTML view |
| 403 on a search | API key lacks permission for that sharing group, or the key is disabled | Ask the MISP administrator; permissions are per-user |
| The event is there but its attributes are not visible | Distribution restriction | Use the event's own page with your account, not the raw API |
| Correlations look wrong | Two unrelated events share a common indicator such as a popular domain | Read the correlation in context; overlapping indicators are not overlapping campaigns |

## 3. VirusTotal

**What it is.** A multi-engine file, URL, domain, and IP analysis service. Uploading a file or submitting a URL runs it through many engines; previously seen objects have stored results, which is what makes it fast during triage.

**What it produces.** Per-engine verdicts, detection names per vendor, file metadata (type, size, signature, embedded names), first-seen/submission dates, and relations — the domains and addresses an object has been observed contacting, which is often the most useful part.

**How to use it.** The v3 API is object-oriented: one endpoint per object type, with an identifier.

```bash
# File lookup by hash. The id is the hash (SHA-256 recommended). NOT EXECUTED here.
curl -s "https://www.virustotal.com/api/v3/files/<SHA256_HASH>" \
  -H "x-apikey: <YOUR_VT_API_KEY>"

# Address and domain lookups use the same pattern
curl -s "https://www.virustotal.com/api/v3/ip_addresses/203.0.113.77" -H "x-apikey: <YOUR_VT_API_KEY>"
curl -s "https://www.virustotal.com/api/v3/domains/example.com"        -H "x-apikey: <YOUR_VT_API_KEY>"

# URL lookups need the URL encoded as base64url without padding, then used as the id
```

**Reading the result, in the order that matters:**

1. **The verdict counts are the least useful number on the page.** A fresh sample is 0/70 because nobody has seen it.
2. **Submission and first-seen dates** tell you whether the object is new (so nobody could have flagged it) or long-standing.
3. **Detection names cluster by family.** Ten engines naming the same family is a strong signal; one engine naming a "generic" or "suspicious" pattern is weak.
4. **Relations are pivots.** The contacted domains and addresses extend your scoping beyond the alert's entities.
5. **Signature and metadata** let you spot masquerading: a binary claiming to be a signed vendor product while unsigned, or carrying an internal original filename that does not match its path.

**Limitations.**

- **Unknown is not clean.** State it exactly that way in your notes: "no external corroboration" rather than "clean".
- **Shared infrastructure dominates.** A CDN address will show detections because *someone* hosted something malicious behind it.
- **Uploading is a disclosure decision.** Submitting an internal document, an internal-only binary, or a raw log publishes your incident to whoever is watching that service. Corporate policy usually requires an internal alternative; ask before you upload anything from work.
- **The public API is heavily rate-limited.** The free tier allows only a few requests per minute and a few hundred per day, and the limits are published in the API documentation — check them for your account rather than assuming.

**Diagnostics.**

| Symptom | Likely cause | Check |
|---|---|---|
| `HTTP 404` for a hash | The object has never been submitted | That is a finding, not an error — record "never submitted" |
| `HTTP 429` / rate-limit error | Free-tier limits exceeded | Batch your lookups; avoid enriching dozens of indicators by hand mid-triage |
| `HTTP 401` / 403 | Missing, wrong, or unauthorised API key | Confirm the header name (`x-apikey`) and that the key has the API product enabled |
| An internal-only hash returns nothing | Nobody can submit what only you have | Decide the disclosure question first, then upload or use an on-premises sandbox |
| An address returns a large CDN's data | The address is shared hosting | Pivot to the hostname or to the TLS certificate instead of the IP |

## 4. Shodan

**What it is.** A search index of internet-facing services, built by continuously scanning the public address space. It answers "what is this address exposed as?" rather than "is this address malicious?".

**What it produces.** Open ports and banners, product and version guesses, TLS certificate details (including subject names, which link addresses to hostnames), historical exposure, and reverse-DNS and hostname data.

**How to use it.** Two shapes: a single-host lookup with an API key, and search filters in the web interface or via the search endpoint.

```bash
# Single host: exposure and banner data. NOT EXECUTED here.
curl -s "https://api.shodan.io/shodan/host/203.0.113.77?key=<YOUR_SHODAN_API_KEY>"

# Domain DNS data (subdomains, records) - a different endpoint with different credit cost
curl -s "https://api.shodan.io/dns/domain/example.com?key=<YOUR_SHODAN_API_KEY>"
```

Useful search filters in the web interface: `ip:`, `net:` (a CIDR), `org:`, `hostname:`, `ssl.cert.subject.cn:`, `http.title:`, and `port:`. The last one is how you answer "how many of our assets expose an RDP or database port?" without scanning anything yourself.

**Limitations.**

- **It is an exposure index, not a reputation service.** An address with a known open port tells you nothing about intent.
- **Data can be weeks old.** Scanning is periodic; treat the result as a snapshot with a date, not as live state.
- **Scanning back is a different activity.** Shodan reads *someone else's* scan data. Actively scanning an address yourself is an authorized-testing decision, not a triage step.
- **Credits are consumed by host lookups on paid plans.** Check your plan before enriching twenty addresses by hand.

**Diagnostics.**

| Symptom | Likely cause | Check |
|---|---|---|
| `No information available` for an address | The address has never been scanned, or the service only indexes what responded | Treat as "no data", not as "nothing is exposed" |
| Results look stale | Scan cycle timing | Read the timestamp on each banner before quoting it |
| Address belongs to a hosting provider | Shared tenant | Do not attribute behaviour to the address owner |
| Quota exhausted mid-investigation | Host lookups consume query credits | Prioritise: is this lookup going to change the verdict? |

## 5. Reputation Services and Ownership Lookups

**AbuseIPDB and blocklist-style services.** They aggregate abuse reports and blocklist membership for an address. Use them as a *weak prior*: a heavily reported address raises suspicion, and an address with no reports lowers nothing. Reports are unverified, may be retaliatory, and shared infrastructure produces both false positives and false negatives.

```bash
# AbuseIPDB check, shape to adapt - NOT EXECUTED here
curl -s -G "https://api.abuseipdb.com/api/v2/check" \
  --data-urlencode "ipAddress=203.0.113.77" \
  --data-urlencode "maxAgeInDays=90" \
  -H "Key: <YOUR_ABUSEIPDB_API_KEY>" \
  -H "Accept: application/json"
```

**RDAP and WHOIS.** Registration data answers the question that changes verdicts most often: *how old is this domain?* A domain registered days before the alert, contacted by a scripting host, is a much stronger signal than the same connection to a decade-old corporate site.

```bash
# RDAP is the standardised successor to WHOIS and returns structured JSON
curl -s "https://rdap.org/domain/example.com"
```

Look for: registration date, registrar, registrant country and privacy service, nameservers, and recent status changes. Remember that privacy services hide the registrant, and that a domain's *age* is more informative than its *owner*.

**Private addresses have no public intelligence.** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and IPv6 unique-local addresses will never appear in any of these services. An analyst who spends five minutes enriching `10.20.30.40` in VirusTotal has learned nothing — those addresses must be resolved internally, through asset inventory and DHCP/DNS records.

## 6. Which Lookup Answers Which Question

| Entity in the alert | Lookup | What a useful result looks like | What would change your verdict |
|---|---|---|---|
| File hash | VirusTotal, MISP, internal threat-hunting repository | Family name with multiple engines agreeing; a MISP event with campaign context | A corroborated family match, or a link to a known campaign |
| Destination domain | RDAP age, passive DNS, MISP, Shodan | Registered days ago; changed hosting recently; appears in a campaign event | Recent registration plus C2-shaped traffic |
| Destination IP | MISP, reputation services, Shodan, reverse DNS | Known C2 in a recent feed; a hosting provider with a linked hostname | A corroborated C2 attribution, or a hostname that ties it to the alert |
| Internal host | Your CMDB/asset inventory, EDR console, DHCP/DNS records | Owner, criticality, purpose, whether it is internet-facing | A critical asset or an internet-facing role raises severity immediately |
| User account | Directory, HR context via the proper channel, sign-in logs | Role, department, service-account flag, recent travel | A role that cannot explain the behaviour |
| URL or mail sender | URL analysis, header analysis, MISP, domain age | A redirect chain, a newly registered lookalike domain, a mismatched sender | A credential-harvesting pattern or a spoofed internal sender |

## 7. Diagnostics: When Enrichment Fails

| Situation | What to do |
|---|---|
| No API key available | Say so in the note. "No MISP access at tier 1; escalation should check" is a legitimate, useful record — do not silently skip the check |
| Rate-limited or offline | Continue with the sources you have, and record which lookup was unavailable so the next analyst can complete it |
| Lookup returns a huge "malicious" count for a shared address | Pivot to the hostname, the certificate, or the URI pattern; the address alone is unusable as evidence |
| Lookup contradicts your own telemetry | Say both. "Feed says C2; our own 90-day history shows this address serving a partner API" is a finding, not a conflict to resolve silently |
| Everything says clean and the behaviour is alarming | Trust the behaviour. External reputation is a prior; unexplained execution, persistence, or beacon-shaped egress outrank it |
| Time is being consumed by lookups | Apply the test from `../methodology/06-threat-intel-and-enrichment.md`: name, before the lookup, the outcome that would change your decision. If there is none, skip it |

## Common Mistakes & Tips

- **Mistake:** treating "no detections" as "clean". *Tip:* write "no external corroboration"; a targeted sample is unknown by construction.
- **Mistake:** enriching private RFC 1918 addresses on public services. *Tip:* no public source can know them; resolve internal addresses through your own inventory.
- **Mistake:** escalating on a feed hit without a warning-list check. *Tip:* CDNs, cloud ranges and scanners live in feeds permanently.
- **Mistake:** uploading internal artefacts to a public multi-scanner during triage. *Tip:* that is a disclosure of your incident; check policy and prefer an on-premises sandbox.
- **Mistake:** reading only the detection ratio and missing the dates. *Tip:* first-seen and submission dates decide whether the absence of detections is meaningful.
- **Mistake:** losing the lookup results because the note says "VT: bad". *Tip:* record the object queried, the date, the specific result, and the conclusion you drew — including the negatives.
- **Mistake:** burning the free-tier quota on indicators that could not change the verdict. *Tip:* prioritise by decision impact, then batch lookups instead of doing them one by one under pressure.

## Checklist / Self-Test

- [ ] I can name what MISP adds that a public multi-scanner cannot.
- [ ] I know what `to_ids` means, and I check warning lists before escalating on a feed hit.
- [ ] I can search an attribute in MISP by API or with PyMISP, and read the event behind a match.
- [ ] I can explain why a 0-detection result on a three-day-old file is not evidence of benign.
- [ ] I know which of my lookups disclose internal data, and what my policy says about them.
- [ ] I can check domain age, and I can say why age matters more than registrant.
- [ ] I can pivot from an address to a hostname or certificate instead of escalating on shared hosting.
- [ ] I recognise that private addresses have no public intelligence and know where to resolve them internally.
- [ ] I record negative results, dates, and source names in the case note.
- [ ] I know my free-tier rate limits, and I batch lookups instead of exhausting them mid-triage.

## Further Resources

- MISP Project — documentation, data model, and REST API reference: https://www.misp-project.org/documentation/
- MISP — warning lists and their purpose: https://www.misp-project.org/warninglists/
- PyMISP — official Python client: https://github.com/MISP/PyMISP
- VirusTotal — API v3 reference (endpoints, identifiers, rate limits): https://docs.virustotal.com/reference/overview
- Shodan — API documentation and search filters: https://developer.shodan.io/api
- AbuseIPDB — API documentation: https://docs.abuseipdb.com/
- RDAP — registration data for domains and IP ranges: https://rdap.org/
- FIRST — Traffic Light Protocol (TLP), for sharing indicators at the right level: https://www.first.org/tlp/
