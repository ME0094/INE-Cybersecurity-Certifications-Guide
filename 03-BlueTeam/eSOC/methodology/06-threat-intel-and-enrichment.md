# eSOC Methodology — Phase 6: Threat Intelligence in Triage

> Tier-1 SOC Analyst focus · INE-Cybersecurity-Certifications-Guide
>
> Threat intelligence is only useful to a tier-1 analyst at the moment it changes a decision. This phase covers the difference between data, reputation, and intelligence; how to judge an indicator instead of collecting one; how MISP fits the analyst workflow; which lookups actually move a verdict; and when enriching does more harm than good. The generic lookup list lives in `03-investigation.md` — this file is about using the results honestly.

## 1. Data, Reputation, Intelligence: Three Different Things

The words get used interchangeably in SOCs, and the confusion produces confidently wrong verdicts.

| Term | What it is | Example | What it can support |
|---|---|---|---|
| **Data** | Raw observations, unjudged | A log line showing `203.0.113.77` connected to port 443 | Nothing on its own; it is the input to everything else |
| **Reputation** | A score or count from a service or feed | "7 of 90 engines flag this hash"; "this IP appears on 3 blocklists" | A weak prior. Reputation tells you what *others* concluded, with unknown method and unknown age |
| **Intelligence** | Data plus context, analysis, and an assessment of relevance to *you* | "This infrastructure has been used since March against finance-sector targets in this region; the actor rotates domains weekly, so treat the domain as perishable and the TLS certificate as the durable pivot" | A decision input: it tells you where to look next and how long an indicator stays useful |

The practical consequence: **a reputation lookup is not a verdict.** "VirusTotal says clean" means nobody has uploaded it or nobody has flagged it yet, which is exactly the situation for a fresh, targeted implant. "VirusTotal says 3/70" in a two-week-old sample is ambiguous. Neither number replaces looking at the behaviour.

## 2. IOC vs TTP, and Why It Changes Your Triage

The pyramid of pain describes how much it costs an adversary to change what you detect. For a triage analyst the pyramid is not theory; it decides which questions are worth asking.

| Layer | Example | Cost for the adversary to change | What it does to your verdict |
|---|---|---|---|
| Hash | SHA-256 of the dropper | Recompile — seconds | Confirms identity of *this* file only; a miss proves nothing |
| IP address | C2 address `203.0.113.77` | Update config — minutes | Useful for scoping a host or a campaign window; shared hosting makes it noisy |
| Domain / URI pattern | `updates-<word>.example` | Re-register — hours | Better pivot: one pattern often covers many samples |
| Network / host artefact | Named pipe, mutex, registry key, user-agent string | Re-engineer — days | Strong detection candidate, survives most rebuilds |
| Tool | A specific loader or post-exploitation framework | Replace tooling — weeks | Confirms family and likely capability; informs severity |
| **TTP** | "Uses signed-binary proxy execution after a macro" | Retrain, redesign — months | The only layer that keeps working after the sample changes; drives the *detection*, not just the verdict |

Applied to triage:

- **An IOC match is a lead to confirm, not a conclusion.** If a hash matches a known tool, ask what the tool did on this host — the indicator tells you *which* file, the behaviour tells you *what happened*.
- **An IOC miss is not evidence of innocence.** A new sample of a known family, or a custom build, has no prior reputation by construction. This is the single most common reasoning error in tier-1 triage.
- **Prefer the behaviour when you escalate.** "Encoded PowerShell from Word, followed by a connection to a fresh domain" survives the attacker changing the domain; "hash matched a report" does not.

## 3. What Each Type of Intelligence Can Support

Not every intel product answers a tier-1 question. Knowing which ones do keeps you from reading a strategic report when you needed a lookup.

| Type | Time horizon | Typical consumer | What tier 1 can do with it |
|---|---|---|---|
| **Strategic** | Months–years | Leadership, risk owners | Understand the threat picture; almost never changes a single triage verdict |
| **Operational** | Weeks–months | Detection engineers, IR | Campaign context, targeting logic, which techniques to expect next |
| **Tactical** | Days–weeks | Detection engineers | TTP-level detection requirements — the most valuable input to a use case |
| **Technical** | Hours–days | Tier 1 and tier 2 analysts | Indicators for enrichment, blocking, and scoping — perishable, so use fast and expire them |

Technical indicators decay. An IP that hosted C2 six months ago is a hosting provider's recycled address today; a domain from a 2023 campaign is usually sinkholed or re-registered. Write an expiry into anything you take from a feed, and re-check before you act on an old indicator during an incident.

## 4. Judging an Indicator: Confidence, Freshness, Provenance

When four sources disagree about the same IP, the answer is not the average. Weigh the three properties that actually predict usefulness.

| Property | Strong | Weak | Why it matters |
|---|---|---|---|
| **Provenance** | A vendor with a stated method; your own incident; a national CERT; a sector ISAC | An anonymous blocklist; a single aggregation site; a scraped feed | You need to know how the conclusion was reached to reuse it |
| **Freshness** | Observed in the last days or weeks for technical indicators | Undated, or older than the campaign it describes | Infrastructure is rented and recycled |
| **Specificity** | A C2 endpoint with a matching JA3 or URI pattern | A shared CDN address, a public cloud range, a common domain | Broad indicators produce false positives and mislead scope |
| **Corroboration** | Two independent sources, or one source plus your own telemetry | One source only | One source is a lead; two agreeing sources are evidence |
| **Direction** | Applies to an entity in your alert (the actual destination, the actual hash) | Applies to a "similar" entity | Enrichment must answer a question about *this* case |

Two traps are worth naming explicitly:

- **Warning lists exist for a reason.** Public indicator collections are full of cloud providers, CDNs, mail infrastructure and popular domains, because somebody once saw malicious traffic to them. Any responsible platform (MISP is the standard example) ships warning lists precisely to stop analysts treating `1.1.1.1` as a C2. Check the warning list verdict before you escalate on a feed hit.
- **Geography is not behaviour.** "Logon from a country the user has never visited" is a hypothesis, not a finding. VPNs, cloud egress, mobile roaming, and corporate proxies all produce surprising geolocation. It becomes evidence when it correlates with something else — a failed-logon burst, a new user agent, a session from an unusual ASN for that account.

## 5. MISP in the Analyst Workflow

MISP (Malware Information Sharing Platform) is the most widely deployed open-source threat-intelligence platform, and a tier-1 analyst usually meets it as a *consumer* first and a *contributor* later.

| MISP concept | What it holds | How a tier-1 analyst uses it |
|---|---|---|
| **Event** | A bundle of related intelligence about one incident, campaign, or report, with a distribution level | Read the event behind an indicator to get context: what campaign, what targeting, what else is related |
| **Attribute** | One indicator: an IP, domain, hash, filename, mutex, URI, email subject | Enrich an alert entity; the attribute carries a category, a type, and metadata |
| **`to_ids`** | A per-attribute flag meaning "this is suitable for automated detection" | Only escalate on automated matching when `to_ids` is set — the flag exists to keep context-only values out of blocking rules |
| **Correlation** | Automatic links between events that share attributes | The fastest way to see whether an indicator is part of a larger campaign or a false-positive cluster |
| **Taxonomies and galaxies** | Structured vocabularies and threat-actor/malware knowledge | Adds standard tags (malware family, actor, confidence) instead of free-text guesses |
| **Warning lists** | Known-good infrastructure that appears in feeds | The check that stops a cloud-provider IP being reported as malicious |
| **Feeds** | Subscriptions that keep the instance current | Explains why an indicator is there and how old it is |
| **Sharing groups / distribution** | Who may see an event | Determines whether you can quote an indicator in a report or an external communication |

Enrichment flow in practice, in words rather than in a script — the exact API form depends on your instance and version:

1. **Search by the entity you already have** (the destination IP, the file hash, the domain) and record the event IDs you matched.
2. **Read the event, not just the hit.** An attribute with no event context is a string; the event tells you the campaign, the target sector, the date, and the source report.
3. **Check `to_ids` and the warning list state.** Automated-actionable and known-good are two different questions, and both matter before you escalate.
4. **Pivot within MISP** to related attributes — an IP that shares a TLS certificate or a URI pattern with your alert is far more interesting than the IP alone.
5. **Give back what you learn.** A confirmed malicious indicator from your incident, contributed with an event and a reference, is what makes the next analyst's triage faster. Do not push unverified guesses: one bad attribute pollutes every instance that consumes it.

> Two handling rules that are easy to forget under pressure. First, **respect the distribution level** — an indicator marked for a limited sharing group does not belong in a broad report. Second, **do not enrich with internal data on public services.** Submitting an internal hostname, an unhashed internal path, or a private document to a public multi-scanner publishes your incident to whoever is watching that service. Where that matters, use an on-premises instance instead.

## 6. Enrichment That Changes a Decision

Enrichment earns its cost only when a plausible outcome would change what you do next. The table below is the test to apply *before* the lookup.

| Lookup | Plausible outcomes | What each outcome changes |
|---|---|---|
| File hash in a multi-scanner and in MISP | Known family / unknown / internal-only file | Known family → escalate with family context and hunt for the same hash elsewhere. Unknown → no reduction in suspicion; behaviour decides. Internal build artefact → close as benign with the owner's confirmation |
| Destination IP or domain: reputation, WHOIS, passive DNS | Long-established corporate service / recently registered / hosting or CDN range | Recently registered + contacted by a scripting host → strong signal, escalate. CDN range → weakens the geo/reputation signal, pivot to the hostname or TLS certificate instead |
| Asset criticality and owner lookup | Domain controller, finance server, developer laptop, decommissioned host | Changes severity immediately, and decides whether containment needs approval from a business owner |
| User context: role, department, recent travel, service account flag | Matches the activity / contradicts it | Contradiction between role and behaviour is the correlation that turns two weak signals into an escalation |
| Historical sightings in your own SIEM (last 90 days) | First sighting / recurring pattern / part of a known approved job | First sighting raises suspicion; a recurring pattern with an approved change record lowers it |
| Internal vulnerability or exposure data for the destination host | Internet-facing, unpatched, or already flagged | Raises the impact assessment and can justify escalation on its own |

By contrast, these lookups rarely change a tier-1 verdict and mostly consume time: broad "threat level" pages with no per-indicator data, SOC-level news with no targeting relevance, and any source that returns a score without telling you what it means.

## 7. Writing Intelligence Into the Note

The value of enrichment is destroyed by how it is usually recorded. Compare:

| Weak record | Why it fails |
|---|---|
| "VT: 3/70 malicious." | No engine names, no age, no meaning assigned |
| "IP is bad." | Unfalsifiable; nobody can check or reuse it |
| "Saw it in MISP." | No event ID, no date, no distribution context |

| Strong record | Why it works |
|---|---|
| "Destination `203.0.113.77` is not in MISP; passive DNS shows the domain was registered 2025-05-28 (4 days before the alert); the hostname resolves only to this address and has no prior history in our SIEM in 90 days. Not corroborated by external intel, so the escalation rests on behaviour: Word → script host → beacon-shaped egress." | States what was checked, what was found, what was *not* found, and explicitly says which evidence carries the verdict |

The habit to build: **record the negative results.** "No MISP match" and "no historical sighting" are findings — they tell the next analyst which questions are still open, and they prevent the same lookups being repeated at the next escalation.

## 8. Worked Example: When a Clean Reputation Means Nothing

An alert fires for an executable launched from a user's downloads folder. The file hash returns no detections from any engine and is absent from MISP.

**The wrong conclusion:** "Not detected by anyone, so it is clean. Close."

**The reasoning that holds:**

1. **Provenance of the file.** Where did it come from — a mail attachment, a web download, a USB device? File telemetry usually answers this, and the answer carries more weight than the scanner result.
2. **Behaviour after launch.** Child processes, network connections, file writes, registry writes, scheduled tasks. This is the evidence that decides the case; a clean scanner result does not explain a new persistence entry.
3. **Internal consistency.** Does the binary's metadata match what it claims to be (publisher, original filename, path)? Masquerading is common and visible.
4. **Absence of evidence, examined.** Is the file *new* (so nobody could have flagged it) or is it genuinely a long-standing, widely distributed legitimate program? Zero detections on a three-day-old file means nothing; zero detections on a signed vendor installer means something.
5. **Decision.** With no external corroboration, the verdict must come from behaviour — escalate if the behaviour is unexplained, close only if the full chain (origin + behaviour + owner confirmation) is benign.

The general rule: **intelligence raises or lowers suspicion; behaviour determines the verdict.** An analyst who escalates only on feed hits will miss every targeted attack, because targeted attacks are precisely the ones with no prior reputation.

## Common Mistakes & Tips

- **Mistake:** treating "not found in any feed" as evidence of benign. *Tip:* a fresh, custom, or targeted sample is absent from feeds by definition; say "no external corroboration" and decide on behaviour.
- **Mistake:** escalating on a feed hit without checking the warning list. *Tip:* cloud providers, CDNs and mail infrastructure are permanently overrepresented in feeds.
- **Mistake:** averaging sources that disagree. *Tip:* weigh provenance, freshness, and specificity; two strong signals beat ten scraped ones, and a single unnamed blocklist beats nothing.
- **Mistake:** enriching an internal artefact on a public service. *Tip:* publishing your incident to a multi-scanner is a disclosure; use an on-premises instance when confidentiality matters.
- **Mistake:** recording only the hits. *Tip:* "checked X, found nothing, in MISP event 12345" is a finding; write the negatives down so nobody repeats the lookup.
- **Mistake:** quoting indicators outside their sharing group. *Tip:* check the distribution level before an indicator goes into a report, a ticket, or a chat channel.
- **Mistake:** keeping an indicator past its useful life. *Tip:* technical indicators expire — infrastructure is rented and recycled; date the indicator and re-check before acting on it months later.

## Checklist / Self-Test

- [ ] I can explain the difference between data, reputation, and intelligence, and give an example of each.
- [ ] I can place an indicator on the pyramid of pain and say how long it stays useful.
- [ ] I can name the three properties I weigh when sources disagree about an indicator.
- [ ] I know what `to_ids` means in MISP and why it exists.
- [ ] I can check a warning list before escalating on a feed hit.
- [ ] I can state, before a lookup, which outcome would change my verdict — and skip the lookup if none would.
- [ ] My triage notes record the negative results of enrichment, not only the hits.
- [ ] I can explain why a clean multi-scanner result does not make a three-day-old binary benign.
- [ ] I know which of my lookups disclose internal data, and where I must use an on-premises service instead.
- [ ] I can hand a confirmed, referenced indicator back to MISP without pushing unverified guesses.

## Further Resources

- MISP Project — platform documentation, data model, and API reference: https://www.misp-project.org/documentation/
- MISP — warning lists and their role in avoiding false positives (maintained list set): https://misp.github.io/misp-warninglists/
- MITRE ATT&CK — technique-level (tactical) intelligence and its data sources: https://attack.mitre.org
- MITRE D3FEND — knowledge graph of defensive countermeasures, useful when naming the control a finding implicates: https://d3fend.mitre.org/
- VirusTotal — public API documentation (rate limits and usage terms apply): https://docs.virustotal.com/reference/overview
- Shodan — API documentation for exposure and infrastructure context: https://developer.shodan.io/api
- FIRST — Traffic Light Protocol (TLP) guidance for sharing indicators safely: https://www.first.org/tlp/
- CISA — public threat intelligence and advisories: https://www.cisa.gov/resources-tools
