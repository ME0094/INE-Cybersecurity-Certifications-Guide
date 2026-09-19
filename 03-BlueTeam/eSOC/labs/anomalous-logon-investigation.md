# Lab — Anomalous Logon Investigation

> eSOC · Labs — INE-Cybersecurity-Certifications-Guide
>
> A logon that succeeds is the hardest alert to argue with, because nothing failed: the credentials were valid, the account exists, and the only thing wrong is that the *where* and the *when* do not fit the account's normal life. This lab works two of those cases — impossible travel, and a successful logon with valid credentials from a source the account has never used — and it walks the correlation across `4624`, `4625`, `4648` and `4672` that turns "this looks odd" into a decision you can defend, escalate, or close with a reason.
>
> **Nothing here is captured output.** The event excerpts, timelines and arithmetic are constructed illustrations of the shape to expect — no SIEM, directory or event log was consulted while writing this note, and none of the commands was executed. Every query below is a shape to adapt to your own field names and run in your own lab; the real output is what you generate.

## The Two Alerts This Lab Uses

Both are single-account, single-source alerts, and both arrive with the same dangerous property: **there is no failed authentication to point at.**

```text
ALERT A - Impossible travel
  Account:   CORP\j.doe
  Observed:  success from 198.51.100.9 (country A) at 09:14 UTC
             success from 203.0.113.77 (country B) at 09:31 UTC
  Claim:     the two locations are ~8 000 km apart; no scheduled travel
  Source:    IdP / VPN / DC authentication logs

ALERT B - Successful logon with valid credentials, new source
  Account:   CORP\s.backup   (service account, interactive logon right)
  Observed:  4624 type 10 (RemoteInteractive) from 192.0.2.44, first time in 180 days
             4672 immediately after, special privileges assigned
  Claim:     a service account logged on interactively from a workstation subnet
  Source:    Windows Security log on the destination host
```

Read together, they are the two shapes an analyst meets most often: a *pattern* anomaly (the same account in two places) and an *attribute* anomaly (a logon that is legitimate in isolation but wrong for this account). The methods below apply to both.

## What "Anomalous" Means Here

An anomaly is a deviation from a baseline, and the baseline is the part that has to be established before the alert means anything.

| Term | What it is | What it is not |
|---|---|---|
| Baseline | What this account, from which sources, at which hours, has actually done over a defined period | A policy statement about what the account *should* do |
| Anomaly | A logon that the baseline does not explain | Evidence of compromise — most anomalies are infrastructure |
| Violation | A logon that breaks a stated rule (a service account used interactively, a shared credential) | Automatically an incident either — but always a finding worth recording |
| Compromise | An anomaly or violation explained by an actor using the account without the owner's intent | Something you can conclude from one event, at any confidence, without scope |

The discipline this lab teaches: **name the baseline, then name what the alert broke.** "A service account logged on interactively" is only meaningful next to "this account has performed 412 logons in 180 days, all type 5 (service), all from the same two hosts".

## Before You Start

- **An isolated Windows VM you own**, snapshotted before each drill. `../labs/soc-scenarios.md` has the lab blueprint and the safety rules; this lab assumes the same environment.
- **Auditing that actually produces the events you need.** Logon/logoff auditing covers `4624`, `4625` and `4648` (*Audit Logon*), plus `4634`/`4647` for the logoff end of a session (*Audit Logoff*); *Audit Special Logon* produces `4672`. If a domain controller feeds your SIEM, add *Audit Kerberos Authentication Service* (`4768`, `4771`) and *Audit Kerberos Service Ticket Operations* (`4769`), which are what make the Kerberos half of the story visible. `../methodology/01-monitoring.md` shows how to prove each channel is switched on instead of assuming it.
- **A second source of authentication telemetry** if you can: a domain controller feeding the SIEM, a VPN concentrator, or a cloud IdP. Impossible travel is far more interesting when two independent systems disagree about where an account is.
- **A SIEM ingesting those channels**, and an asset/user context source (inventory, CMDB, directory) — enrichment is what turns an address into "the corporate VPN pool" or "a hosting provider". `../tools/enrichment-and-ti-tools.md` covers the lookups.

> ⚠️ **Lab rules.** Generate only the events described below, on machines you own, with disposable credentials. Attempting to log on to systems you do not control — even with a wrong password — is not a lab exercise.

## Generating the Events Safely

You do not need an attacker to produce every shape in this lab. The table maps a harmless action to the telemetry it should generate; **what to expect** describes the event, not captured output, so confirm each row against your own logs.

| Harmless action in the lab | Event to look for | What it demonstrates |
|---|---|---|
| Six bad passwords for a lab account from a **second** lab host | `4625` x6, with `SubStatus` for a bad password | The failure half of the story, and the source address it carries |
| One correct logon for that account from the same second host | `4624` with `LogonType` 3 (network) and the source address | The failure-then-success sequence, and the logon type that names the delivery channel |
| An RDP session into the target VM from the second host | `4624` with `LogonType` 10 (RemoteInteractive) | A remote interactive logon — the shape Alert B describes |
| `runas /netonly` or a process started with explicit credentials | `4648` on the **source** host, naming the target account and target server | Credentials supplied explicitly, rather than inherited from the session |
| An interactive logon by an account with admin rights in the lab | `4672` immediately after the `4624` | Special privileges assigned to a new logon — and how noisy it is (`SYSTEM` and service logons produce it too) |
| Log off and log back on to the snapshot-restored VM with no network path to the DC | `4624` with `LogonType` 11 (cached credentials) | Why a logon can appear to come from nowhere, and why the source address may mislead |

Two notes that matter for fidelity. First, `4648` is logged on the machine where the credentials are *used to reach somewhere else*, so look for it on the source host, not the destination. Second, `4672` is not an anomaly by itself: it fires for any logon holding administrative privileges, including many machine and service accounts, which is why the useful question is never "did `4672` fire?" but "did it fire for *this* account, at *this* moment, after *this* logon?".

## The Four Events You Will Correlate

| Event | What it records | Fields that carry the investigation | The trap in it |
|---|---|---|---|
| `4625` — failed logon | An authentication attempt that did not succeed | `TargetUserName`, `IpAddress`, `WorkstationName`, `LogonType`, `SubStatus`, `AuthenticationPackageName` | `SubStatus` separates a mistyped password from a locked or disabled account, and its codes are worth confirming in Microsoft's documentation rather than memorising |
| `4624` — successful logon | An authentication that succeeded | `TargetUserName`, `LogonType`, `IpAddress`, `WorkstationName`, `LogonProcessName`, `AuthenticationPackageName`, `TargetLogonId`, `ElevatedToken` | `LogonType` decides what the event means: 2 console, 3 network, 7 unlock, 9 new credentials, 10 RDP, 11 cached. Interactive logons often carry no useful `IpAddress` at all |
| `4648` — logon with explicit credentials | Credentials were supplied explicitly to reach another resource | `SubjectUserName` (who ran it), `TargetUserName` (whose credentials), `TargetServerName`, `TargetInfo` | It is generated routinely by scheduled tasks, service accounts and administrative tooling, so it is a lead about *how* credentials moved, never proof of theft |
| `4672` — special privileges assigned | A new logon session holding administrative privileges | `SubjectUserName`, `SubjectLogonId`, privilege list | It fires constantly for machine accounts; value comes only from its correlation with an unusual `4624` |

Two more sources complete the picture when you have them: Kerberos events (`4768` TGT requested, `4769` service ticket, `4771` pre-authentication failed) on a domain controller, and `4776` for NTLM credential validation. Their absence is itself worth recording — a lab without a domain controller will never show the Kerberos half of this story.

The join that makes the four events one story is the **logon session**. The `TargetLogonId` in a `4624` can be followed into later process-creation events, where the subject logon id attributes a process to the session that started it. That is how "the account logged on" becomes "the account logged on **and then** started these processes".

## Step 1 — Validate the Raw Events

Before building any theory, confirm the alert is not a ghost. `../methodology/03-investigation.md` treats this as the first gate for good reason: alerts derived from stale indexes, renamed fields or a broken parser cost more analyst time than any real intrusion.

- Find the **raw events** the alert claims to have matched, by account and by time window, and read them rather than the alert summary.
- Check the fields you will reason with are populated: an `IpAddress` of `-` or `::1`, a missing `WorkstationName`, or a `LogonType` your rule misread will send the whole investigation in the wrong direction.
- If the events do not exist, stop and fix the rule. Document that you did: a ghost alert closed as "false positive" without the parser defect recorded is a ghost you will meet again next shift.

## Step 2 — Build the Account's Baseline

The alert's meaning depends on what this account normally does. Assemble that before deciding anything:

| Question | Where to look | What changes the verdict |
|---|---|---|
| Is the account human, service, or shared? | Directory / CMDB | A service account logging on interactively is a violation; a human logging on from a new city may be a commute |
| Which sources has it used in 30/90/180 days? | SIEM `4624` history for the account | "First time ever" versus "a source it uses every Tuesday" |
| Which logon types dominate? | `LogonType` distribution over the same window | A baseline of type 5 (service) makes one type 10 (RDP) a finding |
| Has it ever authenticated from two places inside a short window? | Time-ordered `4624` list, pivoted by source address | Establishes whether "impossible travel" is new behaviour or an infrastructure artifact |
| Does it hold administrative rights? | Group membership, and `4672` history | Decides whether this is a routine user or a privileged identity |
| Is the source address ours? | Asset inventory, VPN pool range, ASN lookup (`../tools/enrichment-and-ti-tools.md`) | Corporate VPN, hosting provider, consumer ISP and anonymising service are four different findings |
| Has this address touched other accounts? | `4624`/`4625` by source address | One address, many accounts is a materially larger incident |

> ⚖️ **Privacy and proportionality (this step is where it bites).** A per-account behavioural baseline — sources used, hours, travel — is a record about a person, not just about a logon. Build it only with a documented **purpose** (investigating this alert), an **authorization** (policy or named approver, plus any employee-representation agreement), and **proportionality**: use the shortest window the question needs rather than "180 days" by reflex, aggregate by account **role** where a role-level answer suffices, and apply a **retention** limit to whatever you persist. HR, travel and location context is requested through the owner of that data for a specific written question, never pulled speculatively. And the case note carries only evidence: the account's *behaviour* and the fields that prove it — not medical, family, religious, union or private-travel detail, and nothing about accounts that turned out to be unrelated.

## Step 3 — Correlate: Queries and What to Look For

Every query below is a shape to adapt. **Run them and read the rows** — no result is quoted here, and none should be trusted until your own data produces it.

```text
# Kibana KQL - the account's logon history, narrowed to successes, then read in time order.
# What to look for: the first appearance of each source address, and its logon type.
event.category : "authentication" and event.outcome : "success" and user.name : "j.doe"

# Who else authenticated from the address in the alert?
# What to look for: more than one account from one unfamiliar address.
source.ip : "198.51.100.9" and event.category : "authentication"
```

```spl
# Splunk - failures and successes side by side, per account and source, with the sub-status kept.
# What to look for: a burst of failures followed by a success (guessing), versus a success with no
# failures at all (credentials that already worked - the shape that suggests theft, not brute force).
index=windows (EventCode=4624 OR EventCode=4625) earliest=-7d
| stats count(eval(EventCode=4625)) as failures,
        count(eval(EventCode=4624)) as successes,
        values(SubStatus) as substatus,
        values(Logon_Type) as logon_types
        by Account_Name, Source_Network_Address
| sort - successes
```

```kusto
// Sentinel - explicit-credential use and privilege assignment around the alerting logon.
// What to look for: a 4648 naming the account as TargetUserName (credentials used explicitly),
// and a 4672 within seconds of the 4624 (the session that followed held admin rights).
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4624, 4625, 4648, 4672)
| where Account has "s.backup" or TargetAccount has "s.backup"
| project TimeGenerated, EventID, Account, TargetAccount, LogonType,
          IpAddress, WorkstationName, Activity
| order by TimeGenerated asc
```

Then walk the correlation in this order, because each step either narrows or widens the scope:

1. **Same account, which sources?** Order every `4624` by time and mark the first occurrence of each address. That list *is* the impossible-travel finding, or its refutation.
2. **Same source, which accounts?** An address that authenticated as two accounts is a scope that has already doubled.
3. **Failures before the success?** A spray followed by a success is a credential-guessing story. A success with no failures is either a legitimate session or credentials that were obtained elsewhere — which is a different investigation, and a more urgent one.
4. **What did the session do next?** Follow `TargetLogonId` into process creation, file access and network connections. A logon that did nothing is a smaller finding than a logon that created a mailbox rule, installed a service, or opened a share it never touches.
5. **Was privilege involved?** A `4672` on the same logon session moves the alert up the escalation list immediately.
6. **Is there an MFA or IdP record?** If the account is federated, the identity provider's sign-in log is where the authentication actually happened, and the directory event may be a downstream consequence of it.

## Step 4 — Legitimate Use or Compromise?

The two verdicts are decided by evidence, not by how the alert feels. This table is the discriminator set to work through before writing either one.

| Observation | Leans legitimate | Leans compromise |
|---|---|---|
| Source address ownership | Corporate VPN pool, branch egress, or the provider the user reported | Hosting provider, anonymising service, or a residential address in a country the organisation does not operate in |
| Device | Managed, compliant, enrolled, seen before | Unmanaged, unknown device ID, no device record in the IdP |
| MFA | Challenge completed on a registered method, from the same device | Session established with a token that was never challenged, or MFA satisfied by a method the user did not use |
| Failures before the success | A few, matching a human retyping | None — nothing was guessed, so the credential came from somewhere |
| Concurrency | Old session ended before the new one started | Two live sessions from two geographies at once |
| Timing | Inside the account's normal hours, or explained by travel | Outside any plausible hour for that user, with no travel or on-call explanation |
| What followed | Nothing unusual; the same applications as always | New mailbox rule, new OAuth consent, new service registration, share enumeration, or lateral logons |
| Privilege | No `4672`, or one consistent with the account's normal role | `4672` on a logon from a source the account has never used |
| Account type | Human account with a plausible reason to move | Service account logging on interactively, or a shared credential used from a new place |

Two habits keep this table honest. **State the entity that names your scope** — "the same address touched three accounts" and "the same account used three addresses" are different findings with different escalation thresholds. And **update the scope when it widens**: the moment a second account or host appears, the case note says so before the investigation continues.

## Step 5 — Shape, Not Threshold: Regularity in Authentication Data

Counts tell you *how many*; shape tells you *what kind*. The same reasoning used for beaconing in `../tools/query-languages.md` applies to authentication: measure the interval between events, not just their number.

| Shape in the logon data | What it usually is | What to do next |
|---|---|---|
| A tight burst of `4625`, then one `4624` | Guessing that succeeded, or a user who mistyped until they did not | Compare the source address and the target account list: many accounts from one address is a spray |
| A regular interval (same gap, hour after hour) | Automation — a monitoring agent, a backup job, a scheduled task | Attribute it to a service or scheduled task before calling it suspicious; regularity from an unexplained source is what matters |
| A small, steady trickle of successes from one new address | Persistent access that is being kept alive | Look at what each session does, and whether the account's sessions are being renewed |
| One success, then silence | Either a legitimate one-off, or access that was used and parked | Check the following 72 hours, not just the alert window |
| Successes from two addresses inside a window that cannot be travelled | Impossible travel — or an infrastructure artifact | Resolve what each address is before escalating; see Step 4 |

The single most common analytical error here is treating an interval as a threshold: "the account logged on eleven times today" says nothing until you know that its baseline is eleven times a day.

## Step 6 — Decide: Close, Monitor, or Escalate

| Evidence you have | Verdict | Action |
|---|---|---|
| Source is ours (VPN/branch), device is managed, MFA challenged, activity matches the account's baseline | False positive, with a reason | Close with the reason recorded, and note the baseline gap that produced the alert as tuning input |
| New source, no destructive or privileged activity, no explanation yet, scope still one account | True positive of unknown intent | Do not label it malicious. Contain only what the playbook authorises, keep monitoring, and hand it over with a written question if the box expires |
| Valid credentials plus unexplained session, or MFA satisfied on a token with no challenge | Suspected credential or token theft | Escalate now: an actor with a live session is inside, and closing the alert does not close the session |
| `4672` on an unusual logon, or a privileged account involved | Escalate immediately | Privileged identity beats every other consideration; scope it in parallel, not after |
| Same source against multiple accounts, or same account on multiple hosts | Scope is expanding | Escalate: this is no longer a single-account anomaly |

Escalation criteria, in the form you can apply under pressure (they mirror `../methodology/03-investigation.md` and `../methodology/04-response.md`):

- Confirmed or strongly suspected credential or session theft.
- Any privileged account, domain controller, or critical asset involved.
- Lateral movement, persistence, or new access paths (mail rules, OAuth consents, service registrations).
- Scope unclear or widening.
- The activity cannot be explained within your time box.

What tier 1 owns at this point is the validation, the enrichment, the first scope and the written case — plus the pre-approved, reversible containment actions the playbook names, typically disabling the account and revoking sessions through the identity owner. What it does not own is anything destructive or irreversible, the rule changes, and the enterprise-wide scope. Containment that stops the session without checking for a second door is not containment; `../methodology/04-response.md` has the trade-off table.

## What You Cannot Conclude From Logon Data

The limits are part of the finding, and stating them is what makes an escalation credible.

- **You cannot identify the person.** An account is not a human. A valid logon from a new country tells you a credential was used; it does not tell you by whom, willingly or not.
- **You cannot conclude the credentials were stolen.** A user on a new laptop, a new phone, a hotel network or a mobile hotspot produces the same events. What you can conclude is whether the *pattern* fits the account's baseline.
- **You cannot trust geography as fact.** Geo-IP is an estimate that misplaces VPN egress, mobile carriers, satellite links and cloud proxies. Two addresses that look 8 000 km apart may be one egress in two databases' opinions.
- **You cannot infer "no MFA" from the absence of an MFA event.** If the identity provider's logs are not in your SIEM, you have no evidence either way — and "we saw no challenge" is not the same as "there was none".
- **You cannot rule out a second door.** Disabling the account does not revoke a stolen refresh token, a registered application, or an existing ticket in some configurations. Session revocation is a separate action.
- **You cannot determine the initial access vector.** Logon events show the use of access, not how it was obtained. Phishing, credential reuse from a breach dump and a malicious OAuth consent all look identical at this layer.
- **You cannot prove exfiltration.** Successful logons and file reads are not transfer evidence; that question needs network or storage telemetry.
- **You cannot conclude malice from an anomaly count.** A high number of failed logons can be a broken application, a stale credential in a scheduled task, or a user with a keyboard. `4625` volume is a lead, and `SubStatus` is what separates the explanations.
- **You cannot, and should not, close a session-shaped finding as a false positive.** If an unfamiliar source holds a live session, closing the alert without revoking it leaves the actor in place with the ticket marked resolved.

## Common Mistakes & Tips

- **Mistake:** treating "impossible travel" as a conclusion. *Tip:* resolve what each address actually is before escalating; the alert is a question about infrastructure as often as it is about an attacker.
- **Mistake:** reading the alert instead of the raw events. *Tip:* an unpopulated `IpAddress`, a cached logon (type 11) or a misread `LogonType` explains a large share of these alerts, and only the raw event shows it.
- **Mistake:** counting failures without reading `SubStatus`. *Tip:* wrong password, unknown user, locked account and disabled account are different stories with different owners.
- **Mistake:** assuming a success without failures means nothing happened. *Tip:* it means nothing was *guessed* — which is exactly what theft looks like.
- **Mistake:** correlating by IP only. *Tip:* correlate by entity — account, address, host, and logon session id — and say which entity named your scope.
- **Mistake:** stopping after disabling the account. *Tip:* check for concurrent sessions, new mail rules, application consents and other accounts from the same address; the credential is rarely the only door.
- **Mistake:** escalating without the questions you could not answer. *Tip:* "I could not explain X, here is the query I ran and the sources I checked" is a handoff; "suspicious logon, please advise" is a restart for someone else.
- **Mistake:** recording the verdict without the baseline. *Tip:* the note says what the account normally does and what this logon broke; without that, the next analyst re-derives everything from nothing.

## Checklist / Self-Test

- [ ] I confirmed the raw `4624`/`4625` events exist and their key fields are populated.
- [ ] I can state the account's baseline: type, normal sources, normal logon types, normal hours.
- [ ] I know which four events I am correlating (`4624`, `4625`, `4648`, `4672`) and what each one does and does not prove.
- [ ] I resolved the alert's source address: owned by us, a hosting provider, an anonymising service, or unknown.
- [ ] I checked for a failure burst before the success, and I can explain what the absence of failures implies.
- [ ] I followed the logon session forward to see what the session actually did.
- [ ] I checked whether other accounts authenticated from the same address, and stated which entity names my scope.
- [ ] I can name the escalation criteria I applied, and the ones that did not apply.
- [ ] If I closed it, the reason is written and the baseline gap that caused the alert was recorded as tuning input.
- [ ] I wrote down what I could **not** conclude, with the queries I ran and the sources I checked.

## Further Resources

- Microsoft Learn — audit logon events and the `4624`/`4625` field reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logon
- Microsoft Learn — event 4648, a logon was attempted using explicit credentials: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4648
- Microsoft Learn — event 4672, special privileges assigned to new logon: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672
- Microsoft Learn — auditing policy recommendations for Windows security events: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings
- MITRE ATT&CK — T1078 (valid accounts) and T1110 (brute force): https://attack.mitre.org/
- MITRE ATT&CK — T1550 (use of alternate authentication material) and T1539 (steal web session cookie): https://attack.mitre.org/
- FIRST — Traffic Light Protocol (TLP), for classifying the account data you collect: https://www.first.org/tlp/
