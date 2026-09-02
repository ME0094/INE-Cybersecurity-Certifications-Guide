# BloodHound + SharpHound Guide

> 02-RedTeam · eCPPT tools — INE-Cybersecurity-Certifications-Guide (English)

BloodHound is a graph-based **Active Directory (AD) attack-path analysis tool**.
It ingests AD data (users, groups, computers, sessions, ACLs, delegation) and
lets you answer questions like *"who is the shortest path from my current user
to Domain Admin?"* SharpHound is BloodHound's **data collector** for Windows;
`bloodhound-python` is an equivalent collector you can run from Linux. Use
BloodHound only inside labs and engagements you are authorized to test.

## How BloodHound works

1. A **collector** queries AD (LDAP, SAMR, and local/remote calls) and writes a
   zip of JSON/JSONL files.
2. You **import** the data into a graph database (Neo4j for the legacy 4.x app;
   BloodHound CE ships its own graph backend).
3. The **UI** lets you click nodes, inspect edges, run pre-built queries, and
   find attack paths. Custom **Cypher queries** let you ask your own questions.

Key concepts:

- **Nodes** — users, computers, groups, domains, OUs, GPOs.
- **Edges/relationships** — how a node can affect another: `MemberOf`,
  `AdminTo`, `HasSession`, `GenericAll`, `GenericWrite`, `WriteDacl`,
  `ForceChangePassword`, `Owns`, `AddMember`, `AllowedToDelegate`, `CanRDP`,
  `CanPSRemote`, and more.
- **High-value targets (HVTs)** — nodes worth reaching (Domain Admins group,
  Domain Controllers, the Domain object, …).

> Version note: the current **BloodHound CE** (Community Edition) is delivered
> with Docker and only imports data from the modern SharpHound CE collectors.
> The legacy **BloodHound 4.x** app runs on Neo4j and imports legacy JSON. Pick
> one pair (legacy JSON with 4.x, or CE JSONL with CE) — mixing them is a
> common source of import failures.

## Installation

### BloodHound CE (current) — Linux/macOS via Docker

```bash
# Get the official repository (contains the Docker Compose example)
git clone https://github.com/SpecterOps/BloodHound.git
cd BloodHound/examples/docker-compose

# Start the graph database, API server, and web UI
sudo docker compose up -d

# UI: http://localhost:8080  (create the admin account on first run)
```

### Legacy BloodHound 4.x + Neo4j (still common in courses) — Linux/Kali

```bash
# Kali / Debian packages: legacy BloodHound app + Neo4j graph DB
sudo apt update && sudo apt install -y bloodhound neo4j

# Start Neo4j (legacy app connects to it over Bolt)
sudo neo4j start

# First run: browse to http://localhost:7474, log in with neo4j/neo4j
# and change the password immediately. Then launch the GUI:
bloodhound
# Login to the app with the SAME neo4j user/password you just set
```

Windows desktop users can download the legacy app release zip or run CE via
Docker Desktop/WSL2. In both cases the flow is the same: collector → import →
explore.

## Data collection

### SharpHound (Windows collector)

Download the SharpHound release that matches your BloodHound version (SharpHound
CE collectors for BloodHound CE; SharpHound v4.x for legacy BloodHound). Run it
on a Windows host that can reach the domain — a domain-joined workstation, from
an account with domain-read rights:

```bat
:: Default + Session + ACL + ObjectProps — the usual starting set
SharpHound.exe --collectionmethods Default,Session,ACL,ObjectProps --zipfilename lab01 --outputdirectory C:\Users\Public\bh

:: Everything (loud; better on a dedicated enumeration host)
SharpHound.exe -c All -d corp.local

:: Loop session collection for a while — sessions change constantly
SharpHound.exe --collectionmethods Session --loop --loopduration 02:00:00

:: Authenticate explicitly if your current context cannot read the domain
SharpHound.exe --collectionmethods All --ldapuser corp\svc_enum --ldappass 'P@ssw0rd!' --domain corp.local
```

Key collection methods:

| Method | What it collects | Notes |
|---|---|---|
| `Default` (or `Group,LocalAdmin`) | groups, users, computers, group membership, local admins | baseline |
| `Session` | active user logon sessions | requires rights on targets; point-in-time |
| `LoggedOn` | sessions via remote registry/`net session` | needs admin on targets; noisy |
| `ACL` | DACLs on objects → ACL-abuse edges | pure LDAP; cheap to collect |
| `ObjectProps` | extra properties (SPNs, delegation flags, …) | enables Kerberoast/delegation queries |
| `DCOM` / `RDP` / `PSRemote` | who can reach a host via each channel | needs admin on targets |
| `GPOLocalGroup` | local admins granted via GPO | read GPOs |
| `Trusts` | domain/forest trusts | useful in multi-domain labs |

`-c All` exists but is loud; in a lab it is fine, on a real engagement ask
first.

### bloodhound-python (Linux collector)

From Kali or any Linux host with LDAP reachability:

```bash
# Install on Kali
sudo apt install -y bloodhound-python

# Collect group/ACL/session data using a domain account (uses LDAP + SAMR)
bloodhound-python -u svc_enum -p 'P@ssw0rd!' -d corp.local -ns 10.0.0.10 -c All

# Only session + ACL data, targeting the DC as LDAP server
bloodhound-python -u svc_enum -p 'P@ssw0rd!' -d corp.local -gc dc01.corp.local --collectionmethod Session,ACL
```

`bloodhound-python` writes one JSON file per node type plus a zip — import it
into **legacy BloodHound 4.x** (its JSONL output is not compatible with CE).

## Starting Neo4j (legacy workflow)

```bash
sudo neo4j start          # start the database service
sudo neo4j status         # confirm it is running
# Browser console (optional): http://localhost:7474
# App login uses the neo4j user: bolt://localhost:7687
```

Change the default Neo4j password before importing real lab data — the default
`neo4j/neo4j` is public knowledge.

## Common Cypher queries

Open the **Cypher** tab in the BloodHound UI. Group names are stored as
`DOMAIN ADMINS@CORP.LOCAL`; the Domain Admins group of a domain always ends
with SID `-512`, so `g.objectid ENDS WITH '-512'` is a robust filter.

```cypher
// 1. Who is in Domain Admins right now?
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-512'
RETURN u.name AS member, g.name AS group

// 2. Kerberoastable users (have an SPN -> can request a TGS)
MATCH (u:User)
WHERE u.hasspn = true AND u.enabled = true
RETURN u.name AS user, u.serviceprincipalnames AS spns

// 3. Live sessions — users logged into computers right now
MATCH (u:User)-[:HasSession]->(c:Computer)
WHERE u.enabled = true
RETURN c.name AS computer, u.name AS user
ORDER BY computer

// 4. High-value targets on the network
MATCH (n)
WHERE n.highvalue = true
RETURN n.name AS target, labels(n) AS type

// 5. Shortest path from a specific user to Domain Admins
MATCH p = shortestPath((u:User)-[*1..]->(g:Group))
WHERE u.name =~ '(?i)JDOE@.*' AND g.objectid ENDS WITH '-512'
RETURN p

// 6. Shortest path from ANY enabled non-admin user to Domain Admins
MATCH p = shortestPath((u:User)-[*1..]->(g:Group))
WHERE u.enabled = true AND u.admincount = false AND g.objectid ENDS WITH '-512'
RETURN p LIMIT 25

// 7. Which users have admin rights over which computers?
MATCH (u:User)-[:AdminTo]->(c:Computer)
RETURN u.name AS user, c.name AS computer
ORDER BY computer
```

The UI also ships useful **pre-built queries** (e.g., "Shortest Paths to High
Value Targets", "Find all Domain Admins", "Kerberoastable Users") — learn to
read them before writing your own.

## Interpretation tips

- **Edges are hypotheses, not exploits.** `GenericAll` on a user usually means
  "reset their password"; on a computer it can mean "add myself to local
  admins". Verify each edge with the command-line equivalent before relying on
  it.
- **Check the `AbuseInfo`** field shown on an edge in CE/4.x — it explains the
  abuse primitive and often the tool to use (PowerView, bloodyAD, net rpc,
  SharpHound abuse, …).
- **Sessions are point-in-time.** `HasSession` data depends on *when* the
  collector ran. Re-run session collection at different times and correlate
  with real logins (e.g., an admin who RDPs in at 9:00).
- **LoggedOn/Session needs privileges** — a non-admin collector will simply
  see far fewer sessions. This is expected, not a bug.
- **The shortest path may be long** — BloodHound shows the graph edge; you
  still have to execute each hop (passwords, hashes, tools) yourself.
- **Correlate with real enumeration** — cross-check BloodHound results with
  `net`, PowerShell AD cmdlets, or PowerView so you understand *why* an edge
  exists (often a group nesting or a DACL you did not notice).
- **Never import production data into a shared instance** — lab/authorized
  environments only; BloodHound data is sensitive.

## Common Mistakes & Tips

- **Importing legacy JSON into CE (or CE JSONL into 4.x)** — collection and
  ingestion versions must match. Check the zip contents before importing.
- **Forgetting to change the Neo4j default password.**
- **Collecting only once** — sessions age; run collectors multiple times.
- **Trusting `AdminTo` without checking** — the collector may run without
  enough rights; local admin data is then incomplete.
- **Ignoring `enabled`/`admincount` filters** — disabled or DA accounts clutter
  path results.
- **Using a domain admin account to collect** — you over-privilege the
  collector and taint your "starting position" analysis. Use a normal
  domain-read account.

## Checklist / Self-Test

- [ ] I can start Neo4j and the BloodHound app (or CE Docker stack) and log in
- [ ] I can run SharpHound (Windows) and `bloodhound-python` (Linux) and import the zip
- [ ] I can list Domain Admin members with a Cypher query
- [ ] I can find Kerberoastable users and read their SPNs
- [ ] I can run a shortest-path query from a controlled user to Domain Admins
- [ ] I can explain what each edge on that path means and how to abuse it
- [ ] I know which collection methods need admin rights and which are LDAP-only

## Further Resources

- [BloodHound (SpecterOps) — official repository](https://github.com/SpecterOps/BloodHound)
- [SharpHound — data collector repository](https://github.com/SpecterOps/SharpHound)
- [bloodhound-python (BloodHound.py) — dirkjanm](https://github.com/dirkjanm/BloodHound.py)
- [Neo4j — graph database documentation](https://neo4j.com/docs/)
- [HackTricks — Active Directory methodology](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology.html)
