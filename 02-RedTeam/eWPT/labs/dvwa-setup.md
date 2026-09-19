# DVWA Setup

> eWPT · Labs — INE-Cybersecurity-Certifications-Guide

## Purpose

**DVWA (Damn Vulnerable Web Application)** is a deliberately vulnerable PHP/MySQL
web application used for practicing web attacks legally. This guide installs
DVWA locally (Docker or LAMP), configures it, explains the four **security
levels**, and shows how to create practice accounts — including low-privilege
accounts you will need for authorization drills.

> ⚠️ DVWA is intentionally full of holes. Run it **only** in an isolated VM,
> container, or localhost environment. Do not expose it to a LAN, the
> Internet, or a shared cloud host. Prefer a snapshot you can roll back.

## 1. Install DVWA

### Option A — Docker (fastest, isolated)

Use the community-maintained image. Map a host port and give the container a
name so it is easy to stop/restart:

```bash
docker run -d --name dvwa -p 8080:80 vulnerables/web-dvwa
```

Then open <http://127.0.0.1:8080>. Log in with `admin` / `password` and click
**Create / Reset Database** on the setup page if prompted.

Notes:

- The `vulnerables/web-dvwa` image is old (PHP 5 era) but fully functional for
  classic labs; it bundles MySQL.
- To rebuild a clean slate later: `docker rm -f dvwa` and run the same command
  again.
- Stop it when not practicing: `docker stop dvwa`.

### Option B — LAMP from source (current PHP, more control)

Run on Kali, Debian, or Ubuntu (a VM is recommended). Install the stack, fetch
DVWA, and configure it:

```bash
sudo apt update && sudo apt install -y apache2 mariadb-server php \
    php-mysqli php-gd libapache2-mod-php git

git clone https://github.com/digininja/DVWA.git /var/www/html/dvwa
cd /var/www/html/dvwa
cp config/config.inc.php.dist config/config.inc.php
sudo chown -R www-data:www-data /var/www/html/dvwa   # if needed for writable dirs
```

Create the database and a dedicated user (defaults DVWA expects):

```sql
sudo mysql -e "CREATE DATABASE IF NOT EXISTS dvwa;
CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;"
```

Start services and finish in the browser:

```bash
sudo systemctl enable --now apache2 mariadb
```

Open <http://127.0.0.1/dvwa/setup.php>, click **Create / Reset Database**,
then log in with `admin` / `password`.

### Option C — Prebuilt VM

Kali includes DVWA material and other labs in its documentation, and some
courses ship a ready VM. If you use a prebuilt VM, verify it is from a trusted
source, change default credentials, and keep it off untrusted networks.

## 2. Configuration essentials

- **`config/config.inc.php`** — holds the DB credentials (`db_user`,
  `db_password`, `db_database`) and the default security level. Edit it before
  running setup if you changed the DB user above:

```php
$_DVWA[ 'db_user' ]     = 'dvwa';
$_DVWA[ 'db_password' ] = 'p@ssw0rd';
$_DVWA[ 'db_database' ] = 'dvwa';
```

- **PHP settings** — the setup page checks PHP options such as
  `allow_url_fopen`, `allow_url_include`, and `display_errors`. For the most
  permissive (low) labs you usually want `allow_url_include = On` in
  `/etc/php/*/apache2/php.ini`; restart Apache after changing it. The setup
  page tells you exactly what it needs.
- **Writable folders** — DVWA writes to folders such as
  `hackable/uploads/` and `external/phpids/`; ensure the web user can write
  there or upload exercises will fail.
- **Reset anytime** — visit `setup.php` and click **Create / Reset Database**
  to restore a pristine state after you break something (you will).

## 3. Security levels

DVWA ships four levels; changing them alters how the same vulnerable page is
implemented:

- **Low** — no protections at all. Input reaches the vulnerable function
  unchanged. Purpose: learn the *mechanics* of each attack without noise.
- **Medium** — naive defenses: some server-side checks, `addslashes()`-style
  escaping in places, or a switch from GET to POST. Purpose: learn to read
  source code and adapt payloads (encoding, alternate syntax, parameter
  location).
- **High** — more layered or stricter defenses (e.g., prepared statements in
  some pages, LIMIT clauses, better sanitization). Purpose: practice
  bypassing specific controls rather than broad filters.
- **Impossible** — properly hardened code: parameterized queries, CSRF
  tokens, strong output encoding. Purpose: see what *correct* code looks like
  and confirm your payloads fail against it.

Switch levels from the **DVWA Security** page (or by setting `security` in the
cookie to `low`/`medium`/`high`/`impossible`).

Recommended progression: master **low** fully, then repeat the same exercises
at **medium** and **high**, reading `source/` for each page to understand the
defense before bypassing it. Never practice "impossible" for exploitation —
use it as a control case to observe secure behavior.

## 4. Creating practice accounts

You need more than `admin` for realistic drills (stored XSS between users,
horizontal privilege checks, login brute force with a real victim account).

- **Via the app:** not available. DVWA ships no registration page — `login.php` in
  current master has no **Register** link and the repository contains no
  `register.php`. Some older forks or course bundles may add one; if yours does,
  create `alice` / `Password123` and `bob` / `Password123` from it.
- **Via SQL (the route that always works):** insert a user with the same password
  hashing DVWA uses (MD5). `user_id` is a PRIMARY KEY with no AUTO_INCREMENT and
  DVWA's own setup seeds ids 1–5 (`admin`, `gordonb`, `1337`, `pablo`, `smithy`),
  so pick an id outside that range. Reset the database afterwards if you corrupt
  anything:

```sql
INSERT INTO dvwa.users (user_id, user, avatar, password, last_login, failed_login)
VALUES ('6', 'alice', 'alice.jpg', MD5('Password123'), NOW(), 0);

INSERT INTO dvwa.users (user_id, user, avatar, password, last_login, failed_login)
VALUES ('7', 'bob', 'bob.jpg', MD5('Password123'), NOW(), 0);
```

- Log out and log back in as the new account to confirm it works before a
  drill that depends on it.
- On the medium/high levels, remember DVWA's own users table is a *target* of
  the SQLi exercises — do not rely on those rows staying intact after you dump
  them in a drill. Keep a fresh `CREATE / RESET DATABASE` one click away.

## 5. Tips for each level's purpose

- **Low** — one page at a time: read the vulnerable parameter, send your
  payload, observe the result, and *write down* the technique. This is where
  you build muscle memory for the payload families in `cheatsheets/web-payloads.md`.
- **Medium** — switch to a fresh browser profile or clear cookies between
  users; pay attention to *which* defense changed (look at the source) and
  craft the minimal bypass rather than spraying payloads.
- **High** — treat it like a small capture-the-flag: the defense is specific,
  so the bypass is specific too. If one approach fails, re-read the source
  instead of brute forcing.
- **General lab hygiene** — snapshot the VM before enabling PHP modules;
  keep DVWA bound to `127.0.0.1` or the VM's NAT interface; route your browser
  through Burp Suite from day one so every exercise doubles as proxy practice.

## Common Mistakes & Tips

- **Running DVWA on a public IP** → within hours it is scanned and abused.
  Keep it on localhost/NAT and stop the container when idle.
- **Skipping `Create / Reset Database`** → white pages or "Table doesn't
  exist" errors. Run setup first and re-run it after config edits.
- **Wrong DB credentials in `config.inc.php`** → setup cannot connect.
  Double-check `db_user`/`db_password` against the user you created in MySQL.
- **`allow_url_include` off** → file-inclusion and some SSRF exercises break
  silently. Fix the PHP flags the setup page lists, then restart Apache.
- **Editing the Docker image's internals** → changes are lost on `docker rm`.
  Prefer environment variables or rebuild scripts for repeatable setups.
- **Using `admin`/`password` on a reachable host** → change defaults if the
  box is not strictly isolated.
- Tip: keep a text file with the exact URLs of the pages you practice most
  (login, SQLi page, XSS stored page, upload page) to avoid clicking through
  the menu each time.
- Tip: pair each level with the matching methodology note so the exercise maps
  to a phase of the testing process.

## Checklist / Self-Test

- [ ] DVWA runs locally (Docker or LAMP) and opens in my browser.
- [ ] I created/reset the database and logged in with the default account.
- [ ] I changed the default security level and confirmed the change sticks.
- [ ] I created at least two practice accounts and logged in with one.
- [ ] I know which PHP flags the setup page requires and where they live.
- [ ] I can reset DVWA to a pristine state in under a minute.
- [ ] DVWA is not reachable from outside my local machine/VM.
- [ ] I completed one full exercise at Low, then repeated it at Medium.

---

> **Verification:** checked against DVWA's own source on 2026-09-19 (current `master`,
> `dvwa/includes/DBMS/MySQL.php`): `users` has `PRIMARY KEY (user_id)` with no `AUTO_INCREMENT`
> and the seed inserts ids 1–5, which is why the accounts above use ids 6 and 7;
> `register.php` returns 404 and `login.php` has no registration link. No MySQL was started
> here, so the INSERT statements were checked against the schema and not executed.

## Further Resources

- DVWA official repository (README has full install notes) — <https://github.com/digininja/DVWA>
- OWASP Vulnerable Web Applications Directory (where to find further deliberately vulnerable apps to practise against) — <https://owasp.org/www-project-vulnerable-web-applications-directory/>
- PortSwigger Web Security Academy (complementary guided labs) — <https://portswigger.net/web-security>
