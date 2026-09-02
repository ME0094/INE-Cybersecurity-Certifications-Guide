# Memory Analysis with Volatility

> eCDFP · Tools — INE Cybersecurity Certifications Study Guide
>
> Why memory forensics matters, how Volatility 2 and 3 differ, the essential plugins, and a repeatable mini-workflow for chasing a suspicious process. All examples use dumps you created or public samples you are authorized to analyze.

## Why memory forensics matters

Disk forensics only shows what touched the disk. A great deal of an attack **never does**:

- Malware that runs **entirely in memory** (fileless or reflective-loaded payloads).
- Decrypted data, passwords, and encryption keys held in RAM.
- Live **network connections** (C2 beacons) that leave no packet capture behind.
- Injected code inside legitimate processes (e.g., `svchost.exe` hosting attacker shellcode).
- Open files, clipboard content, and command lines that expose attacker actions.

A memory dump is a snapshot of a running system, so it also tells you *what was true at the moment of capture* — a powerful complement to disk images that answer *what was left behind*.

> Acquisition note: memory must be captured on the **live** system (FTK Imager, WinPmem, LiME on Linux) and analyzed on a **separate, trusted** machine. You normally capture first, then pull the plug — never the reverse.

## Volatility 2 vs 3 — the basics

| | Volatility 2 (legacy) | Volatility 3 (current) |
| --- | --- | --- |
| Language | Python 2 | Python 3 |
| OS support | Windows focus (+ Linux/macOS experimental) | Windows, Linux, macOS |
| OS knowledge | **Profile** baked into the framework, e.g. `Win7SP1x64` | **Symbol tables** downloaded per build from the official symbol server |
| OS detection | Manual: `imageinfo` / `kdbgscan` | `windows.info`, `linux.info` |
| Typical invocation | `volatility -f img --profile=X pslist` | `python3 vol.py -f img windows.pslist` |

### Profiles (Volatility 2)

A profile encodes the kernel structures for one OS version. You must pick the right one or most plugins fail or lie.

```bash
# Step 1: guess profiles (slow but exhaustive)
volatility -f mem.raw imageinfo
# Suggested Profile(s) : Win7SP1x64, Win7SP1x64_23418, ...

# Step 2: confirm with a fast targeted scan, then run plugins with the profile
volatility -f mem.raw --profile=Win7SP1x64 kdbgscan
volatility -f mem.raw --profile=Win7SP1x64 pslist
```

> Volatility 2 needs an explicit `--profile` on (almost) every command — forgetting it is the #1 beginner error.

### Symbols (Volatility 3)

Volatility 3 figures out the OS automatically and **downloads the right PDB symbol tables** from the official symbol server into a local cache. Offline labs need `--symbol-dir` pointing at pre-fetched tables.

```bash
# Auto-detection + symbol download on first run
python3 vol.py -f mem.raw windows.info
# Volatility 3 Framework 2.x.x
# Symbol table: kernel symbols
# Kernel base: 0xfffff8000363c000

# Point at a local symbol folder when offline
python3 vol.py -f mem.raw -s /evidence/symbols windows.info
```

## Key plugins

All examples below are Volatility 3 syntax; the equivalent Volatility 2 plugin name is noted in parentheses.

### pslist (v2: pslist) — walking process list

Lists processes by walking the kernel's doubly-linked EPROCESS list. Shows PID, PPID, and process start time.

```bash
python3 vol.py -f mem.raw windows.pslist
# PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId Wow64
# 4       0       System          0x...           123     0       0         0
# 3456    528     notepad.exe     0x...           2       45      1         0
```

**Caveat:** advanced malware can *unlink* its EPROCESS entry and hide from this list. That is why `psscan` exists.

### pstree (v2: pstree) — hierarchy view

Arranges processes as a tree so an abnormal parent/child relationship stands out.

```bash
python3 vol.py -f mem.raw windows.pstree
# *** 3456 (notepad.exe) 528  -1
# *** 3992 (cmd.exe) 3456 ...
```

A `cmd.exe` whose parent is `notepad.exe` is a classic sign of a process injection or document-based attack.

### psscan (v2: psscan) — hunt hidden processes

Scans physical memory for EPROCESS structures instead of trusting the linked list; finds processes `pslist` misses.

```bash
python3 vol.py -f mem.raw windows.psscan
```

### netscan (v2: netscan) — network artifacts

Lists TCP/UDP endpoints from kernel pool memory — the fastest way to spot a C2 conversation and its owning PID.

```bash
python3 vol.py -f mem.raw windows.netscan
# Proto Local Address     Foreign Address   State      PID
# TCP   10.0.0.5:49675    45.77.99.10:4444  ESTABLISHED 3456
```

### malfind (v2: malfind) — find injected code

Scans process memory for regions with suspicious characteristics (e.g., **PAGE_EXECUTE_READWRITE**) and prints disassembly — the fingerprint of injected shellcode.

```bash
python3 vol.py -f mem.raw windows.malfind --pid 3456
# Process: notepad.exe Pid: 3456 Address: 0x1e0000
# Protection: PAGE_EXECUTE_READWRITE
# Disassembly:
# 0x1e0000 4d5a      push rbp            ; "MZ" header of a PE image
```

### hashdump (v2: hashdump) — credential material

Extracts the SAM database from memory (local account hashes). Compare hashes against known-bad lists, and handle them as sensitive evidence.

```bash
python3 vol.py -f mem.raw windows.hashdump
# User: Administrator Rid: 500 Hash: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

### dumpfiles (v2: dumpfiles) and memdump (v2: memdump) — extraction

- `windows.memdump` writes the **full address space of one process** to disk for `strings`/AV scanning.
- `windows.dumpfiles` extracts **individual files** (e.g., the malware binary) from File objects in memory.

```bash
# Dump one process's whole memory
python3 vol.py -f mem.raw windows.memdump --pid 3456 --dump /evidence/dumps
# Wrote /evidence/dumps/3456.dmp

# List then extract files owned by the process
python3 vol.py -f mem.raw windows.dumpfiles --pid 3456 --dump
# Wrote 2 files to the current directory (e.g. file.0x...dat)
```

Then examine what you dumped:

```bash
strings -el /evidence/dumps/3456.dmp | head -50
# Classic trick: '-el' decodes UTF-16LE strings typical of Windows binaries
```

## Mini workflow — chasing a suspicious process

Reusable recipe for "something looks off on this box":

1. **Confirm the OS and that symbols loaded:** `windows.info`.
2. **Get the lay of the land:** `windows.pstree` + `windows.pslist`; note odd names, orphaned children, weird parents.
3. **Read the command lines:** `windows.cmdline` — attackers leave flags/paths behind.
4. **Check the network:** `windows.netscan` — is the PID talking to an unusual remote host?
5. **Look for injection:** `windows.malfind --pid <PID>`.
6. **Preserve and extract:** `windows.memdump --pid <PID> --dump <dir>` and `windows.dumpfiles --pid <PID> --dump`.
7. **Analyze offline:** `strings`, hashing the dumped PE (`sha256sum`), then VT or YARA in your sandbox.

```bash
python3 vol.py -f /evidence/mem.raw windows.pstree
python3 vol.py -f /evidence/mem.raw windows.cmdline
python3 vol.py -f /evidence/mem.raw windows.netscan
python3 vol.py -f /evidence/mem.raw windows.malfind --pid 3456
python3 vol.py -f /evidence/mem.raw windows.memdump --pid 3456 --dump /evidence/dumps/
python3 vol.py -f /evidence/mem.raw windows.dumpfiles --pid 3456 --dump
sha256sum /evidence/dumps/3456.dmp
```

## Common Mistakes & Tips

- **Forgetting `--profile` in Volatility 2** — every command needs it; define `PROFILE=...` in your shell to reduce typos.
- **Trusting `pslist` alone** — hidden processes need `psscan`; run both and diff the PIDs.
- **Skipping `windows.info` in Volatility 3** — if symbols fail to download, plugins error out; verify with `windows.info` first, and use `--symbol-dir` when offline.
- **Analyzing on the same machine you acquired from** — never; that machine is contaminated evidence.
- **Dumping gigabytes with no plan** — `memdump` on a big process is slow and huge; confirm the PID and target with the lighter plugins first.
- **Reading only one artifact** — a process name tells you little; combine `pstree` + `cmdline` + `netscan` + `malfind` before concluding anything.
- **Forgetting anti-forensics** — memory can be tampered with by rootkits; correlate memory findings with disk artifacts and logs.

## Checklist / Self-Test

- [ ] I can explain three classes of evidence that exist *only* in memory.
- [ ] I can state the difference between a Volatility 2 profile and a Volatility 3 symbol table.
- [ ] I detected the OS/version of a sample with `windows.info` (v3) and with `imageinfo`+`kdbgscan` (v2).
- [ ] I produced `pslist` and `pstree` output and identified an anomalous parent/child relationship.
- [ ] I used `netscan` to correlate a network connection with a PID.
- [ ] I ran `malfind` on a suspicious PID and could point to the injected region.
- [ ] I dumped a process (`memdump`) and a file (`dumpfiles`) and inspected the result with `strings`.
- [ ] I can name one limitation of `pslist` and the plugin that covers it.

## Further Resources

- Volatility 3 official documentation — volatility3.readthedocs.io (plugin list, quickstart, symbol server notes).
- Volatility Foundation site and GitHub — volatilityfoundation.org, github.com/volatilityfoundation.
- NIST SP 800-86 — *Guide to Integrating Forensic Techniques into Incident Response* (csrc.nist.gov/publications).
- Public, authorized practice dumps: the Volatility project samples and DFRWS challenge datasets — dfrws.org.
