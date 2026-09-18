# Memory Analysis with Volatility

> eCDFP · Tools — INE Cybersecurity Certifications Study Guide
>
> Why memory forensics matters, how Volatility 2 and 3 differ, the essential plugins, how symbols work and how they fail, and a repeatable mini-workflow for chasing a suspicious process. All examples use dumps you created or public samples you are authorized to analyze.
>
> Every command is a **syntax reference**. This repository ships no captured command output — there is no memory dump and no Volatility install on the machine that wrote this file. Plugin and option names differ between Volatility 3 releases, so where a name matters the text tells you to confirm it with `--help` on your build rather than trusting a remembered example.

## Why memory forensics matters

Disk forensics only shows what touched the disk. A great deal of an attack **never does**:

- Malware that runs **entirely in memory** (fileless or reflective-loaded payloads).
- Decrypted data, passwords, and encryption keys held in RAM.
- Live **network connections** (C2 beacons) that leave no packet capture behind.
- Injected code inside legitimate processes (e.g., `svchost.exe` hosting attacker shellcode).
- Open files, clipboard content, and command lines that expose attacker actions.

A memory dump is a snapshot of a running system, so it also tells you *what was true at the moment of capture* — a powerful complement to disk images that answer *what was left behind*.

> Acquisition note: memory must be captured on the **live** system (FTK Imager, WinPmem, LiME on Linux) and analyzed on a **separate, trusted** machine. You normally capture first, then pull the plug — never the reverse.

What memory adds that disk cannot, stated as questions:

| Question | Memory can answer it | Disk usually cannot |
| --- | --- | --- |
| What was executing at the moment of capture, including injected code? | Yes — process structures and their memory regions | Only if an artefact recorded execution |
| Which network connections were open, and by which process? | Yes — kernel socket structures with owning PIDs | Sometimes, from logs, if anything logged them |
| What were the command lines? | Yes, for live processes | Partly, from process-creation events if auditing was on |
| What keys or credentials were in use? | Yes — this is often the only route into encrypted data | No (that is the point of encryption) |
| What did the attacker delete five minutes ago? | Partly — remnants in freed pages | Partly — recovery from unallocated space |

And what memory cannot do: it is a **snapshot**, biased toward whatever happened to be resident. A process that exited before capture, a connection that had already closed, or a page that the OS paged out may be absent. Absence in a memory image is weak evidence; presence is strong.

## Getting Volatility 3 running, and proving it works

```bash
# Install (either form; pick one and record which)
pipx install volatility3
pip install volatility3

# Confirm which console command your install provides, and the framework version
vol --help
vol.py --help
# What to look for: the usage line naming the framework version, and the list of global
# options. The console command has appeared as both 'vol' and 'vol.py' across releases;
# use whichever exists on your install rather than the one in a tutorial.

# List the plugins your build actually ships (names and modules)
vol --help | grep -iE 'windows\.|linux\.|mac\.'
vol -f sample.raw --help
# What to look for: the module namespaces present (windows, linux, mac) and the plugin
# names under them. This list — not this file — is the authority on plugin names for
# your version.

# Plugin-specific options, which change between releases
vol -f sample.raw windows.malfind --help
```

Global options you will use constantly:

| Option | Meaning | Note |
| --- | --- | --- |
| `-f <file>` | The memory image to analyse | Accepts raw dumps and some crash-dump formats; confirm what your build supports |
| `-s <dir>` | Symbol directory | Essential offline; see below |
| `-o <dir>` / `-r <format>` | Output directory / renderer | Use a renderer such as JSON when you intend to script over results |
| `-v` | Verbosity | The fastest way to see *why* a plugin failed — symbol resolution errors appear here |

> **Always run a basic identification plugin first.** If the operating system is not recognised or symbols did not resolve, every later result is suspect. Fix the symbol problem before interpreting anything.

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
# What to look for: candidate profiles, each with a confidence indication. Candidates,
# not answers — confirm before you build conclusions on one.

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
# What to look for: the identified OS and build, the kernel base, and an indication that
# a symbol table was located. If the table is missing, this plugin is where you find out.

# Point at a local symbol folder when offline
python3 vol.py -f mem.raw -s /evidence/symbols windows.info
```

How the symbol mechanism actually behaves, because it decides whether a case is analysable on an air-gapped machine:

| Situation | What happens | What to do |
| --- | --- | --- |
| Machine has internet, symbols uncached | Volatility downloads the table and caches it locally | Nothing; verify with a basic plugin |
| Machine is offline, symbols cached | Plugins work normally | Nothing — but record that symbols came from the cache |
| Machine is offline, symbols not cached | Plugins fail with a symbol/requirement error | Download on a connected machine, copy the cache directory (or the symbol files) to the analysis host, and point `-s` at it |
| The build is unusual (preview builds, embedded, some server editions) | No table is published for that exact build | Try the nearest matching build's table, and state clearly in the report that symbols were approximated |
| Symbols resolved but results look wrong | Possibly the wrong table, not a wrong result | Rerun with `-v` and confirm which table was used |

A failure mode to name explicitly: **a missing symbol table is not an empty result.** Plugins that cannot resolve symbols fail; they do not report "nothing found". If a plugin errored, you have no result at all, and saying "no injected code was found" would be false.

Preparing symbols for an offline analysis host:

```text
1. On a connected machine of the same architecture, run a basic plugin against a dump
   (any dump of a compatible OS) so the required tables are fetched into the cache.
2. Locate the cache directory your install uses and copy it to removable media.
3. On the offline analysis host, place the files where Volatility expects them or point
   -s at the copied directory.
4. Verify by running the same basic plugin and confirming the OS is identified.
```

> Do not guess the cache path. Run `vol --help` and check the documentation for the version you installed: the location has changed across releases.

## Key plugins

All examples below are Volatility 3 syntax; the equivalent Volatility 2 plugin name is noted in parentheses. **Confirm each name against the plugin list your build prints** — for example, plugins for registry artefacts and for scheduled tasks exist under a module path that has changed between releases.

### pslist (v2: pslist) — walking process list

Lists processes by walking the kernel's doubly-linked EPROCESS list. Shows PID, PPID, and process start time.

```bash
python3 vol.py -f mem.raw windows.pslist
# What to look for: PID, parent PID, image name, and start time. The parent-child pairs
# are the analytical content; the list itself is just an inventory.
```

**Caveat:** advanced malware can *unlink* its EPROCESS entry and hide from this list. That is why `psscan` exists.

### pstree (v2: pstree) — hierarchy view

Arranges processes as a tree so an abnormal parent/child relationship stands out.

```bash
python3 vol.py -f mem.raw windows.pstree
# What to look for: a child whose parent makes no sense for it — a shell or scripting
# host under a document viewer, a service under an interactive shell.
```

### psscan (v2: psscan) — hunt hidden processes

Scans physical memory for EPROCESS structures instead of trusting the linked list; finds processes `pslist` misses.

```bash
python3 vol.py -f mem.raw windows.psscan
# What to look for: PIDs present here and absent from pslist. Those are your candidates
# for unlinked (hidden) processes. Note that psscan can also surface TERMINATED processes
# whose structures have not been reused yet — so a one-sided difference is a lead, not
# automatically a rootkit. Check the exit times.
```

### cmdline and envars — what the process was told to do

```bash
python3 vol.py -f mem.raw windows.cmdline
python3 vol.py -f mem.raw windows.envars --pid 2468
# What to look for: encoded or obfuscated arguments, paths outside the expected install
# directory, UNC paths to remote hosts, and temporary directories. Environment blocks
# can also reveal a user profile path, which helps attribution.
```

### dlllist, handles and modules — what it loaded and touched

```bash
python3 vol.py -f mem.raw windows.dlllist --pid 2468
python3 vol.py -f mem.raw windows.handles  --pid 2468
python3 vol.py -f mem.raw windows.modules
python3 vol.py -f mem.raw windows.modscan
# What to look for: DLLs loaded from user-writable paths, handles to files or registry
# keys the process has no business touching, and a difference between the module list
# (linked) and the module scan (physically found) — the same hidden-object idea as
# pslist versus psscan.
```

### netscan (v2: netscan) — network artifacts

Lists TCP/UDP endpoints from kernel pool memory — the fastest way to spot a C2 conversation and its owning PID.

```bash
python3 vol.py -f mem.raw windows.netscan
# What to look for: established connections to unfamiliar addresses, listeners on
# unusual ports, and the owning PID for each. Note that a connection to an address you
# cannot resolve is not evidence of malice — it is a question for the network logs.
```

### malfind (v2: malfind) — find injected code

Scans process memory for regions with suspicious characteristics (e.g., **PAGE_EXECUTE_READWRITE**) and prints disassembly — the fingerprint of injected shellcode.

```bash
python3 vol.py -f mem.raw windows.malfind --pid 2468
# What to look for: an executable, privately-committed region that is not backed by a
# file on disk, with disassembly that looks like a PE header or shellcode. malfind's
# output is a strong LEAD, not a verdict: just-in-time compilers, unpackers and some
# security products legitimately create executable regions.
```

### vadinfo — whether a region is file-backed

```bash
python3 vol.py -f mem.raw windows.vadinfo --pid 2468
# What to look for: the VAD entries whose protection is executable and whose backing is
# private rather than a mapped file. This is the structural question malfind's output
# raises but does not answer on its own.
```

### hashdump (v2: hashdump) — credential material

Extracts the SAM database from memory (local account hashes). Compare hashes against known-bad lists, and handle them as sensitive evidence.

```bash
python3 vol.py -f mem.raw windows.hashdump
# What to look for: account names with RIDs and hash pairs. Treat the output as
# credential material: store it protected, minimise who sees it, and do not paste it
# into a report.
```

Related credential plugins extract cached domain credentials, LSA secrets, and other material. Which ones exist and what they require varies by build and by OS version — list the plugins your build ships and read `--help` for each, rather than relying on a remembered name.

### dumpfiles and memdump — extraction

- `windows.memdump` writes the **full address space of one process** to disk for `strings`/AV scanning.
- `windows.dumpfiles` extracts **individual files** (e.g., the malware binary) from File objects in memory.

```bash
# Dump one process's whole memory
python3 vol.py -f mem.raw windows.memdump --pid 2468 --dump /evidence/dumps
# What to look for: a written file per process, named with the PID. Confirm the size is
# plausible for the process before treating it as complete.

# List then extract files owned by the process
python3 vol.py -f mem.raw windows.dumpfiles --pid 2468 --dump
# What to look for: extracted files whose type (checked with `file`) matches the
# extension they claim, and which are large enough to be a real binary.
```

Then examine what you dumped:

```bash
strings -el /evidence/dumps/2468.dmp | head -50
# What to look for: UTF-16LE strings typical of Windows binaries — URLs, mutexes,
# file paths, error messages. '-el' decodes 16-bit little-endian; try plain ASCII too.

sha256sum /evidence/dumps/2468.dmp
# Record the hash: a dumped region is an exhibit, and it must be reproducible.
```

### YARA against memory

```bash
python3 vol.py -f mem.raw windows.yarascan --yara-file /evidence/rules/lab.yar
python3 vol.py -f mem.raw windows.vadyarascan --yara-file /evidence/rules/lab.yar
# What to look for: matches attributed to a specific process and address, which is far
# more useful than a flat scan of the image. Confirm the plugin names and options with
# --help on your build.
```

### Registries and system state from memory

Volatility can read registry hives out of memory and query many system structures: the hive list, keys, services, scheduled tasks, user activity artefacts and more. Two uses matter most forensically:

- **Recovering a hive you cannot get from disk** (a live system, or a volume that is encrypted on disk but mounted in memory).
- **Comparing memory state with disk state** — a registry key present in memory and absent from the disk image is a finding in itself.

```bash
python3 vol.py -f mem.raw windows.registry.hivelist
python3 vol.py -f mem.raw windows.registry.printkey --key 'Software\Microsoft\Windows\CurrentVersion\Run'
# What to look for: the keys relevant to your question. List the registry plugins your
# build ships before assuming a specific name for a specific artefact.
```

### timeliner — events from memory

Some builds ship a plugin that extracts time-stamped events from memory into a timeline-ready form, which is the cheapest way to fold memory findings into a supertimeline. Confirm the plugin name and its output format on your build, and remember that a memory-derived event carries the same timestamp caveats as any other source (see `../methodology/03-timeline.md`).

## Mini workflow — chasing a suspicious process

Reusable recipe for "something looks off on this box":

1. **Confirm the OS and that symbols loaded:** `windows.info`.
2. **Get the lay of the land:** `windows.pstree` + `windows.pslist`; note odd names, orphaned children, weird parents.
3. **Read the command lines:** `windows.cmdline` — attackers leave flags/paths behind.
4. **Check the network:** `windows.netscan` — is the PID talking to an unusual remote host?
5. **Look for injection:** `windows.malfind --pid <PID>`, then `windows.vadinfo --pid <PID>` to see whether the region is file-backed.
6. **Preserve and extract:** `windows.memdump --pid <PID> --dump <dir>` and `windows.dumpfiles --pid <PID> --dump`.
7. **Analyze offline:** `strings`, hashing the dumped PE (`sha256sum`), then YARA or a sandbox in your own lab.
8. **Corroborate on disk:** was the binary's image on disk ever written? Does the injecting process exist on disk at all? Is there a process-creation event, a Prefetch entry, an Amcache record? Memory evidence plus one independent artefact is a finding; memory alone is a strong lead.

```bash
python3 vol.py -f /evidence/mem.raw windows.pstree
python3 vol.py -f /evidence/mem.raw windows.cmdline
python3 vol.py -f /evidence/mem.raw windows.netscan
python3 vol.py -f /evidence/mem.raw windows.malfind --pid 2468
python3 vol.py -f /evidence/mem.raw windows.vadinfo --pid 2468
python3 vol.py -f /evidence/mem.raw windows.memdump --pid 2468 --dump /evidence/dumps/
python3 vol.py -f /evidence/mem.raw windows.dumpfiles --pid 2468 --dump
sha256sum /evidence/dumps/2468.dmp
```

## When a plugin fails: a diagnosis table

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| "Unable to find a suitable symbol table" / requirement errors | Symbols not cached, offline machine, unsupported build | Fetch symbols on a connected host, or point `-s` at a local directory; confirm the build is supported |
| Every plugin errors, even `windows.info` | Wrong OS module for the image (e.g. a Linux image analysed as Windows), or a corrupted/truncated dump | Identify the OS from the acquisition record; verify the dump's size against the source's RAM |
| The dump opens but nothing is found, and no error appears | Possibly a partial dump, a hypervisor snapshot lacking structures, or a genuinely quiet system | Validate with a basic plugin; try a known-good sample of the same OS to prove the toolchain |
| Results look like nonsense (implausible PIDs, empty names) | Wrong symbol table for this build, or a dump encrypted/compressed in transit | Rerun with `-v`, confirm which table was used |
| A plugin takes extremely long or exhausts memory | Scanning a large image with an expensive plugin | Scope with `--pid` where supported; run on a machine with adequate RAM; process one plugin at a time |
| Output is truncated in the terminal | Very large result sets | Use an output renderer that writes to a directory, or redirect the output to a file |
| Inconsistent results between two runs | Image changed between runs, or different symbol tables were used | Hash the image before and after; record the symbol source |

## Honesty about what memory analysis gives you

- **A dump is a snapshot with a bias.** Present evidence is strong; absent evidence is weak. Say which you have.
- **The kernel's view can be manipulated.** A kernel-mode rootkit can alter the structures Volatility reads. This is why cross-checking (pslist vs psscan, modules vs modscan) exists, and why memory findings should be corroborated on disk where possible.
- **An executable region is not proof of malice.** Just-in-time compilers, unpackers and security tooling create them legitimately. Interpret with the process's identity, path, parent and network behaviour.
- **Credential material is sensitive evidence.** Minimize its collection, store it protected, and do not reproduce it in reports.
- **Capture alters the system.** Loading a memory acquisition tool changes memory. Unavoidable and acceptable — undocumented is not.

## Common Mistakes & Tips

- **Forgetting `--profile` in Volatility 2** — every command needs it; define `PROFILE=...` in your shell to reduce typos.
- **Trusting `pslist` alone** — hidden processes need `psscan`; run both and diff the PIDs, then check whether the difference is an unlinked process or an exited one.
- **Skipping `windows.info` in Volatility 3** — if symbols fail to download, plugins error out; verify with `windows.info` first, and use `--symbol-dir` when offline.
- **Reading a failed plugin as a negative result** — a symbol or requirement error means you have no result, not a clean one.
- **Assuming a plugin name from memory** — list your build's plugins and read `--help`; registry, scheduled-task and memory-scanning plugin paths have changed across releases.
- **Treating `malfind` output as a verdict** — it flags executable private regions. Check whether the region is file-backed, and look at the process's whole behaviour.
- **Analyzing on the same machine you acquired from** — never; that machine is contaminated evidence.
- **Dumping gigabytes with no plan** — `memdump` on a big process is slow and huge; confirm the PID and target with the lighter plugins first.
- **Reading only one artifact** — a process name tells you little; combine `pstree` + `cmdline` + `netscan` + `malfind` before concluding anything.
- **Forgetting anti-forensics** — memory can be tampered with by rootkits; correlate memory findings with disk artifacts and logs.
- **Pasting credential output into a report** — it is sensitive evidence; reference it, minimize it, store it protected.
- **Not hashing your dumps** — a dumped region is an exhibit. Without a hash and the exact command, it is unattributable.
- **Tip:** keep a per-case record of the framework version, the symbol source, and the exact plugin invocations. It is the methodology section of a memory finding.
- **Tip:** validate your toolchain against a public sample of the same OS before you touch the case image. Twenty minutes of baseline work saves days of doubt.

## Checklist / Self-Test

- [ ] I can explain three classes of evidence that exist *only* in memory.
- [ ] I can state the difference between a Volatility 2 profile and a Volatility 3 symbol table.
- [ ] I can list the plugins my installed build actually ships, rather than relying on remembered names.
- [ ] I detected the OS/version of a sample with `windows.info` (v3) and with `imageinfo`+`kdbgscan` (v2).
- [ ] I know how to prepare symbols for an offline analysis host and how to verify they resolved.
- [ ] I can explain why a plugin that fails on missing symbols is not a negative result.
- [ ] I produced `pslist` and `pstree` output and identified an anomalous parent/child relationship.
- [ ] I diffed `pslist` against `psscan` and can explain both a hidden process and an exited one.
- [ ] I used `netscan` to correlate a network connection with a PID.
- [ ] I ran `malfind` on a suspicious PID, then used `vadinfo` to check whether the region is file-backed.
- [ ] I dumped a process (`memdump`) and a file (`dumpfiles`), inspected the result with `strings`, and hashed it.
- [ ] I can name one limitation of `pslist` and the plugin that covers it.
- [ ] I can state three reasons a memory finding should be corroborated with disk evidence.
- [ ] I can explain why a memory snapshot makes presence strong evidence and absence weak evidence.

## Further Resources

- Volatility 3 official documentation — volatility3.readthedocs.io (plugin list, quickstart, symbol server notes).
- Volatility Foundation site and GitHub — volatilityfoundation.org, github.com/volatilityfoundation.
- NIST SP 800-86 — *Guide to Integrating Forensic Techniques into Incident Response* (csrc.nist.gov/publications).
- RFC 3227 — *Guidelines for Evidence Collection and Archiving* (why memory is captured before disk) — rfc-editor.org/rfc/rfc3227.
- Public, authorized practice dumps: the Volatility project samples and DFRWS challenge datasets — dfrws.org.
- `vol --help` and each plugin's `--help` on your own installation: the authoritative list for the version you have.
