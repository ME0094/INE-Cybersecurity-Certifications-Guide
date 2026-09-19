# Memory Injection Lab — Injected Code in a Live Process

> eCDFP · Labs — INE Cybersecurity Certifications Study Guide
>
> A reproducible lab on the memory of a process that has had code injected into it: obtain or stage a known condition, capture the memory, validate the dump before trusting it, find the injected region with Volatility 3, take it off the image, corroborate it outside memory, and state plainly what the analysis proves and what it does not.
>
> Every command here is a **syntax reference**: this repository ships no captured command output — no hypervisor, no memory dump and no Volatility installation sit behind these files — so every command carries a comment saying what to look for instead of a transcript. Everything runs on VMs you own or are explicitly authorized to test, on a host-only network, against a victim you snapshot before you touch it: **detection and interpretation, not capability**.

## 1. Objective

Take one memory image of a Windows VM on which a process is running injected code, and produce a statement you can defend: *this region of this process's address space was executable, was not backed by a file on disk, and here is what corroborates it outside memory — and here is what I cannot conclude from it.*

- Acquire memory yourself, record how, and hash the result as an exhibit.
- Prove the dump is analysable before spending a day interpreting it.
- Locate the injected region with more than one plugin, and separate what memory shows from what it merely suggests.

Deliverables, all under `~/lab/<case-id>/`: the hashed image in `evidence/`, a validated copy in `working/`, exported inventories in `exports/`, the dumped region and process memory in `dumps/` with their hashes, and an `answer-key.md` recording what you staged (see `lab-environment.md`, section 7).

## 2. Prerequisites

- The workbench from [lab-environment.md](lab-environment.md) built and verified: `win-lab`, `linux-lab`, the host-only network, UTC pinned, the evidence workspace convention, and the snapshot chain `00-clean-install` / `01-tooled` / `02-baseline` / `03-<case>-before` / `04-<case>-after`.
- **Volatility 3 on `linux-lab`, proven to run** — version recorded, and the console command name you actually have.
- `win-lab` disposable and snapshotted at `03-<case>-before` before you stage anything, with space for a dump roughly the size of the guest's RAM — and a recorded decision about which of the two paths in section 4 you are taking.

```bash
# On linux-lab. Use the console name your install provides: the project has shipped it as
# both 'vol' and 'vol.py' — if 'vol' is not found, try 'vol.py --help'.
vol --help | head -n 20
# what to look for: a version banner and the module list (windows, linux, mac).
strings --version && sha256sum --version   # yara only if you have a rule (section 8)
# First case-log line: case id, exhibit, examiner, date/time in UTC, and "Memory captured
# with <tool> <version> by <method> on <date> because <reason>."
```

## 3. Ethics, authorization and scope

The lab exercises a **detection** skill. What it stages is a benign, recorded marker in a process you own, so the signature is known in advance and "I found it" is distinguishable from "I imagined it".

- **Authorized targets only.** Your hypervisor, your VMs, the host-only network from `lab-environment.md`. Never a host you do not own, and never a production machine "to test the detection".
- **The victim is disposable and snapshotted first.** Revert to `03-<case>-before` between runs; revert rather than clean up.
- **Memory is captured on a live VM you own and analysed on `linux-lab`** — never on the machine it came from. That is the environment's one non-negotiable property (`lab-environment.md`, section 1).
- **No malware is authored or downloaded to make this work, and detection is the only skill in scope.** Path B is a documented in-process injection of a harmless payload against a process you started. If a step would need a real implant — or an evasion technique — stop: that is not this lab.
- **Evidence ethics apply here too.** Hash the dump on arrival, keep `evidence/` write-once, work on copies in `working/`, log the chain of custody, minimise data, and treat any dump from a real machine as sensitive.

> **The professional norm this lab deliberately breaks.** In a real case an examiner *never* generates the condition they investigate: they receive a machine in an unknown state and reason from what is there. This lab stages it anyway, for the same reason a training range exists — so the signature is known before you look for it, and a null result can be scored as "nothing there" instead of "I did not look properly". Write down what you staged *before* you analyse, and do not read it until your findings are written.

## 4. Building the condition

**Path A is the recommended default**: it needs no offensive tooling, is reproducible anywhere, and decouples the lab from your ability to write an injector.

| | Path A (recommended) | Path B |
| --- | --- | --- |
| Condition | A public memory sample documented to contain injected code | A minimal injection you stage in `win-lab` |
| Effort | Download, hash, document, analyse | Write and debug a short script; no installs |
| Ground truth | The sample's documentation — a *hypothesis* to test | Your own answer key, exact and auditable |
| Best for | Learning the analysis (and a second sample after Path B) | Seeing the signature while it is created |

### Path A — a public training memory sample

Use an image published for training or research: the memory samples the Volatility project distributes, or a DFRWS challenge dataset — both named as authorized practice material in [../tools/memory-analysis.md](../tools/memory-analysis.md) and used by Drill 4 of [forensic-exercises.md](forensic-exercises.md).

```text
1. Record the source: the page you got it from and the date you fetched it.
2. Hash it before any tool opens it:  sha256sum sample.raw | tee ~/lab/case-04/notes/source-hash.txt
3. Copy it into evidence/ as the exhibit; analyse a copy in working/.
4. Note what it is DOCUMENTED to contain (which process, which kind of injection) in
   notes/answer-key.md, then seal that file. Skip every build step below — section 5 onwards
   is unchanged.
```

> Treat the documentation as a hypothesis, not an answer. "Contains injected code in `explorer.exe`" is a claim made by whoever packaged the file. Find the region yourself and describe it in your own words; where your finding disagrees with the documentation, that disagreement is the most interesting thing the lab produces.

### Path B — generate the condition yourself, in the disposable VM

A minimal, documented, in-process injection against a process you own: allocate in the target with `VirtualAllocEx`, write a benign payload with `WriteProcessMemory`, execute it with `CreateRemoteThread`. Nothing else is needed, and nothing else should be added.

**Constraints at every step. These are not suggestions:**

- **Never against a system or security process.** The target is a `notepad.exe` *you* started in this session — not `lsass.exe`, `winlogon.exe`, `services.exe`, or your security product's process.
- **Never against another host.** The target is a PID on `win-lab`. If you give the payload a connection for the corroboration step, it points at a listener you own on `linux-lab` and nowhere else.
- **Never persisted.** No Run key, no scheduled task, no service, no leftover injector binary. The VM is reverted afterwards.
- **Never run outside this VM.** Script, dump and answer key stay in the case folder; nothing is copied to a daily driver.

```powershell
# On win-lab, as labuser, after reverting to '03-meminj-before'. Start the target yourself.
# $PID is reserved in PowerShell (it is the CURRENT process), so name yours something else.
$t = Start-Process notepad.exe -PassThru; $targetPid = $t.Id
# what to look for: the notepad.exe PID you just started — record it in the answer key.

# The three API calls this lab is allowed to use. A P/Invoke declaration has no --help: the
# reference is each function's page on learn.microsoft.com (linked at the end), where you also
# look up the access-right and protection constants by name.
$src = @'
using System;
using System.Runtime.InteropServices;
public class LabInject {
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr VirtualAllocEx(IntPtr p, IntPtr a, uint size, uint alloc, uint protect);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool WriteProcessMemory(IntPtr p, IntPtr a, byte[] buf, uint size, out uint written);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr CreateRemoteThread(IntPtr p, IntPtr at, uint st, IntPtr start, IntPtr par, uint fl, IntPtr tid);
}
'@
Add-Type -TypeDefinition $src
# what to look for: no compiler error — a half-loaded class fails later in a way that looks like
# an injection failure rather than a script error.

# The payload: harmless, terminating, RECORDED. The lab stub is a single-byte return — confirm
# that encoding for your architecture with a disassembler you trust, not with this comment.
$stub = [byte[]]@(0xC3)
$access = <ACCESS_RIGHTS>; $commit = <MEM_COMMIT>; $reserve = <MEM_RESERVE>; $execRW = <EXECUTE_READWRITE>

# Allocate, write, execute — one line at a time, checking each value before continuing.
$h = [LabInject]::OpenProcess($access, $false, $targetPid)
$addr = [LabInject]::VirtualAllocEx($h, [IntPtr]::Zero, [uint32]$stub.Length, ($commit -bor $reserve), $execRW)
$written = [uint32]0
[LabInject]::WriteProcessMemory($h, $addr, $stub, [uint32]$stub.Length, [ref]$written) | Out-Null
$thread = [LabInject]::CreateRemoteThread($h, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
# what to look for: non-zero process handle, allocation address and thread handle, and a write
# count equal to the payload length. The allocation address is the ground truth for the region
# you are about to hunt. Before capturing: the injected notepad.exe must still be running, PID
# and payload must be in the answer key, nothing may have been written to disk, and you must not
# have re-read the key — section 9 tests that absence.
```

## 5. Capture

Memory is only available live, so this is the one acquisition that cannot wait for a clean shutdown (`lab-environment.md`, section 8, step 3): capture memory **first**, then decide about the disk.

| Method | What it is | Honest limits |
| --- | --- | --- |
| Purpose-built acquisition tool on the live guest (FTK Imager, WinPmem, or the Linux equivalent — see [../tools/memory-analysis.md](../tools/memory-analysis.md)) | Code running *inside* the guest, reading the guest's own physical memory | Requires executing software on the victim: the tool's driver, its own allocations and any security product interfering with it all perturb the state you are capturing. Record tool and version. |
| Hypervisor snapshot of the VM's RAM (VMware `.vmem`, VirtualBox `dumpvmcore`) | The hypervisor's copy of guest physical RAM, taken from outside the guest | **Not equivalent to a live acquisition tool.** It is a different view: the guest keeps running (or is paused) while you copy, structures a live tool would walk may be absent or inconsistent, and anything paged out may simply not be there. A legitimate artefact — but not the same artefact, and your report must say which one you hold. |

Three things go in the case log whichever you use: **the tool, the version and the method** — plus whether the guest was running or paused, and how long the capture took.

```bash
# On linux-lab: prepare the destination, move the artefact across, hash it the moment it lands. The
# transport is your call (a virtual disk attached read-only, or your hypervisor's file-level copy of
# the RAM file) — record which you used.
mkdir -p ~/lab/case-04/{evidence,working/dumps,exports,notes}
sha256sum ~/lab/case-04/evidence/mem.raw | tee ~/lab/case-04/notes/dump-hash.txt
# what to look for: one hash line, and a size in the same order of magnitude as the guest's RAM. A far
# smaller dump is truncated and every plugin result from it is suspect. Log the row: date/time (UTC) |
# exhibit | action | source | destination | tool + version | SHA-256 | examiner.
```

## 6. Validate the dump before analysing it

The habit that prevents wasted days: **prove the dump is analysable before you interpret anything from it.** If symbols did not resolve, stop and fix that first — nothing downstream is trustworthy while the symbol table is wrong, and the failure is quiet, because plugins either error out or report structures at the wrong offsets.

```bash
cd ~/lab/case-04
cp evidence/mem.raw working/mem.raw      # analyse the copy, never the exhibit
vol -f working/mem.raw windows.info
# what to look for: framework version, detected OS and build, and a kernel symbol table that RESOLVED.
# Treat any "unable to find", "no symbols" or exception banner as failure, not as an empty result.

# Symbols are fetched per build and cached locally. Check the switch your build accepts (the directory
# form used across this repository is -s / --symbol-dirs) rather than assuming it:
vol --help
vol -f working/mem.raw -s ~/lab/symbols windows.info
# what to look for: the same successful symbol banner. If linux-lab is offline — it should be —
# pre-fetch the tables on a machine allowed to reach the symbol server, copy them in, and record where
# they came from in the case log.

# Validation gate — do not proceed past it:
#   [ ] windows.info names the OS and build and reports a kernel symbol table.
#   [ ] No plugin run so far produced an exception or a "no symbols" warning.
#   [ ] The dump size is consistent with the guest's RAM, and you recorded it.
#   [ ] You know whether you hold a live-tool capture or a hypervisor RAM file.
# A plugin that errors is a hint about a wrong or missing symbol set — never a clean result.
```

## 7. Analysis

Each step answers one question and feeds the next. Plugin mechanics, symbols and the Volatility 2/3 differences live in [../tools/memory-analysis.md](../tools/memory-analysis.md); this is the order and the reasoning for *this* case.

**First, confirm the plugin names and switches on your own build.** Names and option spellings change between releases, and a name you half-remember is how an afternoon disappears.

```bash
vol --help                                       # modules and plugin list for YOUR version
vol -f working/mem.raw windows.malfind --help    # a plugin's own options
# what to look for: that the plugin exists under that exact name, and the exact form of its
# switches — whether the dump option exists at all, and whether it takes a directory or a file
# path. Do this once, for every plugin below, and note any name that differs from this file's.
```

### Step 1 — Build the process inventory two ways and diff it *— what was present?*

```bash
vol -f working/mem.raw -r csv windows.pslist > exports/pslist.csv   # kernel linked list
vol -f working/mem.raw -r csv windows.psscan > exports/psscan.csv   # physical scan
head -1 exports/pslist.csv exports/psscan.csv
cut -d, -f<N> exports/pslist.csv | tail -n +2 | sort -u > working/pslist.pids
cut -d, -f<N> exports/psscan.csv | tail -n +2 | sort -u > working/psscan.pids
comm -13 working/pslist.pids working/psscan.pids
# what to look for: take the PID column name from the header and use its number for <N>. A PID the
# physical scan saw and the walk did not is hidden or already exited — note it, do not chase it yet.
```

### Step 2 — Inspect parentage and command lines *— does the story fit?*

```bash
vol -f working/mem.raw windows.pstree
vol -f working/mem.raw windows.cmdline --pid <PID>
# what to look for: a parent that does not fit (a document application or scripting host spawning a
# system-looking binary), and a command line carrying a path, argument or encoding that does not
# belong. In Path B the interesting command line is the injector's and the interesting parent is the
# shell that started the target.
```

### Step 3 — Check the modules loaded in the target *— which code came from disk?*

```bash
vol -f working/mem.raw windows.dlllist --pid <PID>
# what to look for: module paths, and any module loaded from a user-writable directory or whose name
# mismatches its location. This list is the complement of step 4: code in NO module has no file behind it.
```

### Step 4 — Find executable regions with no file behind them *— what did the loader not put there?*

```bash
vol -f working/mem.raw windows.malfind --pid <PID>
# what to look for: executable regions with unusual protection for a loaded image (write+execute is
# the loud case), no file on disk, and content that looks like code. The plugin scans virtual address
# descriptors for memory that is executable and not file-backed — a claim to verify, not a verdict, and
# step 5 tells you which of those two properties you have.
vol -f working/mem.raw windows.malfind    # sweep the whole image, not just the target
# If several processes show the same kind of region, suspect a JIT compiler, a security product or an
# unpacking runtime before an intruder.
```

### Step 5 — Read the virtual address descriptors *— private, or file-backed?*

```bash
vol -f working/mem.raw windows.vadinfo --pid <PID>
# what to look for: whether the flagged range is backed by a mapped file (and if so, which) or is
# private, committed memory that no file describes — the shape this lab is built around. Record start,
# size and protection from THIS output: it is your evidence description, readable without the plugin.
```

### Step 6 — Check handles and network state *— what was it doing, and what was done to it?*

```bash
vol -f working/mem.raw windows.handles --pid <PID>
vol -f working/mem.raw windows.netscan
# what to look for: whether the target holds a socket at all (a text editor should not), and whether
# an endpoint attributes to your PID. In the suspected injector, a handle to the target is one of the
# few artefacts linking the two, and it survives only while the injector lives — test that link in
# section 9; do not read it as proof of who did what.
```

### Step 7 — Take the region and the process memory off the image *— how do I preserve it?*

```bash
vol -f working/mem.raw -o ~/lab/case-04/dumps/ windows.malfind --pid <PID> --dump  # --dump is a flag
vol -f working/mem.raw -o ~/lab/case-04/dumps/ windows.memmap --pid <PID> --dump   # whole process
vol -f working/mem.raw -o ~/lab/case-04/dumps/ windows.dumpfiles --pid <PID>       # mapped files
sha256sum ~/lab/case-04/dumps/* | tee -a ~/lab/case-04/notes/evidence-hashes.txt
# what to look for: one output file per artefact, a hash for each, no write errors, and names and
# sizes matching the region you described in step 5. Confirm the extraction switch exists on your
# build first (vol ... windows.malfind --help) and use your build's spelling if it differs — your
# report must quote the command you actually ran.
```

## 8. Offline analysis of what you dumped

Leave the memory image alone now and work on the copies you extracted, on `linux-lab`, on artefacts that no longer need Volatility.

```bash
cd ~/lab/case-04
# A dumped region is preserved evidence: hash it, copy it, never overwrite it and never edit it in
# place. Analyse working/, keep dumps/ as the exhibit.
cp dumps/<region-file> working/<region-file>.copy && sha256sum dumps/<region-file>
# what to look for: the hash you recorded when you dumped it. If the two disagree, stop and find out
# why before you analyse either file.

# Strings, with the encoding Windows binaries actually use: narrow first, then UTF-16LE.
strings -a  working/<region-file>.copy | head -n 40
strings -el working/<region-file>.copy | head -n 40
# what to look for: a path, hostname, URL, key name, message, or the marker you planted. Note what is
# NOT there too: no readable strings is consistent with compressed, encrypted or hand-written code —
# and equally consistent with a JIT compiler's output, so do not read intent into an absence of text.

# Is the region the start of an image, or a fragment of one?
file working/<region-file>.copy
xxd working/<region-file>.copy | head -n 4      # or hexdump -C / od -A x -t x1z
# what to look for: whether the region begins with the image signature and, if so, what its header
# claims about sections and entry point. Check those values from YOUR dump against the PE format
# specification: a header claiming sections it does not contain is a strong sign of a fragment or a
# hand-written header, and both are worth writing down.

# YARA — only with a rule you can cite and are licensed to use.
yara --help && yara -r <your-rules>.yar dumps/
# what to look for: a rule name and match offset per hit. A rule matching the marker YOU planted proves
# the pipeline works — the point of the drill — and a rule match is a statement about strings, not about
# behaviour. Never pull in an unexplained rule set to turn a null result positive.
```

## 9. Corroboration

Memory finds a region. It rarely names an actor, and it never proves intent. This is where a lead becomes a finding — or honestly stays a lead.

| Check | Where it lives | What it would show |
| --- | --- | --- |
| Did the target's image on disk change? | Hash of the process's on-disk binary, against the hash you recorded at `02-baseline` | In-memory injection normally leaves the file **unchanged**. A changed image points at a different class of event — a replaced or modified binary — so re-read your finding in that light instead of forcing it to fit injection. |
| Did the injecting process exist on disk at all? | File-system timeline and the process's image path | A loader from a user-writable path is a different story from a legitimate scripting host (`powershell.exe`) that exists on every machine. That difference is why "a script did this" and "malware did this" are not the same finding. |
| Was there a process-creation event for either process? | Sysmon process-creation events, or Security 4688 with command-line auditing — *if* auditing was enabled (`lab-environment.md`, section 6, step 3) | Ground truth for *when* both started, and an independent record of their command lines. Where auditing was off, "this artefact does not exist" is itself a result to report. |
| Is there injection-specific telemetry? | Process-access and remote-thread-creation events in the Sysmon channel, plus PowerShell script-block logging if the injector was a script | Independently records the injector→target relationship. **Verify the event identifiers against the schema of the Sysmon version and configuration you installed** — a config decides which events exist, and one never collected looks exactly like one that never happened. |
| Do the region's contents appear anywhere on disk? | A full-disk search, unallocated space included, for a distinctive string from the region (`bulk_extractor`, or a raw search over the image) | If the string is there, a file carried it at some point. If it is not, that is *consistent* with memory-only execution — but see section 11: absence in a disk image is weak evidence, and you must say so. |
| Does network state corroborate a purpose? | The socket list from memory, the firewall or proxy log, and any listener you own in the lab | A connection attributed to the injected PID, to an address that also appears inside the region, is real corroboration: two artefacts, one conclusion, obtained independently. |

Write negative corroboration down too. "No process-creation event exists for either process, because process-creation auditing was not enabled on this host" is a finding about the environment, and the kind of sentence that makes a report credible.

> **The rule, stated plainly: memory evidence alone is a strong lead; a finding is memory plus at least one independent artefact.** An executable region with no file behind it says something ran that does not live on disk. It does not say who put it there, when, or why. Until a second, independently acquired artefact agrees, call it a lead.

## 10. What you should observe

Described as behaviour and signature, never as output — what you actually see depends on your sample, your path and your build. The analysis should surface:

- **An executable region with no corresponding file on disk** inside the target, reported by the executable-region scan and confirmed as private rather than file-backed by the descriptor view.
- **A private, committed region in a process that does not normally generate code at runtime.** A text editor holding write+execute private memory is the shape — and a shape is a question, not a conclusion.
- **A discrepancy between the linked-list walk and the physical scan**: a PID one inventory reports and the other does not. Often benign (a process that exited but remains resident); occasionally the only trace of something that tried not to be listed.
- **A thread whose start address lies outside any mapped module** — the executing side of the injection. Note that a start address *inside* a legitimate module (a remote `LoadLibrary`-style call) is a different and much weaker signature, and that a legitimate thread pool can also show unusual start addresses.
- **The negative control, which you must run**: on the same dump, examine an ordinary process whose executable regions look alarming — a browser or a .NET runtime generating code through a just-in-time compiler, or a security product injecting its own components into other processes. Those regions are legitimately executable, legitimately private and legitimately absent from disk. That is exactly why **an executable region is not by itself proof of malice**, and why the analysis has to distinguish the two shapes — or admit that it cannot.

If your dump contains only the negative-control shapes, that is a valid outcome, provided you can show what you looked for and what you ruled out. A null result you can defend outranks a finding you cannot.

## 11. What this evidence cannot show

- **It usually cannot tell you *who* injected.** A region has no author. Process handles, parentage and command lines are associations between artefacts, not attribution to a person, and an injector that has exited leaves the target holding nothing that names it.
- **It cannot distinguish malicious from legitimate injection on signatures alone.** Executable, private, non-file-backed memory is what a JIT compiler, a security product's hooking engine, an unpacking runtime and an implant all produce. The discriminating work is contextual: which process, which host, what else agrees, and what your baseline says is normal here.
- **A dump is a snapshot, biased toward whatever was resident.** Paged-out memory may be absent or incomplete; freed pool memory may have been reused before capture; the capture tool's own footprint is in the image you are analysing. Timing cuts both ways — capture too late and the region is gone, too early and it does not exist yet.
- **Absence is not evidence of absence.** A region missing from this dump may never have existed, may have been freed before capture, or may simply not have been captured. "The region was not present in the image I hold" is the strongest sentence you are entitled to write.
- **A hash proves integrity, not authenticity.** It shows the file did not change after you hashed it. That the dump came from the machine you say it did is proven by your acquisition record and chain of custody — which is why `lab-environment.md` insists on both.

> Where this reasoning lives in full: the anti-forensics and evidence-integrity discussion in [../methodology/08-anti-forensics-and-evidence-integrity.md](../methodology/08-anti-forensics-and-evidence-integrity.md), and the limits to quote in a report in [../cheatsheets/evidence-validity.md](../cheatsheets/evidence-validity.md).

## Common Mistakes & Tips

- **Analysing on the machine you captured from.** The one error that invalidates everything downstream. `win-lab` captures, `linux-lab` analyses, always.
- **Interpreting before validating.** A wrong symbol set makes plugins fail or lie, and a truncated dump makes them lie quietly. Run the section 6 gate first, every time.
- **Trusting one plugin.** The executable-region scan and the descriptor view answer different questions. A region is interesting when both agree; a claim built on one alone is a claim about a plugin, not about memory.
- **Forgetting the negative control.** Run the same plugins against an ordinary process on the same image before you characterise your finding, or you cannot tell an anomaly from a Tuesday.
- **Treating a JIT or a security product as an intruder.** Generated code that is executable and private is normal in several legitimate runtimes. Reach for context before you reach for a conclusion.
- **Writing to `evidence/`, or overwriting a dump.** Preserve, hash, copy, analyse the copy. A dump you overwrote is an exhibit you destroyed.
- **Staging before snapshotting, or snapshotting mid-injection.** Take `03-<case>-before` first; this lab's exhibit is a *live* state, so a snapshot never substitutes for the memory capture.
- **Reading the answer key early.** The moment you read what you staged you are confirming, not testing. Write your findings first.
- **Assuming a public sample's documentation is the answer.** It is a claim by whoever packaged the sample. Where your finding disagrees, investigate the disagreement instead of adjusting your finding.
- **Losing the acquisition record.** Tool, version, method, time, hash. A dump without them is a file with an interesting shape.
- **Tip:** write the finding as one sentence with two clauses — what you saw, and what corroborates it. If you cannot fill the second clause, say "lead".

## Checklist / Self-Test

- [ ] I can state, in one sentence, the authorization covering the VMs and network this lab runs on.
- [ ] I recorded whether I used Path A or Path B — and for Path A the sample's source, its hash, and what it is documented to contain.
- [ ] For Path B I targeted only a process I started myself: nothing system-owned, nothing network-facing, nothing persisted.
- [ ] I captured memory with a named tool and version, and wrote the method and time into the case log.
- [ ] My dump has a SHA-256 recorded before any tool opened it, and its size is consistent with the guest's RAM.
- [ ] `windows.info` reports the OS, the build and a resolved symbol table, with no plugin errors behind me.
- [ ] I built the process inventory both ways and can explain any PID that appears in only one.
- [ ] I inspected the target's parentage, command line and modules, and can say which of its code is file-backed.
- [ ] I located an executable, non-file-backed region and confirmed from the descriptor view whether it is private or file-backed.
- [ ] I dumped the region and the process memory, hashed both, and analysed copies rather than the originals.
- [ ] I examined the dumped region offline — both string encodings, the header, a hash — and recorded what I did and did not find.
- [ ] I ran the negative control on an ordinary process and can explain why its executable regions are legitimate.
- [ ] At least one artefact outside memory corroborates or contradicts my finding, and I wrote down which.
- [ ] I can name one thing this evidence cannot show, and I said so in my notes rather than in a footnote.

## Further Resources

- **Volatility 3 documentation** — installation, symbols, plugin reference: https://volatility3.readthedocs.io/
- **Volatility Foundation** — the project's tools and the memory samples it publishes for training: https://github.com/volatilityfoundation
- **DFRWS challenge archives** — authorized practice datasets, including memory images: https://dfrws.org/
- **MITRE ATT&CK, T1055 Process Injection**, and its sub-techniques — the behaviour this lab detects: https://attack.mitre.org/techniques/T1055/
- **Microsoft Win32 API reference** — `VirtualAllocEx` (https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex), `WriteProcessMemory` (https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory), `CreateRemoteThread` (https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread). If a page has moved, search the function name on learn.microsoft.com: the parameter lists and access-right constants are the parts you must not guess.
- **Sysmon** — the event schema that decides which corroboration artefacts in section 9 can exist at all: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- **YARA documentation** — rule syntax and scanning options: https://yara.readthedocs.io/
- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **RFC 3227**, *Guidelines for Evidence Collection and Archiving* — order of volatility, which is why memory is captured first: https://www.rfc-editor.org/rfc/rfc3227
- **This repository:** [../cheatsheets/forensic-commands.md](../cheatsheets/forensic-commands.md) for command forms, and [forensic-exercises.md](forensic-exercises.md) Drill 4 for the basic memory drill this lab assumes.

> **Verification:** executed against **Volatility 3 Framework 2.28.2** on **2026-09-19**.
> `vol --help` prints `-s SYMBOL_DIRS, --symbol-dirs SYMBOL_DIRS` (plural), and the plugin
> namespaces listed by the plugin chooser and by `ls framework/plugins/` are `linux`, `mac` and
> `windows` — there is no `macos`. `vol windows.memmap --help` prints
> `usage: vol windows.memmap.Memmap [-h] [--pid PID] [--dump]` with `--dump` a flag taking no
> argument; the global `-o` must precede the plugin name (`vol -f x windows.memmap --pid 1 --dump
> -o /tmp` → `vol: error: unrecognized arguments: -o /tmp`), and the dump is written as
> `pid.<PID>.dmp`. **Not executed:** `windows.malfind --dump <dir>` and
> `windows.dumpfiles --pid <PID> --dump` on lines 256 and 258 — both were verified to be
> malformed (`malfind --dump` is a flag, and `dumpfiles` has no `--dump` option at all; its
> `--help` lists only `--pid`, `--virtaddr`, `--physaddr`, `--filter`, `--ignore-case`), but they
> fall outside the correction this pass was scoped to and were left as written.
