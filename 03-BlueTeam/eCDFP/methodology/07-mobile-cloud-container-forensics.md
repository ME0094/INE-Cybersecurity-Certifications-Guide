# Mobile, Cloud and Container Forensics (eCDFP Methodology — Phase 07)

> Companion study guide for the eCDFP (Certified Digital Forensics Professional) Blue Team methodology track. Phases 02 and 05 assume a disk you can detach and a host you control. This phase covers the three environments where that assumption fails: a phone you cannot open, a cloud account whose disks you never touch, and a container that may not exist by the time you look.
>
> Where this phase sits: it applies the same discipline as Phases 01–03 — preserve, verify, analyse a copy, report with limitations — to evidence you obtain through a device interface or a provider API instead of through a write blocker.
>
> Every command in this file is a **syntax reference**. This repository ships no captured output: there is no device, no cloud account and no container runtime on the machine that wrote it. Where a command would print a result, the text says what to look for. Confirm flags and subcommands with `--help` or the vendor documentation for the version you actually use, and treat extraction-tool capabilities as version-specific claims to verify rather than facts.

## Overview

The two environments in this phase look unrelated and share the same structural problem: **you do not control the platform.** On a phone, the platform owner decides what can be extracted and under which conditions. In the cloud, the provider holds the hardware, the hypervisor and often the only copy of the log you need. In a container, the "machine" is a construct assembled at runtime and destroyed on restart.

That inversion has three consequences for method:

1. **Acquisition is an interaction, not a copy.** You negotiate with a lock state, an API, a provider's support process, or a snapshot facility. Every one of those interactions needs the same documentation as a `dd` — and often has an authorization requirement attached.
2. **Some evidence has a deadline measured in minutes.** A running cloud instance that gets terminated, a container that restarts, a phone that receives a remote wipe, a log bucket with a short lifecycle rule. Preservation decisions here come first and analysis later.
3. **Identity is usually the primary evidence.** In cloud and mobile cases the central question is frequently "which identity did this", because that is what the available records are organised around.

## 1. Mobile forensics — what you can get, and what it costs

NIST SP 800-101 (*Guidelines on Mobile Device Forensics*) is the reference framing for this section; the extraction taxonomy below follows the way that guidance and vendor practice classify acquisition levels. Check the current revision for exact terminology, because it has evolved with the platforms.

### 1.1 The acquisition levels

| Level | What it produces | What it misses | Requires |
| --- | --- | --- | --- |
| **Manual** | Photographs of what is on screen, transcribed notes of what you navigated to | Almost everything, and it is not a copy so it cannot be verified | Nothing but discipline and a camera |
| **Logical** | Data available through the device's own interfaces: contacts, messages, call logs, media, some app data — typically what a backup contains | Deleted data, unallocated space, app-private databases, system artefacts | An unlocked device, or a backup channel |
| **Backup-based** | A structured extraction of the data the backup service includes (device backup files, or a per-app backup channel) | Anything the app excluded, and anything the platform version no longer allows to be backed up | Credentials, and often the device itself |
| **File system** | The file system itself — including app databases, caches and logs that a logical extraction does not expose | Data not referenced by the file system; sometimes encrypted volumes | A supported exploit, an unlocked bootloader, or vendor tooling |
| **Physical** | A bit-for-bit image of the storage, including unallocated space and deleted records | Nothing in principle — but encryption in practice may reduce it to ciphertext | Exploit capability, correct lock state, and often vendor tooling |
| **Over the air / cloud account** | Data the user's account holds: synced messages, photos, location history, backups held by the provider | Local-only data, and anything not synchronised | Account credentials, authorization, and often legal process |

The practical rule: **the highest level you can legitimately reach is usually lower than the level you would like**, and the limitation belongs in the report. "A logical extraction was performed because the device was running a patched OS version with no supported file-system capability; deleted records were therefore not recoverable" is a professional sentence. Silently presenting a logical extraction as if it were complete is not.

### 1.2 Lock state, encryption and the clock you are racing

Modern mobile devices encrypt storage, and the key material depends on the lock state. The distinction that matters:

- **Before the first unlock after boot** — much of the user data is inaccessible even with a supported extraction method, because the keys are not yet available in memory.
- **After the first unlock** — the device holds keys in memory, so far more is reachable until the next power cycle.

Consequences to plan for:

- **Do not power the device off reflexively.** On a device where you need data that is only reachable in the post-first-unlock state, a power cycle can take it out of reach.
- **Do not let it lock out.** Repeated failed unlock attempts can trigger escalating delays or an automatic wipe, depending on configuration. Handle the device deliberately, not repeatedly.
- **Isolate it from the network, on purpose.** A phone that stays connected can receive a remote wipe command, can sync state changes that overwrite what you were about to look at, and can receive messages that change the very artefact you are documenting. The standard measures are airplane mode (verified in the UI, and re-verified, because it can be turned off remotely on some platforms) or a Faraday enclosure. Whatever you choose, document it — including the fact that a Faraday bag changes the device's behaviour (no time synchronisation, no incoming events).
- **Record the device clock and time zone immediately**, alongside the device model, OS version, serial number and the state you found it in.

### 1.3 Artefact families and the question each answers

| Artefact | Question it answers | Notes |
| --- | --- | --- |
| Call logs | Who spoke to whom, when, for how long, and whether it connected | Device-local; carrier records are an independent source |
| Messages (SMS and app-based) | Content, participants, timestamps | App data may be encrypted at rest and reachable only via a file-system extraction |
| Contacts, calendar | Associations and planned activity | Often synced to an account — the cloud copy may be the one you can obtain |
| Location history | Where the device was | Comes from the platform account, not the device, on many configurations |
| Photos and videos | Content plus embedded metadata (device, settings, and often coordinates) | Only a file-system or physical extraction reliably preserves the original files and their metadata |
| App-private databases | Application-specific activity (chat, fitness, finance) | SQLite in most cases; deleted rows may survive in free pages |
| Wi-Fi and cell association history | Which networks and cells the device joined | The strongest device-local movement evidence when location history is unavailable |
| Device and app settings, permissions | Configuration and capability | Answers "could this device have done that?" |
| Local notifications and keyboard or clipboard caches | Evidence of content that the user may have deleted in the app | Frequently overlooked; extraction-dependent |

Two mobile-specific cautions:

- **The app's own display is not the record.** A conversation that looks deleted in the app's UI may still exist in its database free pages; conversely, a message visible on screen may be a server-side rendering that never reached the local database.
- **Cloud copies are evidence too, and they have their own chain of custody.** Data obtained from an account is not the same exhibit as data obtained from the device, and the two can disagree — which is itself a finding worth reporting.

### 1.4 Mobile-specific anti-forensics

Factory reset, app-level "secure delete", encrypted chat that never writes plaintext, and vendor-implemented wipe-on-tamper all reduce what remains. What frequently survives anyway is worth knowing: device identifiers and activation records, the account's cloud-side history, carrier and network records, the backups the user made before the incident, and the counterparties' devices. A case that looks empty on the device is often not empty in the environment.

### 1.5 Ethics, magnified

A phone is the most personal evidence source in a typical investigation: messages, location, health, relationships. That makes three rules non-negotiable rather than aspirational:

- **Authorization in writing, with a defined scope and window**, before any extraction.
- **Minimization**: extract what the scope requires. A full physical image "in case it is useful later" is a data-protection problem, not thoroughness.
- **Documented handling**: the same chain-of-custody discipline as Phase 01, including the Faraday/isolation decision, the lock state, the extraction level, the tool and version, and every interaction with the device.

## 2. Cloud forensics — evidence you own without possessing it

### 2.1 What changes when the evidence is in someone else's data centre

| Assumption from disk forensics | What replaces it in the cloud |
| --- | --- |
| You can detach the disk | You can, in IaaS, sometimes snapshot and export a volume — through the provider's API, with the provider's retention and cost model |
| Evidence is local and static | Resources are created and destroyed on demand; logs expire on lifecycle rules |
| The machine's clock is the timeline's anchor | Every event carries a provider-generated UTC timestamp, which is usually better than a local clock |
| You can hash the original | You can hash what the API returned; the provider's internal state is not yours to hash |
| Chain of custody is your log | Chain of custody includes the provider's records, your API calls, and often a legal process |
| The suspect could not have altered the disk | The suspect may have had administrative rights over the same account, meaning they could alter or delete the same logs you need |

### 2.2 What you can actually obtain

| Evidence | How it is obtained | What it answers | The catch |
| --- | --- | --- | --- |
| Control-plane audit logs (the provider's API activity record) | Log service query or export | Who called which API, from where, with which parameters, and whether it succeeded | Retention is configurable and often short; the account's own administrator may be able to change it |
| Identity and sign-in logs | Identity provider console or API | Authentication, source address, client application, conditional-access outcome | Federated chains span several providers — you may need two of them |
| Resource configuration and metadata | Read-only API calls, infrastructure-as-code repositories | What existed, how it was configured, and who changed it | A snapshot of *now*; deleted resources leave nothing unless the change was audited |
| Object storage access logs and versioning | Storage service logging; object versions | Who read or wrote which object | Access logging is frequently off by default; versioning may be disabled |
| Block storage snapshots or volume exports | Snapshot, then export or attach to a controlled instance | A file-system image you can analyse with Phases 02 and 05 | You are creating a new artefact, not copying an existing one — document that |
| Instance memory | Rare; usually requires agent-based capture before the instance is stopped | In-memory state, keys, injected code | Ephemeral and normally gone by the time an incident is discovered |
| Platform and application logs | The log service, from agents or native integrations | Application behaviour, errors, access patterns | Volume and cost; sampling and filtering may apply |
| SaaS tenant data | Administrative export or an eDiscovery facility | Mail, documents, collaboration activity | Requires tenant-level authorization and usually legal involvement |

### 2.3 The preservation order for a cloud incident

The windows close in a specific order, so act in this order:

```text
1. PRESERVE THE AUDIT TRAIL. Export the control-plane and identity logs for the window
   FIRST and to storage the compromised account cannot write to. This is the most
   perishable and most valuable evidence in the environment.
2. STOP THE DESTRUCTION. Suspend automatic lifecycle rules, disable scheduled instance
   termination, and — carefully — isolate the affected resources so they are not
   automatically replaced while you work.
3. SNAPSHOT THE VOLUMES. Snapshot every attached volume before anything is stopped,
   rebuilt or terminated. Record snapshot IDs, creation times and regions.
4. RECORD THE CONFIGURATION. Export the resource metadata and the orchestration
   manifests as they are now.
5. TAKE THE IDENTITY RECORD. Export sign-in logs, key and token creation events, and
   role or policy changes for the window and a margin either side.
6. NOTE THE BOUNDARIES. Account/subscription/project identifiers, regions, resource IDs,
   and the retention of each source you touched.
```

**Your own API calls land in the same audit log.** That is useful — it gives you provenance for what you did — and it is also a contamination risk if you mutate resources while investigating. Prefer read-only calls, record what you called, and note when you made an exception.

### 2.4 Cloud-specific anti-forensics

The techniques mirror the on-premises ones with different names: deleting or shortening log retention, disabling an audit integration, deleting a resource so its history disappears with it, changing identity configuration to hide a grant, and creating new credentials that are used once and discarded. The defensive consequence is the same as Phase 05's: **the configuration change leaves its own record**, and the audit trail's own settings are evidence in their own right. Check who last changed the logging configuration and when — that question has ended more cloud investigations than any packet capture.

### 2.5 Reference material

NIST SP 800-145 defines the service and deployment models the vocabulary depends on, and NIST SP 800-86's process model still applies once you have evidence in hand. Cloud-specific forensic guidance is published by standards bodies and by the providers themselves, and it changes faster than the standards — check the current NIST publications list at csrc.nist.gov and your provider's own security and compliance documentation rather than relying on a citation you half-remember.

## 3. Containers and orchestration

### 3.1 The forensic shape of a container

A container is not a small virtual machine. It is a process (or set of processes) on a host, running against a layered file system:

```text
   read-only image layers   ─┐
   read-only image layers   ─┼─►  union mount  ──►  what the process sees as "/"
   writable layer (per container) ─┘
```

Three consequences:

- **"The container's disk" is a construct.** The interesting data is frequently in the writable layer, or in a volume the container mounted from the host, or in the image it was started from — three different locations with three different acquisition paths.
- **Restart destroys the writable layer.** Any evidence written inside the container and not in a mounted volume disappears on recreation. This is the docker equivalent of a machine that deletes its own disk on reboot.
- **The host sees what the container does.** Processes, network connections and most file activity are visible from the node, through the container's namespace. That makes *node-level* collection the most reliable approach, and namespace-aware analysis the interpretative skill.

### 3.2 Where the evidence lives

| Location | Content | How to obtain it |
| --- | --- | --- |
| Writable layer | Files created or modified inside the container | Copy it from the node's storage before the container is replaced, or export the file system |
| Image layers and image metadata | What was baked in at build time, and the build history | The registry's image metadata and digests; the build pipeline's configuration |
| Mounted volumes | Application data that is meant to persist | Volume snapshots or the host path backing the volume |
| Container logs | Whatever the process wrote to standard output and standard error | The runtime's log driver, or the orchestrator's log store |
| Runtime metadata | Creation time, configuration, mounts, environment, labels | The runtime's inspect interface and the orchestrator's API |
| Orchestrator state | Pod specifications, events, role and admission configuration | The orchestrator's API and its audit log |
| Node logs | Kernel, runtime daemon, and container lifecycle events | The node — the same acquisition discipline as any Linux host |
| Registry provenance | Which image, which digest, which pipeline produced it | The registry, plus the CI/CD system's records |

```bash
# Discovery, not a recipe. Confirm the exact syntax and subcommands for your runtime.
docker ps -a --no-trunc                    # full command lines and container IDs
docker inspect <container>                 # mounts, env, creation time, state
docker diff <container>                    # files changed since the image was started
docker logs <container>                    # stdout/stderr as the log driver captured it
# What to look for: environment variables holding credentials, host paths mounted in,
# and a change set in `diff` that includes files you would not expect a clean image
# to produce.
```

```bash
# Exporting the file system. Note the inconsistency caveat below before you use this
# on a running container.
docker export <container> > container-fs.tar
docker save <image> > image-layers.tar
# What to look for: the files you extracted, and whether the export's timestamps are
# plausible for when the container ran.
```

**The consistency caveat matters.** Exporting or committing the file system of a *running* container captures a moving target, exactly like imaging a mounted file system. Where the case depends on the writable layer's precise contents, prefer snapshotting the node or freezing the container first, and document which you did. Where you snapshot the node, remember that the snapshot contains the whole host, so your analysis has to be namespace-aware to attribute anything to a specific container.

```bash
# Orchestrator-side evidence. Subcommand sets differ between versions and between
# managed offerings: confirm with --help against your cluster's client.
kubectl get pods -A -o yaml > pods.yaml
kubectl logs <pod> --all-containers > pod.log
kubectl describe pod <pod> > pod-describe.txt
# What to look for: pod specs that mount host paths, run privileged or with added
# capabilities, pull an unexpected image, or were created by an identity that should
# not be able to create workloads. The API audit log is the artefact that names who
# did it.
```

### 3.3 Container memory and process analysis

Because a container's processes are processes on the host, container memory analysis is host memory analysis with a namespace filter. Practically: capture the node's memory, then attribute artefacts to a container by namespace and cgroup, or by the image and command line the process was started with. The analysis skills are Phase 05's; the attribution skill is knowing that `nginx` on the node and `nginx` in the container may be the same binary and different workloads.

### 3.4 Retention: the reason containers are hard

The characteristic failure of container forensics is not technical difficulty — it is that the evidence window is minutes to hours, and the infrastructure is designed to erase it. Orchestrators recreate containers; volume lifecycles expire; log drivers rotate; image tags are overwritten while digests persist. The mitigating discipline is entirely pre-incident: ship container logs and orchestrator audit logs somewhere durable, keep node-level logging on, prefer immutable image digests over mutable tags, and know which volumes exist and where they are backed up. In an investigation, that preparation is the difference between a reconstruction and a guess.

## 4. Decision table — what to preserve first

| Scenario | Preserve first | Where the evidence lives | If you wait |
| --- | --- | --- | --- |
| A phone that is on and unlocked | Isolation and lock state, then capture the volatile/account state; decide the extraction level | Device + the user's cloud account | Remote wipe; screen lock; a power cycle that changes what is reachable |
| A phone that is off | The account-side data and any backups, in parallel with the device work | Provider account, carrier records, backups | Account-side retention windows close |
| A running cloud instance in scope | Control-plane and identity logs, then snapshots | Provider log service and storage volumes | Instance termination; log lifecycle rules; credential rotation that hides the trail |
| A compromised cloud identity | Identity audit trail and the configuration change history | The provider's audit logs | The logs age out, and the attacker with account rights can shorten their retention |
| A suspicious container still running | Node log collection and the writable layer | Node storage, log driver, orchestrator audit log | Recreation erases the writable layer |
| A container that already restarted | Image digest, orchestrator audit log, volume contents | Registry, orchestrator logs, volumes | Tags get overwritten; short audit retention closes |
| A serverless function | Provider logs and invocation records | The provider's log and trace services | Frequently the only record, with the shortest retention in the environment |

## Common Mistakes & Tips

- **Presenting a logical mobile extraction as if it were complete.** State the level, the lock state, the tool and version, and what the level cannot reach — deleted data above all.
- **Powering a phone off out of habit.** On a device you need data from, a power cycle can put the user data behind keys that are no longer available.
- **Handling a phone repeatedly without isolation.** Attempts, re-locks, incoming syncs and remote wipe all change the exhibit. Isolate, verify it, and document how.
- **Imaging a running container and calling it a snapshot.** Export or commit on a live container captures a moving file system; prefer a node snapshot and say which you used.
- **Forgetting the writable layer.** The image is public and replaceable; the writable layer is the evidence, and it disappears on recreation.
- **Treating the container as a machine.** It is a namespace on a host: collect at the node, analyse with attribution, and remember the host sees everything the container does.
- **Collecting cloud logs after snapshotting volumes.** The audit trail is the most perishable and most probative evidence in the environment — preserve it first.
- **Ignoring who can edit the logs you rely on.** In a cloud account, the suspect may hold the same administrative rights you do. Prefer exporting to storage the account cannot write.
- **Ignoring your own footprint.** Your API calls appear in the same audit log. Keep them read-only where possible and record what you changed.
- **Over-collecting personal data on a phone.** Minimization is a legal requirement, not a courtesy. Extract to scope and record why.
- **Assuming a factory reset erases everything.** Carrier records, cloud-side history, backups, and counterparties' devices usually survive it.
- **Tip:** write the preservation order for your own environment *before* an incident — account IDs, log retention, volume locations, who can authorize an export. The plan is the deliverable you will be glad to have.
- **Tip:** for every artefact in this phase, record which party produced it. A provider-generated timestamp is independent evidence; a device-generated one is a claim by the device.

## Checklist / Self-Test

- [ ] Can I name the mobile acquisition levels and state what each one can and cannot reach?
- [ ] Can I explain why lock state and the first-unlock boundary change what is recoverable?
- [ ] Can I describe how I would isolate a phone, verify it is isolated, and document that decision?
- [ ] Can I name the mobile artefact families and one question each answers?
- [ ] Can I state the minimization rule for mobile evidence and why it is a legal requirement rather than a style choice?
- [ ] Can I list the cloud evidence sources available in a typical IaaS account and what each answers?
- [ ] Can I state the preservation order for a cloud incident and justify why the audit trail comes first?
- [ ] Do I know, in my own environment, the log retention for control-plane and identity logs, and who can change it?
- [ ] Can I explain what a container's writable layer is, and what destroys it?
- [ ] Can I name three places container evidence lives, other than inside the container?
- [ ] Can I describe the consistency problem with exporting a running container, and the alternative I would prefer?
- [ ] For my last case in any of these environments, can I state which artefact came from the platform and which came from the suspect-controlled side?

## Further Resources

- **NIST SP 800-101 Rev. 1**, *Guidelines on Mobile Device Forensics* — https://csrc.nist.gov/publications/detail/sp/800-101/rev-1/final
- **NIST SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response* — https://csrc.nist.gov/publications/detail/sp/800-86/final
- **NIST SP 800-145**, *The NIST Definition of Cloud Computing* (the vocabulary of service and deployment models) — https://csrc.nist.gov/publications/detail/sp/800-145/final
- **ISO/IEC 27037**, *Guidelines for identification, collection, acquisition and preservation of digital evidence* — https://www.iso.org/standard/44381.html
- **ISO/IEC 27050** (electronic discovery, relevant to obtaining data held by third parties) — https://www.iso.org/standard/44459.html
- **NIST Computer Security Resource Center publications list** (for the current cloud and mobile guidance, which is updated more often than any citation) — https://csrc.nist.gov/publications
- **DFRWS challenge archives** (authorized practice datasets, including mobile images) — https://dfrws.org/

> **Verification:** checked against source, not executed — **no command in this file was run**. The
> publication title was corrected on **2026-09-19** against the NIST CSRC record, which names
> SP 800-101 Rev. 1 *Guidelines on Mobile Device Forensics* (not "Mobile Phone Forensics"):
> https://csrc.nist.gov/pubs/sp/800/101/r1/final.
