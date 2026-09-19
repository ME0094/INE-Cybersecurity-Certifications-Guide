# Identity and Privileged Access Management

> eEDA · Methodology — Enterprise Defense Administrator
>
> Phase 06. Identity is the control plane of an enterprise: every other control is enforced *by* an account, *for* an account, or *against* an account. Phase [04-security-engineering](04-security-engineering.md) covers the design principles of identity; this phase covers the operational work an administrator owns — lifecycle, reviews, privileged access patterns, service accounts, and the evidence that proves access is actually controlled.

## Purpose

Most breaches do not begin with a clever exploit; they begin with an account that had more access than it needed, for longer than it needed it. The administrator's side of identity work is therefore unglamorous and decisive: provision and deprovision accurately, review entitlements on a schedule, keep standing privilege small, make elevation temporary and recorded, and keep service credentials out of documents, scripts, and repositories. This guide gives you the lifecycle checklists, review designs, privilege decision tables, and evidence artifacts for that work, and maps them onto **CIS Controls v8 controls 5 (Account Management) and 6 (Access Control Management)**.

## The Identities You Actually Have to Manage

"Users" is the easy half. The population an administrator is accountable for is wider, and each class fails differently.

| Identity class | Typical count vs. users | Failure mode | Control that catches it |
|---|---|---|---|
| Workforce accounts | 1× baseline | Orphaned after departure or role change | Joiner-mover-leaver process, access review |
| Privileged admin accounts | <5% | Standing rights, shared credentials, no MFA | Tiered administration, JIT elevation, PAM |
| Service accounts | Often hundreds, usually untracked | Password never rotated, interactive logon allowed, owner unknown | Service account inventory and rotation |
| Workload/managed identities | Growing with cloud use | Over-scoped role assignments, never reviewed | Cloud IAM review, least-privilege roles |
| Break-glass accounts | 2 (by design) | Credentials unknown, unmonitored, unusable when needed | Sealed storage, monitored use, periodic test |
| Vendor / third-party | Few, high risk | Access outlives the contract | Contract-linked access with expiry |
| Local device accounts | One per endpoint | Shared local admin password across the fleet | Managed local admin solution, unique passwords |
| Application secrets and API tokens | Uncounted | Committed to repositories, never rotated | Secret scanning, secrets manager, rotation policy |

> The inventory problem from [05-asset-inventory-and-configuration](05-asset-inventory-and-configuration.md) applies to identities too: you cannot review, rotate, or revoke an account that nobody listed. Treat the service-account list as you treat the asset register — reconciled on a schedule, with an owner per row.

## Joiner, Mover, Leaver

Provisioning is a request-and-approve workflow; **deprovisioning is a security control with a clock on it**. Design all three stages explicitly.

### Joiner

```text
[ ] Request comes from the hiring manager with role and start date.
[ ] Role maps to a defined access baseline (role-based, not "same as my colleague").
[ ] Account created in the directory; unique ID; no shared credentials.
[ ] MFA enrollment is completed BEFORE first privileged access, not after.
[ ] Access granted by group membership, never by direct per-account rights.
[ ] New starter acknowledges the Acceptable Use Policy, and the acknowledgment is stored.
[ ] Ticket closed with the account name and the groups granted.
```

### Mover

This is where most organisations leak privilege, because nothing forces a review when someone changes team.

```text
[ ] Role change triggers an access review of the OLD role's entitlements.
[ ] Access that no longer matches the new role is removed, not "kept for handover".
[ ] Privileged access from the old role is revoked the same day, not at the next review.
[ ] Any exception is recorded as a time-boxed grant with an expiry date.
[ ] Evidence: before/after group membership for the account.
```

### Leaver

The deprovisioning clock is the metric auditors sample hardest ("pick 20 leavers, show access was removed").

```text
T+0     Session revocation: disable the account (do not delete yet — you need the SID trail).
T+0     Revoke active sessions and refresh tokens; disabling alone does not kill a live session.
T+0h    Remove from all groups, including privileged groups and distribution lists.
T+0h    Revoke VPN, SSO and third-party application access; SaaS apps are the usual survivor.
T+24h   Forward or archive mailbox and file shares per retention policy; transfer ownership of data.
T+24h   Recover and rotate any credentials the leaver knew: local admin passwords on devices
        they touched, shared service accounts, break-glass credentials accessible to them.
T+7d    Confirm no authentication events since departure (a positive check, not an assumption).
T+30d   Delete or move to a documented retention state; record the final disposition.
```

Common survivor list to check explicitly on every leaver: personal cloud sessions on managed devices, API tokens created by the leaver, CI/CD deploy keys, shared mailboxes, distribution lists, MFA device registrations, and vendor portals where the account was created directly by the individual.

> "Disabled" is not "deprovisioned". An account that is disabled but still in twelve groups will be re-enabled by a helpdesk ticket six months later — with all twelve memberships intact. Remove the entitlements *and* disable the account.

## Access Reviews That Mean Something

An access review is a control only if it can produce a revocation. If the outcome is always "confirmed", you are producing evidence of a ritual.

### Campaign design

| Decision | Weak choice | Defensible choice |
|---|---|---|
| Scope | "All users, all systems" annually | Highest-risk entitlements quarterly (T1 systems, privileged groups, finance, HR) |
| Reviewer | The security team | The system or data owner, who can actually judge appropriateness |
| Question asked | "Is this access still needed?" | "Does this person's current role require this entitlement? Yes / No / Unknown" |
| Unknown answers | Treated as yes | Treated as **no** and revoked pending justification |
| Evidence kept | A spreadsheet of ticks | Per-campaign export, reviewer identity, decisions, and tickets for removals |
| Follow-through | Reviewed, not actioned | Removal tickets tracked to closure with timestamps |

### Worked review campaign

Acme Widgets Inc. runs its first privileged-access review:

| Entitlement | Population | Reviewer | Removed | Time-boxed grants | Unknowns |
|---|---|---|---|---|---|
| Domain Admins | 9 | IT Director | 2 (left the role 8 months ago) | 1 (migration, expires in 30 days) | 0 |
| Local Administrators on T1 servers | 14 | Windows Server lead | 4 (helpdesk tier that no longer needs it) | 0 | 1 (resolved as "no") |
| AWS account administrator role | 5 | Cloud architect | 1 | 2 (migration) | 1 (resolved as "no") |
| Finance application admin | 6 | Finance systems owner | 0 | 0 | 0 |
| Backup console operators | 4 | IT Ops manager | 1 (shared account replaced with named accounts) | 0 | 0 |

The review's output is not the table — it is the **eight removal tickets plus three time-boxed grants with expiry dates**. Those are what an auditor samples, and what actually reduces standing privilege.

## Privileged Access: Patterns and Decisions

The goal is simple to state: **fewer accounts with standing privilege, and every elevation attributable to a human and a reason.**

| Pattern | What it is | Use when | Cost |
|---|---|---|---|
| Standing privileged account | A named admin account with permanent rights | Roles that administer continuously (directory, virtualization) | Highest risk; must be MFA-protected and reviewed |
| Just-in-time (JIT) elevation | Rights granted on request, for a window, then removed automatically | Most administrative work, most engineers and operators | Requires a PAM/workflow tool and discipline |
| Break-glass | Sealed emergency access, used when the normal path is unavailable | Exactly the failure of the primary mechanism | Needs monitoring and testing, or it fails when needed |
| Just-enough administration | Delegated rights scoped to an OU, application, or task | Helpdesk and application owners | Needs careful design; under-scoping causes workarounds |

Decision table for a new administrative need:

| Question | If yes | If no |
|---|---|---|
| Is the task performed weekly or more, on T1 systems? | Consider a named standing admin account, MFA-enforced, reviewed quarterly | Prefer JIT |
| Can the task be delegated to a narrower scope (OU, app role)? | Delegate; do not grant full admin | Continue |
| Is the work periodic, project-shaped, or reviewable? | JIT with an expiry date | Continue |
| Is the primary access path itself a single point of failure? | Add a break-glass path and document it | Continue |
| Will more than one person need the same rights? | Use a role-based group, never a shared account | Named account |

### Separation of tiers

Administrative rights should not be a single ladder. Keep at least three control planes separate, each with its own accounts, and never administer a higher tier from a lower-tier workstation:

```text
Tier 0  Identity and control plane   Directory services, federation, backup of the directory,
                                     PAM, virtualization management, certificate authorities.
Tier 1  Servers and applications     Members of T0 admin groups are NOT members of T1 admin groups,
                                     and T0 credentials are never used on a T1 host.
Tier 2  Workstations and end users   Standard user for daily work; no local admin;
                                     admin tasks performed from a separate, controlled workstation.
```

Why it works: it removes the shortest path in almost every real intrusion — steal a workstation credential, escalate to local admin, find server admin credentials in that session, then take the domain. Enforcing tiers costs you convenience and a second device; the alternative is that one phished workstation is a domain compromise.

### Verifying who is actually privileged

Never trust the documentation for the answer to "who is an administrator" — query it. A real, verified example on a Windows workstation (this repository's authoring machine, output reproduced verbatim, machine and account names redacted):

```powershell
# The locale trap: built-in group names are translated. 'Administrators' does not
# exist on a Spanish-locale Windows, and a script that hardcodes it fails.
Get-LocalGroupMember -Group 'Administrators'
```

```text
Get-LocalGroupMember: No se encontró el grupo Administrators.
```

Resolve the group by its well-known SID instead, which works on every locale and language pack:

```powershell
$group = Get-LocalGroup | Where-Object { $_.SID.Value -eq 'S-1-5-32-544' }
$group | Select-Object Name, SID
Get-LocalGroupMember -Group $group.Name | Select-Object Name, ObjectClass, PrincipalSource
```

```text
Name            SID
----            ---
Administradores S-1-5-32-544

Name                     ObjectClass PrincipalSource
----                     ----------- ---------------
<HOST>\Administrador     Usuario                Local
<HOST>\<user>            Usuario     MicrosoftAccount
```

Two conclusions you can carry into any review: query privileged membership from the system rather than from a document, and do it by SID so the check keeps working across locales. The same principle applies to Linux (`getent group sudo`, `getent group wheel`) and to cloud IAM (list role assignments, do not read the design doc).

## Service Accounts, Secrets, and Rotation

Service accounts are the population that breaks every review process, because nobody knows what they are for.

Minimum viable service-account discipline:

```text
[ ] Inventory: every service account listed with an owner, a consumer (which service),
    a purpose, and a rotation date.
[ ] No interactive logon: the account exists to run a service, not for a human to sign in with.
[ ] Least privilege: scoped to the data or API it needs, not "domain user and also backup operator".
[ ] Non-expiring passwords are a finding, not a convenience. Rotate on a schedule you can meet.
[ ] Prefer an identity the platform manages (managed identity / workload identity / group-managed
    service account) over a password you have to store somewhere.
[ ] Secrets live in a secrets manager, never in scripts, config files, wikis or repositories.
[ ] Secret scanning runs in the pipeline so a committed credential is caught in review, not in an incident.
[ ] Rotation is automated; the runbook for "rotate this by hand" is the runbook nobody follows.
```

> The test of a service-account program is not the inventory's existence but this question: *if this account's password leaked today, who would know, and how long until it is rotated?* If the answer is "nobody" and "never", the account is an unmonitored back door with a friendly name.

## Metrics

| Metric | Definition | Why it is the right one |
|---|---|---|
| Deprovisioning SLA compliance | leavers disabled within the target window ÷ leavers in the period | This is what auditors sample; measure it continuously |
| Orphaned accounts | accounts with no manager, no recent logon, and active entitlements | Direct measure of lifecycle hygiene |
| Standing privileged accounts | count of accounts with permanent privileged rights | The number to drive down quarter over quarter |
| Elevations approved vs. used | approved JIT grants that were actually exercised | Detects rubber-stamped approvals as well as unused tooling |
| MFA coverage by class | enrolled ÷ total, split by workforce / privileged / service | Privileged coverage is the one that matters; report it separately |
| Access review completion | entitlements reviewed on schedule ÷ in scope | Completion without removals is the warning sign |
| Service accounts rotated on time | rotated within policy ÷ total with an owner | Proves the rotation process exists in practice |
| Secrets found in repositories | count per period, with time-to-rotation | Should trend to zero as scanning matures |

## Evidence for an Audit or Incident

| Claim | Evidence |
|---|---|
| "Access is provisioned on approval" | Request tickets with approver identity and role-to-group mapping |
| "Leavers lose access" | Sampling of leavers with disable timestamp, group removal, and post-departure authentication check |
| "Privileged access is limited and reviewed" | Privileged group membership export (per campaign) plus removal tickets |
| "Elevation is temporary" | JIT grant records: requester, approver, window, and what was done |
| "Service accounts are known and rotated" | Account inventory with owner, purpose, and last rotation date |
| "Break-glass works" | Test record: date, tester, confirmation that use was alerted on |

## Common Mistakes & Tips

- **Hardcoding built-in account and group names.** `Administrators`, `Administrador`, `Administrateur` — the same SID, three spellings. Use well-known SIDs or the platform's localized lookup, or your compliance check silently reports "group not found" and you read that as compliant.
- **Deleting leaver accounts immediately.** You lose the SID, the ownership trail, and the ability to correlate historical activity. Disable, strip entitlements, retain, then delete on schedule.
- **Assuming disabling ends the session.** Cloud sessions, VPN tunnels, and application tokens outlive the directory state. Revoke sessions explicitly as a separate step.
- **Shared privileged accounts.** They destroy attribution — the single most valuable property during an incident. One account per human, no exceptions; where a vendor requires a shared account, it gets PAM session recording.
- **Reviewing everything annually.** A 4,000-row review in one week is signed without reading. Review the highest-risk entitlements quarterly and rotate the population.
- **Approving JIT requests by default.** If approval is a reflex, the control is decorative. Sample approvals against the work actually performed.
- **Leaving service accounts with interactive logon.** It converts a service credential into a human one, and it will be used that way.
- **Treating MFA as the finish line.** MFA without attention to legacy authentication paths, MFA registration for privileged accounts, and session revocation is only partially deployed.
- **Tip**: run the privileged-membership query monthly and diff it against last month. New members of T0/T1 groups are the highest-signal identity alert an administrator can build.
- **Tip**: put the *date* on every piece of identity evidence. An access review with no timestamp is an assertion.

## Checklist / Self-Test

- [ ] I can list the identity classes an administrator is accountable for, and the failure mode of each.
- [ ] I can write the joiner, mover, and leaver checklists for a specific role in a specific organization.
- [ ] I can define a deprovisioning SLA and explain how it is measured.
- [ ] I can design an access review campaign (scope, reviewer, question, evidence, follow-through) for privileged entitlements.
- [ ] I can choose between standing privilege, JIT, break-glass, and delegation using an explicit decision table.
- [ ] I can explain the tiered administration model and the intrusion path it removes.
- [ ] I can query privileged membership from the system itself, in a way that survives a non-English OS locale.
- [ ] I can state the minimum discipline for service accounts, including rotation and rotation evidence.
- [ ] I can name the evidence for "leavers lose access" and "elevation is temporary".
- [ ] I can define three identity metrics and one way each could be gamed.

> **Verification:** executed against PowerShell 7.6.6 on 2026-09-19, and both queries in "Verifying who is actually privileged" reproduced the documented behaviour: `Get-LocalGroupMember -Group 'Administrators'` answered *No se encontró el grupo Administrators*, and resolving the group by its well-known SID returned `Administradores  S-1-5-32-544` with the two local member rows the table shows (`Usuario`, `Local` and `MicrosoftAccount`). The Linux and cloud equivalents (`getent group sudo`, IAM role listings) were not run — no such target exists on this machine.

## Further Resources

- CIS Critical Security Controls v8 — control 5 (Account Management) and control 6 (Access Control Management): https://www.cisecurity.org/controls
- NIST SP 800-53 Rev. 5 — AC (Access Control) and IA (Identification and Authentication) control families: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST CSF 2.0 — PR.AA (identity management, authentication, and access control) outcomes: https://www.nist.gov/cyberframework
- ISO/IEC 27001:2022 — Annex A 5.15–5.18 (access control, identity management, authentication information, access rights) and A.8.2 (privileged access rights): https://www.iso.org/standard/27001
- Microsoft — Active Directory security best practices and the administrative tier model (vendor guidance for tiering and privileged access): https://learn.microsoft.com/en-us/security/
