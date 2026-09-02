# Lab Setup Guide

> `01-Fundamentals/eJPT` · labs — INE-Cybersecurity-Certifications-Guide

This guide builds a **local, isolated pentest lab**: a Kali attacker plus deliberately
vulnerable targets, all inside virtual machines on one host. Everything here runs on
your own machine — no external targets, no authorization issues.

## Hardware and host requirements

- **RAM**: 8 GB minimum; 16 GB comfortable (Kali 4 GB + Metasploitable 2 < 1 GB +
  Windows VM 4 GB + host overhead).
- **CPU**: any modern x86-64 CPU with **virtualization enabled** (VT-x / AMD-V) in the
  BIOS/UEFI.
- **Disk**: 60–100 GB free for VMs and snapshots.
- **Host OS**: Windows, Linux, or macOS all work.

## Choose a hypervisor

| Hypervisor | Cost | Notes |
|---|---|---|
| Oracle VirtualBox | Free | Cross-platform, scriptable (`VBoxManage`), most lab guides target it |
| VMware Workstation Player / Pro | Free for personal use (Player); Pro commercial | Fast, easy snapshots, excellent USB/3D support |

Pick one and stick with it. The examples below are hypervisor-neutral; where they
differ, VirtualBox is assumed. Install the **guest additions** (VirtualBox) or
**open-vm-tools** (VMware) inside every VM for shared clipboard and resizing.

## Attacker VM: Kali Linux

```bash
# 1. Download a Kali VM image or ISO from kali.org (official, trusted source)
#    https://www.kali.org/get-kali/  -> "Virtual Machines" or "Installer"

# 2. Boot it. Default login on live/prebuilt images: user kali, password kali.
#    Change it immediately:
passwd

# 3. Update package lists and upgrade (do this after every snapshot you keep)
sudo apt update && sudo apt full-upgrade -y

# 4. Install anything missing (nmap, metasploit, ncat normally ship installed)
sudo apt install -y nmap metasploit-framework ncat netcat-traditional gobuster
sudo apt install -y virtualbox-guest-utils   # VirtualBox guest additions
sudo apt install -y open-vm-tools-desktop    # VMware equivalent

# 5. Confirm your lab IP before every session
ip a
ip route
```

> Kali is a rolling distribution. Update it regularly, but snapshot before big
> upgrades so a broken package never ruins a practice week.

## Vulnerable targets

### Metasploitable 2 (primary Linux target)

An intentionally vulnerable Ubuntu VM packed with old, exploitable services. This is the
workhorse of eJPT-style drills.

- Download: SourceForge project "metasploitable" (official Rapid7 release).
- Credentials: `msfadmin` / `msfadmin` (documented by the project).
- Services include vsftpd 2.3.4, OpenSSH, Apache, Samba (SMB), distcc, UnrealIRCd,
  MySQL, PostgreSQL, and more — all public, all documented.

### Metasploitable 3 (optional, advanced)

Modern build of Windows Server 2008 + Ubuntu 14.04 with many vulnerabilities. Setup is
heavier: it uses Packer/Vagrant and downloads Windows ISOs.

- Repository: <https://github.com/rapid7/metasploitable3> (README explains the build).
- Recommended only after you have mastered Metasploitable 2.

### DVWA (web target)

Damn Vulnerable Web Application — a PHP/MySQL web app with graded difficulty levels.
Most useful for the web portions of your practice.

- Repository: <https://github.com/digininja/DVWA> (README covers install).
- Quick option: run it as a Docker container:
  `docker run --rm -it -p 80:80 vulnerables/web-dvwa`
- Default login `admin` / `password`; set the security level to *low* from the DVWA
  Security page when you start.

### Windows evaluation VMs (optional)

Microsoft publishes time-limited evaluation ISOs (Windows Server, Windows 10/11
Enterprise) for testing:

- Microsoft Evaluation Center: <https://www.microsoft.com/en-us/evalcenter/>
- Microsoft developer VMs: <https://developer.microsoft.com/en-us/windows/downloads/virtual-machines>

Evaluation images **expire** after 90 days — take a clean snapshot and revert instead of
reinstalling.

## Network topology

For pentest practice you want the attacker and the targets on an **isolated host-only
network**, plus a second NAT adapter on Kali for internet updates.

| Mode | Kali ↔ Host internet | Kali ↔ Targets | When to use |
|---|---|---|---|
| NAT | Yes | Via host only (shared) | Updates, downloads |
| Host-only / internal | No | Direct, isolated | Lab attacks (recommended) |
| Bridged | Yes | Yes (on real LAN!) | Never for attacks without permission |

```text
Recommended layout
┌────────────────────────── Host ──────────────────────────┐
│   Kali (2 NICs)              Metasploitable 2             │
│   eth0: NAT      (internet)         │                      │
│   eth1: host-only 192.168.56.0/24 ──┼── 192.168.56.101    │
│                                     │                      │
│   DVWA (Docker on Kali or its own VM)                     │
└────────────────────────────────────────────────────────────┘
```

Setup steps:

1. Create a **host-only network** in your hypervisor (VirtualBox default is
   `192.168.56.0/24`; VMware "custom host-only" similar).
2. Give Kali two adapters: NAT (default) + host-only.
3. Give every target one host-only adapter. Static IPs make life easier —
   Metasploitable 2 is easiest to use with a fixed IP you assign in the guest or via the
   hypervisor.
4. Boot everything, then from Kali confirm:
   `ip a` (your IPs) and `ping -c 2 192.168.56.101`.

> Metasploitable 2 ships with a single NAT adapter and default IP 10.0.2.15. Switching
> it to host-only changes the IP — note the new address after boot (`ip a` in the
> guest, or check your hypervisor's DHCP leases).

## Snapshots: your time machine

A snapshot freezes a VM's state so you can destroy the machine and restore it in
seconds.

```bash
# VirtualBox: take snapshots from the GUI (Machine > Take Snapshot) or the CLI
VBoxManage snapshot "Metasploitable2" take "clean-base"
VBoxManage snapshot "Metasploitable2" restore "clean-base"

# VMware: VM > Snapshot > Take Snapshot (and Restore from the same menu)
```

Practical rules:

- Snapshot every VM right after install/update ("clean-base").
- Take a fresh snapshot before starting any drill that may break the guest.
- Restore, don't repair: a shell you trashed is not worth fixing by hand.

## Readiness checklist

Before moving to `practice-scenarios.md`, verify your environment works end to end:

- [ ] Kali boots, has internet via NAT, and is fully updated.
- [ ] Metasploitable 2 boots on the host-only network and answers `ping`.
- [ ] DVWA loads in a browser at `http://<dvwa-ip>/` (or `http://127.0.0.1` if Docker).
- [ ] From Kali: `nmap -sn` sees the targets; `nmap -sV` reads their banners.
- [ ] From Kali: `ssh msfadmin@<metasploitable-ip>` logs in with `msfadmin`.
- [ ] Snapshots "clean-base" exist for every VM.

## Common Mistakes & Tips

- **Hypervisor networking wrong.** If Kali sees the internet but not the targets (or
  vice versa), check the adapter types — NAT cannot reach host-only guests.
- **No snapshot before experiments.** One bad exploit or a `rm -rf` typo and you lose a
  week of setup. Snapshot first, always.
- **Leftover default credentials.** Change the Kali password immediately; the lab
  targets keep their *documented* weak credentials on purpose.
- **Running out of disk.** Snapshots grow fast; prune old ones and give VMs only what
  they need.
- **Practicing against the real LAN.** Keep every lab adapter host-only. Bridged +
  real LAN + scanner = trouble.
- **Old guides say `root/toor`** for Kali — that was pre-2020. Current images use
  `kali`/`kali`.
- **Windows eval VMs expiring** mid-week is normal — restore the clean snapshot rather
  than fighting the expiry screen.
- **Not recording IPs.** Write down each VM's name and IP; static addressing removes
  most confusion.

## Checklist / Self-Test

- [ ] I can name the two hypervisor choices and one reason to prefer each.
- [ ] I can boot Kali, change the default password, and update the system.
- [ ] I installed or imported Metasploitable 2 and DVWA successfully.
- [ ] I can explain NAT vs host-only and describe my lab's IP layout.
- [ ] I can take and restore a snapshot from the CLI or GUI.
- [ ] `nmap -sn` from Kali finds every target on the host-only network.
- [ ] I can SSH from Kali into Metasploitable 2 with its documented credentials.
- [ ] I have a clean "base" snapshot of every VM to restore after each drill.

## Further Resources

- Kali Linux documentation and downloads: <https://www.kali.org/docs/> · <https://www.kali.org/get-kali/>
- VirtualBox manual: <https://www.virtualbox.org/manual/>
- VMware Workstation documentation: <https://docs.vmware.com/>
- Metasploitable 2 (official download): <https://sourceforge.net/projects/metasploitable/>
- Metasploitable 3 repository: <https://github.com/rapid7/metasploitable3>
- DVWA repository: <https://github.com/digininja/DVWA>
- Microsoft Evaluation Center: <https://www.microsoft.com/en-us/evalcenter/>
