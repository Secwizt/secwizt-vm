# Secwizt VM: questions and answers

How to install, use and stay safe with Secwizt VM. For the full feature list see the [README](README.md); for the security design see [SECURITY-NOTES.md](SECURITY-NOTES.md).

## Contents

- [Getting started](#getting-started)
- [Ready-to-run machines](#ready-to-run-machines)
- [Installing an operating system](#installing-an-operating-system)
- [Using a machine](#using-a-machine)
- [Snapshots, templates and throwaway machines](#snapshots-templates-and-throwaway-machines)
- [Networking](#networking)
- [Apps and AI tools inside a machine](#apps-and-ai-tools-inside-a-machine)
- [Backups](#backups)
- [Security and privacy](#security-and-privacy)
- [Troubleshooting](#troubleshooting)
- [Project](#project)

## Getting started

### What is Secwizt VM?

A free, open-source desktop app for Windows that creates and runs virtual machines. It uses two engines from one window: **Hyper-V** for Windows and modern Linux guests, and **QEMU** for Android, BIOS-era systems and emulated Arm. It also has a marketplace of official operating systems, ready-made machines and apps.

### Is it finished?

No. It is an **early preview**, built and tested on one Windows 10 Pro PC. Expect rough edges and read [Known limits](README.md#known-limits) before you rely on it.

### What do I need?

- Windows 10 or 11 (64-bit) Pro, Enterprise or Education.
- **Hyper-V** and the **Windows Hypervisor Platform** turned on (Windows Features).
- The Microsoft Edge WebView2 Runtime (part of current Windows).
- **QEMU for Windows (64-bit)** if you want QEMU machines, including the ready-to-run ones. QEMU is not included.
- **Git for Windows** in its default folder, `C:\Program Files\Git`. Its `gpgv` checks publisher signatures; without it, signed downloads are refused.

### How do I install it?

There is no ready-made installer download yet. Build it from source (it takes a few minutes):

1. Install Rust 1.93 or later with the MSVC toolchain and Visual Studio Build Tools with the C++ workload.
2. In the repository folder run `cargo build --workspace --release`.
3. Run `target\release\svm-app.exe`. Keep `svmd.exe` in the same folder.

To make a per-user installer instead, run `.\installer\build.ps1 target\release` in PowerShell and use `target\installer\SecwizVM-Setup.exe`.

### What runs when I open the app?

Two programs: `svm-app.exe` (the window) and `svmd.exe` (a local background service that owns your machines). The app starts the service for you. If it shows **Service is not running**, choose **Start it**.

### Where are my machines stored?

In `%LOCALAPPDATA%\SecwizVM`. Nothing is uploaded anywhere.

### How do I set up QEMU?

Open **Settings and About → QEMU** and choose `qemu-system-x86_64.exe` from your QEMU folder. Arm support is detected automatically when `qemu-system-aarch64.exe` sits next to it.

## Ready-to-run machines

### What is "Ready to run"?

Official ready-made machines you can start without running an installer: **Debian 13**, **Ubuntu Server 26.04 LTS** and **Kali Linux 2026.3**. Open **Marketplace → Ready to run**.

### How do I get one?

Click **Get** once. The app downloads the image from the publisher's official site, checks its pinned SHA-256 (and, for Ubuntu and Kali, the publisher's signature), then prepares it as a sealed, read-only template. You can leave the page while this happens. Kali's 3.9 GB archive needs about 35 GB of free space while it is prepared; the cloud images need about 5 GB.

### How do I start it?

Click **Launch**. Each machine is a linked copy of the template, so it uses little disk space, and you can launch as many as you like. Before each copy the app re-checks the template's SHA-256: a few seconds for Debian and Ubuntu, longer for the 16 GB Kali template (up to about 2 minutes from a hard disk).

### How do I sign in to Debian or Ubuntu?

When you launch, choose a user name. Let the app **generate a password** (shown once, so copy it) or type your own. Sign in on the machine's **Console**. On first start the machine installs its guest agent and grows its disk to 20 GiB; it needs the internet for that one step. SSH password sign-in is off.

### How do I sign in to Kali?

Kali starts with Kali's public default login, **kali / kali**. The machine page asks you to change it: use **Set a new password** (through the guest agent), or sign in, run `passwd` and choose **I changed it myself**. Port forwarding stays off until you do.

### Why can't I make a plain linked clone of a Debian or Ubuntu template?

Such a copy would have no user to sign in with. Use **Launch**, which sets up the user for each copy.

## Installing an operating system

### How do I install Linux or BSD from an official installer?

1. Open **Marketplace → Installers** and pick a collection (Security, Open source or Windows).
2. Click **Check latest** where offered. The app finds the newest release from the publisher's signed list.
3. Click **Download**. It shows the size and your free space first, downloads only from the official site and checks the checksum and signature before the file can be used.
4. Click **Create VM**. The app suggests the engine, CPU, memory and disk; change anything, then create.

### How do I install Windows?

- **Windows 10 or 11:** the row opens Microsoft's own download page. Download the ISO there, then choose the file; the app accepts it only if it matches Microsoft's published SHA-256. You need your own licence key to activate.
- **Older Windows (XP, Vista, 7, 8):** Microsoft no longer offers them. Use your own ISO; the app has ready-made old-PC settings.

### Can I create a machine from scratch?

Yes: **Library → New machine**. Choose the engine, operating system family, CPU, memory, disk and an installer ISO.

### Can I use an existing virtual disk?

Yes: **Import disk** accepts common formats (qcow2, VMDK, VDI, VHD, VHDX and raw). The app inspects the disk from its own bytes and refuses disks that point to other host files. **Export disk** works the other way.

## Using a machine

### How do I see the machine's screen?

Open the machine and use the **Console** tab. Click it to type; resize the window and the screen follows.

### Which engine should I choose?

**Hyper-V** for Windows and modern Linux: it is the fastest. **QEMU** for Android, BIOS-era systems, Arm, and the ready-to-run images. Arm machines are emulated, so they are much slower than x86. The **Why not available** page explains any control that a machine or engine cannot offer.

### How do I copy files in and out?

Use **Send file to machine** and **Get file from machine**. Transfers are checked with SHA-256 both ways. Linux guests on QEMU need the guest agent (`sudo apt install qemu-guest-agent`); ready-to-run cloud images install it on first boot. Hyper-V Windows guests use PowerShell Direct with the guest's username and password, which are never saved; Hyper-V Linux guests use SSH.

### How does the clipboard work?

It is off by default. Switch it on for a machine while the machine is stopped. Then paste into the guest, and use **Copy guest text** to bring text back.

### Can I run a command inside a guest?

Yes, from the machine's guest tools, once the guest agent (QEMU) or PowerShell Direct or SSH (Hyper-V) is available. You also see the guest's IP address and operating system there.

### Is there a command-line tool?

Yes, `svm.exe`. For example `svm list` shows your machines and `svm service status` checks the service.

## Snapshots, templates and throwaway machines

### How do I take a snapshot?

Use **Take snapshot**, even while the machine runs. With the guest agent the snapshot is guest-quiesced (safe); without it, it is labelled crash-consistent.

### What are templates and linked clones?

Stop a machine and choose **Make template**: its disk becomes read-only with a recorded SHA-256. Then **New linked clone** makes fast copies that share the template's disk; each copy keeps only its own changes. A template cannot be deleted while copies exist.

### What is a throwaway machine?

Turn on **Throwaway** for a machine while it is stopped. Everything you do inside it is thrown away when it powers off: good for malware tests and practice labs. Start it from Secwizt VM and keep the app open while you use it. A throwaway QEMU machine also gets **Isolated network** unless you choose otherwise.

## Networking

### Can my machines reach the internet?

Yes. QEMU machines use QEMU's built-in NAT. Hyper-V machines use the Default Switch or the app's own networks.

### How do I reach a service inside a machine, such as SSH?

Add a **Port forwarding** rule on the machine, for example host `2222` to guest `22`, then connect to `127.0.0.1:2222`. Forwards listen on this PC only, never on your LAN.

### What is "Isolated network"?

A per-machine switch for QEMU guests. It blocks the guest from the host and from the internet, while TCP port forwards keep working. Use it for untrusted software.

### What are the app's own networks?

On the **Networks** page you can create Hyper-V networks where the app's own DHCP and DNS give each machine a permanent address and a `name.vm.lan` host name. Routed and bridged networks need a one-time administrator setup: the app shows the command, which checks the setup script against the SHA-256 built into the app before running it as administrator.

### Can I capture network traffic?

Yes, for QEMU machines: **Packet capture → Start capture**. You get a size-capped `.pcap` file to open in Wireshark if you have it installed.

## Apps and AI tools inside a machine

### How do I install an app inside a machine?

1. Open **Marketplace → Apps & AI tools** and search or choose a category.
2. Select **Install**, then a running machine with network access.
3. Read the command preview and confirm. The machine's **App log** shows each step and its output.

Apps come from the distribution's or the publisher's signed repositories. Labels tell you how each one is checked: **Distro**, **Signed**, **Checksum** or **Reference**.

## Backups

### How do backups work?

Backups use **restic**, and the repository password is decrypted with **age** and a **YubiKey** (`age-plugin-yubikey`). You supply `restic.exe`, `age.exe` and `age-plugin-yubikey.exe` in one folder, an existing local restic repository and a password file encrypted to your YubiKey identity. A YubiKey is required.

## Security and privacy

### Does Secwizt VM send my data anywhere?

No. The app has no account and no telemetry, and your machines stay on your PC. It contacts the internet only to download what you choose from the publishers' official sites.

### How are downloads protected?

Downloads come only over HTTPS from the publisher hosts named in the bundled catalog. Each file must match its pinned SHA-256, and where the publisher signs its checksum list, that signature is checked against the publisher's pinned key. There is no "use anyway" for a file that fails.

### Can a virtual machine attack my PC through the app?

The app's service listens only on `127.77.0.1`, which QEMU guests cannot reach, and every client must prove a secret token with a mutual HMAC handshake. Port forwards bind to `127.0.0.1` only and the clipboard is off by default. A QEMU guest without **Isolated network** can still reach *other* programs on your PC that listen on `127.0.0.1`, so turn isolation on for untrusted guests. See [SECURITY-NOTES.md](SECURITY-NOTES.md).

### Was it tested for security?

Yes. Before release it had an internal review and a pen test: a code review of every area, a live attack on the running service and a dependency advisory check. The findings and fixes are listed in [SECURITY-NOTES.md](SECURITY-NOTES.md).

### How do I report a vulnerability?

Privately, through the **Report a vulnerability** button on this repository's **Security** tab. Please do not open a public issue for it.

## Troubleshooting

### The app says "Service is not running".

Choose **Start it**. If it fails again, make sure `svmd.exe` is in the same folder as `svm-app.exe`.

### A QEMU option is greyed out.

Open **Settings and About → QEMU** and choose `qemu-system-x86_64.exe`. The **Why not available** page explains any other disabled control.

### Signed downloads are refused.

Install Git for Windows in its default folder, so that `C:\Program Files\Git\usr\bin\gpgv.exe` exists.

### A Kali launch takes a long time.

The app re-checks the 16 GB template's SHA-256 before every copy. From a hard disk this can take about 2 minutes; from an SSD, or when Windows still has the file in memory, it is much faster.

### Can I bridge a machine over Wi-Fi?

Bridged networks need a physical Ethernet adapter. Wi-Fi adapters can block frames from guest MAC addresses.

### Can I run macOS or use DirectX 11 in a Windows guest?

No. macOS guests need Apple hardware, and neither engine provides DirectX 11 to Windows guests; Windows guests get a fast 2D desktop.

## Project

### Is it free?

Yes. Secwizt VM is open source under the [Apache License 2.0](LICENSE), copyright Secwizt Private Limited. You may use, change and share it under that licence.

### Does it update itself?

No. Updates come as new releases of this repository. Ready-to-run images and bundled installers are pinned to exact files, so a new release is needed when a publisher replaces a file.

### How can I help?

Open an issue for a bug or an idea, with your Windows version and the steps to reproduce it. For security problems use the private report described above.
