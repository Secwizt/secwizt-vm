# Secwizt VM

A desktop virtual machine manager for Windows. Create and run Linux, Windows, Android and BSD machines on Hyper-V or QEMU from one app, with a built-in marketplace of official operating systems, ready-made machines and apps.

> **Early preview.** Secwizt VM has been built and tested on one Windows 10 Pro PC only. Expect rough edges, and read [Known limits](#known-limits) before you rely on it.

## Introduction video

A 95-second tour of the real app: ready-to-run machines, verified downloads, the two engines, throwaway machines and the security design.

https://github.com/user-attachments/assets/a2270527-9ec4-43ce-a922-f102c2908a1f

## Highlights

- **Two engines, one app.** Hyper-V for Windows and modern Linux guests. QEMU with Windows Hypervisor Platform (WHPX) acceleration for x86 Android and BIOS-era guests, and software emulation (TCG) for Arm guests.
- **Marketplace**
  - **Ready to run:** official ready-made machines (Debian 13, Ubuntu Server 26.04 LTS, Kali Linux 2026.3). Each image is downloaded and checked once, then kept as a sealed, read-only template. Each new machine is a linked copy of the template, with no installer to run; the template's SHA-256 is checked again at every launch.
  - **Installers:** official installation media from each publisher, in two kinds. Bundled entries are pinned to an exact file and SHA-256, and the publisher's signed checksum list ships with the app. **Check latest** entries pick the newest release at run time and accept it only with a signature by the publisher's pinned key, on its checksum list or, for Arch Linux and Security Onion, on the installer itself.
  - **Apps & AI tools:** install packages inside a running guest from the distribution's or publisher's signed repositories. Every command is shown before it runs.
- **Machines:** snapshots, templates and linked clones, throwaway machines that forget every change when they power off, an in-app console, opt-in shared clipboard, file transfer, loopback-only port forwarding and packet capture.
- **Networks:** on the app's own Hyper-V networks, its DHCP and DNS give each machine a permanent address and a `name.vm.lan` host name. QEMU machines use QEMU's built-in NAT.
- **Backups:** encrypted backups and restores with restic. The repository password is decrypted by age with a YubiKey (age-plugin-yubikey), so a YubiKey is required.
- **Safety:** the service's own API listens only on the loopback address `127.77.0.1`, which virtual machines cannot reach, and authenticates every client; downloads come only from official HTTPS hosts and are refused unless they verify; first-boot passwords are stored only as SHA-512-crypt hashes. See [SECURITY-NOTES.md](SECURITY-NOTES.md).

## Requirements

- Windows 10 or 11 (64-bit) Pro, Enterprise or Education, with Hyper-V and the Windows Hypervisor Platform turned on.
- Microsoft Edge WebView2 Runtime.
- QEMU for Windows (64-bit) for QEMU machines. It is not included; choose `qemu-system-x86_64.exe` in **Settings → QEMU**.
- Git for Windows, installed in its default machine-wide folder (`C:\Program Files\Git`). The service checks publisher signatures with `C:\Program Files\Git\usr\bin\gpgv.exe` and refuses signed downloads without it.
- For backups: a YubiKey with an age-plugin-yubikey identity, a password file encrypted to that identity with age, an existing local restic repository, and a folder that holds only `restic.exe`, `age.exe` and `age-plugin-yubikey.exe`. These tools are not included.
- To build: Rust 1.93 or later with the MSVC toolchain (the pinned `sevenz-rust2` 0.25.0 needs 1.93), and Visual Studio Build Tools with the C++ workload. Node.js is needed only for the interface checks.

## Build and run

```
cargo build --workspace --release
```

This produces `target\release\svm-app.exe` (the desktop app), `svmd.exe` (the local service) and `svm.exe` (the command-line tool). Keep `svmd.exe` in the same folder as `svm-app.exe`, then run `svm-app.exe`. It starts the service; if the service is not running, choose **Start it**. Machine data is kept in `%LOCALAPPDATA%\SecwizVM`.

To make the per-user installer, run `.\installer\build.ps1 target\release` in PowerShell. It packs the three programs with `LICENSE`, `NOTICE`, `THIRD-PARTY-NOTICES.md` and `THIRD-PARTY-LICENSES.txt`, and writes `SecwizVM-Setup.exe` to `target\installer`.

## Test

```
cargo test --workspace -- --test-threads=2
node ui/tools/check.mjs
```

Tests that create real machines, download images or need a Hyper-V host are marked `#[ignore]` and need an opt-in environment variable set to `1`. Run them with `cargo test -- --ignored`.

| Variable | Test file | Notes |
| --- | --- | --- |
| `SVM_SERVICE_LIVE`, `SVM_DHCP_LIVE`, `SVM_STORAGE_LIVE`, `SVM_INSTALLED_LIVE` | `crates\svmd\tests\live_service.rs` | The installed-guest test also needs `SVM_INSTALLED_DISK`. |
| `SVM_READY_LIVE` | `crates\svmd\tests\ready_live.rs` | Downloads about 5.2 GB; the file header lists its other variables. |
| `SVM_APP_LIVE` | `crates\svm-app\tests\live_app.rs` | |
| `SVM_HYPERV_LIVE` | `crates\svm-hyperv\tests\live_hyperv.rs` | |

## How it fits together

| Part | Role |
| --- | --- |
| `crates/svm-core` | Machine model, library on disk, identities, DHCP and DNS |
| `crates/svm-hyperv` | Hyper-V engine |
| `crates/svm-qemu` | QEMU engine, disk tools and the per-machine supervisor |
| `crates/svmd` | Local service and HTTP API on `127.77.0.1`, marketplace, downloads, backups |
| `crates/svm` | Command-line client |
| `crates/svm-app` | Desktop window (WebView2) |
| `ui/` | The interface, plain JavaScript |
| `setup/` | Optional administrator script for routed and bridged Hyper-V networks |
| `installer/` | Per-user Windows installer |

## Known limits

- Tested on one PC: Windows 10 Pro, Intel CPU, Hyper-V on.
- QEMU x86 machines boot with BIOS. Secure Boot and a virtual TPM are available on Hyper-V machines only.
- Arm machines are emulated, not accelerated, so they run much slower than x86 machines.
- By default a QEMU guest can reach other programs on the host, including ones that listen only on `127.0.0.1`, through QEMU's NAT gateway (`10.0.2.2`). Secwizt VM's own service and QEMU's control and display ports are on `127.77.0.1`, out of the guest's reach. The per-machine **Isolated network** option blocks the rest; it is on by default for throwaway QEMU machines.
- Designed for a single-user PC: another Windows account on the same PC cannot use your machines, but it can block the app (see [SECURITY-NOTES.md](SECURITY-NOTES.md)).
- Launching a ready-to-run machine re-checks the template's SHA-256 every time. This takes seconds for the cloud images. For the 16 GB Kali template it took about 10 seconds when Windows still had the file in memory, and about 2 minutes reading it from a hard disk.
- Routed and bridged Hyper-V networks need `setup\svm-admin-setup.ps1`, run once as administrator. It has not yet been tested on a clean PC.
- There are no automatic updates. Bundled marketplace entries and ready-to-run images are pinned to exact files and need a new Secwizt VM release when a publisher replaces them.
- The security design and its remaining limits are described in [SECURITY-NOTES.md](SECURITY-NOTES.md).

## Security

Please report vulnerabilities privately through GitHub's **Report a vulnerability** button on this repository's Security tab, not in a public issue.

## Licence

Copyright 2026 Secwizt Private Limited. Licensed under the [Apache License, Version 2.0](LICENSE); see also [NOTICE](NOTICE).

Third-party components keep their own licences. [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) explains how each one is used, [THIRD-PARTY-LICENSES.txt](THIRD-PARTY-LICENSES.txt) holds their full licence texts, and [DOWNLOADS.md](DOWNLOADS.md) lists every component with its version, licence and source.

"Secwizt" is a name of Secwizt Private Limited. The licence does not grant permission to use this name or its logos except to describe the origin of the software.
