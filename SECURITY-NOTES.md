# Security notes

This file describes how Secwizt VM protects the computer it runs on, what an internal review and a pre-release pen test in November 2026 found and fixed, and the limits that remain. To report a vulnerability, use GitHub's private **Report a vulnerability** form on this repository, not a public issue.

## What the design protects

- **The control service is local only.** `svmd` listens on the loopback address `127.77.0.1`, not `127.0.0.1`. QEMU's user-mode network sends a guest's connections to `10.0.2.2` only to `127.0.0.1`, so guests cannot reach the service, its console relay, the QEMU supervisors or QEMU's displays, which all listen on `127.77.0.1`. Each start writes a new owner-only token. The client and the service prove knowledge of it to each other with HMAC-SHA256 over fresh nonces and the loopback port, so the token itself is never sent and a relay through another port fails. The desktop interface runs on the reserved origin `https://svm.localhost`.
- **Administrator setup.** The command the app shows for the one-time network setup reads `setup\svm-admin-setup.ps1`, checks it against the SHA-256 built into `svmd.exe`, copies it into an administrators-only folder under Program Files and runs that copy without a PowerShell profile. A missing, changed or planted script is refused before anything runs elevated, and the script loads PowerShell modules only from Windows PowerShell's own folder.
- **Downloads.** The marketplace downloads only over HTTPS and only from the publisher hosts named in the bundled catalog. Publisher signatures are checked with `gpgv` from Git for Windows at `C:\Program Files\Git\usr\bin\gpgv.exe`; without it, signed downloads are refused. Nothing unverified can be used, and there is no "use anyway". There are two kinds of entries:
  - **Bundled entries** (the Debian and FreeBSD installers and the ready-to-run images) are pinned to an exact file and SHA-256, and a download that does not match is refused. Where the publisher signs its checksum list, that list ships with the app and its signature is checked against a bundled keyring that holds a single key. Windows media are not downloaded: a user-supplied ISO is checked against the SHA-256 that Microsoft publishes.
  - **Check latest entries** pick the newest release at run time. The SHA-256 comes from the publisher's signed checksum list; for Arch Linux and Security Onion it comes from publisher metadata, and the installer's detached signature is checked instead. The publisher keyring is fetched from the address in the catalog, which for Linux Mint, Arch Linux and Security Onion is a public keyserver or GitHub. Only a signature whose primary key matches the pinned fingerprint is accepted, and a release older than the pinned one is refused.
- **Untrusted disks.** Imported and downloaded disk images are inspected from their own bytes with an explicit format. Backing files, external data files, encryption and descriptors that point to other host files are refused. Ready-made images are converted to a fresh standalone disk before use, and their archive is unpacked only if it holds exactly the one named file, with a size limit and a pinned SHA-256.
- **Guests.** QEMU guests use QEMU's user-mode network (NAT). New machines, including ready-to-run ones, start without isolation, and then a guest can reach other programs on the host that listen only on `127.0.0.1`, through the address `10.0.2.2`. Secwizt VM's own service and QEMU's control and display ports are not among them. Turn on **Isolated network** for untrusted guests: it blocks the host, including those local programs, and the internet, while TCP port forwards keep working. Turning on throwaway mode for a QEMU machine also turns on isolation unless you choose otherwise. Port forwards bind to `127.0.0.1` only. Clipboard sharing is off by default. Guest file transfers refuse host paths inside the service's own data folder.
- **First-boot settings.** Cloud images receive a private, read-only settings volume. Every value is checked and written through a fixed template. Passwords are stored only as SHA-512-crypt hashes; a generated password is shown once and never stored. Images that ship a public default login keep port forwarding off until the owner confirms in the app that they changed the default password. The app records this confirmation; it cannot check the guest. The service refuses the confirmation while throwaway mode is on, because a password changed during a throwaway run is discarded at power-off.
- **Templates.** A template's disk is read-only with a recorded SHA-256 that is checked again before every linked clone, including every launch of a ready-to-run machine.

## Fixed in the November 2026 review

| Finding | Fix |
| --- | --- |
| Medium: a stale port file could point the client at another local listener | The client checks the service lock first; the mutual HMAC handshake above replaced the bearer token; the token rotates at every start. |
| Low: unauthenticated connections could hold service workers | Pre-authentication deadline and admission limit. |
| Low: DHCP and event-log growth | Per-machine DHCP rate limit; bounded, rotated event log. |
| Low: declined DHCP leases stayed blocked | Declines expire after 60 seconds or a restart. |
| Low: a transient UDP error stopped DHCP | DHCP continues after receive errors. |
| Low: interface origin | Navigation, native messages and the console use one reserved origin. |
| Low: unbounded guest downloads | Size, free-space and time limits; only completed, verified downloads are published. |
| Low: guest-agent replies | Shapes and sizes are validated before use. |
| Low: clipboard exposure | Warnings and a refused combination with a separate console window. |
| Low: version labels for two publishers | Labelled unverified where only the installer bytes are signed. |
| Low: guest transfers into the service folder | Refused, including nested machine folders. |
| Low: cleanup after a failed disk publication | The machine enters the trash with a receipt and can be emptied. |
| Low: interrupted transfers on removed drives | Recovery retires the record. |
| Low: existing-disk creation | The importer's standalone-disk check runs before copying. |

## Fixed in the pre-release pen test

The pen test combined a code review of every area, a live attack on a running service (requests without the handshake, browser-style and DNS-rebinding requests, a console hijack attempt, oversized input, idle connections, key-file permissions) and a check of the dependencies against the RustSec advisory database.

| Finding | Fix |
| --- | --- |
| Medium: the administrator setup command ran a script from a folder the user's own programs can write | The command checks the script against the SHA-256 built into `svmd.exe`, copies it to an administrators-only folder and runs that copy with no profile. The app shows the whole command before copying it. |
| Medium: a guest without isolation could fill the service's pre-authentication slots and lock the owner out | The service, the console relay, QEMU supervisors and QEMU displays moved to `127.77.0.1`, which the guest's user-mode network cannot reach. The live test checks this from inside each cloud guest. |
| Medium: a guest without isolation could stall a QEMU supervisor, and through it the service | The same move. |
| Low: another program holding port 47800 stopped the service from starting | The service takes another free port; clients read the port from its data folder. |
| Low: a reset connection could end a QEMU supervisor and power off its machine | Reset and aborted connections are ignored. |
| Low: Hyper-V guest downloads had no size or free-space limit | The QEMU limits apply: at most 4 GiB, with 64 MiB left free. |
| Low: SSH to a Hyper-V Linux guest used any address the guest reported | Only private (RFC 1918) and shared (100.64.0.0/10) addresses are used. |
| Low: an existing VHDX with a pending log could change after its check | Refused, as for backups. |
| Low: `url` 2.5.8 (RUSTSEC-2026-0592; `Url::origin` is never called here) | Updated to 2.5.9. |

## Known limits

- QEMU guests without **Isolated network** can reach other programs on the host that listen only on `127.0.0.1`.
- Secwizt VM is designed for a single-user PC. Another Windows account on the same PC cannot use the service or its machines, but it can get in the way: it can hold the service's pre-authentication slots, answer `.vm.lan` lookups while the service is stopped (the administrator setup adds a Windows DNS rule for that name), or hold the global locks that setup and Hyper-V operations use.
- Guests on the same app network can disturb each other's addressing, because DHCP and ARP are not authenticated. Give untrusted guests their own network.
- **Check latest** for Arch Linux and Security Onion: only the installer is signed, not its release name or date. Someone who controls their download host could offer an older signed release as the newest one.
- The installer's internal SHA-256 list detects corruption, not tampering, because it travels inside the same file. Sign release builds with Authenticode and publish their checksums separately.
- The default-login guard relies on the owner's confirmation; the app cannot verify that the guest's password was changed.
- **Check latest** trusts each publisher's pinned primary key. If a publisher starts signing with a new key, its newest releases fail verification until the catalog is updated.
- Hyper-V Manager and other administrator tools can bypass throwaway protection. Use the app's own power controls for a throwaway run.
- The service trusts the files in its own data folder, which only the owner's account can write.
- Throwaway mode has not been verified on an emulated Arm guest.
- Bundled marketplace entries and ready-to-run images are pinned to exact files. A new Secwizt VM release is needed when a publisher replaces a file.
- The optional administrator script for routed and bridged Hyper-V networks has not been tested on a clean PC.
