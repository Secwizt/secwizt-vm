# Dependencies and provenance

This file lists the third-party components that Secwizt VM is built from, embeds or downloads, with their versions, licences and sources, and the pins the app uses to check what it downloads. The desktop app shows every table in this file under **Settings → About**, except the last one (**Other targets in Cargo.lock**). The full licence texts are in [THIRD-PARTY-LICENSES.txt](THIRD-PARTY-LICENSES.txt), and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) explains how each component is used.

## Rust crates in the Windows build

The Windows programs (`svm-app.exe`, `svmd.exe` and `svm.exe`, target `x86_64-pc-windows-msvc`) compile the 133 crates below from crates.io, at the exact versions and checksums recorded in `Cargo.lock`. The list holds normal and build dependencies; the test-only dependencies add no further crates on Windows. Build scripts and procedural macros (for example `cc`, `syn` and `serde_derive`) run only while compiling, but are listed as well. The list was produced with:

```
cargo tree --locked --workspace --edges normal,build --target x86_64-pc-windows-msvc --prefix none --format "{p} | {l}"
```

The licence column is each crate's declared licence expression. Where it offers a choice, any of the options may be used. Every crate in this list is under permissive terms. `sevenz-rust2` 0.25.0, which reads the 7z archive of the Kali image, sets the minimum Rust version for the workspace to 1.93.

| Crate | Version | Licence |
| --- | --- | --- |
| adler2 | 2.0.1 | 0BSD OR MIT OR Apache-2.0 |
| autocfg | 1.5.1 | Apache-2.0 OR MIT |
| base64 | 0.22.1 | MIT OR Apache-2.0 |
| base64 | 0.23.1 | MIT OR Apache-2.0 |
| bitflags | 2.13.1 | MIT OR Apache-2.0 |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 |
| bytes | 1.12.1 | MIT |
| cc | 1.4.5 | MIT OR Apache-2.0 |
| cfg-if | 1.0.4 | MIT OR Apache-2.0 |
| cookie | 0.18.2 | MIT OR Apache-2.0 |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 |
| crc32fast | 1.5.2 | MIT OR Apache-2.0 |
| crossbeam-channel | 0.5.17 | MIT OR Apache-2.0 |
| crossbeam-utils | 0.8.23 | MIT OR Apache-2.0 |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 |
| deranged | 0.5.9 | MIT OR Apache-2.0 |
| digest | 0.10.7 | MIT OR Apache-2.0 |
| displaydoc | 0.2.7 | MIT OR Apache-2.0 |
| dpi | 0.1.2 | Apache-2.0 AND MIT |
| dunce | 1.0.5 | CC0-1.0 OR MIT-0 OR Apache-2.0 |
| fastrand | 2.5.0 | Apache-2.0 OR MIT |
| find-msvc-tools | 0.1.12 | MIT OR Apache-2.0 |
| flate2 | 1.1.10 | MIT OR Apache-2.0 |
| form_urlencoded | 1.2.3 | MIT OR Apache-2.0 |
| generic-array | 0.14.7 | MIT |
| getrandom | 0.2.17 | MIT OR Apache-2.0 |
| getrandom | 0.4.3 | MIT OR Apache-2.0 |
| http | 1.5.0 | MIT OR Apache-2.0 |
| httparse | 1.10.1 | MIT OR Apache-2.0 |
| icu_collections | 2.3.0 | Unicode-3.0 |
| icu_locale_core | 2.3.0 | Unicode-3.0 |
| icu_normalizer | 2.3.0 | Unicode-3.0 |
| icu_normalizer_data | 2.3.0 | Unicode-3.0 |
| icu_properties | 2.3.0 | Unicode-3.0 |
| icu_properties_data | 2.3.0 | Unicode-3.0 |
| icu_provider | 2.3.1 | Unicode-3.0 |
| idna | 1.1.0 | MIT OR Apache-2.0 |
| idna_adapter | 1.2.2 | Apache-2.0 OR MIT |
| itoa | 1.0.15 | MIT OR Apache-2.0 |
| libc | 0.2.191 | MIT OR Apache-2.0 |
| litemap | 0.8.3 | Unicode-3.0 |
| lock_api | 0.4.14 | MIT OR Apache-2.0 |
| log | 0.4.34 | MIT OR Apache-2.0 |
| lzma-rust2 | 0.25.0 | Apache-2.0 |
| memchr | 2.7.4 | Unlicense OR MIT |
| memoffset | 0.9.1 | MIT |
| miniz_oxide | 0.9.1 | MIT OR Zlib OR Apache-2.0 |
| mio | 1.2.4 | MIT |
| num-conv | 0.2.2 | MIT OR Apache-2.0 |
| once_cell | 1.21.4 | MIT OR Apache-2.0 |
| parking_lot | 0.12.5 | MIT OR Apache-2.0 |
| parking_lot_core | 0.9.12 | MIT OR Apache-2.0 |
| percent-encoding | 2.3.2 | MIT OR Apache-2.0 |
| pin-project-lite | 0.2.17 | Apache-2.0 OR MIT |
| potential_utf | 0.1.6 | Unicode-3.0 |
| powerfmt | 0.2.1 | MIT OR Apache-2.0 |
| proc-macro2 | 1.0.95 | MIT OR Apache-2.0 |
| quote | 1.0.47 | MIT OR Apache-2.0 |
| raw-window-handle | 0.6.2 | MIT OR Apache-2.0 OR Zlib |
| ring | 0.17.14 | Apache-2.0 AND ISC |
| rustls | 0.23.46 | Apache-2.0 OR ISC OR MIT |
| rustls-pki-types | 1.15.1 | MIT OR Apache-2.0 |
| rustls-webpki | 0.103.17 | ISC |
| ryu | 1.0.20 | Apache-2.0 OR BSL-1.0 |
| scopeguard | 1.2.0 | MIT OR Apache-2.0 |
| serde | 1.0.220 | MIT OR Apache-2.0 |
| serde_core | 1.0.220 | MIT OR Apache-2.0 |
| serde_derive | 1.0.220 | MIT OR Apache-2.0 |
| serde_json | 1.0.140 | MIT OR Apache-2.0 |
| sevenz-rust2 | 0.25.0 | Apache-2.0 |
| sha1 | 0.10.7 | MIT OR Apache-2.0 |
| sha2 | 0.10.9 | MIT OR Apache-2.0 |
| shlex | 2.0.1 | MIT OR Apache-2.0 |
| simd-adler32 | 0.3.10 | MIT |
| smallvec | 1.16.0 | MIT OR Apache-2.0 |
| socket2 | 0.5.10 | MIT OR Apache-2.0 |
| stable_deref_trait | 1.2.1 | MIT OR Apache-2.0 |
| subtle | 2.6.1 | BSD-3-Clause |
| syn | 2.0.100 | MIT OR Apache-2.0 |
| syn | 3.0.5 | MIT OR Apache-2.0 |
| synstructure | 0.13.2 | MIT |
| tao | 0.37.1 | Apache-2.0 |
| tempfile | 3.27.0 | MIT OR Apache-2.0 |
| thiserror | 1.0.69 | MIT OR Apache-2.0 |
| thiserror | 2.0.20 | MIT OR Apache-2.0 |
| thiserror-impl | 1.0.69 | MIT OR Apache-2.0 |
| thiserror-impl | 2.0.20 | MIT OR Apache-2.0 |
| time | 0.3.55 | MIT OR Apache-2.0 |
| time-core | 0.1.9 | MIT OR Apache-2.0 |
| time-macros | 0.2.32 | MIT OR Apache-2.0 |
| tinystr | 0.8.4 | Unicode-3.0 |
| tokio | 1.53.3 | MIT |
| typenum | 1.20.1 | MIT OR Apache-2.0 |
| uds_windows | 1.2.1 | MIT |
| unicode-ident | 1.0.18 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| unicode-segmentation | 1.13.3 | MIT OR Apache-2.0 |
| untrusted | 0.9.0 | ISC |
| ureq | 3.4.2 | MIT OR Apache-2.0 |
| ureq-proto | 0.6.4 | MIT OR Apache-2.0 |
| url | 2.5.9 | MIT OR Apache-2.0 |
| utf8-zero | 0.8.1 | MIT OR Apache-2.0 |
| utf8_iter | 1.0.4 | Apache-2.0 OR MIT |
| version_check | 0.9.5 | MIT/Apache-2.0 |
| webpki-roots | 1.0.12 | CDLA-Permissive-2.0 |
| webview2-com | 0.39.1 | MIT |
| webview2-com-macros | 0.8.1 | MIT |
| webview2-com-sys | 0.39.1 | MIT |
| windows | 0.62.2 | MIT OR Apache-2.0 |
| windows-collections | 0.3.2 | MIT OR Apache-2.0 |
| windows-core | 0.62.2 | MIT OR Apache-2.0 |
| windows-future | 0.3.2 | MIT OR Apache-2.0 |
| windows-implement | 0.60.2 | MIT OR Apache-2.0 |
| windows-interface | 0.59.3 | MIT OR Apache-2.0 |
| windows-link | 0.2.1 | MIT OR Apache-2.0 |
| windows-numerics | 0.3.1 | MIT OR Apache-2.0 |
| windows-result | 0.4.1 | MIT OR Apache-2.0 |
| windows-strings | 0.5.1 | MIT OR Apache-2.0 |
| windows-sys | 0.52.0 | MIT OR Apache-2.0 |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 |
| windows-targets | 0.52.6 | MIT OR Apache-2.0 |
| windows-threading | 0.2.1 | MIT OR Apache-2.0 |
| windows-version | 0.1.7 | MIT OR Apache-2.0 |
| windows_x86_64_msvc | 0.52.6 | MIT OR Apache-2.0 |
| writeable | 0.6.4 | Unicode-3.0 |
| wry | 0.57.0 | Apache-2.0 OR MIT |
| yoke | 0.8.3 | Unicode-3.0 |
| yoke-derive | 0.8.2 | Unicode-3.0 |
| zerofrom | 0.1.8 | Unicode-3.0 |
| zerofrom-derive | 0.1.7 | Unicode-3.0 |
| zeroize | 1.9.1 | Apache-2.0 OR MIT |
| zerotrie | 0.2.5 | Unicode-3.0 |
| zerovec | 0.11.8 | Unicode-3.0 |
| zerovec-derive | 0.11.6 | Unicode-3.0 |

## Bundled third-party files

| Component | Version | Licence | Location and origin |
| --- | --- | --- | --- |
| noVNC, runtime subset (`core/`, `vendor/pako` and the licence texts) | 1.7.0 | MPL-2.0 for the core library; files with their own notices keep them | `crates/svmd/vendor/novnc`, embedded in `svmd.exe` for the in-app console. Copied from the noVNC v1.7.0 source archive, https://github.com/novnc/noVNC/archive/refs/tags/v1.7.0.zip (823,923 bytes, SHA-256 d55e9cce9a611294df33c7200f32f35108652de2d86a468bebcfc6f2a1c9a196, computed at download; GitHub publishes no checksum for source archives). The version comes from that release tag: the vendored files carry no version string of their own. |
| pako | the copy bundled with noVNC 1.7.0 | MIT | `crates/svmd/vendor/novnc/vendor/pako`, with its `LICENSE` file |
| Quickget catalog data | Quickemu commit 848ed99ef6d7187ccecf77d01caf0ec70a089faa | MIT | The Debian netinst and FreeBSD disc 1 release and file-name rules in `crates/svmd/catalog/entries.json` are adapted from quickget at that commit. Its licence is kept as `crates/svmd/catalog/LICENSE.quickget`. |

The quickget files read at that commit ([source](https://github.com/quickemu-project/quickemu/blob/848ed99ef6d7187ccecf77d01caf0ec70a089faa/quickget)):

| Upstream quickget file | Bytes | SHA-256 |
| --- | ---: | --- |
| quickget | 142211 | 23e6dd3d6654756fb02a56b3e6a1dc7e527f19f4fbba4665719152937db7bb04 |
| LICENSE | 1070 | c71271b024fc70cdff0c17b87cbc7b6fd1856dee9b5ec189b4f6b35e58772d10 |

### Publisher keys and signed checksum lists

These files in `crates/svmd/catalog` are embedded in `svmd.exe` so that downloads can be checked offline. The checksum lists and signatures are the publishers' files, unchanged (`.gitattributes` keeps their exact bytes). Each keyring is a binary OpenPGP keyring with exactly one primary key.

| File | Publisher | Bytes | SHA-256 | Content |
| --- | --- | ---: | --- | --- |
| amd64.SHA512SUMS | Debian | 494 | 5ecd51efd8ec5e1e33a2775af2fbefc106b8bf011441e3fe3fbe27be30ba7482 | SHA-512 list for the Debian 13.7.0 amd64 CD images |
| amd64.SHA512SUMS.sign | Debian | 833 | a0b29fe1ee5048366117b20b3efd14f6e6a2154e3ff61a41b2b0c2f7be83a2b1 | Detached signature of that list |
| arm64.SHA512SUMS | Debian | 162 | 897ac2447053a42aaef439499927e50623e0be0cd639536a19311e752f79170e | SHA-512 list for the Debian 13.7.0 arm64 CD images |
| arm64.SHA512SUMS.sign | Debian | 833 | 791da0efaf85e910d7a9400620e69e34ca3b923a415161d05300cb7629b5ca83 | Detached signature of that list |
| debian-cd-keyring.gpg | Debian | 4469 | b170997fa60b664a5fa0b8f69fde618c8f3fd1209a7bb50739f59666be4b1f22 | Debian CD signing key DF9B9C49EAA9298432589D76DA87E80D6294BE9B |
| freebsd.SHA256SUMS.asc | FreeBSD | 2053 | 801924b52ac5614686486a602055d1ec8d5034545d2572e4fd390fab782a2946 | Cleartext-signed SHA-256 checksums for FreeBSD 15.1-RELEASE amd64 |
| freebsd-release-keyring.gpg | FreeBSD | 6447 | b7df85be96bfd3b46659a969fe449ed44907622f5db2862fa30f4b679d71a904 | FreeBSD release signing key 82563B84D0620EDC0DFB86413897F2E22E65AD3F, converted from the key FreeBSD publishes |
| kali-2026.3.SHA256SUMS | Kali Linux | 2840 | e10a7c773e8e10cf5e63ca9783794c7c38c4405bd80b64e1a76ab73c2490dfdc | SHA256SUMS for the Kali 2026.3 images |
| kali-2026.3.SHA256SUMS.gpg | Kali Linux | 833 | 37a29054e0aa0424f5be1d1bb4c031a47a97d37c36f3ed8b9ffd4ec30996a8fa | Detached signature of that list |
| kali-archive-keyring.gpg | Kali Linux | 1193 | d7f0a918930496f1f91e209d244a68b878a2ab6ace859d3f8b5ebfce60ac85fa | Kali archive signing key 827C8569F2518CC677FECA1AED65462EC8D5E4C5, the binary form of https://archive.kali.org/archive-key.asc |
| ubuntu-26.04-cloud.SHA256SUMS | Canonical | 8788 | e9510b641d24cdab234f02f2772fad872914c2ef1687d6f690bdffb6b421e882 | SHA256SUMS for the Ubuntu 26.04 cloud images, release-20261108 |
| ubuntu-26.04-cloud.SHA256SUMS.gpg | Canonical | 833 | 35e7f11c4869dea90ed2e3354c4950c682e0c3b50b0e246a31e427532785c562 | Detached signature of that list |
| ubuntu-cloudimage-keyring.gpg | Canonical | 2363 | 7d3205c5554f6690006751edae92f147c0c26d4e0bc33ce04709f3f94ca3679d | UEC Image Automatic Signing Key D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81, exported from https://keyserver.ubuntu.com |

Publisher documentation for these keys and lists: [Debian ISO verification](https://www.debian.org/CD/verify), [Debian installer links](https://www.debian.org/releases/stable/debian-installer/), [FreeBSD 15.1 signed checksums](https://www.freebsd.org/releases/15.1R/signatures/), [FreeBSD published keys](https://docs.freebsd.org/en/articles/pgpkeys/), [Kali image verification](https://www.kali.org/docs/introduction/download-images-securely/).

## Installer catalog

The marketplace offers operating-system installers in two ways. Signatures are checked with `gpgv` from Git for Windows at the fixed path `C:\Program Files\Git\usr\bin\gpgv.exe`; without it the app refuses signed downloads and says so before any installer data is received. Downloads use HTTPS and only the publisher hosts named in the catalog.

### Bundled entries

Each entry is pinned to an exact file and SHA-256. The download must match the pin, and its digest must also appear for that file in the publisher's signed checksum list shipped with the app.

| Entry | File | Pinned SHA-256 | Publisher signature |
| --- | --- | --- | --- |
| Debian 13.7.0 amd64 network installer | debian-13.7.0-amd64-netinst.iso | a7ef94ac2fb9a7fec454552abd629b7cc9d5155c886165a45649f5ce6167e355 | SHA512SUMS signed by the Debian CD signing key DF9B9C49EAA9298432589D76DA87E80D6294BE9B |
| Debian 13.7.0 arm64 network installer | debian-13.7.0-arm64-netinst.iso | 6e93fa1759bd9d4b0fc11e938987de6967ee7de5297dac1be27c3a75cc17024b | SHA512SUMS signed by the Debian CD signing key DF9B9C49EAA9298432589D76DA87E80D6294BE9B |
| FreeBSD 15.1 amd64 disc 1 | FreeBSD-15.1-RELEASE-amd64-disc1.iso | fa27646f05a1440fd26ffbb85e06a50bc86e128242a4e9cb7bb3ea76e1aa5fd9 | Cleartext-signed SHA-256 checksums, key 82563B84D0620EDC0DFB86413897F2E22E65AD3F |

### Check latest entries

**Check latest** finds the newest release when the user asks. It reads bounded publisher metadata, picks the matching x86-64 installer and reads its size from the publisher's media host; the transfer starts only after the user confirms the size and the free space. The installer's checksum comes from the publisher's signed checksum list. For Arch Linux and Security Onion it comes from publisher metadata instead, and the installer's detached signature is checked after the download. The publisher's keyring is fetched at check time from the address in the catalog; for Linux Mint, Arch Linux and Security Onion that is a public keyserver or GitHub, not the publisher's own host. Only a signature whose primary key matches the pinned fingerprint is accepted, and a release older than the pinned one is refused. If the newest release cannot be verified, the app offers the pinned release instead. The app keeps the verified release record, so an earlier download stays available after a refresh.

| Publisher | Pinned release (minimum and fallback) | Pinned primary fingerprint | Checksum evidence | Signing key fetched from |
| --- | --- | --- | --- | --- |
| Ubuntu Desktop LTS | 26.04.1 amd64 | 843938DF228D22F7B3742BC0D94AA3F0EFE21092 | Detached signature on SHA256SUMS | archive.ubuntu.com |
| Linux Mint Cinnamon | 22.3 64-bit | 27DEB15644C6B3CF3BD7D291300F846BA25BAE09 | Detached signature on sha256sum.txt | keys.openpgp.org (public keyserver) |
| Fedora Workstation | 45-1.4 x86-64 | 4F50A6114CD5C6976A7F1179655A4B02F577861E | Cleartext-signed SHA-256 list | fedoraproject.org |
| Rocky Linux Minimal | 10.3-20261113.0 x86-64 | FC226859C0860BF0DDB95B085B106C736FEDFC85 | Detached signature on the SHA-256 list | download.rockylinux.org |
| AlmaLinux Minimal | 10.3 x86-64 | EE6DB7B98F5BF5EDD9DA0DE5DEE5C11CC2A1E572 | Cleartext-signed SHA-256 list | repo.almalinux.org |
| Arch Linux | 2026.11.01 x86-64 | 3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C | SHA-256 from the publisher's sha256sums.txt; detached signature on the installer | keyserver.ubuntu.com (public keyserver) |
| openSUSE Leap Network Installer | 16.1 x86-64 | AD485664E901B867051AB15F35A2F86E29B700A4 | Detached signature on the SHA-512 list, matched against the official Metalink SHA-256 | download.opensuse.org |
| Security Onion | 3.4.0-20261102 x86-64 | C804A93D36BE0C733EA196447C1060B7FE507013 | SHA-256 from the publisher's download notes on GitHub; detached signature on the installer | raw.githubusercontent.com (GitHub) |
| Kali Linux Network Installer | 2026.3 amd64 | 827C8569F2518CC677FECA1AED65462EC8D5E4C5 | Detached signature on SHA256SUMS | archive.kali.org |
| Parrot Security | 7.4 amd64 | B711822346552E4D92DA02DF7A8286AF0E81EE4A | Cleartext-signed SHA-256 list | deb.parrot.sh |

The fingerprints come from the publishers' documentation. A publisher that signs with a new key fails verification until the catalog pins it. [Ubuntu verification](https://ubuntu.com/tutorials/how-to-verify-ubuntu), [Linux Mint verification](https://linuxmint.com/verify.php), [Fedora signing keys](https://fedoraproject.org/en/security/), [Rocky signing keys](https://rockylinux.org/resources/gpg-key-info), [AlmaLinux release key](https://wiki.almalinux.org/release-notes/10.3), [Arch release and signing information](https://archlinux.org/download/), [Arch developer fingerprints](https://archlinux.org/people/developers/), [openSUSE release and key information](https://get.opensuse.org/leap/16.1/), [Security Onion release verification](https://raw.githubusercontent.com/Security-Onion-Solutions/securityonion/4dc7f2d97c887eb9e2ad00c403b5b265b0cd333f/DOWNLOAD_AND_VERIFY_ISO.md), [Kali verification](https://www.kali.org/docs/introduction/download-images-securely/), [Parrot verification](https://docs.parrot.sh/docs/configuration/hash-and-key-verification/)

### Windows media

The app does not download Windows. The new-machine wizard checks a selected English x64 ISO against the SHA-256 that Microsoft publishes on its download pages. Microsoft's download links expire after 24 hours, and Windows activation needs a valid licence. [Windows 10 download and checksums](https://www.microsoft.com/en-us/software-download/windows10ISO), [Windows 11 download and checksums](https://www.microsoft.com/en-us/software-download/windows11)

| Windows media | Microsoft published SHA-256 |
| --- | --- |
| Windows 10 22H2 English x64 | a6f470ca6d331eb353b815c043e327a347f594f37ff525f17764738fe812852e |
| Windows 11 26H2 English x64 | bd4307df32bc8af33b39ccecb1174aeb345386630f89a2b86c7a4e36b55ea650 |

The Windows Server 2022 and 2025 evaluation entries use an ISO the user supplies; Microsoft requires registration, the evaluation lasts 180 days, and those pages publish no checksum. [Windows Server 2022 Evaluation Center](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2022), [Windows Server 2025 Evaluation Center](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025). Windows XP, Vista, 7 and 8 use the user's own ISO with a QEMU legacy BIOS profile (IDE storage, VGA and PS/2 input). [QEMU PC system emulator](https://www.qemu.org/docs/master/system/i386/pc.html)

## Ready-to-run images

Each image is pinned in `crates/svmd/catalog/ready.json` and is downloaded only when the user chooses **Get**. The service checks the pinned SHA-256 of the downloaded file. For Kali and Ubuntu it also checks the publisher's signed `SHA256SUMS`, shipped in `crates/svmd/catalog/`, with `gpgv` against a bundled keyring that holds only the pinned primary key. Debian publishes no signature for its cloud image list, so Debian is labelled **Checksum**.

| Image | Catalog ID | File | Bytes | Pinned SHA-256 | Publisher check | Official source |
| --- | --- | --- | --- | --- | --- | --- |
| Debian 13 cloud (generic, amd64) | debian-13-20261123-cloud-amd64 | debian-13-generic-amd64-20261123-2671.qcow2 | 439,484,416 | 7b8981e785a013986df45133c1c74b722b1a6e4d6c80a975bdcdcece5c553131 | SHA-512 562a4614…87104f listed in Debian's `SHA512SUMS` (unsigned); SHA-256 computed from the matching file | [cloud.debian.org dated build 20261123-2671](https://cloud.debian.org/images/cloud/trixie/20261123-2671/) (redirects to Debian's mirror host laotzu.ftp.acc.umu.se, which is allowed by name) |
| Ubuntu Server 26.04 LTS cloud (amd64) | ubuntu-26-04-20261108-cloud-amd64 | ubuntu-26.04-server-cloudimg-amd64.img | 861,563,904 | 7b90593f5532b49b7e3fe3d2743f0d1f0d822e5b07cebcd8e00c0df8069ecab9 | `SHA256SUMS` signed by D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81 (UEC Image Automatic Signing Key) | [cloud-images.ubuntu.com release-20261108](https://cloud-images.ubuntu.com/releases/26.04/release-20261108/) |
| Kali Linux 2026.3 QEMU (amd64) | kali-2026-3-qemu-amd64 | kali-linux-2026.3-qemu-amd64.7z | 3,900,428,588 | 6a73c8496064cc5e6b26a82084b7a7e6d0aea92047e555af34a9208fd430bae8 | `SHA256SUMS` from cdimage.kali.org/kali-2026.3, signed by 827C8569F2518CC677FECA1AED65462EC8D5E4C5 (Kali Linux Archive Automatic Signing Key (2025)), the key also pinned for Kali installers | [kali.download/base-images/kali-2026.3](https://kali.download/base-images/kali-2026.3/), Kali's own download network |

Kali's archive holds one disk, `kali-linux-2026.3-qemu-amd64.qcow2`: 16,638,869,504 bytes, SHA-256 186bd39eedfb3214774a807215ef39f2fbece9d47a462d3fa4cc227877719fbd. The service checks both values while unpacking and refuses an archive that holds anything else. Virtual disk sizes: Debian 3,221,225,472, Ubuntu 3,758,096,384 and Kali 86,000,000,000 bytes.

Keys: the Kali keyring is the binary form of https://archive.kali.org/archive-key.asc. The Ubuntu cloud image keyring was exported from https://keyserver.ubuntu.com for the fingerprint above; the signature on the official `SHA256SUMS` from cloud-images.ubuntu.com verifies with it, and the keyserver lists the same user ID. This fingerprint was not cross-checked against an Ubuntu documentation page.

First-boot settings use only code in this repository: SHA-512-crypt password hashes (tested against the seven test vectors of the SHA-crypt specification, https://www.akkadia.org/drepper/SHA-crypt.txt) and QEMU's built-in read-only `vvfat` driver for the CIDATA volume. On first boot, cloud-init in the Debian and Ubuntu images installs `qemu-guest-agent` from the distribution's own signed package repositories.

## Apps and AI tools marketplace

The bundled catalog holds typed install recipes. Downloads and verification run inside the selected guest. APT uses a temporary source list: it refreshes the distribution's signed metadata and, for a **Signed** recipe, checks the publisher's key before it adds that repository. The publisher key is scoped to its source, and the guest's normal APT configuration is not changed.

| Signed recipe | Full primary OpenPGP fingerprint | Publisher evidence |
| --- | --- | --- |
| Docker Engine on Debian and Ubuntu | 9DC858229FC7DD38854AE2D88D81803C0EBFCD88 | [Debian repository instructions](https://docs.docker.com/engine/install/debian/), [Ubuntu repository instructions](https://docs.docker.com/engine/install/ubuntu/), [Debian public key](https://download.docker.com/linux/debian/gpg), [Ubuntu public key](https://download.docker.com/linux/ubuntu/gpg) |
| Visual Studio Code on Debian-family guests | BC528686B50D79E339D3721CEB3E94ADBE1229CF | [VS Code Linux repository instructions](https://code.visualstudio.com/docs/setup/linux), [Microsoft published fingerprint](https://learn.microsoft.com/en-us/linux/packages), [Microsoft public key](https://packages.microsoft.com/keys/microsoft.asc) |

The full fingerprints were computed from the three official public-key files. The guest checks the full primary fingerprint again on each Signed install. WinGet uses the exact app ID and Microsoft's default community repository, with WinGet's normal hash checks. [WinGet source identity](https://learn.microsoft.com/en-us/windows/package-manager/winget/source#export), [Community manifests](https://github.com/microsoft/winget-pkgs)

Open WebUI is labelled **Checksum**: Docker pulls the publisher's Debian-based 0.13.4-slim amd64/arm64 OCI index by digest `sha256:0c4439e78c24c85e3e7a41936771d3b02f0df38daf28a086cd83ca74804f7676` from the publisher's Docker Hub repository, and the image stays inside the guest. [Publisher deployment documentation](https://docs.openwebui.com/getting-started/quick-start/), [Docker Hub index digest](https://hub.docker.com/layers/openwebui/open-webui/0.13.4-slim/images/sha256-4da3e2b46ebb1dd63f025ec1cf20a0d834094d75bd2a390762810adc76dbc641)

Ollama publishes checksums for its release archives, but an archive install is outside the package-manager recipes. PyTorch CPU stays a **Reference** until a compatible wheel set and its dependency hashes are pinned. [Ollama releases](https://github.com/ollama/ollama/releases), [PyTorch CPU package index instructions](https://pytorch.org/get-started/locally/)

## QEMU (not included)

QEMU is not part of Secwizt VM. The user provides it and chooses `qemu-system-x86_64.exe` in **Settings → QEMU**. Secwizt VM was tested with the build below. `setup/build-slim-qemu.mjs` can make a smaller copy of that verified build; it keeps QEMU's licence files and checks every file against `setup/qemu-slim-11.1.0.json`.

| QEMU item | Value |
| --- | --- |
| Tested build | QEMU 11.1.0 for Windows x86-64, installer build of 2026-08-11 |
| File | qemu-w64-setup-20260811.exe, 206,615,928 bytes |
| Source | https://qemu.weilnetz.de/w64/qemu-w64-setup-20260811.exe (HTTPS) |
| SHA-512 | 5bcf9eed634e8575a37b74f445af41a2fe4106da512d0c30c368301d4c105037fdfab40a5287367a28a957624cddebbc8c07e16c88ab6634f554cdf3d16bf543, as published in https://qemu.weilnetz.de/w64/qemu-w64-setup-20260811.sha512 |
| Licence | GPL-2.0; some components carry their own licences, which QEMU's own notices list |
| Accelerators used | `whpx` (Windows Hypervisor Platform) for x86 guests; `tcg` software emulation for Arm guests |

## Microsoft WebView2 loader

| Component | Version | Licence | How it is included |
| --- | --- | --- | --- |
| Microsoft WebView2 SDK loader (`WebView2LoaderStatic.lib`, x64) | from WebView2 SDK 1.0.3800.47, the version of the `WebView2Loader.dll` shipped beside it in webview2-com-sys 0.39.1 | Microsoft WebView2 SDK licence terms, published with the Microsoft.Web.WebView2 package; the crate package does not include them | Linked statically into `svm-app.exe` by webview2-com-sys on the MSVC target. SHA-256 of the x64 library: 89c6b872783b8f6c3cedbff618adb42082d455c615453ae10cfc753f1e8f25d8 |

The Microsoft Edge WebView2 Runtime that draws the interface is not included; it is part of current Windows or is installed separately.

### Other targets in Cargo.lock

`Cargo.lock` also records 160 packages that the `x86_64-pc-windows-msvc` build never compiles: dependencies that only other platforms use (Linux desktop, macOS and iOS, Android, Redox, UEFI, WebAssembly and other Windows targets), plus one Apple-only entry the resolver keeps. They are listed for completeness and are not shown in the app. `cssparser`, `cssparser-macros`, `dtoa-short`, `selectors` and `option-ext` declare MPL-2.0, and `r-efi` offers LGPL-2.1-or-later as one of three choices. Building or shipping Secwizt VM for another target needs its own licence review.

| Crate | Version | Licence |
| --- | --- | --- |
| atk | 0.18.2 | MIT |
| atk-sys | 0.18.2 | MIT |
| bit-set | 0.8.0 | Apache-2.0 OR MIT |
| bit-vec | 0.8.0 | Apache-2.0 OR MIT |
| block2 | 0.6.2 | MIT |
| bumpalo | 3.20.4 | MIT OR Apache-2.0 |
| cairo-rs | 0.18.5 | MIT |
| cairo-sys-rs | 0.18.2 | MIT |
| cesu8 | 1.1.0 | Apache-2.0/MIT |
| cfg-expr | 0.15.8 | MIT OR Apache-2.0 |
| combine | 4.6.8 | MIT |
| core-foundation | 0.10.1 | MIT OR Apache-2.0 |
| core-foundation-sys | 0.8.7 | MIT OR Apache-2.0 |
| core-graphics | 0.25.0 | MIT OR Apache-2.0 |
| core-graphics-types | 0.2.0 | MIT OR Apache-2.0 |
| cssparser | 0.37.0 | MPL-2.0 |
| cssparser-macros | 0.7.1 | MPL-2.0 |
| derive_more | 2.1.1 | MIT |
| derive_more-impl | 2.1.1 | MIT |
| dirs | 7.0.0 | MIT OR Apache-2.0 |
| dirs-sys | 0.5.0 | MIT OR Apache-2.0 |
| dispatch2 | 0.3.1 | Zlib OR Apache-2.0 OR MIT |
| dlopen2 | 0.8.2 | MIT |
| dlopen2_derive | 0.4.3 | MIT |
| dom_query | 0.28.0 | MIT |
| dtoa | 1.0.11 | MIT OR Apache-2.0 |
| dtoa-short | 0.3.5 | MPL-2.0 |
| equivalent | 1.0.3 | Apache-2.0 OR MIT |
| errno | 0.3.14 | MIT OR Apache-2.0 |
| field-offset | 0.3.6 | MIT OR Apache-2.0 |
| foldhash | 0.2.0 | Zlib |
| foreign-types | 0.5.0 | MIT/Apache-2.0 |
| foreign-types-macros | 0.2.4 | MIT/Apache-2.0 |
| foreign-types-shared | 0.3.1 | MIT/Apache-2.0 |
| futures-channel | 0.3.34 | MIT OR Apache-2.0 |
| futures-core | 0.3.34 | MIT OR Apache-2.0 |
| futures-executor | 0.3.34 | MIT OR Apache-2.0 |
| futures-io | 0.3.34 | MIT OR Apache-2.0 |
| futures-macro | 0.3.34 | MIT OR Apache-2.0 |
| futures-task | 0.3.34 | MIT OR Apache-2.0 |
| futures-util | 0.3.34 | MIT OR Apache-2.0 |
| gdk | 0.18.2 | MIT |
| gdk-pixbuf | 0.18.5 | MIT |
| gdk-pixbuf-sys | 0.18.0 | MIT |
| gdk-sys | 0.18.2 | MIT |
| gdkwayland-sys | 0.18.2 | MIT |
| gio | 0.18.4 | MIT |
| gio-sys | 0.18.1 | MIT |
| glib | 0.18.5 | MIT |
| glib-macros | 0.18.5 | MIT |
| glib-sys | 0.18.1 | MIT |
| gobject-sys | 0.18.0 | MIT |
| gtk | 0.18.2 | MIT |
| gtk-sys | 0.18.2 | MIT |
| gtk3-macros | 0.18.2 | MIT |
| hashbrown | 0.17.1 | MIT OR Apache-2.0 |
| heck | 0.4.1 | MIT OR Apache-2.0 |
| heck | 0.5.0 | MIT OR Apache-2.0 |
| html5ever | 0.39.0 | MIT OR Apache-2.0 |
| indexmap | 2.14.2 | Apache-2.0 OR MIT |
| jni | 0.21.1 | MIT/Apache-2.0 |
| jni-sys | 0.3.1 | MIT OR Apache-2.0 |
| jni-sys | 0.4.1 | MIT OR Apache-2.0 |
| jni-sys-macros | 0.4.1 | MIT OR Apache-2.0 |
| js-sys | 0.3.107 | MIT OR Apache-2.0 |
| libredox | 0.1.25 | MIT |
| linux-raw-sys | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| markup5ever | 0.39.0 | MIT OR Apache-2.0 |
| ndk | 0.9.0 | MIT OR Apache-2.0 |
| ndk-context | 0.1.1 | MIT OR Apache-2.0 |
| ndk-sys | 0.6.0+11769913 | MIT OR Apache-2.0 |
| new_debug_unreachable | 1.0.6 | MIT |
| num_enum | 0.7.6 | BSD-3-Clause OR MIT OR Apache-2.0 |
| num_enum_derive | 0.7.6 | BSD-3-Clause OR MIT OR Apache-2.0 |
| objc2 | 0.6.5 | MIT |
| objc2-app-kit | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| objc2-cloud-kit | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| objc2-core-data | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| objc2-core-foundation | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| objc2-core-graphics | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| objc2-core-image | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| objc2-core-location | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| objc2-core-text | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| objc2-encode | 4.1.0 | MIT |
| objc2-exception-helper | 0.1.1 | Zlib OR Apache-2.0 OR MIT |
| objc2-foundation | 0.3.2 | MIT |
| objc2-io-surface | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| objc2-quartz-core | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| objc2-ui-kit | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| objc2-user-notifications | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| objc2-web-kit | 0.3.2 | Zlib OR Apache-2.0 OR MIT |
| option-ext | 0.2.0 | MPL-2.0 |
| pango | 0.18.3 | MIT |
| pango-sys | 0.18.0 | MIT |
| phf | 0.13.1 | MIT |
| phf_codegen | 0.13.1 | MIT |
| phf_generator | 0.13.1 | MIT |
| phf_macros | 0.13.1 | MIT |
| phf_shared | 0.13.1 | MIT |
| pkg-config | 0.3.34 | MIT OR Apache-2.0 |
| precomputed-hash | 0.1.1 | MIT |
| proc-macro-crate | 1.3.1 | MIT OR Apache-2.0 |
| proc-macro-crate | 2.0.2 | MIT OR Apache-2.0 |
| proc-macro-error | 1.0.4 | MIT OR Apache-2.0 |
| proc-macro-error-attr | 1.0.4 | MIT OR Apache-2.0 |
| r-efi | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| redox_syscall | 0.5.18 | MIT |
| redox_users | 0.5.3 | MIT |
| rustc-hash | 2.1.3 | Apache-2.0 OR MIT |
| rustc_version | 0.4.1 | MIT OR Apache-2.0 |
| rustix | 1.1.5 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| rustversion | 1.0.23 | MIT OR Apache-2.0 |
| same-file | 1.0.6 | Unlicense/MIT |
| selectors | 0.38.0 | MPL-2.0 |
| semver | 1.0.28 | MIT OR Apache-2.0 |
| serde_spanned | 0.6.9 | MIT OR Apache-2.0 |
| servo_arc | 0.4.3 | MIT OR Apache-2.0 |
| signal-hook-registry | 1.4.8 | MIT OR Apache-2.0 |
| siphasher | 1.0.4 | MIT OR Apache-2.0 |
| slab | 0.4.12 | MIT |
| string_cache | 0.9.0 | MIT OR Apache-2.0 |
| string_cache_codegen | 0.6.1 | MIT OR Apache-2.0 |
| syn | 1.0.109 | MIT OR Apache-2.0 |
| system-deps | 6.2.2 | MIT OR Apache-2.0 |
| tao-macros | 0.1.4 | MIT OR Apache-2.0 |
| target-lexicon | 0.12.16 | Apache-2.0 WITH LLVM-exception |
| tendril | 0.5.1 | MIT OR Apache-2.0 |
| toml | 0.8.2 | MIT OR Apache-2.0 |
| toml_datetime | 0.6.3 | MIT OR Apache-2.0 |
| toml_edit | 0.19.15 | MIT OR Apache-2.0 |
| toml_edit | 0.20.2 | MIT OR Apache-2.0 |
| version-compare | 0.2.1 | MIT |
| walkdir | 2.5.0 | Unlicense/MIT |
| wasi | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasm-bindgen | 0.2.130 | MIT OR Apache-2.0 |
| wasm-bindgen-macro | 0.2.130 | MIT OR Apache-2.0 |
| wasm-bindgen-macro-support | 0.2.130 | MIT OR Apache-2.0 |
| wasm-bindgen-shared | 0.2.130 | MIT OR Apache-2.0 |
| web_atoms | 0.2.6 | MIT OR Apache-2.0 |
| winapi | 0.3.9 | MIT/Apache-2.0 |
| winapi-i686-pc-windows-gnu | 0.4.0 | MIT/Apache-2.0 |
| winapi-util | 0.1.11 | Unlicense OR MIT |
| winapi-x86_64-pc-windows-gnu | 0.4.0 | MIT/Apache-2.0 |
| windows-sys | 0.45.0 | MIT OR Apache-2.0 |
| windows-targets | 0.42.2 | MIT OR Apache-2.0 |
| windows_aarch64_gnullvm | 0.42.2 | MIT OR Apache-2.0 |
| windows_aarch64_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_aarch64_msvc | 0.42.2 | MIT OR Apache-2.0 |
| windows_aarch64_msvc | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_gnu | 0.42.2 | MIT OR Apache-2.0 |
| windows_i686_gnu | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_i686_msvc | 0.42.2 | MIT OR Apache-2.0 |
| windows_i686_msvc | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_gnu | 0.42.2 | MIT OR Apache-2.0 |
| windows_x86_64_gnu | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_gnullvm | 0.42.2 | MIT OR Apache-2.0 |
| windows_x86_64_gnullvm | 0.52.6 | MIT OR Apache-2.0 |
| windows_x86_64_msvc | 0.42.2 | MIT OR Apache-2.0 |
| winnow | 0.5.40 | MIT |
