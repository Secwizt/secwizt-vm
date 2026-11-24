# Third-party notices

Secwizt VM's own code is licensed under the Apache License, Version 2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). The components below keep their own licences. [THIRD-PARTY-LICENSES.txt](THIRD-PARTY-LICENSES.txt) holds the full licence texts of everything compiled into or embedded in the Windows programs, and the installer copies it, with this file, `LICENSE` and `NOTICE`, next to the programs. [DOWNLOADS.md](DOWNLOADS.md) lists every component with its exact version, licence and source.

## Included in this repository

| Component | Where | Licence | Notes |
| --- | --- | --- | --- |
| noVNC 1.7.0, runtime subset | `crates/svmd/vendor/novnc` | MPL-2.0 for the core library; `core/crypto/des.js` carries its own BSD-style notices | The in-app console, embedded in `svmd.exe`. Only `core/`, `vendor/pako` and the licence texts are kept, copied from the noVNC 1.7.0 source archive; this repository has not changed them since. `LICENSE.txt` refers to an `AUTHORS` file and the SIL Open Font License text, which are not part of the subset: it has no noVNC fonts, images or HTML. |
| pako (inside noVNC) | `crates/svmd/vendor/novnc/vendor/pako` | MIT | Licence text in that folder. |
| Quickget catalog data | `crates/svmd/catalog` | MIT | Debian and FreeBSD release data adapted from the Quickemu project's quickget. Licence: `crates/svmd/catalog/LICENSE.quickget`. |
| Publisher keys and checksum lists | `crates/svmd/catalog/*.gpg`, `*SHA256SUMS*`, `*SHA512SUMS*` | Published by Debian, FreeBSD, Kali Linux and Canonical for verification | The checksum lists and signatures are the publishers' files, unchanged. The keyrings hold the publishers' public keys as binary OpenPGP keyrings, one primary key each. They let downloads be checked offline. |

## Compiled into the Windows programs

| Component | Licence | Notes |
| --- | --- | --- |
| 133 Rust crates from crates.io | Permissive licences: MIT, Apache-2.0, ISC, BSD-3-Clause, Zlib, Unicode-3.0, CDLA-Permissive-2.0, BSL-1.0, CC0-1.0, MIT-0, 0BSD or Unlicense, often as a choice | Fetched by Cargo at build time, not stored here. `Cargo.lock` pins the exact versions; `DOWNLOADS.md` lists them and the desktop app shows the list under **Settings → About**. |
| Microsoft WebView2 SDK loader (`WebView2LoaderStatic.lib`) | Microsoft WebView2 SDK licence terms | Linked into `svm-app.exe` by the `webview2-com-sys` crate. Its terms are published with the Microsoft.Web.WebView2 package; the crate does not include them, so they are not yet reproduced in `THIRD-PARTY-LICENSES.txt`. |
| Rust standard library | Apache-2.0 OR MIT | Part of every Rust program. |

## Programs used at run time, not included

| Program | Licence | How it is used |
| --- | --- | --- |
| QEMU | GPL-2.0; some components carry their own licences | Chosen by the user in **Settings → QEMU**; runs as a separate program. `setup/build-slim-qemu.mjs` can make a smaller copy of an official QEMU download, keeping QEMU's licence files. |
| gpgv (from Git for Windows) | GPL-3.0-or-later | Checks publisher signatures; runs as a separate program from `C:\Program Files\Git\usr\bin\gpgv.exe`. |
| restic | BSD-2-Clause | Encrypted backups. Supplied by the user ([releases](https://github.com/restic/restic/releases)). The service records the SHA-256 of the selected copy at setup, keeps a private copy and refuses to run it if it changes. |
| age and age-plugin-yubikey | BSD-3-Clause; MIT OR Apache-2.0 | Decrypt the backup repository password with a YubiKey. Supplied by the user ([age releases](https://github.com/FiloSottile/age/releases), [age-plugin-yubikey releases](https://github.com/str4d/age-plugin-yubikey/releases)) and handled like restic. |
| Microsoft Edge WebView2 Runtime | Microsoft software licence | Shows the interface. |

Operating-system images, installers and apps offered in the marketplace are downloaded from their publishers when the user chooses them and are covered by the publishers' own licences.
