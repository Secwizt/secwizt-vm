//! First-boot settings for cloud images (cloud-init NoCloud): a password hash in the SHA-512-crypt
//! format, strict field checks, and the two small files the guest reads from a volume labelled
//! CIDATA. Every value placed in the files comes from a checked field through a fixed template.

use sha2::{Digest, Sha512};

const ITOA64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const DEFAULT_ROUNDS: u32 = 5000;
const MIN_ROUNDS: u32 = 1000;
const MAX_ROUNDS: u32 = 999_999_999;
const MAX_SALT: usize = 16;
/// Characters for generated passwords: no look-alikes (0 O 1 l I) and nothing a keyboard
/// layout or the console could change.
const PASSWORD_ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
pub(super) const GENERATED_PASSWORD_LENGTH: usize = 20;

/// SHA-512-crypt ("$6$"), as specified by U. Drepper's SHA-crypt document. `setting` is
/// `$6$<salt>` or `$6$rounds=<n>$<salt>`; the salt is cut to 16 characters.
pub(super) fn sha512_crypt(key: &[u8], setting: &str) -> Option<String> {
    let rest = setting.strip_prefix("$6$")?;
    let (rounds, explicit, rest) = match rest.strip_prefix("rounds=") {
        Some(tail) => {
            let (number, salt) = tail.split_once('$')?;
            let wanted: u64 = number.parse().ok()?;
            let clamped = u32::try_from(wanted.clamp(u64::from(MIN_ROUNDS), u64::from(MAX_ROUNDS))).ok()?;
            (clamped, true, salt)
        }
        None => (DEFAULT_ROUNDS, false, rest),
    };
    let salt_text = rest.split('$').next()?;
    let salt = &salt_text.as_bytes()[..salt_text.len().min(MAX_SALT)];

    let mut b = Sha512::new();
    b.update(key);
    b.update(salt);
    b.update(key);
    let digest_b = b.finalize();

    let mut a = Sha512::new();
    a.update(key);
    a.update(salt);
    let mut remaining = key.len();
    while remaining > 64 {
        a.update(digest_b);
        remaining -= 64;
    }
    a.update(&digest_b[..remaining]);
    let mut bits = key.len();
    while bits > 0 {
        if bits & 1 != 0 { a.update(digest_b); } else { a.update(key); }
        bits >>= 1;
    }
    let mut digest = a.finalize();

    let mut dp = Sha512::new();
    for _ in 0..key.len() { dp.update(key); }
    let digest_p = dp.finalize();
    let p: Vec<u8> = digest_p.iter().copied().cycle().take(key.len()).collect();

    let mut ds = Sha512::new();
    for _ in 0..16 + usize::from(digest[0]) { ds.update(salt); }
    let digest_s = ds.finalize();
    let s: Vec<u8> = digest_s.iter().copied().cycle().take(salt.len()).collect();

    for round in 0..rounds {
        let mut c = Sha512::new();
        if round & 1 != 0 { c.update(&p); } else { c.update(digest); }
        if round % 3 != 0 { c.update(&s); }
        if round % 7 != 0 { c.update(&p); }
        if round & 1 != 0 { c.update(digest); } else { c.update(&p); }
        digest = c.finalize();
    }

    let mut out = String::from("$6$");
    if explicit { out.push_str(&format!("rounds={rounds}$")); }
    out.push_str(std::str::from_utf8(salt).ok()?);
    out.push('$');
    const ORDER: [(usize, usize, usize); 21] = [
        (0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26), (6, 27, 48),
        (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13),
        (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19), (62, 20, 41),
    ];
    let mut push = |b2: u8, b1: u8, b0: u8, count: usize| {
        let mut word = (u32::from(b2) << 16) | (u32::from(b1) << 8) | u32::from(b0);
        for _ in 0..count {
            out.push(char::from(ITOA64[(word & 0x3f) as usize]));
            word >>= 6;
        }
    };
    for (x, y, z) in ORDER { push(digest[x], digest[y], digest[z], 4); }
    push(0, 0, digest[63], 2);
    Some(out)
}

fn random_bytes(count: usize) -> Result<Vec<u8>, &'static str> {
    let mut bytes = vec![0_u8; count];
    getrandom::fill(&mut bytes).map_err(|_| "The operating system's random source is unavailable.")?;
    Ok(bytes)
}

/// Hash a password with a fresh 16-character random salt.
pub(super) fn hash_password(password: &str) -> Result<String, &'static str> {
    let salt: String = random_bytes(MAX_SALT)?.iter().map(|byte| char::from(ITOA64[usize::from(byte & 0x3f)])).collect();
    sha512_crypt(password.as_bytes(), &format!("$6${salt}")).ok_or("The password could not be hashed.")
}

/// A random password from an unambiguous alphabet (uniform: rejection sampling).
pub(super) fn generate_password() -> Result<String, &'static str> {
    let limit = 256 - (256 % PASSWORD_ALPHABET.len());
    let mut out = String::with_capacity(GENERATED_PASSWORD_LENGTH);
    while out.len() < GENERATED_PASSWORD_LENGTH {
        for byte in random_bytes(64)? {
            if usize::from(byte) < limit && out.len() < GENERATED_PASSWORD_LENGTH {
                out.push(char::from(PASSWORD_ALPHABET[usize::from(byte) % PASSWORD_ALPHABET.len()]));
            }
        }
    }
    Ok(out)
}

const RESERVED_USERS: &[&str] = &[
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy",
    "www-data", "backup", "list", "irc", "gnats", "nobody", "nogroup", "sshd", "messagebus", "syslog",
    "polkitd", "tss", "uuidd", "tcpdump", "dnsmasq", "landscape", "fwupd-refresh", "lxd", "admin",
    "adm", "sudo", "wheel", "users", "staff", "operator", "halt", "shutdown", "ftp", "postgres", "mysql",
];

/// A Linux login name that is safe in every guest: `^[a-z_][a-z0-9_-]{0,30}$`, not a system account.
pub(super) fn valid_user(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty() && bytes.len() <= 31
        && (bytes[0].is_ascii_lowercase() || bytes[0] == b'_')
        && bytes.iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-'))
        && !RESERVED_USERS.contains(&name)
        && !name.starts_with("systemd") && !name.starts_with('_')
}

/// A password typed by the owner: 8 to 128 printable characters, no control characters.
pub(super) fn valid_password(password: &str) -> bool {
    let count = password.chars().count();
    (8..=128).contains(&count) && !password.chars().any(char::is_control) && password.trim() == password
}

/// One DNS label: `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`.
pub(super) fn valid_host(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty() && bytes.len() <= 63
        && bytes.iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && bytes[0] != b'-' && bytes[bytes.len() - 1] != b'-'
}

fn valid_instance(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64
        && id.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_hash(hash: &str) -> bool {
    let Some(rest) = hash.strip_prefix("$6$") else { return false; };
    let Some((salt, digest)) = rest.split_once('$') else { return false; };
    let alphabet = |text: &str| text.bytes().all(|byte| ITOA64.contains(&byte));
    (1..=MAX_SALT).contains(&salt.len()) && alphabet(salt) && digest.len() == 86 && alphabet(digest)
}

const SSH_KEY_TYPES: &[&str] = &[
    "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// Keep only `<type> <base64>` from a one-line OpenSSH public key; the comment is dropped.
pub(super) fn normalized_ssh_key(line: &str) -> Option<String> {
    if line.len() > 8192 || line.contains(['\r', '\n']) { return None; }
    let mut words = line.split_ascii_whitespace();
    let kind = words.next()?;
    let body = words.next()?;
    let base64_ok = (16..=8000).contains(&body.len()) && body.len() % 4 == 0
        && body.trim_end_matches('=').bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
        && body.bytes().rev().take_while(|byte| *byte == b'=').count() <= 2;
    (SSH_KEY_TYPES.contains(&kind) && base64_ok).then(|| format!("{kind} {body}"))
}

pub(super) struct Seed {
    pub(super) meta_data: String,
    pub(super) user_data: String,
}

/// Build the NoCloud files. All inputs are checked again here; this function never trusts its caller.
pub(super) fn cloud_seed(
    instance_id: &str, host: &str, user: &str, password_hash: &str, ssh_key: Option<&str>,
) -> Result<Seed, &'static str> {
    if !valid_instance(instance_id) { return Err("The machine ID cannot be used as a cloud-init instance ID."); }
    if !valid_host(host) { return Err("The machine name cannot be used as a host name."); }
    if !valid_user(user) { return Err("Choose a user name of lowercase letters, digits, - or _ that is not a system account."); }
    if !valid_hash(password_hash) { return Err("The password hash is not a SHA-512-crypt value."); }
    let key = match ssh_key {
        Some(line) => Some(normalized_ssh_key(line).ok_or("Paste one OpenSSH public key line.")?),
        None => None,
    };
    // Quoted, so a host name such as 1234 or no stays a string.
    let meta_data = format!("instance-id: \"{instance_id}\"\nlocal-hostname: \"{host}\"\n");
    let mut user_data = format!(concat!(
        "#cloud-config\n",
        "hostname: \"{host}\"\n",
        "manage_etc_hosts: true\n",
        "users:\n",
        "  - name: \"{user}\"\n",
        "    shell: /bin/bash\n",
        "    groups: [sudo]\n",
        "    lock_passwd: false\n",
        "    hashed_passwd: \"{hash}\"\n",
    ), host = host, user = user, hash = password_hash);
    if let Some(key) = key {
        user_data.push_str(&format!("    ssh_authorized_keys:\n      - \"{key}\"\n"));
    }
    user_data.push_str(concat!(
        "ssh_pwauth: false\n",
        "disable_root: true\n",
        "package_update: true\n",
        "packages:\n",
        "  - qemu-guest-agent\n",
        "runcmd:\n",
        "  - [systemctl, start, qemu-guest-agent]\n",
        "growpart:\n",
        "  mode: auto\n",
        "  devices: [\"/\"]\n",
        "resize_rootfs: true\n",
    ));
    Ok(Seed { meta_data, user_data })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha512_crypt_matches_the_specification_vectors() {
        // The seven SHA-512 vectors published with the SHA-crypt specification.
        let vectors = [
            ("$6$saltstring", "Hello world!",
             "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"),
            ("$6$rounds=10000$saltstringsaltstring", "Hello world!",
             "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."),
            ("$6$rounds=5000$toolongsaltstring", "This is just a test",
             "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"),
            ("$6$rounds=1400$anotherlongsaltstring",
             "a very much longer text to encrypt.  This one even stretches over morethan one line.",
             "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1"),
            ("$6$rounds=77777$short", "we have a short salt string but not a short password",
             "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"),
            ("$6$rounds=123456$asaltof16chars..", "a short string",
             "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"),
            ("$6$rounds=10$roundstoolow", "the minimum number is still observed",
             "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX."),
        ];
        for (setting, key, expected) in vectors {
            assert_eq!(sha512_crypt(key.as_bytes(), setting).as_deref(), Some(expected), "{setting}");
        }
        // A key longer than one digest exercises the repeated-digest branch.
        let long = "x".repeat(150);
        let hashed = sha512_crypt(long.as_bytes(), "$6$saltstring").unwrap();
        assert!(valid_hash(&hashed));
        assert_ne!(hashed, sha512_crypt(&long.as_bytes()[..149], "$6$saltstring").unwrap());
    }

    #[test]
    fn generated_values_are_random_and_well_formed() {
        let first = hash_password("correct horse battery").unwrap();
        let second = hash_password("correct horse battery").unwrap();
        assert!(valid_hash(&first) && valid_hash(&second));
        assert_ne!(first, second, "every hash needs its own salt");
        let password = generate_password().unwrap();
        assert_eq!(password.len(), GENERATED_PASSWORD_LENGTH);
        assert!(password.bytes().all(|byte| PASSWORD_ALPHABET.contains(&byte)));
        assert_ne!(password, generate_password().unwrap());
        assert!(valid_password(&password));
    }

    #[test]
    fn field_checks_refuse_injection_and_system_accounts() {
        for user in ["labuser", "dev_1", "a-b", "_x"] {
            assert_eq!(valid_user(user), user != "_x", "{user}");
        }
        for user in ["", "Root", "root", "1abc", "a b", "a:b", "a\nb", "systemd-network", "sshd", &"a".repeat(32), "x\"y"] {
            assert!(!valid_user(user), "{user:?}");
        }
        for host in ["kali", "web-1", "a"] { assert!(valid_host(host)); }
        for host in ["", "-a", "a-", "A", "a.b", "a b", &"a".repeat(64)] { assert!(!valid_host(host), "{host}"); }
        assert!(valid_password("eight ch"));
        for password in ["short", " padded password ", "line\nbreak password", &"x".repeat(129)] {
            assert!(!valid_password(password), "{password:?}");
        }
        let key = format!("ssh-ed25519 {} user@example", "A".repeat(68));
        assert_eq!(normalized_ssh_key(&key).unwrap(), format!("ssh-ed25519 {}", "A".repeat(68)));
        for bad in ["ssh-dss AAAAB3NzaC1kc3MAAACBA", "ssh-ed25519 not\"base64", "ssh-ed25519 AAAA\nssh-rsa AAAA", "ssh-ed25519"] {
            assert!(normalized_ssh_key(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn seed_files_use_only_checked_values() {
        let hash = sha512_crypt(b"pass phrase", "$6$saltstring").unwrap();
        let seed = cloud_seed("vm-0a1b", "lab-1", "labuser", &hash, None).unwrap();
        assert_eq!(seed.meta_data, "instance-id: \"vm-0a1b\"\nlocal-hostname: \"lab-1\"\n");
        assert!(cloud_seed("vm-0a1b", "1234", "labuser", &hash, None).unwrap().meta_data.contains("local-hostname: \"1234\""));
        assert!(seed.user_data.starts_with("#cloud-config\n"));
        assert!(seed.user_data.contains(&format!("    hashed_passwd: \"{hash}\"\n")));
        assert!(seed.user_data.contains("ssh_pwauth: false\n"));
        assert!(!seed.user_data.contains("pass phrase"));
        assert!(!seed.user_data.contains("ssh_authorized_keys"));
        let key = format!("ssh-rsa {}", "B".repeat(372));
        assert!(cloud_seed("vm-0a1b", "lab-1", "labuser", &hash, Some(&key)).unwrap().user_data.contains(&format!("      - \"{key}\"\n")));
        assert!(cloud_seed("vm-0a1b", "lab-1", "root", &hash, None).is_err());
        assert!(cloud_seed("vm-0a1b", "lab-1", "labuser\n  sudo: ALL", &hash, None).is_err());
        assert!(cloud_seed("vm-0a1b", "lab 1", "labuser", &hash, None).is_err());
        assert!(cloud_seed("vm-0a1b", "lab-1", "labuser", "plain password", None).is_err());
        assert!(cloud_seed("vm-0a1b\ninstance-id: x", "lab-1", "labuser", &hash, None).is_err());
        assert!(cloud_seed("vm-0a1b", "lab-1", "labuser", &hash, Some("ssh-rsa AAAA\"\n- evil")).is_err());
    }
}
