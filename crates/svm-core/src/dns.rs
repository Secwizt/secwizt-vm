//! DNS answers for the machines we manage. Pure functions: no sockets, no clock, no state.
//!
//! The caller owns the listener and the forwarder. For every datagram it calls [`answer`] and then either sends
//! the reply, forwards the untouched query to an upstream resolver, or drops it.
//!
//! What is answered here and never forwarded:
//! * every name under `vm.lan` and every exact name in the table (A, and an empty answer for other record types);
//! * reverse lookups (`in-addr.arpa`) for an address in the table, and for any private or link-local address,
//!   so a guest's reverse lookups of our networks never leave this PC;
//! * anything malformed, any response packet and any non-query operation.
use std::{collections::BTreeMap, net::Ipv4Addr};

/// What the listener must do with one datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Send these bytes back to the sender.
    Reply(Vec<u8>),
    /// A well-formed question about a name that is not ours. Send the query upstream unchanged.
    Forward,
    /// Not answerable and not forwardable (too short, or itself a response). Send nothing.
    Drop,
}

/// The zone every managed machine name lives in.
pub const ZONE: &str = "vm.lan";
/// Seconds a guest may cache one of our answers. Short, because an address can be changed in the app.
pub const TTL: u32 = 30;

const HEADER: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_OPT: u16 = 41;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;
const NOERROR: u8 = 0;
const FORMERR: u8 = 1;
const NXDOMAIN: u8 = 3;
const NOTIMP: u8 = 4;
const REFUSED: u8 = 5;
/// The largest reply we build; the listener's own limit is at least this.
const MAX_REPLY: usize = 1232;

struct Question { name: String, qtype: u16, qclass: u16, end: usize }

fn word(packet: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]))
}

/// Reads the single question. Compression pointers are not valid in a question and are refused.
fn question(packet: &[u8]) -> Option<Question> {
    let mut at = HEADER;
    let mut name = String::new();
    loop {
        let len = usize::from(*packet.get(at)?);
        at += 1;
        if len == 0 { break; }
        if len > 63 { return None; }
        let label = packet.get(at..at + len)?;
        if !label.iter().all(|b| b.is_ascii_graphic() && *b != b'.') { return None; }
        if !name.is_empty() { name.push('.'); }
        name.extend(label.iter().map(|b| char::from(b.to_ascii_lowercase())));
        if name.len() > 253 { return None; }
        at += len;
    }
    Some(Question { name, qtype: word(packet, at)?, qclass: word(packet, at + 2)?, end: at + 4 })
}

/// A name in wire form, or nothing when it is not a valid host name.
fn encode(name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return None;
        }
        out.push(u8::try_from(label.len()).ok()?);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    (out.len() <= 255).then_some(out)
}

fn in_zone(name: &str) -> bool {
    name == ZONE || name.strip_suffix(ZONE).is_some_and(|rest| rest.ends_with('.'))
}

/// The address a reverse-lookup name stands for: `4.3.2.1.in-addr.arpa` is 1.2.3.4.
fn reverse(name: &str) -> Option<Ipv4Addr> {
    let rest = name.strip_suffix(".in-addr.arpa")?;
    let mut parts = [0u8; 4];
    let mut count = 0;
    for label in rest.split('.') {
        if count == 4 || label.is_empty() || label.len() > 3 || !label.bytes().all(|b| b.is_ascii_digit()) { return None; }
        if label.len() > 1 && label.starts_with('0') { return None; }
        parts[3 - count] = label.parse().ok()?;
        count += 1;
    }
    (count == 4).then(|| Ipv4Addr::from(parts))
}

/// A partial reverse name such as `77.10.in-addr.arpa` (a zone cut, not an address) inside a private range.
fn private_reverse_zone(name: &str) -> bool {
    let Some(rest) = name.strip_suffix(".in-addr.arpa") else { return false };
    let labels: Vec<&str> = rest.split('.').collect();
    if labels.len() >= 4 || labels.iter().any(|l| l.is_empty() || l.len() > 3 || !l.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }
    let mut octets = labels.iter().rev().filter_map(|l| l.parse::<u8>().ok());
    match (octets.next(), octets.next()) {
        (Some(10), _) => true,
        (Some(172), Some(second)) => (16..=31).contains(&second),
        (Some(192), Some(168)) | (Some(169), Some(254)) => true,
        _ => false,
    }
}

fn ours(ip: Ipv4Addr) -> bool { ip.is_private() || ip.is_link_local() || ip.is_loopback() }

/// True when the first additional record is an EDNS OPT record, so the reply should carry one too.
fn has_opt(packet: &[u8], after_question: usize) -> bool {
    word(packet, 10).is_some_and(|additional| additional >= 1)
        && packet.get(after_question) == Some(&0)
        && word(packet, after_question + 1) == Some(TYPE_OPT)
}

struct Reply { bytes: Vec<u8>, answers: u16 }

impl Reply {
    /// Header plus the question copied byte for byte, so the sender's own spelling of the name is preserved.
    fn start(packet: &[u8], question_end: usize) -> Self {
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(&packet[..2]);
        bytes.extend_from_slice(&[0; 10]);
        bytes.extend_from_slice(&packet[HEADER..question_end]);
        Self { bytes, answers: 0 }
    }
    /// One record whose owner is the question name (a pointer back to offset 12).
    fn record(&mut self, rtype: u16, data: &[u8]) -> bool {
        let Ok(len) = u16::try_from(data.len()) else { return false };
        if self.bytes.len() + 12 + data.len() + 11 > MAX_REPLY { return false; }
        self.bytes.extend_from_slice(&[0xc0, 0x0c]);
        self.bytes.extend_from_slice(&rtype.to_be_bytes());
        self.bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        self.bytes.extend_from_slice(&TTL.to_be_bytes());
        self.bytes.extend_from_slice(&len.to_be_bytes());
        self.bytes.extend_from_slice(data);
        self.answers += 1;
        true
    }
    fn finish(mut self, packet: &[u8], code: u8, questions: u16, opt: bool) -> Answer {
        // QR=1, opcode copied, AA=1 for our own data, RD copied, RA=1 because the listener can forward.
        self.bytes[2] = 0x80 | (packet[2] & 0x78) | 0x04 | (packet[2] & 0x01);
        self.bytes[3] = 0x80 | (code & 0x0f);
        self.bytes[4..6].copy_from_slice(&questions.to_be_bytes());
        self.bytes[6..8].copy_from_slice(&self.answers.to_be_bytes());
        if opt {
            // Root name, type OPT, our datagram size in the class field, no flags, no options.
            self.bytes.extend_from_slice(&[0, 0, 41]);
            self.bytes.extend_from_slice(&u16::try_from(MAX_REPLY).unwrap_or(1232).to_be_bytes());
            self.bytes.extend_from_slice(&[0; 6]);
            self.bytes[10..12].copy_from_slice(&1u16.to_be_bytes());
        }
        Answer::Reply(self.bytes)
    }
}

/// A reply that carries only a result code and no question, for packets whose question cannot be trusted.
fn bare(packet: &[u8], code: u8) -> Answer {
    Reply { bytes: { let mut b = packet[..2].to_vec(); b.extend_from_slice(&[0; 10]); b }, answers: 0 }.finish(packet, code, 0, false)
}

/// Decides what to do with one DNS datagram.
///
/// `names` maps lowercase fully qualified names without a trailing dot (`debian.vm.lan`) to the machine's address.
pub fn answer(query: &[u8], names: &BTreeMap<String, Ipv4Addr>) -> Answer {
    if query.len() < HEADER || query[2] & 0x80 != 0 { return Answer::Drop; }
    if query[2] & 0x78 != 0 { return bare(query, NOTIMP); }
    let counts = (word(query, 4), word(query, 6), word(query, 8));
    if counts != (Some(1), Some(0), Some(0)) { return bare(query, FORMERR); }
    let Some(q) = question(query) else { return bare(query, FORMERR) };
    let opt = has_opt(query, q.end);
    let reply = |code: u8| Reply::start(query, q.end).finish(query, code, 1, opt);

    let known = names.get(&q.name).copied();
    let address = reverse(&q.name);
    let local_reverse = address.is_some_and(|ip| ours(ip) || names.values().any(|known| *known == ip)) || private_reverse_zone(&q.name);
    if known.is_none() && !in_zone(&q.name) && !local_reverse { return Answer::Forward; }
    if q.qclass != CLASS_IN { return reply(REFUSED); }

    let mut out = Reply::start(query, q.end);
    if let Some(ip) = known {
        if q.qtype == TYPE_A || q.qtype == TYPE_ANY { out.record(TYPE_A, &ip.octets()); }
        return out.finish(query, NOERROR, 1, opt);
    }
    if let Some(ip) = address {
        if q.qtype == TYPE_PTR || q.qtype == TYPE_ANY {
            for (name, _) in names.iter().filter(|(_, known)| **known == ip) {
                if let Some(wire) = encode(name) { if !out.record(TYPE_PTR, &wire) { break; } }
            }
        }
        let found = names.values().any(|known| *known == ip);
        return out.finish(query, if found { NOERROR } else { NXDOMAIN }, 1, opt);
    }
    // The zone itself and reverse zone cuts exist but hold no records of their own; any other name is unknown.
    let exists = q.name == ZONE || private_reverse_zone(&q.name);
    out.finish(query, if exists { NOERROR } else { NXDOMAIN }, 1, opt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> BTreeMap<String, Ipv4Addr> {
        BTreeMap::from([
            ("debian.vm.lan".to_owned(), Ipv4Addr::new(10, 77, 0, 2)),
            ("win-10.vm.lan".to_owned(), Ipv4Addr::new(10, 77, 0, 3)),
            ("alias.vm.lan".to_owned(), Ipv4Addr::new(10, 77, 0, 3)),
            ("printer.home.example".to_owned(), Ipv4Addr::new(203, 0, 113, 9)),
        ])
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut p = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.').filter(|l| !l.is_empty()) {
            p.push(u8::try_from(label.len()).unwrap());
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&CLASS_IN.to_be_bytes());
        p
    }

    fn reply(packet: &[u8]) -> Vec<u8> {
        match answer(packet, &table()) { Answer::Reply(bytes) => bytes, other => panic!("expected a reply, got {other:?}") }
    }
    fn code(reply: &[u8]) -> u8 { reply[3] & 0x0f }
    fn answers(reply: &[u8]) -> u16 { u16::from_be_bytes([reply[6], reply[7]]) }

    #[test]
    fn a_known_machine_name_gets_its_address_in_any_letter_case() {
        let q = query("Debian.VM.Lan", TYPE_A);
        let r = reply(&q);
        assert_eq!(&r[..2], &[0xab, 0xcd], "the sender's id comes back");
        assert_eq!(r[2], 0x85, "response, authoritative, recursion desired copied");
        assert_eq!(r[3], 0x80, "recursion available, no error");
        assert_eq!((answers(&r), code(&r)), (1, NOERROR));
        assert_eq!(&r[HEADER..q.len()], &q[HEADER..], "the question is echoed byte for byte");
        let record = &r[q.len()..];
        assert_eq!(&record[..2], &[0xc0, 0x0c]);
        assert_eq!(&record[2..6], &[0, 1, 0, 1]);
        assert_eq!(u32::from_be_bytes([record[6], record[7], record[8], record[9]]), TTL);
        assert_eq!(&record[10..], &[0, 4, 10, 77, 0, 2]);
    }

    #[test]
    fn other_record_types_for_a_known_name_are_empty_not_missing() {
        let r = reply(&query("debian.vm.lan", 28));
        assert_eq!((answers(&r), code(&r)), (0, NOERROR));
        let any = reply(&query("debian.vm.lan", TYPE_ANY));
        assert_eq!((answers(&any), code(&any)), (1, NOERROR));
    }

    #[test]
    fn unknown_names_in_our_zone_are_refused_locally_and_never_forwarded() {
        let r = reply(&query("ghost.vm.lan", TYPE_A));
        assert_eq!((answers(&r), code(&r)), (0, NXDOMAIN));
        let zone = reply(&query("vm.lan", TYPE_A));
        assert_eq!((answers(&zone), code(&zone)), (0, NOERROR));
        // A name that merely ends in the same letters is not in the zone.
        assert_eq!(answer(&query("evilvm.lan", TYPE_A), &table()), Answer::Forward);
        assert_eq!(answer(&query("vm.lan.example.com", TYPE_A), &table()), Answer::Forward);
    }

    #[test]
    fn public_names_are_forwarded_and_exact_table_names_outside_the_zone_are_answered() {
        assert_eq!(answer(&query("example.com", TYPE_A), &table()), Answer::Forward);
        assert_eq!(answer(&query("example.com", 28), &table()), Answer::Forward);
        let r = reply(&query("printer.home.example", TYPE_A));
        assert_eq!(&r[r.len() - 4..], &[203, 0, 113, 9]);
    }

    #[test]
    fn reverse_lookup_returns_every_name_of_the_address() {
        let q = query("3.0.77.10.in-addr.arpa", TYPE_PTR);
        let r = reply(&q);
        assert_eq!((answers(&r), code(&r)), (2, NOERROR));
        let text = String::from_utf8_lossy(&r[q.len()..]).to_string();
        assert!(text.contains("alias") && text.contains("win-10"), "{text:?}");
        let single = reply(&query("2.0.77.10.in-addr.arpa", TYPE_PTR));
        assert!(single.ends_with(b"\x06debian\x02vm\x03lan\x00"));
    }

    #[test]
    fn private_reverse_lookups_stay_here_and_public_ones_are_forwarded() {
        for name in ["9.0.77.10.in-addr.arpa", "1.1.168.192.in-addr.arpa", "7.5.254.169.in-addr.arpa", "1.0.20.172.in-addr.arpa"] {
            let r = reply(&query(name, TYPE_PTR));
            assert_eq!((answers(&r), code(&r)), (0, NXDOMAIN), "{name}");
        }
        let cut = reply(&query("77.10.in-addr.arpa", 6));
        assert_eq!((answers(&cut), code(&cut)), (0, NOERROR));
        assert_eq!(answer(&query("8.8.8.8.in-addr.arpa", TYPE_PTR), &table()), Answer::Forward);
        assert_eq!(answer(&query("1.0.32.172.in-addr.arpa", TYPE_PTR), &table()), Answer::Forward);
        // A table address outside the private ranges is still ours to answer.
        let public = reply(&query("9.113.0.203.in-addr.arpa", TYPE_PTR));
        assert_eq!((answers(&public), code(&public)), (1, NOERROR));
    }

    #[test]
    fn responses_and_short_packets_are_dropped() {
        let mut response = query("debian.vm.lan", TYPE_A);
        response[2] |= 0x80;
        assert_eq!(answer(&response, &table()), Answer::Drop);
        assert_eq!(answer(&[0; 11], &table()), Answer::Drop);
        assert_eq!(answer(&[], &table()), Answer::Drop);
    }

    #[test]
    fn malformed_questions_get_a_format_error_and_are_never_forwarded() {
        let good = query("example.com", TYPE_A);
        let mut two = good.clone();
        two[5] = 2;
        let mut with_answer = good.clone();
        with_answer[7] = 1;
        let mut pointer = good.clone();
        pointer[HEADER] = 0xc0;
        let truncated = good[..good.len() - 3].to_vec();
        let mut long_label = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 64];
        long_label.extend_from_slice(&[b'a'; 64]);
        long_label.extend_from_slice(&[0, 0, 1, 0, 1]);
        let mut control = good.clone();
        control[HEADER + 1] = 0x07;
        for bad in [two, with_answer, pointer, truncated, long_label, control] {
            let r = reply(&bad);
            assert_eq!(code(&r), FORMERR);
            assert_eq!(r.len(), HEADER, "no question is echoed from an untrusted packet");
            assert_eq!(&r[..2], &bad[..2]);
        }
    }

    #[test]
    fn a_name_longer_than_the_limit_is_a_format_error() {
        let name = ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(63)].join(".");
        assert_eq!(code(&reply(&query(&name, TYPE_A))), FORMERR);
    }

    #[test]
    fn non_query_operations_and_foreign_classes_are_answered_with_an_error() {
        let mut update = query("debian.vm.lan", TYPE_A);
        update[2] = 0x28;
        let r = reply(&update);
        assert_eq!((code(&r), r[2] & 0x78), (NOTIMP, 0x28));
        let mut chaos = query("debian.vm.lan", TYPE_A);
        let end = chaos.len();
        chaos[end - 1] = 3;
        assert_eq!(code(&reply(&chaos)), REFUSED);
        // A foreign class for a name that is not ours is the upstream resolver's business.
        let mut foreign = query("example.com", TYPE_A);
        let end = foreign.len();
        foreign[end - 1] = 3;
        assert_eq!(answer(&foreign, &table()), Answer::Forward);
    }

    #[test]
    fn an_edns_query_gets_an_edns_reply() {
        let mut q = query("debian.vm.lan", TYPE_A);
        q[11] = 1;
        q.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]);
        let r = reply(&q);
        assert_eq!(u16::from_be_bytes([r[10], r[11]]), 1);
        assert_eq!(&r[r.len() - 11..], &[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(answers(&r), 1);
        let plain = reply(&query("debian.vm.lan", TYPE_A));
        assert_eq!(u16::from_be_bytes([plain[10], plain[11]]), 0);
    }

    #[test]
    fn recursion_desired_is_copied_not_invented() {
        let mut q = query("debian.vm.lan", TYPE_A);
        q[2] = 0;
        assert_eq!(reply(&q)[2], 0x84);
    }

    #[test]
    fn replies_never_exceed_the_datagram_limit() {
        let ip = Ipv4Addr::new(10, 77, 0, 9);
        let names: BTreeMap<String, Ipv4Addr> = (0..200).map(|i| (format!("machine-with-a-long-name-{i:03}.vm.lan"), ip)).collect();
        let q = query("9.0.77.10.in-addr.arpa", TYPE_PTR);
        let Answer::Reply(r) = answer(&q, &names) else { panic!("expected a reply") };
        assert!(r.len() <= MAX_REPLY, "{}", r.len());
        assert!(answers(&r) > 10 && answers(&r) < 200);
    }

    #[test]
    fn names_that_cannot_be_written_as_host_names_are_skipped_in_reverse_answers() {
        let ip = Ipv4Addr::new(10, 77, 0, 4);
        let names = BTreeMap::from([("bad name.vm.lan".to_owned(), ip), ("good.vm.lan".to_owned(), ip)]);
        let Answer::Reply(r) = answer(&query("4.0.77.10.in-addr.arpa", TYPE_PTR), &names) else { panic!("expected a reply") };
        assert_eq!(answers(&r), 1);
    }
}
