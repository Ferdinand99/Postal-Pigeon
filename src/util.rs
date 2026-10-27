//! Small helpers: encodings, random ids, UUIDs, dates and addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aws_lc_rs::rand;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Unpadded URL-safe base64.
pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes unpadded URL-safe base64.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// `N` random bytes from the system's random source.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::fill(&mut buf).expect("the system's random source");
    buf
}

/// `n` random bytes as unpadded URL-safe base64.
pub fn random_b64(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::fill(&mut buf).expect("the system's random source");
    b64(&buf)
}

/// A fresh random (version 4) UUID in its canonical lower-case form.
pub fn uuid_v4() -> String {
    let mut b: [u8; 16] = random_bytes();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Whether `s` is a UUID in the canonical 8-4-4-4-12 form (any version).
pub fn is_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    s.bytes().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => c == b'-',
        _ => c.is_ascii_hexdigit(),
    })
}

/// Seconds in a day.
pub const DAY_SECS: i64 = 86_400;

/// A calendar date as days since 1970-01-01 (UTC), the only form in which the
/// relay stores a date.
pub fn day_of(secs: i64) -> i64 {
    secs.div_euclid(DAY_SECS)
}

/// `(year, month, day)` of a day number (Howard Hinnant's civil-from-days).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `YYYY-MM-DD` for a day number.
pub fn day_string(day: i64) -> String {
    let (y, m, d) = civil_from_days(day);
    format!("{y:04}-{m:02}-{d:02}")
}

/// RFC 3339 UTC time (`2026-10-27T12:00:00Z`) for Unix seconds.
pub fn rfc3339(secs: i64) -> String {
    let (y, m, d) = civil_from_days(day_of(secs));
    let rem = secs.rem_euclid(DAY_SECS);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// An IP network such as `10.0.0.0/8` (a bare address is a host network).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Parses `addr` or `addr/prefix`.
    pub fn parse(s: &str) -> Option<IpNet> {
        let s = s.trim();
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().ok()?;
        let addr = addr.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max)?,
            None => max,
        };
        Some(IpNet { addr, prefix })
    }

    /// Whether `ip` is inside this network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                mask_v4(u32::from(n), self.prefix) == mask_v4(u32::from(i), self.prefix)
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                mask_v6(u128::from(n), self.prefix) == mask_v6(u128::from(i), self.prefix)
            }
            _ => false,
        }
    }
}

fn mask_v4(v: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        v & (u32::MAX << (32 - u32::from(prefix)))
    }
}

fn mask_v6(v: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        v & (u128::MAX << (128 - u32::from(prefix)))
    }
}

/// The key that rate limits use for a client address: the address itself for
/// IPv4 and the /64 for IPv6.
pub fn addr_key(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => format!("4:{v4}"),
        IpAddr::V6(v6) => {
            let masked = Ipv6Addr::from(mask_v6(u128::from(v6), 64));
            format!("6:{masked}")
        }
    }
}

/// The coarse prefix kept for 30 days after an instance registers: the /24 for
/// IPv4 and the /48 for IPv6.
pub fn addr_prefix(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => format!("{}/24", Ipv4Addr::from(mask_v4(u32::from(v4), 24))),
        IpAddr::V6(v6) => format!("{}/48", Ipv6Addr::from(mask_v6(u128::from(v6), 48))),
    }
}

/// The client address of a request: the peer, unless the peer is a trusted
/// proxy, in which case the right-most `X-Forwarded-For` entry that is not
/// itself a trusted proxy. `forwarded` holds every `X-Forwarded-For` header
/// line in order (a request may carry several); they are read as one list,
/// from the right.
pub fn client_ip(peer: IpAddr, forwarded: &[&str], trusted: &[IpNet]) -> IpAddr {
    let is_trusted = |ip: IpAddr| trusted.iter().any(|n| n.contains(ip));
    if !is_trusted(peer) {
        return peer.to_canonical();
    }
    for line in forwarded.iter().rev() {
        for part in line.rsplit(',') {
            match part.trim().parse::<IpAddr>() {
                Ok(ip) if is_trusted(ip) => continue,
                Ok(ip) => return ip.to_canonical(),
                Err(_) => return peer.to_canonical(),
            }
        }
    }
    peer.to_canonical()
}

/// The key of the coarser prefix bucket: the /24 for IPv4 and the /48 for IPv6.
pub fn prefix_key(ip: IpAddr) -> String {
    format!("p:{}", addr_prefix(ip))
}

/// Number of leading zero bits of a byte string.
pub fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut n = 0;
    for b in bytes {
        if *b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_round_trip() {
        let u = uuid_v4();
        assert!(is_uuid(&u));
        assert_eq!(&u[14..15], "4");
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("7f6c8e0e-5d1b-4a43-9d3e-0c1d9b1b2a7"));
        assert!(!is_uuid("7f6c8e0e-5d1b-4a43-9d3e-0c1d9b1b2a7g"));
    }

    #[test]
    fn dates() {
        assert_eq!(day_string(0), "1970-01-01");
        assert_eq!(rfc3339(1_793_102_400), "2026-10-27T12:00:00Z");
        assert_eq!(day_string(day_of(1_793_102_400)), "2026-10-27");
    }

    #[test]
    fn nets() {
        let n = IpNet::parse("10.0.0.0/8").unwrap();
        assert!(n.contains("10.9.8.7".parse().unwrap()));
        assert!(!n.contains("11.0.0.1".parse().unwrap()));
        assert!(!n.contains("::1".parse().unwrap()));
        assert!(
            IpNet::parse("::1")
                .unwrap()
                .contains("::1".parse().unwrap())
        );
        assert!(IpNet::parse("10.0.0.0/33").is_none());
        assert!(IpNet::parse("nope").is_none());
    }

    #[test]
    fn address_keys() {
        let a = addr_key("2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap());
        let b = addr_key("2001:db8:1:2::1".parse().unwrap());
        let c = addr_key("2001:db8:1:3::1".parse().unwrap());
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(
            addr_prefix("203.0.113.77".parse().unwrap()),
            "203.0.113.0/24"
        );
        assert_eq!(
            addr_prefix("2001:db8:1:2::1".parse().unwrap()),
            "2001:db8:1::/48"
        );
    }

    #[test]
    fn forwarded_for_only_from_trusted_proxies() {
        let trusted = [
            IpNet::parse("10.0.0.1").unwrap(),
            IpNet::parse("10.0.0.2").unwrap(),
        ];
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let other: IpAddr = "198.51.100.9".parse().unwrap();
        // An untrusted peer can't choose its own address.
        assert_eq!(client_ip(other, &["1.2.3.4"], &trusted), other);
        // A trusted proxy's right-most entry counts, a spoofed left one doesn't.
        assert_eq!(
            client_ip(peer, &["9.9.9.9, 203.0.113.5"], &trusted),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
        assert_eq!(client_ip(peer, &[], &trusted), peer);
        assert_eq!(client_ip(peer, &["garbage"], &trusted), peer);
        // Several header lines are one list: the proxy's line is the last one,
        // and a client-supplied line before it can't win.
        assert_eq!(
            client_ip(peer, &["9.9.9.9", "203.0.113.5"], &trusted),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
        // Trusted hops are skipped, across lines too.
        assert_eq!(
            client_ip(peer, &["9.9.9.9, 203.0.113.5", "10.0.0.2"], &trusted),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
        // A bad entry on the way stops the walk: the peer is used.
        assert_eq!(client_ip(peer, &["203.0.113.5", "junk"], &trusted), peer);
    }

    #[test]
    fn prefix_keys_group_networks() {
        assert_eq!(
            prefix_key("203.0.113.5".parse().unwrap()),
            prefix_key("203.0.113.200".parse().unwrap())
        );
        assert_ne!(
            prefix_key("203.0.113.5".parse().unwrap()),
            prefix_key("203.0.114.5".parse().unwrap())
        );
        assert_eq!(
            prefix_key("2001:db8:1:2::1".parse().unwrap()),
            prefix_key("2001:db8:1:ffff::1".parse().unwrap())
        );
    }

    #[test]
    fn zero_bits() {
        assert_eq!(leading_zero_bits(&[0, 0, 0b0001_0000]), 19);
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0, 0]), 16);
    }
}
