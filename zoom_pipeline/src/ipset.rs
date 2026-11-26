//! Zoom server address gate: a sorted table of disjoint address ranges and a
//! binary search. No strings, no allocation, no linear scan.
//!
//! The old gate parsed the address *string* of every packet and then scanned
//! 49 CIDRs linearly. This one does one `partition_point` over about 50
//! `(lo, hi)` pairs: 6 comparisons. IPv4 and IPv6 share one table (IPv4 is
//! v4-mapped, see [`Addr`]).
//!
//! The list is still a hard filter (your instruction): a packet is counted
//! only if its source or destination is in this set. A stale list is
//! therefore the main operational risk; `pipeline` exports a
//! `zoom_like_unlisted` counter (packets with a valid Zoom header whose IPs
//! are *not* listed) as the early warning, and `from_file` lets you refresh
//! the list without recompiling.

use crate::net::Addr;
use std::net::IpAddr;

/// Zoom's published ranges, copied verbatim from the previous
/// `common/ip_ranges.rs` (48 IPv4 + 3 IPv6 blocks). Re-copy from Zoom's
/// published list periodically.
pub const ZOOM_IPV4_CIDR_STRS: &[&str] = &[
    "3.7.35.0/25",
    "3.235.82.0/23",
    "3.235.96.0/23",
    "3.235.96.26/31",  // vc_combined 2026-11-06: Zoom now publishes these two /31s (inside the /23 above, kept)
    "3.235.96.158/31",
    "15.220.80.0/24",
    "15.220.81.0/25",
    "18.254.23.128/25",
    "18.254.61.0/25",
    "20.203.158.80/28",
    "20.203.190.192/26",
    "52.61.100.128/25",
    "64.211.144.0/24",
    "64.224.32.0/19",
    "69.174.108.0/22",
    "69.174.110.0/23", // vc_combined 2026-11-06: Zoom now publishes this /23 (inside the /22 above, kept)
    "101.36.167.0/24",
    "101.36.170.0/23",
    "103.122.166.0/23",
    "111.33.115.0/25",
    "111.33.181.0/25",
    "115.110.154.192/26",
    "115.114.56.192/26",
    "115.114.115.0/26",
    "115.114.131.0/26",
    "121.244.146.0/27",
    "134.224.0.0/16",
    "137.66.128.0/17",
    "144.195.0.0/16", // contains 144.195.28.40, the endpoint re-validated on slide 59
    "147.124.96.0/19",
    "149.137.0.0/17",
    "156.45.0.0/17",
    "159.124.0.0/16",
    "160.1.56.128/25",
    "161.199.136.0/22",
    "162.12.232.0/22",
    "162.255.36.0/22",
    "166.108.64.0/18",
    "168.140.0.0/17",
    "170.114.0.0/16",
    "173.231.80.0/20",
    "192.204.12.0/23",
    "198.251.128.0/17",
    "203.200.219.128/27",
    "204.80.104.0/21",
    "206.247.0.0/16",
    "221.122.63.0/24",
    "221.122.64.0/24",
    "221.122.88.64/27",
    "221.122.88.128/25",
    "221.122.89.128/25",
    "221.123.139.192/27",
];

pub const ZOOM_IPV6_CIDR_STRS: &[&str] = &["2407:30c0::/32", "2600:9000:2600::/48", "2620:123:2000::/40"];


#[derive(Clone, Debug)]
pub struct IpSet {
    /// Sorted, disjoint, inclusive `(lo, hi)`.
    ranges: Vec<(u128, u128)>,
}

impl IpSet {
    /// Build from `a.b.c.d/len` or `v6::/len` strings. A bare address means
    /// /32 or /128. Overlapping and adjacent ranges are merged.
    pub fn from_cidrs<I, S>(cidrs: I) -> Result<IpSet, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut raw: Vec<(u128, u128)> = Vec::new();
        for c in cidrs {
            let c = c.as_ref().trim();
            let (addr_s, len_s) = match c.split_once('/') {
                Some((a, l)) => (a, Some(l)),
                None => (c, None),
            };
            let ip: IpAddr = addr_s.parse().map_err(|e| format!("bad address in {c:?}: {e}"))?;
            let a = Addr::from_ip(ip);
            // prefix length counted within the family, then lifted into the 128-bit space
            let (fam_bits, base_shift) = if ip.is_ipv4() { (32u32, 0u32) } else { (128, 0) };
            let _ = base_shift;
            let plen: u32 = match len_s {
                Some(l) => l.parse().map_err(|e| format!("bad prefix length in {c:?}: {e}"))?,
                None => fam_bits,
            };
            if plen > fam_bits {
                return Err(format!("prefix length {plen} too large in {c:?}"));
            }
            let host_bits = fam_bits - plen;
            let host_mask: u128 = if host_bits == 0 { 0 } else { (1u128 << host_bits) - 1 };
            let lo = a.0 & !host_mask;
            let hi = a.0 | host_mask;
            raw.push((lo, hi));
        }
        raw.sort_unstable();
        let mut merged: Vec<(u128, u128)> = Vec::with_capacity(raw.len());
        for (lo, hi) in raw {
            match merged.last_mut() {
                Some(last) if lo <= last.1.saturating_add(1) => {
                    if hi > last.1 {
                        last.1 = hi;
                    }
                }
                _ => merged.push((lo, hi)),
            }
        }
        Ok(IpSet { ranges: merged })
    }

    /// Zoom's published list, baked in.
    pub fn zoom_default() -> IpSet {
        let all = ZOOM_IPV4_CIDR_STRS.iter().chain(ZOOM_IPV6_CIDR_STRS.iter());
        IpSet::from_cidrs(all).expect("built-in Zoom CIDR list must parse (checked by a unit test)")
    }

    /// One CIDR per line; `#` starts a comment; blank lines ignored.
    pub fn from_file(path: &std::path::Path) -> Result<IpSet, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        IpSet::from_text(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// vc_combined: the same format from a string (the compiled-in copy of `ip_lists/zoom.txt`).
    pub fn from_text(text: &str) -> Result<IpSet, String> {
        let lines = text
            .lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .filter(|l| !l.is_empty());
        IpSet::from_cidrs(lines)
    }

    #[inline]
    pub fn contains(&self, a: Addr) -> bool {
        let i = self.ranges.partition_point(|r| r.0 <= a.0);
        i > 0 && a.0 <= self.ranges[i - 1].1
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// The behaviour of the previous implementation, kept here as the oracle.
    fn old_linear(ip: IpAddr) -> bool {
        fn m4(ip: u32, base: &str) -> bool {
            let (a, l) = base.split_once('/').unwrap();
            let a: Ipv4Addr = a.parse().unwrap();
            let l: u32 = l.parse().unwrap();
            let mask = if l == 0 { 0 } else { u32::MAX << (32 - l) };
            (ip & mask) == (u32::from(a) & mask)
        }
        fn m6(ip: u128, base: &str) -> bool {
            let (a, l) = base.split_once('/').unwrap();
            let a: Ipv6Addr = a.parse().unwrap();
            let l: u32 = l.parse().unwrap();
            let mask = if l == 0 { 0 } else { u128::MAX << (128 - l) };
            (ip & mask) == (u128::from(a) & mask)
        }
        match ip {
            IpAddr::V4(v) => ZOOM_IPV4_CIDR_STRS.iter().any(|c| m4(u32::from(v), c)),
            IpAddr::V6(v) => ZOOM_IPV6_CIDR_STRS.iter().any(|c| m6(u128::from(v), c)),
        }
    }

    #[test]
    fn builtin_list_parses_and_known_endpoint_matches() {
        let s = IpSet::zoom_default();
        assert!(s.len() > 20);
        assert!(s.contains(Addr::from_v4([144, 195, 28, 40]))); // deck slide 59
        assert!(s.contains(Addr::from_v4([170, 114, 107, 187]))); // server in the 629 s live run
        assert!(!s.contains(Addr::from_v4([10, 184, 29, 164]))); // campus client
        assert!(!s.contains(Addr::from_v4([8, 8, 8, 8])));
    }

    #[test]
    fn boundaries_of_a_slash_25_are_exact() {
        let s = IpSet::zoom_default();
        assert!(s.contains(Addr::from_v4([3, 7, 35, 0])));
        assert!(s.contains(Addr::from_v4([3, 7, 35, 127])));
        assert!(!s.contains(Addr::from_v4([3, 7, 35, 128])));
        assert!(!s.contains(Addr::from_v4([3, 7, 34, 255])));
    }

    #[test]
    fn ipv6_prefixes() {
        let s = IpSet::zoom_default();
        assert!(s.contains(Addr::from_ip("2600:9000:2600::1234".parse().unwrap())));
        assert!(!s.contains(Addr::from_ip("2600:9001::1".parse().unwrap())));
        assert!(s.contains(Addr::from_ip("2407:30c0:106:900:459b:81a2:2f8e:563".parse().unwrap())));
    }

    #[test]
    fn v4_and_v6_do_not_cross_match() {
        // 0.0.0.0/0 for v4 must not accept an IPv6 address, and vice versa.
        let s = IpSet::from_cidrs(["0.0.0.0/0"]).unwrap();
        assert!(s.contains(Addr::from_v4([1, 2, 3, 4])));
        assert!(!s.contains(Addr::from_ip("2001:db8::1".parse().unwrap())));
        let s6 = IpSet::from_cidrs(["2001:db8::/32"]).unwrap();
        assert!(!s6.contains(Addr::from_v4([32, 1, 13, 184])));
    }

    #[test]
    fn overlapping_and_adjacent_ranges_merge() {
        let s = IpSet::from_cidrs(["10.0.0.0/25", "10.0.0.128/25", "10.0.0.64/26", "10.0.2.0/24"]).unwrap();
        assert_eq!(s.len(), 2);
        assert!(s.contains(Addr::from_v4([10, 0, 0, 200])));
        assert!(!s.contains(Addr::from_v4([10, 0, 1, 0])));
    }

    #[test]
    fn bad_input_is_an_error_not_a_panic() {
        assert!(IpSet::from_cidrs(["not-an-ip"]).is_err());
        assert!(IpSet::from_cidrs(["1.2.3.4/33"]).is_err());
        assert!(IpSet::from_cidrs(["1.2.3.4/x"]).is_err());
        assert!(IpSet::from_cidrs(Vec::<&str>::new()).unwrap().is_empty());
    }

    /// Same decision as the old linear scan on 2 million random addresses
    /// plus every range boundary +/- 1.
    #[test]
    fn identical_to_the_old_linear_scan() {
        let s = IpSet::zoom_default();
        let mut x: u64 = 0x1234_5678_9abc_def1;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut hits = 0u32;
        for i in 0..2_000_000u32 {
            // bias half of them into the Zoom /16s so hits are not vanishingly rare
            let v = if i % 2 == 0 {
                rnd() as u32
            } else {
                let base = [144u32 << 24 | 195 << 16, 170 << 24 | 114 << 16, 206 << 24 | 247 << 16, 3 << 24 | 235 << 16 | 82 << 8][(rnd() % 4) as usize];
                base | (rnd() as u32 & 0xffff)
            };
            let ip = IpAddr::V4(Ipv4Addr::from(v));
            let want = old_linear(ip);
            hits += want as u32;
            assert_eq!(s.contains(Addr::from_ip(ip)), want, "{ip}");
        }
        assert!(hits > 100_000, "test would be vacuous: only {hits} hits");
        for &(lo, hi) in &s.ranges {
            for d in [lo.wrapping_sub(1), lo, hi, hi.wrapping_add(1)] {
                if d >> 32 == 0xffff {
                    let ip = IpAddr::V4(Ipv4Addr::from(d as u32));
                    assert_eq!(s.contains(Addr(d)), old_linear(ip), "{ip}");
                } else if d >> 96 != 0xffff_ffff {
                    let ip = IpAddr::V6(Ipv6Addr::from(d));
                    assert_eq!(s.contains(Addr(d)), old_linear(ip), "{ip}");
                }
            }
        }
        for _ in 0..200_000 {
            let v = (rnd() as u128) << 64 | rnd() as u128;
            let v = if rnd() % 2 == 0 { v } else { (0x2407_30c0u128 << 96) | (v & ((1u128 << 96) - 1)) };
            if v >> 32 == 0xffff {
                continue;
            }
            let ip = IpAddr::V6(Ipv6Addr::from(v));
            assert_eq!(s.contains(Addr(v)), old_linear(ip), "{ip}");
        }
    }
}
