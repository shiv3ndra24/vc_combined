//! # ip_ranges.rs: the Teams / Meet address gate
//!
//! **What this file does**
//! - `IpTable`: the Teams and Meet server ranges as one sorted table of disjoint
//!   `(lo, hi, platform)` address ranges (IPv4 stored v4-mapped, `::ffff:a.b.c.d`, so both
//!   families share one table). Lookup is one binary search (`partition_point`).
//! - Built from `ip_lists/teams.txt` and `ip_lists/meet.txt` (one CIDR per line), read at
//!   start-up or compiled in (`IpTable::builtin`).
//! - `quick_precheck(data)`: the outermost gate on the capture path. Parses Ethernet (with
//!   802.1Q / QinQ tags), IPv4 or IPv6 (walking extension headers), confirms UDP and looks
//!   both addresses up. Returns a [`Gate`] for a Teams/Meet packet, `None` otherwise.
//!
//! **Why one table (vc_combined).** Before, the gate had hard-coded checks here and the
//! metrics had a second list of text prefixes in `network_metrics.rs`. They drifted: IPv6
//! Teams traffic to `2603:1063::/38` passed the gate, reached the CSV and produced no metric.
//! Now the gate also decides the direction (`Gate::src_is_server`), and every metric uses it.
//!
//! **Why the lists may not overlap.** A packet must belong to exactly one platform. Example:
//! if `52.112.0.0/14` were in both files, a packet to 52.113.64.10 could be counted as Teams
//! and as Meet. `IpTable::from_lists` refuses overlapping lists at start-up.

use crate::models::Platform;
use std::net::IpAddr;
use std::sync::OnceLock;

/// The compiled-in copies of the list files (same files the binary reads with `--ip-dir`).
pub const BUILTIN_TEAMS: &str = include_str!("../../ip_lists/teams.txt");
pub const BUILTIN_MEET: &str = include_str!("../../ip_lists/meet.txt");

#[derive(Clone, Debug)]
pub struct IpTable {
    /// sorted by `lo`, disjoint, inclusive
    ranges: Vec<(u128, u128, Platform)>,
}

/// IPv4 as a v4-mapped IPv6 number.
#[inline(always)]
pub fn v4(ip: [u8; 4]) -> u128 {
    (0xffffu128 << 32) | u32::from_be_bytes(ip) as u128
}

/// IPv6 (16 bytes, big endian) as a number.
#[inline(always)]
pub fn v6(ip: &[u8]) -> u128 {
    let mut b = [0u8; 16];
    b.copy_from_slice(&ip[..16]);
    u128::from_be_bytes(b)
}

/// Parse one list text: one CIDR (or bare address) per line, `#` starts a comment.
pub fn parse_list(text: &str) -> Result<Vec<(u128, u128)>, String> {
    let mut out = Vec::new();
    for (no, line) in text.lines().enumerate() {
        let l = line.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        let (a, len) = match l.split_once('/') {
            Some((a, n)) => (a, Some(n)),
            None => (l, None),
        };
        let ip: IpAddr = a.parse().map_err(|e| format!("line {}: bad address {l:?}: {e}", no + 1))?;
        let (base, fam_bits) = match ip {
            IpAddr::V4(v) => (v4(v.octets()), 32u32),
            IpAddr::V6(v) => (u128::from_be_bytes(v.octets()), 128u32),
        };
        let plen: u32 = match len {
            Some(n) => n.parse().map_err(|e| format!("line {}: bad prefix length in {l:?}: {e}", no + 1))?,
            None => fam_bits,
        };
        if plen > fam_bits {
            return Err(format!("line {}: prefix length {plen} too large in {l:?}", no + 1));
        }
        let host = fam_bits - plen;
        let mask: u128 = if host == 0 { 0 } else { (1u128 << host) - 1 };
        out.push((base & !mask, base | mask));
    }
    Ok(out)
}

fn merge(mut v: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    v.sort_unstable();
    let mut m: Vec<(u128, u128)> = Vec::with_capacity(v.len());
    for (lo, hi) in v {
        match m.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => m.push((lo, hi)),
        }
    }
    m
}

impl IpTable {
    /// Build from the text of `teams.txt` and `meet.txt`. Fails if the lists overlap.
    pub fn from_lists(teams: &str, meet: &str) -> Result<IpTable, String> {
        let t = merge(parse_list(teams).map_err(|e| format!("teams list: {e}"))?);
        let m = merge(parse_list(meet).map_err(|e| format!("meet list: {e}"))?);
        let mut ranges: Vec<(u128, u128, Platform)> =
            t.into_iter().map(|(a, b)| (a, b, Platform::Teams)).chain(m.into_iter().map(|(a, b)| (a, b, Platform::Meet))).collect();
        ranges.sort_unstable_by_key(|r| r.0);
        for w in ranges.windows(2) {
            if w[1].0 <= w[0].1 {
                return Err(format!(
                    "the Teams and Meet lists overlap ({} and {}): a packet would belong to both platforms",
                    show(w[0].0),
                    show(w[1].0)
                ));
            }
        }
        Ok(IpTable { ranges })
    }

    /// The compiled-in lists.
    pub fn builtin() -> IpTable {
        IpTable::from_lists(BUILTIN_TEAMS, BUILTIN_MEET).expect("compiled-in Teams/Meet lists must parse (unit test)")
    }

    #[inline]
    pub fn lookup(&self, a: u128) -> Option<Platform> {
        let i = self.ranges.partition_point(|r| r.0 <= a);
        if i == 0 {
            return None;
        }
        let r = &self.ranges[i - 1];
        (a <= r.1).then_some(r.2)
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
    /// Number of merged ranges per platform (for the start-up line and run_info).
    pub fn count(&self, p: Platform) -> usize {
        self.ranges.iter().filter(|r| r.2 == p).count()
    }
}

fn show(a: u128) -> String {
    if a >> 32 == 0xffff {
        std::net::Ipv4Addr::from((a & 0xffff_ffff) as u32).to_string()
    } else {
        std::net::Ipv6Addr::from(a).to_string()
    }
}

static TABLE: OnceLock<IpTable> = OnceLock::new();

/// Install the table used by `quick_precheck` (once, before capture starts).
pub fn install(t: IpTable) {
    let _ = TABLE.set(t);
}

/// The installed table (the compiled-in one if `install` was never called).
#[inline(always)]
pub fn table() -> &'static IpTable {
    TABLE.get_or_init(IpTable::builtin)
}

/// What the gate found out about a Teams / Meet packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gate {
    pub platform: Platform,
    pub is_ipv6: bool,
    /// byte offset of the IP header
    pub ip_start: usize,
    /// byte offset of the first UDP payload byte
    pub udp_payload_offset: usize,
    /// true: the SOURCE is the server, so the packet is DOWNLINK and the client is the
    /// destination. false: uplink, the client is the source. If both addresses are listed
    /// (never seen) the source wins, as the old `get_client_ip` did.
    pub src_is_server: bool,
}

/// Gate every raw Ethernet frame: Ethernet / VLAN, IPv4 or IPv6, UDP, and source or
/// destination in the Teams/Meet table. `None` for everything else (most campus traffic;
/// in vc_capture that goes on to the Zoom engine).
#[inline(always)]
pub fn quick_precheck(data: &[u8]) -> Option<Gate> {
    if data.len() < 14 {
        return None;
    }
    let raw_et = u16::from_be_bytes([data[12], data[13]]);
    let (ethertype, ip_start) = match raw_et {
        0x88a8 => {
            if data.len() < 22 {
                return None;
            }
            let inner = u16::from_be_bytes([data[16], data[17]]);
            if inner == 0x8100 { (u16::from_be_bytes([data[20], data[21]]), 22usize) } else { (inner, 18usize) }
        }
        0x8100 => {
            if data.len() < 18 {
                return None;
            }
            (u16::from_be_bytes([data[16], data[17]]), 18usize)
        }
        _ => (raw_et, 14usize),
    };
    let t = table();
    match ethertype {
        0x0800 => {
            if data.len() < ip_start + 20 || data[ip_start + 9] != 17 {
                return None;
            }
            let ihl = (data[ip_start] & 0x0F) as usize * 4;
            if ihl < 20 {
                return None;
            }
            let s = v4([data[ip_start + 12], data[ip_start + 13], data[ip_start + 14], data[ip_start + 15]]);
            let d = v4([data[ip_start + 16], data[ip_start + 17], data[ip_start + 18], data[ip_start + 19]]);
            let (platform, src_is_server) = match (t.lookup(s), t.lookup(d)) {
                (Some(p), _) => (p, true),
                (None, Some(p)) => (p, false),
                _ => return None,
            };
            Some(Gate { platform, is_ipv6: false, ip_start, udp_payload_offset: ip_start + ihl + 8, src_is_server })
        }
        0x86DD => {
            if data.len() < ip_start + 40 {
                return None;
            }
            let s = v6(&data[ip_start + 8..ip_start + 24]);
            let d = v6(&data[ip_start + 24..ip_start + 40]);
            let (platform, src_is_server) = match (t.lookup(s), t.lookup(d)) {
                (Some(p), _) => (p, true),
                (None, Some(p)) => (p, false),
                _ => return None,
            };
            // Walk extension headers until UDP (17) or give up
            let mut next_hdr = data[ip_start + 6];
            let mut offset = ip_start + 40;
            loop {
                match next_hdr {
                    17 => return Some(Gate { platform, is_ipv6: true, ip_start, udp_payload_offset: offset + 8, src_is_server }),
                    0 | 60 | 43 => {
                        if data.len() < offset + 2 {
                            return None;
                        }
                        next_hdr = data[offset];
                        offset += (data[offset + 1] as usize + 1) * 8;
                    }
                    44 => {
                        if data.len() < offset + 8 {
                            return None;
                        }
                        next_hdr = data[offset];
                        offset += 8;
                    }
                    51 => {
                        if data.len() < offset + 2 {
                            return None;
                        }
                        next_hdr = data[offset];
                        offset += (data[offset + 1] as usize + 2) * 4;
                    }
                    _ => return None,
                }
                if offset > data.len() {
                    return None;
                }
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a4(s: &str) -> u128 {
        v4(s.parse::<std::net::Ipv4Addr>().unwrap().octets())
    }
    fn a6(s: &str) -> u128 {
        u128::from_be_bytes(s.parse::<std::net::Ipv6Addr>().unwrap().octets())
    }

    #[test]
    fn builtin_lists_parse_and_hold_the_published_ranges() {
        let t = IpTable::builtin();
        assert_eq!(t.lookup(a4("52.112.0.1")), Some(Platform::Teams));
        assert_eq!(t.lookup(a4("52.115.255.255")), Some(Platform::Teams));
        assert_eq!(t.lookup(a4("52.116.0.0")), None);
        assert_eq!(t.lookup(a4("52.123.10.10")), Some(Platform::Teams));
        assert_eq!(t.lookup(a6("2603:1063:200::5")), Some(Platform::Teams)); // the one that was missing from the metrics list
        assert_eq!(t.lookup(a6("2603:1063:3ff:ffff::1")), Some(Platform::Teams)); // last /38 address block
        assert_eq!(t.lookup(a6("2603:1063:400::5")), None); // /38 = 2603:1063:0000:: .. 2603:1063:03ff:ffff:...
        assert_eq!(t.lookup(a6("2620:1ec:6::1")), Some(Platform::Teams));
        assert_eq!(t.lookup(a6("2603:1010::1")), None, "2603:1010 stays commented out");
        assert_eq!(t.lookup(a4("74.125.250.7")), Some(Platform::Meet));
        assert_eq!(t.lookup(a4("74.125.247.128")), Some(Platform::Meet));
        assert_eq!(t.lookup(a4("74.125.247.129")), None);
        assert_eq!(t.lookup(a4("142.250.82.219")), Some(Platform::Meet));
        assert_eq!(t.lookup(a6("2001:4860:4864:5::17")), Some(Platform::Meet));
        assert_eq!(t.lookup(a6("2001:4860:4864:4:8000::")), Some(Platform::Meet));
        assert_eq!(t.lookup(a6("2001:4860:4864:4:8000::1")), None);
        assert_eq!(t.lookup(a4("10.184.4.232")), None);
        assert_eq!(t.lookup(a4("170.114.10.10")), None, "Zoom is not in the Teams/Meet table");
    }

    #[test]
    fn overlapping_lists_are_refused() {
        assert!(IpTable::from_lists("52.112.0.0/14", "52.113.0.0/16").is_err());
        assert!(IpTable::from_lists("52.112.0.0/14\n# c\n", "74.125.250.0/24").is_ok());
        assert!(IpTable::from_lists("bogus", "").is_err());
        assert!(IpTable::from_lists("10.0.0.0/40", "").is_err());
    }

    fn eth_v4(src: [u8; 4], dst: [u8; 4], vlan: bool) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        if vlan {
            f.extend_from_slice(&[0x81, 0x00, 0x00, 0x05]);
        }
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(&[0x45, 0, 0, 40, 0, 0, 0, 0, 64, 17, 0, 0]);
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&[0x4e, 0x20, 0x0d, 0x96, 0, 20, 0, 0]);
        f.extend_from_slice(&[0x80; 12]);
        f
    }

    #[test]
    fn precheck_gives_platform_and_direction() {
        let up = quick_precheck(&eth_v4([10, 184, 5, 20], [52, 113, 64, 10], false)).unwrap();
        assert_eq!((up.platform, up.src_is_server, up.ip_start, up.udp_payload_offset), (Platform::Teams, false, 14, 42));
        let down = quick_precheck(&eth_v4([142, 250, 82, 219], [10, 184, 4, 232], true)).unwrap();
        assert_eq!((down.platform, down.src_is_server, down.ip_start), (Platform::Meet, true, 18));
        assert!(quick_precheck(&eth_v4([10, 0, 0, 1], [170, 114, 1, 1], false)).is_none());
    }
}
