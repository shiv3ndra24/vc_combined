//! Allocation-free Ethernet / VLAN / IPv4 / IPv6 / UDP frame parser.
//!
//! Why this exists instead of `L4Context` + `FiveTuple::from_ctxt`:
//! the thesis capture code compiles on the campus Retina using only
//! `packet.data()` (the whole frame), so that is the only Retina API this
//! crate relies on. The parser never allocates, never indexes a slice
//! without bounds checking, and returns a [`Reject`] reason rather than
//! panicking, because on a mirror port the bytes are whatever the network
//! sends.
//!
//! What it handles (each has a unit test):
//! * untagged frames and up to 3 stacked VLAN tags (0x8100, 0x88a8,
//!   0x9100, 0x9200). The old C++ tool in the re-validation deck lost up
//!   to 53% of Device A's packets by assuming a 14-byte Ethernet header.
//! * IPv4 with options (IHL) and non-first fragments (rejected, because
//!   they carry no UDP header).
//! * IPv6 with hop-by-hop, routing, destination-options, fragment and AH
//!   extension headers.
//! * Ethernet padding: the payload is cut to the UDP length, not to the
//!   end of the frame, so 4 bytes of FCS/padding never leak into a
//!   fingerprint.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IP address as a `u128`. IPv4 is stored v4-mapped (`::ffff:a.b.c.d`)
/// so one integer type and one sorted range table serve both families.
/// A genuine IPv6 `::ffff:0:0/96` address never appears on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Addr(pub u128);

const V4_MAPPED_PREFIX: u128 = 0xffff_0000_0000;

impl Addr {
    #[inline]
    pub fn from_v4(b: [u8; 4]) -> Addr {
        Addr(V4_MAPPED_PREFIX | u32::from_be_bytes(b) as u128)
    }
    #[inline]
    pub fn from_v6(b: [u8; 16]) -> Addr {
        Addr(u128::from_be_bytes(b))
    }
    #[inline]
    pub fn is_v4(self) -> bool {
        (self.0 >> 32) == 0xffff
    }
    pub fn to_ip(self) -> IpAddr {
        if self.is_v4() {
            IpAddr::V4(Ipv4Addr::from(self.0 as u32))
        } else {
            IpAddr::V6(Ipv6Addr::from(self.0))
        }
    }
    pub fn from_ip(ip: IpAddr) -> Addr {
        match ip {
            IpAddr::V4(v4) => Addr::from_v4(v4.octets()),
            IpAddr::V6(v6) => Addr::from_v6(v6.octets()),
        }
    }
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_ip())
    }
}

/// Why a frame was not turned into a [`UdpView`]. Used only for counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Shorter than the headers it claims to contain.
    TooShort,
    /// Not IPv4/IPv6.
    NotIp,
    /// IP, but not UDP (Retina's `udp` filter should prevent this).
    NotUdp,
    /// Non-first IP fragment: has no UDP header.
    Fragment,
    /// Internally inconsistent lengths.
    Malformed,
}

/// A parsed UDP datagram, borrowing the frame.
#[derive(Clone, Copy, Debug)]
pub struct UdpView<'a> {
    pub src: Addr,
    pub dst: Addr,
    pub src_port: u16,
    pub dst_port: u16,
    /// The UDP length field (header + payload), as sent on the wire.
    pub udp_len: u16,
    /// IPv4 TTL / IPv6 hop limit. Used for the duplicate root-cause
    /// diagnostic (see `dedup.rs`).
    pub ttl: u8,
    /// IPv4 identification (0 for IPv6).
    pub ip_id: u16,
    /// UDP payload, cut to the UDP length (never includes padding).
    pub payload: &'a [u8],
}

#[inline(always)]
fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// Parse a full Ethernet frame (as returned by `ZcFrame::data()`).
pub fn parse_udp(frame: &[u8]) -> Result<UdpView<'_>, Reject> {
    if frame.len() < 14 {
        return Err(Reject::TooShort);
    }
    let mut ethertype = be16(frame, 12).ok_or(Reject::TooShort)?;
    let mut off = 14usize;
    let mut tags = 0;
    while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100 | 0x9200) {
        if tags == 3 {
            return Err(Reject::Malformed);
        }
        ethertype = be16(frame, off + 2).ok_or(Reject::TooShort)?;
        off += 4;
        tags += 1;
    }
    match ethertype {
        0x0800 => parse_v4(frame, off),
        0x86dd => parse_v6(frame, off),
        _ => Err(Reject::NotIp),
    }
}

fn parse_v4(frame: &[u8], ip: usize) -> Result<UdpView<'_>, Reject> {
    let hdr = frame.get(ip..ip + 20).ok_or(Reject::TooShort)?;
    if hdr[0] >> 4 != 4 {
        return Err(Reject::Malformed);
    }
    let ihl = (hdr[0] & 0x0f) as usize * 4;
    if ihl < 20 {
        return Err(Reject::Malformed);
    }
    let total_len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    if total_len < ihl + 8 {
        return Err(Reject::Malformed);
    }
    let ip_id = u16::from_be_bytes([hdr[4], hdr[5]]);
    let frag = u16::from_be_bytes([hdr[6], hdr[7]]);
    if frag & 0x1fff != 0 {
        return Err(Reject::Fragment);
    }
    if hdr[9] != 17 {
        return Err(Reject::NotUdp);
    }
    let ttl = hdr[8];
    let src = Addr::from_v4([hdr[12], hdr[13], hdr[14], hdr[15]]);
    let dst = Addr::from_v4([hdr[16], hdr[17], hdr[18], hdr[19]]);
    let ip_end = (ip + total_len).min(frame.len());
    udp_at(frame, ip + ihl, ip_end, src, dst, ttl, ip_id)
}

fn parse_v6(frame: &[u8], ip: usize) -> Result<UdpView<'_>, Reject> {
    let hdr = frame.get(ip..ip + 40).ok_or(Reject::TooShort)?;
    if hdr[0] >> 4 != 6 {
        return Err(Reject::Malformed);
    }
    let payload_len = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
    let mut next = hdr[6];
    let hop = hdr[7];
    let mut s = [0u8; 16];
    s.copy_from_slice(&hdr[8..24]);
    let mut d = [0u8; 16];
    d.copy_from_slice(&hdr[24..40]);
    let (src, dst) = (Addr::from_v6(s), Addr::from_v6(d));
    // payload_len == 0 can mean a jumbogram; fall back to the frame end.
    let ip_end = if payload_len == 0 {
        frame.len()
    } else {
        (ip + 40 + payload_len).min(frame.len())
    };
    let mut o = ip + 40;
    for _ in 0..8 {
        match next {
            17 => return udp_at(frame, o, ip_end, src, dst, hop, 0),
            0 | 43 | 60 => {
                let n = *frame.get(o).ok_or(Reject::TooShort)?;
                let len = (*frame.get(o + 1).ok_or(Reject::TooShort)? as usize + 1) * 8;
                next = n;
                o += len;
            }
            44 => {
                let n = *frame.get(o).ok_or(Reject::TooShort)?;
                let fo = be16(frame, o + 2).ok_or(Reject::TooShort)?;
                if fo >> 3 != 0 {
                    return Err(Reject::Fragment);
                }
                next = n;
                o += 8;
            }
            51 => {
                let n = *frame.get(o).ok_or(Reject::TooShort)?;
                let len = (*frame.get(o + 1).ok_or(Reject::TooShort)? as usize + 2) * 4;
                next = n;
                o += len;
            }
            _ => return Err(Reject::NotUdp),
        }
        if o > frame.len() {
            return Err(Reject::TooShort);
        }
    }
    Err(Reject::Malformed)
}

#[inline]
fn udp_at(
    frame: &[u8],
    udp: usize,
    ip_end: usize,
    src: Addr,
    dst: Addr,
    ttl: u8,
    ip_id: u16,
) -> Result<UdpView<'_>, Reject> {
    let h = frame.get(udp..udp + 8).ok_or(Reject::TooShort)?;
    let udp_len = u16::from_be_bytes([h[4], h[5]]);
    if (udp_len as usize) < 8 {
        return Err(Reject::Malformed);
    }
    let start = udp + 8;
    let end = (udp + udp_len as usize).min(ip_end).min(frame.len());
    let payload = if start <= end { &frame[start..end] } else { &frame[0..0] };
    Ok(UdpView {
        src,
        dst,
        src_port: u16::from_be_bytes([h[0], h[1]]),
        dst_port: u16::from_be_bytes([h[2], h[3]]),
        udp_len,
        ttl,
        ip_id,
        payload,
    })
}

/// Test/bench helper: build an Ethernet+IP+UDP frame around `payload`.
/// Public so integration tests, benches and the replay tool can all use
/// the same builder.
pub mod build {
    use super::*;

    pub struct Spec<'a> {
        pub src: Addr,
        pub dst: Addr,
        pub src_port: u16,
        pub dst_port: u16,
        pub vlan_tags: u8,
        pub ttl: u8,
        pub ip_id: u16,
        pub payload: &'a [u8],
        /// extra zero bytes after the datagram (Ethernet padding / FCS)
        pub trailer: usize,
    }

    impl<'a> Spec<'a> {
        pub fn new(src: Addr, dst: Addr, sp: u16, dp: u16, payload: &'a [u8]) -> Self {
            Spec { src, dst, src_port: sp, dst_port: dp, vlan_tags: 0, ttl: 64, ip_id: 1, payload, trailer: 0 }
        }
    }

    pub fn frame(s: &Spec) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        f[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        let v4 = s.src.is_v4();
        for _ in 0..s.vlan_tags {
            f.extend_from_slice(&[0x81, 0x00, 0x00, 0x07]);
        }
        // The last tag's TPID field holds the real ethertype; patch the
        // structure: ... [tpid][tci] repeated, then ethertype.
        f.extend_from_slice(&if v4 { [0x08, 0x00] } else { [0x86, 0xdd] });
        let udp_len = (8 + s.payload.len()) as u16;
        if v4 {
            let total = 20 + udp_len;
            f.extend_from_slice(&[0x45, 0]);
            f.extend_from_slice(&total.to_be_bytes());
            f.extend_from_slice(&s.ip_id.to_be_bytes());
            f.extend_from_slice(&[0, 0, s.ttl, 17, 0, 0]);
            f.extend_from_slice(&(s.src.0 as u32).to_be_bytes());
            f.extend_from_slice(&(s.dst.0 as u32).to_be_bytes());
        } else {
            f.extend_from_slice(&[0x60, 0, 0, 0]);
            f.extend_from_slice(&udp_len.to_be_bytes());
            f.extend_from_slice(&[17, s.ttl]);
            f.extend_from_slice(&s.src.0.to_be_bytes());
            f.extend_from_slice(&s.dst.0.to_be_bytes());
        }
        f.extend_from_slice(&s.src_port.to_be_bytes());
        f.extend_from_slice(&s.dst_port.to_be_bytes());
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(s.payload);
        f.extend(std::iter::repeat(0).take(s.trailer));
        f
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    fn a4(a: u8, b: u8, c: u8, d: u8) -> Addr {
        Addr::from_v4([a, b, c, d])
    }

    #[test]
    fn untagged_ipv4_roundtrip() {
        let p = [5u8, 1, 2, 3, 4, 5, 6, 7, 8];
        let f = frame(&Spec { ttl: 63, ip_id: 777, ..Spec::new(a4(10, 0, 0, 1), a4(170, 114, 1, 1), 5000, 8801, &p) });
        let v = parse_udp(&f).unwrap();
        assert_eq!((v.src, v.dst), (a4(10, 0, 0, 1), a4(170, 114, 1, 1)));
        assert_eq!((v.src_port, v.dst_port), (5000, 8801));
        assert_eq!(v.payload, &p);
        assert_eq!((v.ttl, v.ip_id, v.udp_len), (63, 777, 17));
    }

    #[test]
    fn vlan_tags_one_two_three_all_parse_and_four_is_rejected() {
        let p = [1u8; 20];
        for tags in 1..=3 {
            let f = frame(&Spec { vlan_tags: tags, ..Spec::new(a4(1, 1, 1, 1), a4(2, 2, 2, 2), 1, 2, &p) });
            let v = parse_udp(&f).unwrap_or_else(|e| panic!("{tags} tags: {e:?}"));
            assert_eq!(v.payload.len(), 20, "{tags} tags");
        }
        let f = frame(&Spec { vlan_tags: 4, ..Spec::new(a4(1, 1, 1, 1), a4(2, 2, 2, 2), 1, 2, &p) });
        assert_eq!(parse_udp(&f).unwrap_err(), Reject::Malformed);
    }

    #[test]
    fn ipv6_roundtrip() {
        let s = Addr::from_v6("2001:df4:e000::1".parse::<Ipv6Addr>().unwrap().octets());
        let d = Addr::from_v6("2407:30c0::5".parse::<Ipv6Addr>().unwrap().octets());
        let p = [9u8; 33];
        let f = frame(&Spec { ttl: 55, ..Spec::new(s, d, 58474, 8801, &p) });
        let v = parse_udp(&f).unwrap();
        assert_eq!((v.src, v.dst, v.ttl, v.ip_id), (s, d, 55, 0));
        assert!(!v.src.is_v4());
        assert_eq!(v.payload.len(), 33);
    }

    #[test]
    fn padding_after_the_datagram_is_not_payload() {
        let p = [7u8; 10];
        let f = frame(&Spec { trailer: 18, ..Spec::new(a4(1, 1, 1, 1), a4(2, 2, 2, 2), 1, 2, &p) });
        assert_eq!(parse_udp(&f).unwrap().payload, &p);
    }

    #[test]
    fn truncated_capture_gives_a_shorter_payload_not_a_panic() {
        let p = [7u8; 100];
        let f = frame(&Spec::new(a4(1, 1, 1, 1), a4(2, 2, 2, 2), 1, 2, &p));
        let v = parse_udp(&f[..f.len() - 60]).unwrap();
        assert_eq!(v.payload.len(), 40);
    }

    #[test]
    fn ipv4_options_are_skipped() {
        // Build a frame, then rewrite IHL to 6 and insert 4 option bytes.
        let p = [3u8; 12];
        let f = frame(&Spec::new(a4(1, 1, 1, 1), a4(2, 2, 2, 2), 10, 20, &p));
        let mut g = f[..34].to_vec();
        g[14] = 0x46;
        let tl = u16::from_be_bytes([g[16], g[17]]) + 4;
        g[16..18].copy_from_slice(&tl.to_be_bytes());
        g.extend_from_slice(&[1, 1, 1, 0]);
        g.extend_from_slice(&f[34..]);
        let v = parse_udp(&g).unwrap();
        assert_eq!((v.src_port, v.dst_port), (10, 20));
        assert_eq!(v.payload, &p);
    }

    #[test]
    fn non_first_fragment_is_rejected() {
        let p = [3u8; 12];
        let mut f = frame(&Spec::new(a4(1, 1, 1, 1), a4(2, 2, 2, 2), 10, 20, &p));
        f[20] = 0x00;
        f[21] = 0x10; // fragment offset 16
        assert_eq!(parse_udp(&f).unwrap_err(), Reject::Fragment);
        f[20] = 0x20; // MF set, offset 0: first fragment still has a UDP header
        f[21] = 0x00;
        assert!(parse_udp(&f).is_ok());
    }

    #[test]
    fn ipv6_extension_headers_are_walked() {
        let s = Addr::from_v6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let d = Addr::from_v6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let p = [4u8; 16];
        let f = frame(&Spec::new(s, d, 7, 8, &p));
        // insert a hop-by-hop header (8 bytes) between IPv6 and UDP
        let ip = 14;
        let mut g = f[..ip + 40].to_vec();
        g[ip + 6] = 0; // next = hop-by-hop
        let pl = u16::from_be_bytes([g[ip + 4], g[ip + 5]]) + 8;
        g[ip + 4..ip + 6].copy_from_slice(&pl.to_be_bytes());
        g.extend_from_slice(&[17, 0, 1, 4, 0, 0, 0, 0]); // next=UDP, len=0 (8 bytes)
        g.extend_from_slice(&f[ip + 40..]);
        let v = parse_udp(&g).unwrap();
        assert_eq!((v.src_port, v.dst_port), (7, 8));
        assert_eq!(v.payload, &p);
    }

    #[test]
    fn non_ip_and_short_frames_are_rejected_not_panicked() {
        assert_eq!(parse_udp(&[]).unwrap_err(), Reject::TooShort);
        assert_eq!(parse_udp(&[0u8; 13]).unwrap_err(), Reject::TooShort);
        let mut arp = vec![0u8; 60];
        arp[12] = 0x08;
        arp[13] = 0x06;
        assert_eq!(parse_udp(&arp).unwrap_err(), Reject::NotIp);
    }

    /// Cheap deterministic fuzz: random bytes, and valid frames with random
    /// single-byte corruption, must never panic and never yield a payload
    /// longer than the frame.
    #[test]
    fn fuzz_never_panics() {
        let mut x: u64 = 0x9e3779b97f4a7c15;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let base4 = frame(&Spec::new(a4(10, 1, 1, 1), a4(170, 114, 1, 1), 1000, 8801, &[5u8; 64]));
        let base6 = frame(&Spec::new(
            Addr::from_v6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            Addr::from_v6([0x24, 7, 0x30, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            1000,
            8801,
            &[5u8; 64],
        ));
        for i in 0..300_000 {
            let mut buf: Vec<u8> = match i % 3 {
                0 => (0..(rnd() % 200) as usize).map(|_| rnd() as u8).collect(),
                1 => base4.clone(),
                _ => base6.clone(),
            };
            if i % 3 != 0 {
                for _ in 0..(1 + rnd() % 3) {
                    let n = buf.len();
                    buf[(rnd() as usize) % n] = rnd() as u8;
                }
                if rnd() % 4 == 0 {
                    let cut = (rnd() as usize) % (buf.len() + 1);
                    buf.truncate(cut);
                }
            }
            if let Ok(v) = parse_udp(&buf) {
                assert!(v.payload.len() <= buf.len());
            }
        }
    }
}
