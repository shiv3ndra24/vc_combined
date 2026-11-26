//! Live de-duplication of second copies of a packet.
//!
//! ## Problem (from the four sample runs and the dup_check runs try0-try4)
//! Every live capture has ~50% second copies: same 5-tuple, same Zoom
//! sequence numbers, same length, a median 11 us (p99 48 us, max 9 ms)
//! after the first. The replayed pcap does not have them (it is written
//! after de-dup).
//!
//! Where they come from (CONFIRMED by the try4 control run, 2026-10-24): the
//! campus mirror carries BOTH legs of a wireless client's packet, the CAPWAP
//! tunnel leg (access point -> controller) and the native wired leg. The
//! capture strips the CAPWAP wrapper, which makes the tunnel leg look like the
//! wired leg: the same inner IP packet twice. With the strip switched off, the
//! "same IP packet, different Ethernet header" copies fell from 33.6-42.8 % of
//! all frames (try0-try3) to 0.39 % (try4), a factor of about 90. So the second
//! copy is NOT a SPAN misconfiguration that could be "fixed" and is not created
//! by Retina or the NIC: the redundancy is in the network design (central
//! switching on the wireless controller, both sides mirrored). A copy share near
//! 0 % would mean the capture point sees only one leg.
//!
//! The two copies often reach DIFFERENT RX cores, because the NIC hashes the
//! tunnel leg on the outer access-point / controller addresses before the strip
//! (try0-try3: 65-79 % of the header-different copies were on another core).
//! That is why this table is shared (below).
//!
//! Genuine Zoom retransmissions reuse the sequence number about 100 ms plus
//! RTT later and are real traffic that must be counted.
//!
//! ## Design
//! * One direct-mapped table (`Dedup`), no allocation after start, bounded
//!   memory (`slots * 16` bytes; 16,384 slots = 256 KB, fits L2). A slot holds
//!   `(fingerprint, first-seen time, ttl, ip_id)`.
//! * **Shared across capture cores (`SharedDedup`).** The first campus runs
//!   showed that a table *per core* misses most twins: the two copies
//!   of a packet do not always reach the same RX queue (s1: only 4 of 17 flows
//!   were fully de-duplicated, roughly the 1-in-4 chance of two independent
//!   copies landing on the same one of 4 cores; s2: none). The shared table is
//!   split into mutex-guarded stripes picked by the high bits of the
//!   fingerprint, so a packet and its twin always meet in the same stripe
//!   whatever core they arrive on. It sits after the port and address gates,
//!   so it only sees Zoom traffic (about 1.5 to 3 thousand packets per second
//!   on the campus link): an uncontended lock costs ~20 ns, which is
//!   negligible there and keeps the code simple (no atomics-with-torn-slot
//!   reasoning). The per-core `Dedup` is still the building block.
//! * A packet is a duplicate iff its slot holds the same 64-bit fingerprint
//!   seen less than `window` ago. Otherwise it overwrites the slot.
//! * **Fingerprint = 5-tuple + UDP length + the first 48 payload bytes.**
//!   This differs from the design doc's field list (media type, outer seq,
//!   inner seq, inner timestamp) on purpose: those fields all live in the
//!   first 48 bytes (SFU 8 B + media header up to the RTP header at +24 for
//!   video, i.e. bytes 32..44 which also contain RTP seq/timestamp/SSRC; the
//!   other two video layouts end inside the 48 bytes as well: +28 gives
//!   36..48, +20 gives 28..40, p7b),
//!   so the byte hash is a superset of that list, and it needs no header
//!   parsing. Consequences: (a) the 50% of packets that are twins are
//!   rejected *before* the header parse and aggregation; (b) it works for
//!   framings we do not understand (the IPv6 capture has no SFU header);
//!   (c) it does not break when Zoom changes a header layout.
//! * **Window = 10 ms.** Twins p99 48 us / max 9 ms are inside it;
//!   retransmissions (>= 100 ms) are 10x outside. If a retransmission ever
//!   arrived within 10 ms it would be dropped, so the window is not larger.
//! * Each detected duplicate also records whether its **IP TTL and IP ID**
//!   equal the first copy's (`DupInfo`). For the CAPWAP copies both are expected
//!   to be equal, because the strip only replaces the Ethernet header and the
//!   inner IP packet is the same one (INFERENCE from the mechanism; try4 saw
//!   TTL identical in 99.8 % of the few remaining header-different TCP repeats,
//!   a different population, so it is weak support). A TTL off by one would
//!   mean a copy that was seen on both sides of a routed hop, which is not the
//!   CAPWAP case: worth a look if it ever shows up in the counters.

use crate::net::Addr;

/// Folded 64x64->128 multiply (the wyhash mixing step).
#[inline(always)]
pub fn fold(a: u64, b: u64) -> u64 {
    let r = (a as u128).wrapping_mul(b as u128);
    (r as u64) ^ ((r >> 64) as u64)
}

const K0: u64 = 0xa076_1d64_78bd_642f;
const K1: u64 = 0xe703_7ed1_a0b4_28db;
const K2: u64 = 0x8ebc_6af0_9c88_c6e3;
const K3: u64 = 0x5899_65cc_7537_4cc3;

/// Number of leading payload bytes covered by the fingerprint.
pub const FP_BYTES: usize = 48;

/// 64-bit fingerprint; never 0 (0 marks an empty slot).
#[inline]
pub fn fingerprint(seed: u64, src: Addr, dst: Addr, sport: u16, dport: u16, udp_len: u16, payload: &[u8]) -> u64 {
    let mut buf = [0u8; FP_BYTES];
    let n = payload.len().min(FP_BYTES);
    buf[..n].copy_from_slice(&payload[..n]);
    let mut h = fold(seed ^ (src.0 as u64), K0 ^ ((src.0 >> 64) as u64));
    h = fold(h ^ (dst.0 as u64), K1 ^ ((dst.0 >> 64) as u64));
    h = fold(h ^ ((sport as u64) << 48 | (dport as u64) << 32 | udp_len as u64), K2);
    let mut i = 0;
    while i < FP_BYTES {
        let w = u64::from_le_bytes([
            buf[i], buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7],
        ]);
        h = fold(h ^ w, K3 ^ (i as u64));
        i += 8;
    }
    if h == 0 {
        1
    } else {
        h
    }
}

#[derive(Clone, Copy, Default)]
struct Slot {
    fp: u64,
    /// bits 0..40 time in us, 40..48 ttl, 48..64 ip_id
    meta: u64,
}

const T_BITS: u32 = 40;
const T_MASK: u64 = (1u64 << T_BITS) - 1;

/// What the second copy looked like relative to the first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DupInfo {
    /// 0 = same TTL, 1 = differs by exactly 1, 2 = other difference
    pub ttl_rel: u8,
    pub id_same: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    New,
    Dup(DupInfo),
}

pub struct Dedup {
    slots: Box<[Slot]>,
    mask: usize,
    window_us: u64,
}

impl Dedup {
    /// `slots` is rounded up to a power of two.
    pub fn new(slots: usize, window_us: u64) -> Dedup {
        let n = slots.max(16).next_power_of_two();
        Dedup { slots: vec![Slot::default(); n].into_boxed_slice(), mask: n - 1, window_us: window_us.min(T_MASK / 2) }
    }

    pub fn memory_bytes(&self) -> usize {
        self.slots.len() * std::mem::size_of::<Slot>()
    }

    #[inline]
    pub fn check(&mut self, fp: u64, t_us: u64, ttl: u8, ip_id: u16) -> Verdict {
        // Low bits of a wyhash-style fold are well mixed.
        let idx = (fp as usize) & self.mask;
        // SAFETY-free: idx <= mask < slots.len(), but keep it panic-free anyway.
        let Some(slot) = self.slots.get_mut(idx) else {
            return Verdict::New;
        };
        if slot.fp == fp {
            let t0 = slot.meta & T_MASK;
            // Circular distance on the 40-bit clock. Taking the shorter way
            // round makes a small *negative* difference (a timestamp taken a
            // few us "before" the stored one, e.g. a thread migrated between
            // cores or a clock read before the lock) count as close, not as
            // 12 days old.
            let d = (t_us & T_MASK).wrapping_sub(t0) & T_MASK;
            let age = if d > T_MASK / 2 { T_MASK + 1 - d } else { d };
            if age < self.window_us {
                let ttl0 = ((slot.meta >> T_BITS) & 0xff) as u8;
                let id0 = (slot.meta >> 48) as u16;
                let d = (ttl0 as i16 - ttl as i16).abs();
                return Verdict::Dup(DupInfo {
                    ttl_rel: if d == 0 { 0 } else if d == 1 { 1 } else { 2 },
                    id_same: id0 == ip_id,
                });
            }
        }
        slot.fp = fp;
        slot.meta = (t_us & T_MASK) | (ttl as u64) << T_BITS | (ip_id as u64) << 48;
        Verdict::New
    }
}

/// One stripe of the shared table. Aligned so two stripes never share a cache
/// line (the locks of different stripes are taken by different cores).
#[repr(align(128))]
struct Stripe(std::sync::Mutex<Dedup>);

/// Cross-core de-duplication: `stripes` independent [`Dedup`] tables, chosen
/// by the *high* bits of the fingerprint (the table inside a stripe indexes by
/// the *low* bits, so the two choices are independent).
///
/// Why this exists: see the module comment. A packet and its second copy have
/// the same fingerprint, hence the same stripe and the same slot, whichever
/// core each copy was received on.
pub struct SharedDedup {
    stripes: Box<[Stripe]>,
    mask: usize,
}

impl SharedDedup {
    /// `total_slots` is the whole table (rounded up per stripe to a power of
    /// two); `stripes` is rounded up to a power of two (at most 256).
    pub fn new(total_slots: usize, window_us: u64, stripes: usize) -> SharedDedup {
        let n = stripes.clamp(1, 256).next_power_of_two();
        let per = (total_slots / n).max(16);
        let v: Vec<Stripe> = (0..n).map(|_| Stripe(std::sync::Mutex::new(Dedup::new(per, window_us)))).collect();
        SharedDedup { stripes: v.into_boxed_slice(), mask: n - 1 }
    }

    pub fn stripes(&self) -> usize {
        self.stripes.len()
    }

    pub fn memory_bytes(&self) -> usize {
        self.stripes.iter().map(|s| s.0.lock().map_or(0, |d| d.memory_bytes())).sum()
    }

    /// Same contract as [`Dedup::check`]; callable from any core.
    #[inline]
    pub fn check(&self, fp: u64, t_us: u64, ttl: u8, ip_id: u16) -> Verdict {
        let st = &self.stripes[((fp >> 56) as usize) & self.mask];
        // A poisoned lock only means another thread panicked while holding
        // it; the table is plain data, so keep using it.
        let mut g = match st.0.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.check(fp, t_us, ttl, ip_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(n: u8) -> Addr {
        Addr::from_v4([10, 0, 0, n])
    }
    fn fp(payload: &[u8]) -> u64 {
        fingerprint(7, a(1), a(2), 5000, 8801, 8 + payload.len() as u16, payload)
    }

    #[test]
    fn identical_copy_within_window_is_a_duplicate() {
        let mut d = Dedup::new(1024, 10_000);
        let f = fp(&[5, 1, 2, 3]);
        assert_eq!(d.check(f, 1_000, 64, 9), Verdict::New);
        assert_eq!(d.check(f, 1_011, 64, 9), Verdict::Dup(DupInfo { ttl_rel: 0, id_same: true }));
    }

    #[test]
    fn retransmission_100ms_later_is_not_a_duplicate() {
        let mut d = Dedup::new(1024, 10_000);
        let f = fp(&[5, 1, 2, 3]);
        assert_eq!(d.check(f, 0, 64, 1), Verdict::New);
        assert_eq!(d.check(f, 100_000, 64, 2), Verdict::New);
        // and the retransmission's own twin is caught against the new slot time
        assert!(matches!(d.check(f, 100_020, 64, 2), Verdict::Dup(_)));
    }

    #[test]
    fn window_edge() {
        let mut d = Dedup::new(1024, 10_000);
        let f = fp(&[1]);
        d.check(f, 0, 1, 1);
        assert!(matches!(d.check(f, 9_999, 1, 1), Verdict::Dup(_)));
        let mut d = Dedup::new(1024, 10_000);
        d.check(f, 0, 1, 1);
        assert_eq!(d.check(f, 10_000, 1, 1), Verdict::New);
    }

    #[test]
    fn different_byte_or_length_or_port_is_not_a_duplicate() {
        let mut d = Dedup::new(1 << 16, 10_000);
        let base = fp(&[5, 1, 2, 3]);
        d.check(base, 0, 64, 1);
        assert_eq!(d.check(fp(&[5, 1, 2, 4]), 1, 64, 1), Verdict::New);
        assert_eq!(d.check(fp(&[5, 1, 2, 3, 0]), 2, 64, 1), Verdict::New);
        let other_port = fingerprint(7, a(1), a(2), 5001, 8801, 12, &[5, 1, 2, 3]);
        assert_eq!(d.check(other_port, 3, 64, 1), Verdict::New);
        let swapped = fingerprint(7, a(2), a(1), 8801, 5000, 12, &[5, 1, 2, 3]);
        assert_eq!(d.check(swapped, 4, 64, 1), Verdict::New, "reverse direction is a different packet");
    }

    #[test]
    fn bytes_beyond_the_fingerprint_do_not_matter_but_length_does() {
        let mut p1 = vec![9u8; 200];
        let mut p2 = p1.clone();
        p2[100] = 1;
        p1[0] = 5;
        p2[0] = 5;
        assert_eq!(fp(&p1), fp(&p2), "differences after byte 48 are intentionally ignored");
        p2.push(0);
        assert_ne!(fp(&p1), fp(&p2), "a different length is a different packet");
    }

    #[test]
    fn ttl_and_id_diagnostics() {
        let mut d = Dedup::new(1024, 10_000);
        let f = fp(&[1]);
        d.check(f, 0, 64, 100);
        assert_eq!(d.check(f, 5, 63, 100), Verdict::Dup(DupInfo { ttl_rel: 1, id_same: true }));
        let mut d = Dedup::new(1024, 10_000);
        d.check(f, 0, 64, 100);
        assert_eq!(d.check(f, 5, 50, 101), Verdict::Dup(DupInfo { ttl_rel: 2, id_same: false }));
    }

    #[test]
    fn slot_collision_overwrites_and_misses_the_twin() {
        // Two different fingerprints mapping to the same slot: the second
        // overwrites the first, so the first's twin is (wrongly) counted new.
        // This is the documented miss; the test pins the behaviour.
        let mut d = Dedup::new(16, 10_000);
        let f1 = 0x1000_0000_0000_0003u64;
        let f2 = 0x2000_0000_0000_0003u64;
        assert_eq!(f1 as usize & 15, f2 as usize & 15);
        d.check(f1, 0, 1, 1);
        d.check(f2, 1, 1, 1);
        assert_eq!(d.check(f1, 2, 1, 1), Verdict::New);
    }

    #[test]
    fn time_counter_wraparound_is_safe() {
        let mut d = Dedup::new(1024, 10_000);
        let f = fp(&[3]);
        let t0 = T_MASK - 4; // 40-bit wrap happens 5 us later
        d.check(f, t0, 1, 1);
        assert!(matches!(d.check(f, t0 + 9, 1, 1), Verdict::Dup(_)));
    }

    #[test]
    fn slightly_out_of_order_timestamps_still_match() {
        let mut d = Dedup::new(1024, 10_000);
        let f = fp(&[4]);
        d.check(f, 1_000_000, 1, 1);
        // second copy stamped 40 us *earlier* than the first (seen in the sample CSVs)
        assert!(matches!(d.check(f, 1_000_000 - 40, 1, 1), Verdict::Dup(_)));
    }

    #[test]
    fn empty_payload_and_zero_fingerprint_are_safe() {
        let mut d = Dedup::new(16, 10_000);
        let f = fingerprint(0, Addr(0), Addr(0), 0, 0, 8, &[]);
        assert_ne!(f, 0);
        assert_eq!(d.check(f, 0, 0, 0), Verdict::New);
    }

    #[test]
    fn shared_table_catches_a_twin_received_on_another_thread() {
        // The failure seen on campus: copy A on one core, copy B on another.
        let d = std::sync::Arc::new(SharedDedup::new(16_384, 10_000, 16));
        let f = fp(&[5, 9, 9, 9]);
        let d1 = d.clone();
        let first = std::thread::spawn(move || d1.check(f, 1_000, 64, 9)).join().unwrap();
        let d2 = d.clone();
        let second = std::thread::spawn(move || d2.check(f, 1_011, 64, 9)).join().unwrap();
        assert_eq!(first, Verdict::New);
        assert_eq!(second, Verdict::Dup(DupInfo { ttl_rel: 0, id_same: true }));
    }

    #[test]
    fn shared_table_keeps_distinct_packets_distinct_and_spreads_over_stripes() {
        let d = SharedDedup::new(16_384, 10_000, 16);
        assert_eq!(d.stripes(), 16);
        let mut seen = std::collections::HashSet::new();
        for i in 0..2000u16 {
            let f = fp(&i.to_le_bytes());
            seen.insert(((f >> 56) as usize) & 15);
            assert_eq!(d.check(f, i as u64 * 100, 64, i), Verdict::New, "packet {i} is unique");
        }
        assert_eq!(seen.len(), 16, "all stripes used");
        // every one of them is now a duplicate if it comes again within the window
        let f = fp(&1999u16.to_le_bytes());
        assert!(matches!(d.check(f, 1999 * 100 + 11, 64, 1999), Verdict::Dup(_)));
    }

    #[test]
    fn shared_table_concurrent_twins_exactly_one_wins() {
        // Two threads present the same packet at the same moment (a barrier
        // per packet keeps them in step, so no unrelated packet can overwrite
        // the slot in between): exactly one must see New, the other Dup.
        let d = std::sync::Arc::new(SharedDedup::new(65_536, 10_000, 16));
        let bar = std::sync::Arc::new(std::sync::Barrier::new(2));
        let n = 20_000u32;
        let run = |d: std::sync::Arc<SharedDedup>, bar: std::sync::Arc<std::sync::Barrier>| {
            std::thread::spawn(move || {
                let mut new = 0u32;
                for i in 0..n {
                    let f = fingerprint(3, a(1), a(2), 5000, 8801, 16, &i.to_le_bytes());
                    bar.wait();
                    if d.check(f, i as u64 * 50, 64, i as u16) == Verdict::New {
                        new += 1;
                    }
                }
                new
            })
        };
        let (t1, t2) = (run(d.clone(), bar.clone()), run(d.clone(), bar.clone()));
        let total = t1.join().unwrap() + t2.join().unwrap();
        assert_eq!(total, n, "every distinct packet admitted exactly once");
    }
}
