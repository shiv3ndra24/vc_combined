//! # dedup.rs: duplicate filter for the mirror's second copies (`--dedup fp|off`)
//!
//! **Why it exists.** The campus mirror carries each wireless-client packet twice
//! (CAPWAP tunnel leg + wired leg), so without this filter every packet would be counted
//! twice in throughput, packet counts and loss. It drops the second copy before the packet
//! reaches the CSV, the pcap or the session metrics. It runs in the single records thread,
//! after the RX cores have merged into one channel, so it is global across cores.
//!
//! **Temporary by design.** Once the network team stops the double mirroring, run with
//! `--dedup off`, or build without the `dedup` cargo feature (vc_capture/Cargo.toml,
//! `default = []`): `DEDUP_COMPILED` is then false and every branch below is dead code.
//!
//! | `--dedup` | Two packets are "the same" when ...                                       | Only possible error                    |
//! |-----------|----------------------------------------------------------------------------|----------------------------------------|
//! | `fp`      | same 5-tuple + UDP length + first 48 payload bytes, less than 10 ms apart  | a twin that is missed (slot collision) |
//! | `off`     | never                                                                      | twins are counted twice                |
//!
//! The `seq` rule (per-SSRC sequence window) was removed in vc_combined: it swallowed
//! genuine packets for minutes on real Meet runs (213 s of downlink video on 10.184.4.232,
//! run 195835). The same A/B is still possible offline:
//! `tools/dedup_swallow_report.py PCAP --rule seq` on a `--dedup off` capture.
//!
//! ### `fp` in detail
//! * **Fingerprint** (`fingerprint()`): a 64-bit hash of source and destination address
//!   (raw bytes, 4 or 16 each), both ports, the UDP length and the first 48 bytes of the UDP
//!   payload (never more than the UDP length says, so Ethernet padding cannot make a twin
//!   look different). No MAC addresses: the two legs have different layer-2 wrappers.
//! * **Table**: 16 384 slots of 16 bytes, direct-mapped (`index = bits 32..46`); a collision
//!   overwrites (counted in `evicted_live`, the upper bound of missed twins).
//! * **Window**: same fingerprint less than 10 ms (`FP_WINDOW_US`) after the stored copy = twin.
//! * **Clock**: capture time in microseconds, 40 bits, compared the shorter way round.
//! * **Retransmissions** (same bytes, about 100 ms or more later) are kept.
//! * **Different flows are different packets** (the SFU forwarding one packet to two clients).

use std::sync::atomic::{AtomicBool, Ordering};

/// False when built without the `dedup` feature.
pub const DEDUP_COMPILED: bool = cfg!(feature = "dedup");

/// `--dedup fp|off`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DedupMode {
    /// Fingerprint (5-tuple + UDP length + first 48 payload bytes) inside a 10 ms window.
    Fp,
    /// Keep everything, twins included.
    Off,
}

impl DedupMode {
    pub fn as_str(self) -> &'static str {
        match self {
            DedupMode::Fp => "fp",
            DedupMode::Off => "off",
        }
    }
}

/// What `check` found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Not seen before: keep it.
    New,
    /// A twin copy.
    Duplicate,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Fingerprint
// ─────────────────────────────────────────────────────────────────────────────

static FP_WANTED: AtomicBool = AtomicBool::new(false);

/// Called once at start-up: only `--dedup fp` needs the fingerprint, so with `off`
/// the capture cores skip the hashing.
pub fn want_fingerprints(on: bool) {
    FP_WANTED.store(on, Ordering::Relaxed);
}

/// True when `parse_rtp_record` must fill `RtpRecord::fp`.
#[inline(always)]
pub fn fingerprints_wanted() -> bool {
    FP_WANTED.load(Ordering::Relaxed)
}

/// Number of UDP payload bytes that go into the fingerprint.
pub const FP_BYTES: usize = 48;
/// Slots in the `fp` table (power of two). 16 384 x 16 B = 256 KB.
pub const FP_SLOTS: usize = 16_384;
/// `fp` window: a packet with the same fingerprint closer than this is a twin.
pub const FP_WINDOW_US: u64 = 10_000;

const SEED: u64 = 0x243F_6A88_85A3_08D3;
const K0: u64 = 0xA076_1D64_78BD_642F;
const K1: u64 = 0xE703_7ED1_A0B4_28DB;
const K2: u64 = 0x8EBC_6AF0_9C88_C6E3;

/// 64x64 -> 128-bit multiply, xor of the two halves (the wyhash mixing step).
#[inline(always)]
fn fold(a: u64, b: u64) -> u64 {
    let r = (a as u128).wrapping_mul(b as u128);
    (r as u64) ^ ((r >> 64) as u64)
}

/// Up to 8 bytes as a little-endian number, zero-padded.
#[inline(always)]
fn load8(chunk: &[u8]) -> u64 {
    let mut x = 0u64;
    for (i, &b) in chunk.iter().enumerate().take(8) {
        x |= (b as u64) << (8 * i);
    }
    x
}

/// 64-bit fingerprint of one UDP packet. Never 0 (0 marks an empty slot).
///
/// * `addrs`: source address bytes followed by destination address bytes
///   (4 + 4 for IPv4, 16 + 16 for IPv6; the length is part of the hash, so an
///   IPv4 and an IPv6 packet cannot share a fingerprint by accident)
/// * `payload`: the UDP payload, already cut to the UDP length; only the first
///   `FP_BYTES` are used
///
/// `tools/dedup_swallow_report.py` has the same function in Python;
/// `tests::golden_vector` pins both to the same number.
pub fn fingerprint(addrs: &[u8], sport: u16, dport: u16, udp_len: u16, payload: &[u8]) -> u64 {
    let payload = &payload[..payload.len().min(FP_BYTES)];
    let head = ((sport as u64) << 48)
        | ((dport as u64) << 32)
        | ((udp_len as u64) << 16)
        | ((addrs.len() as u64 & 0xFF) << 8)
        | (payload.len() as u64 & 0xFF);
    let mut h = fold(SEED ^ K0, head ^ K1);
    for c in addrs.chunks(8) {
        h = fold(h ^ load8(c), K2);
    }
    for c in payload.chunks(8) {
        h = fold(h ^ load8(c), K1);
    }
    h = fold(h ^ K2, K0);
    h | 1
}

// ─────────────────────────────────────────────────────────────────────────────
//  fp table
// ─────────────────────────────────────────────────────────────────────────────

const T_MASK: u64 = (1u64 << 40) - 1;

/// Distance between two 40-bit microsecond stamps, the shorter way round.
/// A stamp a few microseconds EARLIER than the stored one gives a small age too.
#[inline(always)]
fn age_us(now: u64, then: u64) -> u64 {
    let d = now.wrapping_sub(then) & T_MASK;
    if d > T_MASK / 2 { (T_MASK + 1) - d } else { d }
}

#[derive(Clone, Copy)]
struct Slot {
    fp: u64,   // 0 = empty
    t_us: u64, // capture time of the copy that filled the slot (40 bits used)
}

struct FpTable {
    slots: Vec<Slot>,
    mask: usize,
    window_us: u64,
    /// Overwrites of a slot that still held a DIFFERENT fingerprint younger than
    /// the window: a twin of that evicted packet would now be missed.
    evicted_live: u64,
}

impl FpTable {
    fn new(slots: usize, window_us: u64) -> Self {
        let n = slots.max(2).next_power_of_two();
        Self { slots: vec![Slot { fp: 0, t_us: 0 }; n], mask: n - 1, window_us, evicted_live: 0 }
    }

    /// Duplicate when the slot holds this fingerprint and it is younger than the
    /// window; otherwise the slot is overwritten and the packet is new.
    #[inline]
    fn check(&mut self, fp: u64, t_us: u64) -> Verdict {
        // The index uses bits 32.. so that the forced low bit of `fp` (never 0)
        // does not halve the number of usable slots.
        let i = ((fp >> 32) as usize) & self.mask;
        let s = &mut self.slots[i];
        let t = t_us & T_MASK;
        if s.fp == fp && age_us(t, s.t_us) < self.window_us {
            return Verdict::Duplicate;
        }
        if s.fp != 0 && s.fp != fp && age_us(t, s.t_us) < self.window_us {
            self.evicted_live += 1;
        }
        *s = Slot { fp, t_us: t };
        Verdict::New
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Dedup
// ─────────────────────────────────────────────────────────────────────────────

pub struct Dedup {
    mode: DedupMode,
    table: Option<FpTable>,
    dropped: u64,
}

impl Dedup {
    pub fn new(mode: DedupMode) -> Self {
        Self::with_table(mode, FP_SLOTS, FP_WINDOW_US)
    }

    /// Same, with an explicit table size and window (tests). Without the `dedup`
    /// feature the mode is forced to `off`.
    pub fn with_table(mode: DedupMode, slots: usize, window_us: u64) -> Self {
        let mode = if DEDUP_COMPILED { mode } else { DedupMode::Off };
        let table = if mode == DedupMode::Fp { Some(FpTable::new(slots, window_us)) } else { None };
        Self { mode, table, dropped: 0 }
    }

    pub fn mode(&self) -> DedupMode {
        self.mode
    }

    /// Packets this filter has dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// `fp` only. Times a slot still holding a younger, different fingerprint was
    /// overwritten; each can cause one missed twin, so this bounds the twins left.
    pub fn evicted_live(&self) -> u64 {
        self.table.as_ref().map_or(0, |t| t.evicted_live)
    }

    /// Classify one packet: `fp` = `fingerprint()` of it, `t_us` = capture time in
    /// microseconds since the epoch. With `off` it always answers `New`.
    #[inline]
    pub fn check(&mut self, fp: u64, t_us: u64) -> Verdict {
        let Some(t) = self.table.as_mut() else { return Verdict::New };
        let v = t.check(fp, t_us);
        if v == Verdict::Duplicate {
            self.dropped += 1;
        }
        v
    }
}

#[cfg(all(test, feature = "dedup"))]
mod tests {
    use super::*;

    /// xorshift64*: deterministic, no dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545F4914F6CDD1D)
        }
    }

    const A: [u8; 8] = [10, 184, 4, 232, 142, 250, 82, 219]; // src + dst, IPv4

    fn payload(seq: u16, ts: u32, ssrc: u32, tail: u8) -> Vec<u8> {
        // 12-byte RTP header + 60 bytes of "encrypted" payload that depend on seq
        let mut p = vec![0x80, 96];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&ts.to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        for i in 0..60u8 {
            p.push(i.wrapping_mul(31).wrapping_add(seq as u8).wrapping_add(tail));
        }
        p
    }

    fn fpk(p: &[u8]) -> u64 {
        fingerprint(&A, 60158, 19305, (p.len() + 8) as u16, p)
    }

    #[test]
    fn fp_a_twin_microseconds_later_is_a_duplicate_and_a_third_copy_too() {
        let mut d = Dedup::new(DedupMode::Fp);
        let p = payload(100, 5000, 0x77, 0);
        let f = fpk(&p);
        assert_eq!(d.check(f, 1_000_000), Verdict::New);
        assert_eq!(d.check(f, 1_000_011), Verdict::Duplicate); // median twin gap, 11 us
        assert_eq!(d.check(f, 1_009_000), Verdict::Duplicate); // 9 ms: the rare slow twin
        assert_eq!(d.dropped(), 2);
    }

    #[test]
    fn fp_the_window_edge_is_exactly_10_ms() {
        let mut d = Dedup::new(DedupMode::Fp);
        let f = fpk(&payload(1, 1, 1, 0));
        assert_eq!(d.check(f, 5_000_000), Verdict::New);
        assert_eq!(d.check(f, 5_009_999), Verdict::Duplicate); // 9 999 us
        // the slot still holds the FIRST copy's time, so 10 000 us is out of the window
        assert_eq!(d.check(f, 5_010_000), Verdict::New);
    }

    #[test]
    fn fp_a_retransmission_100_ms_later_is_kept() {
        let mut d = Dedup::new(DedupMode::Fp);
        let f = fpk(&payload(7, 70, 9, 0));
        assert_eq!(d.check(f, 2_000_000), Verdict::New);
        assert_eq!(d.check(f, 2_100_000), Verdict::New); // genuine resend
        assert_eq!(d.dropped(), 0);
    }

    #[test]
    fn fp_a_twin_stamped_earlier_still_matches_and_the_clock_wraps() {
        let mut d = Dedup::new(DedupMode::Fp);
        let f = fpk(&payload(3, 3, 3, 0));
        // second copy carries a stamp 40 us EARLIER than the stored one
        assert_eq!(d.check(f, 9_000_000), Verdict::New);
        assert_eq!(d.check(f, 9_000_000 - 40), Verdict::Duplicate);
        // 40-bit wrap: stored just below 2^40, twin just after zero
        let mut d = Dedup::new(DedupMode::Fp);
        let near_wrap = (1u64 << 40) - 5;
        assert_eq!(d.check(f, near_wrap), Verdict::New);
        assert_eq!(d.check(f, (1u64 << 40) + 6), Verdict::Duplicate); // 11 us later, after the wrap
    }

    #[test]
    fn fp_the_same_bytes_to_another_destination_are_two_packets() {
        // The SFU forwards one packet to two campus clients: same payload, other flow.
        let p = payload(55, 550, 0xAA, 0);
        let to_a = fingerprint(&[10, 184, 4, 232, 142, 250, 82, 219], 19305, 60158, (p.len() + 8) as u16, &p);
        let to_b = fingerprint(&[10, 184, 15, 225, 142, 250, 82, 219], 19305, 39424, (p.len() + 8) as u16, &p);
        assert_ne!(to_a, to_b);
        let mut d = Dedup::new(DedupMode::Fp);
        assert_eq!(d.check(to_a, 1_000), Verdict::New);
        assert_eq!(d.check(to_b, 1_020), Verdict::New);
        assert_eq!(d.dropped(), 0);
    }

    #[test]
    fn fp_a_stream_restart_or_a_reused_ssrc_is_never_swallowed() {
        // The failure that cost 213 s on a real run: the same SSRC arrives 18 636
        // sequence numbers behind another flow's maximum. `seq` (removed in vc_combined)
        // dropped all of it; `fp` has no per-SSRC state.
        let mut fpd = Dedup::new(DedupMode::Fp);
        let (ssrc, up_start, down_start) = (0x77890EDC_u32, 30_000u16, 30_000u16.wrapping_sub(18_636));
        let mut t = 0u64;
        for i in 0..200u16 {
            // uplink flow (device A) sets the maximum
            let p = payload(up_start.wrapping_add(i), 90_000 + i as u32 * 3000, ssrc, 1);
            let f = fingerprint(&[10, 184, 15, 225, 142, 250, 82, 219], 39424, 19305, (p.len() + 8) as u16, &p);
            fpd.check(f, t);
            t += 11_000;
        }
        let mut kept_fp = 0;
        for i in 0..500u16 {
            // downlink flow (device B), other sequence space, same SSRC value
            let s = down_start.wrapping_add(i);
            let p = payload(s, 500_000 + i as u32 * 3000, ssrc, 2);
            let f = fingerprint(&[142, 250, 82, 219, 10, 184, 4, 232], 19305, 60158, (p.len() + 8) as u16, &p);
            if fpd.check(f, t) == Verdict::New { kept_fp += 1; }
            t += 11_000;
        }
        assert_eq!(kept_fp, 500, "fp keeps every packet of it");
    }

    #[test]
    fn fp_a_collision_is_counted_and_can_miss_one_twin() {
        // A two-slot table makes collisions certain; the counter must see the eviction.
        let mut d = Dedup::with_table(DedupMode::Fp, 2, FP_WINDOW_US);
        let mut rng = Rng(7);
        let mut misses = 0;
        let mut twins = 0;
        for i in 0..2000u64 {
            let f = rng.next() | 1;
            let t = i * 50;
            assert_eq!(d.check(f, t), Verdict::New);
            // other packet in between, then the twin
            let g = rng.next() | 1;
            d.check(g, t + 3);
            twins += 1;
            if d.check(f, t + 11) == Verdict::New { misses += 1; }
        }
        assert!(misses > 0 && misses <= twins);
        assert!(d.evicted_live() >= misses, "every miss is preceded by a live eviction");
    }

    #[test]
    fn fp_misses_almost_nothing_at_a_high_rate_with_the_full_table() {
        // 60 000 distinct packets at ~10 000 pkt/s (100 us apart); every twin arrives
        // 500 us after its original, i.e. with ~5 other packets in between. That is
        // 50 times the real median twin gap (11 us), a deliberately hard case.
        // Expected misses: ~5 / 16 384 per packet = 0.03 % -> about 18 of 60 000.
        let mut rng = Rng(99);
        let mut ev: Vec<(u64, u64, bool)> = Vec::new(); // (time, fingerprint, is_twin)
        for i in 0..60_000u64 {
            let f = rng.next() | 1;
            let t = 1_000_000 + i * 100;
            ev.push((t, f, false));
            ev.push((t + 500, f, true));
        }
        ev.sort_by_key(|e| (e.0, e.2));
        let mut d = Dedup::new(DedupMode::Fp);
        let (mut originals_kept, mut twins_left) = (0u32, 0u32);
        for (t, f, is_twin) in ev {
            let v = d.check(f, t);
            match (is_twin, v) {
                (false, Verdict::New) => originals_kept += 1,
                (true, Verdict::New) => twins_left += 1,
                _ => {}
            }
        }
        assert_eq!(originals_kept, 60_000, "an original is never dropped by fp");
        assert!(twins_left < 80, "expected ~18 missed twins, got {twins_left}");
        assert!(d.evicted_live() as u32 >= twins_left);
        assert_eq!(d.dropped() as u32, 60_000 - twins_left);
    }

    // ── fingerprint ────────────────────────────────────────────────────────

    #[test]
    fn fingerprint_is_never_zero_and_is_stable() {
        let p = payload(1, 1, 1, 0);
        let f = fpk(&p);
        assert_ne!(f, 0);
        assert_eq!(f, fpk(&p));
        assert_eq!(f & 1, 1);
    }

    #[test]
    fn fingerprint_sees_every_one_of_the_first_48_bytes_and_nothing_after() {
        let p = payload(10, 100, 5, 0);
        let base = fpk(&p);
        for i in 0..FP_BYTES {
            let mut q = p.clone();
            q[i] ^= 0x01;
            assert_ne!(fingerprint(&A, 60158, 19305, (q.len() + 8) as u16, &q), base, "byte {i} not covered");
        }
        // bytes 48.. are ignored (a retransmission differs there only if the sender re-encrypts)
        let mut q = p.clone();
        q[60] ^= 0xFF;
        assert_eq!(fingerprint(&A, 60158, 19305, (q.len() + 8) as u16, &q), base);
        // each field of the 5-tuple and the UDP length matters
        assert_ne!(fingerprint(&A, 60159, 19305, (p.len() + 8) as u16, &p), base);
        assert_ne!(fingerprint(&A, 60158, 19306, (p.len() + 8) as u16, &p), base);
        assert_ne!(fingerprint(&A, 60158, 19305, (p.len() + 9) as u16, &p), base);
        let mut a2 = A;
        a2[3] ^= 1;
        assert_ne!(fingerprint(&a2, 60158, 19305, (p.len() + 8) as u16, &p), base);
        // IPv4 and IPv6 of "the same" bytes cannot collide by construction
        let mut a6 = A.to_vec();
        a6.extend_from_slice(&[0u8; 24]);
        assert_ne!(fingerprint(&a6, 60158, 19305, (p.len() + 8) as u16, &p), base);
    }

    #[test]
    fn short_packets_use_what_they_have() {
        let p = [0x80u8, 111, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 9, 9, 9]; // 15 bytes
        let f = fingerprint(&A, 1, 2, 23, &p);
        assert_ne!(f, 0);
        assert_ne!(f, fingerprint(&A, 1, 2, 23, &p[..14]));
    }

    #[test]
    fn fingerprints_spread_over_every_slot() {
        // Through the real table: 100 000 distinct packets must occupy (nearly) all 16 384
        // slots. 6.1 packets per slot on average, so for a perfectly random index about 37
        // slots stay empty by chance (Poisson). If the index were taken from the low bits of
        // the forced-odd hash, 8 192 slots would stay empty.
        let mut t = FpTable::new(FP_SLOTS, FP_WINDOW_US);
        for i in 0..100_000u32 {
            let p = payload(i as u16, i.wrapping_mul(2654435761), i % 7, (i >> 16) as u8);
            let f = fingerprint(&A, 60158, 19305, (p.len() + 8) as u16, &p);
            t.check(f, i as u64 * 1_000_000); // 1 s apart: nothing is a duplicate
        }
        let empty = t.slots.iter().filter(|s| s.fp == 0).count();
        assert!(empty < 100, "empty slots: {empty} (random expectation ~37)");
    }

    /// Cost per packet. `cargo test --release -- --ignored --nocapture bench` (not run by default).
    #[test]
    #[ignore]
    fn bench_fingerprint_and_check() {
        use std::hint::black_box;
        use std::time::Instant;
        let p = payload(1, 1, 1, 0);
        let n = 5_000_000u64;
        let t = Instant::now();
        let mut acc = 0u64;
        for i in 0..n {
            acc ^= fingerprint(black_box(&A), 60158, 19305, (p.len() + 8) as u16, black_box(&p[..(48 + (i as usize & 1) * 0)]));
        }
        let fp_ns = t.elapsed().as_nanos() as f64 / n as f64;
        let mut rng = Rng(5);
        let mut d = Dedup::new(DedupMode::Fp);
        let t = Instant::now();
        for i in 0..n {
            acc ^= d.check(black_box(rng.next() | 1), i * 100) as u64;
        }
        let chk_ns = t.elapsed().as_nanos() as f64 / n as f64;
        println!("fingerprint {fp_ns:.1} ns, fp table check {chk_ns:.1} ns (incl. rng)  [{acc}]");
    }

    /// Pins the Rust and the Python (`tools/dedup_swallow_report.py`) fingerprint to
    /// the same number for one fixed packet. If you change `fingerprint()`, change
    /// both and this constant.
    #[test]
    fn golden_vector() {
        let payload: Vec<u8> = (0..60u8).collect();
        let f = fingerprint(&[10, 184, 4, 232, 142, 250, 82, 219], 60158, 19305, 68, &payload);
        assert_eq!(f, GOLDEN_FP, "got {f:#018x}");
    }
    /// Computed by the independent Python implementation in `tools/dedup_swallow_report.py`.
    const GOLDEN_FP: u64 = 0x2643_F320_FB7A_5EA3;

    #[test]
    fn off_never_drops() {
        let mut d = Dedup::new(DedupMode::Off);
        for i in 0..100 {
            assert_eq!(d.check(42, i), Verdict::New);
        }
        assert_eq!(d.dropped(), 0);
    }
}
