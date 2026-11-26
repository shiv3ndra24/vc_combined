//! Health counters.
//!
//! One [`CoreCounters`] per capture core, on its own cache lines. Most
//! counters have a **single writer** (the core's own thread), so they are
//! bumped with a relaxed load + store (a plain `mov`, no `lock` prefix, about
//! 1 ns) instead of a read-modify-write. Counters that more than one thread
//! can touch (the sweeper also emits and evicts) use `fetch_add`.
//!
//! Everything that is dropped, rejected, evicted or recovered is counted
//! here and exported as `capture_health`, so a gap on a dashboard can be
//! told apart from a quiet network.

use crate::headers::{RTP_SLOTS, VIDEO_LAYOUT_SLOTS};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

#[derive(Default)]
#[repr(align(128))]
pub struct CoreCounters {
    // ---- single writer: the owning capture core ----
    pub pkts_in: AtomicU64,
    pub parse_fail: AtomicU64,
    pub port_filtered: AtomicU64,
    pub ip_filtered: AtomicU64,
    pub zoom_like_unlisted: AtomicU64,
    pub dups_dropped: AtomicU64,
    pub dup_ttl_same: AtomicU64,
    pub dup_ttl_off1: AtomicU64,
    pub dup_ttl_other: AtomicU64,
    pub dup_id_same: AtomicU64,
    pub matched: AtomicU64,
    pub matched_bytes: AtomicU64,
    pub no_sfu: AtomicU64,
    pub streams_rejected: AtomicU64,
    pub dump_dropped: AtomicU64,
    /// RTP self-check per type slot (single writer: the owning core)
    pub rtp_ok: [AtomicU64; RTP_SLOTS],
    pub rtp_bad: [AtomicU64; RTP_SLOTS],
    pub rtp_short: AtomicU64,
    /// type-16 packets per media byte-20 layout: [0x02, 0x0a, rtp20, other] (p7a, rtp20 slot p7b; single writer: the owning core)
    pub video_layout: [AtomicU64; VIDEO_LAYOUT_SLOTS],
    /// p7b: bit `b - 0x80` set once a video packet with byte 20 == `b` in 0x80..=0xBF was seen (single writer)
    pub video_rtp20_mask: AtomicU64,
    /// pcap offers that were not queued (single writer: the owning core)
    pub pcap_drop_pool: AtomicU64,
    pub pcap_drop_queue: AtomicU64,
    pub pcap_drop_limit: AtomicU64,
    // ---- multi writer: core and sweeper ----
    pub streams_evicted: AtomicU64,
    pub bins_dropped: AtomicU64,
    pub bins_emitted: AtomicU64,
    pub poison_recovered: AtomicU64,
}

impl CoreCounters {
    /// single-writer increment
    #[inline(always)]
    pub fn bump(c: &AtomicU64) {
        c.store(c.load(Relaxed).wrapping_add(1), Relaxed);
    }
    /// single-writer add
    #[inline(always)]
    pub fn bump_by(c: &AtomicU64, n: u64) {
        c.store(c.load(Relaxed).wrapping_add(n), Relaxed);
    }
    /// single-writer "set this bit" (used for `video_rtp20_mask`): same cost as `bump`
    #[inline(always)]
    pub fn set_bit(c: &AtomicU64, bit: u32) {
        c.store(c.load(Relaxed) | (1u64 << bit), Relaxed);
    }
    /// multi-writer increment
    #[inline(always)]
    pub fn add(c: &AtomicU64) {
        c.fetch_add(1, Relaxed);
    }
    #[inline(always)]
    pub fn get(c: &AtomicU64) -> u64 {
        c.load(Relaxed)
    }
}
