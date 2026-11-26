//! Per-core aggregation shard.
//!
//! One [`Shard`] per capture core. The capture core locks only its own shard
//! (an uncontended mutex), so nothing is shared across cores on the packet
//! path. The sweeper thread takes the same lock briefly, in small chunks, to
//! close quiet bins and evict idle streams.
//!
//! Bounded by construction:
//! * `max_streams` caps the stream table. The slab and the index are
//!   allocated once at start, so the packet path never rehashes or grows.
//!   When the cap is hit new streams are **rejected and counted**
//!   (`streams_rejected`), existing ones keep working.
//! * a closed bin leaves through `try_send`; a full channel is counted
//!   (`bins_dropped`), never waited on.
//! * streams idle for `idle_us` are evicted by the sweeper.
//!
//! This shard is the VOLUME path: packets and UDP payload bytes per stream per
//! 5 s bin for everything that is not a qualified RTP media stream (RTCP, type 21,
//! other types, no-SFU payloads, media-type packets that did not qualify, and since p7b
//! the type-13 probe / control packets (media byte 7 != 0x1e), which are never offered to
//! the hub and are counted as `t13_probe` / `t13_ctrl`).
//! Qualified media and all per-stream metrics (loss, FPS, jitter, stalls) are in
//! `metrics::RtpHub`, which is shared by the cores (see the reason there).

use crate::dedup::fold;
use crate::health::CoreCounters;
use crate::model::{BinMetrics, ExportMsg};
use crate::net::Addr;
use crossbeam_channel::{Sender, TrySendError};
use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};

// ---------------------------------------------------------------- hashing

/// Small, fast, seeded hasher for the stream table (SipHash costs ~20 ns on
/// a 40-byte key; this costs a few ns). The seed is random per process so
/// remote traffic cannot be crafted to collide in the table.
#[derive(Clone, Copy)]
pub struct FastBuild(pub u64);

pub struct FastHasher(u64);

impl BuildHasher for FastBuild {
    type Hasher = FastHasher;
    fn build_hasher(&self) -> FastHasher {
        FastHasher(self.0)
    }
}

const HK: u64 = 0x9e37_79b9_7f4a_7c15;

impl Hasher for FastHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for c in bytes.chunks(8) {
            let mut b = [0u8; 8];
            b[..c.len()].copy_from_slice(c);
            self.0 = fold(self.0 ^ u64::from_le_bytes(b), HK);
        }
    }
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.0 = fold(self.0 ^ i as u64, HK);
    }
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.0 = fold(self.0 ^ i as u64, HK);
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.0 = fold(self.0 ^ i as u64, HK);
    }
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.0 = fold(self.0 ^ i, HK);
    }
    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.0 = fold(self.0 ^ i as u64, HK ^ (i >> 64) as u64);
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.0 = fold(self.0 ^ i as u64, HK);
    }
}

// ----------------------------------------------------------------- streams

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct StreamKey {
    pub client: Addr,
    pub server: Addr,
    pub client_port: u16,
    pub server_port: u16,
    /// `model::Acct` index
    pub acct: u8,
    pub dir: u8,
}

struct Stream {
    key: StreamKey,
    live: bool,
    bin_id: u64,
    pkts: u32,
    bytes: u64,
    first_us: u64,
    last_us: u64,
    last_seen_us: u64,
}

impl Stream {
    fn empty() -> Stream {
        Stream {
            key: StreamKey { client: Addr(0), server: Addr(0), client_port: 0, server_port: 0, acct: 0, dir: 0 },
            live: false,
            bin_id: 0,
            pkts: 0,
            bytes: 0,
            first_us: 0,
            last_us: 0,
            last_seen_us: 0,
        }
    }
}

pub struct ShardCfg {
    pub max_streams: usize,
    pub bin_us: u64,
    pub idle_us: u64,
    pub hash_seed: u64,
}

pub struct Shard {
    index: HashMap<StreamKey, u32, FastBuild>,
    slab: Vec<Stream>,
    free: Vec<u32>,
    max_streams: usize,
    bin_us: u64,
    idle_us: u64,
    cursor: usize,
    tx: Sender<ExportMsg>,
}

impl Shard {
    pub fn new(cfg: ShardCfg, tx: Sender<ExportMsg>) -> Shard {
        let cap = cfg.max_streams.max(1);
        Shard {
            index: HashMap::with_capacity_and_hasher(cap, FastBuild(cfg.hash_seed)),
            slab: Vec::with_capacity(cap),
            free: Vec::new(),
            max_streams: cap,
            bin_us: cfg.bin_us.max(1),
            idle_us: cfg.idle_us,
            cursor: 0,
            tx,
        }
    }

    pub fn streams_active(&self) -> usize {
        self.index.len()
    }

    /// Approximate memory held by the stream table (for sizing).
    pub fn approx_bytes(&self) -> usize {
        self.max_streams * (std::mem::size_of::<Stream>() + 48)
    }

    /// Account one packet. Returns false if the stream table was full and the
    /// packet was shed (counted in `streams_rejected`).
    #[inline]
    pub fn add(&mut self, key: StreamKey, t_us: u64, payload_len: u64, c: &CoreCounters) -> bool {
        let bin = t_us / self.bin_us;
        let idx = match self.index.get(&key) {
            Some(&i) => i as usize,
            None => {
                if self.index.len() >= self.max_streams {
                    CoreCounters::bump(&c.streams_rejected);
                    return false;
                }
                let i = match self.free.pop() {
                    Some(i) => i as usize,
                    None => {
                        self.slab.push(Stream::empty());
                        self.slab.len() - 1
                    }
                };
                let Some(s) = self.slab.get_mut(i) else {
                    return false;
                };
                *s = Stream::empty();
                s.key = key;
                s.live = true;
                s.bin_id = bin;
                self.index.insert(key, i as u32);
                i
            }
        };
        let Some(s) = self.slab.get_mut(idx) else {
            return false;
        };
        if bin > s.bin_id {
            Self::emit(&self.tx, s, c);
            s.bin_id = bin;
        }
        // A packet older than the open bin (timestamp taken before the lock,
        // or the sweeper advanced the bin) is clamped into the open bin.
        if s.pkts == 0 {
            s.first_us = t_us;
        }
        s.pkts = s.pkts.saturating_add(1);
        s.bytes = s.bytes.saturating_add(payload_len);
        s.last_us = t_us;
        s.last_seen_us = t_us;
        true
    }

    #[inline]
    fn emit(tx: &Sender<ExportMsg>, s: &mut Stream, c: &CoreCounters) {
        if s.pkts == 0 {
            return;
        }
        let m = BinMetrics {
            client: s.key.client,
            bin_id: s.bin_id,
            acct: s.key.acct,
            dir: s.key.dir,
            client_port: s.key.client_port,
            server_port: s.key.server_port,
            pkts: s.pkts,
            bytes: s.bytes,
            first_us: s.first_us,
            last_us: s.last_us,
        };
        s.pkts = 0;
        s.bytes = 0;
        match tx.try_send(ExportMsg::Bin(m)) {
            Ok(()) => CoreCounters::add(&c.bins_emitted),
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => CoreCounters::add(&c.bins_dropped),
        }
    }

    /// Sweep up to `n` slab entries starting at the cursor. Closes bins that
    /// ended before `now_us` and evicts streams idle for `idle_us`. Returns
    /// true when the cursor wrapped (one full pass finished).
    pub fn sweep_chunk(&mut self, n: usize, now_us: u64, c: &CoreCounters) -> bool {
        let now_bin = now_us / self.bin_us;
        let len = self.slab.len();
        if len == 0 {
            self.cursor = 0;
            return true;
        }
        let end = self.cursor.saturating_add(n).min(len);
        for i in self.cursor..end {
            let Some(s) = self.slab.get_mut(i) else { continue };
            if !s.live {
                continue;
            }
            if s.pkts > 0 && s.bin_id < now_bin {
                Self::emit(&self.tx, s, c);
            }
            if s.pkts == 0 && now_us.saturating_sub(s.last_seen_us) > self.idle_us {
                self.index.remove(&s.key);
                s.live = false;
                self.free.push(i as u32);
                CoreCounters::add(&c.streams_evicted);
            }
        }
        self.cursor = end;
        if self.cursor >= len {
            self.cursor = 0;
            true
        } else {
            false
        }
    }

    /// Emit every open bin (shutdown).
    pub fn flush_all(&mut self, c: &CoreCounters) {
        for s in self.slab.iter_mut() {
            if s.live {
                Self::emit(&self.tx, s, c);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::{bounded, Receiver};

    const BIN: u64 = 5_000_000;

    fn key(n: u8, acct: u8) -> StreamKey {
        StreamKey {
            client: Addr::from_v4([10, 0, 0, n]),
            server: Addr::from_v4([170, 114, 0, 1]),
            client_port: 5000 + n as u16,
            server_port: 8801,
            acct,
            dir: 1,
        }
    }

    fn shard(max: usize, chan: usize) -> (Shard, Receiver<ExportMsg>, CoreCounters) {
        let (tx, rx) = bounded(chan);
        let s = Shard::new(ShardCfg { max_streams: max, bin_us: BIN, idle_us: 60_000_000, hash_seed: 1 }, tx);
        (s, rx, CoreCounters::default())
    }

    fn drain(rx: &Receiver<ExportMsg>) -> Vec<BinMetrics> {
        rx.try_iter()
            .filter_map(|m| match m {
                ExportMsg::Bin(b) => Some(b),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_bin_closes_when_a_packet_from_the_next_bin_arrives() {
        let (mut s, rx, c) = shard(16, 16);
        for i in 0..10 {
            assert!(s.add(key(1, 0), i * 100_000, 1000, &c));
        }
        assert!(drain(&rx).is_empty());
        s.add(key(1, 0), BIN + 1, 500, &c);
        let b = drain(&rx);
        assert_eq!(b.len(), 1);
        assert_eq!((b[0].pkts, b[0].bytes, b[0].bin_id), (10, 10_000, 0));
        assert_eq!((b[0].first_us, b[0].last_us), (0, 900_000));
    }

    #[test]
    fn sweeper_closes_a_quiet_bin_and_evicts_the_idle_stream() {
        let (mut s, rx, c) = shard(16, 16);
        s.add(key(1, 0), 1_000_000, 100, &c);
        // not yet: still in the open bin
        s.sweep_chunk(100, 4_000_000, &c);
        assert!(drain(&rx).is_empty());
        s.sweep_chunk(100, 6_000_000, &c);
        assert_eq!(drain(&rx).len(), 1);
        assert_eq!(s.streams_active(), 1, "emitted but not yet idle long enough to evict");
        s.sweep_chunk(100, 1_000_000 + 61_000_000, &c);
        assert_eq!(s.streams_active(), 0);
        assert_eq!(CoreCounters::get(&c.streams_evicted), 1);
        // slot is reused
        s.add(key(2, 1), 70_000_000, 100, &c);
        assert_eq!(s.slab.len(), 1);
    }

    #[test]
    fn stream_cap_rejects_and_counts_but_existing_streams_keep_working() {
        let (mut s, _rx, c) = shard(3, 16);
        for n in 0..3 {
            assert!(s.add(key(n, 0), 0, 1, &c));
        }
        assert!(!s.add(key(9, 0), 0, 1, &c));
        assert!(!s.add(key(10, 0), 0, 1, &c));
        assert_eq!(CoreCounters::get(&c.streams_rejected), 2);
        assert!(s.add(key(1, 0), 10, 1, &c), "existing stream still accepted");
        assert_eq!(s.streams_active(), 3);
    }

    #[test]
    fn full_export_channel_sheds_bins_and_counts_without_blocking() {
        let (mut s, rx, c) = shard(16, 2);
        for bin in 0..10u64 {
            s.add(key(1, 0), bin * BIN, 1, &c);
        }
        // 9 closed bins tried, 2 fit
        assert_eq!(CoreCounters::get(&c.bins_emitted), 2);
        assert_eq!(CoreCounters::get(&c.bins_dropped), 7);
        assert_eq!(drain(&rx).len(), 2);
    }

    #[test]
    fn packet_older_than_open_bin_is_clamped_not_lost_or_panicking() {
        let (mut s, rx, c) = shard(16, 16);
        s.add(key(1, 0), 2 * BIN + 5, 100, &c);
        assert!(s.add(key(1, 0), BIN, 100, &c)); // older bin
        s.flush_all(&c);
        let b = drain(&rx);
        assert_eq!(b.len(), 1);
        assert_eq!((b[0].pkts, b[0].bin_id), (2, 2));
    }

    #[test]
    fn chunked_sweep_covers_everything_and_wraps() {
        let (mut s, rx, c) = shard(64, 64);
        for n in 0..40u8 {
            s.add(key(n, 0), 0, 1, &c);
        }
        let mut chunks = 0;
        while !s.sweep_chunk(7, 10 * BIN, &c) {
            chunks += 1;
            assert!(chunks < 100);
        }
        assert_eq!(drain(&rx).len(), 40);
        assert_eq!(chunks, 5); // 40 entries / 7 = 6 calls, the last one wraps
    }

    #[test]
    fn sweep_with_an_enormous_chunk_does_not_overflow() {
        let (mut s, rx, c) = shard(16, 16);
        s.add(key(1, 0), 0, 1, &c);
        s.add(key(2, 0), 0, 1, &c);
        s.sweep_chunk(1, 10 * BIN, &c); // moves the cursor off zero
        assert!(s.sweep_chunk(usize::MAX, 10 * BIN, &c));
        assert_eq!(drain(&rx).len(), 2);
    }

    #[test]
    fn disconnected_exporter_is_counted_not_a_panic() {
        let (mut s, rx, c) = shard(16, 4);
        drop(rx);
        s.add(key(1, 0), 0, 1, &c);
        s.add(key(1, 0), BIN, 1, &c);
        assert_eq!(CoreCounters::get(&c.bins_dropped), 1);
    }
}
