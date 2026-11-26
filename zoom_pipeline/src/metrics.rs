//! Stage 2: per-stream RTP metrics and the stream-qualification rule.
//!
//! ```text
//! packet (after de-dup, any capture core)
//!    -> RtpHub::on_packet   one stripe lock, picked by the CLIENT address
//!         |- SFU counter of the flow  -> capture_missing (SfuBin)
//!         `- RTP stream (client, dir, type, PT, SSRC)
//!              probation -> qualified -> RtpBin per 5 s bin
//!                       `-> failed    -> its bytes are counted as unq_* volume
//! ```
//!
//! ## Why this lives in a shared, striped hub and not in the per-core shard
//!
//! Loss, frame counting and jitter are sequential: they need every packet of a
//! stream in order. The campus link delivers the two copies of one packet (the
//! CAPWAP tunnel leg and the wired leg, try4 CONFIRMED) to different RX cores
//! (STAGE2_DESIGN section 7.4 and LOG Step 6), so a stream can
//! be split over cores whenever the surviving copy alternates. A per-core table
//! would then see two interleaved subsequences and invent loss. De-dup solved the
//! same problem with one shared table in stripes; this uses the same device, with
//! the stripe chosen by the client address so one lock covers the client's SFU
//! counters and all its streams.
//!
//! ## Qualification (STAGE2_DESIGN 9.1)
//!
//! A video / audio / screen packet counts as MEDIA only if it belongs to a stream
//! that behaves like RTP: version 2 on every packet, a stable (client, direction,
//! type, PT, SSRC), and sequence numbers that continue (at least 90 % of the
//! steps forward by 1..=100) over its first 20 packets. Nothing about the probe /
//! padding layout is assumed, so a changed layout cannot fool it. Until a stream
//! qualifies its counters are held (not exported); when it qualifies they are
//! released with the bin in which that happens. A stream that has not qualified
//! after 64 packets is `Failed`: its held bytes and all later ones are counted as
//! `unq_video` / `unq_audio` / `unq_screen`.
//!
//! ## Probation (flood guard)
//!
//! The qualification table is bounded, so a packet stream whose "SSRC" changes
//! every packet must not be able to fill it. The example that motivated the guard is the
//! Type-21 probe padding that travels in Type-13 envelopes (deck2 T13-3; LOG Step 8 first
//! saw it as an "unexplained type-13 family"). Since p7b the media-byte-7 gate keeps those
//! packets away from the hub altogether (they are counted as `t13_probe`), but the guard
//! stays: any RTP-shaped packet with a fresh SSRC each time would still need it. A key gets a table entry only when it is seen a second time within 5 s;
//! the first sighting is remembered in a small direct-mapped array (overwritten
//! freely, no growth). A real stream pays one packet (counted as `unq_*`); a
//! changing-SSRC probe never gets an entry.

use crate::agg::FastBuild;
use crate::dedup::fold;
use crate::model::{Acct, BinMetrics, ExportMsg, RtpBin, SfuBin, KIND_AUDIO, KIND_SCREEN, KIND_VIDEO};
use crate::net::Addr;
use crossbeam_channel::{Sender, TrySendError};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;

/// An inter-frame arrival gap above this is a stall (STAGE2_DESIGN section 1: 200 ms).
pub const STALL_US: u64 = 200_000;
/// Packets a stream needs before it can qualify (the validator's `STREAM_MIN_PKTS`).
pub const QUAL_MIN_PKTS: u32 = 20;
/// Packets after which a stream that still does not qualify is declared `Failed`.
pub const QUAL_GIVE_UP_PKTS: u32 = 64;
/// Share of sequence steps that must be forward by 1..=QUAL_MAX_STEP.
pub const QUAL_MIN_FWD: f64 = 0.9;
pub const QUAL_MAX_STEP: u16 = 100;
/// RTP: a forward jump larger than this resynchronises instead of counting loss
/// (thesis section 4.3.3 caps the loss of a jump at 1,000).
pub const RTP_JUMP_CAP: u16 = 1000;
/// SFU counter: steps up to this are skipped packets, wider ones are counter jumps
/// (the validator's `capture_summary` rule).
pub const SFU_JUMP_CAP: u16 = 100;
/// Late-arrival window of the reorder-aware loss rule (sequence numbers).
pub const LATE_WINDOW: u16 = 128;
/// RTP clock of video and screen share (deck: 89,998 to 90,006 Hz measured).
pub const VIDEO_TICKS_PER_MS: f64 = 90.0;
/// Frame timestamps that are closer than 1,500 or farther than 90,000 ticks apart are
/// not a camera cadence (thesis section 4.3.5: 60 FPS down to 1 FPS on a 90 kHz clock).
pub const MIN_FRAME_TICKS: u32 = 1_500;
pub const MAX_FRAME_TICKS: u32 = 90_000;
/// Packets in one second above which an audio second counts as "active" (STAGE2_DESIGN 9.3).
pub const AUDIO_ACTIVE_PKTS: u16 = 20;
/// Seconds per bin the audio activity array can hold.
pub const MAX_BIN_SECS: usize = 8;
/// Bins of distinct frame timestamps remembered to tell a reordered packet of an
/// older frame from a new frame.
const RING: usize = 8;

// ---------------------------------------------------------------- sequence tracker

/// What one sequence number did to a [`SeqTracker`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeqEvent {
    /// first packet of the stream
    First,
    /// newer than every earlier one; `missing` numbers were skipped
    Forward { missing: u32 },
    /// forward jump wider than the cap: resynchronised, nothing counted as lost
    Jump,
    /// arrived late and filled a gap that was counted: one loss is taken back
    LateFill,
    /// a number that was already received: a repeat that survived de-dup (retransmission)
    Repeat,
    /// older than the window: cannot be told from a repeat, ignored
    TooOld,
}

/// Reorder-aware sequence tracking, the thesis rule (section 4.3.3) made exact with a bitmap:
/// bit `i` of `bits` is set when `highest - i` has arrived. Sequence numbers
/// 100, 101, 103, 102, 104 give Forward(0), Forward(0), Forward(1), LateFill, Forward(0):
/// one gap counted at 103 and taken back at 102, net loss 0 (STAGE2_DESIGN section 2).
#[derive(Clone, Copy, Debug, Default)]
pub struct SeqTracker {
    started: bool,
    highest: u16,
    bits: u128,
}

impl SeqTracker {
    pub fn update(&mut self, seq: u16, jump_cap: u16) -> SeqEvent {
        if !self.started {
            self.started = true;
            self.highest = seq;
            self.bits = 1;
            return SeqEvent::First;
        }
        let d = seq.wrapping_sub(self.highest) as i16 as i32;
        if d > 0 {
            if d > jump_cap as i32 {
                self.highest = seq;
                self.bits = 1;
                return SeqEvent::Jump;
            }
            self.bits = if d >= 128 { 1 } else { (self.bits << d) | 1 };
            self.highest = seq;
            SeqEvent::Forward { missing: (d - 1) as u32 }
        } else if d == 0 {
            SeqEvent::Repeat
        } else {
            let off = (-d) as u32;
            if off >= LATE_WINDOW as u32 {
                return SeqEvent::TooOld;
            }
            let bit = 1u128 << off;
            if self.bits & bit != 0 {
                SeqEvent::Repeat
            } else {
                self.bits |= bit;
                SeqEvent::LateFill
            }
        }
    }
}

// ------------------------------------------------------------------- RTP stream

/// Identity of an RTP stream. SSRC alone is not one (the server assigns the same
/// downlink audio SSRC to different receivers), and PT 110 has its own sequence
/// numbers on the same SSRC; the type byte keeps type 13 and type 30 apart.
///
/// The video LAYOUT (media byte 20) is deliberately not part of the key: one SSRC can
/// switch layout and keep its sequence space (the 0x0a burst is the same SSRC before,
/// during and after), and a stream that changed key at a layout change would be cut in
/// two (a new probation, a lost frame gap). A second video SSRC in the same flow, like
/// the rtp20 / 0x90 stream deck2 saw on one campus client, is simply another key: p7b
/// treats it like any other video stream, so it counts in `video_streams_active` and in
/// the per-client means. TO BE CHECKED (C2, deliberately not done in p7b): whether such a
/// stream should be kept out of `fps_*`, `jitter_ms_*`, `frame_gap_std_ms_*` and
/// `degraded_*`. The evidence so far is one client in one afternoon and nobody knows what
/// the stream is (simulcast layer? thumbnail? another tile? GUESS); see
/// `zoom_capture/README.md`, "The aux / main question".
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RtpKey {
    pub client: Addr,
    pub ssrc: u32,
    pub dir: u8,
    pub pt: u8,
    pub type_byte: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QState {
    Probation,
    Qualified,
    Failed,
}

/// One RTP packet as the hub needs it.
#[derive(Clone, Copy, Debug)]
pub struct RtpInfo {
    pub kind: u8,
    pub type_byte: u8,
    pub pt: u8,
    pub ssrc: u32,
    pub seq: u16,
    pub rtp_ts: u32,
    /// UDP payload bytes (the thesis' throughput definition)
    pub len: u32,
}

#[derive(Clone, Copy)]
pub struct RtpStream {
    key: RtpKey,
    kind: u8,
    pub state: QState,
    // ---- qualification
    fed: u32,
    fwd_ok: u32,
    last_seq: u16,
    // ---- sequential state (survives bins)
    trk: SeqTracker,
    ring: [u32; RING],
    ring_n: u8,
    ring_pos: u8,
    cur_ts: u32,
    prev_ts: u32,
    have_cur: bool,
    have_prev: bool,
    cur_end_us: u64,
    last_end_us: u64,
    have_last_end: bool,
    jitter_ms: f64,
    last_seen_us: u64,
    // ---- accumulators of the open bin (held while on probation)
    bin_id: u64,
    pkts: u32,
    bytes: u64,
    first_us: u64,
    last_us: u64,
    frames: u32,
    rx: u32,
    lost: i32,
    retx: u32,
    gap_n: u32,
    gap_mean: f64,
    gap_m2: f64,
    stalls: u32,
    sec_pkts: [u16; MAX_BIN_SECS],
}

impl RtpStream {
    fn new(key: RtpKey, kind: u8, bin: u64, first_t: u64) -> RtpStream {
        RtpStream {
            key,
            kind,
            state: QState::Probation,
            fed: 0,
            fwd_ok: 0,
            last_seq: 0,
            trk: SeqTracker::default(),
            ring: [0; RING],
            ring_n: 0,
            ring_pos: 0,
            cur_ts: 0,
            prev_ts: 0,
            have_cur: false,
            have_prev: false,
            cur_end_us: 0,
            last_end_us: 0,
            have_last_end: false,
            jitter_ms: 0.0,
            last_seen_us: first_t,
            bin_id: bin,
            pkts: 0,
            bytes: 0,
            first_us: first_t,
            last_us: first_t,
            frames: 0,
            rx: 0,
            lost: 0,
            retx: 0,
            gap_n: 0,
            gap_mean: 0.0,
            gap_m2: 0.0,
            stalls: 0,
            sec_pkts: [0; MAX_BIN_SECS],
        }
    }

    fn reset_bin(&mut self) {
        self.pkts = 0;
        self.bytes = 0;
        self.frames = 0;
        self.rx = 0;
        self.lost = 0;
        self.retx = 0;
        self.gap_n = 0;
        self.gap_mean = 0.0;
        self.gap_m2 = 0.0;
        self.stalls = 0;
        self.sec_pkts = [0; MAX_BIN_SECS];
    }

    fn bin_record(&self) -> RtpBin {
        let active = if self.kind == KIND_AUDIO { self.sec_pkts.iter().filter(|&&n| n > AUDIO_ACTIVE_PKTS).count() as u8 } else { 0 };
        RtpBin {
            client: self.key.client,
            bin_id: self.bin_id,
            dir: self.key.dir,
            kind: self.kind,
            type_byte: self.key.type_byte,
            pt: self.key.pt,
            ssrc: self.key.ssrc,
            pkts: self.pkts,
            bytes: self.bytes,
            first_us: self.first_us,
            last_us: self.last_us,
            frames: self.frames,
            rx: self.rx,
            lost: self.lost,
            retx: self.retx,
            gap_n: self.gap_n,
            gap_mean_ms: self.gap_mean,
            gap_m2: self.gap_m2,
            stalls: self.stalls,
            jitter_ms: self.jitter_ms as f32,
            active_secs: active,
        }
    }

    /// Frame bookkeeping for a video / screen media packet (not FEC).
    fn frame_step(&mut self, ts: u32, t_us: u64) {
        let n = self.ring_n as usize;
        if self.have_cur && ts == self.cur_ts {
            self.cur_end_us = t_us;
            return;
        }
        if self.ring[..n].contains(&ts) {
            return; // a reordered packet of an older frame
        }
        // a new frame starts: the current one is complete
        if self.have_cur {
            if self.have_last_end {
                let gap_us = self.cur_end_us.saturating_sub(self.last_end_us);
                let dts = self.cur_ts.wrapping_sub(self.prev_ts);
                if self.kind == KIND_VIDEO && self.have_prev {
                    let fwd = (dts as i32) > 0;
                    if fwd && gap_us > STALL_US {
                        self.stalls += 1;
                    }
                    if (MIN_FRAME_TICKS..=MAX_FRAME_TICKS).contains(&dts) {
                        let gap_ms = gap_us as f64 / 1000.0;
                        self.gap_n += 1;
                        let delta = gap_ms - self.gap_mean;
                        self.gap_mean += delta / self.gap_n as f64;
                        self.gap_m2 += delta * (gap_ms - self.gap_mean);
                        let d = gap_ms - dts as f64 / VIDEO_TICKS_PER_MS;
                        self.jitter_ms += (d.abs() - self.jitter_ms) / 16.0;
                    }
                }
            }
            self.last_end_us = self.cur_end_us;
            self.have_last_end = true;
            self.prev_ts = self.cur_ts;
            self.have_prev = true;
        }
        self.cur_ts = ts;
        self.have_cur = true;
        self.cur_end_us = t_us;
        self.ring[self.ring_pos as usize] = ts;
        self.ring_pos = ((self.ring_pos as usize + 1) % RING) as u8;
        if (self.ring_n as usize) < RING {
            self.ring_n += 1;
        }
        self.frames += 1;
    }

    /// Account one packet. `bin_us` is the bin length. Emits the previous bin first
    /// when this packet starts a new one (only for qualified streams).
    fn feed(&mut self, p: &RtpInfo, t_us: u64, bin_us: u64, tx: &Sender<ExportMsg>, hc: &HubCounters) {
        let bin = t_us / bin_us;
        if bin > self.bin_id {
            if self.state == QState::Qualified {
                self.emit(tx, hc);
            }
            self.bin_id = bin;
        }
        // After a reset the bin's first packet is this one. A brand-new stream keeps the
        // time of the probation sighting it was created with (that packet is not in `pkts`).
        if self.pkts == 0 && self.fed > 0 {
            self.first_us = t_us;
        }
        self.pkts = self.pkts.saturating_add(1);
        self.bytes = self.bytes.saturating_add(p.len as u64);
        self.last_us = t_us;
        self.last_seen_us = t_us;
        let sec = (((t_us % bin_us) / 1_000_000) as usize).min(MAX_BIN_SECS - 1);
        self.sec_pkts[sec] = self.sec_pkts[sec].saturating_add(1);

        match self.trk.update(p.seq, RTP_JUMP_CAP) {
            SeqEvent::First | SeqEvent::Jump => self.rx += 1,
            SeqEvent::Forward { missing } => {
                self.rx += 1;
                self.lost += missing as i32;
            }
            SeqEvent::LateFill => {
                self.rx += 1;
                self.lost -= 1;
            }
            SeqEvent::Repeat => self.retx += 1,
            SeqEvent::TooOld => {}
        }
        if p.pt != FEC_PT && (self.kind == KIND_VIDEO || self.kind == KIND_SCREEN) {
            self.frame_step(p.rtp_ts, t_us);
        }
        // qualification
        if self.fed > 0 {
            let d = p.seq.wrapping_sub(self.last_seq);
            if (1..=QUAL_MAX_STEP).contains(&d) {
                self.fwd_ok += 1;
            }
        }
        self.last_seq = p.seq;
        self.fed += 1;
        if self.state == QState::Probation {
            if self.fed >= QUAL_MIN_PKTS && self.fwd_ok as f64 >= QUAL_MIN_FWD * (self.fed - 1) as f64 {
                self.state = QState::Qualified;
                hc.qualified.fetch_add(1, Relaxed);
            } else if self.fed >= QUAL_GIVE_UP_PKTS {
                self.state = QState::Failed;
                hc.failed_qual.fetch_add(1, Relaxed);
            }
        }
    }

    fn emit(&mut self, tx: &Sender<ExportMsg>, hc: &HubCounters) {
        if self.pkts == 0 {
            return;
        }
        let rec = self.bin_record();
        self.reset_bin();
        match tx.try_send(ExportMsg::Rtp(rec)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                hc.bins_dropped.fetch_add(1, Relaxed);
            }
        }
    }

    /// Volume held while the stream was not (or never became) qualified, as a
    /// level-1 bin of the matching `unq_*` category.
    fn flush_as_unqualified(&mut self, tx: &Sender<ExportMsg>, hc: &HubCounters) {
        if self.pkts == 0 {
            return;
        }
        let acct = match self.kind {
            KIND_VIDEO => Acct::UnqVideo,
            KIND_AUDIO => Acct::UnqAudio,
            _ => Acct::UnqScreen,
        };
        let m = BinMetrics {
            client: self.key.client,
            bin_id: self.bin_id,
            acct: acct as u8,
            dir: self.key.dir,
            client_port: 0,
            server_port: 0,
            pkts: self.pkts,
            bytes: self.bytes,
            first_us: self.first_us,
            last_us: self.last_us,
        };
        self.reset_bin();
        match tx.try_send(ExportMsg::Bin(m)) {
            Ok(()) => {}
            Err(_) => {
                hc.bins_dropped.fetch_add(1, Relaxed);
            }
        }
    }
}

/// Payload type of the FEC companion of video / screen streams (deck Table 3).
pub const FEC_PT: u8 = 110;

// ------------------------------------------------------------------- SFU counter

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SfuKey {
    pub client: Addr,
    pub client_port: u16,
    pub dir: u8,
}

/// The 8-byte SFU header carries a 16-bit counter that goes up by one per packet of
/// a flow, whatever the media type. Numbers that never show up are packets the
/// capture missed (uplink: the counter is the client's) or packets the server
/// skipped (downlink). STAGE2_DESIGN section 8.1 and 9.5.
#[derive(Clone, Copy)]
pub struct SfuFlow {
    key: SfuKey,
    trk: SeqTracker,
    bin_id: u64,
    seen: u32,
    missed: i32,
    last_seen_us: u64,
}

impl SfuFlow {
    fn new(key: SfuKey, bin: u64, t: u64) -> SfuFlow {
        SfuFlow { key, trk: SeqTracker::default(), bin_id: bin, seen: 0, missed: 0, last_seen_us: t }
    }
    fn emit(&mut self, tx: &Sender<ExportMsg>, hc: &HubCounters) {
        if self.seen == 0 && self.missed == 0 {
            return;
        }
        let rec = SfuBin { client: self.key.client, bin_id: self.bin_id, dir: self.key.dir, seen: self.seen, missed: self.missed };
        self.seen = 0;
        self.missed = 0;
        if tx.try_send(ExportMsg::Sfu(rec)).is_err() {
            hc.bins_dropped.fetch_add(1, Relaxed);
        }
    }
    fn feed(&mut self, seq: u16, t_us: u64, bin_us: u64, tx: &Sender<ExportMsg>, hc: &HubCounters) {
        let bin = t_us / bin_us;
        if bin > self.bin_id {
            self.emit(tx, hc);
            self.bin_id = bin;
        }
        self.last_seen_us = t_us;
        match self.trk.update(seq, SFU_JUMP_CAP) {
            SeqEvent::First | SeqEvent::Jump => self.seen += 1,
            SeqEvent::Forward { missing } => {
                self.seen += 1;
                self.missed += missing as i32;
            }
            SeqEvent::LateFill => {
                self.seen += 1;
                self.missed -= 1;
            }
            SeqEvent::Repeat | SeqEvent::TooOld => {}
        }
    }
}

// ------------------------------------------------------------------ bounded map

/// Hash index + slab with a hard cap. Allocated once; the packet path never rehashes.
struct BoundedMap<K, V> {
    index: HashMap<K, u32, FastBuild>,
    slab: Vec<Option<(K, V)>>,
    free: Vec<u32>,
    cap: usize,
}

impl<K: std::hash::Hash + Eq + Copy, V> BoundedMap<K, V> {
    fn new(cap: usize, seed: u64) -> Self {
        let cap = cap.max(1);
        BoundedMap { index: HashMap::with_capacity_and_hasher(cap, FastBuild(seed)), slab: Vec::with_capacity(cap), free: Vec::new(), cap }
    }
    fn len(&self) -> usize {
        self.index.len()
    }
    fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        let i = *self.index.get(k)? as usize;
        self.slab.get_mut(i)?.as_mut().map(|e| &mut e.1)
    }
    /// `None` when the map is full.
    fn insert(&mut self, k: K, v: V) -> Option<&mut V> {
        if self.index.len() >= self.cap {
            return None;
        }
        let i = match self.free.pop() {
            Some(i) => {
                self.slab[i as usize] = Some((k, v));
                i as usize
            }
            None => {
                self.slab.push(Some((k, v)));
                self.slab.len() - 1
            }
        };
        self.index.insert(k, i as u32);
        self.slab[i].as_mut().map(|e| &mut e.1)
    }
    fn remove_at(&mut self, i: usize) {
        if let Some((k, _)) = self.slab.get_mut(i).and_then(|e| e.take()) {
            self.index.remove(&k);
            self.free.push(i as u32);
        }
    }
}

// --------------------------------------------------------------------- the hub

#[derive(Default)]
pub struct HubCounters {
    pub qualified: AtomicU64,
    pub failed_qual: AtomicU64,
    pub probation_skipped: AtomicU64,
    pub streams_rejected: AtomicU64,
    pub bins_dropped: AtomicU64,
    pub evicted: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct HubCfg {
    /// lock stripes (picked by client address)
    pub stripes: usize,
    /// total RTP streams (and, separately, SFU flows) across stripes; each stripe may hold up to twice its share
    pub max_streams: usize,
    pub bin_us: u64,
    pub idle_us: u64,
    /// probation slots per stripe (16 B each)
    pub probation_slots: usize,
    pub seed: u64,
}

impl Default for HubCfg {
    fn default() -> Self {
        HubCfg { stripes: 64, max_streams: 65_536, bin_us: 5_000_000, idle_us: 60_000_000, probation_slots: 1024, seed: 0x1234_5678_9abc_def1 }
    }
}

/// What the hub did with a packet's RTP header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtpOutcome {
    /// no RTP header was offered
    NotRtp,
    /// stream is qualified: the packet is counted in the stream
    Counted,
    /// stream is on probation: the packet is held in the stream and will be released
    /// when it qualifies or flushed as `unq_*` when it fails or goes idle
    Held,
    /// not a media stream (probation sighting, failed stream, or table full): the caller must count the packet as `unq_*`
    Unqualified,
}

/// One packet for the hub (a client's media or SFU-counter packet).
#[derive(Clone, Copy, Debug)]
pub struct HubPkt {
    pub client: Addr,
    pub client_port: u16,
    pub dir: u8,
    pub t_us: u64,
    pub sfu_seq: Option<u16>,
    pub rtp: Option<RtpInfo>,
}

#[repr(align(128))]
struct Padded<T>(T);

struct Stripe {
    rtp: BoundedMap<RtpKey, RtpStream>,
    sfu: BoundedMap<SfuKey, SfuFlow>,
    /// (key hash, time of first sighting); hash 0 = empty
    prob: Vec<(u64, u64)>,
    cursor: usize,
}

pub struct RtpHub {
    cfg: HubCfg,
    stripes: Vec<Padded<Mutex<Stripe>>>,
    tx: Sender<ExportMsg>,
    pub ctr: HubCounters,
}

/// A probation sighting stays valid for this long.
const PROBATION_TTL_US: u64 = 5_000_000;

impl RtpHub {
    pub fn new(cfg: HubCfg, tx: Sender<ExportMsg>) -> RtpHub {
        let n = cfg.stripes.max(1);
        let per = ((cfg.max_streams / n) * 2).max(256);
        let stripes = (0..n)
            .map(|i| {
                let seed = cfg.seed ^ (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
                Padded(Mutex::new(Stripe {
                    rtp: BoundedMap::new(per, seed),
                    sfu: BoundedMap::new(per, seed ^ 1),
                    prob: vec![(0, 0); cfg.probation_slots.max(16)],
                    cursor: 0,
                }))
            })
            .collect();
        RtpHub { cfg, stripes, tx, ctr: HubCounters::default() }
    }

    #[inline]
    fn stripe_of(&self, client: Addr) -> usize {
        let h = fold((client.0 as u64) ^ self.cfg.seed, ((client.0 >> 64) as u64) ^ 0xa076_1d64_78bd_642f);
        (h % self.stripes.len() as u64) as usize
    }

    #[inline]
    fn key_hash(&self, k: &RtpKey) -> u64 {
        let h = fold((k.client.0 as u64) ^ self.cfg.seed, ((k.client.0 >> 64) as u64) ^ 0xe703_7ed1_a0b4_28db);
        let v = ((k.ssrc as u64) << 24) | ((k.dir as u64) << 16) | ((k.pt as u64) << 8) | k.type_byte as u64;
        fold(h ^ v, 0x8ebc_6af0_9c88_c6e3) | 1
    }

    fn lock(&self, i: usize) -> std::sync::MutexGuard<'_, Stripe> {
        match self.stripes[i].0.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// The packet path. One lock (the client's stripe), no allocation.
    pub fn on_packet(&self, p: &HubPkt) -> RtpOutcome {
        let bin_us = self.cfg.bin_us;
        let mut g = self.lock(self.stripe_of(p.client));
        let g: &mut Stripe = &mut g;
        if let Some(seq) = p.sfu_seq {
            let key = SfuKey { client: p.client, client_port: p.client_port, dir: p.dir };
            if g.sfu.get_mut(&key).is_none() {
                let _ = g.sfu.insert(key, SfuFlow::new(key, p.t_us / bin_us, p.t_us));
            }
            if let Some(f) = g.sfu.get_mut(&key) {
                f.feed(seq, p.t_us, bin_us, &self.tx, &self.ctr);
            }
        }
        let Some(r) = p.rtp else { return RtpOutcome::NotRtp };
        let key = RtpKey { client: p.client, ssrc: r.ssrc, dir: p.dir, pt: r.pt, type_byte: r.type_byte };
        if let Some(s) = g.rtp.get_mut(&key) {
            return self.feed_stream(s, &r, p.t_us);
        }
        // unknown stream: probation
        let h = self.key_hash(&key);
        let slot = (h % g.prob.len() as u64) as usize;
        let (sh, st) = g.prob[slot];
        if sh == h && p.t_us.saturating_sub(st) <= PROBATION_TTL_US {
            g.prob[slot] = (0, 0);
            let s = RtpStream::new(key, r.kind, p.t_us / bin_us, st);
            return match g.rtp.insert(key, s) {
                Some(s) => self.feed_stream(s, &r, p.t_us),
                None => {
                    self.ctr.streams_rejected.fetch_add(1, Relaxed);
                    RtpOutcome::Unqualified
                }
            };
        }
        g.prob[slot] = (h, p.t_us);
        self.ctr.probation_skipped.fetch_add(1, Relaxed);
        RtpOutcome::Unqualified
    }

    #[inline]
    fn feed_stream(&self, s: &mut RtpStream, r: &RtpInfo, t_us: u64) -> RtpOutcome {
        if s.state == QState::Failed {
            s.last_seen_us = t_us;
            return RtpOutcome::Unqualified;
        }
        s.feed(r, t_us, self.cfg.bin_us, &self.tx, &self.ctr);
        match s.state {
            QState::Qualified => RtpOutcome::Counted,
            QState::Probation => RtpOutcome::Held,
            QState::Failed => {
                // just failed: everything held, this packet included, becomes unq_* volume
                s.flush_as_unqualified(&self.tx, &self.ctr);
                RtpOutcome::Held
            }
        }
    }

    pub fn streams_active(&self) -> (usize, usize) {
        let (mut a, mut b) = (0, 0);
        for i in 0..self.stripes.len() {
            let g = self.lock(i);
            a += g.rtp.len();
            b += g.sfu.len();
        }
        (a, b)
    }

    /// Close quiet bins and evict idle entries, `chunk` slab entries per lock hold.
    pub fn sweep_once(&self, now_us: u64, chunk: usize) {
        for i in 0..self.stripes.len() {
            loop {
                let wrapped = self.lock(i).sweep_chunk(chunk, now_us, &self.cfg, &self.tx, &self.ctr);
                if wrapped {
                    break;
                }
                std::thread::yield_now();
            }
        }
    }

    /// Release everything (shutdown).
    pub fn flush_all(&self) {
        for i in 0..self.stripes.len() {
            let mut g = self.lock(i);
            for e in g.rtp.slab.iter_mut().flatten() {
                let s = &mut e.1;
                if s.state == QState::Qualified {
                    s.emit(&self.tx, &self.ctr);
                } else {
                    s.flush_as_unqualified(&self.tx, &self.ctr);
                }
            }
            for e in g.sfu.slab.iter_mut().flatten() {
                e.1.emit(&self.tx, &self.ctr);
            }
        }
    }
}

impl Stripe {
    fn sweep_chunk(&mut self, n: usize, now_us: u64, cfg: &HubCfg, tx: &Sender<ExportMsg>, hc: &HubCounters) -> bool {
        let now_bin = now_us / cfg.bin_us;
        let nr = self.rtp.slab.len();
        let total = nr + self.sfu.slab.len();
        if total == 0 {
            self.cursor = 0;
            return true;
        }
        let end = self.cursor.saturating_add(n).min(total);
        for i in self.cursor..end {
            if i < nr {
                let mut evict = false;
                if let Some((_, s)) = self.rtp.slab[i].as_mut() {
                    if s.state == QState::Qualified && s.pkts > 0 && s.bin_id < now_bin {
                        s.emit(tx, hc);
                    }
                    if now_us.saturating_sub(s.last_seen_us) > cfg.idle_us {
                        if s.state != QState::Qualified {
                            s.flush_as_unqualified(tx, hc);
                        } else {
                            s.emit(tx, hc);
                        }
                        evict = true;
                    }
                }
                if evict {
                    self.rtp.remove_at(i);
                    hc.evicted.fetch_add(1, Relaxed);
                }
            } else {
                let j = i - nr;
                let mut evict = false;
                if let Some((_, f)) = self.sfu.slab[j].as_mut() {
                    if (f.seen != 0 || f.missed != 0) && f.bin_id < now_bin {
                        f.emit(tx, hc);
                    }
                    if now_us.saturating_sub(f.last_seen_us) > cfg.idle_us {
                        f.emit(tx, hc);
                        evict = true;
                    }
                }
                if evict {
                    self.sfu.remove_at(j);
                }
            }
        }
        self.cursor = end;
        if self.cursor >= total {
            self.cursor = 0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::{unbounded, Receiver};

    const BIN: u64 = 5_000_000;

    // ---------------------------------------------------------------- helpers

    struct H {
        hub: RtpHub,
        rx: Receiver<ExportMsg>,
    }

    fn hub() -> H {
        let (tx, rx) = unbounded();
        H { hub: RtpHub::new(HubCfg { stripes: 4, max_streams: 1024, ..Default::default() }, tx), rx }
    }

    fn client(n: u8) -> Addr {
        Addr::from_v4([10, 0, 0, n])
    }

    fn video(ssrc: u32, seq: u16, ts: u32, len: u32) -> RtpInfo {
        RtpInfo { kind: KIND_VIDEO, type_byte: 16, pt: 98, ssrc, seq, rtp_ts: ts, len }
    }

    fn pkt(c: u8, dir: u8, t_us: u64, r: RtpInfo) -> HubPkt {
        HubPkt { client: client(c), client_port: 40_000, dir, t_us, sfu_seq: None, rtp: Some(r) }
    }

    impl H {
        fn send(&self, c: u8, dir: u8, t_us: u64, r: RtpInfo) -> RtpOutcome {
            self.hub.on_packet(&pkt(c, dir, t_us, r))
        }
        /// everything the hub has emitted so far
        fn drain(&self) -> (Vec<RtpBin>, Vec<BinMetrics>, Vec<SfuBin>) {
            let (mut r, mut b, mut s) = (vec![], vec![], vec![]);
            for m in self.rx.try_iter() {
                match m {
                    ExportMsg::Rtp(x) => r.push(x),
                    ExportMsg::Bin(x) => b.push(x),
                    ExportMsg::Sfu(x) => s.push(x),
                    _ => {}
                }
            }
            (r, b, s)
        }
        /// Scenario tests are about frame / loss / jitter arithmetic, not about qualification
        /// (tested on its own): mark every stream in the table as qualified.
        fn qualify_all(&self) {
            for i in 0..self.hub.stripes.len() {
                let mut g = self.hub.lock(i);
                for e in g.rtp.slab.iter_mut().flatten() {
                    e.1.state = QState::Qualified;
                }
            }
        }
        /// the first packet of any stream is only a probation sighting; send one so the next ones count
        fn prime(&self, c: u8, dir: u8, t_us: u64, r: RtpInfo) {
            assert_eq!(self.send(c, dir, t_us, r), RtpOutcome::Unqualified);
        }
    }

    // ------------------------------------------------------------ SeqTracker

    #[test]
    fn reordered_packets_are_a_gap_that_is_taken_back() {
        // the thesis example: 100, 101, 103, 102, 104 -> one gap counted at 103, taken back at 102, net 0
        let mut t = SeqTracker::default();
        let ev: Vec<SeqEvent> = [100u16, 101, 103, 102, 104].iter().map(|&s| t.update(s, RTP_JUMP_CAP)).collect();
        assert_eq!(
            ev,
            vec![SeqEvent::First, SeqEvent::Forward { missing: 0 }, SeqEvent::Forward { missing: 1 }, SeqEvent::LateFill, SeqEvent::Forward { missing: 0 }]
        );
        // and a number that never arrives stays lost
        let mut t = SeqTracker::default();
        assert_eq!(t.update(10, 1000), SeqEvent::First);
        assert_eq!(t.update(13, 1000), SeqEvent::Forward { missing: 2 });
        assert_eq!(t.update(12, 1000), SeqEvent::LateFill); // 11 is still missing
        assert_eq!(t.update(14, 1000), SeqEvent::Forward { missing: 0 });
    }

    #[test]
    fn sequence_numbers_wrap_around_without_a_false_loss() {
        let mut t = SeqTracker::default();
        assert_eq!(t.update(65_534, 1000), SeqEvent::First);
        assert_eq!(t.update(65_535, 1000), SeqEvent::Forward { missing: 0 });
        assert_eq!(t.update(0, 1000), SeqEvent::Forward { missing: 0 });
        assert_eq!(t.update(1, 1000), SeqEvent::Forward { missing: 0 });
        // a late packet from just before the wrap is still found in the window
        assert_eq!(t.update(3, 1000), SeqEvent::Forward { missing: 1 });
        assert_eq!(t.update(2, 1000), SeqEvent::LateFill);
        assert_eq!(t.update(65_535, 1000), SeqEvent::Repeat);
    }

    #[test]
    fn repeat_too_old_and_jump_are_told_apart() {
        let mut t = SeqTracker::default();
        t.update(1000, 1000);
        t.update(1001, 1000);
        assert_eq!(t.update(1001, 1000), SeqEvent::Repeat, "same number twice = retransmission that survived de-dup");
        assert_eq!(t.update(1000, 1000), SeqEvent::Repeat);
        // 128 or more behind the highest: outside the bitmap, ignored
        t.update(1300, 1000);
        assert_eq!(t.update(1001, 1000), SeqEvent::TooOld);
        // a forward step above the cap re-synchronises and counts nothing as lost
        assert_eq!(t.update(1300 + 1001, 1000), SeqEvent::Jump);
        assert_eq!(t.update(1300 + 1002, 1000), SeqEvent::Forward { missing: 0 });
        // exactly at the cap is still counted
        let mut t = SeqTracker::default();
        t.update(5, 1000);
        assert_eq!(t.update(5 + 1000, 1000), SeqEvent::Forward { missing: 999 });
        // the SFU counter uses a tighter cap
        let mut t = SeqTracker::default();
        t.update(5, SFU_JUMP_CAP);
        assert_eq!(t.update(5 + 101, SFU_JUMP_CAP), SeqEvent::Jump);
    }

    // --------------------------------------------------------- qualification

    #[test]
    fn a_real_stream_qualifies_with_its_20th_counted_packet() {
        let h = hub();
        let mut out = vec![];
        for i in 0..40u32 {
            out.push(h.send(1, 0, 1_000_000 + i as u64 * 33_000, video(0xAA, 500 + i as u16, i * 3000, 1000)));
        }
        // sighting 1: probation (counted by the caller as unq_video); 2..20 held; the 21st sighting is the 20th fed packet
        assert_eq!(out[0], RtpOutcome::Unqualified);
        assert!(out[1..20].iter().all(|o| *o == RtpOutcome::Held), "{out:?}");
        assert!(out[20..].iter().all(|o| *o == RtpOutcome::Counted), "{out:?}");
        assert_eq!(h.hub.ctr.qualified.load(Relaxed), 1);
        assert_eq!(h.hub.streams_active().0, 1);
        // the 19 held packets are released together with the qualifying one: 39 packets, 39,000 bytes
        h.hub.flush_all();
        let (rtp, bins, _) = h.drain();
        assert!(bins.is_empty(), "nothing unqualified: {bins:?}");
        assert_eq!(rtp.len(), 1);
        assert_eq!((rtp[0].pkts, rtp[0].bytes, rtp[0].frames, rtp[0].rx, rtp[0].lost), (39, 39_000, 39, 39, 0));
        // the stream started at its first sighting, which is when media was first observed
        assert_eq!(rtp[0].first_us, 1_000_000);
    }

    #[test]
    fn a_probe_with_a_new_ssrc_in_every_packet_never_gets_a_table_entry() {
        let h = hub();
        for i in 0..10_000u32 {
            let r = RtpInfo { kind: KIND_SCREEN, type_byte: 13, pt: 99, ssrc: 0x4000_0000 + i, seq: i as u16, rtp_ts: 0, len: 1051 };
            assert_eq!(h.send(1, 0, 1_000_000 + i as u64 * 100, r), RtpOutcome::Unqualified);
        }
        assert_eq!(h.hub.streams_active().0, 0, "the qualification table must not grow with probe packets");
        assert_eq!(h.hub.ctr.probation_skipped.load(Relaxed), 10_000);
        assert_eq!(h.hub.ctr.streams_rejected.load(Relaxed), 0);
        h.hub.flush_all();
        let (rtp, bins, _) = h.drain();
        assert!(rtp.is_empty() && bins.is_empty());
    }

    #[test]
    fn a_stream_that_never_looks_like_rtp_fails_after_64_packets_and_becomes_unq_volume() {
        let h = hub();
        let mut out = vec![];
        for i in 0..100u32 {
            // sequence numbers jump by 7,919: same SSRC and PT, but not RTP-like
            let r = RtpInfo { kind: KIND_SCREEN, type_byte: 13, pt: 99, ssrc: 0x77, seq: (i * 7919) as u16, rtp_ts: 0, len: 1000 };
            out.push(h.send(1, 1, 2_000_000 + i as u64 * 1000, r));
        }
        assert_eq!(out[0], RtpOutcome::Unqualified);
        assert!(out[1..64].iter().all(|o| *o == RtpOutcome::Held));
        assert_eq!(out[64], RtpOutcome::Held, "the packet that tips it over is part of the flushed volume");
        assert!(out[65..].iter().all(|o| *o == RtpOutcome::Unqualified), "afterwards the caller counts them");
        assert_eq!(h.hub.ctr.failed_qual.load(Relaxed), 1);
        assert_eq!(h.hub.ctr.qualified.load(Relaxed), 0);
        let (rtp, bins, _) = h.drain();
        assert!(rtp.is_empty(), "a failed stream must never appear as media");
        assert_eq!(bins.len(), 1);
        assert_eq!((bins[0].acct, bins[0].dir, bins[0].pkts, bins[0].bytes), (Acct::UnqScreen as u8, 1, 64, 64_000));
    }

    #[test]
    fn an_idle_stream_still_on_probation_is_flushed_as_unq_not_lost() {
        let h = hub();
        h.prime(1, 0, 1_000_000, video(9, 1, 0, 800));
        for i in 0..4u32 {
            assert_eq!(h.send(1, 0, 1_010_000 + i as u64 * 20_000, video(9, 2 + i as u16, i * 3000, 800)), RtpOutcome::Held);
        }
        h.hub.sweep_once(1_100_000 + 61_000_000, 1000);
        let (rtp, bins, _) = h.drain();
        assert!(rtp.is_empty());
        assert_eq!(bins.len(), 1);
        assert_eq!((bins[0].acct, bins[0].pkts, bins[0].bytes), (Acct::UnqVideo as u8, 4, 3200));
        assert_eq!(h.hub.streams_active().0, 0, "and the entry is gone");
    }

    // ------------------------------------------------------- frame metrics

    #[test]
    fn jitter_follows_the_rfc3550_rule_at_frame_level() {
        // frames 3000 ticks (33.33 ms) apart in RTP time but 41 ms apart on arrival:
        // D = 41 - 33.33 = 7.667 ms, J = D / 16 = 0.479 ms. The gap of frames 1->2 is only known
        // when frame 3 starts, so three frames are needed.
        let h = hub();
        h.prime(1, 0, 900_000, video(5, 99, 0, 1000));
        h.send(1, 0, 1_000_000, video(5, 100, 0, 1000));
        h.qualify_all();
        h.send(1, 0, 1_041_000, video(5, 101, 3000, 1000));
        h.send(1, 0, 1_075_000, video(5, 102, 6000, 1000));
        h.hub.flush_all();
        let (rtp, _, _) = h.drain();
        assert_eq!(rtp[0].frames, 3);
        assert_eq!(rtp[0].gap_n, 1);
        assert!((rtp[0].jitter_ms as f64 - (41.0 - 3000.0 / 90.0) / 16.0).abs() < 1e-4, "{}", rtp[0].jitter_ms);
        assert!((rtp[0].gap_mean_ms - 41.0).abs() < 1e-9);
    }

    #[test]
    fn a_stall_is_a_frame_gap_over_200_ms_and_feeds_the_gap_statistics() {
        let h = hub();
        h.prime(1, 0, 1_900_000, video(5, 1, 0, 1000));
        let frames = [(2_000_000u64, 0u32), (2_033_000, 3000), (2_066_000, 6000), (2_400_000, 36_000), (2_433_000, 39_000)];
        for (i, (t, ts)) in frames.iter().enumerate() {
            h.send(1, 0, *t, video(5, 2 + i as u16, *ts, 1000));
            h.qualify_all();
        }
        h.hub.flush_all();
        let (rtp, _, _) = h.drain();
        let r = rtp[0];
        assert_eq!(r.frames, 5);
        assert_eq!(r.stalls, 1, "the 334 ms gap");
        assert_eq!(r.gap_n, 3);
        let xs = [33.0f64, 33.0, 334.0];
        let mean = xs.iter().sum::<f64>() / 3.0;
        let m2: f64 = xs.iter().map(|x| (x - mean).powi(2)).sum();
        assert!((r.gap_mean_ms - mean).abs() < 1e-9);
        assert!((r.gap_m2 - m2).abs() < 1e-6, "{} vs {m2}", r.gap_m2);
        // sigma (population) as the exporter derives it
        assert!(((r.gap_m2 / r.gap_n as f64).sqrt() - (m2 / 3.0).sqrt()).abs() < 1e-9);
    }

    #[test]
    fn a_reordered_packet_neither_starts_a_frame_nor_leaves_a_loss() {
        let h = hub();
        h.prime(1, 0, 900_000, video(5, 99, 0, 1000));
        h.send(1, 0, 1_000_000, video(5, 100, 0, 1000)); // frame A
        h.qualify_all();
        h.send(1, 0, 1_033_000, video(5, 102, 3000, 1000)); // frame B, 101 is late
        h.send(1, 0, 1_034_000, video(5, 101, 0, 1000)); // 101 belongs to frame A
        h.hub.flush_all();
        let (rtp, _, _) = h.drain();
        assert_eq!(rtp[0].frames, 2, "the late packet of frame A is not a third frame");
        assert_eq!(rtp[0].lost, 0, "gap at 102 was taken back when 101 arrived");
        assert_eq!(rtp[0].rx, 3);
    }

    #[test]
    fn a_repeated_sequence_number_is_a_retransmission_not_extra_goodput() {
        let h = hub();
        h.prime(1, 0, 900_000, video(5, 99, 0, 1000));
        h.send(1, 0, 1_000_000, video(5, 100, 0, 1000));
        h.qualify_all();
        h.send(1, 0, 1_033_000, video(5, 101, 3000, 1000));
        h.send(1, 0, 1_040_000, video(5, 101, 3000, 1000));
        h.hub.flush_all();
        let (rtp, _, _) = h.drain();
        assert_eq!((rtp[0].rx, rtp[0].retx, rtp[0].pkts), (2, 1, 3));
    }

    #[test]
    fn screen_share_counts_frames_but_not_camera_cadence_statistics() {
        let h = hub();
        let s = |seq: u16, ts: u32| RtpInfo { kind: KIND_SCREEN, type_byte: 30, pt: 99, ssrc: 0x30, seq, rtp_ts: ts, len: 900 };
        h.prime(1, 1, 900_000, s(0, 0));
        // 1 frame per 400 ms: would be a stall for a camera, is normal for a slide
        for i in 0..6u32 {
            h.send(1, 1, 1_000_000 + i as u64 * 400_000, s(1 + i as u16, i * 36_000));
            h.qualify_all();
        }
        h.hub.flush_all();
        let (rtp, _, _) = h.drain();
        assert_eq!((rtp[0].kind, rtp[0].type_byte), (KIND_SCREEN, 30));
        assert_eq!(rtp[0].frames, 6);
        assert_eq!((rtp[0].stalls, rtp[0].gap_n), (0, 0));
    }

    #[test]
    fn fec_packets_are_volume_of_their_own_stream_and_never_frames() {
        let h = hub();
        for i in 0..30u32 {
            let r = RtpInfo { kind: KIND_VIDEO, type_byte: 16, pt: FEC_PT, ssrc: 0x99, seq: 7000 + i as u16, rtp_ts: i * 3000, len: 1200 };
            h.send(1, 0, 1_000_000 + i as u64 * 33_000, r);
        }
        h.hub.flush_all();
        let (rtp, _, _) = h.drain();
        assert_eq!(rtp.len(), 1);
        assert_eq!((rtp[0].pt, rtp[0].frames, rtp[0].gap_n), (FEC_PT, 0, 0));
        assert_eq!(rtp[0].pkts, 29);
    }

    #[test]
    fn audio_seconds_are_active_above_20_packets() {
        let h = hub();
        let a = |seq: u16| RtpInfo { kind: KIND_AUDIO, type_byte: 15, pt: 113, ssrc: 0xA0, seq, rtp_ts: seq as u32 * 960, len: 100 };
        // 50 pps for 3 s, then 10 pps (comfort noise) for 1 s, all inside bin 0
        let mut t = 0u64;
        let mut seq = 0u16;
        for _ in 0..150 {
            h.send(1, 0, t, a(seq));
            seq += 1;
            t += 20_000;
        }
        for _ in 0..10 {
            h.send(1, 0, t, a(seq));
            seq += 1;
            t += 100_000;
        }
        h.hub.flush_all();
        let (rtp, _, _) = h.drain();
        assert_eq!(rtp[0].active_secs, 3);
        assert_eq!(rtp[0].frames, 0, "audio has no frames");
    }

    // ----------------------------------------------------- bins and sweeping

    #[test]
    fn a_stream_is_cut_into_bins_but_its_state_runs_across_them() {
        let h = hub();
        let mut sent = 0u32;
        let mut lost_in_gen = 0;
        for i in 0..360u32 {
            let t = i as u64 * 33_333; // 12 s at 30 fps
            if i == 200 {
                lost_in_gen += 1; // packet never reaches the capture
                continue;
            }
            let o = h.send(1, 0, t, video(0xB, i as u16, i * 3000, 1000));
            if o != RtpOutcome::Unqualified {
                sent += 1;
            }
        }
        h.hub.flush_all();
        let (rtp, bins, _) = h.drain();
        assert!(bins.is_empty());
        let ids: Vec<u64> = rtp.iter().map(|r| r.bin_id).collect();
        assert_eq!(ids, vec![0, 1, 2], "{ids:?}");
        for r in &rtp {
            assert!(r.first_us / BIN == r.bin_id && r.last_us / BIN == r.bin_id, "{r:?}");
        }
        assert_eq!(rtp.iter().map(|r| r.pkts).sum::<u32>(), sent, "every counted packet is in exactly one bin");
        assert_eq!(rtp.iter().map(|r| r.lost).sum::<i32>(), lost_in_gen, "one packet lost, reported once, in the bin where the next one arrived");
        assert_eq!(rtp.iter().map(|r| r.frames).sum::<u32>(), sent, "one packet per frame; no frame counted twice at a bin edge");
    }

    #[test]
    fn sweeping_closes_quiet_bins_and_then_evicts_the_idle_stream() {
        let h = hub();
        h.prime(1, 0, 1_000_000, video(7, 0, 0, 500));
        for i in 1..40u32 {
            h.send(1, 0, 1_000_000 + i as u64 * 33_000, video(7, i as u16, i * 3000, 500));
        }
        let before = h.drain().0.len();
        assert_eq!(before, 0, "bin 0 is still open");
        h.hub.sweep_once(2 * BIN + 1, 1000);
        let (rtp, _, _) = h.drain();
        assert_eq!(rtp.len(), 1, "the bin was closed by the sweeper although no later packet arrived");
        assert_eq!(rtp[0].pkts, 39);
        assert_eq!(h.hub.streams_active().0, 1, "not idle yet");
        h.hub.sweep_once(2_400_000 + 61_000_000, 1000);
        assert_eq!(h.hub.streams_active().0, 0);
        assert_eq!(h.hub.ctr.evicted.load(Relaxed), 1);
        assert!(h.drain().0.is_empty(), "nothing is emitted twice");
    }

    #[test]
    fn same_ssrc_in_another_direction_type_or_client_is_another_stream() {
        let h = hub();
        for i in 0..2u16 {
            h.send(1, 0, 1_000_000 + i as u64, video(5, i, 0, 100));
            h.send(1, 1, 1_000_000 + i as u64, video(5, i, 0, 100)); // downlink
            h.send(2, 0, 1_000_000 + i as u64, video(5, i, 0, 100)); // other client
            let s13 = RtpInfo { kind: KIND_SCREEN, type_byte: 13, pt: 99, ssrc: 5, seq: i, rtp_ts: 0, len: 100 };
            let s30 = RtpInfo { type_byte: 30, ..s13 };
            h.send(1, 0, 1_000_000 + i as u64, s13);
            h.send(1, 0, 1_000_000 + i as u64, s30);
        }
        assert_eq!(h.hub.streams_active().0, 5);
    }

    #[test]
    fn full_table_is_counted_and_the_packet_is_left_to_the_caller() {
        let (tx, _rx) = unbounded();
        let hub = RtpHub::new(HubCfg { stripes: 1, max_streams: 1, ..Default::default() }, tx); // 256 per stripe minimum
        let mut rejected = 0;
        for s in 0..400u32 {
            for k in 0..2u16 {
                if hub.on_packet(&pkt(1, 0, 1_000_000 + s as u64 * 10 + k as u64, video(s, k, 0, 100))) == RtpOutcome::Unqualified && k == 1 {
                    rejected += 1;
                }
            }
        }
        assert_eq!(hub.streams_active().0, 256);
        assert_eq!(rejected, 400 - 256);
        assert_eq!(hub.ctr.streams_rejected.load(Relaxed), 144);
    }

    // ------------------------------------------------------------ SFU counter

    #[test]
    fn the_sfu_counter_reports_missing_numbers_per_flow_and_bin() {
        let h = hub();
        let mut seen = vec![];
        for (i, seq) in [1u16, 2, 3, 6, 7, 5, 8].iter().enumerate() {
            let p = HubPkt { client: client(1), client_port: 40_000, dir: 0, t_us: 1_000_000 + i as u64 * 1000, sfu_seq: Some(*seq), rtp: None };
            seen.push(h.hub.on_packet(&p));
        }
        assert!(seen.iter().all(|o| *o == RtpOutcome::NotRtp));
        // another flow of the same client (another port, same direction) has its own counter
        let p = HubPkt { client: client(1), client_port: 40_001, dir: 0, t_us: 1_500_000, sfu_seq: Some(500), rtp: None };
        h.hub.on_packet(&p);
        h.hub.flush_all();
        let (_, _, sfu) = h.drain();
        let main = sfu.iter().find(|s| s.seen == 7).expect("flow 1");
        // 4 and 5 skipped, 5 arrived late: only 4 is missing
        assert_eq!((main.dir, main.missed), (0, 1));
        assert!(sfu.iter().any(|s| s.seen == 1 && s.missed == 0));
        assert_eq!(h.hub.streams_active().1, 2);
    }
}
