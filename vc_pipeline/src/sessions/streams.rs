//! # sessions/streams.rs: per-RTP-stream metrics for Teams / Meet (vc_combined)
//!
//! Replaces `media_metrics.rs` and `rtp_streams.rs`. One [`Stream`] per (direction, SSRC) of a
//! client session. It computes, with the **same rules as the Zoom engine** (`zoom_pipeline::metrics`
//! and `export.rs`), every metric the user chose to port (2026-11-06): per-direction volume split,
//! stalls, retransmits, RFC 3550 jitter (frame level, video), fps over the covered time, audio-active
//! seconds, screen-share streams and stream qualification. Same rule -> same field name as Zoom.
//!
//! ## Why (direction, SSRC) and not SSRC alone
//! The per-direction fields need it, and Meet does send a client its own uplink SSRC back on
//! the downlink (10.184.33.83, 2026-11-04): keyed by SSRC alone the two would be one "stream".
//! The session-level loss (`rtp_loss_pct_*`, network_metrics.rs) keeps its old SSRC-only key, as
//! decided (no loss upgrade).
//!
//! ## What is "video" here
//! Teams/Meet media is encrypted SRTP and carries no media type the way Zoom's header does, so
//! the old size rule stays the classifier (roadmap step 5 plans PT + clock rate):
//! * a stream is **video** when, over its life in the session, more packets had `udp_len > 400`
//!   than `<= 400`; otherwise **audio** (same rule as the old `teams_rtp_stream` tag);
//! * a video stream is **screen** when its RTP-timestamp gap histogram is not clustered
//!   (the old degradation classifier, needs >= 10 gaps; INFERENCE quality);
//! * only packets with `udp_len > 400` take part in frame counting (unchanged: a frame made of
//!   small packets is not seen; H3 in the handoff).
//!
//! ## Qualification (Zoom rule, STAGE2_DESIGN 9.1)
//! A stream counts as media only after >= 20 packets of which >= 90 % moved the sequence
//! number forward by 1..=100. Not qualified after 64 packets = failed. A bin is counted as media
//! when the stream is qualified at the end of the bin (so the bin in which it qualifies counts
//! whole, as Zoom releases its held counters). Example: Meet's SSRC-0 probe packets (seq 1, 2, 3)
//! never reach 20 packets: their bytes go to `unq_media_*`, never to `fps_*` or `video_*`.

use crate::models::RtpRecord;
use std::collections::HashMap;

/// Inter-frame arrival gap above which a frame is a stall (Zoom: 200 ms).
pub const STALL_NS: u64 = 200_000_000;
pub const QUAL_MIN_PKTS: u32 = 20;
pub const QUAL_GIVE_UP_PKTS: u32 = 64;
pub const QUAL_MIN_FWD: f64 = 0.9;
pub const QUAL_MAX_STEP: u16 = 100;
/// Frame timestamp gaps outside this range are not a camera cadence (60 fps .. 1 fps at 90 kHz).
pub const MIN_FRAME_TICKS: u32 = 1_500;
pub const MAX_FRAME_TICKS: u32 = 90_000;
pub const VIDEO_TICKS_PER_MS: f64 = 90.0;
/// Packets in one second above which an audio second is "active" (Zoom: 20).
pub const AUDIO_ACTIVE_PKTS: u16 = 20;
/// Size rule: a packet with `udp_len` above this is a video packet.
pub const VIDEO_MIN_UDP_LEN: u16 = 400;
/// A stream needs this much covered time in a bin before its fps is used (Zoom: 1 s).
pub const MIN_FPS_COVER_S: f64 = 1.0;
/// Coverage of a "full" bin, the only bins `degraded_*` judges (Zoom: 4 s).
pub const FULL_BIN_COVER_S: f64 = 4.0;
/// fps below this is degraded (thesis / Zoom: 15).
pub const DEGRADED_FPS: f64 = 15.0;
/// Late-arrival window of the retransmit detector (Zoom: 128).
const LATE_WINDOW: u32 = 128;
const RING: usize = 8;
const MAX_BIN_SECS: usize = 8;
// screen-share classifier (old degradation.rs values)
const HIST_BIN: u32 = 500;
const HIST_BINS: usize = 360;
const CLUSTER_PCT: f64 = 70.0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QState {
    Probation,
    Qualified,
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Audio,
    Video,
    Screen,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Audio => "audio",
            Kind::Video => "video",
            Kind::Screen => "screen",
        }
    }
}

/// Repeat detector: Zoom's `SeqTracker` (bitmap of the last 128 sequence numbers). Used here
/// ONLY to count retransmits (a sequence number that arrives again after de-dup); the loss
/// fields keep their old formula.
#[derive(Clone, Copy, Default)]
struct RepeatTracker {
    started: bool,
    highest: u16,
    bits: u128,
}

impl RepeatTracker {
    /// true = this sequence number was already received (a retransmission).
    fn is_repeat(&mut self, seq: u16) -> bool {
        if !self.started {
            self.started = true;
            self.highest = seq;
            self.bits = 1;
            return false;
        }
        let d = seq.wrapping_sub(self.highest) as i16 as i32;
        if d > 0 {
            if d > 1000 {
                self.highest = seq;
                self.bits = 1;
                return false;
            }
            self.bits = if d >= 128 { 1 } else { (self.bits << d) | 1 };
            self.highest = seq;
            false
        } else if d == 0 {
            true
        } else {
            let off = (-d) as u32;
            if off >= LATE_WINDOW {
                return false;
            }
            let bit = 1u128 << off;
            if self.bits & bit != 0 {
                true
            } else {
                self.bits |= bit;
                false
            }
        }
    }
}

pub struct Stream {
    pub uplink: bool,
    pub ssrc: u32,
    pub pt: u8,
    // ---- lifetime
    small: u64,
    large: u64,
    pub state: QState,
    fed: u32,
    fwd_ok: u32,
    q_last_seq: u16,
    rep: RepeatTracker,
    // old per-stream loss rule (rtp_streams.rs): uncapped, no late-packet credit
    loss_last_seq: u16,
    loss_started: bool,
    // frame state (Zoom frame_step), survives bins
    ring: [u32; RING],
    ring_n: u8,
    ring_pos: u8,
    cur_ts: u32,
    prev_ts: u32,
    have_cur: bool,
    have_prev: bool,
    cur_end_ns: u64,
    last_end_ns: u64,
    have_last_end: bool,
    pub jitter_ms: f64,
    // screen classifier (lifetime histogram of RTP timestamp gaps of video packets)
    hist: Box<[u32; HIST_BINS]>,
    hist_total: u32,
    hist_last_ts: Option<u32>,
    // ---- bin
    pub pkts: u32,
    pub bytes: u64,
    pub first_ns: u64,
    pub last_ns: u64,
    pub frames: u32,
    pub lost: u64,
    pub retx: u32,
    pub gap_n: u32,
    pub gap_mean: f64,
    pub gap_m2: f64,
    pub stalls: u32,
    sec_pkts: [u16; MAX_BIN_SECS],
}

impl Stream {
    fn new(uplink: bool, ssrc: u32, pt: u8) -> Stream {
        Stream {
            uplink,
            ssrc,
            pt,
            small: 0,
            large: 0,
            state: QState::Probation,
            fed: 0,
            fwd_ok: 0,
            q_last_seq: 0,
            rep: RepeatTracker::default(),
            loss_last_seq: 0,
            loss_started: false,
            ring: [0; RING],
            ring_n: 0,
            ring_pos: 0,
            cur_ts: 0,
            prev_ts: 0,
            have_cur: false,
            have_prev: false,
            cur_end_ns: 0,
            last_end_ns: 0,
            have_last_end: false,
            jitter_ms: 0.0,
            hist: Box::new([0; HIST_BINS]),
            hist_total: 0,
            hist_last_ts: None,
            pkts: 0,
            bytes: 0,
            first_ns: 0,
            last_ns: 0,
            frames: 0,
            lost: 0,
            retx: 0,
            gap_n: 0,
            gap_mean: 0.0,
            gap_m2: 0.0,
            stalls: 0,
            sec_pkts: [0; MAX_BIN_SECS],
        }
    }

    /// Lifetime size majority, then the gap-histogram screen test.
    pub fn kind(&self) -> Kind {
        if self.large <= self.small {
            return Kind::Audio;
        }
        if self.is_screen() { Kind::Screen } else { Kind::Video }
    }

    fn is_screen(&self) -> bool {
        if self.hist_total < 10 {
            return false;
        }
        let (mut mode, mut maxc) = (0usize, 0u32);
        for (i, &c) in self.hist.iter().enumerate() {
            if c > maxc {
                maxc = c;
                mode = i;
            }
        }
        if maxc == 0 {
            return false;
        }
        let mode_gap = mode as u32 * HIST_BIN + HIST_BIN / 2;
        let tol = (mode_gap as f64 * 0.2) as u32;
        let (lo, hi) = (mode_gap.saturating_sub(tol), mode_gap.saturating_add(tol));
        let clustered: u32 = self
            .hist
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                let g = *i as u32 * HIST_BIN + HIST_BIN / 2;
                g >= lo && g <= hi
            })
            .map(|(_, &c)| c)
            .sum();
        (clustered as f64 / self.hist_total as f64) * 100.0 < CLUSTER_PCT
    }

    /// Covered time of the stream in this bin, seconds.
    pub fn cover_s(&self) -> f64 {
        self.last_ns.saturating_sub(self.first_ns) as f64 / 1e9
    }

    /// fps in this bin, if the stream covered >= 1 s and showed a camera cadence.
    pub fn fps(&self) -> Option<f64> {
        let c = self.cover_s();
        (c >= MIN_FPS_COVER_S && self.gap_n >= 1).then(|| self.frames as f64 / c)
    }

    pub fn active_secs(&self) -> u8 {
        self.sec_pkts.iter().filter(|&&n| n > AUDIO_ACTIVE_PKTS).count() as u8
    }

    pub fn frame_gap_std_ms(&self) -> Option<f64> {
        (self.gap_n >= 2).then(|| (self.gap_m2 / self.gap_n as f64).sqrt())
    }

    pub fn rtp_loss_pct(&self) -> f64 {
        let exp = self.pkts as u64 + self.lost;
        if exp == 0 { 0.0 } else { self.lost as f64 * 100.0 / exp as f64 }
    }

    fn frame_step(&mut self, ts: u32, t_ns: u64) {
        let n = self.ring_n as usize;
        if self.have_cur && ts == self.cur_ts {
            self.cur_end_ns = t_ns;
            return;
        }
        if self.ring[..n].contains(&ts) {
            return; // a reordered packet of an older frame
        }
        if self.have_cur {
            if self.have_last_end && self.have_prev {
                let gap_ns = self.cur_end_ns.saturating_sub(self.last_end_ns);
                let dts = self.cur_ts.wrapping_sub(self.prev_ts);
                if (dts as i32) > 0 && gap_ns > STALL_NS {
                    self.stalls += 1;
                }
                if (MIN_FRAME_TICKS..=MAX_FRAME_TICKS).contains(&dts) {
                    let gap_ms = gap_ns as f64 / 1e6;
                    self.gap_n += 1;
                    let delta = gap_ms - self.gap_mean;
                    self.gap_mean += delta / self.gap_n as f64;
                    self.gap_m2 += delta * (gap_ms - self.gap_mean);
                    // RFC 3550 6.4.1 on frame end times: D = (ET_i - ET_i-1) - (TS_i - TS_i-1)/90 kHz
                    let d = gap_ms - dts as f64 / VIDEO_TICKS_PER_MS;
                    self.jitter_ms += (d.abs() - self.jitter_ms) / 16.0;
                }
            }
            if self.have_cur {
                self.last_end_ns = self.cur_end_ns;
                self.have_last_end = true;
                self.prev_ts = self.cur_ts;
                self.have_prev = true;
            }
        }
        self.cur_ts = ts;
        self.have_cur = true;
        self.cur_end_ns = t_ns;
        self.ring[self.ring_pos as usize] = ts;
        self.ring_pos = ((self.ring_pos as usize + 1) % RING) as u8;
        if (self.ring_n as usize) < RING {
            self.ring_n += 1;
        }
        self.frames += 1;
    }

    pub fn feed(&mut self, r: &RtpRecord) {
        let t = r.arrival_epoch_ns;
        if self.pkts == 0 {
            self.first_ns = t;
        }
        self.pkts += 1;
        self.bytes += (r.udp_len as u64).saturating_sub(8);
        self.last_ns = t;
        self.pt = r.payload_type;
        let sec = (((t % 5_000_000_000) / 1_000_000_000) as usize).min(MAX_BIN_SECS - 1);
        self.sec_pkts[sec] = self.sec_pkts[sec].saturating_add(1);

        // retransmits (repeat detector, Zoom rule)
        if self.rep.is_repeat(r.seq_num) {
            self.retx += 1;
        }
        // old per-stream loss rule, unchanged
        if self.loss_started {
            let diff = r.seq_num.wrapping_sub(self.loss_last_seq) as i16;
            if diff > 1 {
                self.lost += (diff as u64) - 1;
            }
            if diff > 0 {
                self.loss_last_seq = r.seq_num;
            }
        } else {
            self.loss_started = true;
            self.loss_last_seq = r.seq_num;
        }
        // size rule + frames
        if r.udp_len > VIDEO_MIN_UDP_LEN {
            self.large += 1;
            if let Some(last) = self.hist_last_ts {
                let g = r.rtp_timestamp.wrapping_sub(last);
                if g > 0 && g < HIST_BINS as u32 * HIST_BIN {
                    self.hist[(g / HIST_BIN) as usize] += 1;
                    self.hist_total += 1;
                }
            }
            self.hist_last_ts = Some(r.rtp_timestamp);
            self.frame_step(r.rtp_timestamp, t);
        } else {
            self.small += 1;
        }
        // qualification
        if self.fed > 0 {
            let d = r.seq_num.wrapping_sub(self.q_last_seq);
            if (1..=QUAL_MAX_STEP).contains(&d) {
                self.fwd_ok += 1;
            }
        }
        self.q_last_seq = r.seq_num;
        self.fed = self.fed.saturating_add(1);
        if self.state == QState::Probation {
            if self.fed >= QUAL_MIN_PKTS && self.fwd_ok as f64 >= QUAL_MIN_FWD * (self.fed - 1) as f64 {
                self.state = QState::Qualified;
            } else if self.fed >= QUAL_GIVE_UP_PKTS {
                self.state = QState::Failed;
            }
        }
    }

    fn reset_bin(&mut self) {
        self.pkts = 0;
        self.bytes = 0;
        self.frames = 0;
        self.lost = 0;
        self.retx = 0;
        self.gap_n = 0;
        self.gap_mean = 0.0;
        self.gap_m2 = 0.0;
        self.stalls = 0;
        self.sec_pkts = [0; MAX_BIN_SECS];
    }
}

/// Sums of one direction in one bin (the session line's per-direction fields).
#[derive(Default, Clone, Debug)]
pub struct DirAgg {
    pub video_pkts: u64,
    pub video_bytes: u64,
    pub audio_pkts: u64,
    pub audio_bytes: u64,
    pub screen_pkts: u64,
    pub screen_bytes: u64,
    pub unq_pkts: u64,
    pub unq_bytes: u64,
    /// qualified camera-video streams with packets in the bin
    pub video_streams: u32,
    pub video_frames: u64,
    pub fps_n: u32,
    pub fps_sum: f64,
    pub full_n: u32,
    pub full_fps_sum: f64,
    pub full_below: u32,
    pub stream_bps_sum: f64,
    pub gap_n: u64,
    pub gap_mean: f64,
    pub gap_m2: f64,
    pub jit_sum: f64,
    pub jit_w: f64,
    pub stalls: u64,
    pub retx: u64,
    pub audio_streams: u32,
    pub audio_active_s: u8,
    pub screen_streams: u32,
    pub screen_frames: u64,
    pub screen_fps_n: u32,
    pub screen_fps_sum: f64,
}

/// Parallel Welford merge (as Zoom's exporter).
fn merge_welford(n: &mut u64, mean: &mut f64, m2: &mut f64, bn: u64, bmean: f64, bm2: f64) {
    if bn == 0 {
        return;
    }
    if *n == 0 {
        *n = bn;
        *mean = bmean;
        *m2 = bm2;
        return;
    }
    let (na, nb) = (*n as f64, bn as f64);
    let tot = na + nb;
    let delta = bmean - *mean;
    *m2 += bm2 + delta * delta * na * nb / tot;
    *mean += delta * nb / tot;
    *n += bn;
}

#[derive(Default)]
pub struct StreamTracker {
    streams: HashMap<(bool, u32), Stream>,
}

/// One per-SSRC line's worth of data (`rtp_stream`).
pub struct StreamLine<'a> {
    pub s: &'a Stream,
    pub kind: Kind,
}

impl StreamTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process_packet(&mut self, r: &RtpRecord) {
        self.streams.entry((r.uplink, r.ssrc)).or_insert_with(|| Stream::new(r.uplink, r.ssrc, r.payload_type)).feed(r);
    }

    /// Per-direction sums of the bin: `[uplink, downlink]`.
    pub fn aggregate(&self) -> [DirAgg; 2] {
        let mut a = [DirAgg::default(), DirAgg::default()];
        for s in self.streams.values().filter(|s| s.pkts > 0) {
            let d = &mut a[if s.uplink { 0 } else { 1 }];
            if s.state != QState::Qualified {
                d.unq_pkts += s.pkts as u64;
                d.unq_bytes += s.bytes;
                continue;
            }
            d.retx += s.retx as u64;
            match s.kind() {
                Kind::Audio => {
                    d.audio_pkts += s.pkts as u64;
                    d.audio_bytes += s.bytes;
                    d.audio_streams += 1;
                    d.audio_active_s = d.audio_active_s.max(s.active_secs());
                }
                Kind::Screen => {
                    d.screen_pkts += s.pkts as u64;
                    d.screen_bytes += s.bytes;
                    d.screen_streams += 1;
                    d.screen_frames += s.frames as u64;
                    if let Some(f) = s.fps() {
                        d.screen_fps_n += 1;
                        d.screen_fps_sum += f;
                    }
                }
                Kind::Video => {
                    d.video_pkts += s.pkts as u64;
                    d.video_bytes += s.bytes;
                    d.video_streams += 1;
                    d.video_frames += s.frames as u64;
                    d.stalls += s.stalls as u64;
                    merge_welford(&mut d.gap_n, &mut d.gap_mean, &mut d.gap_m2, s.gap_n as u64, s.gap_mean, s.gap_m2);
                    if s.gap_n > 0 {
                        d.jit_sum += s.jitter_ms * s.pkts as f64;
                        d.jit_w += s.pkts as f64;
                    }
                    if let Some(f) = s.fps() {
                        d.fps_n += 1;
                        d.fps_sum += f;
                        d.stream_bps_sum += s.bytes as f64 * 8.0 / 5.0;
                        if s.cover_s() >= FULL_BIN_COVER_S {
                            d.full_n += 1;
                            d.full_fps_sum += f;
                            if f < DEGRADED_FPS {
                                d.full_below += 1;
                            }
                        }
                    }
                }
            }
        }
        a
    }

    /// Streams with packets in this bin, for the optional `rtp_stream` lines.
    pub fn lines(&self) -> Vec<StreamLine<'_>> {
        let mut v: Vec<_> = self.streams.values().filter(|s| s.pkts > 0).map(|s| StreamLine { s, kind: s.kind() }).collect();
        v.sort_by_key(|l| (!l.s.uplink, l.s.ssrc));
        v
    }

    pub fn reset_bin(&mut self) {
        for s in self.streams.values_mut() {
            s.reset_bin();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Platform;

    pub(crate) fn rec(uplink: bool, ssrc: u32, seq: u16, ts: u32, udp_len: u16, t_ns: u64) -> RtpRecord {
        RtpRecord {
            arrival_epoch_ns: t_ns,
            platform: Platform::Meet,
            src_ip: if uplink { "10.184.4.232".into() } else { "142.250.82.219".into() },
            dst_ip: if uplink { "142.250.82.219".into() } else { "10.184.4.232".into() },
            src_port: 1,
            dst_port: 2,
            ip_proto: 17,
            ip_len: udp_len + 20,
            udp_len,
            ssrc,
            rtp_timestamp: ts,
            seq_num: seq,
            payload_type: 96,
            marker: false,
            fp: 0,
            uplink,
            frame: None,
            frame_len: 0,
        }
    }

    const T0: u64 = 1_800_000_000_000_000_000; // a bin boundary (divisible by 5 s)

    /// 30 fps camera: 3 packets of 1 020 B per frame, frame k ends at k*33.3 ms (+ jitter_ms on odd frames).
    fn camera(t: &mut StreamTracker, uplink: bool, ssrc: u32, frames: u32, extra_ms_odd: f64) {
        let mut seq = 1000u16;
        for k in 0..frames {
            let base = T0 + (k as f64 * 33.333_333 * 1e6) as u64 + if k % 2 == 1 { (extra_ms_odd * 1e6) as u64 } else { 0 };
            for p in 0..3u64 {
                t.process_packet(&rec(uplink, ssrc, seq, 90_000 + k * 3000, 1020, base + p * 100_000));
                seq = seq.wrapping_add(1);
            }
        }
    }

    #[test]
    fn a_30_fps_camera_gives_30_fps_no_stalls_and_almost_no_jitter() {
        let mut t = StreamTracker::new();
        camera(&mut t, false, 0x77, 150, 0.0);
        let a = t.aggregate();
        let d = &a[1];
        assert_eq!(d.video_streams, 1);
        assert_eq!(d.video_frames, 150);
        let fps = d.fps_sum / d.fps_n as f64;
        // 150 frames over 4.967 s covered (first packet of frame 0 .. last of frame 149): Zoom's rule
        assert!((fps - 150.0 / 4.9668).abs() < 0.05, "{fps}");
        assert_eq!(d.stalls, 0);
        assert!(d.jit_sum / d.jit_w < 0.01);
        assert_eq!(d.video_bytes, 450 * 1012, "payload bytes = udp_len - 8");
        assert_eq!(d.full_n, 1);
        assert_eq!(d.full_below, 0);
    }

    #[test]
    fn rfc3550_jitter_follows_the_frame_level_rule() {
        // frames alternately on time and 8 ms late: |D| alternates 8 and 8 ms -> J converges to 8
        let mut t = StreamTracker::new();
        camera(&mut t, true, 0x10, 150, 8.0);
        let s = t.lines()[0].s;
        assert!((s.jitter_ms - 8.0).abs() < 0.2, "{}", s.jitter_ms);
        // first step by hand: J1 = (|D| - 0)/16 with D = 41.33 - 33.33 = 8.0 ms
        let mut t2 = StreamTracker::new();
        camera(&mut t2, true, 0x10, 3, 8.0);
        let j = t2.lines()[0].s.jitter_ms;
        assert!((j - 8.0 / 16.0).abs() < 1e-3, "{j}");
    }

    #[test]
    fn a_frame_gap_over_200_ms_is_a_stall() {
        let mut t = StreamTracker::new();
        let mut seq = 1u16;
        for (k, ms) in [0u64, 33, 66, 400, 433].iter().enumerate() {
            for p in 0..21u64 {
                // 21 packets per frame so the stream qualifies quickly
                t.process_packet(&rec(false, 9, seq, 1000 + k as u32 * 3000, 1100, T0 + ms * 1_000_000 + p));
                seq += 1;
            }
        }
        // a frame is closed when the next one starts: gap 66 -> 400 ms is closed at frame 4
        assert_eq!(t.aggregate()[1].stalls, 1);
    }

    #[test]
    fn retransmits_are_counted_and_loss_keeps_the_old_rule() {
        let mut t = StreamTracker::new();
        for s in 1..=30u16 {
            t.process_packet(&rec(true, 5, s, 0, 160, T0 + s as u64 * 20_000_000));
        }
        t.process_packet(&rec(true, 5, 25, 0, 160, T0 + 700_000_000)); // retransmission of 25
        t.process_packet(&rec(true, 5, 35, 0, 160, T0 + 720_000_000)); // 31..34 missing
        let s = t.lines()[0].s;
        assert_eq!(s.retx, 1);
        assert_eq!(s.lost, 4);
        assert_eq!(t.aggregate()[0].retx, 1);
        assert_eq!(t.aggregate()[0].audio_streams, 1);
    }

    #[test]
    fn a_probe_never_qualifies_and_counts_only_as_unqualified_volume() {
        let mut t = StreamTracker::new();
        for s in 1..=3u16 {
            t.process_packet(&rec(false, 0, s, 0, 1200, T0 + s as u64));
        }
        let a = t.aggregate();
        assert_eq!((a[1].unq_pkts, a[1].video_streams, a[1].video_pkts), (3, 0, 0));
    }

    #[test]
    fn audio_active_seconds_count_seconds_with_more_than_20_packets() {
        let mut t = StreamTracker::new();
        // 50 pkt/s for the first 3 s, then 10 pkt/s
        let mut seq = 0u16;
        for ms in (0..3000).step_by(20).chain((3000..5000).step_by(100)) {
            t.process_packet(&rec(false, 3, seq, 0, 150, T0 + ms as u64 * 1_000_000));
            seq += 1;
        }
        assert_eq!(t.aggregate()[1].audio_active_s, 3);
    }

    #[test]
    fn the_same_ssrc_on_uplink_and_downlink_is_two_streams() {
        let mut t = StreamTracker::new();
        camera(&mut t, true, 0x1A0A, 60, 0.0);
        camera(&mut t, false, 0x1A0A, 60, 0.0);
        assert_eq!(t.lines().len(), 2);
        let a = t.aggregate();
        assert_eq!((a[0].video_streams, a[1].video_streams), (1, 1));
    }
}
