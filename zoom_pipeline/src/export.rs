//! Exporter: the single consumer of the capture-to-exporter channel.
//!
//! Matches the thesis architecture (bounded channel, `try_send` on the
//! producer side, one consumer, one HTTP writer) with these properties:
//!
//! * **Merging.** A client's audio, video and screen streams have different
//!   5-tuples, so RSS may put them on different cores. Each core emits its
//!   own `BinMetrics`; the [`Assembler`] sums them per `(bin, client)` into
//!   one wide point and emits it once the bin has *settled* (`settle_us`
//!   after its end, long enough for every core's sweeper to have closed it).
//! * **Bounded.** Pending bins are capped (`max_pending`); a batch is at most
//!   `batch_max_lines`; retries are 3 with exponential backoff (200 ms
//!   doubling to 5 s), after which the batch is dropped and counted. A dead
//!   database therefore costs a bounded amount of memory and shows up in
//!   `capture_health` instead of crashing the process.
//! * **No exporter state grows without bound over 24 h**: sessions are
//!   closed after `session_gap_us` of silence and `session_summary` is
//!   upserted (same series + timestamp overwrites in InfluxDB).
//! * **Wall clock only here.** Capture cores use a monotonic clock. The
//!   epoch offset is recomputed at every emission, so an NTP step moves the
//!   exported timestamps, never the capture arithmetic.

use crate::metrics::FEC_PT;
use crate::headers::{VLAYOUT_SLOT_OTHER, VLAYOUT_SLOT_RTP20};
use crate::model::{Acct, BinMetrics, ExportMsg, HealthSnapshot, RtpBin, SfuBin, KIND_AUDIO, KIND_VIDEO, NACCT};
use crate::net::Addr;
use crossbeam_channel::{Receiver, RecvTimeoutError};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// -------------------------------------------------------------------- sinks

#[derive(Debug, Clone)]
pub struct SinkError {
    pub retryable: bool,
    pub msg: String,
}

pub trait Sink: Send {
    fn send(&mut self, body: &str) -> Result<(), SinkError>;
}

/// InfluxDB 2.x `/api/v2/write` over HTTP(S).
/// `url` carries org, bucket and precision, e.g.
/// `http://host:8087/api/v2/write?org=teams&bucket=qoe&precision=ns`
/// (the same shape as the thesis' `TEAMS_QOE_INFLUX_URL`).
pub struct HttpSink {
    agent: ureq::Agent,
    url: String,
    token: String,
}

impl HttpSink {
    pub fn new(url: String, token: String) -> HttpSink {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(2))
            .timeout_write(Duration::from_secs(5))
            .timeout_read(Duration::from_secs(5))
            .build();
        HttpSink { agent, url, token }
    }
}

impl Sink for HttpSink {
    fn send(&mut self, body: &str) -> Result<(), SinkError> {
        match self
            .agent
            .post(&self.url)
            .set("Authorization", &format!("Token {}", self.token))
            .set("Content-Type", "text/plain; charset=utf-8")
            .send_string(body)
        {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(code, resp)) => {
                let snippet: String = resp.into_string().unwrap_or_default().chars().take(200).collect();
                // 4xx other than 408/429 means our request is wrong (bad token, bad line):
                // retrying the same bytes cannot help.
                Err(SinkError { retryable: code >= 500 || code == 429 || code == 408, msg: format!("HTTP {code}: {snippet}") })
            }
            Err(e) => Err(SinkError { retryable: true, msg: format!("transport: {e}") }),
        }
    }
}

/// Appends line protocol to a file (offline runs, or when no Influx is set).
pub struct FileSink(std::io::BufWriter<std::fs::File>);

impl FileSink {
    pub fn create(path: &std::path::Path) -> std::io::Result<FileSink> {
        Ok(FileSink(std::io::BufWriter::new(std::fs::OpenOptions::new().create(true).append(true).open(path)?)))
    }
}

impl Sink for FileSink {
    fn send(&mut self, body: &str) -> Result<(), SinkError> {
        use std::io::Write;
        self.0
            .write_all(body.as_bytes())
            .and_then(|_| self.0.flush())
            .map_err(|e| SinkError { retryable: false, msg: e.to_string() })
    }
}

/// Prints to stdout (what the thesis does when no URL is configured).
pub struct StdoutSink;
impl Sink for StdoutSink {
    fn send(&mut self, body: &str) -> Result<(), SinkError> {
        print!("{body}");
        Ok(())
    }
}

/// Test sink: records bodies; can be told to fail the next N sends.
#[derive(Clone, Default)]
pub struct MemSink {
    pub bodies: Arc<Mutex<Vec<String>>>,
    pub fail_next: Arc<AtomicU64>,
    pub fail_retryable: bool,
    pub delay: Duration,
}

impl Sink for MemSink {
    fn send(&mut self, body: &str) -> Result<(), SinkError> {
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        if self.fail_next.load(Relaxed) > 0 {
            self.fail_next.fetch_sub(1, Relaxed);
            return Err(SinkError { retryable: self.fail_retryable, msg: "injected failure".into() });
        }
        self.bodies.lock().unwrap_or_else(|e| e.into_inner()).push(body.to_string());
        Ok(())
    }
}

// ------------------------------------------------------------------- config

#[derive(Clone, Debug)]
pub struct ExportCfg {
    pub bin_us: u64,
    pub batch_max_lines: usize,
    pub flush_every: Duration,
    /// wait this long after a bin ends before emitting it (all cores' sweepers must have closed it)
    pub settle_us: u64,
    pub retries: u32,
    pub backoff_start: Duration,
    pub backoff_max: Duration,
    pub session_gap_us: u64,
    pub summary_every_us: u64,
    pub max_pending: usize,
    /// also write one `rtp_stream` line (was `zoom_rtp_stream`) per qualified RTP stream and bin (series cardinality grows with calls: debug use)
    pub ssrc_lines: bool,
    pub host: String,
}

impl Default for ExportCfg {
    fn default() -> Self {
        ExportCfg {
            bin_us: 5_000_000,
            batch_max_lines: 5_000,
            flush_every: Duration::from_secs(1),
            settle_us: 3_000_000,
            retries: 3,
            backoff_start: Duration::from_millis(200),
            backoff_max: Duration::from_secs(5),
            session_gap_us: 120_000_000, // media-silence timeout; 120 s is the thesis SESSION_TIMEOUT (see touch_session)
            summary_every_us: 60_000_000,
            // a pending (bin, client) holds the per-stream sums (about 1.5 KB), so 100_000 of them cost ~150 MB at most;
            // the p6 catalogue said 1_000_000, which was never the code's value (corrected in the p7b catalogue addendum)
            max_pending: 100_000,
            ssrc_lines: false,
            host: std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into()),
        }
    }
}

#[derive(Default)]
pub struct ExportStats {
    pub lines_ok: AtomicU64,
    pub lines_dropped: AtomicU64,
    pub batches_ok: AtomicU64,
    pub batches_failed: AtomicU64,
    pub retries: AtomicU64,
    pub pending_overflow: AtomicU64,
    pub sessions_closed: AtomicU64,
}

// ---------------------------------------------------------------- assembler

/// Packets and UDP payload bytes of one (direction, accounting category).
#[derive(Clone, Copy, Default)]
struct VolAgg {
    pkts: u64,
    bytes: u64,
}

/// Media slots of one direction: video, audio, screen share type 13, screen share type 30.
const M_VIDEO: usize = 0;
const M_AUDIO: usize = 1;
const M_SS13: usize = 2;
const M_SS30: usize = 3;
const NMEDIA: usize = 4;

/// Everything the qualified RTP streams of one (client, bin, direction, media slot) add up to.
/// "main" = payload type other than 110 (110 is the FEC companion: own sequence numbers,
/// same frame timestamps, so it is excluded from loss, frames and jitter).
#[derive(Clone, Copy)]
struct MediaAgg {
    pkts: u64,
    bytes: u64,
    fec_pkts: u64,
    fec_bytes: u64,
    /// "main" streams with packets in the bin. Here "main" means NOT FEC (payload type 110 is the FEC
    /// companion, `fec_*`), not "the primary camera": every other qualified video stream counts, including
    /// a second video SSRC in the same flow (the rtp20 layout, p7b). TO BE CHECKED (C2, not done): whether such
    /// a stream belongs in the per-client means below; today fps, jitter, frame-gap sigma and `degraded` are
    /// means over all of them (example: 24 fps + 5 fps = 14.5 -> `degraded` = 1 although the 24 fps stream is fine).
    streams: u32,
    frames: u64,
    /// main streams whose coverage is >= 1 s: their FPS, summed (the mean is fps_sum / fps_n)
    fps_n: u32,
    fps_sum: f64,
    /// main streams whose coverage is >= 4 s ("full bin"), the ones `degraded` may judge
    full_n: u32,
    full_fps_sum: f64,
    full_below: u32,
    rx: u64,
    lost: i64,
    retx: u64,
    stalls: u64,
    /// pooled inter-frame gaps (parallel Welford)
    gap_n: u64,
    gap_mean: f64,
    gap_m2: f64,
    jit_sum: f64,
    jit_w: f64,
    active_secs: u8,
}

impl Default for MediaAgg {
    fn default() -> Self {
        MediaAgg {
            pkts: 0,
            bytes: 0,
            fec_pkts: 0,
            fec_bytes: 0,
            streams: 0,
            frames: 0,
            fps_n: 0,
            fps_sum: 0.0,
            full_n: 0,
            full_fps_sum: 0.0,
            full_below: 0,
            rx: 0,
            lost: 0,
            retx: 0,
            stalls: 0,
            gap_n: 0,
            gap_mean: 0.0,
            gap_m2: 0.0,
            jit_sum: 0.0,
            jit_w: 0.0,
            active_secs: 0,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct SfuAgg {
    seen: u64,
    missed: i64,
}

/// One client's traffic in one bin, merged over cores and streams.
struct Wide {
    vol: [[VolAgg; NACCT]; 2],
    media: [[MediaAgg; NMEDIA]; 2],
    sfu: [SfuAgg; 2],
    /// first / last packet of any kind in the bin (for `bin_cover_s`)
    first_us: u64,
    last_us: u64,
    /// first / last packet of QUALIFIED media: what starts and extends a session
    media_first_us: u64,
    media_last_us: u64,
    /// per-stream records, kept only when `--ssrc-lines` is on
    streams: Vec<RtpBin>,
}

impl Default for Wide {
    fn default() -> Self {
        Wide {
            vol: [[VolAgg::default(); NACCT]; 2],
            media: [[MediaAgg::default(); NMEDIA]; 2],
            sfu: [SfuAgg::default(); 2],
            first_us: u64::MAX,
            last_us: 0,
            media_first_us: u64::MAX,
            media_last_us: 0,
            streams: Vec::new(),
        }
    }
}

impl Wide {
    fn has_media(&self) -> bool {
        self.media_first_us != u64::MAX
    }
    fn share_active(&self) -> bool {
        (0..2).any(|d| self.media[d][M_SS13].streams + self.media[d][M_SS30].streams > 0)
    }
}

/// Parallel Welford merge (Chan et al.): combine (n, mean, M2) of two sets of gaps.
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

#[derive(Clone, Copy)]
struct Session {
    id: u64,
    /// time of the first QUALIFIED media packet of the session (us, pipeline time)
    first_us: u64,
    /// time of the last qualified media packet seen so far
    last_media_us: u64,
    first_epoch_ns: i128,
    bytes_up: u64,
    bytes_down: u64,
    bins: u32,
    media_bins: u32,
    video_bins: u32,
    audio_bins: u32,
    screen_bins: u32,
    last_summary_us: u64,
}

pub struct Assembler {
    cfg: ExportCfg,
    pending: BTreeMap<(u64, u128), Wide>,
    sessions: HashMap<u128, Session>,
}

pub fn tag_value(v: &str) -> String {
    v.replace('\\', "\\\\").replace(',', "\\,").replace('=', "\\=").replace(' ', "\\ ")
}

fn session_id(client: Addr, first_epoch_ns: i128) -> u64 {
    use std::hash::{Hash, Hasher};
    // DefaultHasher::new() uses fixed keys, so ids are stable for the same inputs.
    let mut h = std::collections::hash_map::DefaultHasher::new();
    client.0.hash(&mut h);
    first_epoch_ns.hash(&mut h);
    h.finish()
}

impl Assembler {
    pub fn new(cfg: ExportCfg) -> Assembler {
        Assembler { cfg, pending: BTreeMap::new(), sessions: HashMap::new() }
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
    pub fn sessions_len(&self) -> usize {
        self.sessions.len()
    }

    fn wide(&mut self, bin: u64, client: Addr, stats: &ExportStats) -> &mut Wide {
        if !self.pending.contains_key(&(bin, client.0)) && self.pending.len() >= self.cfg.max_pending {
            if self.pending.pop_first().is_some() {
                stats.pending_overflow.fetch_add(1, Relaxed);
            }
        }
        self.pending.entry((bin, client.0)).or_default()
    }

    /// Volume of a non-media (or unqualified) stream.
    pub fn add(&mut self, b: BinMetrics, stats: &ExportStats) {
        let w = self.wide(b.bin_id, b.client, stats);
        let ci = (b.acct as usize).min(NACCT - 1);
        let v = &mut w.vol[(b.dir & 1) as usize][ci];
        v.pkts += b.pkts as u64;
        v.bytes += b.bytes;
        w.first_us = w.first_us.min(b.first_us);
        w.last_us = w.last_us.max(b.last_us);
    }

    /// One qualified RTP stream in one bin.
    pub fn add_rtp(&mut self, b: RtpBin, stats: &ExportStats) {
        let keep = self.cfg.ssrc_lines;
        let w = self.wide(b.bin_id, b.client, stats);
        let d = (b.dir & 1) as usize;
        let slot = match (b.kind, b.type_byte) {
            (KIND_VIDEO, _) => M_VIDEO,
            (KIND_AUDIO, _) => M_AUDIO,
            (_, 30) => M_SS30,
            _ => M_SS13,
        };
        w.first_us = w.first_us.min(b.first_us);
        w.last_us = w.last_us.max(b.last_us);
        w.media_first_us = w.media_first_us.min(b.first_us);
        w.media_last_us = w.media_last_us.max(b.last_us);
        if keep {
            w.streams.push(b);
        }
        let m = &mut w.media[d][slot];
        m.pkts += b.pkts as u64;
        m.bytes += b.bytes;
        m.retx += b.retx as u64;
        if b.pt == FEC_PT {
            m.fec_pkts += b.pkts as u64;
            m.fec_bytes += b.bytes;
            return;
        }
        m.streams += 1;
        m.frames += b.frames as u64;
        m.rx += b.rx as u64;
        m.lost += b.lost as i64;
        m.stalls += b.stalls as u64;
        merge_welford(&mut m.gap_n, &mut m.gap_mean, &mut m.gap_m2, b.gap_n as u64, b.gap_mean_ms, b.gap_m2);
        m.jit_sum += b.jitter_ms as f64 * b.pkts as f64;
        m.jit_w += b.pkts as f64;
        m.active_secs = m.active_secs.max(b.active_secs);
        if b.kind != KIND_AUDIO {
            let cover = b.last_us.saturating_sub(b.first_us) as f64 / 1e6;
            if cover >= MIN_FPS_COVER_S {
                let fps = b.frames as f64 / cover;
                m.fps_n += 1;
                m.fps_sum += fps;
                if cover >= FULL_BIN_COVER_S {
                    m.full_n += 1;
                    m.full_fps_sum += fps;
                    if fps < DEGRADED_FPS {
                        m.full_below += 1;
                    }
                }
            }
        }
    }

    /// SFU-counter bookkeeping of a flow in one bin.
    pub fn add_sfu(&mut self, b: SfuBin, stats: &ExportStats) {
        let w = self.wide(b.bin_id, b.client, stats);
        let s = &mut w.sfu[(b.dir & 1) as usize];
        s.seen += b.seen as u64;
        s.missed += b.missed as i64;
    }

    /// Format every settled bin (or all, if `force`) as line protocol into
    /// `out`; returns the number of lines written. `epoch_ns(t_us)` converts
    /// pipeline time to Unix nanoseconds.
    pub fn emit_ready(
        &mut self,
        now_us: u64,
        force: bool,
        epoch_ns: &dyn Fn(u64) -> i128,
        out: &mut String,
        stats: &ExportStats,
    ) -> usize {
        let mut lines = 0;
        let bin_s = self.cfg.bin_us as f64 / 1e6;
        while let Some((&(bin, client), _)) = self.pending.first_key_value() {
            let bin_start = bin * self.cfg.bin_us;
            let bin_end = bin_start + self.cfg.bin_us;
            if !force && bin_end + self.cfg.settle_us > now_us {
                break;
            }
            let Some((_, w)) = self.pending.pop_first() else { break };
            let caddr = Addr(client);
            let (sess, n) = self.touch_session(caddr, bin_start, bin_end, &w, epoch_ns, out, stats);
            lines += n;
            lines += write_bin(out, caddr, sess.as_ref(), &w, bin_s, bin_end, epoch_ns(bin_end));
        }
        // close sessions that have had no media for longer than the timeout
        let gap = self.cfg.session_gap_us;
        let stale: Vec<u128> = self
            .sessions
            .iter()
            .filter(|(_, s)| force || now_us.saturating_sub(s.last_media_us) > gap + self.cfg.settle_us)
            .map(|(k, _)| *k)
            .collect();
        for k in stale {
            if let Some(s) = self.sessions.remove(&k) {
                lines += Self::write_summary(Addr(k), &s, epoch_ns, out);
                stats.sessions_closed.fetch_add(1, Relaxed);
            }
        }
        lines
    }

    /// Session rule (thesis section 4.1.1, adapted to media):
    /// * a session belongs to one client IP and starts at the client's first QUALIFIED media
    ///   packet in either direction (type 16/15/13/30 in an RTP-looking stream). Type 21, 10,
    ///   RTCP and unqualified packets never start one. Two clients of one meeting therefore get
    ///   two sessions, each starting at its own first media packet.
    /// * `session_id = hash(client IP, epoch ns of that first packet)`, as in the thesis.
    /// * it ends after `session_gap_us` (120 s, the thesis' SESSION_TIMEOUT) without a media
    ///   packet; the next media packet starts a new session. A bin without media but inside
    ///   the timeout still belongs to the open session.
    #[allow(clippy::too_many_arguments)]
    fn touch_session(
        &mut self,
        client: Addr,
        bin_start: u64,
        bin_end: u64,
        w: &Wide,
        epoch_ns: &dyn Fn(u64) -> i128,
        out: &mut String,
        stats: &ExportStats,
    ) -> (Option<Session>, usize) {
        let mut lines = 0;
        let gap = self.cfg.session_gap_us;
        let has_media = w.has_media();
        if let Some(s) = self.sessions.get(&client.0) {
            let reference = if has_media { w.media_first_us } else { bin_start };
            if reference.saturating_sub(s.last_media_us) > gap {
                if let Some(old) = self.sessions.remove(&client.0) {
                    lines += Self::write_summary(client, &old, epoch_ns, out);
                    stats.sessions_closed.fetch_add(1, Relaxed);
                }
            }
        }
        if has_media && !self.sessions.contains_key(&client.0) {
            let first_epoch_ns = epoch_ns(w.media_first_us);
            self.sessions.insert(
                client.0,
                Session {
                    id: session_id(client, first_epoch_ns),
                    first_us: w.media_first_us,
                    last_media_us: w.media_last_us,
                    first_epoch_ns,
                    bytes_up: 0,
                    bytes_down: 0,
                    bins: 0,
                    media_bins: 0,
                    video_bins: 0,
                    audio_bins: 0,
                    screen_bins: 0,
                    last_summary_us: bin_start,
                },
            );
        }
        let Some(s) = self.sessions.get_mut(&client.0) else { return (None, lines) };
        if has_media {
            s.first_us = s.first_us.min(w.media_first_us);
            s.last_media_us = s.last_media_us.max(w.media_last_us);
            s.media_bins += 1;
            s.video_bins += (w.media[0][M_VIDEO].pkts + w.media[1][M_VIDEO].pkts > 0) as u32;
            s.audio_bins += (w.media[0][M_AUDIO].pkts + w.media[1][M_AUDIO].pkts > 0) as u32;
            s.screen_bins += w.share_active() as u32;
        }
        s.bins += 1;
        for a in 0..NACCT {
            s.bytes_up += w.vol[0][a].bytes;
            s.bytes_down += w.vol[1][a].bytes;
        }
        for m in 0..NMEDIA {
            s.bytes_up += w.media[0][m].bytes;
            s.bytes_down += w.media[1][m].bytes;
        }
        if bin_end.saturating_sub(s.last_summary_us) >= self.cfg.summary_every_us {
            s.last_summary_us = bin_end;
            let snapshot = *s;
            lines += Self::write_summary(client, &snapshot, epoch_ns, out);
        }
        (Some(*s), lines)
    }

    /// `session_summary` is keyed by (client, session_id) and timestamped at
    /// the session's first media packet, so repeated writes overwrite one point.
    /// `start_epoch_ns` / `end_epoch_ns` are the first and last MEDIA packet.
    fn write_summary(client: Addr, s: &Session, epoch_ns: &dyn Fn(u64) -> i128, out: &mut String) -> usize {
        let end_ns = epoch_ns(s.last_media_us);
        let _ = writeln!(
            out,
            "session_summary,client_ip={},session_id=Z_{:016x},platform=zoom start_epoch_ns={}i,end_epoch_ns={}i,duration_s={:.1},bytes_uplink={}i,bytes_downlink={}i,bins={}i,media_bins={}i,video_bins={}i,audio_bins={}i,screen_bins={}i,had_video={}i,had_audio={}i,had_screen={}i {}",
            tag_value(&client.to_string()),
            s.id,
            s.first_epoch_ns,
            end_ns,
            s.last_media_us.saturating_sub(s.first_us) as f64 / 1e6,
            s.bytes_up,
            s.bytes_down,
            s.bins,
            s.media_bins,
            s.video_bins,
            s.audio_bins,
            s.screen_bins,
            (s.video_bins > 0) as u8,
            (s.audio_bins > 0) as u8,
            (s.screen_bins > 0) as u8,
            s.first_epoch_ns
        );
        1
    }
}

// ------------------------------------------------------------- line formatting

/// Thresholds (STAGE2_DESIGN section 1).
const MIN_FPS_COVER_S: f64 = 1.0;
const FULL_BIN_COVER_S: f64 = 4.0;
const DEGRADED_FPS: f64 = 15.0;

/// Comma-separated `name=value` writer for one line-protocol field set.
struct Fields<'a> {
    out: &'a mut String,
    first: bool,
}

impl Fields<'_> {
    fn sep(&mut self) {
        if self.first {
            self.first = false;
        } else {
            self.out.push(',');
        }
    }
    fn f(&mut self, name: &str, v: f64, prec: usize) {
        if v.is_finite() {
            self.sep();
            let _ = write!(self.out, "{name}={v:.prec$}");
        }
    }
    fn i(&mut self, name: &str, v: i64) {
        self.sep();
        let _ = write!(self.out, "{name}={v}i");
    }
}

const DIRS: [&str; 2] = ["uplink", "downlink"];

/// Volume groups written as `<n>_bitrate_<dir>_bps` and `<n>_pps_<dir>`.
///
/// History of the names: the first six existed before Stage 2; their meaning changed
/// in two ways then: video / audio / screen are QUALIFIED media only (the rest of those
/// type bytes is `unq_*`), and `other` does not contain type 21 (`type21`).
/// p7b added `t13_probe` and `t13_ctrl`: the type-13 packets that are not screen-share
/// RTP (sub-type 0x15 = Type-21 probe padding in a Type-13 envelope; every other
/// sub-type except 0x1e = control messages), which p7a still counted inside `unq_screen`.
/// `unq_screen` is now only the RTP-shaped remainder (type 30, and type 13 with sub-type
/// 0x1e, that is not in a qualified stream). The two new names are kept as their own
/// dashboard series on purpose, so the padding can still be watched (the Zoom dashboard's
/// "Screen Share Bitrate" panel shows them).
///
/// Disjoint groups (each packet is in exactly one): video, audio, screen, rtcp, other, nohdr,
/// type21, unq_video, unq_audio, unq_screen, t13_probe, t13_ctrl. `screen13`, `screen30`, `fec`,
/// `nonmedia` and `unq_media` are views over them, never summed with them.
const GROUPS: [&str; 17] = [
    "video", "audio", "screen", "screen13", "screen30", "fec", "rtcp", "other", "nohdr", "type21", "unq_video", "unq_audio", "unq_screen",
    "t13_probe", "t13_ctrl", "nonmedia", "unq_media",
];

fn group(w: &Wide, d: usize, name: &str) -> (u64, u64) {
    let vol = |a: Acct| (w.vol[d][a.idx()].pkts, w.vol[d][a.idx()].bytes);
    let med = |m: usize| (w.media[d][m].pkts, w.media[d][m].bytes);
    let add = |a: (u64, u64), b: (u64, u64)| (a.0 + b.0, a.1 + b.1);
    match name {
        "video" => med(M_VIDEO),
        "audio" => med(M_AUDIO),
        "screen" => add(med(M_SS13), med(M_SS30)),
        "screen13" => med(M_SS13),
        "screen30" => med(M_SS30),
        "fec" => {
            let f = |m: usize| (w.media[d][m].fec_pkts, w.media[d][m].fec_bytes);
            add(add(f(M_VIDEO), f(M_SS13)), f(M_SS30))
        }
        "rtcp" => vol(Acct::Rtcp),
        "other" => vol(Acct::Other),
        "nohdr" => vol(Acct::NoHdr),
        "type21" => vol(Acct::Type21),
        "unq_video" => vol(Acct::UnqVideo),
        "unq_audio" => vol(Acct::UnqAudio),
        "unq_screen" => vol(Acct::UnqScreen),
        "t13_probe" => vol(Acct::T13Probe),
        "t13_ctrl" => vol(Acct::T13Ctrl),
        // everything that is neither media nor type 21: RTCP, other types, no SFU header
        "nonmedia" => add(add(vol(Acct::Rtcp), vol(Acct::Other)), vol(Acct::NoHdr)),
        // media-type packets (13, 15, 16, 30) that are not in a qualified stream. p7b keeps the
        // p7a meaning: the two type-13 buckets that were part of `unq_screen` are added back, so
        // this value is identical to p7a's for the same traffic (a conservation check of the replay).
        "unq_media" => add(
            add(add(vol(Acct::UnqVideo), vol(Acct::UnqAudio)), vol(Acct::UnqScreen)),
            add(vol(Acct::T13Probe), vol(Acct::T13Ctrl)),
        ),
        _ => (0, 0),
    }
}

fn pct(part: i64, rest: u64) -> Option<f64> {
    let p = part.max(0) as u64;
    let den = rest + p;
    (den > 0).then(|| 100.0 * p as f64 / den as f64)
}

/// Write one client-bin: `session_metrics` if the client has an open session, else
/// `client_no_media` (volume only: type 21 and the like, no session to attach it to).
/// Returns the number of lines.
fn write_bin(out: &mut String, client: Addr, sess: Option<&Session>, w: &Wide, bin_s: f64, bin_end_us: u64, ts: i128) -> usize {
    let ip = tag_value(&client.to_string());
    match sess {
        Some(s) => {
            let _ = write!(out, "session_metrics,client_ip={ip},session_id=Z_{:016x},platform=zoom ", s.id);
        }
        None => {
            let _ = write!(out, "client_no_media,client_ip={ip},platform=zoom ");
        }
    }
    let mut f = Fields { out, first: true };
    // ---- totals (UDP payload, the thesis definition) and the per-group volume
    let tot = |d: usize| {
        let mut p = 0u64;
        let mut b = 0u64;
        for a in 0..NACCT {
            p += w.vol[d][a].pkts;
            b += w.vol[d][a].bytes;
        }
        for m in 0..NMEDIA {
            p += w.media[d][m].pkts;
            b += w.media[d][m].bytes;
        }
        (p, b)
    };
    for d in 0..2 {
        f.f(&format!("throughput_{}_bps", DIRS[d]), tot(d).1 as f64 * 8.0 / bin_s, 1);
    }
    for d in 0..2 {
        f.f(&format!("pps_{}", DIRS[d]), tot(d).0 as f64 / bin_s, 2);
    }
    for n in GROUPS {
        for d in 0..2 {
            f.f(&format!("{n}_bitrate_{}_bps", DIRS[d]), group(w, d, n).1 as f64 * 8.0 / bin_s, 1);
        }
        for d in 0..2 {
            f.f(&format!("{n}_pps_{}", DIRS[d]), group(w, d, n).0 as f64 / bin_s, 2);
        }
    }
    let cover = if w.first_us == u64::MAX { 0.0 } else { w.last_us.saturating_sub(w.first_us) as f64 / 1e6 };
    f.f("bin_cover_s", cover, 3);
    let mut lines = 1;
    if let Some(s) = sess {
        // ---- per-stream metrics (RTP)
        f.f("session_age_s", bin_end_us.saturating_sub(s.first_us) as f64 / 1e6, 1);
        let share = w.share_active();
        f.i("share_active", share as i64);
        for d in 0..2 {
            let n = DIRS[d];
            let v = &w.media[d][M_VIDEO];
            let a = &w.media[d][M_AUDIO];
            let (s13, s30) = (&w.media[d][M_SS13], &w.media[d][M_SS30]);
            // video
            f.i(&format!("video_streams_active_{n}"), v.streams as i64);
            f.i(&format!("video_frames_{n}"), v.frames as i64);
            if v.fps_n > 0 {
                f.f(&format!("fps_{n}"), v.fps_sum / v.fps_n as f64, 2);
            }
            if v.gap_n >= 2 {
                f.f(&format!("frame_gap_std_ms_{n}"), (v.gap_m2 / v.gap_n as f64).sqrt(), 3);
            }
            if v.jit_w > 0.0 && v.gap_n > 0 {
                f.f(&format!("jitter_ms_{n}"), v.jit_sum / v.jit_w, 3);
            }
            f.i(&format!("stalls_{n}"), v.stalls as i64);
            f.i(&format!("retransmits_{n}"), (v.retx + a.retx + s13.retx + s30.retx) as i64);
            if v.bytes > 0 {
                f.f(&format!("fec_share_{n}"), v.fec_bytes as f64 / v.bytes as f64, 4);
            }
            // degraded: only judged on full bins and never while a screen share is running
            if !share && v.full_n > 0 {
                f.i(&format!("degraded_{n}"), ((v.full_fps_sum / v.full_n as f64) < DEGRADED_FPS) as i64);
                f.i(&format!("video_streams_degraded_{n}"), v.full_below as i64);
            }
            // loss. Uplink: a skipped sequence number is a lost packet (minus the capture floor, below).
            // Downlink: Zoom's server forwards a subset of frames with the sender's numbering, so gaps are
            // not loss (STAGE2_DESIGN 7.1) and are exported under their own name.
            if let Some(p) = pct(v.lost, v.rx) {
                let (pn, cn, en) = if d == 0 { ("loss_pct", "lost_pkts", "expected_pkts") } else { ("seq_gap_pct", "seq_gap_pkts", "seq_expected_pkts") };
                f.f(&format!("{pn}_{n}"), p, 3);
                f.i(&format!("{cn}_{n}"), v.lost.max(0));
                f.i(&format!("{en}_{n}"), v.lost.max(0) + v.rx as i64);
            }
            // audio
            if a.streams > 0 {
                f.i(&format!("audio_active_s_{n}"), a.active_secs as i64);
                if let Some(p) = pct(a.lost, a.rx) {
                    // over-counts until the type-7 audio layout is parsed (STAGE2_DESIGN 7.3)
                    f.f(&format!("audio_seq_gap_pct_{n}"), p, 3);
                }
            }
            // screen share: type 13 and 30 together (volume split above in screen13 / screen30)
            let (sn, sfps, ssum) = (s13.streams + s30.streams, s13.fps_n + s30.fps_n, s13.fps_sum + s30.fps_sum);
            f.i(&format!("screen_streams_active_{n}"), sn as i64);
            f.i(&format!("screen_frames_{n}"), (s13.frames + s30.frames) as i64);
            if sfps > 0 {
                f.f(&format!("screen_fps_{n}"), ssum / sfps as f64, 2);
            }
            // capture completeness from the SFU counter
            let sf = &w.sfu[d];
            if sf.seen > 0 {
                let name = if d == 0 { "capture_missing" } else { "sfu_gap" };
                if let Some(p) = pct(sf.missed, sf.seen) {
                    f.f(&format!("{name}_pct_{n}"), p, 3);
                    f.i(&format!("{name}_pkts_{n}"), sf.missed.max(0));
                }
            }
        }
    }
    out.push(' ');
    let _ = writeln!(out, "{ts}");
    if sess.is_some() && !w.streams.is_empty() {
        let s = sess.unwrap();
        for b in &w.streams {
            lines += write_stream_line(out, client, s.id, b, bin_s, ts);
        }
    }
    lines
}

/// Optional per-SSRC line (`--ssrc-lines`), STAGE2_DESIGN section 4.
fn write_stream_line(out: &mut String, client: Addr, sid: u64, b: &RtpBin, bin_s: f64, ts: i128) -> usize {
    let stype = match b.kind {
        KIND_VIDEO => "video",
        KIND_AUDIO => "audio",
        _ => "screen",
    };
    let _ = write!(
        out,
        "rtp_stream,client_ip={},session_id=Z_{:016x},ssrc=0x{:08X},stream_type={},direction={},platform=zoom,pt={},type={} ",
        tag_value(&client.to_string()),
        sid,
        b.ssrc,
        stype,
        DIRS[(b.dir & 1) as usize],
        b.pt,
        b.type_byte
    );
    let mut f = Fields { out, first: true };
    f.i("packets", b.pkts as i64);
    f.i("bytes", b.bytes as i64);
    let lost = b.lost.max(0) as i64;
    f.i("lost_packets", lost);
    if let Some(p) = pct(b.lost as i64, b.rx as u64) {
        f.f("loss_pct", p, 3);
    }
    f.f("throughput_bps", b.bytes as f64 * 8.0 / bin_s, 1);
    let cover = b.last_us.saturating_sub(b.first_us) as f64 / 1e6;
    if b.kind != KIND_AUDIO && cover >= MIN_FPS_COVER_S {
        f.f("fps", b.frames as f64 / cover, 2);
    }
    if b.gap_n >= 2 {
        f.f("frame_gap_std_ms", (b.gap_m2 / b.gap_n as f64).sqrt(), 3);
    }
    if b.gap_n > 0 {
        f.f("rfc3550_jitter_ms", b.jitter_ms as f64, 3);
    }
    f.i("stalls", b.stalls as i64);
    f.i("retransmits", b.retx as i64);
    out.push(' ');
    let _ = writeln!(out, "{ts}");
    1
}

/// `capture_health` + per-core lines for one health snapshot.
///
/// Stage 1 added (all integers, so existing `capture_health` points are
/// unaffected): the RTP self-check `rtp_ok_<type>` / `rtp_bad_<type>` /
/// `rtp_short`, and the on-disk capture counters `pcap_*`, `csv_*`,
/// `file_io_errors`, `capture_limit_tripped`, `capture_disk_bytes`.
/// p7a added `video_layout_02` / `video_layout_0a` / `video_layout_other`: unique
/// type-16 packets by media byte 20 (0x02 = RTP at +24, 0x0a = RTP at +28, other =
/// never seen so far; `video_layout_other` should stay 0).
/// p7b added `video_layout_rtp20` (byte 20 in 0x80-0xBF, RTP at +20; integer, so existing
/// points are unaffected) and `video_rtp20_bytes`, a STRING field listing the exact byte
/// values behind it (`"90"`, `"80,90"`, `"-"` = none yet). A string rather than an integer
/// mask because a mask with bit 63 set does not fit InfluxDB's signed 64-bit integers.
/// `report::rtp20_bytes` or `-` when no byte value has been seen (an empty string field is avoided).
fn rtp20_bytes_or_dash(mask: u64) -> String {
    if mask == 0 {
        "-".to_string()
    } else {
        crate::report::rtp20_bytes(mask)
    }
}

pub fn health_lines(h: &HealthSnapshot, st: &ExportStats, host: &str, ts_ns: i128, out: &mut String) -> usize {
    let host = tag_value(host);
    let _ = write!(
        out,
        "capture_health,host={host},engine=zoom pkts_in={}i,parse_fail={}i,port_filtered={}i,ip_filtered={}i,zoom_like_unlisted={}i,\
dups_dropped={}i,dup_ttl_same={}i,dup_ttl_off1={}i,dup_ttl_other={}i,dup_id_same={}i,matched={}i,matched_bytes={}i,no_sfu={}i,\
streams_rejected={}i,streams_evicted={}i,streams_active={}i,bins_emitted={}i,bins_dropped={}i,poison_recovered={}i,dump_dropped={}i,\
export_lines_ok={}i,export_lines_dropped={}i,export_batches_ok={}i,export_batches_failed={}i,export_retries={}i,export_pending_overflow={}i,sessions_closed={}i,\
rtp_streams_active={}i,rtp_streams_rejected={}i,rtp_qualified={}i,rtp_failed_qual={}i,rtp_probation_skipped={}i,sfu_flows_active={}i,hub_bins_dropped={}i",
        h.pkts_in, h.parse_fail, h.port_filtered, h.ip_filtered, h.zoom_like_unlisted,
        h.dups_dropped, h.dup_ttl_same, h.dup_ttl_off1, h.dup_ttl_other, h.dup_id_same, h.matched, h.matched_bytes, h.no_sfu,
        h.streams_rejected, h.streams_evicted, h.streams_active, h.bins_emitted, h.bins_dropped, h.poison_recovered, h.dump_dropped,
        st.lines_ok.load(Relaxed), st.lines_dropped.load(Relaxed), st.batches_ok.load(Relaxed), st.batches_failed.load(Relaxed),
        st.retries.load(Relaxed), st.pending_overflow.load(Relaxed), st.sessions_closed.load(Relaxed),
        h.rtp_streams_active, h.rtp_streams_rejected, h.rtp_qualified, h.rtp_failed_qual, h.rtp_probation_skipped, h.sfu_flows_active, h.hub_bins_dropped,
    );
    for (k, name) in crate::headers::RTP_SLOT_NAMES.iter().enumerate() {
        let _ = write!(out, ",rtp_ok_{name}={}i,rtp_bad_{name}={}i", h.rtp_ok[k], h.rtp_bad[k]);
    }
    let _ = writeln!(
        out,
        ",rtp_short={}i,video_layout_02={}i,video_layout_0a={}i,video_layout_rtp20={}i,video_layout_other={}i,video_rtp20_bytes=\"{}\",pcap_pkts={}i,pcap_bytes={}i,pcap_files={}i,pcap_drop_pool={}i,pcap_drop_queue={}i,pcap_drop_limit={}i,\
csv_rows={}i,csv_bytes={}i,csv_files={}i,csv_drop_limit={}i,file_io_errors={}i,capture_limit_tripped={}i,capture_disk_bytes={}i {ts_ns}",
        h.rtp_short, h.video_layout[0], h.video_layout[1], h.video_layout[VLAYOUT_SLOT_RTP20], h.video_layout[VLAYOUT_SLOT_OTHER], rtp20_bytes_or_dash(h.video_rtp20_mask), h.pcap_pkts, h.pcap_bytes, h.pcap_files, h.pcap_drop_pool, h.pcap_drop_queue, h.pcap_drop_limit,
        h.csv_rows, h.csv_bytes, h.csv_files, h.csv_drop_limit, h.file_io_errors, h.capture_limit_tripped, h.capture_disk_bytes,
    );
    let mut n = 1;
    for (i, (pi, di)) in h.per_core_in.iter().zip(h.per_core_dups.iter()).enumerate() {
        let _ = writeln!(out, "capture_health_core,host={host},engine=zoom,core={i} pkts_in={pi}i,dups_dropped={di}i {ts_ns}");
        n += 1;
    }
    n
}

// ----------------------------------------------------------------- exporter

fn epoch_offset_ns(start: Instant) -> i128 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as i128;
    now - start.elapsed().as_nanos() as i128
}

fn deliver(sink: &mut dyn Sink, body: &str, lines: usize, cfg: &ExportCfg, st: &ExportStats, last_log: &mut Option<Instant>) {
    let mut backoff = cfg.backoff_start;
    for attempt in 0..=cfg.retries {
        match sink.send(body) {
            Ok(()) => {
                st.lines_ok.fetch_add(lines as u64, Relaxed);
                st.batches_ok.fetch_add(1, Relaxed);
                return;
            }
            Err(e) if e.retryable && attempt < cfg.retries => {
                st.retries.fetch_add(1, Relaxed);
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(cfg.backoff_max);
            }
            Err(e) => {
                st.batches_failed.fetch_add(1, Relaxed);
                st.lines_dropped.fetch_add(lines as u64, Relaxed);
                if last_log.map_or(true, |t| t.elapsed() > Duration::from_secs(30)) {
                    eprintln!("[zoom_capture] export failed, dropped {lines} lines after {} attempt(s): {}", attempt + 1, e.msg);
                    *last_log = Some(Instant::now());
                }
                return;
            }
        }
    }
}

/// Run until `Shutdown` (or all senders gone). `start` must be the
/// pipeline's monotonic zero.
pub fn run_exporter(rx: Receiver<ExportMsg>, sink: Box<dyn Sink>, cfg: ExportCfg, start: Instant, stats: Arc<ExportStats>) {
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(move || start.elapsed().as_micros() as u64);
    run_exporter_clocked(rx, sink, cfg, start, stats, clock)
}

/// Same, with an injectable pipeline-time clock (microseconds). Used by the
/// compressed-time soak test; production passes the real monotonic clock.
pub fn run_exporter_clocked(
    rx: Receiver<ExportMsg>,
    mut sink: Box<dyn Sink>,
    cfg: ExportCfg,
    start: Instant,
    stats: Arc<ExportStats>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
) {
    let mut asm = Assembler::new(cfg.clone());
    let mut out = String::with_capacity(1 << 20);
    let mut lines = 0usize;
    let mut last_flush = Instant::now();
    let mut last_log = None;
    let mut shutdown = false;

    loop {
        let first = rx.recv_timeout(Duration::from_millis(200));
        let mut msgs = Vec::new();
        match first {
            Ok(m) => msgs.push(m),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => shutdown = true,
        }
        // drain what is already queued, without waiting
        while msgs.len() < 20_000 {
            match rx.try_recv() {
                Ok(m) => msgs.push(m),
                Err(_) => break,
            }
        }
        let off = epoch_offset_ns(start);
        let epoch = move |t_us: u64| off + t_us as i128 * 1000;
        for m in msgs {
            match m {
                ExportMsg::Bin(b) => asm.add(b, &stats),
                ExportMsg::Rtp(b) => asm.add_rtp(b, &stats),
                ExportMsg::Sfu(b) => asm.add_sfu(b, &stats),
                ExportMsg::Health(h) => {
                    lines += health_lines(&h, &stats, &cfg.host, epoch(h.t_us), &mut out);
                }
                ExportMsg::Shutdown => shutdown = true,
            }
        }
        let now_us = clock();
        lines += asm.emit_ready(now_us, shutdown, &epoch, &mut out, &stats);

        if lines > 0 && (lines >= cfg.batch_max_lines || last_flush.elapsed() >= cfg.flush_every || shutdown) {
            deliver(sink.as_mut(), &out, lines, &cfg, &stats, &mut last_log);
            out.clear();
            lines = 0;
            last_flush = Instant::now();
        }
        if shutdown {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{KIND_SCREEN};

    const BIN: u64 = 5_000_000;

    fn bm(client_n: u8, bin: u64, acct: Acct, dir: u8, pkts: u32, bytes: u64) -> BinMetrics {
        BinMetrics {
            client: Addr::from_v4([10, 0, 0, client_n]),
            bin_id: bin,
            acct: acct as u8,
            dir,
            client_port: 1,
            server_port: 8801,
            pkts,
            bytes,
            first_us: bin * BIN + 100_000,
            last_us: bin * BIN + 4_900_000,
        }
    }

    /// A qualified RTP stream record with sensible defaults; override fields with struct update syntax.
    fn rb(client_n: u8, bin: u64, kind: u8, type_byte: u8, dir: u8, pt: u8, pkts: u32, bytes: u64) -> RtpBin {
        RtpBin {
            client: Addr::from_v4([10, 0, 0, client_n]),
            bin_id: bin,
            dir,
            kind,
            type_byte,
            pt,
            ssrc: 0x1000_0000 + client_n as u32 * 16 + dir as u32,
            pkts,
            bytes,
            first_us: bin * BIN + 100_000,
            last_us: bin * BIN + 4_900_000,
            frames: 0,
            rx: pkts,
            lost: 0,
            retx: 0,
            gap_n: 0,
            gap_mean_ms: 0.0,
            gap_m2: 0.0,
            stalls: 0,
            jitter_ms: 0.0,
            active_secs: 0,
        }
    }

    fn epoch(t: u64) -> i128 {
        1_700_000_000_000_000_000 + t as i128 * 1000
    }

    fn run(a: &mut Assembler, st: &ExportStats) -> String {
        let mut out = String::new();
        a.emit_ready(u64::MAX / 4, false, &epoch, &mut out, st);
        out
    }

    fn line<'a>(out: &'a str, prefix: &str, client_n: u8) -> &'a str {
        let ip = format!("client_ip=10.0.0.{client_n},");
        out.lines().find(|l| l.starts_with(prefix) && l.contains(&ip)).unwrap_or_else(|| panic!("no {prefix} line for client {client_n} in:\n{out}"))
    }

    fn field(l: &str, name: &str) -> Option<f64> {
        let fields = l.split(' ').nth(1)?;
        fields.split(',').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == name).then(|| v.trim_end_matches('i').parse().ok()).flatten()
        })
    }

    #[test]
    fn volume_and_qualified_media_from_different_streams_merge_into_one_point() {
        let st = ExportStats::default();
        let mut a = Assembler::new(ExportCfg::default());
        a.add_rtp(rb(1, 7, KIND_VIDEO, 16, 0, 98, 100, 100_000), &st);
        a.add_rtp(rb(1, 7, KIND_AUDIO, 15, 0, 113, 50, 5_000), &st);
        a.add_rtp(rb(1, 7, KIND_VIDEO, 16, 1, 98, 400, 500_000), &st);
        a.add(bm(1, 7, Acct::Type21, 1, 50, 52_000), &st);
        a.add(bm(2, 7, Acct::Other, 1, 10, 1_000), &st); // a second client with no media at all
        let out = run(&mut a, &st);
        let l1 = line(&out, "session_metrics", 1);
        // (100_000 + 5_000) B * 8 / 5 s = 168000 bps up; (500_000 + 52_000) * 8 / 5 = 883200 down
        assert_eq!(field(l1, "throughput_uplink_bps"), Some(168_000.0), "{l1}");
        assert_eq!(field(l1, "throughput_downlink_bps"), Some(883_200.0), "{l1}");
        assert_eq!(field(l1, "video_bitrate_uplink_bps"), Some(160_000.0), "{l1}");
        assert_eq!(field(l1, "audio_bitrate_uplink_bps"), Some(8_000.0), "{l1}");
        assert_eq!(field(l1, "pps_uplink"), Some(30.0), "{l1}");
        assert_eq!(field(l1, "pps_downlink"), Some(90.0), "{l1}");
        assert_eq!(field(l1, "bin_cover_s"), Some(4.8), "{l1}");
        // the type 21 packets are their own metric, not video and not "other"
        assert_eq!(field(l1, "type21_pps_downlink"), Some(10.0), "{l1}");
        assert_eq!(field(l1, "type21_bitrate_downlink_bps"), Some(83_200.0), "{l1}");
        assert_eq!(field(l1, "nonmedia_pps_downlink"), Some(0.0), "{l1}");
        assert_eq!(field(l1, "other_pps_downlink"), Some(0.0), "{l1}");
        // timestamp = end of bin 7 = 40 s
        assert!(l1.ends_with(&format!(" {}", epoch(40_000_000))), "{l1}");
        // the client with only a non-media packet type has no session
        assert!(out.lines().any(|l| l.starts_with("client_no_media") && l.contains("client_ip=10.0.0.2,")), "{out}");
        assert_eq!(out.lines().filter(|l| l.starts_with("session_metrics")).count(), 1, "{out}");
    }

    #[test]
    fn type21_and_nonmedia_non21_pps_are_separate_and_partition_the_total() {
        let st = ExportStats::default();
        let mut a = Assembler::new(ExportCfg::default());
        a.add(bm(1, 0, Acct::Type21, 0, 1000, 1_044_000), &st); // 200 pps of 1,044 B probe packets
        a.add(bm(1, 0, Acct::Other, 1, 25, 1_750), &st); // type 10 feedback etc.
        a.add(bm(1, 0, Acct::Rtcp, 1, 5, 500), &st);
        a.add(bm(1, 0, Acct::NoHdr, 0, 15, 4_500), &st);
        a.add(bm(1, 0, Acct::UnqScreen, 1, 100, 100_000), &st);
        a.add_rtp(rb(1, 0, KIND_VIDEO, 16, 0, 98, 150, 150_000), &st); // gives the client a session
        let out = run(&mut a, &st);
        let l = line(&out, "session_metrics", 1);
        assert_eq!(field(l, "type21_pps_uplink"), Some(200.0), "{l}");
        // nonmedia = other + rtcp + nohdr (none of them type 21, none of them media-typed)
        assert_eq!(field(l, "nonmedia_pps_uplink"), Some(3.0), "{l}");
        assert_eq!(field(l, "nonmedia_pps_downlink"), Some(6.0), "{l}");
        assert_eq!(field(l, "unq_screen_pps_downlink"), Some(20.0), "{l}");
        assert_eq!(field(l, "unq_media_pps_downlink"), Some(20.0), "{l}");
        // every packet is in exactly one group: total pps = sum of the disjoint groups
        for d in ["uplink", "downlink"] {
            let sum: f64 = ["video", "audio", "screen", "rtcp", "other", "nohdr", "type21", "unq_video", "unq_audio", "unq_screen", "t13_probe", "t13_ctrl"]
                .iter()
                .map(|n| field(l, &format!("{n}_pps_{d}")).unwrap())
                .sum();
            assert!((sum - field(l, &format!("pps_{d}")).unwrap()).abs() < 1e-9, "{d}: groups {sum} vs total in {l}");
        }
    }

    #[test]
    fn type13_probe_and_ctrl_are_their_own_groups_and_unq_media_keeps_its_p7a_meaning() {
        let st = ExportStats::default();
        let mut a = Assembler::new(ExportCfg::default());
        a.add(bm(1, 0, Acct::T13Probe, 0, 1000, 1_085_000), &st); // 200 pps of 1,085 B (1,078 B probe + 7 B envelope)
        a.add(bm(1, 0, Acct::T13Ctrl, 0, 50, 35_650), &st); // control messages, median 713 B
        a.add(bm(1, 0, Acct::UnqScreen, 0, 25, 27_000), &st); // RTP-shaped screen packets still on probation
        a.add(bm(1, 0, Acct::UnqVideo, 1, 5, 6_000), &st);
        a.add_rtp(rb(1, 0, KIND_VIDEO, 16, 0, 98, 150, 150_000), &st); // gives the client a session
        let out = run(&mut a, &st);
        let l = line(&out, "session_metrics", 1);
        assert_eq!(field(l, "t13_probe_pps_uplink"), Some(200.0), "{l}");
        assert_eq!(field(l, "t13_probe_bitrate_uplink_bps"), Some(1_085_000.0 * 8.0 / 5.0), "{l}");
        assert_eq!(field(l, "t13_ctrl_pps_uplink"), Some(10.0), "{l}");
        assert_eq!(field(l, "unq_screen_pps_uplink"), Some(5.0), "{l}");
        // none of the three is screen share
        assert_eq!(field(l, "screen_pps_uplink"), Some(0.0), "{l}");
        assert_eq!(field(l, "share_active"), Some(0.0), "{l}");
        // p7a counted all three in unq_screen; unq_media is the p7a number: 200 + 10 + 5 uplink, 1 downlink
        assert_eq!(field(l, "unq_media_pps_uplink"), Some(215.0), "{l}");
        assert_eq!(field(l, "unq_media_pps_downlink"), Some(1.0), "{l}");
        assert_eq!(
            field(l, "unq_media_bitrate_uplink_bps"),
            Some((1_085_000.0 + 35_650.0 + 27_000.0) * 8.0 / 5.0),
            "{l}"
        );
        // and the disjoint groups still add up to the total (the partition identity)
        for d in ["uplink", "downlink"] {
            let sum: f64 = ["video", "audio", "screen", "rtcp", "other", "nohdr", "type21", "unq_video", "unq_audio", "unq_screen", "t13_probe", "t13_ctrl"]
                .iter()
                .map(|n| field(l, &format!("{n}_pps_{d}")).unwrap())
                .sum();
            assert!((sum - field(l, &format!("pps_{d}")).unwrap()).abs() < 1e-9, "{d}: groups {sum} vs total in {l}");
        }
    }

    #[test]
    fn session_starts_at_the_first_media_packet_of_each_client_independently() {
        let st = ExportStats::default();
        let mut a = Assembler::new(ExportCfg::default());
        // same meeting: client 1 starts sending audio 1.2 s into bin 2, client 2 only receives video 3.7 s into bin 3
        let mut a1 = rb(1, 2, KIND_AUDIO, 15, 0, 113, 40, 8_000);
        a1.first_us = 2 * BIN + 1_200_000;
        let mut v2 = rb(2, 3, KIND_VIDEO, 16, 1, 98, 60, 70_000);
        v2.first_us = 3 * BIN + 3_700_000;
        a.add_rtp(a1, &st);
        a.add_rtp(v2, &st);
        // client 1 also had type-21 traffic in bin 1, before any media: it must not start a session
        a.add(bm(1, 1, Acct::Type21, 0, 500, 522_000), &st);
        let mut out = String::new();
        a.emit_ready(u64::MAX / 4, true, &epoch, &mut out, &st);
        let starts: Vec<(String, i128)> = out
            .lines()
            .filter(|l| l.starts_with("session_summary"))
            .map(|l| (l.split(',').nth(1).unwrap().to_string(), field(l, "start_epoch_ns").unwrap() as i128))
            .collect();
        assert_eq!(starts.len(), 2, "{out}");
        let s1 = starts.iter().find(|(c, _)| c == "client_ip=10.0.0.1").unwrap().1;
        let s2 = starts.iter().find(|(c, _)| c == "client_ip=10.0.0.2").unwrap().1;
        assert_eq!(s1, epoch(2 * BIN + 1_200_000), "client 1 starts at its first audio packet, not at its type-21 bin");
        assert_eq!(s2, epoch(3 * BIN + 3_700_000), "client 2 starts at its own first media packet");
        // the type-21-only bin 1 of client 1 is not a session line
        let nm = out.lines().filter(|l| l.starts_with("client_no_media")).count();
        assert_eq!(nm, 1, "{out}");
        // different clients, different ids
        let ids: std::collections::HashSet<&str> = out.lines().filter(|l| l.starts_with("session_summary")).map(|l| l.split(',').nth(2).unwrap()).collect();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn session_ends_after_120s_without_media_and_a_new_one_starts_with_the_next_media_packet() {
        let st = ExportStats::default();
        let cfg = ExportCfg::default();
        let gap_bins = cfg.session_gap_us / cfg.bin_us; // 24 bins = 120 s
        let mut a = Assembler::new(cfg);
        a.add_rtp(rb(1, 0, KIND_VIDEO, 16, 0, 98, 10, 1_000), &st);
        a.add_rtp(rb(1, 1, KIND_VIDEO, 16, 0, 98, 10, 1_000), &st);
        // type 21 keeps flowing for 2+ minutes with NO media: not media, so it neither extends nor keeps the session
        for b in 2..(2 + gap_bins + 6) {
            a.add(bm(1, b, Acct::Type21, 0, 100, 104_400), &st);
        }
        let resume = 2 + gap_bins + 6;
        a.add_rtp(rb(1, resume, KIND_VIDEO, 16, 0, 98, 10, 1_000), &st);
        let mut out = String::new();
        // "now" just after the last bin has settled: the second session is still open (it had media a moment ago)
        let now = (resume + 1) * BIN + ExportCfg::default().settle_us + 1;
        a.emit_ready(now, false, &epoch, &mut out, &st);
        // session_summary is an upsert: several lines with the same session_id (periodic refreshes) are normal;
        // what matters is the number of DISTINCT sessions and the content of the last line of each
        let sums: Vec<&str> = out.lines().filter(|l| l.starts_with("session_summary")).collect();
        let sid = |l: &str| l.split(',').nth(2).unwrap().to_string();
        let ids: std::collections::BTreeSet<String> = sums.iter().map(|l| sid(l)).collect();
        assert_eq!(ids.len(), 1, "the first session must have been closed when the next media arrived, the next one is still open:\n{out}");
        let first = sums.iter().rev().find(|l| sid(l) == *ids.iter().next().unwrap()).unwrap();
        assert_eq!(field(first, "media_bins"), Some(2.0), "{first}");
        // it ended at its last media packet (bin 1, 4.9 s into it), not 120 s later
        assert_eq!(field(first, "end_epoch_ns"), Some((epoch(BIN + 4_900_000)) as f64), "{first}");
        // inside the grace period the type-21 bins still belong to the open session; after it they are "no media"
        let in_session = out.lines().filter(|l| l.starts_with("session_metrics")).count();
        let no_media = out.lines().filter(|l| l.starts_with("client_no_media")).count();
        assert_eq!(in_session + no_media, 2 + (gap_bins as usize + 6) + 1, "every bin written once:\n{out}");
        assert!(no_media >= 5 && no_media <= 7, "no_media={no_media}\n{out}");
        let mut out2 = String::new();
        a.emit_ready(u64::MAX / 4, true, &epoch, &mut out2, &st);
        assert!(out2.contains("session_summary"), "second session closes at shutdown");
        assert_eq!(st.sessions_closed.load(Relaxed), 2);
    }

    #[test]
    fn screen_13_and_30_are_aggregated_and_shown_separately_and_unqualified_packets_are_not_screen() {
        let st = ExportStats::default();
        let mut a = Assembler::new(ExportCfg::default());
        let mut s13 = rb(1, 0, KIND_SCREEN, 13, 0, 99, 200, 200_000);
        s13.frames = 40;
        let mut s30 = rb(1, 0, KIND_SCREEN, 30, 0, 99, 100, 120_000);
        s30.frames = 20;
        s30.ssrc = 0x2000_0001;
        a.add_rtp(s13, &st);
        a.add_rtp(s30, &st);
        a.add(bm(1, 0, Acct::T13Probe, 0, 1000, 1_051_000), &st); // type-13 probe padding: 1,051 B packets
        let out = run(&mut a, &st);
        let l = line(&out, "session_metrics", 1);
        assert_eq!(field(l, "screen13_pps_uplink"), Some(40.0), "{l}");
        assert_eq!(field(l, "screen30_pps_uplink"), Some(20.0), "{l}");
        assert_eq!(field(l, "screen_pps_uplink"), Some(60.0), "13 + 30 counted together: {l}");
        assert_eq!(field(l, "screen_bitrate_uplink_bps"), Some((200_000.0 + 120_000.0) * 8.0 / 5.0), "{l}");
        assert_eq!(field(l, "screen_streams_active_uplink"), Some(2.0), "{l}");
        assert_eq!(field(l, "share_active"), Some(1.0), "{l}");
        // the probe packets are visible, but not as screen share (p7a showed them as unq_screen)
        assert_eq!(field(l, "t13_probe_pps_uplink"), Some(200.0), "{l}");
        assert_eq!(field(l, "t13_probe_bitrate_uplink_bps"), Some(1_051_000.0 * 8.0 / 5.0), "{l}");
        assert_eq!(field(l, "unq_screen_pps_uplink"), Some(0.0), "{l}");
        // FPS of the share: each stream covers 4.8 s: 40/4.8 and 20/4.8, mean of the two
        let want = (40.0 / 4.8 + 20.0 / 4.8) / 2.0;
        assert!((field(l, "screen_fps_uplink").unwrap() - want).abs() < 0.01, "{l}");
        // and the summary says the session had a share
        // (run() used a "now" far in the future, so the session was already closed and summarised there)
        assert_eq!(field(out.lines().find(|l| l.starts_with("session_summary")).unwrap(), "had_screen"), Some(1.0), "{out}");
    }

    #[test]
    fn fps_loss_stalls_jitter_and_degraded_are_computed_from_the_stream_records() {
        let st = ExportStats::default();
        let mut a = Assembler::new(ExportCfg::default());
        // uplink camera: 150 frames in 4.9 s (30.6 FPS), 3 of 1,003 packets lost, 2 stalls, 7 retransmissions
        let mut up = rb(1, 3, KIND_VIDEO, 16, 0, 98, 1000, 1_200_000);
        up.frames = 150;
        up.rx = 1000;
        up.lost = 3;
        up.stalls = 2;
        up.retx = 7;
        up.first_us = 3 * BIN;
        up.last_us = 3 * BIN + 4_900_000;
        // gaps: 3 values 30, 30, 30 ms -> mean 30, sigma 0 ; 3 more of 60 -> pooled below
        up.gap_n = 3;
        up.gap_mean_ms = 30.0;
        up.gap_m2 = 0.0;
        up.jitter_ms = 2.0;
        // a FEC companion (PT 110) of the same stream: counted in bytes, never in loss / frames
        let mut fec = rb(1, 3, KIND_VIDEO, 16, 0, 110, 100, 130_000);
        fec.ssrc = 0x1000_0099;
        fec.lost = 999; // must be ignored
        fec.frames = 77; // must be ignored
        // downlink: a degraded camera (10 FPS on a full bin) with sequence gaps
        let mut dn = rb(1, 3, KIND_VIDEO, 16, 1, 98, 300, 360_000);
        dn.frames = 49;
        dn.rx = 300;
        dn.lost = 100;
        dn.first_us = 3 * BIN;
        dn.last_us = 3 * BIN + 4_900_000;
        a.add_rtp(up, &st);
        a.add_rtp(fec, &st);
        a.add_rtp(dn, &st);
        let out = run(&mut a, &st);
        let l = line(&out, "session_metrics", 1);
        assert!((field(l, "fps_uplink").unwrap() - 150.0 / 4.9).abs() < 0.01, "{l}");
        assert!((field(l, "fps_downlink").unwrap() - 10.0).abs() < 0.01, "{l}");
        assert_eq!(field(l, "degraded_uplink"), Some(0.0), "{l}");
        assert_eq!(field(l, "degraded_downlink"), Some(1.0), "{l}");
        assert_eq!(field(l, "video_streams_degraded_downlink"), Some(1.0), "{l}");
        // uplink loss = 3 / (1000 + 3); FEC ignored
        assert!((field(l, "loss_pct_uplink").unwrap() - 100.0 * 3.0 / 1003.0).abs() < 1e-3, "{l}");
        assert_eq!(field(l, "lost_pkts_uplink"), Some(3.0), "{l}");
        // downlink gaps are NOT called loss
        assert!(field(l, "loss_pct_downlink").is_none(), "{l}");
        assert!((field(l, "seq_gap_pct_downlink").unwrap() - 25.0).abs() < 1e-3, "{l}");
        assert_eq!(field(l, "stalls_uplink"), Some(2.0), "{l}");
        assert_eq!(field(l, "retransmits_uplink"), Some(7.0), "{l}");
        assert_eq!(field(l, "video_frames_uplink"), Some(150.0), "FEC frames must not count: {l}");
        assert!((field(l, "fec_share_uplink").unwrap() - 130_000.0 / 1_330_000.0).abs() < 1e-4, "{l}");
        assert_eq!(field(l, "jitter_ms_uplink"), Some(2.0), "{l}");
        assert_eq!(field(l, "frame_gap_std_ms_uplink"), Some(0.0), "{l}");
        assert_eq!(field(l, "video_streams_active_uplink"), Some(1.0), "the FEC record is not a second video: {l}");
    }

    #[test]
    fn degraded_is_not_judged_while_a_screen_share_runs() {
        let st = ExportStats::default();
        let mut a = Assembler::new(ExportCfg::default());
        let mut cam = rb(1, 0, KIND_VIDEO, 16, 0, 98, 60, 80_000);
        cam.frames = 54; // 11 FPS: Zoom lowered the camera on purpose while sharing
        let mut share = rb(1, 0, KIND_SCREEN, 13, 0, 99, 300, 300_000);
        share.frames = 20;
        a.add_rtp(cam, &st);
        a.add_rtp(share, &st);
        let out = run(&mut a, &st);
        let l = line(&out, "session_metrics", 1);
        assert_eq!(field(l, "share_active"), Some(1.0), "{l}");
        assert!(field(l, "degraded_uplink").is_none(), "no verdict during a share: {l}");
        assert!((field(l, "fps_uplink").unwrap() - 54.0 / 4.8).abs() < 0.01, "the dip itself stays visible: {l}");
    }

    #[test]
    fn partial_bins_use_covered_time_for_fps_and_are_never_judged() {
        let st = ExportStats::default();
        let mut a = Assembler::new(ExportCfg::default());
        // a call that ends 2 s into the bin: 60 frames in 2.0 s = 30 FPS (dividing by 5 would say 12)
        let mut v = rb(1, 0, KIND_VIDEO, 16, 0, 98, 180, 200_000);
        v.frames = 60;
        v.first_us = 100_000;
        v.last_us = 2_100_000;
        a.add_rtp(v, &st);
        let l = run(&mut a, &st);
        let l = line(&l, "session_metrics", 1);
        assert!((field(l, "fps_uplink").unwrap() - 30.0).abs() < 1e-9, "{l}");
        assert!(field(l, "degraded_uplink").is_none(), "{l}");
    }

    #[test]
    fn pooled_welford_equals_the_direct_computation() {
        let xs = [30.0, 31.0, 33.0, 29.0, 60.0, 61.0, 34.0, 33.0, 200.0, 32.0];
        let direct = |v: &[f64]| {
            let n = v.len() as f64;
            let m = v.iter().sum::<f64>() / n;
            (n as u64, m, v.iter().map(|x| (x - m) * (x - m)).sum::<f64>())
        };
        let (mut n, mut mean, mut m2) = (0u64, 0.0, 0.0);
        for part in [&xs[..3], &xs[3..4], &xs[4..]] {
            let (bn, bm_, bm2) = direct(part);
            merge_welford(&mut n, &mut mean, &mut m2, bn, bm_, bm2);
        }
        let (dn, dm, dm2) = direct(&xs);
        assert_eq!(n, dn);
        assert!((mean - dm).abs() < 1e-9 && (m2 - dm2).abs() < 1e-6, "{mean} {m2} vs {dm} {dm2}");
    }

    #[test]
    fn capture_floor_comes_from_the_sfu_counter() {
        let st = ExportStats::default();
        let mut a = Assembler::new(ExportCfg::default());
        a.add_rtp(rb(1, 0, KIND_VIDEO, 16, 0, 98, 10, 1_000), &st);
        a.add_sfu(SfuBin { client: Addr::from_v4([10, 0, 0, 1]), bin_id: 0, dir: 0, seen: 950, missed: 50 }, &st);
        a.add_sfu(SfuBin { client: Addr::from_v4([10, 0, 0, 1]), bin_id: 0, dir: 1, seen: 800, missed: 0 }, &st);
        let out = run(&mut a, &st);
        let l = line(&out, "session_metrics", 1);
        assert!((field(l, "capture_missing_pct_uplink").unwrap() - 5.0).abs() < 1e-9, "{l}");
        assert_eq!(field(l, "capture_missing_pkts_uplink"), Some(50.0), "{l}");
        assert_eq!(field(l, "sfu_gap_pct_downlink"), Some(0.0), "{l}");
    }

    #[test]
    fn ssrc_lines_only_when_asked() {
        let st = ExportStats::default();
        let mk = |on: bool| {
            let mut a = Assembler::new(ExportCfg { ssrc_lines: on, ..Default::default() });
            let mut v = rb(1, 0, KIND_VIDEO, 16, 0, 98, 150, 150_000);
            v.frames = 120;
            v.ssrc = 0xDEAD_BEEF;
            a.add_rtp(v, &st);
            run(&mut a, &st)
        };
        assert!(!mk(false).contains("rtp_stream"));
        let out = mk(true);
        let l = out.lines().find(|l| l.starts_with("rtp_stream")).expect("stream line");
        assert!(l.contains("ssrc=0xDEADBEEF,stream_type=video,direction=uplink,platform=zoom,pt=98,type=16 "), "{l}");
        assert_eq!(field(l, "packets"), Some(150.0));
    }

    #[test]
    fn a_bin_is_held_until_it_has_settled() {
        let st = ExportStats::default();
        let mut a = Assembler::new(ExportCfg::default());
        a.add(bm(1, 0, Acct::Other, 0, 1, 1), &st);
        let mut out = String::new();
        // bin 0 ends at 5 s; settle 3 s -> not before 8 s
        a.emit_ready(7_999_999, false, &epoch, &mut out, &st);
        assert!(out.is_empty());
        a.emit_ready(8_000_000, false, &epoch, &mut out, &st);
        assert!(out.contains("client_no_media"));
        assert_eq!(a.pending_len(), 0);
    }

    #[test]
    fn late_contribution_after_emit_becomes_its_own_point_not_a_panic() {
        let st = ExportStats::default();
        let mut a = Assembler::new(ExportCfg::default());
        a.add_rtp(rb(1, 0, KIND_VIDEO, 16, 0, 98, 1, 1), &st);
        let mut out = String::new();
        a.emit_ready(10_000_000, false, &epoch, &mut out, &st);
        a.add_rtp(rb(1, 0, KIND_AUDIO, 15, 0, 113, 1, 1), &st); // straggler for the same bin
        a.emit_ready(11_000_000, false, &epoch, &mut out, &st);
        assert_eq!(out.lines().filter(|l| l.starts_with("session_metrics")).count(), 2);
    }

    #[test]
    fn pending_is_capped_and_overflow_counted() {
        let st = ExportStats::default();
        let mut a = Assembler::new(ExportCfg { max_pending: 10, ..Default::default() });
        for i in 0..50u8 {
            a.add(bm(i, 0, Acct::Other, 0, 1, 1), &st);
        }
        assert_eq!(a.pending_len(), 10);
        assert_eq!(st.pending_overflow.load(Relaxed), 40);
    }

    #[test]
    fn tag_escaping() {
        assert_eq!(tag_value("a b,c=d"), "a\\ b\\,c\\=d");
        let st = ExportStats::default();
        let mut out = String::new();
        let h = HealthSnapshot { per_core_in: vec![5, 6], per_core_dups: vec![1, 2], ..Default::default() };
        let n = health_lines(&h, &st, "host name", 42, &mut out);
        assert_eq!(n, 3);
        assert!(out.starts_with("capture_health,host=host\\ name,engine=zoom pkts_in=0i"));
        assert!(out.contains("rtp_streams_active=0i"));
        assert!(out.contains("capture_health_core,host=host\\ name,engine=zoom,core=1 pkts_in=6i,dups_dropped=2i 42"));
    }

    #[test]
    fn capture_health_carries_the_video_layout_counters_as_integers() {
        let st = ExportStats::default();
        let mut out = String::new();
        let h = HealthSnapshot { per_core_in: vec![1], per_core_dups: vec![0], video_layout: [261_875, 1_500, 0, 0], ..Default::default() };
        health_lines(&h, &st, "h", 1, &mut out);
        let first = out.lines().next().unwrap();
        // the p7a names and their order are unchanged; the new rtp20 integer sits between 0a and other
        assert!(
            first.contains(",video_layout_02=261875i,video_layout_0a=1500i,video_layout_rtp20=0i,video_layout_other=0i,video_rtp20_bytes=\"-\","),
            "{first}"
        );
        // with the +20 layout seen: count and the exact byte values (0x90 only so far)
        let mut out = String::new();
        let h = HealthSnapshot {
            per_core_in: vec![1],
            per_core_dups: vec![0],
            video_layout: [261_875, 1_500, 143_157, 0],
            video_rtp20_mask: 1 << (0x90 - 0x80),
            ..Default::default()
        };
        health_lines(&h, &st, "h", 1, &mut out);
        let first = out.lines().next().unwrap();
        assert!(first.contains(",video_layout_rtp20=143157i,video_layout_other=0i,video_rtp20_bytes=\"90\","), "{first}");
    }

    fn run_with(sink: MemSink, cfg: ExportCfg, feed: impl FnOnce(&crossbeam_channel::Sender<ExportMsg>)) -> Arc<ExportStats> {
        let (tx, rx) = crossbeam_channel::bounded(1024);
        let st = Arc::new(ExportStats::default());
        let st2 = st.clone();
        let start = Instant::now();
        let h = std::thread::spawn(move || run_exporter(rx, Box::new(sink), cfg, start, st2));
        feed(&tx);
        tx.send(ExportMsg::Shutdown).unwrap();
        h.join().unwrap();
        st
    }

    #[test]
    fn exporter_end_to_end_delivers_lines_for_every_message_kind() {
        let sink = MemSink::default();
        let bodies = sink.bodies.clone();
        let st = run_with(sink, ExportCfg::default(), |tx| {
            for i in 0..20u64 {
                tx.send(ExportMsg::Rtp(rb(1, i, KIND_VIDEO, 16, 0, 98, 10, 1000))).unwrap();
                tx.send(ExportMsg::Bin(bm(1, i, Acct::Type21, 0, 5, 500))).unwrap();
                tx.send(ExportMsg::Sfu(SfuBin { client: Addr::from_v4([10, 0, 0, 1]), bin_id: i, dir: 0, seen: 15, missed: 0 })).unwrap();
            }
        });
        let all = bodies.lock().unwrap().join("");
        assert_eq!(all.lines().filter(|l| l.starts_with("session_metrics")).count(), 20);
        assert_eq!(all.lines().filter(|l| l.starts_with("session_summary")).count() >= 1, true);
        assert!(st.lines_ok.load(Relaxed) >= 20);
        assert_eq!(st.lines_dropped.load(Relaxed), 0);
    }

    #[test]
    fn retryable_failures_are_retried_then_succeed() {
        let sink = MemSink { fail_retryable: true, ..Default::default() };
        sink.fail_next.store(2, Relaxed);
        let bodies = sink.bodies.clone();
        let cfg = ExportCfg { backoff_start: Duration::from_millis(5), backoff_max: Duration::from_millis(20), ..Default::default() };
        let st = run_with(sink, cfg, |tx| {
            tx.send(ExportMsg::Bin(bm(1, 0, Acct::Other, 0, 1, 1))).unwrap();
        });
        assert_eq!(st.retries.load(Relaxed), 2);
        assert_eq!(st.batches_ok.load(Relaxed), 1);
        assert_eq!(st.lines_dropped.load(Relaxed), 0);
        assert!(!bodies.lock().unwrap().is_empty());
    }

    #[test]
    fn persistent_failure_drops_the_batch_after_the_retry_budget_and_counts_it() {
        let sink = MemSink { fail_retryable: true, ..Default::default() };
        sink.fail_next.store(1_000, Relaxed);
        let cfg = ExportCfg { backoff_start: Duration::from_millis(2), backoff_max: Duration::from_millis(4), ..Default::default() };
        let st = run_with(sink, cfg, |tx| {
            tx.send(ExportMsg::Bin(bm(1, 0, Acct::Other, 0, 1, 1))).unwrap();
        });
        assert_eq!(st.retries.load(Relaxed), 3);
        assert_eq!(st.batches_failed.load(Relaxed), 1);
        assert!(st.lines_dropped.load(Relaxed) >= 1);
    }

    #[test]
    fn non_retryable_error_is_not_retried() {
        let sink = MemSink { fail_retryable: false, ..Default::default() };
        sink.fail_next.store(1_000, Relaxed);
        let st = run_with(sink, ExportCfg::default(), |tx| {
            tx.send(ExportMsg::Bin(bm(1, 0, Acct::Other, 0, 1, 1))).unwrap();
        });
        assert_eq!(st.retries.load(Relaxed), 0);
        assert_eq!(st.batches_failed.load(Relaxed), 1);
    }
}
