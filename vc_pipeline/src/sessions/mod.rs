//! # sessions/: per-client 5 s bins -> InfluxDB line protocol (Teams / Meet)
//!
//! One session per (platform, client IP). Every kept record (after de-dup) updates
//! * `network`     (network_metrics.rs): totals per direction + the old loss formula,
//! * `streams`     (streams.rs): per-(direction, SSRC) metrics with the Zoom engine's rules,
//! * `degradation` (degradation.rs): the old camera degradation fields.
//!
//! At the end of a bin the session writes ONE `session_metrics` point (tags `client_ip`,
//! `session_id`, `platform`) and, with `--ssrc-lines teams-meet|all` (default `teams-meet`), one
//! `rtp_stream` point per SSRC. Both measurement names are shared with the Zoom engine
//! (vc_combined; before: `teams_session_qoe` / `teams_rtp_stream`), so one Grafana query can show
//! all three platforms (`platform` tag = `zoom` / `teams` / `meet`).
//!
//! Fields are written only when they are defined, as the Zoom engine does: `fps_downlink` is
//! absent (not 0.00) in a bin without a counted video stream; `video_streams_active_downlink=0i`
//! says so explicitly. Before vc_combined such a bin read `down_fps=0.00`, which looked like a
//! frozen picture (handoff section 1).

pub mod degradation;
pub mod network_metrics;
pub mod streams;

use crate::models::{Platform, RtpRecord};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, bounded};
use degradation::DegradationTracker;
use network_metrics::NetworkMetrics;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use streams::{DEGRADED_FPS, DirAgg, StreamTracker};

pub const BATCH_SIZE: usize = 5_000;

static INFLUX_OK: AtomicU64 = AtomicU64::new(0); // HTTP writes (or file writes) accepted
static INFLUX_FAIL: AtomicU64 = AtomicU64::new(0); // refused / unreachable
static INFLUX_LINES: AtomicU64 = AtomicU64::new(0); // lines inside accepted writes
static INFLUX_QUEUE_DROPS: AtomicU64 = AtomicU64::new(0); // lines lost because the writer queue was full

/// (accepted writes, failed writes, lines accepted, lines lost to a full queue)
pub fn influx_stats() -> (u64, u64, u64, u64) {
    (
        INFLUX_OK.load(Ordering::Relaxed),
        INFLUX_FAIL.load(Ordering::Relaxed),
        INFLUX_LINES.load(Ordering::Relaxed),
        INFLUX_QUEUE_DROPS.load(Ordering::Relaxed),
    )
}

const SESSION_TIMEOUT_NS: u64 = 120 * 1_000_000_000;
const BIN_SIZE_NS: u64 = 5 * 1_000_000_000;
const BIN_S: f64 = 5.0;

/// Where the line protocol goes.
#[derive(Clone, Debug)]
pub enum InfluxTarget {
    /// InfluxDB 2 `/api/v2/write` URL (org, bucket, precision=ns in the query) + token
    Http { url: String, token: String },
    /// append to this file (no URL configured)
    File(PathBuf),
}

/// Session-layer options.
#[derive(Clone, Debug)]
pub struct SessionOpts {
    pub target: InfluxTarget,
    /// write one `rtp_stream` point per SSRC and bin
    pub ssrc_lines: bool,
}

pub struct Batch {
    pub records: Vec<RtpRecord>,
    pub seq: u64,
}

static BATCH_TX: OnceLock<Sender<Batch>> = OnceLock::new();
static LINE_TX: OnceLock<Sender<String>> = OnceLock::new();
static SSRC_LINES: AtomicBool = AtomicBool::new(true);

pub fn init_batch_queue(capacity: usize) -> Receiver<Batch> {
    let (tx, rx) = bounded::<Batch>(capacity);
    BATCH_TX.set(tx).expect("Batch queue already initialised");
    rx
}

pub fn push_batch(batch: Batch) -> bool {
    match BATCH_TX.get() {
        Some(tx) => tx.try_send(batch).is_ok(),
        None => false,
    }
}

pub fn push_shutdown_batch() {
    if let Some(tx) = BATCH_TX.get() {
        let _ = tx.send(Batch { records: Vec::new(), seq: 0 });
    }
}

/// Queue one extra line for the Teams/Meet Influx writer (the engine's `capture_health`).
pub fn push_line(line: String) {
    if let Some(tx) = LINE_TX.get() {
        if tx.try_send(line).is_err() {
            INFLUX_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct SessionState {
    session_id: String,
    platform: Platform,
    client_ip: String,
    first_seen_ns: u64,
    last_seen_ns: u64,
    current_bin_id: u64,
    bin_first_ns: u64,
    bin_last_ns: u64,
    network: NetworkMetrics,
    streams: StreamTracker,
    degradation: DegradationTracker,
}

pub struct SessionEngine {
    sessions: HashMap<String, SessionState>,
    influx_tx: Option<Sender<String>>,
    influx_handle: Option<JoinHandle<()>>,
}

/// The client is the endpoint that is not the server; the gate decided which one that is.
fn client_ip(r: &RtpRecord) -> &str {
    if r.uplink { &r.src_ip } else { &r.dst_ip }
}

fn new_session_id(platform: Platform, client_ip: &str, first_seen_ns: u64) -> String {
    let prefix = match platform {
        Platform::Teams => "T",
        Platform::Meet => "M",
    };
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    client_ip.hash(&mut hasher);
    first_seen_ns.hash(&mut hasher);
    format!("{}_{:016x}", prefix, hasher.finish())
}

pub fn tag_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace(',', "\\,").replace('=', "\\=").replace(' ', "\\ ")
}

pub fn platform_tag(p: Platform) -> &'static str {
    match p {
        Platform::Teams => "teams",
        Platform::Meet => "meet",
    }
}

impl SessionEngine {
    pub fn new(opts: SessionOpts) -> Self {
        SSRC_LINES.store(opts.ssrc_lines, Ordering::Relaxed);
        let (tx, rx) = bounded::<String>(100_000);
        let _ = LINE_TX.set(tx.clone());
        let target = opts.target;
        let handle = std::thread::Builder::new()
            .name("vc-influx".into())
            .spawn(move || influx_writer_thread(rx, target))
            .expect("spawn influx writer");
        Self { sessions: HashMap::new(), influx_tx: Some(tx), influx_handle: Some(handle) }
    }

    pub fn process_batch(&mut self, batch: Batch) {
        for record in batch.records {
            self.process_record(record);
        }
    }

    fn process_record(&mut self, record: RtpRecord) {
        let client = client_ip(&record).to_string();
        let key = format!("{}:{}", platform_tag(record.platform), client);
        let bin = record.arrival_epoch_ns / BIN_SIZE_NS;
        let tx = self.influx_tx.clone();
        let t = record.arrival_epoch_ns;
        let state = self.sessions.entry(key).or_insert_with(|| SessionState {
            session_id: new_session_id(record.platform, &client, t),
            platform: record.platform,
            client_ip: client.clone(),
            first_seen_ns: t,
            last_seen_ns: t,
            current_bin_id: bin,
            bin_first_ns: t,
            bin_last_ns: t,
            network: NetworkMetrics::new(),
            streams: StreamTracker::new(),
            degradation: DegradationTracker::new(),
        });
        if t.saturating_sub(state.last_seen_ns) > SESSION_TIMEOUT_NS {
            flush_session(tx.as_ref(), state);
            reset_session(state, t, bin);
        }
        if bin > state.current_bin_id {
            flush_session(tx.as_ref(), state);
            state.current_bin_id = bin;
            state.bin_first_ns = t;
        }
        if !state.network.has_data() {
            state.bin_first_ns = t;
        }
        state.network.process_packet(&record);
        state.streams.process_packet(&record);
        state.degradation.process_packet(&record);
        state.last_seen_ns = t;
        state.bin_last_ns = t;
    }

    pub fn cleanup_stale_sessions(&mut self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_nanos() as u64;
        let tx = self.influx_tx.clone();
        let mut stale = Vec::new();
        for (k, st) in self.sessions.iter_mut() {
            if now.saturating_sub(st.last_seen_ns) > SESSION_TIMEOUT_NS {
                flush_session(tx.as_ref(), st);
                stale.push(k.clone());
            }
        }
        for k in stale {
            self.sessions.remove(&k);
        }
    }

    pub fn sessions_open(&self) -> usize {
        self.sessions.len()
    }

    pub fn shutdown(mut self) {
        let tx = self.influx_tx.clone();
        for st in self.sessions.values_mut() {
            flush_session(tx.as_ref(), st);
        }
        self.influx_tx.take();
        drop(tx);
        // LINE_TX (a static) still holds a sender: tell the writer to stop explicitly
        if let Some(t) = LINE_TX.get() {
            let _ = t.send(String::new());
        }
        if let Some(h) = self.influx_handle.take() {
            if h.join().is_err() {
                eprintln!("[WARN] InfluxDB writer thread panicked.");
            }
        }
    }
}

fn reset_session(st: &mut SessionState, first_seen_ns: u64, bin: u64) {
    st.session_id = new_session_id(st.platform, &st.client_ip, first_seen_ns);
    st.first_seen_ns = first_seen_ns;
    st.last_seen_ns = first_seen_ns;
    st.current_bin_id = bin;
    st.bin_first_ns = first_seen_ns;
    st.bin_last_ns = first_seen_ns;
    st.network = NetworkMetrics::new();
    st.streams = StreamTracker::new();
    st.degradation = DegradationTracker::new();
}

/// `,name=value` with Zoom's convention: only finite values.
fn ff(out: &mut String, name: &str, v: f64, prec: usize) {
    if v.is_finite() {
        let _ = write!(out, ",{name}={v:.prec$}");
    }
}
fn fi(out: &mut String, name: &str, v: i64) {
    let _ = write!(out, ",{name}={v}i");
}

/// The Zoom-compatible per-direction fields (same names and rules as zoom_pipeline/src/export.rs).
pub fn direction_fields(out: &mut String, n: &str, d: &DirAgg, share_active: bool) {
    let bps = |b: u64| b as f64 * 8.0 / BIN_S;
    let pps = |p: u64| p as f64 / BIN_S;
    ff(out, &format!("video_bitrate_{n}_bps"), bps(d.video_bytes), 1);
    ff(out, &format!("video_pps_{n}"), pps(d.video_pkts), 2);
    ff(out, &format!("audio_bitrate_{n}_bps"), bps(d.audio_bytes), 1);
    ff(out, &format!("audio_pps_{n}"), pps(d.audio_pkts), 2);
    ff(out, &format!("screen_bitrate_{n}_bps"), bps(d.screen_bytes), 1);
    ff(out, &format!("screen_pps_{n}"), pps(d.screen_pkts), 2);
    ff(out, &format!("unq_media_bitrate_{n}_bps"), bps(d.unq_bytes), 1);
    ff(out, &format!("unq_media_pps_{n}"), pps(d.unq_pkts), 2);
    fi(out, &format!("video_streams_active_{n}"), d.video_streams as i64);
    fi(out, &format!("video_frames_{n}"), d.video_frames as i64);
    if d.fps_n > 0 {
        ff(out, &format!("fps_{n}"), d.fps_sum / d.fps_n as f64, 2);
        ff(out, &format!("video_stream_bitrate_mean_{n}_bps"), d.stream_bps_sum / d.fps_n as f64, 1);
    }
    if d.gap_n >= 2 {
        ff(out, &format!("frame_gap_std_ms_{n}"), (d.gap_m2 / d.gap_n as f64).sqrt(), 3);
    }
    if d.jit_w > 0.0 && d.gap_n > 0 {
        ff(out, &format!("jitter_ms_{n}"), d.jit_sum / d.jit_w, 3);
    }
    fi(out, &format!("stalls_{n}"), d.stalls as i64);
    fi(out, &format!("retransmits_{n}"), d.retx as i64);
    if !share_active && d.full_n > 0 {
        fi(out, &format!("degraded_{n}"), ((d.full_fps_sum / d.full_n as f64) < DEGRADED_FPS) as i64);
        fi(out, &format!("video_streams_degraded_{n}"), d.full_below as i64);
    }
    if d.audio_streams > 0 {
        fi(out, &format!("audio_active_s_{n}"), d.audio_active_s as i64);
    }
    fi(out, &format!("screen_streams_active_{n}"), d.screen_streams as i64);
    fi(out, &format!("screen_frames_{n}"), d.screen_frames as i64);
    if d.screen_fps_n > 0 {
        ff(out, &format!("screen_fps_{n}"), d.screen_fps_sum / d.screen_fps_n as f64, 2);
    }
}

fn flush_session(tx: Option<&Sender<String>>, st: &mut SessionState) {
    if !st.network.has_data() {
        return;
    }
    let ts = (st.current_bin_id + 1) * BIN_SIZE_NS;
    let client_tag = tag_value(&st.client_ip);
    let session_tag = tag_value(&st.session_id);
    let plat = platform_tag(st.platform);
    let agg = st.streams.aggregate();
    let share = agg[0].screen_streams + agg[1].screen_streams > 0;

    let mut line = String::with_capacity(2048);
    let _ = write!(line, "session_metrics,client_ip={client_tag},session_id={session_tag},platform={plat} ");
    line.push_str(&st.network.to_influx_fields(BIN_S));
    ff(&mut line, "bin_cover_s", st.bin_last_ns.saturating_sub(st.bin_first_ns) as f64 / 1e9, 3);
    ff(&mut line, "session_age_s", ts.saturating_sub(st.first_seen_ns) as f64 / 1e9, 1);
    fi(&mut line, "share_active", share as i64);
    direction_fields(&mut line, "uplink", &agg[0], share);
    direction_fields(&mut line, "downlink", &agg[1], share);
    line.push(',');
    line.push_str(&st.degradation.to_influx_fields(BIN_S));
    let _ = write!(line, " {ts}");
    push(tx, line);

    if SSRC_LINES.load(Ordering::Relaxed) {
        for l in st.streams.lines() {
            let s = l.s;
            let mut o = String::with_capacity(400);
            let _ = write!(
                o,
                "rtp_stream,client_ip={client_tag},session_id={session_tag},ssrc=0x{:08X},stream_type={},direction={},platform={plat},pt={} \
                 packets={}i,bytes={}i,throughput_bps={:.1},rtp_lost_packets={}i,rtp_loss_pct={:.4},stalls={}i,retransmits={}i,qualified={}i",
                s.ssrc,
                l.kind.as_str(),
                if s.uplink { "uplink" } else { "downlink" },
                s.pt,
                s.pkts,
                s.bytes,
                s.bytes as f64 * 8.0 / BIN_S,
                s.lost,
                s.rtp_loss_pct(),
                s.stalls,
                s.retx,
                (s.state == streams::QState::Qualified) as i64
            );
            if l.kind != streams::Kind::Audio {
                if let Some(f) = s.fps() {
                    ff(&mut o, "fps", f, 2);
                }
                if let Some(g) = s.frame_gap_std_ms() {
                    ff(&mut o, "frame_gap_std_ms", g, 3);
                }
                if s.gap_n > 0 {
                    ff(&mut o, "rfc3550_jitter_ms", s.jitter_ms, 3);
                }
            }
            let _ = write!(o, " {ts}");
            push(tx, o);
        }
    }
    st.network.reset_bin();
    st.streams.reset_bin();
    st.degradation.reset_bin();
}

fn push(tx: Option<&Sender<String>>, line: String) {
    if let Some(tx) = tx {
        if tx.try_send(line).is_err() {
            INFLUX_QUEUE_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

static SESSIONS_OPEN: AtomicU64 = AtomicU64::new(0);
pub fn sessions_open() -> u64 {
    SESSIONS_OPEN.load(Ordering::Relaxed)
}

pub fn session_worker(rx: Receiver<Batch>, opts: SessionOpts) {
    let mut engine = SessionEngine::new(opts);
    loop {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(batch) => {
                if batch.records.is_empty() {
                    engine.shutdown();
                    break;
                }
                engine.process_batch(batch);
                engine.cleanup_stale_sessions();
            }
            Err(RecvTimeoutError::Timeout) => engine.cleanup_stale_sessions(),
            Err(RecvTimeoutError::Disconnected) => {
                engine.shutdown();
                break;
            }
        }
        SESSIONS_OPEN.store(engine.sessions_open() as u64, Ordering::Relaxed);
    }
}

enum Out {
    Http { agent: ureq::Agent, url: String, token: String },
    File(std::io::BufWriter<std::fs::File>),
}

fn influx_writer_thread(rx: Receiver<String>, target: InfluxTarget) {
    let mut out = match target {
        InfluxTarget::Http { url, token } => {
            let agent = ureq::AgentBuilder::new().timeout_write(Duration::from_secs(2)).timeout_read(Duration::from_secs(2)).build();
            Out::Http { agent, url, token }
        }
        InfluxTarget::File(p) => match std::fs::OpenOptions::new().create(true).append(true).open(&p) {
            Ok(f) => Out::File(std::io::BufWriter::new(f)),
            Err(e) => {
                eprintln!("[WARN] cannot open {}: {e}; Teams/Meet metrics are computed but not written", p.display());
                while let Ok(l) = rx.recv() {
                    if l.is_empty() {
                        break;
                    }
                }
                return;
            }
        },
    };
    loop {
        let (payload, done) = collect_payload(&rx);
        if !payload.is_empty() {
            let n = payload.lines().count() as u64;
            let ok = match &mut out {
                Out::Http { agent, url, token } => match agent
                    .post(url)
                    .set("Authorization", &format!("Token {token}"))
                    .set("Content-Type", "text/plain; charset=utf-8")
                    .send_string(&payload)
                {
                    Ok(_) => true,
                    Err(e) => {
                        eprintln!("[WARN] [teams/meet] InfluxDB write failed ({n} lines lost): {e}");
                        false
                    }
                },
                Out::File(f) => {
                    use std::io::Write;
                    f.write_all(payload.as_bytes()).and_then(|_| f.flush()).is_ok()
                }
            };
            if ok {
                INFLUX_OK.fetch_add(1, Ordering::Relaxed);
                INFLUX_LINES.fetch_add(n, Ordering::Relaxed);
            } else {
                INFLUX_FAIL.fetch_add(1, Ordering::Relaxed);
            }
        }
        if done {
            break;
        }
    }
}

/// Up to 500 lines, waiting at most 1 s for the first. Returns (payload, writer should stop).
/// An empty line is the stop signal.
fn collect_payload(rx: &Receiver<String>) -> (String, bool) {
    let mut payload = String::new();
    match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(l) if l.is_empty() => return (payload, true),
        Ok(l) => {
            payload.push_str(&l);
            payload.push('\n');
        }
        Err(RecvTimeoutError::Timeout) => return (payload, false),
        Err(RecvTimeoutError::Disconnected) => return (payload, true),
    }
    for _ in 0..499 {
        match rx.try_recv() {
            Ok(l) if l.is_empty() => return (payload, true),
            Ok(l) => {
                payload.push_str(&l);
                payload.push('\n');
            }
            Err(_) => break,
        }
    }
    (payload, false)
}
