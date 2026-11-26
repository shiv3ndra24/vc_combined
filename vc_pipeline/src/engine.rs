//! # engine.rs: the Teams / Meet engine as the router in vc_capture sees it
//!
//! * [`try_take`]: called by the capture callback for EVERY UDP frame. Returns `false` at once
//!   when neither address is a Teams/Meet server (the router then hands the frame to the Zoom
//!   engine). Returns `true` when the frame belongs to Teams/Meet, after counting it and, if it
//!   is RTP, queueing its record for the records thread.
//! * [`start`] / [`stop`]: threads (records, sessions, Influx writer, 5 s health), shutdown.
//! * [`final_report`]: the "Capture Statistics" block for the console and `run_info.txt`.
//!
//! Hot path cost on a non-Teams/Meet frame: the L2-L4 parse and two binary searches in a table
//! of ~16 ranges, no allocation.

use crate::channels::record::{self, RecordMessage, RecordOpts};
use crate::channels::{RECORD_TX, init_record_channel, records_thread};
use crate::dedup::{self, DedupMode};
use crate::files::ByteBudget;
use crate::ip_ranges::quick_precheck;
use crate::models::{Platform, parse_rtp_record, rtp_record};
use crate::protocol::identify_protocol;
use crate::sessions::{self, SessionOpts};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

macro_rules! counters {
    ($($name:ident),*) => {
        /// Packet counters of the Teams/Meet engine (all cumulative).
        #[derive(Clone, Copy, Debug, Default)]
        pub struct Counters { $(pub $name: u64),* }
        mod c { use std::sync::atomic::AtomicU64; $(#[allow(non_upper_case_globals)] pub static $name: AtomicU64 = AtomicU64::new(0);)* }
        /// Snapshot of the packet counters.
        pub fn counters() -> Counters { Counters { $($name: c::$name.load(std::sync::atomic::Ordering::Relaxed)),* } }
    };
}
counters!(teams_udp, meet_udp, teams_ipv6, meet_ipv6, teams_rtp, meet_rtp, rtcp, stun, dtls, quic, unknown, rtp_short);

#[inline(always)]
fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

static STOP: AtomicBool = AtomicBool::new(false);

/// The capture-path entry. See the module doc.
#[inline(always)]
pub fn try_take(data: &[u8]) -> bool {
    let Some(g) = quick_precheck(data) else { return false };
    match (g.platform, g.is_ipv6) {
        (Platform::Teams, v6) => {
            bump(&c::teams_udp);
            if v6 {
                bump(&c::teams_ipv6);
            }
        }
        (Platform::Meet, v6) => {
            bump(&c::meet_udp);
            if v6 {
                bump(&c::meet_ipv6);
            }
        }
    }
    let payload = match data.get(g.udp_payload_offset..) {
        Some(p) if p.len() >= 2 => p,
        _ => {
            bump(&c::unknown);
            return true;
        }
    };
    match identify_protocol(payload) {
        1 => {
            bump(if g.platform == Platform::Teams { &c::teams_rtp } else { &c::meet_rtp });
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
            match parse_rtp_record(data, &g, ts) {
                Some(rec) => {
                    if let Some(tx) = RECORD_TX.get() {
                        if tx.try_send(RecordMessage::Record(rec)).is_err() {
                            record::inc_record_drops();
                        }
                    }
                }
                None => bump(&c::rtp_short),
            }
        }
        2 => bump(&c::rtcp),
        3 => bump(&c::stun),
        4 => bump(&c::dtls),
        5 => bump(&c::quic),
        _ => bump(&c::unknown),
    }
    true
}

/// Everything the engine needs from the command line.
#[derive(Clone)]
pub struct EngineCfg {
    pub dedup: DedupMode,
    pub csv: bool,
    pub pcap: bool,
    pub snaplen: usize,
    pub rotate_bytes: u64,
    pub budget: Arc<dyn ByteBudget>,
    pub sessions: SessionOpts,
    /// seconds between `capture_health` points
    pub health_secs: u64,
    pub host: String,
    /// capture-to-records channel slots
    pub record_queue: usize,
}

pub struct Running {
    records: JoinHandle<()>,
    sessions: JoinHandle<()>,
    health: JoinHandle<()>,
}

/// Start the engine's threads. Call once, before the capture starts.
pub fn start(cfg: EngineCfg) -> Running {
    dedup::want_fingerprints(cfg.dedup == DedupMode::Fp);
    rtp_record::set_snaplen(if cfg.pcap { cfg.snaplen } else { 0 });
    let record_rx = init_record_channel(cfg.record_queue);
    let batch_rx = sessions::init_batch_queue(64);
    let ropts = RecordOpts {
        dedup: cfg.dedup,
        csv: cfg.csv,
        pcap: cfg.pcap,
        snaplen: cfg.snaplen,
        rotate_bytes: cfg.rotate_bytes,
        budget: cfg.budget.clone(),
    };
    let records = std::thread::Builder::new().name("vc-records".into()).spawn(move || records_thread(record_rx, ropts)).expect("spawn");
    let sopts = cfg.sessions.clone();
    let sessions = std::thread::Builder::new().name("vc-sessions".into()).spawn(move || sessions::session_worker(batch_rx, sopts)).expect("spawn");
    let (every, host, budget) = (cfg.health_secs.max(1), cfg.host.clone(), cfg.budget.clone());
    let health = std::thread::Builder::new()
        .name("vc-health".into())
        .spawn(move || {
            let mut ticks = 0u64;
            while !STOP.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(250));
                ticks += 1;
                if ticks % (every * 4) == 0 {
                    sessions::push_line(health_line(&host, budget.as_ref()));
                }
            }
        })
        .expect("spawn");
    Running { records, sessions, health }
}

/// Stop after the capture has stopped: drain the records, flush sessions and Influx.
pub fn stop(r: Running, host: &str, budget: &dyn ByteBudget) {
    STOP.store(true, Ordering::Relaxed);
    let _ = r.health.join();
    if let Some(tx) = RECORD_TX.get() {
        let _ = tx.send(RecordMessage::Shutdown);
    }
    let _ = r.records.join();
    sessions::push_line(health_line(host, budget)); // one last health point, with final counters
    sessions::push_shutdown_batch(); // now the session layer may flush and stop the writer
    let _ = r.sessions.join();
}

/// One `capture_health` point of the Teams/Meet engine (tag `engine=teams_meet`; the Zoom engine
/// writes its own with `engine=zoom`). All fields are cumulative counters since start.
pub fn health_line(host: &str, budget: &dyn ByteBudget) -> String {
    let k = counters();
    let (ok, fail, lines, qdrop) = sessions::influx_stats();
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_nanos();
    format!(
        "capture_health,host={},engine=teams_meet teams_udp={}i,meet_udp={}i,teams_rtp={}i,meet_rtp={}i,rtcp={}i,stun={}i,dtls={}i,quic={}i,unknown={}i,rtp_short={}i,\
records_in={}i,kept={}i,dups_dropped={}i,fp_evicted_live={}i,record_queue_drops={}i,batch_drops={}i,sessions_open={}i,\
csv_rows={}i,csv_bytes={}i,csv_files={}i,csv_drop_limit={}i,pcap_pkts={}i,pcap_bytes={}i,pcap_files={}i,pcap_drop_limit={}i,file_io_errors={}i,\
capture_limit_tripped={}i,capture_disk_bytes={}i,export_writes_ok={}i,export_writes_failed={}i,export_lines_ok={}i,export_lines_dropped={}i {ts}",
        sessions::tag_value(host),
        k.teams_udp,
        k.meet_udp,
        k.teams_rtp,
        k.meet_rtp,
        k.rtcp,
        k.stun,
        k.dtls,
        k.quic,
        k.unknown,
        k.rtp_short,
        record::records_in(),
        record::kept_records(),
        record::duplicate_records(),
        record::fp_evicted_live(),
        record::record_drops(),
        record::batch_drops(),
        sessions::sessions_open(),
        record::csv_rows(),
        record::csv_bytes(),
        record::csv_parts(),
        record::csv_skipped(),
        record::pcap_frames(),
        record::pcap_bytes(),
        record::pcap_parts(),
        record::pcap_skipped(),
        record::file_errors(),
        (!budget.is_open()) as u8,
        budget.used(),
        ok,
        fail,
        lines,
        qdrop,
    )
}

/// The 15 s status line.
pub fn status_line() -> String {
    let k = counters();
    let (ok, fail, lines, qdrop) = sessions::influx_stats();
    format!(
        "[teams/meet] rtp teams={} meet={} | kept={} dups={} | csv={} rows pcap={} frames | queue_drops={} | influx ok={} fail={} lines={} dropped={}",
        k.teams_rtp,
        k.meet_rtp,
        record::kept_records(),
        record::duplicate_records(),
        record::csv_rows(),
        record::pcap_frames(),
        record::record_drops(),
        ok,
        fail,
        lines,
        qdrop
    )
}

/// Final block: printed at the end and appended to `run_info.txt` as `key=value` lines
/// (the first element) and as the verbatim console text (the second).
pub fn final_report(dedup: DedupMode) -> (Vec<(String, String)>, String) {
    let k = counters();
    let (ok, fail, lines, qdrop) = sessions::influx_stats();
    let kv: Vec<(&str, u64)> = vec![
        ("teams_udp", k.teams_udp),
        ("teams_ipv6", k.teams_ipv6),
        ("meet_udp", k.meet_udp),
        ("meet_ipv6", k.meet_ipv6),
        ("teams_rtp", k.teams_rtp),
        ("meet_rtp", k.meet_rtp),
        ("rtcp", k.rtcp),
        ("stun", k.stun),
        ("dtls", k.dtls),
        ("quic", k.quic),
        ("unknown", k.unknown),
        ("rtp_short", k.rtp_short),
        ("records_in", record::records_in()),
        ("kept", record::kept_records()),
        ("duplicates_dropped", record::duplicate_records()),
        ("fp_evicted_live", record::fp_evicted_live()),
        ("record_queue_drops", record::record_drops()),
        ("batch_drops", record::batch_drops()),
        ("csv_rows", record::csv_rows()),
        ("csv_bytes", record::csv_bytes()),
        ("csv_files", record::csv_parts()),
        ("csv_skipped_limit", record::csv_skipped()),
        ("pcap_frames", record::pcap_frames()),
        ("pcap_bytes", record::pcap_bytes()),
        ("pcap_files", record::pcap_parts()),
        ("pcap_skipped_limit", record::pcap_skipped()),
        ("file_io_errors", record::file_errors()),
        ("influx_writes_ok", ok),
        ("influx_writes_failed", fail),
        ("influx_lines_ok", lines),
        ("influx_lines_dropped", qdrop),
    ];
    let pct = |a: u64, b: u64| if b == 0 { 0.0 } else { a as f64 * 100.0 / b as f64 };
    let text = format!(
        "Teams/Meet capture statistics\n\
         =============================\n\
         \x20 Teams UDP packets        : {} (IPv6 {:.1}%)\n\
         \x20 Meet UDP packets         : {} (IPv6 {:.1}%)\n\
         \x20 RTP packets              : teams {}  meet {}   (RFC 7983 demux)\n\
         \x20 Not RTP (counted only)   : rtcp {}  stun/turn {}  dtls {}  quic {}  unknown {}  short rtp {}\n\
         \x20 De-dup ({})              : {} twins dropped of {} records, {} kept; {} fp slot overwrites (upper bound of missed twins)\n\
         \x20 CSV                      : {} rows, {} bytes in {} file(s); {} kept rows not written (size limit)\n\
         \x20 PCAP                     : {} frames, {} bytes in {} file(s); {} kept frames not written (size limit)\n\
         \x20 Queue drops              : records {}  batches {}  influx lines {}\n\
         \x20 InfluxDB                 : {} writes ok, {} failed, {} lines accepted",
        k.teams_udp,
        pct(k.teams_ipv6, k.teams_udp),
        k.meet_udp,
        pct(k.meet_ipv6, k.meet_udp),
        k.teams_rtp,
        k.meet_rtp,
        k.rtcp,
        k.stun,
        k.dtls,
        k.quic,
        k.unknown,
        k.rtp_short,
        dedup.as_str(),
        record::duplicate_records(),
        record::records_in(),
        record::kept_records(),
        record::fp_evicted_live(),
        record::csv_rows(),
        record::csv_bytes(),
        record::csv_parts(),
        record::csv_skipped(),
        record::pcap_frames(),
        record::pcap_bytes(),
        record::pcap_parts(),
        record::pcap_skipped(),
        record::record_drops(),
        record::batch_drops(),
        qdrop,
        ok,
        fail,
        lines
    );
    (kv.into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(), text)
}
