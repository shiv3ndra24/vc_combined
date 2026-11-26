//! # vc_capture: ONE Retina capture for Zoom, Teams and Meet
//!
//! ```text
//! Retina #[filter("udp")] callback, per RX core
//!   router: vc_pipeline::engine::try_take(frame)   Teams/Meet address gate (ip_lists/teams.txt, meet.txt)
//!     |-- true  -> already handled by the Teams/Meet engine (RFC 7983 demux, records thread, de-dup,
//!     |            teams_/meet_record_NNNN.csv + .pcap, session metrics)
//!     `-- false -> zoom_pipeline::Pipeline::on_frame   Zoom's own gate (ports 8801-8810/3478/3479 +
//!                  ip_lists/zoom.txt), shared fp de-dup, zoom_record_NNNN.pcap + .csv, shards, exporter
//! ```
//! Why Teams/Meet first and "everything else" to Zoom: the three address lists never overlap
//! (checked at start-up), so the order changes no result; and the Zoom engine keeps seeing every
//! other UDP packet, so its health counters (`ip_filtered`, `port_filtered`, `zoom_like_unlisted`)
//! mean exactly what they meant in zoom_capture.
//!
//! Both engines are the validated code of their own crates; this file only wires them: one CLI,
//! one run folder, one byte budget for all capture files, one InfluxDB target, one run_info.txt.

use clap::{Parser, ValueEnum};
use retina_core::config::{DisplayConfig, MonitorConfig, load_config};
use retina_core::{CoreId, Runtime};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vc_pipeline::dedup::DedupMode;
use vc_pipeline::files::ByteBudget;
use vc_pipeline::sessions::{InfluxTarget, SessionOpts};
use zoom_pipeline::capture_files::{CaptureLimits, DiskBudget, PcapCfg, PcapWriter, DEFAULT_PCAP_POOL_SLOTS};
use zoom_pipeline::csvdump::CsvWriter;
use zoom_pipeline::export::{run_exporter, ExportCfg, ExportStats, FileSink, HttpSink, Sink};
use zoom_pipeline::ipset::IpSet;
use zoom_pipeline::pipeline::{thread_core_index, Pipeline, PipelineConfig};
use zoom_pipeline::report::health_line;

/// Compiled-in copy of ip_lists/zoom.txt (the Teams/Meet copies live in vc_pipeline).
const BUILTIN_ZOOM: &str = include_str!("../../ip_lists/zoom.txt");

static ZOOM: OnceLock<Arc<Pipeline>> = OnceLock::new();

#[inline(always)]
fn on_packet(packet: &ZcFrame) {
    let data = packet.data();
    if vc_pipeline::engine::try_take(data) {
        return;
    }
    if let Some(z) = ZOOM.get() {
        z.on_frame(thread_core_index(), data);
    }
}

// Every UDP packet: Teams/Meet have no port rule, so a narrower Retina filter is not possible.
#[filter("udp")]
fn capture_udp(packet: &ZcFrame, _core_id: &CoreId) {
    on_packet(packet);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum DedupArg {
    /// fingerprint (5-tuple + UDP length + first 48 payload bytes) within 10 ms, both engines
    Fp,
    /// keep every packet, twins included
    Off,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum SsrcLines {
    /// no rtp_stream points
    None,
    /// rtp_stream points for Teams and Meet only (what the Teams/Meet crate always did)
    TeamsMeet,
    /// rtp_stream points for all three (Zoom's were opt-in: cardinality grows with calls)
    All,
}

/// One capture for Zoom, Teams and Meet. Docs: docs/USAGE.md (commands, flags), docs/METRICS.md (fields).
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Retina config (config.toml = 8 h production, config.observe.toml = 10 min)
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,

    /// Run folder. Created; refused if it already holds output files. Default: captures/run_<UTC yyyymmdd_HHMMSS>
    #[arg(short, long, value_name = "DIR")]
    out_dir: Option<PathBuf>,

    /// Mirror-twin filter for BOTH engines. `off` once the campus mirror sends one copy only.
    /// Default `fp`; a build without the `dedup` feature only accepts `off` (and defaults to it).
    #[arg(long, value_enum, value_name = "fp|off")]
    dedup: Option<DedupArg>,

    /// Write <platform>_record_NNNN.csv for Zoom, Teams and Meet (after de-dup)
    #[arg(long)]
    csv: bool,

    /// Write <platform>_record_NNNN.pcap for Zoom, Teams and Meet (after de-dup)
    #[arg(long)]
    pcap: bool,

    /// Bytes kept per packet in every pcap. 128 = headers only (every metric can be recomputed
    /// from them); 1536 = whole frames (contain the users' encrypted media: decide first)
    #[arg(long, default_value_t = 128, value_name = "BYTES")]
    pcap_snaplen: usize,

    /// ONE limit for all capture files together (6 kinds: CSV + pcap x 3 platforms). When reached,
    /// every capture file stops; metrics and InfluxDB go on. 0 = no limit
    #[arg(long, default_value_t = 10_240, value_name = "MB")]
    capture_max_mb: u64,

    /// Start a new part of a file after this many MB (MB = 1 000 000 bytes)
    #[arg(long, default_value_t = 256, value_name = "MB")]
    rotate_mb: u64,

    /// Folder with zoom.txt, teams.txt and meet.txt (one CIDR per line). Default: the copies compiled
    /// in at build time (same files as ip_lists/ in the source tree)
    #[arg(long, value_name = "DIR")]
    ip_dir: Option<PathBuf>,

    /// Per-SSRC `rtp_stream` points
    #[arg(long, value_enum, default_value = "teams-meet")]
    ssrc_lines: SsrcLines,

    /// Write all line protocol to <run folder>/influx_zoom.lp and influx_teams_meet.lp, even if
    /// VC_QOE_INFLUX_URL is set (dry run)
    #[arg(long)]
    influx_file: bool,

    /// Seconds between status lines and capture_health points
    #[arg(long, default_value_t = 5, value_name = "S")]
    health_secs: u64,

    /// Host tag of capture_health (default: the machine's host name)
    #[arg(long)]
    host: Option<String>,

    // ---- advanced (defaults as in the two source crates)
    /// Zoom: aggregation shards (default: number of `cores` in the config)
    #[arg(long)]
    zoom_shards: Option<usize>,
    /// Zoom: tracked flows per shard
    #[arg(long, default_value_t = 65_536)]
    zoom_max_streams: usize,
    /// Zoom: tracked RTP streams
    #[arg(long, default_value_t = 65_536)]
    zoom_max_rtp_streams: usize,
    /// Zoom: capture-to-exporter queue (bins)
    #[arg(long, default_value_t = 262_144)]
    zoom_channel_cap: usize,
    /// Zoom: packets that can wait for the pcap writer
    #[arg(long, default_value_t = DEFAULT_PCAP_POOL_SLOTS)]
    zoom_pcap_pool: usize,
    /// Teams/Meet: capture-to-records queue (records)
    #[arg(long, default_value_t = 2_000_000)]
    vc_record_queue: usize,
}

/// The ONE byte budget (Zoom's `DiskBudget`), seen by the Teams/Meet engine through its trait.
struct SharedBudget(Arc<DiskBudget>);
impl ByteBudget for SharedBudget {
    fn reserve(&self, n: u64) -> bool {
        self.0.reserve(n)
    }
    fn is_open(&self) -> bool {
        self.0.is_open()
    }
    fn used(&self) -> u64 {
        self.0.used()
    }
}

/// FNV-1a 64 of a list text (run_info records which list a run used; no extra dependency).
fn fnv64(s: &str) -> u64 {
    s.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x0100_0000_01b3))
}

/// Unix seconds -> (y, m, d, H, M, S) in UTC (civil-from-days; no chrono needed).
fn utc(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d, (rem / 3600) as u32, (rem % 3600 / 60) as u32, (rem % 60) as u32)
}

fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs()
}

fn die(msg: String) -> ! {
    eprintln!("[ERROR] {msg}");
    std::process::exit(2);
}

/// Count `cores = [..]` entries over all `[[online.ports]]` in the Retina config (Zoom shard count).
fn cores_in_config(path: &Path) -> Option<usize> {
    let v: toml::Value = std::fs::read_to_string(path).ok()?.parse().ok()?;
    let n: usize = v.get("online")?.get("ports")?.as_array()?.iter().filter_map(|p| p.get("cores")?.as_array().map(|c| c.len())).sum();
    (n > 0).then_some(n)
}

/// Where one engine's line protocol goes. Environment, in this order:
///   VC_QOE_<ENGINE>_INFLUX_URL / _TOKEN  (only to separate the engines; see docs/USAGE.md)
///   VC_QOE_INFLUX_URL / VC_QOE_INFLUX_TOKEN  (the ONE common target)
///   nothing -> <run folder>/<file>
fn target_for(engine: &str, file: &str, force_file: bool) -> (InfluxTarget, String) {
    let file_t = || (InfluxTarget::File(PathBuf::from(file)), format!("file {file} (no InfluxDB URL set)"));
    if force_file {
        return (InfluxTarget::File(PathBuf::from(file)), format!("file {file} (--influx-file)"));
    }
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    let (url, token, how) = match env(&format!("VC_QOE_{engine}_INFLUX_URL")) {
        Some(u) => (Some(u), env(&format!("VC_QOE_{engine}_INFLUX_TOKEN")).or_else(|| env("VC_QOE_INFLUX_TOKEN")), "separate target"),
        None => (env("VC_QOE_INFLUX_URL"), env("VC_QOE_INFLUX_TOKEN"), "common target"),
    };
    match (url, token) {
        (Some(url), Some(token)) => {
            let shown = url.clone(); // org and bucket, no secret; the token is never printed
            (InfluxTarget::Http { url, token }, format!("{shown} ({how}, token not shown)"))
        }
        (Some(_), None) => die(format!("an InfluxDB URL is set for {engine} but no token (VC_QOE_INFLUX_TOKEN or VC_QOE_{engine}_INFLUX_TOKEN)")),
        _ => file_t(),
    }
}

/// Files a run can create; a folder that holds any of them is refused (one folder = one run).
fn refuse_used_folder(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if n == "run_info.txt" || n.contains("_record_") || n.starts_with("influx_") {
            die(format!("{} already holds {n}; refusing to overwrite an earlier run. Pick a new --out-dir.", dir.display()));
        }
    }
}

struct RunInfo(PathBuf);
impl RunInfo {
    fn put(&self, k: &str, v: impl std::fmt::Display) {
        self.raw(&format!("{k}={v}\n"));
    }
    fn raw(&self, s: &str) {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.0) {
            let _ = f.write_all(s.as_bytes());
        }
    }
}

#[retina_main(1)]
fn main() {
    let args = Args::parse();
    let dedup_compiled = vc_pipeline::dedup::DEDUP_COMPILED && zoom_pipeline::pipeline::DEDUP_COMPILED;
    let dedup = match (args.dedup, dedup_compiled) {
        (Some(DedupArg::Fp), false) => die("this binary was built without the `dedup` feature: only --dedup off is possible".into()),
        (Some(DedupArg::Fp), true) | (None, true) => DedupMode::Fp,
        (Some(DedupArg::Off), _) | (None, false) => DedupMode::Off,
    };
    if args.pcap_snaplen < 64 || args.pcap_snaplen > 9216 {
        die(format!("--pcap-snaplen must be 64..=9216, got {}", args.pcap_snaplen));
    }
    let config_path = std::fs::canonicalize(&args.config).unwrap_or_else(|e| die(format!("cannot read config {}: {e}", args.config.display())));
    let ip_dir = args.ip_dir.as_ref().map(|d| std::fs::canonicalize(d).unwrap_or_else(|e| die(format!("--ip-dir {}: {e}", d.display()))));

    // ---- IP lists: read and check BEFORE anything is created
    let read = |name: &str, builtin: &'static str| -> (String, String) {
        match &ip_dir {
            Some(d) => {
                let p = d.join(name);
                (std::fs::read_to_string(&p).unwrap_or_else(|e| die(format!("{}: {e}", p.display()))), p.display().to_string())
            }
            None => (builtin.to_string(), "compiled-in".to_string()),
        }
    };
    let (zoom_txt, zoom_src) = read("zoom.txt", BUILTIN_ZOOM);
    let (teams_txt, teams_src) = read("teams.txt", vc_pipeline::ip_ranges::BUILTIN_TEAMS);
    let (meet_txt, meet_src) = read("meet.txt", vc_pipeline::ip_ranges::BUILTIN_MEET);
    let vc_table = vc_pipeline::ip_ranges::IpTable::from_lists(&teams_txt, &meet_txt).unwrap_or_else(|e| die(e));
    let zoom_ips = IpSet::from_text(&zoom_txt).unwrap_or_else(|e| die(format!("zoom list: {e}")));
    // the router relies on the lists being disjoint: a Zoom range inside Teams/Meet would be stolen
    for (lo, hi) in vc_pipeline::ip_ranges::parse_list(&zoom_txt).unwrap_or_default() {
        if vc_table.lookup(lo).is_some() || vc_table.lookup(hi).is_some() {
            die("the Zoom list overlaps the Teams/Meet lists; a packet would belong to two platforms".into());
        }
    }

    // ---- run folder
    let started = now_s();
    let (y, mo, d, h, mi, s) = utc(started);
    let out_dir = args.out_dir.clone().unwrap_or_else(|| PathBuf::from(format!("captures/run_{y:04}{mo:02}{d:02}_{h:02}{mi:02}{s:02}")));
    std::fs::create_dir_all(&out_dir).unwrap_or_else(|e| die(format!("cannot create {}: {e}", out_dir.display())));
    refuse_used_folder(&out_dir);
    std::env::set_current_dir(&out_dir).unwrap_or_else(|e| die(format!("cannot enter {}: {e}", out_dir.display())));
    let run_dir = std::env::current_dir().unwrap_or_default();
    let host = args.host.clone().unwrap_or_else(|| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()).unwrap_or_else(|_| "capture".into()));

    // ---- one budget, one rotation size, for all six kinds of capture file
    let limits = CaptureLimits {
        rotate_bytes: args.rotate_mb.max(1).saturating_mul(1_000_000),
        max_total_bytes: if args.capture_max_mb == 0 { u64::MAX } else { args.capture_max_mb.saturating_mul(1_000_000) },
    };
    let disk = Arc::new(DiskBudget::new(limits));
    let budget: Arc<dyn ByteBudget> = Arc::new(SharedBudget(disk.clone()));

    // ---- InfluxDB: one common target (or two, if separated; see docs/USAGE.md)
    let (zoom_target, zoom_shown) = target_for("ZOOM", "influx_zoom.lp", args.influx_file);
    let (vc_target, vc_shown) = target_for("TEAMS_MEET", "influx_teams_meet.lp", args.influx_file);

    // ---- run_info.txt, start block
    let ri = RunInfo(run_dir.join("run_info.txt"));
    ri.raw("# vc_capture run. key=value lines; tools/check_dups.py reads dedup=, csv=, pcap=.\n");
    ri.put("program", format!("vc_capture {}", env!("CARGO_PKG_VERSION")));
    ri.put("started_unix", started);
    ri.put("started_utc", format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z"));
    ri.put("config", config_path.display());
    ri.put("run_dir", run_dir.display());
    ri.put("host", &host);
    ri.put("dedup", dedup.as_str());
    ri.put("dedup_compiled", dedup_compiled);
    ri.put("csv", if args.csv { "on" } else { "off" });
    ri.put("pcap", if args.pcap { "on" } else { "off" });
    ri.put("pcap_snaplen", args.pcap_snaplen);
    ri.put("capture_max_bytes", if limits.max_total_bytes == u64::MAX { "unlimited".to_string() } else { limits.max_total_bytes.to_string() });
    ri.put("rotate_bytes", limits.rotate_bytes);
    ri.put("ssrc_lines", match args.ssrc_lines { SsrcLines::None => "none", SsrcLines::TeamsMeet => "teams-meet", SsrcLines::All => "all" });
    ri.put("influx_zoom", &zoom_shown);
    ri.put("influx_teams_meet", &vc_shown);
    for (n, src, txt) in [("zoom", &zoom_src, &zoom_txt), ("teams", &teams_src, &teams_txt), ("meet", &meet_src, &meet_txt)] {
        ri.put(&format!("iplist_{n}"), src);
        ri.put(&format!("iplist_{n}_fnv64"), format!("{:016x}", fnv64(txt)));
    }
    ri.put("iplist_zoom_ranges", zoom_ips.len());
    ri.put("iplist_teams_ranges", vc_table.count(vc_pipeline::models::Platform::Teams));
    ri.put("iplist_meet_ranges", vc_table.count(vc_pipeline::models::Platform::Meet));
    ri.put("zoom_ports", "8801-8810,3478,3479");

    println!("vc_capture {}: one capture for Zoom, Teams and Meet", env!("CARGO_PKG_VERSION"));
    println!("[INFO] run folder : {}", run_dir.display());
    println!("[INFO] config     : {}", config_path.display());
    println!(
        "[INFO] dedup={} csv={} pcap={} (snaplen {} B) | all capture files together: {} | new part every {} MB",
        dedup.as_str(),
        args.csv,
        args.pcap,
        args.pcap_snaplen,
        if args.capture_max_mb == 0 { "no limit".to_string() } else { format!("max {} MB", args.capture_max_mb) },
        args.rotate_mb
    );
    println!(
        "[INFO] ip lists   : zoom {} ranges ({zoom_src}), teams {} ({teams_src}), meet {} ({meet_src})",
        zoom_ips.len(),
        vc_table.count(vc_pipeline::models::Platform::Teams),
        vc_table.count(vc_pipeline::models::Platform::Meet)
    );
    println!("[INFO] influx     : zoom -> {zoom_shown}");
    println!("[INFO]              teams/meet -> {vc_shown}");
    if !args.csv && !args.pcap {
        println!("[INFO] no --csv and no --pcap: only metrics are written");
    }

    // ---- Teams / Meet engine
    vc_pipeline::ip_ranges::install(vc_table);
    let vc_cfg = vc_pipeline::engine::EngineCfg {
        dedup,
        csv: args.csv,
        pcap: args.pcap,
        snaplen: args.pcap_snaplen,
        rotate_bytes: limits.rotate_bytes,
        budget: budget.clone(),
        sessions: SessionOpts { target: vc_target, ssrc_lines: args.ssrc_lines != SsrcLines::None },
        health_secs: args.health_secs,
        host: host.clone(),
        record_queue: args.vc_record_queue,
    };
    let vc_running = vc_pipeline::engine::start(vc_cfg);

    // ---- Zoom engine (zoom_capture's main, with the shared budget and the common file names)
    let shards = args.zoom_shards.or_else(|| cores_in_config(&config_path)).unwrap_or(4);
    let pcfg = PipelineConfig {
        shards,
        max_streams: args.zoom_max_streams,
        max_rtp_streams: args.zoom_max_rtp_streams,
        channel_cap: args.zoom_channel_cap,
        dedup: dedup == DedupMode::Fp,
        dump_cap: args.csv.then_some(1 << 18),
        pcap: args.pcap.then(|| PcapCfg { snaplen: args.pcap_snaplen, pool_slots: args.zoom_pcap_pool }.clamped()),
        limits,
        ..Default::default()
    };
    let start = Instant::now();
    let mut built = Pipeline::with_start_budget(pcfg, zoom_ips, start, Some(disk.clone()));
    let files = built.files.clone();
    let pcap_parts = built.pcap.take();
    let pipe = Arc::new(built.pipeline);
    let _ = ZOOM.set(pipe.clone());
    // Two stop flags: `stop` ends the sweeper and the status thread; `files_stop` ends the Zoom
    // CSV/pcap writers only AFTER `pipe.shutdown()` has handed them the last partial batches.
    // (zoom_capture used one flag, so the writers could exit first and the last batch of each
    // core, up to 31 packets, was counted as pcap_drop_queue; seen in the vc_combined e2e test: 37.)
    let stop = Arc::new(AtomicBool::new(false));
    let files_stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(ExportStats::default());
    let sink: Box<dyn Sink> = match zoom_target {
        InfluxTarget::Http { url, token } => Box::new(HttpSink::new(url, token)),
        InfluxTarget::File(p) => Box::new(FileSink::create(&p).unwrap_or_else(|e| die(format!("cannot open {}: {e}", p.display())))),
    };
    let exporter = {
        let st = stats.clone();
        let cfg = ExportCfg { ssrc_lines: args.ssrc_lines == SsrcLines::All, host: host.clone(), ..Default::default() };
        std::thread::Builder::new().name("zoom-exporter".into()).spawn(move || run_exporter(built.export_rx, sink, cfg, start, st)).expect("spawn")
    };
    let zoom_csv = built.dump_rx.map(|rx| {
        let w = CsvWriter::open(rx, Path::new("zoom_record_0001.csv"), &files).unwrap_or_else(|e| die(format!("zoom_record_0001.csv: {e}")));
        let (files, stop) = (files.clone(), files_stop.clone());
        std::thread::spawn(move || w.run(&files, &stop).unwrap_or(0))
    });
    let zoom_pcap = pcap_parts.map(|parts| {
        let w = PcapWriter::open(parts, Path::new("."), &files).unwrap_or_else(|e| die(format!("zoom pcap: {e}")));
        let (files, stop) = (files.clone(), files_stop.clone());
        std::thread::spawn(move || w.run(&files, &stop).unwrap_or(0))
    });
    let sweeper = pipe.spawn_sweeper(stop.clone(), Duration::from_secs(args.health_secs));
    let reporter = {
        let (p, st, stop, every) = (pipe.clone(), stats.clone(), stop.clone(), args.health_secs.max(1));
        std::thread::spawn(move || {
            let mut prev = p.health();
            let t0 = Instant::now();
            let mut last_vc = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                for _ in 0..every * 4 {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
                let cur = p.health();
                println!("[zoom] {}", health_line(&prev, &cur, &st, t0.elapsed().as_secs()));
                prev = cur;
                if last_vc.elapsed() >= Duration::from_secs(15) {
                    println!("{}", vc_pipeline::engine::status_line());
                    last_vc = Instant::now();
                }
            }
        })
    };

    // ---- Retina
    let mut config = load_config(&config_path);
    if let Some(online) = config.online.as_mut() {
        // NIC counters on the console (as the Teams/Meet crate did for the thesis)
        online.monitor = Some(MonitorConfig {
            display: Some(DisplayConfig {
                throughput: true,
                mempool_usage: true,
                port_stats: ["miss", "drop", "discard", "error", "nombuf", "out_of_buffer", "phy"].iter().map(|s| s.to_string()).collect(),
            }),
            log: None,
        });
    }
    println!("[INFO] starting capture. Ctrl+C stops cleanly and flushes every file.");
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    // ---- shutdown: both engines, then run_info end block
    println!("\n[INFO] capture stopped: flushing both engines...");
    stop.store(true, Ordering::Relaxed);
    let _ = sweeper.join();
    let _ = reporter.join();
    pipe.shutdown();
    files_stop.store(true, Ordering::Relaxed);
    let _ = exporter.join();
    let zoom_csv_rows = zoom_csv.map(|h| h.join().unwrap_or(0));
    let zoom_pcap_pkts = zoom_pcap.map(|h| h.join().unwrap_or(0));
    vc_pipeline::engine::stop(vc_running, &host, budget.as_ref());

    let zh = pipe.health();
    let zoom_final = format!(
        "final: in={} zoom={} dups_dropped={} ip_filtered={} port_filtered={} zoom_like_unlisted={} bins_dropped={} streams_rejected={} export_lines_ok={} export_lines_dropped={} rtp_ok={:?} rtp_bad={:?} rtp_short={} video_layout(02/0a/rtp20/other)={:?} rtp20_bytes=[{}] pcap_pkts={} pcap_drops(pool/queue/limit)={}/{}/{} csv_rows={} csv_queue_drops={} limit_tripped={}",
        zh.pkts_in,
        zh.matched,
        zh.dups_dropped,
        zh.ip_filtered,
        zh.port_filtered,
        zh.zoom_like_unlisted,
        zh.bins_dropped,
        zh.streams_rejected,
        stats.lines_ok.load(Ordering::Relaxed),
        stats.lines_dropped.load(Ordering::Relaxed),
        zh.rtp_ok,
        zh.rtp_bad,
        zh.rtp_short,
        zh.video_layout,
        zoom_pipeline::report::rtp20_bytes(zh.video_rtp20_mask),
        zh.pcap_pkts,
        zh.pcap_drop_pool,
        zh.pcap_drop_queue,
        zh.pcap_drop_limit,
        zh.csv_rows,
        zh.dump_dropped,
        zh.capture_limit_tripped,
    );
    let (vc_kv, vc_text) = vc_pipeline::engine::final_report(dedup);
    println!("\nZoom capture statistics\n=======================\n  {zoom_final}");
    if let Some(n) = zoom_csv_rows {
        println!("  zoom csv: {n} rows written");
    }
    if let Some(n) = zoom_pcap_pkts {
        println!("  zoom pcap: {n} packets written");
    }
    println!("\n{vc_text}");
    println!(
        "\nAll capture files: {} bytes of {}{}",
        disk.used(),
        if limits.max_total_bytes == u64::MAX { "no limit".to_string() } else { format!("{} allowed", limits.max_total_bytes) },
        if disk.is_open() { "" } else { "  (LIMIT REACHED: later packets were not written to files; metrics are complete)" }
    );

    let fin = now_s();
    ri.raw("# ---- end of run\n");
    ri.put("finished_unix", fin);
    let (y, mo, d, h, mi, s) = utc(fin);
    ri.put("finished_utc", format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z"));
    ri.put("duration_s", fin.saturating_sub(started));
    ri.put("final_capture_bytes", disk.used());
    ri.put("final_capture_limit_reached", !disk.is_open());
    for (k, v) in [
        ("pkts_in", zh.pkts_in),
        ("matched", zh.matched),
        ("dups_dropped", zh.dups_dropped),
        ("ip_filtered", zh.ip_filtered),
        ("port_filtered", zh.port_filtered),
        ("zoom_like_unlisted", zh.zoom_like_unlisted),
        ("bins_dropped", zh.bins_dropped),
        ("streams_rejected", zh.streams_rejected),
        ("rtp_short", zh.rtp_short),
        ("pcap_pkts", zh.pcap_pkts),
        ("pcap_drop_pool", zh.pcap_drop_pool),
        ("pcap_drop_queue", zh.pcap_drop_queue),
        ("pcap_drop_limit", zh.pcap_drop_limit),
        ("csv_rows", zh.csv_rows),
        ("csv_queue_drops", zh.dump_dropped),
        ("export_lines_ok", stats.lines_ok.load(Ordering::Relaxed)),
        ("export_lines_dropped", stats.lines_dropped.load(Ordering::Relaxed)),
    ] {
        ri.put(&format!("final_zoom_{k}"), v);
    }
    for (k, v) in vc_kv {
        ri.put(&format!("final_teams_meet_{k}"), v);
    }
    // the human-readable final lines, verbatim (the "ending capture line" of each engine)
    ri.raw("# ---- final console lines (verbatim)\n");
    ri.raw(&format!("zoom_final_line={zoom_final}\n"));
    for l in vc_text.lines() {
        ri.raw(&format!("# {l}\n"));
    }
    println!("[INFO] run_info.txt written: {}", run_dir.join("run_info.txt").display());
}
