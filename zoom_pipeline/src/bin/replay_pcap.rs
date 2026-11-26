//! Replay one or more classic pcap files through the real pipeline and the real exporter and write
//! the line protocol to a file. New in p7b (roadmap Step 1, "replay the evening pcaps, p7a and p7b
//! side by side"): until now only CSVs could be replayed, and a CSV does not record media byte 20,
//! byte 7 or the bytes behind them, so the new layout and gate rules could not be tested on the
//! real campus capture with it.
//!
//!     replay_pcap --no-dedup --lp p7b.lp eve_part1.pcap eve_part2.pcap
//!     python3 -I tools/compare_replays.py p7a.lp p7b.lp
//!
//! Why `--no-dedup` for the files `zoom_capture --pcap` writes: they hold UNIQUE packets only (the
//! capture de-duplicates before it writes), so a second de-dup pass has nothing to find and can
//! only hash the 128-byte truncated payloads. Without the flag, de-dup runs as live.
//!
//! What is replayed: every Ethernet frame goes through `Pipeline::on_frame_at`, the function the
//! Retina callback calls (port gate, IP gate, parse, hub, aggregation), with the capture's own
//! timestamps (microseconds since the first packet).
//!
//! RE-SORTING. The records of a `zoom_capture --pcap-dir` file are NOT in time order: one writer
//! thread per RX core appends its batches to the same file, so a flow whose two copies came in on
//! different cores, or whose packets moved between cores, is interleaved with other batches (the
//! demo's 20 s call has ~1,100 backwards steps; `tools/validate_rtp_csv.py` reports the same for
//! real captures as "normal"). RTP qualification needs sequence order (>= 90 % forward steps), so a
//! replay that fed the records in file order would fail streams that qualify live. Records are
//! therefore held in a 0.5 s window (`REORDER_US`, the window `tools/probe_unknown_types.py` uses; a
//! batch is flushed every 100 ms) and released in timestamp order. The summary line says how many
//! records had to be moved and how many were older than the window (those are clamped to the last
//! released time; a non-zero count there means the window is too small for that file). Snaplen 128 B is enough for every rule in
//! p7b: media byte 7 is at payload offset 15, byte 20 at 28, and the deepest RTP header (+28
//! media, +36 payload) ends at byte 48.
//!
//! This file uses only API that exists in p7a AND p7b (`Pipeline::on_frame_at`, `health`,
//! `export::health_lines`, `RTP_SLOT_NAMES`), so the same source compiles in both trees: copy
//! `replay_pcap.rs` into `zoom_pipeline/src/bin/` of the p7a tree to produce the baseline `.lp`.
//!
//! Output: the `.lp` file gets the normal `session_metrics` / `client_no_media` / `session_summary`
//! lines plus one final `capture_health` line (with the p7b layout counters when run on p7b).
//! The timestamps are replay wall-clock based (like `replay_packets`): compare two runs with
//! `tools/compare_replays.py`, which aligns them by relative time.
//!
//! Byte totals. The records are cut at the capture's snaplen (128 B by default) and `Pipeline::on_frame_at`
//! sees only that, so the replay's byte and `*_bps` fields count CAPTURED bytes, not wire bytes (on the demo
//! a 1,051 B probe packet adds 82 B). Packet counts, layouts, qualification, loss, jitter, fps and every
//! percentage are unaffected, and two replays of the same file (p7a, p7b) are cut identically, so
//! `tools/compare_replays.py` stays valid. Do not read a replay's bitrates as bitrates.
//!
//! Limits: classic pcap only (little or big endian, microsecond or nanosecond timestamps,
//! Ethernet). pcapng is refused with a hint (`editcap -F pcap in.pcapng out.pcap`). Two pcaps are
//! replayed one after the other, in the order given, with their timestamps respected.
//!
//! Usage: replay_pcap [--lp FILE] [--ssrc-lines] [--no-dedup] [--max-packets N] file.pcap [file2.pcap ...]

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use zoom_pipeline::export::{health_lines, run_exporter, ExportCfg, ExportStats, FileSink};
use zoom_pipeline::headers::RTP_SLOT_NAMES;
use zoom_pipeline::ipset::IpSet;
use zoom_pipeline::pipeline::{Pipeline, PipelineConfig};

/// How far out of order the records of one file can be (microseconds). See the module doc.
const REORDER_US: i128 = 500_000;

/// Hands records to the pipeline in timestamp order with times relative to the first one.
struct Feeder {
    base: Option<i128>,
    last_t_us: u64,
    /// records older than something already released (the disorder exceeded the window): clamped
    too_old: u64,
}

impl Feeder {
    fn release(&mut self, p: &Pipeline, ts_us: i128, frame: &[u8]) {
        let base = *self.base.get_or_insert(ts_us);
        let raw = ts_us - base;
        let t = if raw < self.last_t_us as i128 {
            self.too_old += 1;
            self.last_t_us
        } else {
            raw as u64
        };
        self.last_t_us = t;
        p.on_frame_at(0, t, frame);
    }
}

/// Byte order and timestamp unit of a classic pcap, from its magic number.
struct Fmt {
    be: bool,
    nanos: bool,
}

fn rd32(b: &[u8], be: bool) -> u32 {
    let a = [b[0], b[1], b[2], b[3]];
    if be {
        u32::from_be_bytes(a)
    } else {
        u32::from_le_bytes(a)
    }
}

fn read_global(r: &mut impl Read, path: &str) -> Fmt {
    let mut g = [0u8; 24];
    r.read_exact(&mut g).unwrap_or_else(|e| fail(&format!("{path}: cannot read the pcap header: {e}")));
    let magic = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let fmt = match magic {
        0xa1b2_c3d4 => Fmt { be: false, nanos: false },
        0xd4c3_b2a1 => Fmt { be: true, nanos: false },
        0xa1b2_3c4d => Fmt { be: false, nanos: true },
        0x4d3c_b2a1 => Fmt { be: true, nanos: true },
        0x0a0d_0d0a => fail(&format!("{path}: this is a pcapng file; convert it first: editcap -F pcap {path} out.pcap")),
        m => fail(&format!("{path}: not a pcap file (magic {m:#010x})")),
    };
    let linktype = rd32(&g[20..24], fmt.be);
    if linktype != 1 {
        fail(&format!("{path}: link type {linktype}, only Ethernet (1) is supported"));
    }
    fmt
}

fn fail(msg: &str) -> ! {
    eprintln!("replay_pcap: {msg}");
    std::process::exit(2);
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let (mut dedup, mut ssrc_lines, mut lp, mut max_packets) = (true, false, None::<PathBuf>, u64::MAX);
    let mut files = vec![];
    while !args.is_empty() {
        let a = args.remove(0);
        match a.as_str() {
            "--no-dedup" => dedup = false,
            "--ssrc-lines" => ssrc_lines = true,
            "--lp" => lp = Some(PathBuf::from(args.remove(0))),
            "--max-packets" => max_packets = args.remove(0).parse().expect("--max-packets N"),
            _ => files.push(a),
        }
    }
    if files.is_empty() {
        eprintln!("usage: replay_pcap [--lp FILE] [--ssrc-lines] [--no-dedup] [--max-packets N] file.pcap [file2.pcap ...]");
        std::process::exit(2);
    }

    // one shard: the replay is single-threaded and deterministic (no RSS split to reproduce)
    let cfg = PipelineConfig { shards: 1, dedup, channel_cap: 1 << 22, probation_slots: 1 << 16, ..Default::default() };
    let built = Pipeline::new(cfg, IpSet::zoom_default());
    let p = built.pipeline;
    let lp_path = lp.unwrap_or_else(|| PathBuf::from(format!("{}.lp", files[0])));
    let _ = std::fs::remove_file(&lp_path);
    let sink = FileSink::create(&lp_path).expect("open --lp file");
    let stats = std::sync::Arc::new(ExportStats::default());
    let (st2, start) = (stats.clone(), p.start());
    let ecfg = ExportCfg { host: "replay".into(), ssrc_lines, ..Default::default() };
    let rx = built.export_rx;
    let exporter = std::thread::spawn(move || run_exporter(rx, Box::new(sink), ecfg, start, st2));

    let t0 = std::time::Instant::now();
    let (mut n, mut bytes) = (0u64, 0u64);
    let (mut newest, mut moved) = (i128::MIN, 0u64);
    // min-heap on (timestamp, arrival number); the arrival number keeps equal timestamps in file order
    let mut heap: BinaryHeap<Reverse<(i128, u64, Vec<u8>)>> = BinaryHeap::new();
    let mut feed = Feeder { base: None, last_t_us: 0, too_old: 0 };
    let mut buf = vec![0u8; 65_536];
    'files: for path in &files {
        let f = std::fs::File::open(path).unwrap_or_else(|e| fail(&format!("open {path}: {e}")));
        let mut r = BufReader::with_capacity(1 << 20, f);
        let fmt = read_global(&mut r, path);
        loop {
            let mut h = [0u8; 16];
            match r.read_exact(&mut h) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break, // clean end, or a file cut mid-header
                Err(e) => fail(&format!("{path}: {e}")),
            }
            let (sec, sub, incl) = (rd32(&h[0..4], fmt.be) as i128, rd32(&h[4..8], fmt.be) as i128, rd32(&h[8..12], fmt.be) as usize);
            if incl > buf.len() {
                fail(&format!("{path}: record of {incl} bytes is larger than 64 KiB (corrupt file?)"));
            }
            if r.read_exact(&mut buf[..incl]).is_err() {
                eprintln!("replay_pcap: {path}: last record is cut short, stopping this file");
                break;
            }
            let ts_us = sec * 1_000_000 + if fmt.nanos { sub / 1000 } else { sub };
            if ts_us < newest {
                moved += 1; // arrived after a newer record: the heap puts it back in order
            }
            newest = newest.max(ts_us);
            heap.push(Reverse((ts_us, n, buf[..incl].to_vec())));
            n += 1;
            bytes += incl as u64;
            while let Some(Reverse((ts, _, _))) = heap.peek() {
                if *ts >= newest - REORDER_US {
                    break;
                }
                let Reverse((ts, _, data)) = heap.pop().expect("peeked");
                feed.release(&p, ts, &data);
            }
            if n >= max_packets {
                break 'files;
            }
        }
    }
    while let Some(Reverse((ts, _, data))) = heap.pop() {
        feed.release(&p, ts, &data);
    }
    let dt = t0.elapsed();
    p.shutdown();
    exporter.join().unwrap();
    let hl = p.health();

    // one capture_health line at the end of the file (the replay has no periodic health task)
    let mut hline = String::new();
    health_lines(&hl, &stats, "replay", 0, &mut hline);
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&lp_path) {
        let _ = f.write_all(hline.as_bytes());
    }

    println!(
        "replay: {n} packets ({:.1} MB in the file records), {:.1} s of capture time, {:.0} ns/packet, de-dup {}, re-sorted {moved} records ({:.1} %), {} older than the 0.5 s window",
        bytes as f64 / 1e6,
        feed.last_t_us as f64 / 1e6,
        dt.as_nanos() as f64 / n.max(1) as f64,
        if dedup { "on" } else { "off" },
        100.0 * moved as f64 / n.max(1) as f64,
        feed.too_old
    );
    println!(
        "pipeline: pkts_in={} matched={} dups_dropped={} port_filtered={} ip_filtered={} parse_fail={} no_sfu={}",
        hl.pkts_in, hl.matched, hl.dups_dropped, hl.port_filtered, hl.ip_filtered, hl.parse_fail, hl.no_sfu
    );
    let rtp: Vec<String> = RTP_SLOT_NAMES
        .iter()
        .enumerate()
        .map(|(k, name)| {
            let tot = hl.rtp_ok[k] + hl.rtp_bad[k];
            if tot == 0 {
                format!("{name}:-")
            } else {
                format!("{name}:{:.2}% ({}/{tot})", 100.0 * hl.rtp_ok[k] as f64 / tot as f64, hl.rtp_ok[k])
            }
        })
        .collect();
    println!("rtp_v2 self-check: {}  rtp_short={}", rtp.join("  "), hl.rtp_short);
    // 3 slots in p7a [02, 0a, other], 4 in p7b [02, 0a, rtp20, other]
    println!("video_layout counters: {:?}", hl.video_layout);
    println!("hub: qualified={} failed={} sightings={} rejected={}", hl.rtp_qualified, hl.rtp_failed_qual, hl.rtp_probation_skipped, hl.rtp_streams_rejected);
    println!(
        "export: {} lines -> {}  (lines_ok={}, dropped={})",
        std::fs::read_to_string(&lp_path).map(|s| s.lines().count()).unwrap_or(0),
        lp_path.display(),
        stats.lines_ok.load(std::sync::atomic::Ordering::Relaxed),
        stats.lines_dropped.load(std::sync::atomic::Ordering::Relaxed)
    );
}
