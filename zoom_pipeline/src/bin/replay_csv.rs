//! Replay the old `zoom_udp.csv` sample captures through the real pipeline.
//!
//! The CSV is a post-gate, partial view of each packet: it has the 5-tuple,
//! frame length, Zoom media type, media sequence/timestamp, frame_seq,
//! frame_pkt_count and the SFU direction bit, but not the outer SFU sequence
//! or any RTP bytes. This tool rebuilds a byte-accurate Ethernet/IP/UDP
//! frame with exactly those fields, so the **same `Pipeline::on_frame_at`
//! the Retina callback calls** runs on real traffic structure and real
//! inter-packet timing.
//!
//! Limitation (stated in LOG.md): two *different* packets that agree on every
//! CSV field would look identical here (and to the oracle); real packets also
//! differ in the unseen bytes, so the fingerprint can only do better live.
//!
//! Usage: replay_csv [--no-dedup] [--lp out.lp] file.csv [file2.csv ...]

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use zoom_pipeline::export::{run_exporter, ExportCfg, ExportStats, FileSink};
use zoom_pipeline::ipset::IpSet;
use zoom_pipeline::net::build::{frame, Spec};
use zoom_pipeline::net::Addr;
use zoom_pipeline::pipeline::{Pipeline, PipelineConfig};

struct Row {
    t_us: u64,
    frame_len: usize,
    src: Addr,
    dst: Addr,
    sport: u16,
    dport: u16,
    dir_from_sfu: Option<bool>,
    type_byte: u8,
    seq: u16,
    ts: u32,
    frame_seq: Option<u16>,
    pkt_cnt: Option<u8>,
}

fn parse_rows(path: &str) -> Vec<Row> {
    let text = std::fs::read_to_string(path).expect("read csv");
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            continue;
        }
        let f: Vec<&str> = line.split(',').collect();
        if f.len() < 14 {
            continue;
        }
        let ip = |s: &str| Addr::from_ip(s.parse::<IpAddr>().expect("ip"));
        out.push(Row {
            t_us: (f[0].parse::<f64>().unwrap() * 1e6).round() as u64,
            frame_len: f[1].parse().unwrap(),
            src: ip(f[2]),
            dst: ip(f[3]),
            sport: f[4].parse().unwrap(),
            dport: f[5].parse().unwrap(),
            dir_from_sfu: match f[6] {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
            type_byte: f[7].parse().unwrap(),
            seq: f[9].parse().unwrap(),
            ts: f[10].parse().unwrap(),
            frame_seq: f[11].parse().ok(),
            pkt_cnt: f[12].parse().ok(),
        });
    }
    out
}

fn payload_for(r: &Row) -> Vec<u8> {
    let overhead = if r.src.is_v4() { 42 } else { 62 };
    let len = r.frame_len.saturating_sub(overhead);
    let mut p = vec![0u8; len];
    let put = |p: &mut Vec<u8>, off: usize, b: &[u8]| {
        if off + b.len() <= p.len() {
            p[off..off + b.len()].copy_from_slice(b);
        }
    };
    let base = if r.dir_from_sfu.is_some() {
        put(&mut p, 0, &[0x05]);
        put(&mut p, 7, &[if r.dir_from_sfu == Some(true) { 0x04 } else { 0x00 }]);
        8
    } else {
        0
    };
    put(&mut p, base, &[r.type_byte]);
    put(&mut p, base + 9, &r.seq.to_be_bytes());
    put(&mut p, base + 11, &r.ts.to_be_bytes());
    if let Some(fs) = r.frame_seq {
        put(&mut p, base + 21, &fs.to_be_bytes());
    }
    if let Some(c) = r.pkt_cnt {
        put(&mut p, base + 23, &[c]);
    }
    p
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut dedup = true;
    let mut slots = 16_384usize;
    let mut window_us = 10_000u64;
    let mut quiet_lp = false;
    let mut lp: Option<PathBuf> = None;
    let mut files = Vec::new();
    while !args.is_empty() {
        let a = args.remove(0);
        match a.as_str() {
            "--no-dedup" => dedup = false,
            "--lp" => lp = Some(PathBuf::from(args.remove(0))),
            "--slots" => slots = args.remove(0).parse().unwrap(),
            "--window-us" => window_us = args.remove(0).parse().unwrap(),
            "--no-lp" => quiet_lp = true,
            _ => files.push(a),
        }
    }
    for path in files {
        let rows = parse_rows(&path);
        println!("\n=== {path}: {} rows", rows.len());
        let cfg = PipelineConfig { shards: 1, dedup, dedup_slots: slots, dedup_window_us: window_us, dump_cap: Some(rows.len() + 16), channel_cap: 1 << 20, ..Default::default() };
        let built = Pipeline::new(cfg.clone(), IpSet::zoom_default());
        let p = built.pipeline;
        let dump_rx = built.dump_rx.unwrap();

        // ---- oracle: exact key, unlimited memory, same window and the same
        // "slot keeps the first copy's time" rule
        let mut last: HashMap<(Addr, Addr, u16, u16, usize, u8, u16, u32, Option<u16>, Option<u8>, Option<bool>), u64> = HashMap::new();
        let mut oracle_dup = Vec::with_capacity(rows.len());
        let mut long_gap_repeats = 0u64;
        let mut oracle_kept_ok = 0u64;
        let mut oracle_kept_bytes = 0u64;
        for r in &rows {
            let k = (r.src, r.dst, r.sport, r.dport, r.frame_len, r.type_byte, r.seq, r.ts, r.frame_seq, r.pkt_cnt, r.dir_from_sfu);
            let is_dup = match last.get(&k) {
                Some(&t0) if (r.t_us as i64 - t0 as i64).unsigned_abs() < cfg.dedup_window_us => true,
                Some(_) => {
                    long_gap_repeats += 1;
                    false
                }
                None => false,
            };
            if !is_dup {
                last.insert(k, r.t_us);
                let port_ok = |p: u16| (8801..=8810).contains(&p);
                if port_ok(r.sport) || port_ok(r.dport) {
                    oracle_kept_ok += 1;
                    oracle_kept_bytes += payload_for(r).len() as u64;
                }
            }
            oracle_dup.push(is_dup);
        }

        // ---- exporter writing line protocol to a file
        let lp_path = lp.clone().unwrap_or_else(|| PathBuf::from(if quiet_lp { "/dev/null".to_string() } else { format!("{}.lp", path) }));
        if !quiet_lp { let _ = std::fs::remove_file(&lp_path); }
        let sink = FileSink::create(&lp_path).expect("lp file");
        let stats = std::sync::Arc::new(ExportStats::default());
        let st2 = stats.clone();
        let start = p.start();
        let ecfg = ExportCfg { host: "replay".into(), ..Default::default() };
        let h = std::thread::spawn(move || run_exporter(built.export_rx, Box::new(sink), ecfg, start, st2));

        let t0 = std::time::Instant::now();
        for r in &rows {
            let pay = payload_for(r);
            let f = frame(&Spec::new(r.src, r.dst, r.sport, r.dport, &pay));
            p.on_frame_at(0, r.t_us, &f);
        }
        let dt = t0.elapsed();
        p.sweep_once(u64::MAX / 4);
        p.shutdown();
        h.join().unwrap();

        // ---- compare dedup decisions row by row. Only rows whose port passes the
        // gate produce a dump record, so walk the same filter on the oracle side
        // (matching on timestamps is wrong when many rows share one microsecond).
        let port_ok = |p: u16| (8801..=8810).contains(&p);
        let (mut tp, mut fp, mut fnn) = (0u64, 0u64, 0u64);
        let mut dumps = dump_rx.try_iter();
        for (i, r) in rows.iter().enumerate() {
            if !(port_ok(r.sport) || port_ok(r.dport)) {
                continue;
            }
            let Some(d) = dumps.next() else { break };
            assert_eq!(d.t_us, r.t_us, "alignment lost at row {i}");
            match (oracle_dup[i], d.dup) {
                (true, true) => tp += 1,
                (false, true) => fp += 1,
                (true, false) => fnn += 1,
                _ => {}
            }
        }
        let hl = p.health();
        let truth = rows.iter().zip(oracle_dup.iter()).filter(|(r, &d)| d && (port_ok(r.sport) || port_ok(r.dport))).count() as u64;
        println!("pipeline: pkts_in={} port_filtered={} ip_filtered={} parse_fail={} dups_dropped={} matched={} no_sfu={} streams={} bins_emitted={} bins_dropped={}",
            hl.pkts_in, hl.port_filtered, hl.ip_filtered, hl.parse_fail, hl.dups_dropped, hl.matched, hl.no_sfu, hl.streams_active, hl.bins_emitted, hl.bins_dropped);
        println!("dedup:    oracle twins={} ({:.2}% of rows)  flagged={}  TP={} FP={} FN={}  recall={:.3}%  precision={:.3}%",
            truth, 100.0 * truth as f64 / rows.len().max(1) as f64, tp + fp, tp, fp, fnn,
            100.0 * tp as f64 / (tp + fnn).max(1) as f64, 100.0 * tp as f64 / (tp + fp).max(1) as f64);
        println!("          same-key repeats farther apart than the window (kept as retransmissions): {long_gap_repeats}");
        println!("totals:   matched={} (oracle kept & port-ok = {})  matched_bytes={} (oracle {})  -> {}",
            hl.matched, oracle_kept_ok, hl.matched_bytes, oracle_kept_bytes,
            if !dedup { "dedup off".to_string() } else if hl.matched == oracle_kept_ok && hl.matched_bytes == oracle_kept_bytes { "EXACT MATCH".to_string() } else { format!("diff {} pkts", hl.matched as i64 - oracle_kept_ok as i64) });
        println!("speed:    {:.1} ns/row including frame construction ({} rows in {:.2?})", dt.as_nanos() as f64 / rows.len().max(1) as f64, rows.len(), dt);
        println!("export:   {} lines written to {}  (lines_ok={}, dropped={})", std::fs::read_to_string(&lp_path).map(|s| s.lines().count()).unwrap_or(0), lp_path.display(), stats.lines_ok.load(std::sync::atomic::Ordering::Relaxed), stats.lines_dropped.load(std::sync::atomic::Ordering::Relaxed));
    }
}
