//! Replay a packet CSV (`--packet-csv`, 25 columns in Stage 1, 27 since p7b) through the real pipeline and the
//! real exporter, and write the Stage-2 line protocol to a file. This is how a campus capture
//! can be turned into metrics (and checked) offline, without the NIC:
//!
//!     replay_packets packets.csv --lp metrics.lp
//!     python3 -I tools/verify_metrics.py packets.csv metrics.lp
//!
//! The CSV is a partial view of each packet, so the frame is REBUILT: Ethernet/IP/UDP around a
//! payload that has exactly the fields the CSV records (SFU header with counter and direction
//! bit, media type, media sequence/timestamp, frame sequence/count, and the inner RTP header at
//! the documented offset when `rtp_ver_ok` is set, and since p7b media bytes 20 and 7 from the
//! `media_b20` / `media_b7` columns). Bytes the CSV does not record are zero, so
//! two different packets that agree on every column look identical to the de-dup; that can only
//! make the replay's de-dup slightly more eager than the live one.
//!
//! CSVs written before p7b have no `media_b20` / `media_b7` columns. They still replay, with the old
//! assumptions: video is rebuilt at +24 with byte 20 = 0x02, and a type-13 row is given sub-type
//! 0x1e when its `rtp_ver_ok` is 1 and 0x00 otherwise. That is NOT what the packets carried, so such a
//! replay cannot show the +20 layout or `t13_probe`; use a p7b CSV, or `replay_pcap` on the pcap.
//!
//! Needs real (or synthetic) IP addresses in the CSV, not anonymised names, and server
//! addresses that are in the Zoom list (they are, if the CSV came from the capture).
//!
//! Usage: replay_packets [--lp FILE] [--ssrc-lines] [--no-dedup] [--shards N] packets.csv
//! Rows flagged `dup=1` are replayed too (the de-dup should flag them again); with `--no-dedup`
//! they are skipped so the output is the same either way.

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
    udp_len: usize,
    src: Addr,
    dst: Addr,
    sport: u16,
    dport: u16,
    down: bool,
    class: String,
    ty: u8,
    sfu_seq: u16,
    mseq: u16,
    mts: u32,
    fseq: u16,
    fcnt: u8,
    ttl: u8,
    ip_id: u16,
    dup: bool,
    rtp: Option<(u32, u32, u16, u8, bool)>, // ssrc, ts, seq, pt, marker
    core: usize,
    /// media bytes 20 and 7 (p7b CSV columns); None for older CSVs and for payloads too short to hold them
    b20: Option<u8>,
    b7: Option<u8>,
}

fn num<T: std::str::FromStr + Default>(s: &str) -> T {
    s.trim().parse().unwrap_or_default()
}

fn hex_or_dec(s: &str) -> u32 {
    let s = s.trim();
    s.strip_prefix("0x").map(|h| u32::from_str_radix(h, 16).unwrap_or(0)).unwrap_or_else(|| s.parse().unwrap_or(0))
}

fn parse(path: &str) -> Vec<Row> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let mut lines = text.lines();
    let head: Vec<&str> = lines.next().expect("empty csv").split(',').collect();
    let col = |n: &str| head.iter().position(|h| *h == n).unwrap_or_else(|| panic!("{path}: no column {n} (is this a --packet-csv file with the RTP columns?)"));
    let (c_t, c_len, c_src, c_dst, c_sp, c_dp, c_dir, c_cls, c_ty) = (col("time_offset_s"), col("udp_len"), col("src_ip"), col("dst_ip"), col("src_port"), col("dst_port"), col("dir"), col("class"), col("media_type_byte"));
    let (c_sfu, c_ms, c_mt, c_fs, c_fc, c_ttl, c_id, c_dup) = (col("sfu_seq"), col("media_sequence"), col("media_timestamp"), col("frame_seq"), col("frame_pkt_count"), col("ip_ttl"), col("ip_id"), col("dup"));
    let (c_ssrc, c_rts, c_rseq, c_pt, c_mk, c_ok, c_core) = (col("rtp_ssrc"), col("rtp_timestamp"), col("rtp_seq"), col("rtp_pt"), col("rtp_marker"), col("rtp_ver_ok"), col("core"));
    // p7b columns: optional, so a Stage-1 CSV still loads
    let opt = |n: &str| head.iter().position(|h| *h == n);
    let (c_b20, c_b7) = (opt("media_b20"), opt("media_b7"));
    let cell_u8 = |f: &[&str], c: Option<usize>| c.and_then(|c| f.get(c)).and_then(|v| v.trim().parse::<u8>().ok());
    let ip = |s: &str| match s.parse::<IpAddr>() {
        Ok(a) => Addr::from_ip(a),
        Err(_) => panic!("{path}: '{s}' is not an IP address (anonymised CSV?)"),
    };
    let mut out = Vec::new();
    for line in lines {
        let f: Vec<&str> = line.split(',').collect();
        if f.len() < head.len() {
            continue;
        }
        out.push(Row {
            t_us: (f[c_t].parse::<f64>().unwrap() * 1e6).round() as u64,
            udp_len: num(f[c_len]),
            src: ip(f[c_src]),
            dst: ip(f[c_dst]),
            sport: num(f[c_sp]),
            dport: num(f[c_dp]),
            down: f[c_dir] == "down",
            class: f[c_cls].to_string(),
            ty: num(f[c_ty]),
            sfu_seq: num(f[c_sfu]),
            mseq: num(f[c_ms]),
            mts: num(f[c_mt]),
            fseq: num(f[c_fs]),
            fcnt: num(f[c_fc]),
            ttl: if f[c_ttl].is_empty() { 64 } else { num(f[c_ttl]) },
            ip_id: num(f[c_id]),
            dup: f[c_dup] != "0",
            rtp: (f[c_ok] == "1").then(|| (hex_or_dec(f[c_ssrc]), num(f[c_rts]), num(f[c_rseq]), num(f[c_pt]), f[c_mk] == "1")),
            core: num(f[c_core]),
            b20: cell_u8(&f, c_b20),
            b7: cell_u8(&f, c_b7),
        });
    }
    out
}

/// RTP header offset inside the media header, per type byte (headers.rs). p7a: type 30 is +20 (p6: +27).
/// Video: media byte 20 selects +24 (0x02), +28 (0x0a) or +20 (0x80-0xBF, p7b); a CSV without the
/// `media_b20` column (before p7b) is rebuilt as the normal layout (+24, byte 20 = 0x02), because the
/// metrics depend only on the RTP fields and those CSVs recorded them read at +24 / +28.
fn rtp_offset(ty: u8, b20: Option<u8>) -> Option<usize> {
    match ty {
        16 => Some(match b20 {
            Some(0x0a) => 28,
            Some(b) if b >> 6 == 2 => 20,
            _ => 24,
        }),
        15 => Some(19),
        13 => Some(27),
        30 => Some(20),
        _ => None,
    }
}

fn payload(r: &Row) -> Vec<u8> {
    let len = r.udp_len.saturating_sub(8);
    let mut p = vec![0u8; len];
    let put = |p: &mut Vec<u8>, off: usize, b: &[u8]| {
        if off + b.len() <= p.len() {
            p[off..off + b.len()].copy_from_slice(b);
        }
    };
    if r.class == "nohdr" {
        put(&mut p, 0, &[23]); // anything but the SFU marker 0x05
        return p;
    }
    put(&mut p, 0, &[0x05]);
    put(&mut p, 1, &r.sfu_seq.to_be_bytes());
    put(&mut p, 7, &[if r.down { 0x04 } else { 0x00 }]);
    put(&mut p, 8, &[r.ty]);
    put(&mut p, 8 + 9, &r.mseq.to_be_bytes());
    put(&mut p, 8 + 11, &r.mts.to_be_bytes());
    put(&mut p, 8 + 21, &r.fseq.to_be_bytes());
    put(&mut p, 8 + 23, &[r.fcnt]);
    if r.ty == 16 {
        put(&mut p, 8 + 20, &[r.b20.unwrap_or(0x02)]); // the layout byte (0x02 for CSVs that did not record it)
    }
    if r.ty == 13 {
        // the type-13 sub-type (p7b gate): recorded in p7b CSVs; for older ones a row with a readable RTP
        // header is rebuilt as 0x1e and every other row as 0x00 (control), see the header comment
        let b7 = r.b7.unwrap_or(if r.rtp.is_some() { 0x1e } else { 0x00 });
        put(&mut p, 8 + 7, &[b7]);
    }
    if let (Some((ssrc, ts, seq, pt, mk)), Some(off)) = (r.rtp, rtp_offset(r.ty, r.b20)) {
        let o = 8 + off;
        put(&mut p, o, &[0x80]);
        put(&mut p, o + 1, &[pt | if mk { 0x80 } else { 0 }]);
        put(&mut p, o + 2, &seq.to_be_bytes());
        put(&mut p, o + 4, &ts.to_be_bytes());
        put(&mut p, o + 8, &ssrc.to_be_bytes());
        if r.ty == 16 {
            // for the +20 layout byte 20 IS the first RTP byte (0x90 = version 2 + extension bit): restore it
            if let Some(b) = r.b20.filter(|b| b >> 6 == 2) {
                put(&mut p, 8 + 20, &[b]);
            }
        }
    }
    p
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let (mut dedup, mut ssrc_lines, mut lp, mut shards) = (true, false, None::<PathBuf>, None::<usize>);
    let mut files = vec![];
    while !args.is_empty() {
        let a = args.remove(0);
        match a.as_str() {
            "--no-dedup" => dedup = false,
            "--ssrc-lines" => ssrc_lines = true,
            "--lp" => lp = Some(PathBuf::from(args.remove(0))),
            "--shards" => shards = Some(args.remove(0).parse().expect("--shards N")),
            _ => files.push(a),
        }
    }
    if files.len() != 1 {
        eprintln!("usage: replay_packets [--lp FILE] [--ssrc-lines] [--no-dedup] [--shards N] packets.csv");
        std::process::exit(2);
    }
    let path = &files[0];
    let mut rows = parse(path);
    if !dedup {
        rows.retain(|r| !r.dup);
    }
    // the CSV is written in per-core batches: replay in time order, as the live pipeline saw it
    rows.sort_by_key(|r| r.t_us);
    let csv_dups = rows.iter().filter(|r| r.dup).count();
    let n_shards = shards.unwrap_or_else(|| rows.iter().map(|r| r.core).max().map_or(1, |m| m + 1));
    let cfg = PipelineConfig { shards: n_shards, dedup, channel_cap: 1 << 22, probation_slots: 1 << 16, ..Default::default() };
    let built = Pipeline::new(cfg, IpSet::zoom_default());
    let p = built.pipeline;
    let lp_path = lp.unwrap_or_else(|| PathBuf::from(format!("{path}.lp")));
    let _ = std::fs::remove_file(&lp_path);
    let sink = FileSink::create(&lp_path).expect("open --lp file");
    let stats = std::sync::Arc::new(ExportStats::default());
    let (st2, start) = (stats.clone(), p.start());
    let ecfg = ExportCfg { host: "replay".into(), ssrc_lines, ..Default::default() };
    let rx = built.export_rx;
    let h = std::thread::spawn(move || run_exporter(rx, Box::new(sink), ecfg, start, st2));
    let mut by_type: HashMap<&str, u64> = HashMap::new();
    let t0 = std::time::Instant::now();
    for r in &rows {
        let pay = payload(r);
        let f = frame(&Spec { ttl: r.ttl, ip_id: r.ip_id, ..Spec::new(r.src, r.dst, r.sport, r.dport, &pay) });
        p.on_frame_at(r.core % n_shards, r.t_us, &f);
        *by_type.entry(if r.rtp.is_some() { "with RTP header" } else { "without" }).or_default() += 1;
    }
    let dt = t0.elapsed();
    p.shutdown();
    h.join().unwrap();
    let hl = p.health();
    println!("replay: {} rows ({} flagged dup in the CSV), {} shards, {:.0} ns/row", rows.len(), csv_dups, n_shards, dt.as_nanos() as f64 / rows.len().max(1) as f64);
    println!("pipeline: pkts_in={} matched={} dups_dropped={} port_filtered={} ip_filtered={} no_sfu={}", hl.pkts_in, hl.matched, hl.dups_dropped, hl.port_filtered, hl.ip_filtered, hl.no_sfu);
    println!("hub: qualified={} failed={} sightings={} rejected={}", hl.rtp_qualified, hl.rtp_failed_qual, hl.rtp_probation_skipped, hl.rtp_streams_rejected);
    println!("dup flags: CSV {} vs replay {}{}", csv_dups, hl.dups_dropped, if !dedup { " (de-dup off)" } else if csv_dups as u64 == hl.dups_dropped { "  -> same" } else { "  -> DIFFERENT (unrecorded bytes, or a CSV that dropped rows)" });
    println!("export: {} lines -> {}  (lines_ok={}, dropped={})", std::fs::read_to_string(&lp_path).map(|s| s.lines().count()).unwrap_or(0), lp_path.display(), stats.lines_ok.load(std::sync::atomic::Ordering::Relaxed), stats.lines_dropped.load(std::sync::atomic::Ordering::Relaxed));
}
