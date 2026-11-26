//! What does the pcap tap (and the RTP parse in front of it) cost the capture core?
//!
//! Usage: bench_pcap SCRATCH_DIR [packets]      (build with --release)
//!
//! Part 1  parse_rtp alone: ns per call, tight loop, no I/O.
//! Part 2  the whole per-packet path (`on_frame_at`) with the tap OFF vs ON,
//!         paced at ~250 kpps in 256-packet batches. Only the time spent inside
//!         `on_frame_at` is measured (two clock reads per batch), so the number
//!         is what the capture core pays, not what the pacing loop does.
//!         The writer thread really writes pcap files under SCRATCH_DIR.
//! Part 3  saturation: no pacing, so the writer cannot keep up. The capture
//!         core must stay at the same ns/packet while the drop counters rise;
//!         that is the property "the tap never blocks capture" in numbers.
//!
//! This sandbox has 2 vCPUs shared with the writer thread and a noisy
//! neighbour, so absolute numbers are indicative; compare lines within one run.

use std::hint::black_box;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zoom_pipeline::capture_files::{PcapCfg, PcapWriter};
use zoom_pipeline::headers::parse_rtp;
use zoom_pipeline::ipset::IpSet;
use zoom_pipeline::net::build::{frame, Spec};
use zoom_pipeline::net::Addr;
use zoom_pipeline::pipeline::{Pipeline, PipelineConfig};

fn zoom_payload(i: u32) -> Vec<u8> {
    let (mt, len, off) = if i % 5 == 0 { (15u8, 200usize, 19usize) } else { (16u8, 1150usize, 24usize) };
    let mut p = vec![0u8; len];
    p[0] = 5;
    p[1..3].copy_from_slice(&(i as u16).to_be_bytes());
    p[7] = 4;
    p[8] = mt;
    p[17..19].copy_from_slice(&(i as u16).to_be_bytes());
    p[19..23].copy_from_slice(&(i * 3000).to_be_bytes());
    p[29..31].copy_from_slice(&((i / 7) as u16).to_be_bytes());
    let o = 8 + off;
    p[o] = 0x80;
    p[o + 1] = if mt == 16 { 98 } else { 113 };
    p[o + 2..o + 4].copy_from_slice(&(i as u16).to_be_bytes());
    p[o + 4..o + 8].copy_from_slice(&(i * 3000).to_be_bytes());
    p[o + 8..o + 12].copy_from_slice(&(0x1000_0000 + (i % 400)).to_be_bytes());
    p
}

fn frames() -> Vec<Vec<u8>> {
    let srv = Addr::from_v4([170, 114, 107, 187]);
    (0..4096u32)
        .map(|i| {
            let client = Addr::from_v4([10, 184, (i % 200) as u8, 7]);
            let pl = zoom_payload(i);
            if i % 2 == 0 {
                frame(&Spec::new(client, srv, 50000 + (i % 3) as u16, 8801, &pl))
            } else {
                frame(&Spec::new(srv, client, 8801, 50000 + (i % 3) as u16, &pl))
            }
        })
        .collect()
}

struct Result {
    ns_per_pkt: f64,
    pcap_pkts: u64,
    drop_pool: u64,
    drop_queue: u64,
    secs: f64,
}

/// `rate_pps` = 0 means unpaced.
fn run(label: &str, tap: bool, n: u64, rate_pps: u64, scratch: &std::path::Path, fr: &[Vec<u8>]) -> Result {
    run_with(label, tap, true, 16_384, n, rate_pps, scratch, fr)
}

/// Consumer that takes every batch and gives it straight back without reading it:
/// the hand-off machinery without the writer's data movement and I/O.
fn run_recycle(label: &str, n: u64, rate_pps: u64, fr: &[Vec<u8>]) -> Result {
    let b = Pipeline::new(PipelineConfig { shards: 1, pcap: Some(PcapCfg { snaplen: 128, pool_slots: 16_384 }), ..Default::default() }, IpSet::zoom_default());
    let p = Arc::new(b.pipeline);
    let _export_rx = b.export_rx;
    let parts = b.pcap.unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let h = std::thread::spawn(move || {
        while !s2.load(Ordering::Relaxed) {
            match parts.rx.try_recv() {
                Ok(mut b) => {
                    b.clear();
                    let _ = parts.free_tx.try_send(b);
                }
                Err(_) => std::thread::sleep(zoom_pipeline::capture_files::WRITER_POLL),
            }
        }
    });
    const BATCH: u64 = 256;
    let budget = if rate_pps > 0 { BATCH * 1_000_000_000 / rate_pps } else { 0 };
    let mut busy = 0u128;
    let mut i = 0u64;
    while i < n {
        let t = Instant::now();
        for j in i..(i + BATCH).min(n) {
            p.on_frame_at(0, j * 10, &fr[(j as usize) % fr.len()]);
        }
        busy += t.elapsed().as_nanos();
        i += BATCH;
        if rate_pps > 0 {
            while t.elapsed() < Duration::from_nanos(budget) {
                std::hint::spin_loop();
            }
        }
    }
    p.shutdown();
    stop.store(true, Ordering::Relaxed);
    let _ = h.join();
    let hh = p.health();
    let r = Result { ns_per_pkt: busy as f64 / n as f64, pcap_pkts: 0, drop_pool: hh.pcap_drop_pool, drop_queue: hh.pcap_drop_queue, secs: 0.0 };
    println!("  {label:<34} {:>7.1} ns/pkt   dropped: pool {:>8} queue {:>8}", r.ns_per_pkt, r.drop_pool, r.drop_queue);
    r
}

/// `writer = false` leaves the queue undrained: with a pool as large as `n` every offer then
/// succeeds and nothing else touches the channels, which isolates the uncontended cost of one offer.
#[allow(clippy::too_many_arguments)]
fn run_with(label: &str, tap: bool, writer: bool, pool: usize, n: u64, rate_pps: u64, scratch: &std::path::Path, fr: &[Vec<u8>]) -> Result {
    let cfg = PipelineConfig { shards: 1, pcap: if tap { Some(PcapCfg { snaplen: 128, pool_slots: pool }) } else { None }, ..Default::default() };
    let b = Pipeline::new(cfg, IpSet::zoom_default());
    let files = b.files.clone();
    let p = Arc::new(b.pipeline);
    let _export_rx = b.export_rx;
    let stop = Arc::new(AtomicBool::new(false));
    let dir = scratch.join(format!("bench_{}", label.replace(' ', "_")));
    let _ = std::fs::remove_dir_all(&dir);
    let parts = b.pcap;
    let _keep_parts;
    let writer = if writer {
        parts.map(|parts| {
            let w = PcapWriter::open(parts, &dir, &files).expect("open pcap");
            let (f, s) = (files.clone(), stop.clone());
            std::thread::spawn(move || w.run(&f, &s))
        })
    } else {
        _keep_parts = parts; // queue stays undrained but alive
        None
    };

    const BATCH: u64 = 256;
    let batch_ns_budget = if rate_pps > 0 { BATCH * 1_000_000_000 / rate_pps } else { 0 };
    let mut busy_ns = 0u128;
    let wall = Instant::now();
    let mut i = 0u64;
    while i < n {
        let t = Instant::now();
        for j in i..(i + BATCH).min(n) {
            // 10 us per frame x 4096 frames = 41 ms per cycle > the 10 ms dedup window
            p.on_frame_at(0, j * 10, &fr[(j as usize) % fr.len()]);
        }
        let spent = t.elapsed();
        busy_ns += spent.as_nanos();
        i += BATCH;
        if rate_pps > 0 {
            let want = Duration::from_nanos(batch_ns_budget);
            while t.elapsed() < want {
                std::hint::spin_loop();
            }
        }
    }
    let secs = wall.elapsed().as_secs_f64();
    p.shutdown();
    stop.store(true, Ordering::Relaxed);
    if let Some(h) = writer {
        let _ = h.join();
    }
    let h = p.health();
    let _ = std::fs::remove_dir_all(&dir);
    let r = Result { ns_per_pkt: busy_ns as f64 / n as f64, pcap_pkts: h.pcap_pkts, drop_pool: h.pcap_drop_pool, drop_queue: h.pcap_drop_queue, secs };
    println!(
        "  {label:<34} {:>7.1} ns/pkt   offered {:>6.0} kpps   pcap written {:>9}   dropped: pool {:>8} queue {:>8}",
        r.ns_per_pkt,
        n as f64 / secs / 1e3,
        r.pcap_pkts,
        r.drop_pool,
        r.drop_queue
    );
    r
}

/// The debug CSV (`--packet-csv`) for comparison: one `PacketDump` row per packet
/// (twins included) goes through the dump channel to the CSV writer thread.
fn run_csv(label: &str, n: u64, rate_pps: u64, scratch: &std::path::Path, fr: &[Vec<u8>]) -> Result {
    use zoom_pipeline::csvdump::CsvWriter;
    let b = Pipeline::new(PipelineConfig { shards: 1, dump_cap: Some(1 << 20), ..Default::default() }, IpSet::zoom_default());
    let files = b.files.clone();
    let p = Arc::new(b.pipeline);
    let _export_rx = b.export_rx;
    let stop = Arc::new(AtomicBool::new(false));
    let dir = scratch.join("bench_csv");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let w = CsvWriter::open(b.dump_rx.unwrap(), &dir.join("packets.csv"), &files).expect("open csv");
    let (f, s2) = (files.clone(), stop.clone());
    let h = std::thread::spawn(move || w.run(&f, &s2));
    const BATCH: u64 = 256;
    let budget = if rate_pps > 0 { BATCH * 1_000_000_000 / rate_pps } else { 0 };
    let mut busy = 0u128;
    let mut i = 0u64;
    while i < n {
        let t = Instant::now();
        for j in i..(i + BATCH).min(n) {
            p.on_frame_at(0, j * 10, &fr[(j as usize) % fr.len()]);
        }
        busy += t.elapsed().as_nanos();
        i += BATCH;
        if rate_pps > 0 {
            while t.elapsed() < Duration::from_nanos(budget) {
                std::hint::spin_loop();
            }
        }
    }
    p.shutdown();
    stop.store(true, Ordering::Relaxed);
    let rows = h.join().unwrap().unwrap();
    let hh = p.health();
    let _ = std::fs::remove_dir_all(&dir);
    let r = Result { ns_per_pkt: busy as f64 / n as f64, pcap_pkts: rows, drop_pool: hh.dump_dropped, drop_queue: 0, secs: 0.0 };
    println!("  {label:<34} {:>7.1} ns/pkt   rows written {:>9}   dump rows dropped {:>8}", r.ns_per_pkt, rows, hh.dump_dropped);
    r
}

fn main() {
    let scratch = std::path::PathBuf::from(std::env::args().nth(1).expect("usage: bench_pcap SCRATCH_DIR [packets]"));
    let n: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(1_500_000);
    std::fs::create_dir_all(&scratch).unwrap();

    // ---- part 1
    let mut v = vec![0u8; 64];
    v[24] = 0x80;
    v[25] = 98;
    let mut a = vec![0u8; 64];
    a[19] = 0x80;
    a[20] = 113;
    let iters = 20_000_000u64;
    let t = Instant::now();
    let mut acc = 0u64;
    for i in 0..iters {
        let (b, ty) = if i & 1 == 0 { (&v, 16u8) } else { (&a, 15u8) };
        if let Some(r) = parse_rtp(black_box(b), black_box(ty)) {
            acc += r.ssrc as u64;
        }
    }
    black_box(acc);
    println!("\npart 1: parse_rtp alone (video/audio alternating): {:.1} ns/call\n", t.elapsed().as_nanos() as f64 / iters as f64);

    let fr = frames();
    // warm the page cache / allocator once
    println!("part 2: paced at 250 kpps, {n} packets per line (capture-core time only)\n");
    let off = run("tap OFF", false, n, 250_000, &scratch, &fr);
    let on = run("tap ON  (snaplen 128, pool 16384)", true, n, 250_000, &scratch, &fr);
    println!("\n  difference: {:+.1} ns/pkt  ({:+.0} %)\n", on.ns_per_pkt - off.ns_per_pkt, 100.0 * (on.ns_per_pkt / off.ns_per_pkt - 1.0));

    println!("part 3: unpaced (writer cannot keep up), {n} packets per line\n");
    let off = run("tap OFF unpaced", false, n, 0, &scratch, &fr);
    let on = run("tap ON  unpaced", true, n, 0, &scratch, &fr);
    println!("\n  difference: {:+.1} ns/pkt  ({:+.0} %)", on.ns_per_pkt - off.ns_per_pkt, 100.0 * (on.ns_per_pkt / off.ns_per_pkt - 1.0));
    let _ = (off.secs, on.secs);

    println!("\npart 5: where does the paced cost come from? 250 kpps, {n} packets per line\n");
    let off = run("tap OFF", false, n, 250_000, &scratch, &fr);
    let rec = run_recycle("tap ON, consumer only recycles", n, 250_000, &fr);
    let shm = std::path::Path::new("/dev/shm/zc_bench_pcap");
    let tm = run("tap ON, writer on tmpfs (no disk)", true, n, 250_000, shm, &fr);
    let dk = run("tap ON, writer on disk", true, n, 250_000, &scratch, &fr);
    println!(
        "\n  vs tap OFF:  recycle only {:+.0} ns   tmpfs writer {:+.0} ns   disk writer {:+.0} ns",
        rec.ns_per_pkt - off.ns_per_pkt,
        tm.ns_per_pkt - off.ns_per_pkt,
        dk.ns_per_pkt - off.ns_per_pkt
    );
    let _ = std::fs::remove_dir_all(shm);

    println!("\npart 6: the debug CSV for comparison, paced at 250 kpps\n");
    let off = run("no capture files", false, n, 250_000, &scratch, &fr);
    let csv = run_csv("--packet-csv ON", n, 250_000, &scratch, &fr);
    println!("\n  difference: {:+.1} ns/pkt  ({:+.0} %)", csv.ns_per_pkt - off.ns_per_pkt, 100.0 * (csv.ns_per_pkt / off.ns_per_pkt - 1.0));

    println!("\npart 4: uncontended cost of one successful offer (no writer, pool = {n} slots, nothing drained)\n");
    let off = run_with("tap OFF", false, false, 0, n, 0, &scratch, &fr);
    let on = run_with("tap ON, no consumer", true, false, n as usize, n, 0, &scratch, &fr);
    println!("\n  difference: {:+.1} ns/pkt  ({:+.0} %)", on.ns_per_pkt - off.ns_per_pkt, 100.0 * (on.ns_per_pkt / off.ns_per_pkt - 1.0));
}
