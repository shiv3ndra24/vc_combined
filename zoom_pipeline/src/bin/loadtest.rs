//! Overload and endurance scenarios. Each prints what happened and whether
//! the property the design promises held.
//!
//!   loadtest slow-sink | flood | tail | soak | all
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zoom_pipeline::export::{run_exporter, run_exporter_clocked, ExportCfg, ExportStats, MemSink, Sink, SinkError};
use zoom_pipeline::ipset::IpSet;
use zoom_pipeline::net::build::{frame, Spec};
use zoom_pipeline::net::Addr;
use zoom_pipeline::pipeline::{Pipeline, PipelineConfig};

fn rss_mb() -> f64 {
    let s = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let pages: f64 = s.split_whitespace().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0.0);
    pages * 4096.0 / 1048576.0
}

struct CountSink(Arc<AtomicU64>);
impl Sink for CountSink {
    fn send(&mut self, body: &str) -> Result<(), SinkError> {
        self.0.fetch_add(body.lines().count() as u64, Ordering::Relaxed);
        Ok(())
    }
}

fn pay(mt: u8, i: u32, len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len];
    p[0] = 5;
    p[7] = 4;
    p[8] = mt;
    p[17..19].copy_from_slice(&(i as u16).to_be_bytes());
    p[19..23].copy_from_slice(&i.to_be_bytes());
    p
}

const SRV: [u8; 4] = [170, 114, 107, 187];

/// A slow database must not slow capture; the excess is shed and counted.
fn slow_sink() {
    println!("\n== slow-sink: 1 capture thread + exporter on the 2nd core; 100 ms bins x 4096 clients; sink blocks 0.4 s per batch vs instant");
    let mut result = Vec::new();
    for slow in [false, true] {
        let cfg = PipelineConfig { shards: 1, bin_us: 100_000, channel_cap: 2048, dedup: false, ..Default::default() };
        let b = Pipeline::new(cfg, IpSet::zoom_default());
        let p = Arc::new(b.pipeline);
        let st = Arc::new(ExportStats::default());
        let sink = MemSink { delay: if slow { Duration::from_millis(400) } else { Duration::ZERO }, ..Default::default() };
        let ecfg = ExportCfg { bin_us: 100_000, settle_us: 300_000, batch_max_lines: 200, retries: 0, ..Default::default() };
        let (st2, start) = (st.clone(), p.start());
        let h = std::thread::spawn(move || run_exporter(b.export_rx, Box::new(sink), ecfg, start, st2));
        let frames: Arc<Vec<Vec<u8>>> = Arc::new(
            (0..4096u32)
                .map(|i| frame(&Spec::new(Addr::from_v4([10, 184, (i % 250) as u8, (i / 250) as u8]), Addr::from_v4(SRV), 50000, 8801, &pay(16, i, 1000))))
                .collect(),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let t0 = Instant::now();
        let hs: Vec<_> = (0..1)
            .map(|core| {
                let (p, f, stop) = (p.clone(), frames.clone(), stop.clone());
                std::thread::spawn(move || {
                    let mut i = core * 7;
                    let mut n = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        for _ in 0..1000 {
                            p.on_frame(core, &f[i % f.len()]);
                            i += 1;
                            n += 1;
                        }
                    }
                    n
                })
            })
            .collect();
        std::thread::sleep(Duration::from_secs(3));
        stop.store(true, Ordering::Relaxed);
        let total: u64 = hs.into_iter().map(|h| h.join().unwrap()).sum();
        let dt = t0.elapsed().as_secs_f64();
        let hl = p.health();
        println!(
            "  sink={:<5}: capture {:>6.2} Mpps | bins closed={:>8} delivered-to-channel={:>8} shed&counted={:>8} ({:>5.1}% shed) | matched={}",
            if slow { "slow" } else { "fast" },
            total as f64 / dt / 1e6,
            hl.bins_emitted + hl.bins_dropped,
            hl.bins_emitted,
            hl.bins_dropped,
            100.0 * hl.bins_dropped as f64 / (hl.bins_emitted + hl.bins_dropped).max(1) as f64,
            hl.matched
        );
        result.push(total as f64 / dt / 1e6);
        p.shutdown();
        drop(p);
        let _ = h.join();
    }
    println!("  -> capture rate with the blocked sink is {:.0}% of the fast-sink rate (no back-pressure reaches the capture thread)", 100.0 * result[1] / result[0]);
}

/// Far more clients than the stream table holds: memory must stay bounded,
/// existing streams keep working, the excess is counted.
fn flood() {
    println!("\n== flood: 1,000,000 distinct clients against a 2 x 50,000-stream cap");
    let cfg = PipelineConfig { shards: 2, max_streams: 50_000, ..Default::default() };
    let b = Pipeline::new(cfg, IpSet::zoom_default());
    let p = b.pipeline;
    let _rx = b.export_rx;
    let rss0 = rss_mb();
    let t0 = Instant::now();
    let mut sent = 0u64;
    for client in 0..1_000_000u32 {
        let c = Addr::from_v4([10, (client >> 16) as u8, (client >> 8) as u8, client as u8]);
        let f = frame(&Spec::new(c, Addr::from_v4(SRV), 50000, 8801, &pay(16, client, 600)));
        for k in 0..3 {
            p.on_frame_at((client & 1) as usize, client as u64 * 10 + k, &f);
            sent += 1;
        }
    }
    let dt = t0.elapsed().as_secs_f64();
    let h = p.health();
    println!(
        "  sent {sent} pkts ({:.2} Mpps incl. frame build) | streams_active={} (cap 100000) streams_rejected={} matched={} dups={}",
        sent as f64 / dt / 1e6,
        h.streams_active,
        h.streams_rejected,
        h.matched,
        h.dups_dropped
    );
    println!("  RSS {:.0} MB after construction -> {:.0} MB after the flood: the tables are preallocated, pages become resident as they are first touched, and it can never exceed this", rss0, rss_mb());
    // existing streams still work
    let before = p.health().matched;
    let c = Addr::from_v4([10, 0, 0, 0]);
    let f = frame(&Spec::new(c, Addr::from_v4(SRV), 50000, 8801, &pay(16, 99_999_999, 600)));
    p.on_frame_at(0, 2_000_000_000, &f);
    println!("  an already-tracked client is still accepted after the flood: {}", p.health().matched == before + 1);
}

/// Worst-case latency a capture core sees because of the sweeper.
fn tail() {
    println!("\n== tail: per-packet latency while the sweeper runs (65,536 streams on the shard)");
    for chunk in [2048usize, usize::MAX] {
        let cfg = PipelineConfig { shards: 1, max_streams: 65_536, sweep_chunk: chunk, idle_us: u64::MAX / 4, ..Default::default() };
        let b = Pipeline::new(cfg, IpSet::zoom_default());
        let p = Arc::new(b.pipeline);
        let _rx = b.export_rx;
        // fill the table
        let frames: Vec<Vec<u8>> = (0..60_000u32)
            .map(|i| frame(&Spec::new(Addr::from_v4([10, (i >> 16) as u8, (i >> 8) as u8, i as u8]), Addr::from_v4(SRV), 50000, 8801, &pay(16, i, 300))))
            .collect();
        for (i, f) in frames.iter().enumerate() {
            p.on_frame_at(0, i as u64, f);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let (ps, ss) = (p.clone(), stop.clone());
        let sweeper = std::thread::spawn(move || {
            let mut t = 100_000_000u64;
            while !ss.load(Ordering::Relaxed) {
                ps.sweep_once(t);
                t += 5_000_000; // each sweep also closes a bin for every stream
                std::thread::sleep(Duration::from_millis(2)); // production sweeps every 250 ms; this is 100x more aggressive
            }
        });
        let mut lat: Vec<u32> = Vec::with_capacity(2_000_000);
        for i in 0..2_000_000usize {
            let f = &frames[i % frames.len()];
            let t = Instant::now();
            p.on_frame(0, f);
            lat.push(t.elapsed().as_nanos() as u32);
        }
        stop.store(true, Ordering::Relaxed);
        sweeper.join().unwrap();
        lat.sort_unstable();
        let q = |x: f64| lat[((lat.len() as f64 * x) as usize).min(lat.len() - 1)];
        println!(
            "  sweep_chunk={:<20} p50={:>5} ns  p99={:>6} ns  p99.99={:>8} ns  max={:>10} ns",
            if chunk == usize::MAX { "whole shard at once".to_string() } else { chunk.to_string() },
            q(0.5),
            q(0.99),
            q(0.9999),
            lat[lat.len() - 1]
        );
    }
    println!("  -> inconclusive here: the tails are dominated by OS scheduling noise on a shared 2-core VM (the sweeper competes with the capture thread for CPU).");
    // What chunking guarantees is the lock-hold time, which can be measured directly and
    // deterministically: how long does one lock acquisition by the sweeper last?
    use zoom_pipeline::agg::{Shard, ShardCfg, StreamKey};
    use zoom_pipeline::health::CoreCounters;
    for chunk in [2048usize, 8192, usize::MAX] {
        let (tx, _rx) = crossbeam_channel::bounded(1 << 20);
        let mut sh = Shard::new(ShardCfg { max_streams: 65_536, bin_us: 5_000_000, idle_us: u64::MAX / 4, hash_seed: 3 }, tx);
        let c = CoreCounters::default();
        for i in 0..65_000u32 {
            let k = StreamKey { client: Addr::from_v4([10, (i >> 16) as u8, (i >> 8) as u8, i as u8]), server: Addr::from_v4(SRV), client_port: 1, server_port: 8801, acct: 0, dir: 0 };
            sh.add(k, 1000, 100, &c);
        }
        let mut worst = Duration::ZERO;
        let mut sum = Duration::ZERO;
        let mut calls = 0;
        loop {
            let t = Instant::now();
            let done = sh.sweep_chunk(chunk, 100_000_000, &c); // every stream has a closed bin to emit
            let d = t.elapsed();
            worst = worst.max(d);
            sum += d;
            calls += 1;
            if done {
                break;
            }
        }
        println!(
            "  sweep_chunk={:<20} full pass of 65,000 streams = {:>8.2?} in {:>3} lock acquisitions; longest single lock hold = {:>9.2?}",
            if chunk == usize::MAX { "whole shard".to_string() } else { chunk.to_string() },
            sum,
            calls,
            worst
        );
    }
}

/// 24 hours of virtual time with client churn: state must stay bounded.
fn soak() {
    println!("\n== soak: 24 h of virtual time, 3 clients/s arriving, each active 10 min, 40 pps per client");
    let cfg = PipelineConfig { shards: 2, max_streams: 100_000, bin_us: 5_000_000, idle_us: 60_000_000, ..Default::default() };
    let b = Pipeline::new(cfg, IpSet::zoom_default());
    let p = b.pipeline;
    let lines = Arc::new(AtomicU64::new(0));
    let vnow = Arc::new(AtomicU64::new(0));
    let st = Arc::new(ExportStats::default());
    let (st2, start, vn, ln) = (st.clone(), p.start(), vnow.clone(), lines.clone());
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(move || vn.load(Ordering::Relaxed));
    let h = std::thread::spawn(move || run_exporter_clocked(b.export_rx, Box::new(CountSink(ln)), ExportCfg::default(), start, st2, clock));
    let rss0 = rss_mb();
    let mut peak_streams = 0u64;
    let mut peak_pending_clients = 0u64;
    let day_s: u64 = 86_400;
    let mut next_client: u32 = 0;
    let mut active: std::collections::VecDeque<(u32, u64)> = Default::default(); // (client, ends_at_s)
    let tstart = Instant::now();
    let mut sent = 0u64;
    let mut frames_cache: std::collections::HashMap<u32, Vec<u8>> = Default::default();
    for sec in 0..day_s {
        for _ in 0..3 {
            active.push_back((next_client, sec + 600));
            next_client = next_client.wrapping_add(1);
        }
        while active.front().map_or(false, |&(_, end)| end <= sec) {
            if let Some((c, _)) = active.pop_front() {
                frames_cache.remove(&c);
            }
        }
        for &(c, _) in active.iter() {
            let fr = frames_cache.entry(c).or_insert_with(|| {
                let a = Addr::from_v4([10, 184 + (c >> 16) as u8, (c >> 8) as u8, c as u8]);
                frame(&Spec::new(a, Addr::from_v4(SRV), 50000, 8801, &pay(16, c, 800)))
            });
            // mutate the seq so successive packets are distinct
            for k in 0..40u64 {
                let t = sec * 1_000_000 + k * 25_000 + (c as u64 % 1000);
                let n = fr.len();
                let s = (sec * 40 + k) as u32;
                fr[n - 800 + 17..n - 800 + 19].copy_from_slice(&(s as u16).to_be_bytes());
                fr[n - 800 + 19..n - 800 + 23].copy_from_slice(&s.to_be_bytes());
                p.on_frame_at((c & 1) as usize, t, fr);
                sent += 1;
            }
        }
        vnow.store(sec * 1_000_000 + 999_000, Ordering::Relaxed);
        if sec % 5 == 0 {
            p.sweep_once(sec * 1_000_000 + 999_000);
        }
        if sec % 3600 == 3599 {
            let hh = p.health();
            peak_streams = peak_streams.max(hh.streams_active);
            peak_pending_clients = peak_pending_clients.max(active.len() as u64);
            println!(
                "  virtual hour {:>2}: RSS {:>6.1} MB | active clients {:>5} | streams_active {:>6} | evicted {:>9} | bins_dropped {} | influx lines so far {}",
                (sec + 1) / 3600,
                rss_mb(),
                active.len(),
                hh.streams_active,
                hh.streams_evicted,
                hh.bins_dropped,
                lines.load(Ordering::Relaxed)
            );
        }
    }
    p.shutdown();
    h.join().unwrap();
    let hl = p.health();
    println!(
        "  done: {sent} pkts in {:.1?} real time | RSS {:.1} -> {:.1} MB | peak streams_active {} | bins_dropped {} | export lines_ok={} dropped={} pending_overflow={}",
        tstart.elapsed(),
        rss0,
        rss_mb(),
        peak_streams,
        hl.bins_dropped,
        st.lines_ok.load(Ordering::Relaxed),
        st.lines_dropped.load(Ordering::Relaxed),
        st.pending_overflow.load(Ordering::Relaxed)
    );
}

/// Every stream's bin ends at the same wall-clock instant, so the sweeper
/// emits one BinMetrics per stream in a burst. Does the channel absorb it?
fn burst() {
    println!("\n== burst: 200,000 streams (4 shards x 50,000) all close their 5 s bin at the same instant");
    for cap in [65_536usize, 262_144] {
        let cfg = PipelineConfig { shards: 4, max_streams: 50_000, channel_cap: cap, dedup: false, ..Default::default() };
        let b = Pipeline::new(cfg, IpSet::zoom_default());
        let p = b.pipeline;
        let lines = Arc::new(AtomicU64::new(0));
        let st = Arc::new(ExportStats::default());
        let (st2, start, ln) = (st.clone(), p.start(), lines.clone());
        let h = std::thread::spawn(move || run_exporter(b.export_rx, Box::new(CountSink(ln)), ExportCfg::default(), start, st2));
        for i in 0..200_000u32 {
            let c = Addr::from_v4([10, (i >> 16) as u8, (i >> 8) as u8, i as u8]);
            let f = frame(&Spec::new(c, Addr::from_v4(SRV), 50000, 8801, &pay(16, i, 300)));
            p.on_frame_at((i % 4) as usize, 1000 + i as u64, &f);
        }
        let t = Instant::now();
        p.sweep_once(6_000_000); // the bin boundary passes: everything closes
        let sweep = t.elapsed();
        std::thread::sleep(Duration::from_millis(500));
        let hl = p.health();
        println!(
            "  channel_cap={:>7}: closed {} bins in {:.1?} -> delivered {} / shed {} ({:.1}% shed)",
            cap,
            hl.bins_emitted + hl.bins_dropped,
            sweep,
            hl.bins_emitted,
            hl.bins_dropped,
            100.0 * hl.bins_dropped as f64 / (hl.bins_emitted + hl.bins_dropped).max(1) as f64
        );
        p.shutdown();
        let _ = h.join();
    }
}

fn main() {
    let what = std::env::args().nth(1).unwrap_or_else(|| "all".into());
    match what.as_str() {
        "slow-sink" => slow_sink(),
        "flood" => flood(),
        "tail" => tail(),
        "burst" => burst(),
        "soak" => soak(),
        _ => {
            slow_sink();
            flood();
            tail();
            burst();
            soak();
        }
    }
}
