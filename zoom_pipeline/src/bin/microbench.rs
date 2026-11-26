//! Breakdown of the per-packet cost by stage (single thread, release).
use std::hint::black_box;
use std::sync::Mutex;
use std::time::Instant;
use zoom_pipeline::agg::{Shard, ShardCfg, StreamKey};
use zoom_pipeline::dedup::{fingerprint, Dedup, SharedDedup};
use zoom_pipeline::health::CoreCounters;
use zoom_pipeline::net::build::{frame, Spec};
use zoom_pipeline::net::{parse_udp, Addr};

fn timeit(label: &str, n: u64, mut f: impl FnMut(u64)) {
    for i in 0..n / 20 { f(i); }
    let t = Instant::now();
    for i in 0..n { f(i); }
    println!("  {label:<52} {:>7.1} ns", t.elapsed().as_nanos() as f64 / n as f64);
}

fn main() {
    let n = 5_000_000u64;
    let srv = Addr::from_v4([170, 114, 107, 187]);
    let frames: Vec<Vec<u8>> = (0..4096u32).map(|i| {
        let mut p = vec![0u8; 1150]; p[0] = 5; p[8] = 16; p[17..19].copy_from_slice(&(i as u16).to_be_bytes());
        frame(&Spec::new(Addr::from_v4([10, 184, (i % 200) as u8, 7]), srv, 50000 + (i % 3) as u16, 8801, &p))
    }).collect();
    let views: Vec<_> = frames.iter().map(|f| parse_udp(f).unwrap()).collect();
    println!("stages, same 4096-frame pool (5 MB, bigger than L2):");
    timeit("loop + frame fetch only (touch first byte)", n, |i| { black_box(frames[(i as usize) % 4096][0]); });
    timeit("parse_udp", n, |i| { black_box(parse_udp(&frames[(i as usize) % 4096]).is_ok()); });
    timeit("fingerprint (pre-parsed view)", n, |i| { let u = &views[(i as usize) % 4096]; black_box(fingerprint(1, u.src, u.dst, u.src_port, u.dst_port, u.udp_len, u.payload)); });
    let m = Mutex::new(0u64);
    timeit("Mutex lock+unlock (uncontended)", n, |_| { *m.lock().unwrap() += 1; });
    let mut d = Dedup::new(16384, 10_000);
    timeit("Dedup::check (precomputed fp, 4096 distinct)", n, |i| { black_box(d.check(i % 4096 * 0x9e3779b97f4a7c15 | 1, i * 10, 64, 1)); });
    let sd = SharedDedup::new(16384, 10_000, 16);
    timeit("SharedDedup::check (1 thread, uncontended)", n, |i| { black_box(sd.check(i % 4096 * 0x9e3779b97f4a7c15 | 1, i * 10, 64, 1)); });
    // Worst case, far beyond the real load (Zoom-only traffic is ~1.5 to 3 kpps):
    // 4 cores calling the shared table back to back.
    {
        let sd = std::sync::Arc::new(SharedDedup::new(16384, 10_000, 16));
        let per = 2_000_000u64;
        let t = Instant::now();
        let hs: Vec<_> = (0..4u64).map(|c| { let sd = sd.clone(); std::thread::spawn(move || { for i in 0..per { black_box(sd.check((i * 4 + c) % 8192 * 0x9e3779b97f4a7c15 | 1, i * 10, 64, 1)); } }) }).collect();
        for h in hs { h.join().unwrap(); }
        println!("  {:<52} {:>7.1} ns/call (4 threads hammering, {:.1} Mcalls/s total)", "SharedDedup::check under contention", t.elapsed().as_nanos() as f64 / per as f64, 4.0 * per as f64 / t.elapsed().as_secs_f64() / 1e6);
    }
    let (tx, _rx) = crossbeam_channel::bounded(1 << 16);
    let mut sh = Shard::new(ShardCfg { max_streams: 65536, bin_us: 5_000_000, idle_us: 60_000_000, hash_seed: 7 }, tx);
    let c = CoreCounters::default();
    let keys: Vec<StreamKey> = (0..1200u32).map(|i| StreamKey { client: Addr::from_v4([10, 184, (i % 200) as u8, 7]), server: srv, client_port: 50000 + (i % 6) as u16, server_port: 8801, acct: (i % 3) as u8, dir: (i % 2) as u8 }).collect();
    timeit("Shard::add (1200 streams, existing)", n, |i| { sh.add(keys[(i as usize) % 1200], i * 10, 1150, &c); });
    timeit("CoreCounters::bump (single-writer)", n, |_| { CoreCounters::bump(&c.pkts_in); });
    timeit("Instant::now()", n, |_| { black_box(Instant::now()); });
}
