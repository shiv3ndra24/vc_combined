//! Per-packet cost of the whole packet path with REAL RTP headers (Stage 2 adds a shared hub:
//! one stripe lock, an SFU-counter update and a per-stream update for every Zoom media packet).
//! The same file compiles against the pre-Stage-2 tree (it only uses `Pipeline::new` and
//! `on_frame_at`), so the difference between the two builds is the cost of the Stage-2 metrics.
//!
//!     cargo run --release --bin bench_hub [PACKETS_PER_THREAD] [STREAMS] [THREADS]
//!
//! Traffic: STREAMS RTP streams (clients x {video up, audio up, video down}) served round-robin,
//! all qualified after their first 21 packets, 5 s bins, de-dup on, every packet unique.

use std::sync::{Arc, Barrier};
use std::time::Instant;
use zoom_pipeline::ipset::IpSet;
use zoom_pipeline::net::build::{frame, Spec};
use zoom_pipeline::net::Addr;
use zoom_pipeline::pipeline::{Pipeline, PipelineConfig};

struct Tpl {
    f: Vec<u8>,
    off: usize, // start of the UDP payload inside the frame
    rtp: usize, // RTP header offset inside the UDP payload
    seq: u16,
    ts: u32,
    step: u32,
}

fn make(client: u32, kind: u8, down: bool) -> Tpl {
    let (ty, rtp, pt, len, step) = match kind {
        0 => (16u8, 8 + 24, 98u8, 1000usize, 3000u32),
        _ => (15u8, 8 + 19, 113u8, 200usize, 960u32),
    };
    let mut p = vec![0u8; len];
    p[0] = 5;
    p[7] = if down { 4 } else { 0 };
    p[8] = ty;
    p[rtp] = 0x80;
    p[rtp + 1] = pt;
    p[rtp + 8..rtp + 12].copy_from_slice(&(0x1000_0000 + client * 8 + kind as u32 * 2 + down as u32).to_be_bytes());
    let c = Addr::from_v4([10, 184, (client >> 8) as u8, client as u8]);
    let s = Addr::from_v4([170, 114, 107, 187]);
    let f = if down { frame(&Spec::new(s, c, 8801, 50_000 + (client % 1000) as u16, &p)) } else { frame(&Spec::new(c, s, 50_000 + (client % 1000) as u16, 8801, &p)) };
    let off = f.len() - len;
    Tpl { f, off, rtp, seq: 0, ts: 0, step }
}

fn run(pkts: u64, streams: usize, threads: usize) -> f64 {
    let b = Pipeline::new(PipelineConfig { shards: threads.max(1), channel_cap: 1 << 20, ..Default::default() }, IpSet::zoom_default());
    let p = Arc::new(b.pipeline);
    let _rx = b.export_rx; // keep the channel open; messages are dropped when it is full, like a slow exporter
    let bar = Arc::new(Barrier::new(threads + 1));
    let mut hs = vec![];
    for th in 0..threads {
        let (p, bar) = (p.clone(), bar.clone());
        hs.push(std::thread::spawn(move || {
            // each thread serves its own clients (RSS keeps a flow on one core)
            let mut tpls: Vec<Tpl> = (0..streams).map(|i| make((th * streams + i) as u32 / 3, (i % 3 == 1) as u8, i % 3 == 2)).collect();
            bar.wait();
            let t0 = Instant::now();
            let mut t_us = 1_000u64;
            for n in 0..pkts {
                let s = &mut tpls[(n as usize) % streams];
                s.seq = s.seq.wrapping_add(1);
                s.ts = s.ts.wrapping_add(s.step);
                let (o, r) = (s.off, s.rtp);
                s.f[o + 1..o + 3].copy_from_slice(&s.seq.to_be_bytes()); // SFU counter
                s.f[o + r + 2..o + r + 4].copy_from_slice(&s.seq.to_be_bytes());
                s.f[o + r + 4..o + r + 8].copy_from_slice(&s.ts.to_be_bytes());
                t_us += 20;
                p.on_frame_at(th, t_us, &s.f);
            }
            t0.elapsed().as_nanos() as f64 / pkts as f64
        }));
    }
    bar.wait();
    let ns: Vec<f64> = hs.into_iter().map(|h| h.join().unwrap()).collect();
    let h = p.health();
    assert_eq!(h.matched + h.dups_dropped, h.pkts_in, "every packet must be accounted for");
    ns.iter().sum::<f64>() / ns.len() as f64
}

fn main() {
    let a: Vec<u64> = std::env::args().skip(1).filter_map(|x| x.parse().ok()).collect();
    let pkts = a.first().copied().unwrap_or(2_000_000);
    let streams = a.get(1).copied().unwrap_or(300) as usize;
    let threads = a.get(2).copied().unwrap_or(1) as usize;
    run(pkts / 10, streams, threads); // warm up
    let mut best = f64::MAX;
    for _ in 0..3 {
        best = best.min(run(pkts, streams, threads));
    }
    println!("{threads} thread(s), {streams} streams/thread, {pkts} packets/thread: best of 3 = {best:.0} ns/pkt  ({:.2} Mpps per thread)", 1e3 / best);
}
