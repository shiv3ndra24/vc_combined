//! Cost of the "new Zoom packet" path versus working-set size.
use std::time::Instant;
use zoom_pipeline::ipset::IpSet;
use zoom_pipeline::net::build::{frame, Spec};
use zoom_pipeline::net::Addr;
use zoom_pipeline::pipeline::{Pipeline, PipelineConfig};

fn main() {
    let n = 5_000_000u64;
    let srv = Addr::from_v4([170, 114, 107, 187]);
    println!("{:>10} {:>10} {:>10} {:>12}", "pool", "dedupslots", "dedup", "ns/pkt");
    for (pool, slots, dedup) in [(64usize, 16384usize, true), (4096, 16384, true), (4096, 4096, true), (4096, 1024, true), (4096, 65536, true), (4096, 16384, false), (64, 16384, false)] {
        let frames: Vec<Vec<u8>> = (0..pool as u32).map(|i| {
            let mut p = vec![0u8; 1150]; p[0] = 5; p[8] = 16; p[17..19].copy_from_slice(&(i as u16).to_be_bytes());
            frame(&Spec::new(Addr::from_v4([10, 184, (i % 200) as u8, 7]), srv, 50000 + (i % 3) as u16, 8801, &p))
        }).collect();
        let b = Pipeline::new(PipelineConfig { shards: 1, dedup, dedup_slots: slots, ..Default::default() }, IpSet::zoom_default());
        let _rx = b.export_rx;
        let step = (20_000 / pool as u64).max(1) * 1; // keep cycle > window except for tiny pools
        for i in 0..n / 20 { b.pipeline.on_frame_at(0, i * 10_000 + i * step, &frames[(i as usize) % pool]); }
        let t = Instant::now();
        for i in 0..n { b.pipeline.on_frame_at(0, 1_000_000_000 + i * 10_000, &frames[(i as usize) % pool]); }
        println!("{:>10} {:>10} {:>10} {:>12.1}", pool, slots, dedup, t.elapsed().as_nanos() as f64 / n as f64);
    }
}
