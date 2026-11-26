//! Per-packet cost of the old gate versus the new pipeline, single thread and
//! two threads (this sandbox has 2 cores). Build with --release.
//!
//! "old" re-creates, in std only, exactly what the previous callback did
//! before it ever looked at the payload: take a global mutex, format both
//! addresses to `String`, parse them back, scan 48+3 CIDRs linearly.

use std::hint::black_box;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use zoom_pipeline::ipset::{IpSet, ZOOM_IPV4_CIDR_STRS};
use zoom_pipeline::net::build::{frame, Spec};
use zoom_pipeline::net::{parse_udp, Addr};
use zoom_pipeline::pipeline::{Pipeline, PipelineConfig};

fn zoom_payload(media_type: u8, i: u32, len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len];
    p[0] = 5;
    p[1..3].copy_from_slice(&(i as u16).to_be_bytes());
    p[7] = 4;
    p[8] = media_type;
    p[17..19].copy_from_slice(&(i as u16).to_be_bytes());
    p[19..23].copy_from_slice(&(i * 3000).to_be_bytes());
    p[29..31].copy_from_slice(&((i / 7) as u16).to_be_bytes());
    p
}

fn timeit(label: &str, n: u64, mut f: impl FnMut(u64)) -> f64 {
    for i in 0..n / 20 {
        f(i);
    }
    let t = Instant::now();
    for i in 0..n {
        f(i);
    }
    let ns = t.elapsed().as_nanos() as f64 / n as f64;
    println!("  {label:<58} {ns:>8.1} ns/pkt   {:>6.2} Mpps", 1e3 / ns);
    ns
}

struct OldCidr(u32, u32);
fn old_cidrs() -> Vec<OldCidr> {
    ZOOM_IPV4_CIDR_STRS
        .iter()
        .map(|s| {
            let (a, l) = s.split_once('/').unwrap();
            let a: std::net::Ipv4Addr = a.parse().unwrap();
            let l: u32 = l.parse().unwrap();
            OldCidr(u32::from(a), if l == 0 { 0 } else { u32::MAX << (32 - l) })
        })
        .collect()
}
fn old_is_zoom(c: &[OldCidr], ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v)) => {
            let x = u32::from(v);
            c.iter().any(|c| (x & c.1) == (c.0 & c.1))
        }
        _ => false,
    }
}

fn old_gate_threads(threads: usize, n: u64, frames: &Arc<Vec<Vec<u8>>>) -> f64 {
    let m = Arc::new(Mutex::new(0u64));
    let c = Arc::new(old_cidrs());
    let t = Instant::now();
    let hs: Vec<_> = (0..threads)
        .map(|_| {
            let (m, c, frames) = (m.clone(), c.clone(), frames.clone());
            std::thread::spawn(move || {
                for i in 0..n {
                    let f = &frames[(i as usize) % frames.len()];
                    let mut g = m.lock().unwrap(); // lock BEFORE the IP check, as the old code did
                    if let Ok(u) = parse_udp(f) {
                        let s = u.src.to_ip().to_string();
                        let d = u.dst.to_ip().to_string();
                        if old_is_zoom(&c, &s) || old_is_zoom(&c, &d) {
                            *g += 1;
                        }
                    }
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    t.elapsed().as_nanos() as f64 / (n * threads as u64) as f64
}

fn new_threads(threads: usize, n: u64, frames: &Arc<Vec<Vec<u8>>>) -> (f64, u64) {
    let b = Pipeline::new(PipelineConfig { shards: threads, ..Default::default() }, IpSet::zoom_default());
    let p = Arc::new(b.pipeline);
    let _rx = b.export_rx; // keep the channel open
    let t = Instant::now();
    let hs: Vec<_> = (0..threads)
        .map(|core| {
            let (p, frames) = (p.clone(), frames.clone());
            std::thread::spawn(move || {
                for i in 0..n {
                    p.on_frame(core, &frames[(i as usize) % frames.len()]);
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    let ns = t.elapsed().as_nanos() as f64 / (n * threads as u64) as f64;
    (ns, p.health().matched)
}

fn main() {
    let n: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(5_000_000);
    let srv = Addr::from_v4([170, 114, 107, 187]);
    // 4096 distinct Zoom frames (200 clients, mixed video/audio, up and down)
    let zoom: Vec<Vec<u8>> = (0..4096u32)
        .map(|i| {
            let client = Addr::from_v4([10, 184, (i % 200) as u8, 7]);
            let (mt, len) = if i % 5 == 0 { (15, 200) } else { (16, 1150) };
            let pl = zoom_payload(mt, i, len);
            if i % 2 == 0 {
                frame(&Spec::new(client, srv, 50000 + (i % 3) as u16, 8801, &pl))
            } else {
                frame(&Spec::new(srv, client, 8801, 50000 + (i % 3) as u16, &pl))
            }
        })
        .collect();
    // non-Zoom UDP: DNS/QUIC/game traffic to public addresses
    let other: Vec<Vec<u8>> = (0..4096u32)
        .map(|i| frame(&Spec::new(Addr::from_v4([10, 184, (i % 200) as u8, 9]), Addr::from_v4([8, 8, (i % 250) as u8, 8]), 40000 + (i % 100) as u16, 443, &[0x40u8; 120])))
        .collect();
    // right port, wrong address (a different video app on 8801)
    let wrong_ip: Vec<Vec<u8>> = (0..4096u32)
        .map(|i| frame(&Spec::new(Addr::from_v4([10, 184, (i % 200) as u8, 9]), Addr::from_v4([93, 184, 216, (i % 250) as u8]), 40000, 8801, &[0x16u8; 120])))
        .collect();

    println!("\nsingle thread, {n} packets per line (release build)\n");
    let clk = timeit("Instant::now() alone (clock read)", n, |_| {
        black_box(Instant::now());
    });
    let cidrs = old_cidrs();
    let m = Mutex::new(0u64);
    let old = timeit("OLD gate, Zoom packet (mutex+2 Strings+linear scan)", n, |i| {
        let f = &zoom[(i as usize) % zoom.len()];
        let mut g = m.lock().unwrap();
        if let Ok(u) = parse_udp(f) {
            let s = u.src.to_ip().to_string();
            let d = u.dst.to_ip().to_string();
            if old_is_zoom(&cidrs, &s) || old_is_zoom(&cidrs, &d) {
                *g += 1;
            }
        }
    });
    let _ = old;

    let b = Pipeline::new(PipelineConfig { shards: 1, ..Default::default() }, IpSet::zoom_default());
    let p = b.pipeline;
    let _rx = b.export_rx;
    let ips = IpSet::zoom_default();
    timeit("parse_udp only (Ethernet+IP+UDP)", n, |i| {
        black_box(parse_udp(&zoom[(i as usize) % zoom.len()]).is_ok());
    });
    timeit("IpSet::contains only (binary search)", n, |i| {
        black_box(ips.contains(Addr(i as u128 | 0x2f00_0000_0000)));
    });
    println!();
    timeit("NEW non-Zoom UDP (port 443): rejected at port gate", n, |i| {
        p.on_frame_at(0, i * 10, &other[(i as usize) % other.len()]);
    });
    timeit("NEW port 8801, address not Zoom: rejected at IP gate", n, |i| {
        p.on_frame_at(0, i * 10, &wrong_ip[(i as usize) % wrong_ip.len()]);
    });
    let hit = timeit("NEW Zoom packet, new (parse+gate+dedup+header+aggregate)", n, |i| {
        // 10 us step x 4096 frames = 41 ms per cycle > 10 ms window, so none is a repeat
        p.on_frame_at(0, i * 10, &zoom[(i as usize) % zoom.len()]);
    });
    let mut j = 0u64;
    let dup = timeit("NEW Zoom packet, second copy (dedup hit, cheapest)", n, |i| {
        // each frame sent twice, 11 us apart
        let f = &zoom[((i / 2) as usize) % zoom.len()];
        if i % 2 == 0 {
            j = i * 10 + 100_000_000 * (i / 8192);
        }
        p.on_frame_at(0, j + (i % 2) * 11, f);
    });
    let real = timeit("NEW same as 'new' but with the real clock (Instant::now)", n, |i| {
        p.on_frame(0, &zoom[(i as usize) % zoom.len()]);
    });
    let _ = (dup, real, hit, clk);
    println!("\n  health after run: {:?}", {
        let h = p.health();
        (h.pkts_in, h.matched, h.dups_dropped, h.port_filtered, h.ip_filtered)
    });

    println!("\nscaling (each thread handles Zoom packets; old = one global mutex, new = one shard per thread)\n");
    let frames = Arc::new(zoom.clone());
    for th in [1usize, 2] {
        let o = old_gate_threads(th, n / 2, &frames);
        let (nw, matched) = new_threads(th, n / 2, &frames);
        println!("  threads={th}: OLD {o:>7.1} ns/pkt ({:>5.2} Mpps total)   NEW {nw:>6.1} ns/pkt ({:>5.2} Mpps total)  [new matched={matched}]", th as f64 * 1e3 / o, th as f64 * 1e3 / nw);
    }
}
