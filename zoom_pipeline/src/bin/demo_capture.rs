//! Synthetic Zoom call -> the real pipeline -> the real CSV and pcap writers.
//!
//! Purpose: produce the same files a campus run with `--packet-csv` and
//! `--pcap-dir` produces, without a NIC, so that
//!   * you can look at the files before the first campus run,
//!   * `tools/validate_rtp_csv.py` can be tested on a good file (PASS) and on
//!     two deliberately wrong ones (`--wrong-offset video`: RTP header one byte
//!     off => FAIL; `--garbage video`: valid version bits but noise in the rest
//!     => FAIL, the subtle case), and
//!   * the pcap can be opened with any independent reader (tcpdump, Wireshark,
//!     dpkt) to confirm the files are real pcaps.
//!
//! Usage: demo_capture OUT_DIR [--secs N] [--snaplen N] [--wrong-offset video|audio|screen13|rtcp] [--garbage video|audio|screen13] [--unknown-types]
//!
//! `--unknown-types` adds two clients that mimic the SHAPE of what the first campus captures
//! showed: an audio stream in which every 15th packet is a type-7 packet (same flow, same RTP
//! sequence space, but another header layout: RTP at media offset +31), and a video stream of a
//! made-up type number (99, which Zoom does not use as far as we know) with RTP at +20. The pipeline
//! logs them without RTP fields; `tools/probe_unknown_types.py` has to find the offsets (a test of
//! the probe, not evidence about Zoom: the layouts here are made up).
//!
//! p7b change: this second client used to be "type 21 video, RTP at +20". That was the p6 reading of
//! Type 21; deck2 test T21-4 REFUTED it (Type 21 is probe padding, not RTP), so a fixture that
//! says "type 21 is video" would teach the wrong thing. The probe test only needs SOME type
//! the pipeline does not know, so it now uses a type number nobody assigned.
//!
//! The traffic is made up (but follows the header layout in `headers.rs`):
//! client A video call (down 30 fps x 3 pkts, up 15 fps x 2 pkts, audio both
//! ways, RTCP sender reports, a few retransmissions), client B audio plus
//! screen share (type 13, media byte 7 = 0x1e), client F (p7b): a camera with a main video stream
//! (media byte 20 = 0x02, RTP at +24) AND a second video stream whose RTP header starts at media
//! byte 20 itself (0x90, RTP at +20), one IPv6 client without an SFU header, port-443 noise, and
//! every packet delivered twice 11 us apart: the CAPWAP tunnel leg and the wired leg of the same
//! frame (try4 CONFIRMED; the demo does not model the tunnel itself, only the two copies).

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use zoom_pipeline::capture_files::{PcapCfg, PcapWriter};
use zoom_pipeline::csvdump::CsvWriter;
use zoom_pipeline::ipset::IpSet;
use zoom_pipeline::net::build::{frame, Spec};
use zoom_pipeline::net::Addr;
use zoom_pipeline::pipeline::{Pipeline, PipelineConfig};

/// `--garbage TYPE`: keep the version bits valid (V=2, so the pipeline's own
/// check passes) but fill the rest of the 12 RTP bytes with noise. This is what
/// a wrong offset looks like one time in four on real traffic, and it is the
/// case the validator's statistical checks exist for.
static GARBAGE_TYPE: AtomicU8 = AtomicU8::new(0);
static RNG: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

fn noise_byte() -> u8 {
    // xorshift64*; deterministic so the demo output is reproducible
    let mut x = RNG.load(Ordering::Relaxed);
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    RNG.store(x, Ordering::Relaxed);
    (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
}

struct Rtp {
    pt: u8,
    marker: bool,
    seq: u16,
    ts: u32,
    ssrc: u32,
}

/// Build a Zoom UDP payload: SFU header + media header (+ RTP at `rtp_off`).
/// `shift` moves the RTP header by that many bytes (a deliberately wrong offset).
#[allow(clippy::too_many_arguments)]
fn payload(media_type: u8, from_sfu: bool, sfu_seq: u16, media_seq: u16, media_ts: u32, frame: Option<(u16, u8)>, rtp: Option<(usize, &Rtp)>, shift: usize, len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len];
    p[0] = 0x05;
    p[1..3].copy_from_slice(&sfu_seq.to_be_bytes());
    p[7] = if from_sfu { 0x04 } else { 0x00 };
    let m = 8;
    p[m] = media_type;
    p[m + 9..m + 11].copy_from_slice(&media_seq.to_be_bytes());
    p[m + 11..m + 15].copy_from_slice(&media_ts.to_be_bytes());
    if let Some((fs, cnt)) = frame {
        p[m + 21..m + 23].copy_from_slice(&fs.to_be_bytes());
        p[m + 23] = cnt;
    }
    if let Some((off, r)) = rtp {
        if media_type == 16 && off != 20 {
            // like real video: media byte 20 says which layout this is (0x02 -> RTP at +24, 0x0a -> RTP at +28).
            // For the third layout (off == 20) there is no layout byte: byte 20 IS the first byte of the RTP header.
            p[m + 20] = if off == 28 { 0x0a } else { 0x02 };
        }
        if media_type == 13 {
            // p7b: a type-13 packet carries RTP only if media byte 7 says so (0x1e). The probe/control
            // fixtures override this after the fact (`E::b7`).
            p[m + 7] = 0x1e;
        }
        let o = m + off + shift;
        // V=2. In the +20 layout the first RTP byte is 0x90 (V=2 plus the extension bit), as seen on campus;
        // the pipeline only needs the top two bits (0b10) to call it that layout
        p[o] = if media_type == 16 && off == 20 { 0x90 } else { 0x80 };
        p[o + 1] = r.pt | if r.marker { 0x80 } else { 0 };
        p[o + 2..o + 4].copy_from_slice(&r.seq.to_be_bytes());
        p[o + 4..o + 8].copy_from_slice(&r.ts.to_be_bytes());
        p[o + 8..o + 12].copy_from_slice(&r.ssrc.to_be_bytes());
        if media_type == GARBAGE_TYPE.load(Ordering::Relaxed) {
            for b in &mut p[o + 1..o + 12] {
                *b = noise_byte();
            }
        }
    }
    p
}

/// A media type number that no part of the pipeline assigns (used by the `--unknown-types` fixture).
const MADE_UP_TYPE: u8 = 99;

/// RX cores simulated (the campus run uses 4).
const CORES: usize = 4;

type Events = Vec<(u64, usize, Vec<u8>)>;

/// Every frame arrives twice, ~11 us apart (on campus: the CAPWAP tunnel leg and the wired leg of the
/// same frame, try4 CONFIRMED), and the two copies often reach DIFFERENT RX cores (a per-core de-dup
/// table missed those): the second copy goes to the next core here, so the demo exercises the shared table.
fn add(ev: &mut Events, t: u64, f: Vec<u8>) {
    let c = ((t / 7) % CORES as u64) as usize;
    ev.push((t, c, f.clone()));
    ev.push((t + 11, (c + 1) % CORES, f));
}

// ------------------------------------------------------------------------------------------
// `--stage2 FILE`: extra clients that exercise every Stage-2 metric (loss, reorder, stall, FEC,
// screen share 13 and 30, type 21, probes, sessions) and a run of the REAL exporter into FILE.
// `tools/verify_metrics.py` recomputes the same numbers from packets.csv and compares.
// ------------------------------------------------------------------------------------------

/// One logical packet of a client. `lose`: the packet consumed an SFU counter number but never
/// reached the capture (so the counter shows a gap).
#[derive(Clone)]
struct E {
    t: u64,
    up: bool,
    ty: u8,
    off: Option<usize>,
    pt: u8,
    marker: bool,
    ssrc: u32,
    rseq: u16,
    rts: u32,
    len: usize,
    lose: bool,
    /// p7b: override media byte 7 (the type-13 sub-type). `None` keeps what `payload()` wrote (0x1e for a
    /// type-13 packet that has RTP, 0 otherwise). 0x15 = probe padding in a Type-13 envelope, other = control.
    b7: Option<u8>,
}

#[allow(clippy::too_many_arguments)]
fn e(t: u64, up: bool, ty: u8, off: Option<usize>, pt: u8, ssrc: u32, rseq: u16, rts: u32, len: usize) -> E {
    E { t, up, ty, off, pt, marker: false, ssrc, rseq, rts, len, lose: false, b7: None }
}

/// Turn a client's logical packets into frames: SFU counters are assigned in time order per direction.
/// `blackout`: every packet whose time falls in [from, to) never reaches the capture (its counter number is still used).
fn emit_client(ev: &mut Events, cl: Addr, port: u16, mut list: Vec<E>, blackout: Option<(u64, u64)>, next_id: &mut dyn FnMut() -> u16) {
    let srv = Addr::from_v4([170, 114, 107, 187]);
    list.sort_by_key(|x| x.t); // stable
    let (mut cu, mut cd) = (1u16, 1u16);
    for x in list {
        let ctr = if x.up { &mut cu } else { &mut cd };
        let c = *ctr;
        *ctr = ctr.wrapping_add(1);
        if x.lose || blackout.is_some_and(|(a, b)| x.t >= a && x.t < b) {
            continue;
        }
        let r = Rtp { pt: x.pt, marker: x.marker, seq: x.rseq, ts: x.rts, ssrc: x.ssrc };
        let mut p = payload(x.ty, !x.up, c, x.rseq, (x.t / 1000) as u32, None, x.off.map(|o| (o, &r)), 0, x.len);
        if let Some(v) = x.b7 {
            p[8 + 7] = v; // media byte 7 (media header starts at 8)
        }
        let f = if x.up {
            frame(&Spec { ip_id: next_id(), vlan_tags: 1, ..Spec::new(cl, srv, port, 8801, &p) })
        } else {
            frame(&Spec { ip_id: next_id(), vlan_tags: 1, ..Spec::new(srv, cl, 8801, port, &p) })
        };
        add(ev, x.t, f);
    }
}

fn stage2_events(ev: &mut Events, t0: u64, next_id: &mut dyn FnMut() -> u16) {
    let s = |x: f64| t0 + (x * 1e6) as u64;
    // ---- G: impaired camera + mic, a screen share in each direction, type 21 / 10 background, changing-SSRC probes
    let mut g = vec![];
    for i in 0..600u64 {
        g.push(e(s(0.0) + i * 50_000, true, 21, None, 0, 0, i as u16, 0, 1044)); // 20 pps type 21, from before any media
    }
    for i in 0..150u64 {
        g.push(e(s(0.0) + i * 200_000, true, 10, None, 0, 0, i as u16, 0, 80)); // 5 pps type 10
    }
    for i in 0..600u64 {
        // camera: 30 fps, one packet per frame. 150, 151 and 400 never arrive; 350 arrives just after 351 (a reorder
        // away from a bin edge, so the loss it briefly shows is taken back in the same bin); from frame 250 on
        // the sender paused 120 ms (one inter-frame gap of ~153 ms: slow, but NOT a stall) and from frame 450 on
        // another 200 ms (a gap of ~233 ms: a stall, but under 250 ms)
        let mut t = s(2.0) + i * 33_333;
        if i >= 250 {
            t += 120_000;
        }
        if i >= 450 {
            t += 200_000;
        }
        if i == 350 {
            t += 34_333;
        }
        let mut x = e(t, true, 16, Some(24), 98, 0x2100_0001, 100 + i as u16, i as u32 * 3000, 1000);
        x.marker = true;
        x.lose = matches!(i, 150 | 151 | 400);
        g.push(x);
        if i == 300 {
            let mut r = e(t + 100_000, true, 16, Some(24), 98, 0x2100_0001, 100 + i as u16, i as u32 * 3000, 1000); // retransmission
            r.marker = true;
            g.push(r);
        }
    }
    for i in 0..1000u64 {
        g.push(e(s(2.5) + i * 20_000, true, 15, Some(19), 113, 0x2100_0002, 5000 + i as u16, i as u32 * 960, 120));
    }
    for i in 0..120u64 {
        g.push(e(s(8.0) + i * 66_666, true, 30, Some(20), 99, 0x2100_0003, 9000 + i as u16, i as u32 * 6000, 900)); // we share: type 30 up
    }
    for i in 0..60u64 {
        g.push(e(s(12.0) + i * 100_000, false, 13, Some(27), 99, 0x2100_0004, 300 + i as u16, i as u32 * 9000, 900)); // we watch a share: type 13 down
    }
    // p7b: 400 type-13 packets that are NOT screen-share RTP, 100 of each kind (all downlink, 1051 bytes):
    //   i%4==0  media byte 7 = 0x15, no RTP-looking bytes at +27      -> t13_probe  (Type-21 padding in a Type-13 envelope)
    //   i%4==1  media byte 7 = 0x15, a v2-LOOKING header at +27       -> t13_probe  (the decoy: the gate must not read it)
    //   i%4==2  media byte 7 = 0x00, no RTP-looking bytes at +27      -> t13_ctrl
    //   i%4==3  media byte 7 = 0x00, a v2-LOOKING header at +27       -> t13_ctrl   (same decoy, other sub-type)
    // In p7a all four kinds were `unq_screen` (the v2-looking ones as one-packet sightings with a new SSRC each).
    // The SSRC differs per packet, as the decoy bytes of real padding do, so even a reader that ignored the gate
    // could never qualify them: the proof that the gate works is the group counts, not the absence of a stream.
    for i in 0..400u64 {
        let off = if i % 2 == 0 { None } else { Some(27) };
        let mut x = e(s(8.0) + i * 20_000, false, 13, off, 99, 0x6000_0000 + i as u32, i as u16, 0, 1051);
        x.b7 = Some(if i % 4 < 2 { 0x15 } else { 0x00 });
        g.push(x);
    }
    // a type-13 stream with ONE ssrc whose sequence numbers jump around: it must never qualify (fails after 64 packets)
    for i in 0..100u64 {
        g.push(e(s(14.0) + i * 50_000, false, 13, Some(27), 99, 0x2100_0005, (i * 7919) as u16, 0, 1051));
    }
    emit_client(ev, Addr::from_v4([10, 184, 2, 1]), 50010, g, None, next_id);

    // ---- H: two sessions in one call: audio 4.3-12.3 s, nothing for 127.7 s (type 21 keeps flowing), audio again at 140 s
    let mut h = vec![];
    for i in 0..170u64 {
        h.push(e(s(0.0) + i * 1_000_000, true, 21, None, 0, 0, i as u16, 0, 600));
    }
    for i in 0..400u64 {
        h.push(e(s(4.3) + i * 20_000, false, 15, Some(19), 116, 0x2200_0001, 100 + i as u16, i as u32 * 960, 150));
    }
    for i in 0..250u64 {
        h.push(e(s(140.0) + i * 20_000, false, 15, Some(19), 116, 0x2200_0002, 5000 + i as u16, i as u32 * 960, 150));
    }
    emit_client(ev, Addr::from_v4([10, 184, 2, 2]), 50011, h, None, next_id);

    // ---- L: one session with a 110 s pause (under the 120 s timeout): audio 3-8 s, a type-21 trickle all along,
    // the same audio stream again at 118-123 s. A 100 s timeout would split it in two.
    let mut l = vec![];
    for i in 0..130u64 {
        l.push(e(s(0.0) + i * 1_000_000, true, 21, None, 0, 0, i as u16, 0, 600));
    }
    for i in 0..250u64 {
        // packets 100..230 never reach the capture: 130 consecutive RTP numbers (counted as lost, under the 1,000 cap)
        // and 130 consecutive counter numbers (over the SFU cap of 100: a restart, not 'missing')
        let mut x = e(s(3.0) + i * 20_000, false, 15, Some(19), 116, 0x2500_0001, 100 + i as u16, i as u32 * 960, 150);
        x.lose = (100..230).contains(&i);
        l.push(x);
    }
    for i in 250..500u64 {
        l.push(e(s(118.0) + (i - 250) * 20_000, false, 15, Some(19), 116, 0x2500_0001, 100 + i as u16, i as u32 * 960, 150));
    }
    emit_client(ev, Addr::from_v4([10, 184, 2, 5]), 50014, l, None, next_id);

    // ---- K: one camera stream (downlink, 30 fps, one packet per frame) whose media header changes layout twice: frames
    // 150..270 (4 s) use the burst layout (media byte 20 = 0x0a, RTP header at +28), the rest the normal one (0x02, +24).
    // Same SSRC, consecutive RTP sequence numbers. Expected: no loss, no stall, a flat 30 fps, no `unq_video` after the
    // first sighting. p6 read the burst at +24 and showed a false loss spike and an empty bin here.
    let mut k = vec![];
    for i in 0..600u64 {
        let off = if (150..270).contains(&i) { 28 } else { 24 };
        let mut x = e(s(2.0) + i * 33_333, false, 16, Some(off), 98, 0x2600_0001, 400 + i as u16, i as u32 * 3000, 1000);
        x.marker = true;
        k.push(x);
    }
    emit_client(ev, Addr::from_v4([10, 184, 2, 6]), 50015, k, None, next_id);

    // ---- M (p7b): a camera flow with TWO video streams in the downlink, like the campus capture that has a second video
    // SSRC whose RTP header starts at media byte 20 (byte 20 = 0x90, no frame-seq / packet-count fields). The main
    // stream (0x02 layout, RTP at +24) runs 30 fps, the second one (rtp20 layout, RTP at +20) 15 fps, one packet per
    // frame each. Both are separate streams (SSRC differs) of ONE flow, so they share one SFU counter.
    // Expected from p7b: both qualify, `video_streams_active` = 2, `video_layout_rtp20` = 300 packets, `video_rtp20_bytes`
    // = "90", no `unq_video` after the first sightings. p7a read the second stream at +24, found no RTP there and
    // dropped all of it into `unq_video`.
    // TO BE CHECKED (C2, deferred): the per-client means (`fps_*`, `jitter_ms_*`, `frame_gap_std_ms_*`, `degraded_*`)
    // average over BOTH streams here, so `fps_downlink` shows about (30 + 15) / 2 = 22.5 (the demo prints 22.7), not the 30 the user sees on
    // the main tile. Whether the second stream should be a separate series is the open aux/main question
    // (zoom_capture/README.md, 'The aux / main question').
    let mut m = vec![];
    for i in 0..600u64 {
        let mut x = e(s(2.0) + i * 33_333, false, 16, Some(24), 98, 0x2700_0001, 700 + i as u16, i as u32 * 3000, 1000);
        x.marker = true;
        m.push(x);
    }
    for i in 0..300u64 {
        let mut x = e(s(2.0) + 5_000 + i * 66_666, false, 16, Some(20), 98, 0x2700_0002, 9100 + i as u16, i as u32 * 6000, 600);
        x.marker = true;
        m.push(x);
    }
    emit_client(ev, Addr::from_v4([10, 184, 2, 7]), 50016, m, None, next_id);

    // ---- I: only type 21 and type 10: never a session
    let mut c = vec![];
    for i in 0..400u64 {
        c.push(e(s(1.0) + i * 50_000, true, 21, None, 0, 0, i as u16, 0, 1044));
    }
    for i in 0..100u64 {
        c.push(e(s(1.0) + i * 200_000, false, 10, None, 0, 0, i as u16, 0, 90));
    }
    emit_client(ev, Addr::from_v4([10, 184, 2, 3]), 50012, c, None, next_id);

    // ---- J: gallery view. Video A 30 fps x 3 pkts (the server forwards a subset: every 7th frame is skipped, so the
    // downlink sequence has gaps that are NOT loss) with FEC (PT 110, same SSRC, own sequence space); video B 10 fps x 2
    // pkts (below 15 FPS = degraded); two speakers; five audio packets lost before the capture, and a 1 s blackout of
    // the whole flow (about 170 counter numbers at once: a counter JUMP the capture cannot tell from a restart, not 'missing').
    let mut j = vec![];
    let mut seq_a = 1000u16;
    let mut fec_seq = 60_000u16;
    for i in 0..600u64 {
        if i % 7 == 6 {
            seq_a = seq_a.wrapping_add(3);
            continue;
        }
        for k in 0..3u64 {
            let mut x = e(s(3.0) + i * 33_333 + k * 300, false, 16, Some(24), 98, 0x2400_0001, seq_a, i as u32 * 3000, 1100);
            x.marker = k == 2;
            j.push(x);
            seq_a = seq_a.wrapping_add(1);
        }
        if i % 10 == 5 {
            j.push(e(s(3.0) + i * 33_333 + 1_000, false, 16, Some(24), 110, 0x2400_0001, fec_seq, i as u32 * 3000, 700));
            fec_seq = fec_seq.wrapping_add(1);
        }
    }
    let mut seq_b = 2000u16;
    for i in 0..200u64 {
        for k in 0..2u64 {
            let mut x = e(s(3.0) + i * 100_000 + k * 400, false, 16, Some(24), 98, 0x2400_0002, seq_b, i as u32 * 9000, 800);
            x.marker = k == 1;
            j.push(x);
            seq_b = seq_b.wrapping_add(1);
        }
    }
    for i in 0..1000u64 {
        let mut x = e(s(3.0) + i * 20_000, false, 15, Some(19), 113, 0x2400_0011, 100 + i as u16, i as u32 * 960, 130);
        x.lose = matches!(i, 100 | 300 | 301 | 700 | 900);
        j.push(x);
    }
    for sec in 0..4u64 {
        for i in 0..100u64 {
            j.push(e(s(4.0 + 5.0 * sec as f64) + i * 20_000, false, 15, Some(19), 113, 0x2400_0012, (sec * 100 + i) as u16, ((sec * 100 + i) * 960) as u32, 130));
        }
    }
    emit_client(ev, Addr::from_v4([10, 184, 2, 4]), 50013, j, Some((s(12.0), s(13.0))), next_id);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = std::path::PathBuf::from(args.get(1).expect("usage: demo_capture OUT_DIR [--secs N] [--snaplen N] [--wrong-offset TYPE] [--garbage TYPE]"));
    let opt = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let secs: u64 = opt("--secs").and_then(|v| v.parse().ok()).unwrap_or(20);
    let snaplen: usize = opt("--snaplen").and_then(|v| v.parse().ok()).unwrap_or(128);
    let wrong = opt("--wrong-offset").unwrap_or_default();
    let shift = |name: &str| usize::from(wrong == name);
    let garbage = opt("--garbage").unwrap_or_default();
    let unknown_types = args.iter().any(|a| a == "--unknown-types");
    let stage2_out = opt("--stage2");
    GARBAGE_TYPE.store(match garbage.as_str() { "video" => 16, "audio" => 15, "screen13" => 13, _ => 0 }, Ordering::Relaxed);
    std::fs::create_dir_all(&out).expect("create out dir");

    let srv = Addr::from_v4([170, 114, 107, 187]);
    let a = Addr::from_v4([10, 184, 1, 10]);
    let b = Addr::from_v4([10, 184, 1, 11]);
    let c6 = Addr::from_ip("2001:df4:e000::5".parse().unwrap());
    let srv6 = Addr::from_ip("2407:30c0:106:900::1".parse().unwrap());
    let (port_a, port_b, port_c) = (50000u16, 50001u16, 50002u16);

    let mut ev: Events = Vec::new();
    let t0 = 1_000_000u64;
    let up = |cl: Addr, port: u16, pl: &[u8], id: u16| frame(&Spec { ip_id: id, vlan_tags: 1, ..Spec::new(cl, srv, port, 8801, pl) });
    let down = |cl: Addr, port: u16, pl: &[u8], id: u16| frame(&Spec { ip_id: id, vlan_tags: 1, ..Spec::new(srv, cl, 8801, port, pl) });

    let mut id = 1u16;
    let mut next_id = || {
        id = id.wrapping_add(1);
        id
    };
    // ---- client A: video down 30 fps x 3, video up 15 fps x 2, audio both ways, RTCP
    let (mut vseq_d, mut vseq_u, mut aseq_d, mut aseq_u) = (1000u16, 7000u16, 300u16, 900u16);
    let (mut fs_d, mut fs_u) = (10u16, 50u16);
    for s in 0..secs {
        let sec_t = t0 + s * 1_000_000;
        for f in 0..30u64 {
            let ft = sec_t + f * 33_333;
            let rts = ((s * 30 + f) * 3000) as u32;
            fs_d = fs_d.wrapping_add(1 + (f % 2) as u16); // frame_seq steps by 1 or 2 like the real data
            for k in 0..3u64 {
                let r = Rtp { pt: 98, marker: k == 2, seq: vseq_d, ts: rts, ssrc: 0x1000_0001 };
                let p = payload(16, true, vseq_d, vseq_d, (ft / 1000) as u32, Some((fs_d, 3)), Some((24, &r)), shift("video"), 1150);
                let t = ft + k * 300;
                add(&mut ev, t, down(a, port_a, &p, next_id()));
                if vseq_d % 200 == 0 {
                    ev.push((t + 100_000, 0, down(a, port_a, &p, next_id()))); // retransmission 100 ms later: must survive de-dup
                }
                vseq_d = vseq_d.wrapping_add(1);
            }
            if f % 10 == 5 {
                // a FEC packet (PT 110, own SSRC)
                let r = Rtp { pt: 110, marker: false, seq: (f as u16) + (s as u16) * 30, ts: rts, ssrc: 0x1000_0002 };
                let p = payload(16, true, 1, 1, (ft / 1000) as u32, Some((fs_d, 3)), Some((24, &r)), shift("video"), 700);
                add(&mut ev, ft + 1_000, down(a, port_a, &p, next_id()));
            }
        }
        for f in 0..15u64 {
            let ft = sec_t + f * 66_666;
            let rts = ((s * 15 + f) * 6000) as u32;
            fs_u = fs_u.wrapping_add(1);
            for k in 0..2u64 {
                let r = Rtp { pt: 98, marker: k == 1, seq: vseq_u, ts: rts, ssrc: 0x2000_0001 };
                let p = payload(16, false, vseq_u, vseq_u, (ft / 1000) as u32, Some((fs_u, 2)), Some((24, &r)), shift("video"), 900);
                add(&mut ev, ft + k * 400, up(a, port_a, &p, next_id()));
                vseq_u = vseq_u.wrapping_add(1);
            }
        }
        for i in 0..50u64 {
            let t = sec_t + i * 20_000;
            let r = Rtp { pt: 113, marker: false, seq: aseq_d, ts: ((s * 50 + i) * 960) as u32, ssrc: 0x3000_0001 };
            let p = payload(15, true, aseq_d, aseq_d, (t / 1000) as u32, None, Some((19, &r)), shift("audio"), 200);
            add(&mut ev, t, down(a, port_a, &p, next_id()));
            aseq_d = aseq_d.wrapping_add(1);
            let r = Rtp { pt: 113, marker: false, seq: aseq_u, ts: ((s * 50 + i) * 960) as u32, ssrc: 0x3000_0002 };
            let p = payload(15, false, aseq_u, aseq_u, (t / 1000) as u32, None, Some((19, &r)), shift("audio"), 180);
            add(&mut ev, t + 5_000, up(a, port_a, &p, next_id()));
            aseq_u = aseq_u.wrapping_add(1);
        }
        // RTCP sender report (type 34): RTCP header at +16: V=2, PT=200, SSRC at +4
        let mut p = payload(34, true, 1, 1, 1, None, None, 0, 100);
        let o = 8 + 16 + shift("rtcp");
        p[o] = 0x80;
        p[o + 1] = 200;
        p[o + 4..o + 8].copy_from_slice(&0x1000_0001u32.to_be_bytes());
        add(&mut ev, sec_t + 500_000, down(a, port_a, &p, next_id()));
    }
    // ---- client B: audio down + screen share down (type 13, 10 fps x 4)
    let (mut aseq_b, mut sseq, mut fs_s) = (50u16, 20u16, 400u16);
    for s in 0..secs {
        let sec_t = t0 + 3_000 + s * 1_000_000;
        for i in 0..50u64 {
            let t = sec_t + i * 20_000;
            let r = Rtp { pt: 116, marker: false, seq: aseq_b, ts: ((s * 50 + i) * 960) as u32, ssrc: 0x4000_0001 };
            add(&mut ev, t, down(b, port_b, &payload(15, true, 1, aseq_b, (t / 1000) as u32, None, Some((19, &r)), shift("audio"), 190), next_id()));
            aseq_b = aseq_b.wrapping_add(1);
        }
        for f in 0..10u64 {
            fs_s = fs_s.wrapping_add(1);
            for k in 0..4u64 {
                let r = Rtp { pt: 99, marker: k == 3, seq: sseq, ts: ((s * 10 + f) * 9000) as u32, ssrc: 0x5000_0001 };
                let t = sec_t + f * 100_000 + k * 300;
                add(&mut ev, t, down(b, port_b, &payload(13, true, 1, sseq, (t / 1000) as u32, Some((fs_s, 4)), Some((27, &r)), shift("screen13"), 1000), next_id()));
                sseq = sseq.wrapping_add(1);
            }
        }
    }
    if unknown_types {
        // ---- client D: audio down, every 15th packet in another layout (type 7)
        let d = Addr::from_v4([10, 184, 1, 12]);
        let (mut aseq_x, mut sfu_x, mut n_x) = (4000u16, 100u16, 0u64);
        for s in 0..secs {
            let sec_t = t0 + 5_000 + s * 1_000_000;
            for i in 0..50u64 {
                let t = sec_t + i * 20_000;
                let r = Rtp { pt: 116, marker: false, seq: aseq_x, ts: ((s * 50 + i) * 960) as u32, ssrc: 0x6000_0001 };
                let p = if n_x % 15 == 7 {
                    payload(7, true, sfu_x, 251, 0x1234_5678, None, Some((31, &r)), 0, 190)
                } else {
                    payload(15, true, sfu_x, aseq_x.wrapping_add(30_000), (t / 1000) as u32, None, Some((19, &r)), 0, 190)
                };
                add(&mut ev, t, down(d, 50003, &p, next_id()));
                aseq_x = aseq_x.wrapping_add(1);
                sfu_x = sfu_x.wrapping_add(1);
                n_x += 1;
            }
        }
        // ---- client E: a video stream of a MADE-UP type number (99), RTP at media offset +20, 1044-byte packets.
        // p6/p7a used type 21 here ("phone-like type-21 video"); deck2 T21-4 REFUTED type 21 as RTP, so this fixture
        // now uses a number no part of the pipeline assigns. It must stay in the `other` class with no RTP fields.
        let e = Addr::from_v4([10, 184, 1, 13]);
        let (mut vseq_e, mut sfu_e) = (9000u16, 500u16);
        for s in 0..secs {
            let sec_t = t0 + 6_000 + s * 1_000_000;
            for f in 0..30u64 {
                let ft = sec_t + f * 33_333;
                let r = Rtp { pt: 98, marker: true, seq: vseq_e, ts: ((s * 30 + f) * 3000) as u32, ssrc: 0x7000_0001 };
                let p = payload(MADE_UP_TYPE, false, sfu_e, 1, 1, None, Some((20, &r)), 0, 1044);
                add(&mut ev, ft, up(e, 50004, &p, next_id()));
                vseq_e = vseq_e.wrapping_add(1);
                sfu_e = sfu_e.wrapping_add(1);
            }
        }
    }
    // ---- client F (p7b): a camera flow with a main video stream (media byte 20 = 0x02, RTP at +24, 30 fps) and a
    // second video stream whose RTP header starts at media byte 20 (0x90, RTP at +20, 15 fps), both downlink in one
    // flow. This is what makes `validate_rtp_csv.py` check the third layout on a normal (non --stage2) demo run.
    {
        let f_addr = Addr::from_v4([10, 184, 1, 14]);
        let mut fl = vec![];
        for i in 0..secs * 30 {
            let mut x = e(t0 + 8_000 + i * 33_333, false, 16, Some(24), 98, 0x8000_0001, 100 + i as u16, i as u32 * 3000, 1000);
            x.marker = true;
            fl.push(x);
        }
        for i in 0..secs * 15 {
            let mut x = e(t0 + 12_000 + i * 66_666, false, 16, Some(20), 98, 0x8000_0002, 5000 + i as u16, i as u32 * 6000, 600);
            x.marker = true;
            fl.push(x);
        }
        emit_client(&mut ev, f_addr, 50005, fl, None, &mut next_id);
    }
    // ---- client C: IPv6, no SFU header (first byte 23), and port-443 noise
    for s in 0..secs {
        for i in 0..20u64 {
            let t = t0 + 7_000 + s * 1_000_000 + i * 50_000;
            add(&mut ev, t, frame(&Spec::new(c6, srv6, port_c, 8801, &[23u8; 300])));
            add(&mut ev, t + 1_000, frame(&Spec::new(a, srv, 40000, 443, &[1u8; 200])));
        }
    }
    if stage2_out.is_some() {
        stage2_events(&mut ev, t0, &mut next_id);
    }
    ev.sort_by_key(|e| e.0);

    // ---- the real pipeline with the real writers
    // (the pool is large because this loop replays 20 s of virtual time in milliseconds, so the
    // 100 ms partial-batch flushes come far faster than a real run's; a live run counts any drops)
    let b = Pipeline::new(
        PipelineConfig { shards: CORES, dump_cap: Some(1 << 20), pcap: Some(PcapCfg { snaplen, pool_slots: 65_536 }), channel_cap: 1 << 20, probation_slots: 1 << 16, ..Default::default() },
        IpSet::zoom_default(),
    );
    let (files, p) = (b.files.clone(), Arc::new(b.pipeline));
    let export_rx = b.export_rx;
    // `--stage2 FILE`: the real exporter (assembler, sessions, line protocol) writes FILE.
    // Without it the receiver is only kept alive so the pipeline never sees a closed channel.
    let mut keep_rx = None;
    let exporter = if let Some(path) = &stage2_out {
        let sink = zoom_pipeline::export::FileSink::create(std::path::Path::new(path)).expect("open metrics file");
        let cfg = zoom_pipeline::export::ExportCfg { host: "demo".into(), ssrc_lines: true, ..Default::default() };
        let (st, start) = (Arc::new(zoom_pipeline::export::ExportStats::default()), p.start());
        Some(std::thread::spawn(move || zoom_pipeline::export::run_exporter(export_rx, Box::new(sink), cfg, start, st)))
    } else {
        keep_rx = Some(export_rx);
        None
    };
    let stop = Arc::new(AtomicBool::new(false));
    let csv_path = out.join("packets.csv");
    let csv = CsvWriter::open(b.dump_rx.unwrap(), &csv_path, &files).expect("open csv");
    let pcap = PcapWriter::open(b.pcap.unwrap(), &out.join("pcap"), &files).expect("open pcap");
    let (f1, s1) = (files.clone(), stop.clone());
    let h_csv = std::thread::spawn(move || csv.run(&f1, &s1));
    let (f2, s2) = (files.clone(), stop.clone());
    let h_pcap = std::thread::spawn(move || pcap.run(&f2, &s2));
    for (t, core, f) in &ev {
        p.on_frame_at(*core, *t, f);
        // the writers are far faster than this loop on a real disk, but let them breathe
        // so the demo never drops (a real run counts drops instead)
        if t % 1000 == 0 {
            std::thread::yield_now();
        }
    }
    p.shutdown();
    if let Some(h) = exporter {
        h.join().expect("exporter thread");
    }
    drop(keep_rx);
    stop.store(true, Ordering::Relaxed);
    let rows = h_csv.join().unwrap().unwrap();
    let pk = h_pcap.join().unwrap().unwrap();
    let h = p.health();
    println!("demo: {} frames fed ({} s of synthetic traffic, wrong offset: {})", ev.len(), secs, if wrong.is_empty() { "none" } else { &wrong });
    println!("pipeline: in={} matched={} dups_dropped={} port_filtered={} no_sfu={}", h.pkts_in, h.matched, h.dups_dropped, h.port_filtered, h.no_sfu);
    println!("rtp_ok={:?} rtp_bad={:?} rtp_short={} video_layout[02,0a,rtp20,other]={:?}", h.rtp_ok, h.rtp_bad, h.rtp_short, h.video_layout);
    println!("csv: {rows} rows -> {}   pcap: {pk} packets -> {}/pcap/", csv_path.display(), out.display());
    println!("drops: dump={} pcap(pool/queue/limit)={}/{}/{}", h.dump_dropped, h.pcap_drop_pool, h.pcap_drop_queue, h.pcap_drop_limit);
}
