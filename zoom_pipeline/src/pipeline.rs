//! The packet path and its supervisor.
//!
//! ```text
//! capture core i (Retina callback, per packet; no allocation, no I/O, no wait)
//!   parse_udp -> port gate -> IpSet gate -> shared de-dup (striped, any core)
//!       -> [lock shard i] -> Zoom header class (+ inner RTP header, self-checked)
//!       -> [optional: pcap tap, debug-CSV dump]
//!       -> RtpHub.on_packet (client's stripe: SFU counter + RTP stream qualification/metrics)
//!       -> media in a qualified stream: counted by the hub (RtpBin per 5 s bin)
//!          everything else: shard.add (volume by Acct category) -> (bin closes) try_send(BinMetrics)
//! sweeper thread (1 Hz): per shard, small chunks: close quiet bins, evict idle streams
//! exporter thread: see export.rs
//! ```
//! Every early exit bumps a named counter, so `pkts_in` equals the sum of all
//! outcomes (checked by a unit test).

use crate::agg::{Shard, ShardCfg, StreamKey};
use crate::capture_files::{new_pcap, CaptureLimits, DiskBudget, FileCtx, PcapCfg, PcapTap, PcapWriterParts};
use crate::dedup::{fingerprint, SharedDedup, Verdict};
use crate::headers::{
    parse_media_header, parse_rtp, parse_sfu_header, rtp_slot, type13_kind, video_layout, MediaType, RtpFields, RtpKind, Type13Kind, VideoLayout,
    SFU_HEADER_LEN, T13_SUBTYPE_BYTE, VIDEO_LAYOUT_BYTE,
};
use crate::health::CoreCounters;
use crate::ipset::IpSet;
use crate::metrics::{HubCfg, HubPkt, RtpHub, RtpInfo, RtpOutcome};
use crate::model::{Acct, Class, Dir, ExportMsg, HealthSnapshot, PacketDump, KIND_AUDIO, KIND_SCREEN, KIND_VIDEO};
use crate::net::{parse_udp, Addr};
use crossbeam_channel::{bounded, Receiver, Sender};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct PipelineConfig {
    /// number of aggregation shards = number of RX cores (extra threads share)
    pub shards: usize,
    /// hard cap on tracked streams per shard
    pub max_streams: usize,
    /// de-duplicate second copies of a packet (one table shared by all capture cores)
    pub dedup: bool,
    /// total slots of the shared table (16 bytes each)
    pub dedup_slots: usize,
    /// lock stripes of the shared table (rounded up to a power of two)
    pub dedup_stripes: usize,
    pub dedup_window_us: u64,
    pub bin_us: u64,
    /// evict a stream after this long without packets
    pub idle_us: u64,
    /// bounded capture-to-exporter channel
    pub channel_cap: usize,
    /// Zoom media UDP port range (inclusive); a packet passes if either side matches
    pub port_lo: u16,
    pub port_hi: u16,
    /// optional extra ports (e.g. 3478, 3479); 0 = unused
    pub extra_ports: [u16; 4],
    /// `Some(cap)` enables the per-packet debug dump channel
    pub dump_cap: Option<usize>,
    /// `Some(..)` enables the pcap of unique Zoom packets (see `capture_files`)
    pub pcap: Option<PcapCfg>,
    /// size limits shared by the pcap and the debug CSV (see `capture_files`)
    pub limits: CaptureLimits,
    /// slab entries handled per lock acquisition by the sweeper
    pub sweep_chunk: usize,
    /// lock stripes of the shared RTP-stream hub (picked by client address)
    pub rtp_stripes: usize,
    /// total RTP streams (and, separately, SFU flows) the hub tracks
    pub max_rtp_streams: usize,
    /// direct-mapped probation slots per stripe (the flood guard)
    pub probation_slots: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        PipelineConfig {
            shards: 4,
            max_streams: 65_536,
            dedup: true,
            dedup_slots: 16_384,
            dedup_stripes: 16,
            dedup_window_us: 10_000,
            bin_us: 5_000_000,
            idle_us: 60_000_000,
            channel_cap: 262_144,
            port_lo: 8801,
            port_hi: 8810,
            extra_ports: [3478, 3479, 0, 0], // vc_combined: Zoom's published list, 2026-11-06
            dump_cap: None,
            pcap: None,
            limits: CaptureLimits::default(),
            sweep_chunk: 1024,
            rtp_stripes: 64,
            max_rtp_streams: 65_536,
            probation_slots: 1024,
        }
    }
}

/// False when the crate is built without the `dedup` feature: the de-dup table is then never
/// created and every branch that uses it is dead code.
pub const DEDUP_COMPILED: bool = cfg!(feature = "dedup");

#[repr(align(128))]
struct Padded<T>(T);

pub struct Pipeline {
    pub cfg: PipelineConfig,
    start: Instant,
    ips: IpSet,
    dedup: Option<SharedDedup>,
    shards: Vec<Padded<Mutex<Shard>>>,
    hub: RtpHub,
    counters: Vec<CoreCounters>,
    export_tx: Sender<ExportMsg>,
    dump_tx: Option<Sender<PacketDump>>,
    pcap: Option<PcapTap>,
    files: FileCtx,
}

pub struct Built {
    pub pipeline: Pipeline,
    pub export_rx: Receiver<ExportMsg>,
    pub dump_rx: Option<Receiver<PacketDump>>,
    /// writer side of the pcap, present iff `cfg.pcap` was `Some`
    pub pcap: Option<PcapWriterParts>,
    /// shared by the CSV and pcap writer threads (stats, byte budget, clock)
    pub files: FileCtx,
}

/// Extracted Zoom framing of one UDP payload.
struct ZoomFields {
    has_sfu: bool,
    class: Class,
    type_byte: u8,
    from_sfu: bool,
    sfu_seq: u16,
    media_seq: u16,
    media_ts: u32,
    frame_seq: i32,
    pkt_cnt: i16,
    /// inner RTP/RTCP header at the type's documented offset (None: type has
    /// no RTP, the payload is too short to hold it, or, p7b, a type-13 packet whose
    /// sub-type is not 0x1e and so has no RTP header at all)
    rtp: Option<RtpFields>,
    /// type 16 only: the media byte-20 layout (slot 0 = 0x02, 1 = 0x0a, 2 = rtp20, 3 = other),
    /// None for every other type and for a video payload too short to reach byte 20
    vlayout: Option<VideoLayout>,
    /// type 13 only (p7b): what media byte 7 says this packet is (RTP / probe padding / control)
    t13: Option<Type13Kind>,
    /// media byte 20 and byte 7, -1 when the payload is too short (debug CSV columns)
    b20: i16,
    b7: i16,
}

#[inline]
fn zoom_fields(p: &[u8]) -> ZoomFields {
    if let Some(sfu) = parse_sfu_header(p) {
        let media = p.get(SFU_HEADER_LEN..);
        if let Some(m) = media.and_then(parse_media_header) {
            let class = match m.media_type {
                MediaType::Video => Class::Video,
                MediaType::Audio => Class::Audio,
                MediaType::ScreenShareServer | MediaType::ScreenShareOptimized => Class::Screen,
                MediaType::RtcpSenderReport => Class::Rtcp,
                _ => Class::Other,
            };
            return ZoomFields {
                has_sfu: true,
                class,
                type_byte: m.raw_type,
                from_sfu: sfu.from_sfu(),
                sfu_seq: sfu.sequence,
                media_seq: m.sequence,
                media_ts: m.timestamp,
                frame_seq: m.frame_seq.map_or(-1, |v| v as i32),
                pkt_cnt: m.frame_pkt_count.map_or(-1, |v| v as i16),
                rtp: media.and_then(|rest| parse_rtp(rest, m.raw_type)),
                vlayout: if class == Class::Video { media.map(video_layout) } else { None },
                t13: if m.media_type == MediaType::ScreenShareServer { media.map(type13_kind) } else { None },
                b20: media.and_then(|r| r.get(VIDEO_LAYOUT_BYTE)).map_or(-1, |&b| b as i16),
                b7: media.and_then(|r| r.get(T13_SUBTYPE_BYTE)).map_or(-1, |&b| b as i16),
            };
        }
    }
    ZoomFields {
        has_sfu: false,
        class: Class::NoHdr,
        type_byte: 0,
        from_sfu: false,
        sfu_seq: 0,
        media_seq: 0,
        media_ts: 0,
        frame_seq: -1,
        pkt_cnt: -1,
        rtp: None,
        vlayout: None,
        t13: None,
        b20: -1,
        b7: -1,
    }
}

fn random_seed() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(0x5eed);
    h.finish()
}

impl Pipeline {
    pub fn new(cfg: PipelineConfig, ips: IpSet) -> Built {
        Self::with_start(cfg, ips, Instant::now())
    }

    /// `start` is the monotonic zero shared with the exporter.
    pub fn with_start(cfg: PipelineConfig, ips: IpSet, start: Instant) -> Built {
        Self::with_start_budget(cfg, ips, start, None)
    }

    /// vc_combined: like `with_start`, with an externally owned byte budget, so that the Zoom
    /// files and the Teams/Meet files are charged to ONE total limit.
    pub fn with_start_budget(cfg: PipelineConfig, ips: IpSet, start: Instant, budget: Option<Arc<DiskBudget>>) -> Built {
        let n = cfg.shards.max(1);
        let (export_tx, export_rx) = bounded(cfg.channel_cap.max(16));
        let seed = random_seed();
        let mut shards = Vec::with_capacity(n);
        let mut counters = Vec::with_capacity(n);
        for i in 0..n {
            shards.push(Padded(Mutex::new(Shard::new(
                ShardCfg {
                    max_streams: cfg.max_streams,
                    bin_us: cfg.bin_us,
                    idle_us: cfg.idle_us,
                    hash_seed: seed ^ (i as u64).wrapping_mul(0x9e37_79b9),
                },
                export_tx.clone(),
            ))));
            counters.push(CoreCounters::default());
        }
        let (dump_tx, dump_rx) = match cfg.dump_cap {
            Some(cap) => {
                let (t, r) = bounded(cap.max(16));
                (Some(t), Some(r))
            }
            None => (None, None),
        };
        let files = match budget {
            Some(b) => FileCtx::with_budget(b, start),
            None => FileCtx::new(cfg.limits, start),
        };
        let dedup = (cfg.dedup && DEDUP_COMPILED).then(|| SharedDedup::new(cfg.dedup_slots, cfg.dedup_window_us, cfg.dedup_stripes));
        let (pcap, pcap_parts) = match cfg.pcap {
            Some(pc) => {
                let (tap, parts) = new_pcap(pc, files.budget.clone(), n);
                (Some(tap), Some(parts))
            }
            None => (None, None),
        };
        let hub = RtpHub::new(
            HubCfg {
                stripes: cfg.rtp_stripes,
                max_streams: cfg.max_rtp_streams,
                bin_us: cfg.bin_us,
                idle_us: cfg.idle_us,
                probation_slots: cfg.probation_slots,
                seed: seed ^ 0x7f4a_7c15,
            },
            export_tx.clone(),
        );
        Built {
            pipeline: Pipeline { cfg, start, ips, dedup, shards, hub, counters, export_tx, dump_tx, pcap, files: files.clone() },
            export_rx,
            dump_rx,
            pcap: pcap_parts,
            files,
        }
    }

    pub fn start(&self) -> Instant {
        self.start
    }

    #[inline]
    pub fn now_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }

    #[inline]
    fn port_ok(&self, p: u16) -> bool {
        (p >= self.cfg.port_lo && p <= self.cfg.port_hi) || (p != 0 && self.cfg.extra_ports.contains(&p))
    }

    /// The packet path. `core` is the dense capture-core index.
    #[inline]
    pub fn on_frame(&self, core: usize, frame: &[u8]) {
        self.on_frame_at(core, self.now_us(), frame)
    }

    /// Same with an explicit clock (tests, replay).
    pub fn on_frame_at(&self, core: usize, t_us: u64, frame: &[u8]) {
        let ci = core % self.counters.len();
        let c = &self.counters[ci];
        CoreCounters::bump(&c.pkts_in);

        let Ok(u) = parse_udp(frame) else {
            CoreCounters::bump(&c.parse_fail);
            return;
        };
        if !(self.port_ok(u.src_port) || self.port_ok(u.dst_port)) {
            CoreCounters::bump(&c.port_filtered);
            return;
        }
        let src_in = self.ips.contains(u.src);
        let dst_in = self.ips.contains(u.dst);
        if !(src_in || dst_in) {
            // Staleness canary: a valid-looking Zoom SFU packet from an
            // address that is not on the list means the list is out of date.
            if u.payload.len() >= 23 && u.payload[0] == 0x05 {
                CoreCounters::bump(&c.zoom_like_unlisted);
            } else {
                CoreCounters::bump(&c.ip_filtered);
            }
            return;
        }

        // De-dup first, on the table shared by all cores, so the second copy of a packet is
        // recognised whichever RX queue delivered it (a per-core table missed
        // most twins on the campus link). A duplicate that is not being dumped
        // never takes the shard lock at all.
        let mut is_dup = false;
        if let Some(d) = self.dedup.as_ref() {
            let fp = fingerprint(0x5a5a, u.src, u.dst, u.src_port, u.dst_port, u.udp_len, u.payload);
            if let Verdict::Dup(info) = d.check(fp, t_us, u.ttl, u.ip_id) {
                CoreCounters::bump(&c.dups_dropped);
                match info.ttl_rel {
                    0 => CoreCounters::bump(&c.dup_ttl_same),
                    1 => CoreCounters::bump(&c.dup_ttl_off1),
                    _ => CoreCounters::bump(&c.dup_ttl_other),
                }
                if info.id_same {
                    CoreCounters::bump(&c.dup_id_same);
                }
                is_dup = true;
            }
        }
        // vc_combined: a twin goes nowhere, not even to the debug CSV, so the CSV and the pcap
        // both hold the kept packets only (they used to keep twins with `dup=1`).
        if is_dup {
            return;
        }

        let mut guard = match self.shards[ci].0.lock() {
            Ok(g) => g,
            Err(p) => {
                CoreCounters::add(&c.poison_recovered);
                p.into_inner()
            }
        };
        let shard: &mut Shard = &mut guard;

        let z = zoom_fields(u.payload);
        // Direction: the listed address is the server.
        let down = match (src_in, dst_in) {
            (true, false) => true,
            (false, true) => false,
            _ => z.from_sfu,
        };
        let dir = if down { Dir::Down } else { Dir::Up };

        if let Some(tx) = &self.dump_tx {
            let rec = PacketDump {
                t_us,
                src: u.src,
                dst: u.dst,
                src_port: u.src_port,
                dst_port: u.dst_port,
                udp_len: u.udp_len,
                ttl: u.ttl,
                ip_id: u.ip_id,
                class: z.class as u8,
                dir: dir as u8,
                dup: is_dup,
                core: ci as u8,
                has_sfu: z.has_sfu,
                media_type_byte: z.type_byte,
                sfu_seq: z.sfu_seq,
                media_seq: z.media_seq,
                media_ts: z.media_ts,
                frame_seq: z.frame_seq,
                frame_pkt_count: z.pkt_cnt,
                rtp_state: z.rtp.map_or(0, |r| if r.version_ok { 1 } else { 2 }),
                rtp_ssrc: z.rtp.map_or(0, |r| r.ssrc),
                rtp_seq: z.rtp.map_or(0, |r| r.seq),
                rtp_ts: z.rtp.map_or(0, |r| r.timestamp),
                rtp_pt: z.rtp.map_or(0, |r| r.payload_type),
                rtp_marker: z.rtp.is_some_and(|r| r.marker),
                media_b20: z.b20,
                media_b7: z.b7,
            };
            if tx.try_send(rec).is_err() {
                CoreCounters::bump(&c.dump_dropped);
            }
        }
        if is_dup {
            return;
        }

        // RTP self-check on unique packets only, so the ratio matches what the
        // metrics will see: a falling pass rate means a documented offset does
        // not hold on this network (see headers::parse_rtp).
        //
        // p7b: a type-13 packet whose sub-type (media byte 7) is not 0x1e has no RTP header,
        // so it is not part of the check at all. Without this branch every probe-padding packet
        // would be counted as `rtp_short` (parse_rtp returns None for it): tens of thousands per
        // share on the campus link, and the counter would stop meaning "payload too short".
        let gated_out = matches!(z.t13, Some(Type13Kind::Probe) | Some(Type13Kind::Control));
        if let Some(slot) = rtp_slot(z.type_byte).filter(|_| z.has_sfu && !gated_out) {
            match z.rtp {
                Some(r) if r.version_ok => CoreCounters::bump(&c.rtp_ok[slot]),
                Some(_) => CoreCounters::bump(&c.rtp_bad[slot]),
                None => CoreCounters::bump(&c.rtp_short),
            }
        }
        // Video layout (media byte 20, see headers::video_layout): how many unique video packets
        // used each layout. `other` must stay 0; a rising `other` is a fourth layout nobody has seen.
        // `rtp20` is the +20 layout (byte 20 in 0x80..=0xBF): its exact byte values go into a mask,
        // because "the whole range means +20" is an INFERENCE that only 0x90 has ever backed.
        if let Some(l) = z.vlayout {
            if let Some(slot) = l.slot() {
                CoreCounters::bump(&c.video_layout[slot]);
            }
            if let VideoLayout::Rtp20(b) = l {
                CoreCounters::set_bit(&c.video_rtp20_mask, (b - 0x80) as u32);
            }
        }
        // Optional pcap of unique packets (after de-dup, before aggregation).
        if let Some(tap) = &self.pcap {
            tap.offer(ci, t_us, frame, c);
        }

        if !z.has_sfu {
            CoreCounters::bump(&c.no_sfu);
        }
        let (client, server, cport, sport) = if down {
            (u.dst, u.src, u.dst_port, u.src_port)
        } else {
            (u.src, u.dst, u.src_port, u.dst_port)
        };
        // vc_combined: bytes = UDP length field - 8 (the UDP payload as sent), not the bytes we hold.
        // Identical on live traffic; on a replay of a 128-byte pcap it keeps bitrates right.
        let plen = (u.udp_len as u64).saturating_sub(8);

        // Media in a stream that behaves like RTP is counted by the hub (together with its
        // metrics); every other packet is volume in exactly one `Acct` category.
        let kind = match z.class {
            Class::Video => Some(KIND_VIDEO),
            Class::Audio => Some(KIND_AUDIO),
            Class::Screen => Some(KIND_SCREEN),
            _ => None,
        };
        let rtp = match (kind, z.rtp) {
            (Some(kind), Some(r)) if r.kind == RtpKind::Rtp && r.version_ok => Some(RtpInfo {
                kind,
                type_byte: z.type_byte,
                pt: r.payload_type,
                ssrc: r.ssrc,
                seq: r.seq,
                rtp_ts: r.timestamp,
                len: plen as u32,
            }),
            _ => None,
        };
        let outcome = if z.has_sfu {
            self.hub.on_packet(&HubPkt { client, client_port: cport, dir: dir as u8, t_us, sfu_seq: Some(z.sfu_seq), rtp })
        } else {
            RtpOutcome::NotRtp
        };
        let acct = match outcome {
            RtpOutcome::Counted | RtpOutcome::Held => None,
            _ => Some(match z.class {
                Class::Video => Acct::UnqVideo,
                Class::Audio => Acct::UnqAudio,
                // p7b: type-13 probe padding and control messages are named, not "unqualified screen
                // share"; RTP-shaped screen packets (type 30, type 13 sub-type 0x1e) that are not in a
                // qualified stream stay `UnqScreen`.
                Class::Screen => match z.t13 {
                    Some(Type13Kind::Probe) => Acct::T13Probe,
                    Some(Type13Kind::Control) => Acct::T13Ctrl,
                    _ => Acct::UnqScreen,
                },
                Class::Rtcp => Acct::Rtcp,
                Class::NoHdr => Acct::NoHdr,
                Class::Other => {
                    if z.type_byte == 21 {
                        Acct::Type21
                    } else {
                        Acct::Other
                    }
                }
            }),
        };
        match acct {
            None => {
                CoreCounters::bump(&c.matched);
                CoreCounters::bump_by(&c.matched_bytes, plen);
            }
            Some(a) => {
                let key = StreamKey { client, server, client_port: cport, server_port: sport, acct: a as u8, dir: dir as u8 };
                if shard.add(key, t_us, plen, c) {
                    CoreCounters::bump(&c.matched);
                    CoreCounters::bump_by(&c.matched_bytes, plen);
                }
            }
        }
    }

    // ---------------------------------------------------------- supervision

    /// One full sweep of every shard, `sweep_chunk` entries per lock hold.
    pub fn sweep_once(&self, now_us: u64) {
        for (i, sh) in self.shards.iter().enumerate() {
            loop {
                let wrapped = {
                    let mut g = match sh.0.lock() {
                        Ok(g) => g,
                        Err(p) => {
                            CoreCounters::add(&self.counters[i].poison_recovered);
                            p.into_inner()
                        }
                    };
                    g.sweep_chunk(self.cfg.sweep_chunk, now_us, &self.counters[i])
                };
                if wrapped {
                    break;
                }
                std::thread::yield_now();
            }
        }
        self.hub.sweep_once(now_us, self.cfg.sweep_chunk);
    }

    pub fn health(&self) -> HealthSnapshot {
        let mut h = HealthSnapshot { t_us: self.now_us(), ..Default::default() };
        for (i, c) in self.counters.iter().enumerate() {
            let g = CoreCounters::get;
            h.pkts_in += g(&c.pkts_in);
            h.parse_fail += g(&c.parse_fail);
            h.port_filtered += g(&c.port_filtered);
            h.ip_filtered += g(&c.ip_filtered);
            h.zoom_like_unlisted += g(&c.zoom_like_unlisted);
            h.dups_dropped += g(&c.dups_dropped);
            h.dup_ttl_same += g(&c.dup_ttl_same);
            h.dup_ttl_off1 += g(&c.dup_ttl_off1);
            h.dup_ttl_other += g(&c.dup_ttl_other);
            h.dup_id_same += g(&c.dup_id_same);
            h.matched += g(&c.matched);
            h.matched_bytes += g(&c.matched_bytes);
            h.no_sfu += g(&c.no_sfu);
            h.streams_rejected += g(&c.streams_rejected);
            h.streams_evicted += g(&c.streams_evicted);
            h.bins_dropped += g(&c.bins_dropped);
            h.bins_emitted += g(&c.bins_emitted);
            h.poison_recovered += g(&c.poison_recovered);
            h.dump_dropped += g(&c.dump_dropped);
            for k in 0..h.rtp_ok.len() {
                h.rtp_ok[k] += g(&c.rtp_ok[k]);
                h.rtp_bad[k] += g(&c.rtp_bad[k]);
            }
            h.rtp_short += g(&c.rtp_short);
            h.video_rtp20_mask |= g(&c.video_rtp20_mask);
            for k in 0..h.video_layout.len() {
                h.video_layout[k] += g(&c.video_layout[k]);
            }
            h.pcap_drop_pool += g(&c.pcap_drop_pool);
            h.pcap_drop_queue += g(&c.pcap_drop_queue);
            h.pcap_drop_limit += g(&c.pcap_drop_limit);
            h.per_core_in.push(g(&c.pkts_in));
            h.per_core_dups.push(g(&c.dups_dropped));
            let n = match self.shards[i].0.lock() {
                Ok(s) => s.streams_active(),
                Err(p) => p.into_inner().streams_active(),
            };
            h.streams_active += n as u64;
        }
        let (rs, sf) = self.hub.streams_active();
        h.rtp_streams_active = rs as u64;
        h.sfu_flows_active = sf as u64;
        let hc = &self.hub.ctr;
        h.rtp_streams_rejected = hc.streams_rejected.load(Ordering::Relaxed);
        h.rtp_qualified = hc.qualified.load(Ordering::Relaxed);
        h.rtp_failed_qual = hc.failed_qual.load(Ordering::Relaxed);
        h.rtp_probation_skipped = hc.probation_skipped.load(Ordering::Relaxed);
        h.hub_bins_dropped = hc.bins_dropped.load(Ordering::Relaxed);
        h.bins_dropped += h.hub_bins_dropped;
        h.streams_evicted += hc.evicted.load(Ordering::Relaxed);
        let f = &self.files;
        let g = |a: &std::sync::atomic::AtomicU64| a.load(Ordering::Relaxed);
        h.pcap_pkts = g(&f.stats.pcap_pkts);
        h.pcap_bytes = g(&f.stats.pcap_bytes);
        h.pcap_files = g(&f.stats.pcap_files);
        // a packet can be lost to the limit on the capture side (tap closed) or on the writer side
        h.pcap_drop_limit += g(&f.stats.pcap_drop_limit_writer);
        h.csv_rows = g(&f.stats.csv_rows);
        h.csv_bytes = g(&f.stats.csv_bytes);
        h.csv_files = g(&f.stats.csv_files);
        h.csv_drop_limit = g(&f.stats.csv_drop_limit);
        h.file_io_errors = g(&f.stats.io_errors);
        h.capture_limit_tripped = (!f.budget.is_open()) as u64;
        h.capture_disk_bytes = f.budget.used();
        h
    }

    /// Queue a health snapshot for export (never blocks).
    pub fn emit_health(&self) {
        let _ = self.export_tx.try_send(ExportMsg::Health(Box::new(self.health())));
    }

    /// Close every open bin and tell the exporter to finish. Call after the
    /// capture runtime has stopped.
    pub fn shutdown(&self) {
        for (i, sh) in self.shards.iter().enumerate() {
            let mut g = match sh.0.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            g.flush_all(&self.counters[i]);
        }
        self.hub.flush_all();
        // hand the writer the batches still being filled; then it can be told to stop
        if let Some(tap) = &self.pcap {
            for (i, c) in self.counters.iter().enumerate() {
                tap.flush(i, c);
            }
        }
        self.emit_health();
        // blocking send is fine here: capture has stopped and the exporter drains
        let _ = self.export_tx.send_timeout(ExportMsg::Shutdown, Duration::from_secs(5));
    }

    /// Spawn the 1 Hz sweeper; also queues a health snapshot every
    /// `health_every`. Stops when `stop` is set.
    pub fn spawn_sweeper(self: &Arc<Self>, stop: Arc<AtomicBool>, health_every: Duration) -> JoinHandle<()> {
        let p = Arc::clone(self);
        std::thread::Builder::new()
            .name("zc-sweeper".into())
            .spawn(move || {
                let mut last_health = Instant::now();
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(250));
                    p.sweep_once(p.now_us());
                    if last_health.elapsed() >= health_every {
                        p.emit_health();
                        last_health = Instant::now();
                    }
                }
            })
            .expect("spawn sweeper thread")
    }
}

/// Dense thread-local core index for the Retina callback: the first packet a
/// thread handles takes the next number. RX cores are pinned threads, so the
/// mapping is stable. `CoreId` is deliberately not used (it is the lcore
/// number, e.g. 1,3,5,7, not a dense index).
pub fn thread_core_index() -> usize {
    use std::cell::Cell;
    use std::sync::atomic::AtomicUsize;
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    thread_local! { static IDX: Cell<usize> = const { Cell::new(usize::MAX) }; }
    IDX.with(|c| {
        if c.get() == usize::MAX {
            c.set(NEXT.fetch_add(1, Ordering::Relaxed));
        }
        c.get()
    })
}

#[allow(dead_code)]
fn _assert_sync() {
    fn is<T: Send + Sync>() {}
    is::<Pipeline>();
    let _ = Addr(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::build::{frame, Spec};

    const SRV: [u8; 4] = [170, 114, 107, 187];

    fn zoom_payload(media_type: u8, dir: u8, sfu_seq: u16, seq: u16, ts: u32, len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len.max(40)];
        p[0] = 0x05;
        p[1..3].copy_from_slice(&sfu_seq.to_be_bytes());
        p[7] = dir;
        p[8] = media_type;
        p[17..19].copy_from_slice(&seq.to_be_bytes());
        p[19..23].copy_from_slice(&ts.to_be_bytes());
        p
    }

    fn up_frame(client_n: u8, payload: &[u8], ttl: u8, id: u16) -> Vec<u8> {
        frame(&Spec { ttl, ip_id: id, ..Spec::new(Addr::from_v4([10, 184, 0, client_n]), Addr::from_v4(SRV), 50000, 8801, payload) })
    }
    fn down_frame(client_n: u8, payload: &[u8]) -> Vec<u8> {
        frame(&Spec::new(Addr::from_v4(SRV), Addr::from_v4([10, 184, 0, client_n]), 8801, 50000, payload))
    }

    fn mk(cfg: PipelineConfig) -> Built {
        Pipeline::new(cfg, IpSet::zoom_default())
    }

    fn bins(rx: &Receiver<ExportMsg>) -> Vec<crate::model::BinMetrics> {
        rx.try_iter()
            .filter_map(|m| if let ExportMsg::Bin(b) = m { Some(b) } else { None })
            .collect()
    }

    #[test]
    #[cfg(feature = "dedup")] // exercises the de-dup table
    fn counters_account_for_every_packet() {
        let b = mk(PipelineConfig { shards: 1, ..Default::default() });
        let p = &b.pipeline;
        let zp = zoom_payload(16, 0, 1, 1, 1, 1000);
        let mut t = 0;
        let mut send = |f: &[u8]| {
            t += 1000;
            p.on_frame_at(0, t, f);
        };
        send(&up_frame(1, &zp, 64, 1)); // matched
        send(&up_frame(1, &zp, 64, 1)); // duplicate
        send(&[1, 2, 3]); // parse fail
        // wrong port
        send(&frame(&Spec::new(Addr::from_v4([10, 0, 0, 1]), Addr::from_v4(SRV), 1111, 443, &zp)));
        // right port, unlisted address, Zoom-looking header -> canary
        send(&frame(&Spec::new(Addr::from_v4([10, 0, 0, 1]), Addr::from_v4([1, 2, 3, 4]), 1111, 8801, &zp)));
        // right port, unlisted address, not Zoom-looking
        send(&frame(&Spec::new(Addr::from_v4([10, 0, 0, 1]), Addr::from_v4([1, 2, 3, 4]), 1111, 8801, &[0u8; 30])));
        let h = p.health();
        assert_eq!(h.pkts_in, 6);
        assert_eq!(
            (h.matched, h.dups_dropped, h.parse_fail, h.port_filtered, h.zoom_like_unlisted, h.ip_filtered),
            (1, 1, 1, 1, 1, 1)
        );
        assert_eq!(h.pkts_in, h.matched + h.dups_dropped + h.parse_fail + h.port_filtered + h.zoom_like_unlisted + h.ip_filtered + h.streams_rejected);
    }

    #[test]
    fn direction_class_and_client_come_from_the_ip_gate_and_media_type() {
        let b = mk(PipelineConfig { shards: 1, ..Default::default() });
        let p = &b.pipeline;
        let v = zoom_payload(16, 0, 1, 1, 1, 1200);
        let a = zoom_payload(15, 4, 1, 1, 1, 200);
        for i in 0..3 {
            p.on_frame_at(0, 1000 + i * 10_000, &up_frame(7, &zoom_payload(16, 0, i as u16, i as u16, i as u32, 1200), 64, 1));
        }
        p.on_frame_at(0, 40_000, &down_frame(7, &a));
        p.on_frame_at(0, 50_000, &down_frame(7, &v));
        p.shutdown();
        let mut got = bins(&b.export_rx);
        got.sort_by_key(|x| (x.acct, x.dir));
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].client, Addr::from_v4([10, 184, 0, 7]));
        // These payloads carry no valid RTP header (zero bytes), so the video / audio packets are volume
        // of the unqualified categories, not media. video up (3 pkts), video down (1), audio down (1)
        let find = |acct: u8, dir: u8| got.iter().find(|x| x.acct == acct && x.dir == dir).unwrap();
        assert_eq!(find(Acct::UnqVideo as u8, Dir::Up as u8).pkts, 3);
        assert_eq!(find(Acct::UnqVideo as u8, Dir::Down as u8).pkts, 1);
        assert_eq!(find(Acct::UnqAudio as u8, Dir::Down as u8).bytes, 200);
        let v_up = find(Acct::UnqVideo as u8, 0);
        assert_eq!((v_up.client_port, v_up.server_port), (50000, 8801));
    }

    #[test]
    fn payload_without_sfu_header_is_counted_by_volume_as_nohdr() {
        let b = mk(PipelineConfig { shards: 1, ..Default::default() });
        let p = &b.pipeline;
        p.on_frame_at(0, 10, &up_frame(1, &[23u8; 300], 64, 1)); // first byte 23 like the IPv6 capture
        p.shutdown();
        let got = bins(&b.export_rx);
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].acct, got[0].bytes), (Acct::NoHdr as u8, 300));
        assert_eq!(p.health().no_sfu, 1);
    }

    #[test]
    #[cfg(feature = "dedup")] // exercises the de-dup table
    fn duplicates_are_removed_before_aggregation_and_diagnosed() {
        let b = mk(PipelineConfig { shards: 1, ..Default::default() });
        let p = &b.pipeline;
        for i in 0..100u16 {
            let zp = zoom_payload(16, 0, i, i, i as u32 * 3000, 1000);
            let t = 1_000 + i as u64 * 20_000;
            p.on_frame_at(0, t, &up_frame(1, &zp, 64, 100 + i));
            p.on_frame_at(0, t + 11, &up_frame(1, &zp, 64, 100 + i)); // twin 11 us later
        }
        p.shutdown();
        let h = p.health();
        assert_eq!((h.pkts_in, h.matched, h.dups_dropped), (200, 100, 100));
        assert_eq!((h.dup_ttl_same, h.dup_id_same), (100, 100));
        let got = bins(&b.export_rx);
        assert_eq!(got.iter().map(|x| x.pkts as u64).sum::<u64>(), 100);
    }

    #[test]
    #[cfg(feature = "dedup")] // exercises the de-dup table
    fn a_twin_received_on_a_different_core_is_still_removed() {
        // The campus failure: with a table per core, only twins that happened
        // to reach the same RX queue were caught (s1: 4 of 17 flows, s2: none),
        // and the exporter summed the surviving copies from different shards,
        // so counts came out up to 2x. Here every twin goes to another core.
        let b = mk(PipelineConfig { shards: 4, dump_cap: Some(1000), ..Default::default() });
        let p = &b.pipeline;
        for i in 0..100u16 {
            let zp = zoom_payload(16, 0, i, i, i as u32 * 3000, 1000);
            let t = 1_000 + i as u64 * 20_000;
            let core = (i % 4) as usize;
            p.on_frame_at(core, t, &up_frame(1, &zp, 64, 100 + i));
            p.on_frame_at((core + 1) % 4, t + 11, &up_frame(1, &zp, 64, 100 + i));
        }
        p.shutdown();
        let h = p.health();
        assert_eq!((h.pkts_in, h.matched, h.dups_dropped), (200, 100, 100));
        let got = bins(&b.export_rx);
        assert_eq!(got.iter().map(|x| x.pkts as u64).sum::<u64>(), 100, "no double counting across shards");
        // vc_combined: the CSV holds the kept copy only (twins go nowhere), and records which core saw it
        let rows: Vec<_> = b.dump_rx.as_ref().unwrap().try_iter().collect();
        assert_eq!(rows.len(), 100);
        assert_eq!(rows.iter().filter(|r| r.dup).count(), 0);
        assert_eq!(rows.iter().map(|r| r.core).collect::<std::collections::BTreeSet<_>>().len(), 4);
    }

    #[test]
    fn retransmission_100ms_later_is_kept() {
        let b = mk(PipelineConfig { shards: 1, ..Default::default() });
        let p = &b.pipeline;
        let zp = zoom_payload(16, 0, 9, 9, 9, 1000);
        p.on_frame_at(0, 0, &up_frame(1, &zp, 64, 1));
        p.on_frame_at(0, 100_000, &up_frame(1, &zp, 64, 2));
        assert_eq!(p.health().matched, 2);
    }

    #[test]
    fn dedup_can_be_switched_off() {
        let b = mk(PipelineConfig { shards: 1, dedup: false, ..Default::default() });
        let zp = zoom_payload(16, 0, 9, 9, 9, 1000);
        b.pipeline.on_frame_at(0, 0, &up_frame(1, &zp, 64, 1));
        b.pipeline.on_frame_at(0, 5, &up_frame(1, &zp, 64, 1));
        assert_eq!(b.pipeline.health().matched, 2);
    }

    #[test]
    fn a_panicking_thread_does_not_poison_the_capture_path() {
        let b = mk(PipelineConfig { shards: 1, ..Default::default() });
        let p = Arc::new(b.pipeline);
        let q = Arc::clone(&p);
        let r = std::thread::spawn(move || {
            let _g = q.shards[0].0.lock().unwrap();
            panic!("simulated bug while holding the shard lock");
        })
        .join();
        assert!(r.is_err());
        assert!(p.shards[0].0.is_poisoned());
        let zp = zoom_payload(16, 0, 1, 1, 1, 500);
        p.on_frame_at(0, 1, &up_frame(1, &zp, 64, 1));
        p.on_frame_at(0, 2_000_000, &up_frame(2, &zp, 64, 1));
        let h = p.health();
        assert_eq!(h.matched, 2);
        assert!(h.poison_recovered >= 1);
        p.sweep_once(10_000_000); // sweeper survives too
    }

    #[test]
    fn thread_core_index_is_dense_and_stable() {
        let a = thread_core_index();
        assert_eq!(a, thread_core_index());
        let b = std::thread::spawn(thread_core_index).join().unwrap();
        assert_ne!(a, b);
    }

    /// Zoom payload with an RTP header written where the deck says it is:
    /// SFU header (8 B) + `rtp_off` bytes into the media header.
    #[allow(clippy::too_many_arguments)]
    fn zoom_rtp_payload(media_type: u8, rtp_off: usize, ver: u8, pt: u8, rseq: u16, rts: u32, ssrc: u32, len: usize) -> Vec<u8> {
        let mut p = zoom_payload(media_type, 0, 1, rseq, rts, len.max(8 + rtp_off + 12 + 8));
        let o = 8 + rtp_off;
        if media_type == 16 && rtp_off != 20 {
            // like real video: media byte 20 says which layout this is (0x02 -> RTP at +24, 0x0a -> RTP at +28);
            // for the +20 layout byte 20 is the RTP header's own first byte, written below
            p[8 + crate::headers::VIDEO_LAYOUT_BYTE] = if rtp_off == 28 { 0x0a } else { 0x02 };
        }
        if media_type == 13 {
            // p7b: a type-13 packet only carries RTP when media byte 7 (the sub-type) is 0x1e
            p[8 + T13_SUBTYPE_BYTE] = crate::headers::T13_SUBTYPE_RTP;
        }
        p[o] = ver << 6;
        p[o + 1] = pt | 0x80;
        p[o + 2..o + 4].copy_from_slice(&rseq.to_be_bytes());
        p[o + 4..o + 8].copy_from_slice(&rts.to_be_bytes());
        p[o + 8..o + 12].copy_from_slice(&ssrc.to_be_bytes());
        p
    }

    #[test]
    fn rtp_self_check_counts_ok_bad_and_short_per_type_and_ignores_types_without_rtp() {
        let b = mk(PipelineConfig { shards: 1, dedup: false, ..Default::default() });
        let p = &b.pipeline;
        let mut t = 0u64;
        let mut send = |pl: &[u8], id: u16| {
            t += 100_000;
            p.on_frame_at(0, t, &up_frame(1, pl, 64, id));
        };
        for i in 0..3 {
            send(&zoom_rtp_payload(16, 24, 2, 98, i, 90_000 + i as u32, 0xAAAA, 1000), i); // video ok x3
        }
        send(&zoom_rtp_payload(16, 24, 1, 98, 9, 9, 0xAAAA, 1000), 10); // video wrong version
        send(&zoom_rtp_payload(15, 19, 2, 113, 1, 1, 0xBBBB, 200), 11); // audio ok
        send(&zoom_rtp_payload(13, 27, 2, 99, 1, 1, 0xCCCC, 900), 12); // screen13 ok
        send(&zoom_rtp_payload(30, 20, 0, 99, 1, 1, 0xCCCC, 900), 13); // screen30 bad (version bits 0 at +20)
        send(&zoom_payload(21, 0, 1, 1, 1, 500), 14); // type 21: no RTP, no count
        send(&zoom_payload(16, 0, 1, 1, 1, 20), 15); // video too short for RTP: payload len 40 min => see below
        send(&zoom_rtp_payload(30, 20, 2, 99, 2, 2, 0xDDDD, 900), 16); // screen30 ok: RTP at +20 (p7a; p6 read +27)
        // v2 headers only at the OLD +27: bad at +20. Two of them, so that reading +27 again (ok = 2, bad = 2) could not
        // give the same counts as the right reading (ok = 1, bad = 3).
        send(&zoom_rtp_payload(30, 27, 2, 99, 3, 3, 0xEEEE, 900), 17);
        send(&zoom_rtp_payload(30, 27, 2, 99, 4, 4, 0xFFFF, 900), 18);
        let h = p.health();
        assert_eq!(h.rtp_ok, [3, 1, 1, 1, 0]);
        assert_eq!(h.rtp_bad, [1, 0, 0, 3, 0]);
        // video byte 20: the 4 fixture packets say 0x02; the short zero-filled one has byte 20 = 0 -> "other"
        assert_eq!(h.video_layout, [4, 0, 0, 1]);
        // zoom_payload pads to 40 B; video RTP needs 8+24+12 = 44 B, so this one is "short"
        assert_eq!(h.rtp_short, 1);
    }

    #[test]
    #[cfg(feature = "dedup")] // exercises the de-dup table
    fn rtp_self_check_ignores_duplicates_and_payloads_without_an_sfu_header() {
        let b = mk(PipelineConfig { shards: 1, ..Default::default() });
        let p = &b.pipeline;
        let pl = zoom_rtp_payload(16, 24, 2, 98, 1, 1, 0xAAAA, 1000);
        p.on_frame_at(0, 1000, &up_frame(1, &pl, 64, 1));
        p.on_frame_at(0, 1011, &up_frame(1, &pl, 64, 1)); // second copy
        p.on_frame_at(0, 5000, &up_frame(1, &[23u8; 300], 64, 2)); // no SFU header
        let h = p.health();
        assert_eq!((h.rtp_ok[0], h.rtp_bad[0], h.rtp_short), (1, 0, 0));
        assert_eq!(h.dups_dropped, 1);
    }

    #[test]
    #[cfg(feature = "dedup")] // exercises the de-dup table
    fn dump_rows_carry_the_inner_rtp_fields_and_twins_are_not_dumped() {
        let b = mk(PipelineConfig { shards: 1, dump_cap: Some(64), ..Default::default() });
        let p = &b.pipeline;
        let pl = zoom_rtp_payload(16, 24, 2, 98, 4242, 0x0102_0304, 0xDEAD_BEEF, 1000);
        p.on_frame_at(0, 1000, &up_frame(1, &pl, 64, 1));
        p.on_frame_at(0, 1011, &up_frame(1, &pl, 64, 1)); // twin
        let rows: Vec<PacketDump> = b.dump_rx.as_ref().unwrap().try_iter().collect();
        assert_eq!(rows.len(), 1, "vc_combined: the twin is not written to the CSV");
        let r = &rows[0];
        assert_eq!((r.rtp_state, r.rtp_ssrc, r.rtp_seq, r.rtp_ts, r.rtp_pt, r.rtp_marker), (1, 0xDEAD_BEEF, 4242, 0x0102_0304, 98, true));
        assert!(!r.dup);
    }

    #[test]
    #[cfg(feature = "dedup")] // exercises the de-dup table
    fn pcap_is_off_by_default_and_on_it_holds_unique_packets_only() {
        use crate::capture_files::PcapWriter;
        assert!(mk(PipelineConfig::default()).pcap.is_none());

        let dir = std::env::temp_dir().join(format!("zc_pipe_pcap_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = mk(PipelineConfig {
            shards: 1,
            pcap: Some(PcapCfg { snaplen: 100, pool_slots: 256 }),
            ..Default::default()
        });
        let writer = PcapWriter::open(b.pcap.take().unwrap(), &dir, &b.files).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let h = {
            let (files, stop) = (b.files.clone(), stop.clone());
            std::thread::spawn(move || writer.run(&files, &stop))
        };
        let p = &b.pipeline;
        let mut originals = vec![];
        for i in 0..20u16 {
            let pl = zoom_rtp_payload(16, 24, 2, 98, i, i as u32, 0xAAAA, 1000);
            let f = up_frame(1, &pl, 64, i);
            p.on_frame_at(0, 1000 + i as u64 * 20_000, &f);
            p.on_frame_at(0, 1011 + i as u64 * 20_000, &f); // twin 11 us later: must NOT be in the pcap
            originals.push(f);
        }
        p.on_frame_at(0, 900_000, &up_frame(1, &[23u8; 300], 64, 99)); // NoHdr packet is kept
        p.on_frame_at(0, 910_000, &[1, 2, 3]); // parse failure is not a Zoom packet: not kept
        std::thread::sleep(Duration::from_millis(200));
        stop.store(true, Ordering::Relaxed);
        assert_eq!(h.join().unwrap().unwrap(), 21);
        let hs = p.health();
        assert_eq!((hs.pcap_pkts, hs.pcap_files, hs.dups_dropped), (21, 1, 20));
        assert_eq!((hs.pcap_drop_pool, hs.pcap_drop_queue, hs.pcap_drop_limit), (0, 0, 0));
        assert!(hs.pcap_bytes > 24 + 21 * 16);

        // read back with an independent minimal reader
        let f = std::fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
        let bytes = std::fs::read(&f).unwrap();
        let mut i = 24;
        let mut n = 0;
        while i < bytes.len() {
            let cap = u32::from_le_bytes([bytes[i + 8], bytes[i + 9], bytes[i + 10], bytes[i + 11]]) as usize;
            let orig = u32::from_le_bytes([bytes[i + 12], bytes[i + 13], bytes[i + 14], bytes[i + 15]]) as usize;
            let data = &bytes[i + 16..i + 16 + cap];
            if n < 20 {
                assert_eq!((cap, orig), (100, originals[n].len()));
                assert_eq!(data, &originals[n][..100], "packet {n}");
            } else {
                assert_eq!(orig, up_frame(1, &[23u8; 300], 64, 99).len());
            }
            i += 16 + cap;
            n += 1;
        }
        assert_eq!(n, 21);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn built_without_the_dedup_feature_nothing_is_dropped() {
        let b = mk(PipelineConfig { shards: 1, ..Default::default() });
        let p = &b.pipeline;
        let pl = zoom_rtp_payload(16, 24, 2, 98, 1, 1, 0xAAAA, 1000);
        p.on_frame_at(0, 1000, &up_frame(1, &pl, 64, 1));
        p.on_frame_at(0, 1011, &up_frame(1, &pl, 64, 1)); // twin
        let h = p.health();
        assert_eq!(h.dups_dropped, if DEDUP_COMPILED { 1 } else { 0 });
        assert_eq!(h.matched, if DEDUP_COMPILED { 1 } else { 2 });
    }

    #[test]
    fn extra_ports_and_vlan_and_ipv6_work_end_to_end() {
        let b = mk(PipelineConfig { shards: 1, extra_ports: [3478, 0, 0, 0], ..Default::default() });
        let p = &b.pipeline;
        let zp = zoom_payload(15, 0, 1, 1, 1, 100);
        // VLAN-tagged IPv4 on 3478
        let f = frame(&Spec { vlan_tags: 2, ..Spec::new(Addr::from_v4([10, 0, 0, 5]), Addr::from_v4(SRV), 4000, 3478, &zp) });
        p.on_frame_at(0, 1, &f);
        // IPv6 to the listed 2407:30c0::/32
        let s6 = Addr::from_ip("2001:df4:e000::5".parse().unwrap());
        let d6 = Addr::from_ip("2407:30c0:106:900::1".parse().unwrap());
        p.on_frame_at(0, 2, &frame(&Spec::new(s6, d6, 58474, 8801, &zp)));
        assert_eq!(p.health().matched, 2);
    }

    // ------------------------------------------------------------------
    // End to end: frames -> Pipeline -> ExportMsg -> Assembler -> line protocol
    // ------------------------------------------------------------------

    /// Everything the pipeline sent to the exporter, run through the real assembler.
    fn assemble(b: &Built) -> String {
        use crate::export::{Assembler, ExportCfg, ExportStats};
        let st = ExportStats::default();
        let mut asm = Assembler::new(ExportCfg::default());
        for m in b.export_rx.try_iter() {
            match m {
                ExportMsg::Bin(x) => asm.add(x, &st),
                ExportMsg::Rtp(x) => asm.add_rtp(x, &st),
                ExportMsg::Sfu(x) => asm.add_sfu(x, &st),
                _ => {}
            }
        }
        let mut out = String::new();
        asm.emit_ready(u64::MAX / 4, true, &|t: u64| 1_700_000_000_000_000_000i128 + t as i128 * 1000, &mut out, &st);
        out
    }

    fn fld(l: &str, name: &str) -> Option<f64> {
        l.split(' ').nth(1)?.split(',').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == name).then(|| v.trim_end_matches('i').parse().ok()).flatten()
        })
    }

    /// Sum of `name` x 5 s over the lines of one client: packets for the `*_pps_*` fields.
    fn pkts_of(out: &str, client_n: u8, name: &str) -> f64 {
        let tag = format!("client_ip=10.184.0.{client_n},");
        out.lines()
            .filter(|l| (l.starts_with("session_metrics") || l.starts_with("client_no_media")) && l.contains(&tag))
            .filter_map(|l| fld(l, name))
            .sum::<f64>()
            * 5.0
    }

    fn sum_of(out: &str, client_n: u8, name: &str) -> f64 {
        let tag = format!("client_ip=10.184.0.{client_n},");
        out.lines().filter(|l| l.starts_with("session_metrics") && l.contains(&tag)).filter_map(|l| fld(l, name)).sum()
    }

    #[test]
    fn end_to_end_sessions_screen_share_type21_and_the_packet_partition() {
        let b = mk(PipelineConfig { shards: 2, ..Default::default() });
        let p = &b.pipeline;
        // (time, client, up?, media type, rtp offset or None, pt, ssrc, rtp seq, rtp ts, len, sfu_seq skip)
        struct Ev {
            t: u64,
            c: u8,
            up: bool,
            ty: u8,
            off: Option<usize>,
            pt: u8,
            ssrc: u32,
            seq: u16,
            ts: u32,
            len: usize,
            sfu_skip: bool,
            /// override of media byte 7 (the type-13 sub-type); None = what the payload builder wrote
            b7: Option<u8>,
        }
        let mut ev: Vec<Ev> = vec![];
        let ms = 1000u64;
        // client 1: type 21 probe traffic for the whole 14 s, 10 pps up. Never media.
        for i in 0..140u64 {
            ev.push(Ev { t: i * 100 * ms, c: 1, up: true, ty: 21, off: None, pt: 0, ssrc: 0, seq: i as u16, ts: i as u32, len: 1044, sfu_skip: false, b7: None });
        }
        // client 1: camera up from 7.2 s, 30 fps, 150 packets, RTP 60 never arrives (also missing from the SFU counter)
        for i in 0..150u64 {
            if i == 60 {
                ev.push(Ev { t: 7_200_000 + i * 33_333, c: 1, up: true, ty: 0, off: None, pt: 0, ssrc: 0, seq: 0, ts: 0, len: 0, sfu_skip: true, b7: None });
                continue;
            }
            ev.push(Ev { t: 7_200_000 + i * 33_333, c: 1, up: true, ty: 16, off: Some(24), pt: 98, ssrc: 0x11, seq: 1000 + i as u16, ts: i as u32 * 3000, len: 1000, sfu_skip: false, b7: None });
        }
        // client 1: microphone up from 8.0 s, 50 pps, 200 packets
        for i in 0..200u64 {
            ev.push(Ev { t: 8_000_000 + i * 20_000, c: 1, up: true, ty: 15, off: Some(19), pt: 113, ssrc: 0x21, seq: 300 + i as u16, ts: i as u32 * 960, len: 120, sfu_skip: false, b7: None });
        }
        // client 1: screen share type 13 down from 9.0 s, 20 pps, 60 packets
        for i in 0..60u64 {
            ev.push(Ev { t: 9_000_000 + i * 50_000, c: 1, up: false, ty: 13, off: Some(27), pt: 99, ssrc: 0x31, seq: 10 + i as u16, ts: i as u32 * 4500, len: 900, sfu_skip: false, b7: None });
        }
        // client 1: screen share type 30 down from 10.0 s, 10 pps, 30 packets
        for i in 0..30u64 {
            ev.push(Ev { t: 10_000_000 + i * 100_000, c: 1, up: false, ty: 30, off: Some(20), pt: 99, ssrc: 0x32, seq: 50 + i as u16, ts: i as u32 * 9000, len: 900, sfu_skip: false, b7: None });
        }
        // client 1: 100 type-13 packets from 9.5 s that are NOT screen share: 60 probe padding (sub-type 0x15) and
        // 40 control messages (sub-type 0x00). Every other one carries a decoy header that looks like RTP version 2
        // at +27, with a new SSRC each time. p7a sent those to the hub as probation sightings (and counted them in
        // the screen13 self-check); since p7b the sub-type gate (media byte 7 != 0x1e) never lets them reach either.
        for i in 0..100u64 {
            let off = if i % 2 == 0 { Some(27) } else { None };
            let b7 = if i % 5 < 3 { 0x15 } else { 0x00 };
            ev.push(Ev { t: 9_500_000 + i * 10_000, c: 1, up: false, ty: 13, off, pt: 99, ssrc: 0x5000_0000 + i as u32, seq: i as u16, ts: 0, len: 1051, sfu_skip: false, b7: Some(b7) });
        }
        // client 2 (same meeting): only receives audio, from 12.3 s, 50 pps, 100 packets
        for i in 0..100u64 {
            ev.push(Ev { t: 12_300_000 + i * 20_000, c: 2, up: false, ty: 15, off: Some(19), pt: 113, ssrc: 0x41, seq: 700 + i as u16, ts: i as u32 * 960, len: 120, sfu_skip: false, b7: None });
        }
        ev.sort_by_key(|e| e.t);

        let mut sfu_up = [0u16; 3];
        let mut sfu_dn = [0u16; 3];
        let mut sent_up = [0u64; 3];
        let mut sent_dn = [0u64; 3];
        let mut sent_t21 = 0u64;
        for (n, e) in ev.iter().enumerate() {
            let ctr = if e.up { &mut sfu_up[e.c as usize] } else { &mut sfu_dn[e.c as usize] };
            *ctr = ctr.wrapping_add(1);
            if e.sfu_skip {
                continue; // the packet was not captured: its counter number is missing
            }
            let mut pl = match e.off {
                Some(off) => zoom_rtp_payload(e.ty, off, 2, e.pt, e.seq, e.ts, e.ssrc, e.len),
                None => zoom_payload(e.ty, 0, 1, e.seq, e.ts, e.len),
            };
            if let Some(b) = e.b7 {
                pl[8 + crate::headers::T13_SUBTYPE_BYTE] = b;
            }
            pl[1..3].copy_from_slice(&ctr.to_be_bytes());
            // make every packet distinct (no accidental de-dup). Bytes 3..5 of the SFU header are unused by the parser and
            // are inside the first 48 bytes the de-dup hashes; bytes 30 / 31 (p6) now lie inside a type-30 RTP header.
            pl[3] = n as u8;
            pl[4] = (n >> 8) as u8;
            if e.ty == 21 {
                sent_t21 += 1;
            }
            let f = if e.up { up_frame(e.c, &pl, 64, n as u16) } else { down_frame(e.c, &pl) };
            if e.up {
                sent_up[e.c as usize] += 1;
            } else {
                sent_dn[e.c as usize] += 1;
            }
            p.on_frame_at(n % 2, e.t, &f);
        }
        p.shutdown();
        let h = p.health();
        let out = assemble(&b);
        if std::env::var("ZP_PRINT").is_ok() {
            println!("{out}");
        }

        // ---- sessions: media only, per client, starting at that client's first media packet
        let summaries = |c: u8| -> Vec<&str> {
            let tag = format!("client_ip=10.184.0.{c},");
            out.lines().filter(|l| l.starts_with("session_summary") && l.contains(&tag)).collect()
        };
        for c in [1u8, 2] {
            let ids: std::collections::BTreeSet<&str> = summaries(c).iter().map(|l| l.split(',').nth(2).unwrap()).collect();
            assert_eq!(ids.len(), 1, "client {c}: exactly one session\n{out}");
        }
        let epoch = |t: u64| 1_700_000_000_000_000_000i128 + t as i128 * 1000;
        let s1 = summaries(1);
        let s2 = summaries(2);
        assert_eq!(fld(s1.last().unwrap(), "start_epoch_ns"), Some(epoch(7_200_000) as f64), "client 1 starts at its first camera packet, not at the first type-21 packet (t=0)");
        assert_eq!(fld(s2.last().unwrap(), "start_epoch_ns"), Some(epoch(12_300_000) as f64), "client 2 starts at ITS first media packet, independent of client 1");
        assert_ne!(s1[0].split(',').nth(2), s2[0].split(',').nth(2));
        assert_eq!(fld(s1.last().unwrap(), "had_screen"), Some(1.0));
        assert_eq!(fld(s2.last().unwrap(), "had_screen"), Some(0.0));
        assert_eq!(fld(s2.last().unwrap(), "had_video"), Some(0.0));
        // bin 0 of client 1 has only type 21: reported as "no media", with its type-21 rate
        let nm: Vec<&str> = out.lines().filter(|l| l.starts_with("client_no_media") && l.contains("client_ip=10.184.0.1,")).collect();
        assert_eq!(nm.len(), 1, "{out}");
        assert_eq!(fld(nm[0], "type21_pps_uplink"), Some(10.0));

        // ---- every captured packet is in exactly one place
        for c in [1usize, 2] {
            assert_eq!(pkts_of(&out, c as u8, "pps_uplink").round() as u64, sent_up[c], "client {c} uplink packets");
            assert_eq!(pkts_of(&out, c as u8, "pps_downlink").round() as u64, sent_dn[c], "client {c} downlink packets");
        }
        assert_eq!(h.matched, sent_up.iter().sum::<u64>() + sent_dn.iter().sum::<u64>(), "matched = packets that were not filtered / dups");
        // ---- type 21 is its own metric, and the non-media non-21 share is separate
        assert_eq!(pkts_of(&out, 1, "type21_pps_uplink").round() as u64, sent_t21);
        assert_eq!(pkts_of(&out, 1, "nonmedia_pps_uplink").round() as u64, 0);
        // ---- screen share: 13 + 30 aggregated, probes are not screen
        // qualified packets = sent - 1 (the first packet of a stream is a probation sighting)
        assert_eq!(pkts_of(&out, 1, "screen13_pps_downlink").round() as u64, 59);
        assert_eq!(pkts_of(&out, 1, "screen30_pps_downlink").round() as u64, 29);
        assert_eq!(pkts_of(&out, 1, "screen_pps_downlink").round() as u64, 59 + 29);
        // the 100 type-13 non-RTP packets are volume, not screen share, and (p7b) they have names: 60 probe
        // padding, 40 control. unq_screen keeps only the two sighting packets (first packet of the type-13
        // and of the type-30 stream), so unq_screen + t13_probe + t13_ctrl is exactly what p7a called unq_screen.
        assert_eq!(pkts_of(&out, 1, "t13_probe_pps_downlink").round() as u64, 60);
        assert_eq!(pkts_of(&out, 1, "t13_ctrl_pps_downlink").round() as u64, 40);
        assert_eq!(pkts_of(&out, 1, "unq_screen_pps_downlink").round() as u64, 2);
        let p7a_unq_screen = ["unq_screen", "t13_probe", "t13_ctrl"].iter().map(|n| pkts_of(&out, 1, &format!("{n}_pps_downlink")).round() as u64).sum::<u64>();
        assert_eq!(p7a_unq_screen, 100 + 2);
        assert_eq!(pkts_of(&out, 1, "unq_media_pps_downlink").round() as u64, 100 + 2, "unq_media keeps its p7a meaning");
        // the self-check sees only the packets that claim to be RTP: the 60 real screen13 ones, none of the 100 decoys
        assert_eq!((h.rtp_ok[2], h.rtp_bad[2], h.rtp_short), (60, 0, 0));
        assert_eq!(sum_of(&out, 1, "screen_frames_downlink") as u64, 59 + 29);
        assert!(sum_of(&out, 1, "screen_streams_active_downlink") >= 2.0);
        // ---- camera: one packet lost in 150, found by the RTP sequence and also by the SFU counter
        assert_eq!(sum_of(&out, 1, "lost_pkts_uplink") as u64, 1);
        assert_eq!(sum_of(&out, 1, "video_frames_uplink") as u64, 148, "149 camera packets seen after the sighting, one lost... frames = qualified packets");
        assert_eq!(sum_of(&out, 1, "capture_missing_pkts_uplink") as u64, 1);
        assert_eq!(pkts_of(&out, 1, "video_pps_uplink").round() as u64, 148);
        assert_eq!(pkts_of(&out, 1, "unq_video_pps_uplink").round() as u64, 1, "the sighting packet");
        // ---- audio
        assert_eq!(pkts_of(&out, 1, "audio_pps_uplink").round() as u64, 199);
        assert_eq!(pkts_of(&out, 2, "audio_pps_downlink").round() as u64, 99);
        // ---- hub bookkeeping
        assert_eq!(h.rtp_qualified, 5, "camera, mic, screen 13, screen 30, client 2 audio");
        assert_eq!(h.rtp_failed_qual, 0);
        // p7a: >= 50 (every decoy header was a first sighting of a new SSRC). Now only the first packet of each real
        // stream is a sighting, and the decoys never reach the hub.
        assert_eq!(h.rtp_probation_skipped, 5, "one sighting per real stream, none from the 100 type-13 probes / control messages");
    }

    /// p7a: 9 s of a camera stream use the other video layout (media byte 20 = 0x0a, RTP header at +28) and
    /// then switch back, same SSRC and consecutive RTP sequence numbers throughout. p6 read the burst packets at
    /// +24: they failed the version test (-> `unq_video`, `rtp_bad`) and the stream then saw a forward sequence
    /// jump that it booked as loss (empty bins, a false loss spike, a stall, false jitter).
    #[test]
    fn video_burst_layout_stays_in_its_stream_with_no_false_loss() {
        let b = mk(PipelineConfig { shards: 1, ..Default::default() });
        let p = &b.pipeline;
        let total = 900u64; // 30 s at 30 fps, one packet per frame, uplink
        let mut n_burst = 0u64;
        for i in 0..total {
            let burst = (300..570).contains(&i); // 9 s, 270 packets
            let off = if burst {
                n_burst += 1;
                28
            } else {
                24
            };
            let mut pl = zoom_rtp_payload(16, off, 2, 98, 1000 + i as u16, i as u32 * 3000, 0x0100_0001, 1000);
            pl[1..3].copy_from_slice(&(i as u16 + 1).to_be_bytes()); // gap-free SFU counter
            p.on_frame_at(0, 1_000_000 + i * 33_333, &up_frame(1, &pl, 64, i as u16));
        }
        p.shutdown();
        let h = p.health();
        let out = assemble(&b);
        if std::env::var("ZP_PRINT").is_ok() {
            println!("{out}");
        }
        assert_eq!(n_burst, 270);
        // the layout counters see both layouts and nothing unseen; the self-check passes every packet
        assert_eq!(h.video_layout, [total - n_burst, n_burst, 0, 0]);
        assert_eq!((h.rtp_ok[0], h.rtp_bad[0], h.rtp_short), (total, 0, 0));
        assert_eq!(h.rtp_qualified, 1, "one stream, not two");
        // all packets but the stream's first sighting are video; nothing is parked in unq_video
        assert_eq!(pkts_of(&out, 1, "video_pps_uplink").round() as u64, total - 1);
        assert_eq!(pkts_of(&out, 1, "unq_video_pps_uplink").round() as u64, 1, "only the sighting packet");
        // and no false loss / stall / capture gap / jitter
        assert_eq!(sum_of(&out, 1, "lost_pkts_uplink") as u64, 0);
        assert_eq!(sum_of(&out, 1, "stalls_uplink") as u64, 0);
        assert_eq!(sum_of(&out, 1, "capture_missing_pkts_uplink") as u64, 0);
        let max_jitter = out
            .lines()
            .filter(|l| l.starts_with("session_metrics"))
            .filter_map(|l| fld(l, "jitter_ms_uplink"))
            .fold(0.0f64, f64::max);
        assert!(max_jitter < 1.0, "jitter {max_jitter} ms");
    }
    /// p7b (C1): a second video stream inside one downlink flow whose media byte 20 is 0x90 (deck2 Part G: SSRC
    /// 0x01003C02 next to 0x01002801, ~26 pkt/s next to ~127 pkt/s). Its RTP header is at +20. p7a read it at +24:
    /// seq / timestamp / SSRC were garbage, 29.8 % passed the version test by accident, and the stream never
    /// qualified (`unq_video`, a video RTP-OK of 91.33 % for that client).
    #[test]
    fn second_video_stream_with_byte_20_0x90_is_read_at_plus_20_and_is_a_stream_of_its_own() {
        let b = mk(PipelineConfig { shards: 1, ..Default::default() });
        let p = &b.pipeline;
        let (mut n_main, mut n_aux) = (0u64, 0u64);
        for i in 0..400u64 {
            let aux = i % 5 == 4; // one packet in five: the real flow has ~26 pkt/s next to ~127 pkt/s
            let mut pl = if aux {
                n_aux += 1;
                let mut pl = zoom_rtp_payload(16, 20, 2, 98, 5000 + n_aux as u16, n_aux as u32 * 9000, 0x0100_3C02, 1000);
                pl[8 + crate::headers::VIDEO_LAYOUT_BYTE] = 0x90; // RTP version 2 + extension bit: byte 20 is RTP byte 0
                pl
            } else {
                n_main += 1;
                zoom_rtp_payload(16, 24, 2, 98, 1000 + n_main as u16, n_main as u32 * 3000, 0x0100_2801, 1000)
            };
            pl[1..3].copy_from_slice(&(i as u16 + 1).to_be_bytes()); // gap-free SFU counter of the flow
            p.on_frame_at(0, 1_000_000 + i * 7_800, &down_frame(1, &pl));
        }
        p.shutdown();
        let h = p.health();
        let out = assemble(&b);
        if std::env::var("ZP_PRINT").is_ok() {
            println!("{out}");
        }
        assert_eq!((n_main, n_aux), (320, 80));
        // layout counters: both layouts, and the exact byte value behind rtp20 (bit 0x90 - 0x80 = 16)
        assert_eq!(h.video_layout, [n_main, 0, n_aux, 0]);
        assert_eq!(h.video_rtp20_mask, 1u64 << 16);
        // self-check: every packet passes. NOT evidence by itself (rtp20 is selected by the very bit test it is
        // checked with); the evidence is that both SSRCs qualified as streams, with no failed qualification.
        assert_eq!((h.rtp_ok[0], h.rtp_bad[0], h.rtp_short), (400, 0, 0));
        assert_eq!((h.rtp_qualified, h.rtp_failed_qual), (2, 0), "two SSRCs in one flow = two streams");
        // everything but the two sighting packets is video; the aux stream does not end up in unq_video
        assert_eq!(pkts_of(&out, 1, "video_pps_downlink").round() as u64, 400 - 2);
        assert_eq!(pkts_of(&out, 1, "unq_video_pps_downlink").round() as u64, 2);
        // consecutive sequence numbers in both streams: no false loss, no capture gap
        assert_eq!(sum_of(&out, 1, "lost_pkts_downlink") as u64, 0);
        assert_eq!(sum_of(&out, 1, "capture_missing_pkts_downlink") as u64, 0);
        // TO BE CHECKED (C2, not implemented in p7b): the +20 stream is counted like any other video stream,
        // so `video_streams_active` is 2 and fps / jitter are means over both. When the aux / main split is
        // added (README, "The aux / main question") this assertion changes on purpose.
        let max_streams = out
            .lines()
            .filter(|l| l.starts_with("session_metrics"))
            .filter_map(|l| fld(l, "video_streams_active_downlink"))
            .fold(0.0f64, f64::max);
        assert_eq!(max_streams, 2.0);
    }

    /// p7b (C1): packets whose byte 20 is outside 0x80-0xBF and not 0x02 / 0x0a are still read at +24 and counted
    /// in `other`, so a fourth layout shows up in the status line, not silently in the metrics.
    #[test]
    fn video_byte_20_outside_the_known_values_counts_as_other_and_keeps_the_p6_offset() {
        let b = mk(PipelineConfig { shards: 1, dedup: false, ..Default::default() });
        let p = &b.pipeline;
        for (i, v) in [0x7Fu8, 0xC0, 0x00, 0x03].iter().enumerate() {
            let mut pl = zoom_rtp_payload(16, 24, 2, 98, i as u16, i as u32, 0x77, 1000);
            pl[8 + crate::headers::VIDEO_LAYOUT_BYTE] = *v;
            p.on_frame_at(0, 1000 + i as u64, &up_frame(1, &pl, 64, i as u16));
        }
        let h = p.health();
        assert_eq!(h.video_layout, [0, 0, 0, 4]);
        assert_eq!(h.video_rtp20_mask, 0);
        assert_eq!(h.rtp_ok[0], 4, "still read at +24 like p6");
    }
}
