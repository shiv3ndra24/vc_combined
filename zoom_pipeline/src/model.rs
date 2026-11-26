//! Plain data types that cross thread boundaries. All `Copy`/POD so the
//! capture path never allocates to produce one.

use crate::headers::{RTP_SLOTS, VIDEO_LAYOUT_SLOTS};
use crate::net::Addr;

/// What kind of Zoom packet this is. Decided by the Zoom media-type byte
/// (deck slide 21), not by packet size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Class {
    Video = 0,
    Audio = 1,
    /// media types 13 and 30
    Screen = 2,
    /// media types 33 and 34 (RTCP sender reports)
    Rtcp = 3,
    /// valid SFU header, media type 21/10/other: control-ish, non-media
    Other = 4,
    /// no Zoom SFU header: counted by volume, never fed to media metrics
    NoHdr = 5,
}
pub const NCLASS: usize = 6;
pub const CLASS_NAMES: [&str; NCLASS] = ["video", "audio", "screen", "rtcp", "other", "nohdr"];

impl Class {
    #[inline]
    pub fn idx(self) -> usize {
        self as usize
    }
    pub fn from_idx(i: u8) -> Class {
        match i {
            0 => Class::Video,
            1 => Class::Audio,
            2 => Class::Screen,
            3 => Class::Rtcp,
            4 => Class::Other,
            _ => Class::NoHdr,
        }
    }
}

/// Direction relative to the Zoom server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Dir {
    /// client -> server
    Up = 0,
    /// server -> client
    Down = 1,
}

/// Accounting category of the VOLUME path (packets and UDP payload bytes per
/// stream and 5 s bin). `Class` above says what the packet claims to be (it is
/// what the debug CSV prints); `Acct` says where its bytes are counted.
///
/// Qualified media (video / audio / screen packets that belong to an RTP-looking
/// stream, see `metrics.rs`) is NOT in this list: it travels as `RtpBin`, which
/// carries the per-stream metrics as well. Everything else is here, so every
/// packet is counted in exactly one place (a unit test checks the partition).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Acct {
    /// types 33/34: RTCP sender reports
    Rtcp = 0,
    /// valid SFU header, type is neither media nor 21 (10, 7, 1, 32, ...)
    Other = 1,
    /// no Zoom SFU header
    NoHdr = 2,
    /// type 21: probe padding (94 %) and control reports (5.8 %), deck2 T21-2. Never media,
    /// never RTP. p7b deliberately does NOT split it by sub-type (see `headers::MediaType::Unknown21`).
    Type21 = 3,
    /// type 16 packets that are not in a qualified RTP stream
    UnqVideo = 4,
    /// type 15 packets that are not in a qualified RTP stream
    UnqAudio = 5,
    /// RTP-shaped screen-share packets that are not (yet) in a qualified RTP stream: type 30, and
    /// type 13 with sub-type 0x1e (e.g. the first packets of a stream on probation, or a stream that
    /// never qualified). Since p7b this no longer holds probe padding or control messages of type 13:
    /// those are `T13Probe` / `T13Ctrl`. Identity with p7a: p7a `unq_screen` = p7b `unq_screen +
    /// t13_probe + t13_ctrl`, packet for packet and byte for byte.
    UnqScreen = 6,
    /// type 13 with sub-type (media byte 7) 0x15: a Type-21 probe packet in a Type-13 envelope
    /// (deck2 T13-3, CONFIRMED). Not screen share. See `headers::Type13Kind`.
    T13Probe = 7,
    /// type 13 with any other sub-type except 0x1e: short control messages (deck2 T13-4, INFERENCE),
    /// plus any probe whose marker is not at byte 7 (an OPEN gap of 4 % to about 15 % of the padding,
    /// see `headers::Type13Kind`).
    T13Ctrl = 8,
}
pub const NACCT: usize = 9;
pub const ACCT_NAMES: [&str; NACCT] =
    ["rtcp", "other", "nohdr", "type21", "unq_video", "unq_audio", "unq_screen", "t13_probe", "t13_ctrl"];

impl Acct {
    #[inline]
    pub fn idx(self) -> usize {
        self as usize
    }
}

/// Media kinds that get per-stream RTP metrics (`RtpBin::kind`). Same numbers as `Class`.
pub const KIND_VIDEO: u8 = 0;
pub const KIND_AUDIO: u8 = 1;
pub const KIND_SCREEN: u8 = 2;

/// One closed 5-second bin of one stream (one client x server x ports x
/// accounting category x direction). Produced by a capture core or the
/// sweeper, merged per client by the exporter.
#[derive(Clone, Copy, Debug)]
pub struct BinMetrics {
    pub client: Addr,
    pub bin_id: u64,
    /// `Acct` index
    pub acct: u8,
    pub dir: u8,
    pub client_port: u16,
    pub server_port: u16,
    pub pkts: u32,
    /// UDP payload bytes (thesis definition of throughput)
    pub bytes: u64,
    /// first and last packet time inside the bin, us since pipeline start
    pub first_us: u64,
    pub last_us: u64,
}

/// One closed 5-second bin of one QUALIFIED RTP stream, keyed by
/// (client, direction, SSRC, payload type). Carries the volume (so qualified
/// media bitrate comes from here) and everything Stage 2 computes per stream.
/// The exporter merges these per client and bin (and optionally writes them
/// one by one as `rtp_stream` lines).
#[derive(Clone, Copy, Debug)]
pub struct RtpBin {
    pub client: Addr,
    pub bin_id: u64,
    pub dir: u8,
    /// `KIND_VIDEO` / `KIND_AUDIO` / `KIND_SCREEN`
    pub kind: u8,
    /// Zoom media type byte: 16, 15, 13 or 30 (13 and 30 are both `KIND_SCREEN`)
    pub type_byte: u8,
    pub pt: u8,
    pub ssrc: u32,
    pub pkts: u32,
    pub bytes: u64,
    /// first / last packet time of this bin's counters, us. After a late
    /// qualification `first_us` can lie in an earlier bin: it is the first
    /// packet of the stream, which is when a session starts.
    pub first_us: u64,
    pub last_us: u64,
    /// distinct RTP timestamps seen first in this bin (frames); 0 for FEC (PT 110) and audio
    pub frames: u32,
    /// unique packets received (the loss denominator is rx + lost)
    pub rx: u32,
    /// sequence numbers skipped minus late arrivals that filled an earlier gap.
    /// Signed: a late packet can fill a gap counted in the previous bin.
    pub lost: i32,
    /// repeated sequence numbers that survived de-dup (retransmissions)
    pub retx: u32,
    /// inter-frame arrival gaps (ms) of this bin, as Welford sums: count, mean, sum of squared deviations
    pub gap_n: u32,
    pub gap_mean_ms: f64,
    pub gap_m2: f64,
    /// gaps longer than the stall threshold (200 ms)
    pub stalls: u32,
    /// RFC 3550 interarrival jitter at frame level, ms, value at the end of the bin
    pub jitter_ms: f32,
    /// audio only: seconds of this bin with more than 20 packets
    pub active_secs: u8,
}

/// SFU-counter bookkeeping of one flow and bin (works for every media type,
/// see `metrics::SfuFlow`): how many counter values were seen and how many
/// were skipped. On the uplink a skipped value is a packet the CAPTURE missed.
#[derive(Clone, Copy, Debug)]
pub struct SfuBin {
    pub client: Addr,
    pub bin_id: u64,
    pub dir: u8,
    pub seen: u32,
    pub missed: i32,
}

/// A cumulative snapshot of every health counter (monotonic, except the
/// `streams_active` gauge). Exported as `capture_health`.
#[derive(Clone, Debug, Default)]
pub struct HealthSnapshot {
    pub t_us: u64,
    pub pkts_in: u64,
    pub parse_fail: u64,
    pub port_filtered: u64,
    pub ip_filtered: u64,
    pub zoom_like_unlisted: u64,
    pub dups_dropped: u64,
    pub dup_ttl_same: u64,
    pub dup_ttl_off1: u64,
    pub dup_ttl_other: u64,
    pub dup_id_same: u64,
    pub matched: u64,
    pub matched_bytes: u64,
    pub no_sfu: u64,
    pub streams_rejected: u64,
    pub streams_evicted: u64,
    pub streams_active: u64,
    pub bins_dropped: u64,
    pub bins_emitted: u64,
    pub poison_recovered: u64,
    pub dump_dropped: u64,
    /// RTP/RTCP self-check, per type slot (see `headers::RTP_SLOT_NAMES`):
    /// version-2 header found / not found at the documented offset
    pub rtp_ok: [u64; RTP_SLOTS],
    pub rtp_bad: [u64; RTP_SLOTS],
    /// type with an RTP offset but a payload too short to hold the header
    pub rtp_short: u64,
    /// type-16 packets per media byte-20 layout `[0x02, 0x0a, rtp20, other]` (see `headers::video_layout`);
    /// `other` should stay 0, `0a` is the +28 burst layout, `rtp20` the +20 layout (byte 20 = 0x80-0xBF)
    pub video_layout: [u64; VIDEO_LAYOUT_SLOTS],
    /// bit `b - 0x80` is set once a video packet with byte 20 == `b` (0x80-0xBF) has been seen: the
    /// exact values behind the `rtp20` slot. Only 0x90 has occurred so far; any other bit is news.
    pub video_rtp20_mask: u64,
    /// optional on-disk capture (pcap / debug CSV); all zero when off
    pub pcap_pkts: u64,
    pub pcap_bytes: u64,
    pub pcap_files: u64,
    pub pcap_drop_pool: u64,
    pub pcap_drop_queue: u64,
    pub pcap_drop_limit: u64,
    pub csv_rows: u64,
    pub csv_bytes: u64,
    pub csv_files: u64,
    pub csv_drop_limit: u64,
    pub file_io_errors: u64,
    /// gauge: 1 once the total-size limit stopped the on-disk capture
    pub capture_limit_tripped: u64,
    /// bytes written to capture files so far (pcap + csv)
    pub capture_disk_bytes: u64,
    /// RTP stream tracking (`metrics::RtpHub`)
    pub rtp_streams_active: u64,
    pub rtp_streams_rejected: u64,
    pub rtp_qualified: u64,
    pub rtp_failed_qual: u64,
    pub rtp_probation_skipped: u64,
    pub sfu_flows_active: u64,
    pub hub_bins_dropped: u64,
    /// per-core `pkts_in`, to see RSS imbalance
    pub per_core_in: Vec<u64>,
    pub per_core_dups: Vec<u64>,
}

/// Messages to the exporter thread.
#[derive(Debug)]
pub enum ExportMsg {
    Bin(BinMetrics),
    Rtp(RtpBin),
    Sfu(SfuBin),
    Health(Box<HealthSnapshot>),
    /// flush everything and exit
    Shutdown,
}

/// A per-packet record for the optional debug CSV (`--packet-csv`).
#[derive(Clone, Copy, Debug)]
pub struct PacketDump {
    pub t_us: u64,
    pub src: Addr,
    pub dst: Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub udp_len: u16,
    pub ttl: u8,
    pub ip_id: u16,
    pub class: u8,
    pub dir: u8,
    pub dup: bool,
    /// dense index of the RX core that handled this copy (CSV column `core`)
    pub core: u8,
    pub has_sfu: bool,
    pub media_type_byte: u8,
    pub sfu_seq: u16,
    pub media_seq: u16,
    pub media_ts: u32,
    /// -1 when not present
    pub frame_seq: i32,
    pub frame_pkt_count: i16,
    /// Inner RTP/RTCP header at the type's documented offset:
    /// 0 = not applicable (no RTP in this type, or payload too short),
    /// 1 = found, version bits OK, 2 = found, version bits wrong (offset suspect).
    /// The fields below are filled for 1 and 2 (see `headers::RtpFields`).
    pub rtp_state: u8,
    pub rtp_ssrc: u32,
    pub rtp_seq: u16,
    pub rtp_ts: u32,
    pub rtp_pt: u8,
    pub rtp_marker: bool,
    /// Media-header byte 20 (the video layout selector) and byte 7 (the type-13 sub-type),
    /// -1 when the payload is too short to hold them. Added in p7b so the debug CSV carries
    /// what the layout and gate rules decide on (and `tools/verify_metrics.py` can redo them).
    pub media_b20: i16,
    pub media_b7: i16,
}
