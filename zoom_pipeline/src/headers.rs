//! Zoom's proprietary UDP header — parsing logic.
//!
//! Source of truth, in order of precedence:
//!   1. "Zoom unexplained packets: Type 21 / Type 13 / RTP offsets, Oct 2026"
//!      (`deck2.pdf`, the p7b input) — a closer look at the three things the
//!      first re-validation left open: Type 21 (probe padding + control),
//!      the non-RTP half of Type 13 (probe padding in a Type-13 envelope,
//!      plus control) and the video RTP offset (three layouts, selected by
//!      media byte 20). Every claim there carries a CONFIRMED / INFERENCE /
//!      GUESS label; comments below repeat the label next to the claim.
//!   2. "Zoom header-format re-validation, Sept 2026" (`deck.pdf`) — a
//!      2026 re-capture (9 scenarios x 2 devices, ~990K packets) that
//!      independently re-derived every field against the IMC'22 paper's
//!      own artifact and scored each claim Holds / Refined / Does NOT hold.
//!   3. Michel, Sengupta, Kim, Netravali, Rexford, "Enabling Passive
//!      Measurement of Zoom Performance in Production Networks", IMC'22
//!      (`3517745.3561414.pdf`) — the original reverse-engineering.
//!
//! Where they disagree, this file follows the newer one and says so in a
//! comment, because that's the one checked against traffic this project
//! will actually see. Re-check periodically: the format is undocumented and
//! proprietary, so it can (and did, twice already: the +28 and the +20 video
//! layouts) drift.
//!
//! ## Wire layout
//!
//! Two headers stack before the real RTP/RTCP packet, on every Zoom UDP
//! payload:
//!
//! ```text
//! [ SFU Encapsulation (8B, server-relayed only) ] [ Media Encapsulation (variable) ] [ RTP / RTCP ]
//! ```
//!
//! - Server-relayed traffic: SFU Encapsulation, then Media Encapsulation.
//! - P2P traffic: Media Encapsulation directly (no SFU header) — per the
//!   2026 re-validation this path was never observed in 18 captures (see
//!   `groundtruths/zoom/`), so treat it as unverified/theoretical for now
//!   rather than dead code to delete outright.
//!
//! Both headers open with a 1-byte Type; the inner one also fixes where
//! the real RTP/RTCP header begins, via a type-dependent byte offset.

/// SFU Encapsulation is a fixed 8 bytes.
pub const SFU_HEADER_LEN: usize = 8;

/// SFU byte 0 == this value means "Media Encapsulation follows".
/// Re-validation: holds for 96.44% of server-relayed packets (n=900,144),
/// down slightly from the paper's 98.4% — stable enough to gate on.
pub const SFU_TYPE_MEDIA_FOLLOWS: u8 = 0x05;

/// SFU byte 7 ("Direction") bit meaning "packet is FROM the SFU"
/// (downlink). The paper claimed this byte is strictly 0x00 (to SFU) or
/// 0x04 (from SFU). Re-validation found dir==0 (49.4%) and dir==4 (46.4%)
/// cover 95.9% together, but dir==1 (2.1%) and dir==5 (2.1%) also appear,
/// and 5 == 4 | 1. That means byte 7 is a small **bitmask**, not a binary
/// enum — the 0x01 bit's meaning is unidentified. Decision: test this bit
/// with `&`, not `==`, so an unidentified extra flag doesn't misclassify
/// direction.
pub const SFU_DIR_FROM_SFU_BIT: u8 = 0x04;

/// Parsed SFU Encapsulation header (outer, server-relayed only).
#[derive(Debug, Clone, Copy)]
pub struct SfuHeader {
    pub raw_type: u8,
    /// Outer packet sequence number (bytes 1-2). Endianness not
    /// independently re-verified in the 2026 pass — treated as
    /// big-endian per the paper's dissector; revisit if sequence deltas
    /// look wrong on real traffic.
    pub sequence: u16,
    /// Byte 7, unmodified — use `from_sfu()` rather than comparing this
    /// directly, since it's a bitmask (see `SFU_DIR_FROM_SFU_BIT`).
    pub direction_raw: u8,
}

impl SfuHeader {
    /// `true` if this packet is server -> client (downlink).
    pub fn from_sfu(&self) -> bool {
        self.direction_raw & SFU_DIR_FROM_SFU_BIT != 0
    }
}

/// Parse an 8-byte SFU Encapsulation header. Returns `None` if `buf` is
/// too short or byte 0 isn't the "Media Encapsulation follows" type —
/// callers should fall back to treating `buf` as starting directly with
/// a Media Encapsulation header (the P2P layout) in that case.
pub fn parse_sfu_header(buf: &[u8]) -> Option<SfuHeader> {
    if buf.len() < SFU_HEADER_LEN {
        return None;
    }
    let raw_type = buf[0];
    if raw_type != SFU_TYPE_MEDIA_FOLLOWS {
        return None;
    }
    Some(SfuHeader {
        raw_type,
        sequence: u16::from_be_bytes([buf[1], buf[2]]),
        direction_raw: buf[7],
    })
}

/// Media Encapsulation Type byte (byte 0) values seen in the 2026
/// re-validation, with each one's share of inner-typed traffic and
/// whether the 2022 paper documented it. `n` is unlabeled below where
/// the deck didn't give an exact reproducible figure.
///
/// | Type | Share (2026) | In paper? |
/// |------|-------------|-----------|
/// | 16 (Video)          | 30.34% | yes |
/// | 21 (unknown)         | 21.13% | NO — new |
/// | 30 (Screen Share)    | 17.87% | no (paper's "P2P" label is wrong — see below) |
/// | 13 (Screen Share)    | 13.25% | yes |
/// | 15 (Audio)           | 8.17%  | yes |
/// | 10 / 7 (unknown)     | 4.22% / 4.13% | no |
/// | 32 (unknown)         | 0.42%  | no |
/// | 34 / 33 (RTCP)       | 0.27% / 0.09% | yes |
/// | 35 / 12 / 1 (unknown)| <0.1% each | no |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    /// Type 16 — RTP video. PT 98 ("main") + PT 110 ("FEC") in both eras;
    /// internal main/FEC split (89.98% / 10.02%) matches the paper's
    /// 91.0% / 9.0% closely enough that Table 3's video verdict is
    /// "Holds" outright — safe to key "is video on" off this type alone.
    Video,
    /// Type 15 — RTP audio. **Payload-type numbers changed**: the paper's
    /// PT 112 ("speaking", 22%) and PT 99 ("silent", 2.6%) are entirely
    /// absent in 2026; PT 116 (71.34%, new) and PT 113 (28.66%, was rare/
    /// mobile-only in the paper) now cover it. Don't hardcode PT112/99 as
    /// "the" audio payload types — if a payload-type check is added
    /// later, source it from a fresh capture, not the paper's Table 3.
    Audio,
    /// Type 13 — RTP screen share, server path. PT 99 "main" = 99.99%,
    /// matching the paper. New in 2026: an FEC substream on PT 110
    /// (3.84%) that the paper never lists for screen share — treat FEC
    /// as expected on this type, not an anomaly.
    ///
    /// **Only part of type 13 is RTP (p7b).** Media byte 7 (the "sub-type")
    /// says which: 0x1e = RTP at +27 (zoom.lua's own gate), 0x15 = a Type-21
    /// probe packet wrapped in a Type-13 envelope, anything else = short
    /// control messages. Pooled over the 18 lab captures (deck2, T13-3,
    /// CONFIRMED): 61.5 % RTP, 26.4 % probe padding, 12.1 % other by packets
    /// (64.2 / 28.3 / 7.5 % by bytes). See `Type13Kind` and `type13_kind`.
    ScreenShareServer,
    /// Type 30 (0x1e) — the paper's own code labels this
    /// `P2P_SCREEN_SHARE_TYPE`. That label does not hold: in the 2026
    /// captures every Type-30 packet's IP pair was
    /// `10.184.0.181 <-> 144.195.28.40`, and .40 is inside Zoom's
    /// published server subnets, not a peer. Type 30 tracks with
    /// screen-share-with-"optimize for video clip"-enabled instead,
    /// independent of P2P/SFU routing. Payload types match Type 13
    /// (PT 99 main 96.16%, PT 110 FEC 3.84%), so it's grouped as a
    /// screen-share variant here rather than its own capture_logic path.
    ScreenShareOptimized,
    /// Types 34 (SR+SDES) / 33 (SR) — RTCP. Holds: sender reports only,
    /// receiver reports are 0.055% noise (structural check, see below).
    RtcpSenderReport,
    /// Type 21 — 21.1% of inner-typed traffic in the 18 lab captures (3 % on
    /// the campus link). The paper's own Lua dissector flags it "unclear what
    /// this type is"; deck2 (Oct 2026) explained most of it:
    ///
    /// * **probe padding, 94.0 %** (172,395 of 183,410 packets): a 36-byte
    ///   header (type 0x15, sub-type byte 0x33 at media byte 9, a per-flow
    ///   packet counter at 13-14, a millisecond clock at 15-18, `0x03e8` at
    ///   22-23) followed by 1000 identical filler bytes, payload 1036 B.
    ///   CONFIRMED that it is padding (0.33 bits/byte, not encrypted);
    ///   "used for bandwidth probing" is an INFERENCE. It is episodic, not
    ///   always on: a set-up burst at the start of every flow, then a flood
    ///   (~1.5 Mb/s) during an "optimised for video" screen share.
    /// * **control reports, 5.8 %** (sub-type 0, every ~0.3 s while video or
    ///   audio is live; they carry the peer's clock). Purpose = "RTT / clock
    ///   sync" INFERENCE, bodies not decoded.
    /// * attribute messages (sub-type 0x35, 0.2 %) and sub-types 2 and 3
    ///   (0.06 %): not decoded.
    ///
    /// It is NOT RTP (deck2 T21-3/T21-4 REFUTED the RTCP and RTP readings), so
    /// there is no RTP offset and it can never be media. p7a's demo fixture and
    /// a doc line that called it "phone clients' main traffic" were wrong.
    ///
    /// **p7b does not split Type 21 by sub-type** (decision of 2026-10-31: the
    /// data for sub-type 0x33 is solid, but that control reports sit at the
    /// same byte is only read from deck2's table). The map above is recorded
    /// here so a later step can add `type21_probe` / `type21_ctrl` cheaply.
    ///
    /// Decision that matters for capture_logic: **never treat Type-21
    /// presence as a "media is active" signal** — control reports follow
    /// live media, but the probe flows do not, and neither says "someone is
    /// talking". Any classifier keying off "is *any* inner-typed traffic
    /// present" instead of the specific media types above would read "always
    /// on" and be useless.
    Unknown21,
    /// Type 10 — small (~70B), fixed-size, plausibly a keepalive.
    /// Unexplained in the paper. Not investigated further — out of scope
    /// for this pass, same as the rest of `Other`.
    Keepalive10,
    /// Every other type byte seen (7, 12, 32, 35, 1, ...) — together
    /// ~9% of inner-typed traffic, unexplained in the paper and mostly still
    /// unexplained after the 2026 re-validation. (Type 7 is the exception that
    /// is partly understood: its packets sit inside the sequence gaps of audio
    /// streams, i.e. audio in another header layout; its offsets are not decoded
    /// yet, roadmap Step 4.) Carries the raw byte for logging/curiosity,
    /// but nothing downstream should branch on a specific value here
    /// without first confirming it against a fresh capture.
    Other(u8),
}

impl MediaType {
    pub fn from_type_byte(b: u8) -> Self {
        match b {
            16 => MediaType::Video,
            15 => MediaType::Audio,
            13 => MediaType::ScreenShareServer,
            30 => MediaType::ScreenShareOptimized,
            34 | 33 => MediaType::RtcpSenderReport,
            21 => MediaType::Unknown21,
            10 => MediaType::Keepalive10,
            other => MediaType::Other(other),
        }
    }

    /// `true` for the media types that should count toward "is this
    /// meeting doing audio/video/screenshare right now" — deliberately
    /// excludes `Unknown21`, `Keepalive10`, `RtcpSenderReport`, and
    /// `Other`, per the reasoning on `Unknown21` above.
    pub fn is_active_media_signal(&self) -> bool {
        matches!(
            self,
            MediaType::Video
                | MediaType::Audio
                | MediaType::ScreenShareServer
                | MediaType::ScreenShareOptimized
        )
    }

    /// Offset, in bytes from the *start of the Media Encapsulation
    /// header*, where the real RTP/RTCP header begins — Fig. 7 / Table 1
    /// of the paper, re-confirmed in the 2026 pass except where noted.
    ///
    /// Returns `RtpOffset::None` for types that aren't RTP/RTCP at all
    /// (Unknown21, Keepalive10, Other) so callers don't accidentally
    /// parse RTP out of an opaque channel.
    ///
    /// Video is the one type with THREE layouts (+24 and +28 since p7a,
    /// +20 since p7b): this returns the normal one (+24). A short burst of
    /// packets inside a video stream carries media byte 20 = 0x0a and has its
    /// RTP header at +28; a second video stream in one downlink flow has
    /// byte 20 = 0x90 and RTP at +20. `parse_rtp` picks the offset per packet
    /// with `video_layout()`.
    ///
    /// Type 13 is the one type where only SOME packets are RTP: the +27 below
    /// applies only when media byte 7 == 0x1e (see `type13_kind`; `parse_rtp`
    /// enforces it).
    pub fn rtp_offset(&self) -> RtpOffset {
        match self {
            MediaType::Video => RtpOffset::Confirmed(VIDEO_RTP_OFFSET_NORMAL),
            MediaType::Audio => RtpOffset::Confirmed(19),
            MediaType::ScreenShareServer => RtpOffset::Confirmed(27),
            // p7a: +20, confirmed on the 2026-10 campus captures. In p6 this
            // was a guess (+27, "reuse Type 13's offset"); it is wrong.
            // Evidence: the ground truth of those captures; the Wireshark
            // Zoom dissector (zoom.lua, type 30: RTP at media byte 20); and
            // 155,173 of 155,182 parseable type-30 packets (99.9942 %) have RTP
            // version 2 at +20. (So the CSV's frame_seq / frame_pkt_count cells of
            // a type-30 row are RTP header bytes 1..3, not frame counters.)
            MediaType::ScreenShareOptimized => RtpOffset::Confirmed(20),
            MediaType::RtcpSenderReport => RtpOffset::Confirmed(16),
            MediaType::Unknown21 | MediaType::Keepalive10 | MediaType::Other(_) => RtpOffset::None,
        }
    }
}

/// How much to trust a `MediaType::rtp_offset()` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtpOffset {
    /// Directly re-validated against 2026 traffic.
    Confirmed(usize),
    /// Best-effort, not independently confirmed — see the type's doc
    /// comment for why. Fine to try, but don't assert on the result.
    Unconfirmed(usize),
    /// This type isn't RTP/RTCP; there's nothing to offset into.
    None,
}

impl RtpOffset {
    pub fn value(&self) -> Option<usize> {
        match self {
            RtpOffset::Confirmed(n) | RtpOffset::Unconfirmed(n) => Some(*n),
            RtpOffset::None => None,
        }
    }
}

/// Media Encapsulation header (inner; present on both P2P and
/// server-relayed traffic). Only the fields this project currently uses
/// are pulled out — the full byte range up to `rtp_offset()` may contain
/// more, per the paper.
#[derive(Debug, Clone, Copy)]
pub struct MediaHeader {
    /// Byte 0, unparsed — kept alongside `media_type` so callers (e.g.
    /// the CSV writer) can log/inspect a raw value the `Other(u8)`
    /// variant would otherwise discard the meaning of.
    pub raw_type: u8,
    pub media_type: MediaType,
    /// Inner sequence number, bytes 9-10.
    pub sequence: u16,
    /// Media sampling timestamp, bytes 11-14.
    pub timestamp: u32,
    /// Frame sequence number, bytes 21-22 — video only (`None`
    /// otherwise; also `None` if the buffer is too short to contain it,
    /// which is expected for audio/RTCP where the header is shorter).
    ///
    /// p7b: this is read from the bytes whatever the layout, so it is a real
    /// frame counter only in the 0x02 and 0x0a video layouts. In the rtp20
    /// layout (media byte 20 = 0x90) and in type 30, bytes 20..23 are the
    /// first bytes of the RTP header and this value is just RTP bytes 1-2
    /// (marker/payload type, sequence high byte). No metric uses it; the CSV
    /// writes it as it is (see csvdump.rs).
    pub frame_seq: Option<u16>,
    /// Packets in this frame, byte 23 — video only, same caveats (meaningless
    /// in the rtp20 layout and in type 30: it is RTP byte 3 there).
    pub frame_pkt_count: Option<u8>,
}

/// Minimum length to safely read the fields this project uses (through
/// byte 14, the timestamp). The video-only fields at 21-23 are read
/// opportunistically and left `None` if the buffer doesn't reach them.
const MEDIA_HEADER_MIN_LEN: usize = 15;

/// Parse a Media Encapsulation header from `buf`, which must start at
/// the Media Encapsulation Type byte (i.e., already past the SFU header
/// if one was present).
pub fn parse_media_header(buf: &[u8]) -> Option<MediaHeader> {
    if buf.len() < MEDIA_HEADER_MIN_LEN {
        return None;
    }
    let raw_type = buf[0];
    let media_type = MediaType::from_type_byte(raw_type);
    let sequence = u16::from_be_bytes([buf[9], buf[10]]);
    let timestamp = u32::from_be_bytes([buf[11], buf[12], buf[13], buf[14]]);

    let frame_seq = if buf.len() >= 23 {
        Some(u16::from_be_bytes([buf[21], buf[22]]))
    } else {
        None
    };
    let frame_pkt_count = if buf.len() >= 24 { Some(buf[23]) } else { None };

    Some(MediaHeader {
        raw_type,
        media_type,
        sequence,
        timestamp,
        frame_seq,
        frame_pkt_count,
    })
}

/// Given `buf` = the full UDP payload, unwrap the SFU header (if
/// present) and locate the Media Encapsulation header. Returns
/// `(media_header, sfu_header, remaining_after_media_header)` where
/// `remaining_after_media_header` starts at the Media Encapsulation
/// Type byte — callers use `media_header.media_type.rtp_offset()` from
/// there to find RTP/RTCP.
pub fn parse_zoom_headers(buf: &[u8]) -> Option<(MediaHeader, Option<SfuHeader>, &[u8])> {
    if let Some(sfu) = parse_sfu_header(buf) {
        let rest = &buf[SFU_HEADER_LEN..];
        let media = parse_media_header(rest)?;
        Some((media, Some(sfu), rest))
    } else {
        // No SFU header recognized — either P2P traffic (per the 2026
        // re-validation, not observed in 18 captures, so treat this
        // branch as unverified) or `buf` isn't Zoom traffic at all.
        let media = parse_media_header(buf)?;
        Some((media, None, buf))
    }
}

/// Loose sanity check that `bytes`, read as an RTP header, has version 2
/// (the constant part of RFC 3550's first byte: top two bits == `10`).
/// Re-validation: holds for 99.72% of packets at a confirmed RTP offset;
/// the remaining ~0.3% is attributed to the offset heuristic locking
/// onto the wrong spot, not real protocol violations. Treat a `false`
/// here as "this offset was probably wrong", not "drop the packet" —
/// counting mismatches is more useful than filtering on them silently.
pub fn looks_like_rtp_version_2(bytes: &[u8]) -> bool {
    bytes.first().map(|b| (b >> 6) & 0b11 == 2).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Inner RTP / RTCP header (Stage 1 of the metrics work)
// ---------------------------------------------------------------------------

/// Number of per-type slots used by the RTP self-check counters:
/// 0 = type 16 video, 1 = type 15 audio, 2 = type 13 screen share,
/// 3 = type 30 screen share (RTP at +20; kept as its own counter because it is
/// a different stream family from type 13), 4 = types 33/34 RTCP.
///
/// p7b: the self-check only sees packets that CLAIM to be RTP. For type 13 that
/// means media byte 7 == 0x1e (see `Type13Kind`), so the screen13 pass rate is a
/// real check of the +27 offset again (expect >= 99.9 %, deck2: 99.99 %) instead
/// of the ~34 % mix it was in p7a. The p6/p7a `RTP_SLOT_MIXED` exemption is gone.
/// `screen30` was already strict: with the +20 offset 99.994 % of its packets pass.
pub const RTP_SLOTS: usize = 5;
pub const RTP_SLOT_NAMES: [&str; RTP_SLOTS] = ["video", "audio", "screen13", "screen30", "rtcp"];

// ---------------------------------------------------------------------------
// Type 13: only the packets whose media byte 7 is 0x1e are RTP (p7b)
// ---------------------------------------------------------------------------

/// Media-header byte (type byte = 0) that tells the kinds of type-13 packet
/// apart. deck2 calls it "inner byte 7" or the "sub-type byte"; zoom.lua hands
/// a type-13 packet to its RTP dissector only when it is 0x1e.
pub const T13_SUBTYPE_BYTE: usize = 7;
/// Sub-type of type-13 packets that carry screen-share RTP (at +27).
pub const T13_SUBTYPE_RTP: u8 = 0x1e;
/// Sub-type of type-13 packets that are a Type-21 probe packet inside a
/// Type-13 envelope (0x15 = 21, the Type-21 marker).
pub const T13_SUBTYPE_PROBE: u8 = 0x15;

/// What a type-13 packet is, decided from media byte 7 alone.
///
/// Why this exists: p6 and p7a read an RTP header at +27 from EVERY type-13
/// packet and left the sorting to the stream qualification in the hub. That
/// worked for the numbers (a probe never qualifies as a stream) but had three
/// costs. (1) The RTP self-check was meaningless for screen13: on the s3 two-PC
/// run only ~34 % of type-13 packets passed the version-2 test (a 2-bit test
/// also passes 25 % of random bytes), so p6 had to exempt that slot from the
/// alarm (`RTP_SLOT_MIXED`). (2) Random bytes passing the test one time in four
/// created short-lived probation entries in the hub. (3) Everything that was
/// not qualified RTP landed in one bucket, `unq_screen`, so "padding" looked
/// like "unqualified screen share".
///
/// Evidence (deck2, "Type 13", all CONFIRMED unless marked):
/// * T13-1: the 0x1e packets are screen-share RTP (99.2-100 % inside the share
///   windows +-3 s, PT 99 in 99.99 %, 90 kHz clock).
/// * T13-3: the non-RTP packets are mostly Type-21 probe padding in a Type-13
///   envelope (30,383 packets end in 1000 identical bytes; 0x15 at byte 7 in
///   25,839 uplink packets; `03 e8` at payload byte 37 in 1,997 of 2,000
///   sampled). That is 68.6 % of non-RTP packets and 79 % of their bytes.
///   Frame size 1085 B = 1078 B Type-21 probe + 7 B envelope.
/// * T13-4 (INFERENCE, not decoded): the remaining 31.4 % are small control
///   messages (median 713 B; 101-244 B outside a share).
///
/// Known gap (OPEN, not tested on real packets): deck2 slide 41 annotates the
/// probe marker as sitting at byte 7 on the uplink but at byte 15 on the
/// downlink (an extra 8-byte prefix). The deck counts 30,383 padding packets,
/// 96 % of them uplink, but "0x15 at inner byte 7" in 25,839 uplink packets:
/// so between about 4 % (the downlink share alone) and about 15 % (30,383 -
/// 25,839, if everything without 0x15 at byte 7 is padding too) of the padding
/// may be read as `Control` by this function. The deck does not say which; the
/// "type-13 sub-type census" of `tools/probe_unknown_types.py` counts it
/// directly (control-filed packets with 0x15 at byte 15, and with the padding
/// signature `03 e8` at payload byte 37 / 45). If the evening pcaps show such
/// packets, extend the rule here; nothing else needs to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type13Kind {
    /// byte 7 == 0x1e: RTP screen share at +27
    Rtp,
    /// byte 7 == 0x15: Type-21 probe padding in a Type-13 envelope
    Probe,
    /// every other byte-7 value: control messages (and, see above, any
    /// probe whose marker is not at byte 7)
    Control,
}

/// Classify a type-13 packet. `media_rest` starts at the Media Encapsulation
/// type byte. (A buffer too short to hold byte 7 cannot reach this point:
/// `parse_media_header` needs 15 bytes; it is classed `Control` for safety.)
#[inline]
pub fn type13_kind(media_rest: &[u8]) -> Type13Kind {
    match media_rest.get(T13_SUBTYPE_BYTE) {
        Some(&T13_SUBTYPE_RTP) => Type13Kind::Rtp,
        Some(&T13_SUBTYPE_PROBE) => Type13Kind::Probe,
        _ => Type13Kind::Control,
    }
}

/// Map a Media Encapsulation type byte to its RTP self-check slot.
#[inline]
pub fn rtp_slot(type_byte: u8) -> Option<usize> {
    match type_byte {
        16 => Some(0),
        15 => Some(1),
        13 => Some(2),
        30 => Some(3),
        33 | 34 => Some(4),
        _ => None,
    }
}

/// Fixed RTP header length (RFC 3550 §5.1), without CSRC list or extension.
const RTP_FIXED_LEN: usize = 12;
/// RTCP: V/P/RC, PT, length (2 B), SSRC (4 B).
const RTCP_COMMON_LEN: usize = 8;

/// Whether the bytes found at the documented offset are an RTP or an RTCP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtpKind {
    Rtp,
    Rtcp,
}

/// What `parse_rtp` read at the type's documented RTP offset.
///
/// `version_ok == false` does NOT mean "drop the packet": it means "the offset
/// is probably wrong for this packet". The fields are still filled in (as if
/// the bytes were a header) so a validation run can see *how* it is wrong
/// (e.g. a stable SSRC at the wrong version bits points at an off-by-one
/// offset). Counting mismatches is the self-check; filtering would hide it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpFields {
    pub kind: RtpKind,
    /// RTP: top two bits of byte 0 == 2. RTCP: the same plus PT in 200..=207.
    pub version_ok: bool,
    /// RTP marker bit (always false for RTCP)
    pub marker: bool,
    /// RTP: 7-bit payload type (98 video, 110 FEC, ...). RTCP: the full PT byte (200 = SR).
    pub payload_type: u8,
    /// RTP sequence number (0 for RTCP)
    pub seq: u16,
    /// RTP timestamp (0 for RTCP)
    pub timestamp: u32,
    /// RTP: bytes 8-11. RTCP: bytes 4-7 (the sender SSRC).
    pub ssrc: u32,
}

// ---------------------------------------------------------------------------
// Type 16 (video) has three layouts (+24 and +28 since p7a, +20 since p7b)
// ---------------------------------------------------------------------------

/// Media-header byte that tells the video layouts apart.
pub const VIDEO_LAYOUT_BYTE: usize = 20;
/// Byte 20 of the normal video layout (261,875 of 263,375 type-16 packets, 99.43 %).
pub const VIDEO_LAYOUT_NORMAL: u8 = 0x02;
/// Byte 20 of the burst layout (1,500 packets, 0.57 %): the media header is 4 bytes longer.
pub const VIDEO_LAYOUT_BURST: u8 = 0x0a;
/// RTP offset of the normal video layout.
pub const VIDEO_RTP_OFFSET_NORMAL: usize = 24;
/// RTP offset of the burst layout.
pub const VIDEO_RTP_OFFSET_BURST: usize = 28;
/// RTP offset of the third layout (p7b): byte 20 IS the first RTP byte.
pub const VIDEO_RTP_OFFSET_RTP20: usize = 20;
/// Counter slots for `video_layout`: 0 = byte 20 is 0x02, 1 = 0x0a, 2 = RTP
/// starts at byte 20 (top two bits of byte 20 are `10`, e.g. 0x90), 3 = anything else.
pub const VIDEO_LAYOUT_SLOTS: usize = 4;
pub const VIDEO_LAYOUT_NAMES: [&str; VIDEO_LAYOUT_SLOTS] = ["02", "0a", "rtp20", "other"];
/// Slot numbers, so callers do not hard-code 2 and 3.
pub const VLAYOUT_SLOT_RTP20: usize = 2;
pub const VLAYOUT_SLOT_OTHER: usize = 3;

/// Which layout a type-16 packet has, read from media byte 20.
///
/// Why this exists: on the 2026-10 campus captures byte 20 was tabulated
/// against the SSRC-validated true RTP offset over all 263,375 video packets of
/// 18 captures: 0x02 -> RTP at +24 in 100.00 % of 261,875 packets (never +28),
/// 0x0a -> RTP at +28 in 100.00 % of 1,500 packets (never +24). The 0x0a packets
/// come in two bursts of ~9 s inside one stream (same SSRC before, during and
/// after, starting ~13 s after the stream's first packet). Read at +24 they fail
/// the version-2 test, are booked as `unq_video`, and the stream then sees a
/// forward RTP-seq jump that p6 counts as loss (an empty bin, a false loss
/// spike, a stall, false jitter). The Wireshark Zoom dissector (zoom.lua) tests
/// the same byte (`== 0x02`) but puts the other layout's RTP header at +20; the
/// measured offset for 0x0a is +28.
///
/// **Third layout (p7b, deck2 Part G).** The 5 h 21 min campus run of
/// 2026-10-15 printed `video_layout other = 185,021` and `rtp_v2[video] 98.6 %`.
/// All of it traced to ONE downlink flow (server -> client c-583a70, 8,917-15,212 s
/// into the run) whose second video stream has byte 20 = 0x90. That byte is the
/// first RTP byte (0x90 = version 2, extension bit set, no CSRC): RTP starts at
/// +20 and the 3-field frame block (frame seq at 21-22, packet count at 23)
/// is absent. Over the 143,157 such packets in the pcaps (1.56 % of the video packets there):
/// RTP valid at +20 in 100 %, at the two older offsets in 0 % (SSRC check)
/// CONFIRMED. Read at +24 (p7a) the seq / timestamp / SSRC are garbage, 29.8 %
/// still pass the version test by accident (timestamp byte 0xa2 starts with bits
/// `10`), and c-583a70's video RTP-OK came out at 91.33 %.
///
/// The rule is `byte 20 >> 6 == 2` (0x80-0xBF), not `== 0x90`: a stream without
/// the header extension would start with 0x80, and the two older values have top
/// bits `00`, so nothing collides. **Only 0x90 has ever been seen**; that the
/// whole 0x80-0xBF range means "+20" is an INFERENCE (deck2 G-5: it matches the
/// Wireshark dissector's convention). `capture_health.video_rtp20_bytes` lists
/// the exact byte values that occurred so a live run can confirm or refute it.
///
/// **TO BE CHECKED (C2, deliberately not done in p7b).** The 0x90 packets are a
/// SECOND video SSRC inside the same UDP flow (SSRC 0x01003C02 next to 0x01002801
/// for the 0x02 packets; median 26 pkt/s next to 127; present in 93 % of the
/// flow's seconds; never alone). p7b parses it correctly and, like every other
/// qualified video stream, includes it in the video volume, `video_streams_active`
/// and the per-client means (`fps_*`, `jitter_ms_*`, `frame_gap_std_ms_*`,
/// `degraded_*`). Whether such a stream is a simulcast layer, a thumbnail or
/// just another tile, and so whether it should count in those means, is a GUESS
/// (deck2: "not examined"). See README "The aux / main question".
///
/// `Other(b)` is a layout we have never seen: it is read at +24 (the safe default,
/// because that is what p6 did) and counted in `capture_health.video_layout_other`
/// so a fourth layout shows up in the first status line instead of in the metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoLayout {
    /// byte 20 == 0x02: RTP at +24
    Normal,
    /// byte 20 == 0x0a: RTP at +28
    Burst,
    /// byte 20 has top bits `10` (0x80-0xBF; only 0x90 seen): RTP at +20, no frame fields
    Rtp20(u8),
    /// any other value of byte 20: unseen so far; handled like `Normal`
    Other(u8),
    /// the buffer ends before byte 20 (such a packet cannot hold RTP anyway)
    Short,
}

impl VideoLayout {
    /// RTP header offset (media-header-relative) for this layout.
    #[inline]
    pub fn rtp_offset(self) -> usize {
        match self {
            VideoLayout::Burst => VIDEO_RTP_OFFSET_BURST,
            VideoLayout::Rtp20(_) => VIDEO_RTP_OFFSET_RTP20,
            _ => VIDEO_RTP_OFFSET_NORMAL,
        }
    }
    /// Counter slot (see `VIDEO_LAYOUT_NAMES`); `None` = too short to tell.
    #[inline]
    pub fn slot(self) -> Option<usize> {
        match self {
            VideoLayout::Normal => Some(0),
            VideoLayout::Burst => Some(1),
            VideoLayout::Rtp20(_) => Some(VLAYOUT_SLOT_RTP20),
            VideoLayout::Other(_) => Some(VLAYOUT_SLOT_OTHER),
            VideoLayout::Short => None,
        }
    }
}

/// Classify a type-16 packet. `media_rest` starts at the Media Encapsulation type byte.
#[inline]
pub fn video_layout(media_rest: &[u8]) -> VideoLayout {
    match media_rest.get(VIDEO_LAYOUT_BYTE) {
        Some(&VIDEO_LAYOUT_NORMAL) => VideoLayout::Normal,
        Some(&VIDEO_LAYOUT_BURST) => VideoLayout::Burst,
        Some(&b) if b >> 6 == 2 => VideoLayout::Rtp20(b),
        Some(&b) => VideoLayout::Other(b),
        None => VideoLayout::Short,
    }
}

/// Read the RTP (or RTCP) header that sits `rtp_offset()` bytes after the
/// start of the Media Encapsulation header.
///
/// `media_rest` must start at the Media Encapsulation type byte (the `rest`
/// slice returned by `parse_zoom_headers`, or `payload[SFU_HEADER_LEN..]`).
/// `raw_type` is that type byte. Returns `None` when the type carries no RTP
/// (21, 10, other) or the buffer is too short to hold the header; callers
/// count the short case separately so it is not mistaken for a wrong offset.
///
/// Offsets (video +24, +28 or +20, audio +19, type 13 +27, type 30 +20, RTCP +16)
/// come from the 2026 deck's captures and the 2026-10 campus validation; the
/// version-2 pass-rate counters and `tools/validate_rtp_csv.py` keep checking
/// them. Two things are packet-dependent:
/// * video: media byte 20 selects +24 (0x02), +28 (0x0a) or +20 (0x80-0xBF), see
///   `video_layout`;
/// * type 13: the offset +27 only holds for packets whose media byte 7 is 0x1e.
///   Since p7b this function enforces that: for any other type-13 packet it
///   returns `None` (probe padding and control messages have no RTP header),
///   see `type13_kind`. Callers that must tell "gated out" from "too short" use
///   `type13_kind` themselves; `pipeline::zoom_fields` does.
#[inline]
pub fn parse_rtp(media_rest: &[u8], raw_type: u8) -> Option<RtpFields> {
    let media_type = MediaType::from_type_byte(raw_type);
    let mut off = media_type.rtp_offset().value()?;
    if matches!(media_type, MediaType::Video) {
        off = video_layout(media_rest).rtp_offset();
    }
    // p7b: only a type-13 packet with sub-type 0x1e is RTP (see `Type13Kind`)
    if matches!(media_type, MediaType::ScreenShareServer) && type13_kind(media_rest) != Type13Kind::Rtp {
        return None;
    }
    if matches!(media_type, MediaType::RtcpSenderReport) {
        let h = media_rest.get(off..off + RTCP_COMMON_LEN)?;
        let version_ok = (h[0] >> 6) == 2 && (200..=207).contains(&h[1]);
        return Some(RtpFields {
            kind: RtpKind::Rtcp,
            version_ok,
            marker: false,
            payload_type: h[1],
            seq: 0,
            timestamp: 0,
            ssrc: u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
        });
    }
    let h = media_rest.get(off..off + RTP_FIXED_LEN)?;
    Some(RtpFields {
        kind: RtpKind::Rtp,
        version_ok: looks_like_rtp_version_2(h),
        marker: h[1] & 0x80 != 0,
        payload_type: h[1] & 0x7f,
        seq: u16::from_be_bytes([h[2], h[3]]),
        timestamp: u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
        ssrc: u32::from_be_bytes([h[8], h[9], h[10], h[11]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sfu_and_media(media_type: u8, dir: u8) -> Vec<u8> {
        let mut buf = vec![0u8; SFU_HEADER_LEN + MEDIA_HEADER_MIN_LEN + 16];
        buf[0] = SFU_TYPE_MEDIA_FOLLOWS;
        buf[1] = 0x00;
        buf[2] = 0x2a; // outer seq = 42
        buf[7] = dir;
        buf[SFU_HEADER_LEN] = media_type; // media type byte
        buf
    }

    #[test]
    fn parses_sfu_then_media_video() {
        let buf = make_sfu_and_media(16, 0x05); // dir = from_sfu | unknown bit
        let (media, sfu, _rest) = parse_zoom_headers(&buf).expect("should parse");
        let sfu = sfu.expect("SFU header should be present");
        assert_eq!(sfu.sequence, 0x2a);
        assert!(sfu.from_sfu(), "0x05 has the 0x04 bit set");
        assert_eq!(media.media_type, MediaType::Video);
        assert_eq!(media.media_type.rtp_offset(), RtpOffset::Confirmed(24));
    }

    #[test]
    fn direction_is_a_bitmask_not_an_equality() {
        // dir == 1 alone (no 0x04 bit) must NOT read as "from SFU".
        let buf = make_sfu_and_media(15, 0x01);
        let (_media, sfu, _rest) = parse_zoom_headers(&buf).expect("should parse");
        assert!(!sfu.unwrap().from_sfu());
    }

    #[test]
    fn unknown21_has_no_rtp_offset_and_is_not_an_active_signal() {
        let mt = MediaType::from_type_byte(21);
        assert_eq!(mt.rtp_offset(), RtpOffset::None);
        assert!(!mt.is_active_media_signal());
    }

    #[test]
    fn too_short_buffer_does_not_panic() {
        assert!(parse_zoom_headers(&[0x05, 0x00]).is_none());
    }

    /// Media-header-relative buffer (starts at the type byte) with an RTP
    /// header written at `off`.
    fn media_with_rtp(raw_type: u8, off: usize, ver: u8, pt: u8, marker: bool, seq: u16, ts: u32, ssrc: u32) -> Vec<u8> {
        let mut b = vec![0u8; off + 12 + 40];
        b[0] = raw_type;
        b[off] = ver << 6;
        b[off + 1] = pt | if marker { 0x80 } else { 0 };
        b[off + 2..off + 4].copy_from_slice(&seq.to_be_bytes());
        b[off + 4..off + 8].copy_from_slice(&ts.to_be_bytes());
        b[off + 8..off + 12].copy_from_slice(&ssrc.to_be_bytes());
        b
    }

    #[test]
    fn rtp_is_read_at_each_documented_offset() {
        // (type byte, offset from the media header start, expected slot)
        for (t, off, slot) in [(16u8, 24usize, 0usize), (15, 19, 1), (13, 27, 2), (30, 20, 3)] {
            let mut b = media_with_rtp(t, off, 2, 98, true, 0xfffe, 0x0102_0304, 0xdead_beef);
            if t == 13 {
                b[T13_SUBTYPE_BYTE] = T13_SUBTYPE_RTP; // p7b: type 13 is only RTP with sub-type 0x1e
            }
            let r = parse_rtp(&b, t).unwrap_or_else(|| panic!("type {t}"));
            assert_eq!(r.kind, RtpKind::Rtp);
            assert!(r.version_ok, "type {t}");
            assert!(r.marker);
            assert_eq!((r.payload_type, r.seq, r.timestamp, r.ssrc), (98, 0xfffe, 0x0102_0304, 0xdead_beef), "type {t}");
            assert_eq!(rtp_slot(t), Some(slot));
        }
    }

    // ---- p7a: type 30 sits at +20 (p6 read +27)
    #[test]
    fn type_30_rtp_is_at_plus_20_and_nothing_is_read_at_the_old_plus_27() {
        assert_eq!(MediaType::from_type_byte(30).rtp_offset(), RtpOffset::Confirmed(20));
        // a v2 header at +20 is found (the whole header is read from +20, not from +27)
        let b = media_with_rtp(30, 20, 2, 99, false, 4242, 0x0102_0304, 0x0100_0302);
        let r = parse_rtp(&b, 30).unwrap();
        assert!(r.version_ok);
        assert_eq!((r.payload_type, r.seq, r.timestamp, r.ssrc), (99, 4242, 0x0102_0304, 0x0100_0302));
        // a v2 header ONLY at the old +27 is no longer accepted: +20 holds zeros
        let b = media_with_rtp(30, 27, 2, 99, false, 1, 1, 0x11);
        assert!(!parse_rtp(&b, 30).unwrap().version_ok);
        // needs 20 + 12 = 32 bytes
        assert!(parse_rtp(&vec![0u8; 31], 30).is_none());
        assert!(parse_rtp(&vec![0u8; 32], 30).is_some());
    }

    // ---- video has three layouts, selected by media byte 20 (two since p7a, the third, rtp20, since p7b)
    fn video_with_layout(layout_byte: u8, off: usize, seq: u16, ssrc: u32) -> Vec<u8> {
        let mut b = media_with_rtp(16, off, 2, 98, false, seq, 90_000, ssrc);
        b[VIDEO_LAYOUT_BYTE] = layout_byte;
        b
    }

    #[test]
    fn video_byte_20_selects_the_rtp_offset() {
        // 0x02 -> +24, and a decoy v2 header at +28 is ignored
        let mut b = video_with_layout(0x02, 24, 100, 0xAAAA_0001);
        b[28] = 0x80;
        b[28 + 2..28 + 4].copy_from_slice(&999u16.to_be_bytes());
        let r = parse_rtp(&b, 16).unwrap();
        assert!(r.version_ok);
        assert_eq!((r.seq, r.ssrc), (100, 0xAAAA_0001));
        assert_eq!(video_layout(&b), VideoLayout::Normal);
        assert_eq!(video_layout(&b).slot(), Some(0));

        // 0x0a -> +28, and a decoy v2 header at +24 is ignored
        let mut b = video_with_layout(0x0a, 28, 200, 0xAAAA_0001);
        b[24] = 0x80;
        b[24 + 2..24 + 4].copy_from_slice(&888u16.to_be_bytes());
        let r = parse_rtp(&b, 16).unwrap();
        assert!(r.version_ok);
        assert_eq!((r.payload_type, r.seq, r.timestamp, r.ssrc), (98, 200, 90_000, 0xAAAA_0001));
        assert_eq!(video_layout(&b), VideoLayout::Burst);
        assert_eq!(video_layout(&b).slot(), Some(1));
        assert_eq!(VideoLayout::Normal.rtp_offset(), 24);
        assert_eq!(VideoLayout::Burst.rtp_offset(), 28);
        assert_eq!(VideoLayout::Rtp20(0x90).rtp_offset(), 20);

        // the burst layout needs 28 + 12 = 40 bytes
        let mut short = vec![0u8; 39];
        short[0] = 16;
        short[VIDEO_LAYOUT_BYTE] = 0x0a;
        assert!(parse_rtp(&short, 16).is_none());
        short.push(0);
        assert!(parse_rtp(&short, 16).is_some());
    }

    #[test]
    fn video_with_an_unseen_byte_20_is_read_like_p6_and_classified_other() {
        // 263,375 real packets had only 0x02 and 0x0a; anything else keeps the p6 behaviour (+24) and is counted
        for v in [0x00u8, 0x01, 0x03, 0x08, 0x12, 0xff] {
            let b = video_with_layout(v, 24, 7, 0x5555);
            assert_eq!(video_layout(&b), VideoLayout::Other(v));
            assert_eq!(video_layout(&b).slot(), Some(VLAYOUT_SLOT_OTHER));
            let r = parse_rtp(&b, 16).unwrap();
            assert!(r.version_ok, "byte 20 = {v:#04x}");
            assert_eq!((r.seq, r.ssrc), (7, 0x5555));
        }
        assert_eq!(video_layout(&[0u8; 20]), VideoLayout::Short); // ends before byte 20
        assert_eq!(video_layout(&[0u8; 20]).slot(), None);
        assert_eq!(video_layout(&[]), VideoLayout::Short);
        assert_eq!(VIDEO_LAYOUT_NAMES, ["02", "0a", "rtp20", "other"]);
        assert_eq!((VLAYOUT_SLOT_RTP20, VLAYOUT_SLOT_OTHER), (2, 3));
    }

    #[test]
    fn byte_20_is_only_a_selector_for_video() {
        // audio and type 13 have other things at media byte 20: parse_rtp must not look at it
        let mut a = media_with_rtp(15, 19, 2, 113, false, 5, 5, 0x77);
        a[VIDEO_LAYOUT_BYTE] = 0x0a; // inside the audio RTP header (byte 1 of it: PT/marker)
        a[19] = 0x80;
        assert_eq!(parse_rtp(&a, 15).unwrap().ssrc, 0x77);
        let mut s = media_with_rtp(13, 27, 2, 99, false, 5, 5, 0x78);
        s[T13_SUBTYPE_BYTE] = T13_SUBTYPE_RTP;
        s[VIDEO_LAYOUT_BYTE] = 0x0a;
        assert_eq!(parse_rtp(&s, 13).unwrap().ssrc, 0x78);
    }

    // ---- p7b C1: the third video layout, selected by the top two bits of byte 20
    /// A type-16 media buffer whose RTP header sits at +20: byte 20 IS the first
    /// RTP byte, so it carries the version bits (0x80 | X/CC bits).
    fn video_rtp20(first_byte: u8, seq: u16, ssrc: u32) -> Vec<u8> {
        let mut b = media_with_rtp(16, 20, 2, 98, false, seq, 90_000, ssrc);
        b[0] = 16; // media_with_rtp wrote the type at byte 0 already; keep it explicit
        b[VIDEO_LAYOUT_BYTE] = first_byte;
        b
    }

    #[test]
    fn video_with_byte_20_0x90_has_its_rtp_header_at_plus_20_not_plus_24() {
        let mut b = video_rtp20(0x90, 4321, 0x0100_3C02);
        // the p7a rule would read its SSRC from +32..+36 (RTP at +24, SSRC at +8): plant a decoy
        // there, just past the real 12-byte header (+20..+32), so the two readings differ
        b[32..36].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        let r = parse_rtp(&b, 16).unwrap();
        assert!(r.version_ok);
        assert_eq!((r.payload_type, r.seq, r.timestamp, r.ssrc), (98, 4321, 90_000, 0x0100_3C02));
        assert_eq!(video_layout(&b), VideoLayout::Rtp20(0x90));
        assert_eq!(video_layout(&b).slot(), Some(VLAYOUT_SLOT_RTP20));
        // the old rule (+24 for everything but 0x0a) reads the planted bytes instead: wrong SSRC
        let old = &b[24..36];
        assert_eq!(u32::from_be_bytes([old[8], old[9], old[10], old[11]]), 0xdead_beef);
        assert_ne!(u32::from_be_bytes([old[8], old[9], old[10], old[11]]), r.ssrc);
        // needs 20 + 12 = 32 bytes
        let mut short = vec![0u8; 31];
        short[0] = 16;
        short[VIDEO_LAYOUT_BYTE] = 0x90;
        assert!(parse_rtp(&short, 16).is_none());
        short.push(0);
        assert!(parse_rtp(&short, 16).is_some());
    }

    #[test]
    fn the_rtp20_range_is_exactly_0x80_to_0xbf() {
        // top bits `10`: 0x80 (no extension) and 0xBF are the two ends of the range
        for v in [0x80u8, 0x90, 0xA0, 0xBF] {
            let b = video_rtp20(v, 10, 0x77);
            assert_eq!(video_layout(&b), VideoLayout::Rtp20(v), "{v:#04x}");
            assert_eq!(parse_rtp(&b, 16).unwrap().ssrc, 0x77, "{v:#04x}");
        }
        // one step outside on each side: not the +20 layout, read at +24 and counted `other`
        for v in [0x7Fu8, 0xC0] {
            let b = video_rtp20(v, 10, 0x77);
            assert_eq!(video_layout(&b), VideoLayout::Other(v), "{v:#04x}");
            assert_eq!(video_layout(&b).slot(), Some(VLAYOUT_SLOT_OTHER));
            assert_eq!(video_layout(&b).rtp_offset(), 24);
        }
        // the two older values still win: 0x02 and 0x0a have top bits `00`
        assert_eq!(video_layout(&video_rtp20(0x02, 1, 1)), VideoLayout::Normal);
        assert_eq!(video_layout(&video_rtp20(0x0a, 1, 1)), VideoLayout::Burst);
    }

    // ---- p7b C3: type 13 is RTP only when media byte 7 is 0x1e
    #[test]
    fn type13_kind_is_decided_by_media_byte_7_alone() {
        let mk = |b7: u8| {
            let mut b = vec![0u8; 40];
            b[0] = 13;
            b[T13_SUBTYPE_BYTE] = b7;
            b
        };
        assert_eq!(type13_kind(&mk(0x1e)), Type13Kind::Rtp);
        assert_eq!(type13_kind(&mk(0x15)), Type13Kind::Probe);
        for v in [0x00u8, 0x1d, 0x1f, 0x14, 0x16, 0xff] {
            assert_eq!(type13_kind(&mk(v)), Type13Kind::Control, "{v:#04x}");
        }
        // a buffer that ends before byte 7 cannot be told: Control (parse_media_header needs 15 bytes, so unreachable live)
        assert_eq!(type13_kind(&[13, 0, 0]), Type13Kind::Control);
        assert_eq!(type13_kind(&[]), Type13Kind::Control);
    }

    #[test]
    fn type13_without_sub_type_0x1e_has_no_rtp_even_if_a_v2_header_sits_at_27() {
        // the 1-in-4 case: random bytes that happen to look like version 2 at +27
        for b7 in [T13_SUBTYPE_PROBE, 0x00, 0x1d, 0xff] {
            let mut b = media_with_rtp(13, 27, 2, 99, false, 5, 5, 0x78);
            b[T13_SUBTYPE_BYTE] = b7;
            assert!(parse_rtp(&b, 13).is_none(), "sub-type {b7:#04x} must not reach the RTP parser");
        }
        // with 0x1e the same bytes are read
        let mut b = media_with_rtp(13, 27, 2, 99, false, 5, 5, 0x78);
        b[T13_SUBTYPE_BYTE] = T13_SUBTYPE_RTP;
        assert_eq!(parse_rtp(&b, 13).unwrap().ssrc, 0x78);
    }

    #[test]
    fn the_sub_type_gate_applies_to_type_13_only() {
        // type 30 has RTP at +20 whatever byte 7 holds; video and audio likewise
        for (t, off) in [(30u8, 20usize), (16, 24), (15, 19)] {
            let mut b = media_with_rtp(t, off, 2, 98, false, 9, 9, 0x99);
            b[T13_SUBTYPE_BYTE] = T13_SUBTYPE_PROBE;
            if t == 16 {
                b[VIDEO_LAYOUT_BYTE] = VIDEO_LAYOUT_NORMAL;
            }
            assert_eq!(parse_rtp(&b, t).map(|r| r.ssrc), Some(0x99), "type {t}");
        }
    }

    #[test]
    fn wrong_version_bits_are_reported_not_hidden() {
        let b = media_with_rtp(16, 24, 1, 98, false, 7, 9, 0x11);
        let r = parse_rtp(&b, 16).unwrap();
        assert!(!r.version_ok);
        // the fields are still filled so a validation run can see how it is wrong
        assert_eq!((r.seq, r.timestamp, r.ssrc), (7, 9, 0x11));
    }

    #[test]
    fn types_without_rtp_and_short_buffers_return_none() {
        for t in [21u8, 10, 7, 32] {
            assert!(parse_rtp(&vec![0u8; 100], t).is_none(), "type {t}");
            assert_eq!(rtp_slot(t), None);
        }
        // video needs off(24) + 12 = 36 bytes; 35 is one too few
        assert!(parse_rtp(&vec![0u8; 35], 16).is_none());
        assert!(parse_rtp(&vec![0u8; 36], 16).is_some());
        assert!(parse_rtp(&[], 16).is_none());
    }

    #[test]
    fn rtcp_sender_report_reads_pt_and_ssrc_from_the_rtcp_layout() {
        for t in [33u8, 34] {
            let mut b = vec![0u8; 16 + 28];
            b[0] = t;
            b[16] = 0x80; // V=2
            b[17] = 200; // SR
            b[20..24].copy_from_slice(&0xcafe_f00du32.to_be_bytes()); // sender SSRC
            let r = parse_rtp(&b, t).unwrap();
            assert_eq!(r.kind, RtpKind::Rtcp);
            assert!(r.version_ok);
            assert_eq!((r.payload_type, r.ssrc, r.seq, r.timestamp, r.marker), (200, 0xcafe_f00d, 0, 0, false));
            assert_eq!(rtp_slot(t), Some(4));
            // an RTP-looking byte pair is not RTCP: PT 98 is outside 200..=207
            b[17] = 98;
            assert!(!parse_rtp(&b, t).unwrap().version_ok);
        }
    }
}
