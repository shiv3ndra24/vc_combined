//! # models/rtp_record.rs
//!
//! **What this file does:**
//! - `RtpRecord` — the structured representation of one captured RTP packet,
//!   derived from the raw Ethernet frame.  Fields mirror the CSV column order
//!   written by `records_thread`.
//! - `parse_rtp_record(data, is_ipv6, ip_start, udp_payload_offset, ts)` —
//!   extracts all RTP + IP + UDP header fields from the raw bytes.  Returns
//!   `None` if the frame is too short to contain a valid RTP fixed header
//!   (12 bytes).
//!
//! This module has no side-effects and no global state — it is pure parsing.

use serde::Serialize;
use std::time::Duration;

/// Which conferencing platform this packet belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Platform {
    Teams,
    Meet,
}

/// All fields captured from a single RTP/UDP/IP frame.
/// `Serialize` is derived so the struct can be turned into JSON or CSV rows
/// without extra code.
#[derive(Clone, Debug, Serialize)]
pub struct RtpRecord {
    pub arrival_epoch_ns: u64, // wall-clock at capture, nanoseconds since UNIX epoch
    pub platform: Platform,
    pub src_ip: String,        // dotted-decimal IPv4 or colon-hex IPv6
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_proto: u8,       // always 17 (UDP) for records produced here
    pub ip_len: u16,        // total IP packet length (header + payload)
    pub udp_len: u16,       // UDP length field (header + payload)
    pub ssrc: u32,          // RTP synchronisation source identifier
    pub rtp_timestamp: u32, // RTP media clock timestamp
    pub seq_num: u16,       // RTP sequence number
    pub payload_type: u8,   // RTP PT (lower 7 bits of byte 1)
    pub marker: bool,       // RTP marker bit (top bit of byte 1)
    /// `dedup::fingerprint` of the frame (5-tuple, UDP length, first 48 payload
    /// bytes). Computed here because only here are the raw bytes at hand; only
    /// with `--dedup fp` (0 otherwise). Not a CSV column.
    #[serde(skip)]
    pub fp: u64,
    /// vc_combined: direction, decided by the gate from the ONE server list.
    /// true = client -> server (uplink), false = server -> client (downlink).
    #[serde(skip)]
    pub uplink: bool,
    /// vc_combined, only with `--pcap`: the first `snaplen` bytes of the frame, written to
    /// the pcap by the records thread AFTER the de-dup verdict (so pcap = kept packets).
    #[serde(skip)]
    pub frame: Option<Box<[u8]>>,
    /// Length of the whole frame on the wire (pcap `orig_len`).
    #[serde(skip)]
    pub frame_len: u32,
}

/// vc_combined: bytes of each frame kept for the pcap (0 = no pcap). Set once at start-up.
static SNAPLEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Turn the pcap copy on (`n` > 0 bytes per frame) or off (0).
pub fn set_snaplen(n: usize) {
    SNAPLEN.store(n, std::sync::atomic::Ordering::Relaxed);
}

pub fn snaplen() -> usize {
    SNAPLEN.load(std::sync::atomic::Ordering::Relaxed)
}

/// Parse a raw Ethernet `data` slice into an `RtpRecord`.
///
/// Caller must have already verified via `quick_precheck` that:
/// - `ip_start` points at a valid IPv4 or IPv6 header
/// - `udp_payload_offset` points at the first byte after the 8-byte UDP header
///
/// Returns `None` if there are fewer than 12 bytes of RTP payload available.
pub fn parse_rtp_record(data: &[u8], gate: &crate::ip_ranges::Gate, ts: Duration) -> Option<RtpRecord> {
    let (platform, is_ipv6, ip_start, udp_payload_offset) = (gate.platform, gate.is_ipv6, gate.ip_start, gate.udp_payload_offset);
    // RTP fixed header is 12 bytes
    if udp_payload_offset + 12 > data.len() {
        return None;
    }

    // ── UDP header fields (8 bytes immediately before the payload) ────────
    let udp_hdr = udp_payload_offset - 8;
    let src_port = u16::from_be_bytes([data[udp_hdr], data[udp_hdr + 1]]);
    let dst_port = u16::from_be_bytes([data[udp_hdr + 2], data[udp_hdr + 3]]);
    let udp_len = u16::from_be_bytes([data[udp_hdr + 4], data[udp_hdr + 5]]);

    // ── IP address strings + total IP length ─────────────────────────────
    let (src_ip, dst_ip, ip_len) = if is_ipv6 {
        let src = std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(&data[ip_start + 8..ip_start + 24]).unwrap(),
        )
        .to_string();
        let dst = std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(&data[ip_start + 24..ip_start + 40]).unwrap(),
        )
        .to_string();
        // IPv6 payload length does not include the 40-byte fixed header
        let payload_len = u16::from_be_bytes([data[ip_start + 4], data[ip_start + 5]]);
        (src, dst, payload_len + 40)
    } else {
        let src = std::net::Ipv4Addr::new(
            data[ip_start + 12],
            data[ip_start + 13],
            data[ip_start + 14],
            data[ip_start + 15],
        )
        .to_string();
        let dst = std::net::Ipv4Addr::new(
            data[ip_start + 16],
            data[ip_start + 17],
            data[ip_start + 18],
            data[ip_start + 19],
        )
        .to_string();
        let len = u16::from_be_bytes([data[ip_start + 2], data[ip_start + 3]]);
        (src, dst, len)
    };

    // ── RTP fixed header (bytes 0-11 of UDP payload) ──────────────────────
    let rtp = &data[udp_payload_offset..];
    let payload_type = rtp[1] & 0x7F; // lower 7 bits
    let marker = (rtp[1] & 0x80) != 0; // top bit
    let seq_num = u16::from_be_bytes([rtp[2], rtp[3]]);
    let rtp_timestamp = u32::from_be_bytes([rtp[4], rtp[5], rtp[6], rtp[7]]);
    let ssrc = u32::from_be_bytes([rtp[8], rtp[9], rtp[10], rtp[11]]);

    // ── Fingerprint for `--dedup fp` ──────────────────────────────────────
    // Raw source + destination address (not the strings above), both ports, the
    // UDP length, and the first 48 bytes of the UDP payload, cut to the UDP length
    // so Ethernet padding after the datagram cannot make two twins differ.
    // No MAC addresses: the two mirror legs have different layer-2 wrappers.
    // Skipped (0) unless `--dedup fp` asked for it: `seq` and `off` pay nothing for it.
    let fp = if crate::dedup::fingerprints_wanted() {
        let addrs: &[u8] = if is_ipv6 {
            &data[ip_start + 8..ip_start + 40]
        } else {
            &data[ip_start + 12..ip_start + 20]
        };
        let payload_len = (udp_len as usize).saturating_sub(8).min(rtp.len());
        crate::dedup::fingerprint(addrs, src_port, dst_port, udp_len, &rtp[..payload_len])
    } else {
        0
    };

    // ── pcap copy (only with --pcap): an allocation of `snaplen` bytes, the price of
    //    writing the pcap after de-dup in the records thread. 128 B by default.
    let snap = snaplen();
    let frame = if snap > 0 { Some(data[..data.len().min(snap)].to_vec().into_boxed_slice()) } else { None };

    Some(RtpRecord {
        arrival_epoch_ns: ts.as_nanos() as u64,
        platform,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        ip_proto: 17,
        ip_len,
        udp_len,
        ssrc,
        rtp_timestamp,
        seq_num,
        payload_type,
        marker,
        fp,
        uplink: !gate.src_is_server,
        frame,
        frame_len: data.len() as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ethernet + IPv4 + UDP + RTP frame; `pad` bytes of Ethernet padding after the datagram.
    fn frame(src_mac_last: u8, seq: u16, pad: &[u8]) -> Vec<u8> {
        let mut rtp = vec![0x80, 98];
        rtp.extend_from_slice(&seq.to_be_bytes());
        rtp.extend_from_slice(&90_000u32.to_be_bytes());
        rtp.extend_from_slice(&0x77890EDCu32.to_be_bytes());
        rtp.extend((0..40u8).map(|i| i.wrapping_mul(7)));
        let udp_len = (8 + rtp.len()) as u16;
        let mut f = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, src_mac_last, 0, 1, 2, 3, 4, 5, 0x08, 0x00];
        let ip_start = f.len();
        f.extend_from_slice(&[0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0]);
        f.extend_from_slice(&[142, 250, 82, 219, 10, 184, 4, 232]);
        let ip_len = (20 + udp_len as usize) as u16;
        f[ip_start + 2..ip_start + 4].copy_from_slice(&ip_len.to_be_bytes());
        f.extend_from_slice(&19305u16.to_be_bytes());
        f.extend_from_slice(&60158u16.to_be_bytes());
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&rtp);
        f.extend_from_slice(pad);
        f
    }

    fn gate() -> crate::ip_ranges::Gate {
        crate::ip_ranges::Gate { platform: Platform::Meet, is_ipv6: false, ip_start: 14, udp_payload_offset: 14 + 20 + 8, src_is_server: true }
    }

    #[test]
    fn direction_comes_from_the_gate() {
        let r = rec(&frame(0x01, 500, &[]));
        assert!(!r.uplink, "source 142.250.82.219 is the server: downlink");
    }

    /// The fingerprint switch is a process-wide flag (set once by main); tests that flip it take this lock.
    static FLAG: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn rec(f: &[u8]) -> RtpRecord {
        let _g = FLAG.lock().unwrap_or_else(|e| e.into_inner());
        crate::dedup::want_fingerprints(true); // set by main() only with --dedup fp
        parse_rtp_record(f, &gate(), Duration::from_micros(5)).unwrap()
    }

    #[test]
    fn a_mirror_twin_has_the_same_fingerprint_even_with_other_macs_and_padding() {
        let a = rec(&frame(0x01, 500, &[]));
        let b = rec(&frame(0x99, 500, &[0, 0, 0, 0]));       // other source MAC, Ethernet padding
        let c = rec(&frame(0x01, 500, &[1, 2, 3, 4, 5, 6])); // padding with other bytes
        assert_eq!(a.fp, b.fp);
        assert_eq!(a.fp, c.fp);
        assert_ne!(a.fp, 0);
    }

    #[test]
    fn without_dedup_fp_the_fingerprint_is_not_computed() {
        let f = frame(0x01, 500, &[]);
        let r = {
            let _g = FLAG.lock().unwrap_or_else(|e| e.into_inner());
            crate::dedup::want_fingerprints(false);
            let r = parse_rtp_record(&f, &gate(), Duration::from_micros(5)).unwrap();
            crate::dedup::want_fingerprints(true);
            r
        };
        assert_eq!(r.fp, 0);
        assert_ne!(rec(&f).fp, 0);
    }

    #[test]
    fn the_next_packet_of_the_stream_has_another_fingerprint() {
        assert_ne!(rec(&frame(0x01, 500, &[])).fp, rec(&frame(0x01, 501, &[])).fp);
    }
}
