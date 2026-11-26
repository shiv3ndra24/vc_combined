//! Optional per-packet debug CSV (`--packet-csv`), written by its own thread
//! from a bounded channel. Off by default: per-packet text output at campus
//! rates is exactly the hot-path I/O this redesign removes. It exists so a
//! short capture can still be taken for validation (dedup parity, sequence
//! analysis, RTP offset validation) without touching the packet path: the
//! capture core only does a `try_send` of a `Copy` struct, and a full
//! channel is counted in `dump_dropped`.
//!
//! ## Columns
//! The first 17 columns are the pre-existing ones, unchanged and in the same
//! order, so anything that reads the old file still works:
//! `time_offset_s,udp_len,src_ip,dst_ip,src_port,dst_port,dir,class,
//! media_type_byte,sfu_seq,media_sequence,media_timestamp,frame_seq,
//! frame_pkt_count,ip_ttl,ip_id,dup`
//! (rows with `dup=1` are the second copies the pipeline removed).
//!
//! Appended in Stage 1 (decision of 2026-10-09: "our current CSV + RTP
//! columns appended"). The RTP names and the `0xXXXXXXXX` SSRC format are the
//! thesis' (`capture_data` `teams_rtp_records.csv`), so its tools can be
//! pointed at these columns:
//! * `rtp_ssrc, rtp_timestamp, rtp_seq, rtp_pt, rtp_marker`: the inner RTP
//!   header read at the media type's documented offset. For RTCP types
//!   (33/34) only `rtp_ssrc` (the sender SSRC) and `rtp_pt` (the RTCP packet
//!   type, 200 = sender report) are filled.
//! * `rtp_ver_ok`: 1 = version bits (and, for RTCP, packet type) look right,
//!   0 = they do not, so the offset is suspect for that packet. The other RTP
//!   cells are still filled when it is 0 so a validation run can see how the
//!   offset is wrong. Empty = this type has no RTP (21, 10, ...) or the
//!   payload was too short.
//! * `arrival_epoch_ns`: Unix time of the packet (the monotonic offset above
//!   plus the start time taken once at launch), so a row can be matched to a
//!   packet in the pcap or to an Influx point. This one is an addition to the
//!   "RTP columns" you asked for.
//! * `core`: dense index (0..shards) of the RX core that received this copy.
//!   Added after the first campus runs: with it, a second copy that reached a
//!   different core than its first copy is visible directly (same packet,
//!   two different `core` values), instead of being inferred.
//!
//! Appended in p7b (still at the END, so every older reader keeps working):
//! * `media_b20`: media-header byte 20 (the video layout selector: 0x02 -> RTP at
//!   +24, 0x0a -> +28, 0x80-0xBF -> +20), printed as a decimal number; empty when the
//!   payload is shorter than 20 bytes past the SFU header. Filled for EVERY type
//!   (it is just a byte of the packet), only meaningful for type 16.
//! * `media_b7`: media-header byte 7 (the type-13 sub-type: 0x1e = RTP screen share,
//!   0x15 = probe padding in a Type-13 envelope), same conventions, only meaningful
//!   for type 13.
//! With them `tools/verify_metrics.py` can redo the layout and gate rules from the
//! CSV alone, which is what makes it an independent check.
//!
//! Two cell meanings changed in p7b without a new column:
//! * a type-13 packet whose sub-type is not 0x1e has no RTP: its `rtp_*` cells are
//!   EMPTY (p7a read +27 anyway and printed `rtp_ver_ok=0` or a lucky `1`);
//! * for a video packet with byte 20 in 0x80-0xBF the RTP header is read at +20,
//!   and `frame_seq` / `frame_pkt_count` (fixed positions 21-23 of the older layouts)
//!   are RTP header bytes 1-3 there, not frame counters (the same caveat as for type 30).

use crate::capture_files::{FileCtx, FileKind, Put, Rotating, IDLE_FLUSH, WRITER_POLL};
use crate::model::{Class, PacketDump, CLASS_NAMES};
use crossbeam_channel::{Receiver, TryRecvError};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

/// The 17 original columns.
pub const HEADER_V1: &str = "time_offset_s,udp_len,src_ip,dst_ip,src_port,dst_port,dir,class,media_type_byte,sfu_seq,media_sequence,media_timestamp,frame_seq,frame_pkt_count,ip_ttl,ip_id,dup";
/// The columns appended in Stage 1 and p7b (`media_b20`, `media_b7`).
pub const HEADER_APPENDED: &str = "rtp_ssrc,rtp_timestamp,rtp_seq,rtp_pt,rtp_marker,rtp_ver_ok,arrival_epoch_ns,core,media_b20,media_b7";
/// Full header line (without the newline).
pub fn header() -> String {
    format!("{HEADER_V1},{HEADER_APPENDED}")
}

/// Format one row (including the trailing newline) into `out`.
/// `start_epoch_ns` is the Unix time of pipeline time 0.
pub fn format_row(r: &PacketDump, start_epoch_ns: i128, out: &mut String) {
    let class = CLASS_NAMES[(Class::from_idx(r.class)).idx()];
    let _ = write!(
        out,
        "{:.6},{},{},{},{},{},{},{},",
        r.t_us as f64 / 1e6,
        r.udp_len,
        r.src,
        r.dst,
        r.src_port,
        r.dst_port,
        if r.dir == 0 { "up" } else { "down" },
        class,
    );
    if r.has_sfu {
        let _ = write!(out, "{}", r.media_type_byte);
    }
    let _ = write!(out, ",{},{},{},", r.sfu_seq, r.media_seq, r.media_ts);
    if r.frame_seq >= 0 {
        let _ = write!(out, "{}", r.frame_seq);
    }
    out.push(',');
    if r.frame_pkt_count >= 0 {
        let _ = write!(out, "{}", r.frame_pkt_count);
    }
    let _ = write!(out, ",{},{},{}", r.ttl, r.ip_id, r.dup as u8);
    // ---- appended columns ----
    if r.rtp_state == 0 {
        out.push_str(",,,,,,");
    } else if r.class == Class::Rtcp as u8 {
        // RTCP: only the sender SSRC and the RTCP packet type are meaningful
        let _ = write!(out, ",0x{:08X},,,{},,{}", r.rtp_ssrc, r.rtp_pt, (r.rtp_state == 1) as u8);
    } else {
        let _ = write!(
            out,
            ",0x{:08X},{},{},{},{},{}",
            r.rtp_ssrc,
            r.rtp_ts,
            r.rtp_seq,
            r.rtp_pt,
            r.rtp_marker as u8,
            (r.rtp_state == 1) as u8
        );
    }
    let epoch_ns = start_epoch_ns + r.t_us as i128 * 1000;
    let _ = write!(out, ",{epoch_ns},{},", r.core);
    if r.media_b20 >= 0 {
        let _ = write!(out, "{}", r.media_b20);
    }
    out.push(',');
    if r.media_b7 >= 0 {
        let _ = write!(out, "{}", r.media_b7);
    }
    out.push('\n');
}

/// Name of CSV file number `n`: number 1 is exactly the path the user gave,
/// later ones are `stem.N.ext` (`debug.csv`, `debug.2.csv`, `debug.3.csv`...).
pub fn csv_name(base: &Path, n: u32) -> PathBuf {
    if n <= 1 {
        return base.to_path_buf();
    }
    // vc_combined: a base ending in `_0001.csv` numbers its parts `_0002.csv`, `_0003.csv`...
    if let Some(stem) = base.file_name().and_then(|f| f.to_str()).and_then(|f| f.strip_suffix("_0001.csv")) {
        return base.with_file_name(format!("{stem}_{n:04}.csv"));
    }
    let stem = base.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "packets".into());
    let ext = base.extension().map(|e| e.to_string_lossy().into_owned()).unwrap_or_else(|| "csv".into());
    base.with_file_name(format!("{stem}.{n}.{ext}"))
}

/// An opened CSV writer. Opening is separate from running so that an
/// unwritable path is reported at start-up, before capture begins.
pub struct CsvWriter {
    rx: Receiver<PacketDump>,
    out: Rotating,
}

impl CsvWriter {
    pub fn open(rx: Receiver<PacketDump>, path: &Path, ctx: &FileCtx) -> std::io::Result<CsvWriter> {
        let base = path.to_path_buf();
        let mut head = header().into_bytes();
        head.push(b'\n');
        let out = Rotating::open(Box::new(move |n| csv_name(&base, n)), head, FileKind::Csv, ctx)?;
        Ok(CsvWriter { rx, out })
    }

    /// Runs until `stop` is set and the queue is empty (the pipeline lives in a
    /// `static`, so the channel never disconnects on its own). Returns the
    /// number of rows written.
    pub fn run(mut self, ctx: &FileCtx, stop: &AtomicBool) -> std::io::Result<u64> {
        let mut n = 0u64;
        let mut line = String::with_capacity(256);
        let (mut dirty, mut last_row) = (false, Instant::now());
        loop {
            let r = match self.rx.try_recv() {
                Ok(r) => r,
                Err(TryRecvError::Empty) => {
                    if dirty && last_row.elapsed() >= IDLE_FLUSH {
                        let _ = self.out.flush();
                        dirty = false;
                    }
                    if stop.load(Relaxed) && self.rx.is_empty() {
                        break;
                    }
                    // poll, do not block in recv: see capture_files::WRITER_POLL
                    std::thread::sleep(WRITER_POLL);
                    continue;
                }
                Err(TryRecvError::Disconnected) => break,
            };
            dirty = true;
            last_row = Instant::now();
            line.clear();
            format_row(&r, ctx.start_epoch_ns, &mut line);
            match self.out.put(&[line.as_bytes()]) {
                Ok(Put::Written) => {
                    n += 1;
                    ctx.stats.csv_rows.fetch_add(1, Relaxed);
                }
                Ok(Put::LimitReached) => {
                    ctx.stats.csv_drop_limit.fetch_add(1, Relaxed);
                }
                Err(_) => {
                    ctx.stats.io_errors.fetch_add(1, Relaxed);
                }
            }
        }
        self.out.flush()?;
        Ok(n)
    }
}

/// Convenience used by `zoom_capture`: open, then run to completion.
pub fn run_csv_writer(rx: Receiver<PacketDump>, path: &Path, stop: &AtomicBool, ctx: &FileCtx) -> std::io::Result<u64> {
    CsvWriter::open(rx, path, ctx)?.run(ctx, stop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture_files::CaptureLimits;
    use crate::net::Addr;
    use std::time::Instant;

    fn dump() -> PacketDump {
        PacketDump {
            t_us: 1_500_000,
            src: Addr::from_v4([10, 184, 58, 124]),
            dst: Addr::from_v4([170, 114, 107, 187]),
            src_port: 50000,
            dst_port: 8801,
            udp_len: 1158,
            ttl: 63,
            ip_id: 4242,
            class: Class::Video as u8,
            dir: 0,
            dup: false,
            core: 3,
            has_sfu: true,
            media_type_byte: 16,
            sfu_seq: 7,
            media_seq: 1001,
            media_ts: 123456,
            frame_seq: 88,
            frame_pkt_count: 3,
            rtp_state: 1,
            rtp_ssrc: 0x0001_0203,
            rtp_seq: 65535,
            rtp_ts: 90_000,
            rtp_pt: 98,
            rtp_marker: true,
            media_b20: 0x02,
            media_b7: 0,
        }
    }

    #[test]
    fn header_keeps_the_17_original_columns_first_and_appends_the_rest() {
        let h = header();
        let cols: Vec<&str> = h.split(',').collect();
        assert_eq!(cols.len(), 27);
        assert_eq!(cols[..17].join(","), HEADER_V1);
        // the Stage-1 columns keep their positions; the two p7b columns come last
        assert_eq!(
            &cols[17..],
            &["rtp_ssrc", "rtp_timestamp", "rtp_seq", "rtp_pt", "rtp_marker", "rtp_ver_ok", "arrival_epoch_ns", "core", "media_b20", "media_b7"]
        );
        assert_eq!(&cols[..3], &["time_offset_s", "udp_len", "src_ip"]);
    }

    #[test]
    fn row_has_one_cell_per_header_column_and_the_expected_values() {
        let mut s = String::new();
        let start = 1_800_000_000_000_000_000i128;
        format_row(&dump(), start, &mut s);
        assert!(s.ends_with('\n'));
        let cells: Vec<&str> = s.trim_end().split(',').collect();
        assert_eq!(cells.len(), 27, "{s}");
        assert_eq!(cells[0], "1.500000");
        assert_eq!(cells[6], "up");
        assert_eq!(cells[7], "video");
        assert_eq!(cells[8], "16");
        assert_eq!((cells[10], cells[11], cells[12], cells[13]), ("1001", "123456", "88", "3"));
        assert_eq!((cells[14], cells[15], cells[16]), ("63", "4242", "0"));
        assert_eq!(&cells[17..], &["0x00010203", "90000", "65535", "98", "1", "1", "1800000001500000000", "3", "2", "0"]);
    }

    #[test]
    fn media_byte_cells_are_decimal_and_empty_when_the_payload_was_too_short() {
        let mut d = dump();
        d.media_b20 = 0x90; // a +20-layout video packet
        d.media_b7 = 0x1e; // (a type-13 RTP sub-type; every type fills both cells)
        let mut s = String::new();
        format_row(&d, 0, &mut s);
        let cells: Vec<&str> = s.trim_end().split(',').collect();
        assert_eq!((cells[25], cells[26]), ("144", "30"), "{s}");
        d.media_b20 = -1;
        d.media_b7 = -1;
        let mut s = String::new();
        format_row(&d, 0, &mut s);
        let cells: Vec<&str> = s.trim_end().split(',').collect();
        assert_eq!(cells.len(), 27, "{s}");
        assert_eq!((cells[25], cells[26]), ("", ""), "{s}");
    }

    #[test]
    fn rows_without_rtp_or_without_sfu_have_empty_cells_not_garbage() {
        let mut d = dump();
        d.rtp_state = 0;
        d.has_sfu = false;
        d.frame_seq = -1;
        d.frame_pkt_count = -1;
        d.class = Class::NoHdr as u8;
        let mut s = String::new();
        format_row(&d, 0, &mut s);
        let cells: Vec<&str> = s.trim_end().split(',').collect();
        assert_eq!(cells.len(), 27);
        assert_eq!((cells[8], cells[12], cells[13]), ("", "", ""));
        assert!(cells[17..23].iter().all(|c| c.is_empty()), "{s}");
        assert_eq!(cells[23], "1500000000");
    }

    #[test]
    fn a_failed_version_check_still_shows_the_fields_and_is_flagged() {
        let mut d = dump();
        d.rtp_state = 2;
        let mut s = String::new();
        format_row(&d, 0, &mut s);
        let cells: Vec<&str> = s.trim_end().split(',').collect();
        assert_eq!((cells[17], cells[22]), ("0x00010203", "0"));
    }

    #[test]
    fn rtcp_rows_fill_only_ssrc_and_packet_type() {
        let mut d = dump();
        d.class = Class::Rtcp as u8;
        d.media_type_byte = 34;
        d.rtp_pt = 200;
        let mut s = String::new();
        format_row(&d, 0, &mut s);
        let cells: Vec<&str> = s.trim_end().split(',').collect();
        assert_eq!(cells.len(), 27, "{s}");
        assert_eq!(&cells[17..23], &["0x00010203", "", "", "200", "", "1"]);
    }

    #[test]
    fn dup_rows_stay_in_the_csv_flagged() {
        let mut d = dump();
        d.dup = true;
        let mut s = String::new();
        format_row(&d, 0, &mut s);
        assert_eq!(s.trim_end().split(',').nth(16), Some("1"));
    }

    #[test]
    fn file_names_first_is_the_given_path_then_numbered() {
        let b = Path::new("/x/debug.csv");
        assert_eq!(csv_name(b, 1), PathBuf::from("/x/debug.csv"));
        assert_eq!(csv_name(b, 2), PathBuf::from("/x/debug.2.csv"));
        assert_eq!(csv_name(Path::new("noext"), 3), PathBuf::from("noext.3.csv"));
        let z = Path::new("/r/zoom_record_0001.csv");
        assert_eq!(csv_name(z, 1), PathBuf::from("/r/zoom_record_0001.csv"));
        assert_eq!(csv_name(z, 12), PathBuf::from("/r/zoom_record_0012.csv"));
    }

    #[test]
    fn writer_rotates_repeats_the_header_and_stops_at_the_cap() {
        let dir = std::env::temp_dir().join(format!("zc_csv_{}_{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("d.csv");
        // header ~170 B, a row ~110 B: rotate at 600 B, cap total at 1300 B
        let cx = FileCtx::new(CaptureLimits { rotate_bytes: 600, max_total_bytes: 1300 }, Instant::now());
        let (tx, rx) = crossbeam_channel::bounded(1000);
        let w = CsvWriter::open(rx, &path, &cx).unwrap();
        for i in 0..50u64 {
            let mut d = dump();
            d.t_us = i;
            tx.send(d).unwrap();
        }
        let stop = AtomicBool::new(true);
        let n = w.run(&cx, &stop).unwrap();
        assert!(n >= 3 && n < 50, "wrote {n}");
        assert!(!cx.budget.is_open());
        assert!(cx.budget.used() <= 1300);
        assert_eq!(cx.stats.csv_rows.load(Relaxed), n);
        assert_eq!(cx.stats.csv_rows.load(Relaxed) + cx.stats.csv_drop_limit.load(Relaxed), 50);
        let mut files: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
        files.sort();
        assert!(files.len() >= 2, "{files:?}");
        for f in &files {
            let text = std::fs::read_to_string(f).unwrap();
            assert_eq!(text.lines().next().unwrap(), header(), "{f:?}");
            assert!(text.len() <= 600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
