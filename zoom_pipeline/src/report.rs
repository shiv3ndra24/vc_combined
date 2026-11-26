//! The one-line status the operator watches in the terminal / journal.
//! Pure function of two snapshots so it is unit-tested.

use crate::export::ExportStats;
use crate::headers::{VLAYOUT_SLOT_OTHER, VLAYOUT_SLOT_RTP20};
use crate::model::HealthSnapshot;
use std::sync::atomic::Ordering::Relaxed;

/// The byte values in an rtp20 mask as `90` or `80,90` (hex, no prefix); bit `i` is byte `0x80 + i`.
pub fn rtp20_bytes(mask: u64) -> String {
    (0..64u32).filter(|i| mask & (1u64 << i) != 0).map(|i| format!("{:02x}", 0x80 + i)).collect::<Vec<_>>().join(",")
}

pub fn health_line(prev: &HealthSnapshot, cur: &HealthSnapshot, st: &ExportStats, elapsed_s: u64) -> String {
    let d = |a: u64, b: u64| a.saturating_sub(b);
    let din = d(cur.pkts_in, prev.pkts_in);
    let dd = d(cur.dups_dropped, prev.dups_dropped);
    let dm = d(cur.matched, prev.matched);
    let dt = (cur.t_us.saturating_sub(prev.t_us)) as f64 / 1e6;
    let rate = if dt > 0.0 { din as f64 / dt } else { 0.0 };
    // duplicates as a share of Zoom candidates (matched + dups). The campus link shows about 50 %:
    // every packet arrives twice, once on the CAPWAP tunnel leg and once on the wired leg (the try4
    // control run, CONFIRMED; it is not a SPAN setting that could be "fixed"). A share near 0 % means
    // the capture point sees only one leg, a share near 100 % would be a new source of copies.
    let cand = dm + dd;
    let dup_pct = if cand > 0 { 100.0 * dd as f64 / cand as f64 } else { 0.0 };
    let mut s = format!(
        "[{elapsed_s:>6}s] in={:>10} ({:>7.0}/s) zoom={:>9} dups={:>9} ({:>4.1}% of zoom) ip_filt=+{} port_filt=+{} parse_fail=+{} streams={} bins_shed=+{} export_ok={} export_dropped={}",
        cur.pkts_in,
        rate,
        cur.matched,
        cur.dups_dropped,
        dup_pct,
        d(cur.ip_filtered, prev.ip_filtered),
        d(cur.port_filtered, prev.port_filtered),
        d(cur.parse_fail, prev.parse_fail),
        cur.streams_active,
        d(cur.bins_dropped, prev.bins_dropped),
        st.lines_ok.load(Relaxed),
        st.lines_dropped.load(Relaxed),
    );
    // RTP self-check (cumulative): share of packets whose inner header has RTP version 2
    // at the documented offset. "-" = no packets of that type yet. Every slot is alarmed
    // below 95 % (with >= 100 samples). Since p7b that includes screen13: only type-13 packets
    // with sub-type 0x1e (RTP) reach the check, probe padding and control messages no longer
    // dilute it (it read ~34 % in p7a and had to be exempted).
    //
    // Caution for the video slot: packets of the +20 layout (`rtp20`) are chosen BECAUSE the top
    // two bits of byte 20 are `10`, which is the very bit test this check performs, so they pass by
    // construction. A video pass rate of 100 % is therefore no evidence that the +20 rule is right;
    // the evidence is stream qualification (`hub[... qual= failed=]`), a stable SSRC and a 90 kHz
    // clock (see README, "How to check the rtp20 layout").
    let mut rtp = String::new();
    let mut suspect = String::new();
    for (k, name) in crate::headers::RTP_SLOT_NAMES.iter().enumerate() {
        let (ok, bad) = (cur.rtp_ok[k], cur.rtp_bad[k]);
        let tot = ok + bad;
        if !rtp.is_empty() {
            rtp.push(' ');
        }
        if tot == 0 {
            rtp.push_str(&format!("{name}:-"));
        } else {
            let pct = 100.0 * ok as f64 / tot as f64;
            rtp.push_str(&format!("{name}:{pct:.1}%"));
            if tot >= 100 && pct < 95.0 {
                suspect.push_str(&format!(" {name}({pct:.1}%)"));
            }
        }
    }
    s.push_str(&format!(" rtp_v2[{rtp}]"));
    // Video layout (media byte 20, cumulative): 02 = RTP at +24, 0a = RTP at +28 (the burst layout),
    // rtp20 = RTP at +20 (byte 20 in 0x80-0xBF, p7b), other = unseen. `rtp20_bytes` lists the exact
    // byte values behind rtp20 (only 0x90 has ever been seen). Packets in the rtp20 layout belong to a
    // second video stream of a flow (deck2 Part G); they are counted as video like any other stream.
    // TO BE CHECKED (C2, not done in p7b): whether that stream should be reported apart from the main one.
    s.push_str(&format!(
        " vlayout[02={} 0a={} rtp20={} other={}]",
        cur.video_layout[0],
        cur.video_layout[1],
        cur.video_layout[VLAYOUT_SLOT_RTP20],
        cur.video_layout[VLAYOUT_SLOT_OTHER]
    ));
    if cur.video_rtp20_mask != 0 {
        s.push_str(&format!(" rtp20_bytes=[{}]", rtp20_bytes(cur.video_rtp20_mask)));
    }
    // Stage-2 hub: live streams, qualified / failed (cumulative) and first sightings that were not streams (probes, new flows)
    s.push_str(&format!(
        " hub[streams={} flows={} qual={} failed={} sightings=+{}]",
        cur.rtp_streams_active,
        cur.sfu_flows_active,
        cur.rtp_qualified,
        cur.rtp_failed_qual,
        d(cur.rtp_probation_skipped, prev.rtp_probation_skipped)
    ));
    if cur.pcap_files + cur.csv_files > 0 {
        s.push_str(&format!(
            " disk={:.1}MB pcap={} csv={} csv_queue_drops={} pcap_drops(pool/queue/limit)={}/{}/{}",
            cur.capture_disk_bytes as f64 / 1e6,
            cur.pcap_pkts,
            cur.csv_rows,
            cur.dump_dropped,
            cur.pcap_drop_pool,
            cur.pcap_drop_queue,
            cur.pcap_drop_limit
        ));
    }
    if !suspect.is_empty() {
        s.push_str(&format!("  !! RTP offset suspect for:{suspect}"));
    }
    let d_other = d(cur.video_layout[VLAYOUT_SLOT_OTHER], prev.video_layout[VLAYOUT_SLOT_OTHER]);
    if d_other > 0 {
        s.push_str(&format!("  !! video byte-20 layout other=+{d_other} (a fourth video layout? see headers::video_layout)"));
    }
    // Not an alarm: the first sighting of an rtp20 byte value other than 0x90. Reading the whole
    // 0x80-0xBF range as "+20" is an INFERENCE; the first 0x80 or 0xA0 is the first test of it.
    let new_bits = cur.video_rtp20_mask & !prev.video_rtp20_mask & !(1u64 << (0x90 - 0x80));
    if new_bits != 0 {
        s.push_str(&format!(
            "  note: first sighting of rtp20 byte value(s) other than 0x90: {} (check README, Open items: rtp20 range)",
            rtp20_bytes(new_bits)
        ));
    }
    if cur.capture_limit_tripped > 0 {
        s.push_str("  !! capture size limit reached: pcap/csv stopped, metrics continue");
    }
    if cur.file_io_errors > prev.file_io_errors {
        s.push_str("  !! capture file I/O errors (disk full or path gone?)");
    }
    if d(cur.zoom_like_unlisted, prev.zoom_like_unlisted) > 0 {
        s.push_str(&format!("  !! zoom_like_unlisted=+{} (IP list may be stale)", d(cur.zoom_like_unlisted, prev.zoom_like_unlisted)));
    }
    if d(cur.streams_rejected, prev.streams_rejected) > 0 {
        s.push_str(&format!("  !! streams_rejected=+{} (raise --max-streams)", d(cur.streams_rejected, prev.streams_rejected)));
    }
    if d(cur.bins_dropped, prev.bins_dropped) > 0 || d(cur.hub_bins_dropped, prev.hub_bins_dropped) > 0 {
        s.push_str("  !! bins shed (exporter or channel too slow)");
    }
    if d(cur.rtp_streams_rejected, prev.rtp_streams_rejected) > 0 {
        s.push_str(&format!("  !! rtp_streams_rejected=+{} (raise --max-rtp-streams)", d(cur.rtp_streams_rejected, prev.rtp_streams_rejected)));
    }
    if cur.per_core_in.len() > 1 && prev.per_core_in.len() == cur.per_core_in.len() {
        let deltas: Vec<u64> = cur.per_core_in.iter().zip(prev.per_core_in.iter()).map(|(a, b)| d(*a, *b)).collect();
        let max = *deltas.iter().max().unwrap_or(&0) as f64;
        let min = *deltas.iter().min().unwrap_or(&0) as f64;
        if max > 100_000.0 && min / max < 0.2 {
            s.push_str("  !! capture cores very unbalanced (check RSS / queues)");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_reports_rates_percentages_and_warnings() {
        let prev = HealthSnapshot { t_us: 0, per_core_in: vec![0, 0], ..Default::default() };
        let cur = HealthSnapshot {
            t_us: 5_000_000,
            pkts_in: 1_000_000,
            matched: 500,
            dups_dropped: 500,
            zoom_like_unlisted: 3,
            bins_dropped: 2,
            streams_rejected: 1,
            per_core_in: vec![990_000, 10_000],
            ..Default::default()
        };
        let st = ExportStats::default();
        let l = health_line(&prev, &cur, &st, 5);
        assert!(l.contains("200000/s)"), "{l}");
        assert!(l.contains("(50.0% of zoom)"), "{l}");
        assert!(l.contains("zoom_like_unlisted=+3"));
        assert!(l.contains("streams_rejected=+1"));
        assert!(l.contains("bins shed"));
        assert!(l.contains("unbalanced"));
        assert!(l.contains("hub[streams=0 flows=0 qual=0 failed=0 sightings=+0]"), "{l}");
        let quiet = health_line(&cur, &cur, &st, 10);
        assert!(!quiet.contains("!!"), "{quiet}");
    }

    #[test]
    fn video_layout_counts_show_in_the_line_and_an_unseen_layout_raises_the_alarm() {
        let prev = HealthSnapshot { per_core_in: vec![0], ..Default::default() };
        let mut cur = HealthSnapshot { t_us: 5_000_000, per_core_in: vec![1], video_layout: [9_000, 300, 0, 0], ..Default::default() };
        let st = ExportStats::default();
        let l = health_line(&prev, &cur, &st, 5);
        assert!(l.contains("vlayout[02=9000 0a=300 rtp20=0 other=0]"), "{l}");
        assert!(!l.contains("rtp20_bytes"), "{l}");
        // the burst layout (0a) is normal traffic, not a warning
        assert!(!l.contains("!!"), "{l}");
        // a fourth layout is: the alarm shows the increase since the previous line
        cur.video_layout[VLAYOUT_SLOT_OTHER] = 7;
        let l = health_line(&prev, &cur, &st, 5);
        assert!(l.contains("vlayout[02=9000 0a=300 rtp20=0 other=7]"), "{l}");
        assert!(l.contains("!! video byte-20 layout other=+7"), "{l}");
        // ... and only while it is rising
        assert!(!health_line(&cur, &cur, &st, 10).contains("!!"));
    }

    #[test]
    fn the_rtp20_layout_is_shown_with_its_byte_values_and_is_not_an_alarm() {
        let prev = HealthSnapshot { per_core_in: vec![0], ..Default::default() };
        let mut cur = HealthSnapshot { t_us: 5_000_000, per_core_in: vec![1], video_layout: [9_000, 300, 143_157, 0], ..Default::default() };
        cur.video_rtp20_mask = 1 << (0x90 - 0x80); // only the 0x90 seen so far
        let st = ExportStats::default();
        let l = health_line(&prev, &cur, &st, 5);
        assert!(l.contains("vlayout[02=9000 0a=300 rtp20=143157 other=0] rtp20_bytes=[90]"), "{l}");
        assert!(!l.contains("!!") && !l.contains("note:"), "0x90 is the known value, nothing to flag: {l}");
        // the first sighting of another value in the range is flagged once (a note, not an alarm) ...
        let mut cur2 = cur.clone();
        cur2.video_rtp20_mask |= 1; // 0x80
        let l = health_line(&cur, &cur2, &st, 10);
        assert!(l.contains("rtp20_bytes=[80,90]"), "{l}");
        assert!(l.contains("note: first sighting of rtp20 byte value(s) other than 0x90: 80"), "{l}");
        assert!(!l.contains("!!"), "{l}");
        // ... and not again on the next line
        assert!(!health_line(&cur2, &cur2, &st, 15).contains("note:"));
        assert_eq!(rtp20_bytes((1 << 0x3f) | 1), "80,bf");
        assert_eq!(rtp20_bytes(0), "");
    }

    #[test]
    fn hub_counters_and_rejections_show_in_the_line() {
        let prev = HealthSnapshot { per_core_in: vec![0], ..Default::default() };
        let cur = HealthSnapshot {
            t_us: 5_000_000,
            per_core_in: vec![1],
            rtp_streams_active: 12,
            sfu_flows_active: 7,
            rtp_qualified: 30,
            rtp_failed_qual: 2,
            rtp_probation_skipped: 410,
            rtp_streams_rejected: 3,
            hub_bins_dropped: 1,
            ..Default::default()
        };
        let l = health_line(&prev, &cur, &ExportStats::default(), 5);
        assert!(l.contains("hub[streams=12 flows=7 qual=30 failed=2 sightings=+410]"), "{l}");
        assert!(l.contains("rtp_streams_rejected=+3 (raise --max-rtp-streams)"), "{l}");
        assert!(l.contains("bins shed"), "{l}");
    }

    #[test]
    fn rtp_pass_rate_capture_file_counters_and_warnings_show_in_the_line() {
        let mut cur = HealthSnapshot { t_us: 5_000_000, per_core_in: vec![1], ..Default::default() };
        let prev = HealthSnapshot { per_core_in: vec![0], ..Default::default() };
        cur.rtp_ok[0] = 990;
        cur.rtp_bad[0] = 10; // video 99.0%
        cur.rtp_ok[3] = 50;
        cur.rtp_bad[3] = 150; // screen30 25.0%, enough samples to be flagged
        cur.rtp_ok[2] = 9_999;
        cur.rtp_bad[2] = 1; // screen13 99.99 %: since p7b only type-13 packets with sub-type 0x1e are tested (deck2: 99.99 %)
        cur.pcap_files = 1;
        cur.pcap_pkts = 1234;
        cur.capture_disk_bytes = 2_500_000;
        let st = ExportStats::default();
        let l = health_line(&prev, &cur, &st, 5);
        assert!(l.contains("video:99.0%"), "{l}");
        assert!(l.contains("audio:-"), "{l}");
        assert!(l.contains("screen30:25.0%"), "{l}");
        assert!(l.contains("RTP offset suspect for: screen30(25.0%)"), "{l}");
        assert!(!l.contains("video(99.0%)"), "{l}");
        // screen13 is a strict slot like the others since p7b (p7a exempted it as "(mixed)")
        assert!(l.contains("screen13:100.0%"), "{l}");
        assert!(!l.contains("(mixed)"), "{l}");
        assert!(!l.contains("screen13("), "{l}");
        // ... so a collapse of its pass rate now raises the alarm
        cur.rtp_ok[2] = 337;
        cur.rtp_bad[2] = 663;
        let l = health_line(&prev, &cur, &st, 5);
        assert!(l.contains("RTP offset suspect for: screen13(33.7%) screen30(25.0%)"), "{l}");
        cur.rtp_ok[2] = 9_999;
        cur.rtp_bad[2] = 1;
        assert!(l.contains("disk=2.5MB pcap=1234"), "{l}");
        assert!(l.contains("csv_queue_drops="), "{l}");
        cur.capture_limit_tripped = 1;
        assert!(health_line(&prev, &cur, &st, 6).contains("size limit reached"));
    }
}
