use crate::models::RtpRecord;
use std::collections::HashMap;

// vc_combined: the two server lists that used to live here (MICROSOFT_SERVER_IPS, MEET_SERVER_IPS)
// are gone. The direction of every packet is decided once by the gate (ip_ranges.rs, from
// ip_lists/teams.txt and meet.txt) and carried in `RtpRecord::uplink`.
//
// Loss formula: UNCHANGED (user decision 2026-11-06, no loss upgrade). Per SSRC (no direction in
// the key), diff > 1 -> lost += min(diff - 1, 1000); -100 < diff < 0 -> one loss taken back.
// Bytes: UDP payload (udp_len - 8), as the Zoom engine and the thesis define throughput.

#[derive(Clone, Copy)]
struct SeqState {
    last_seq: u16,
}

#[derive(Default)]
pub struct NetworkMetrics {
    uplink_bytes: u64,
    downlink_bytes: u64,
    uplink_packets: u64,
    downlink_packets: u64,
    uplink_lost_packets: u64,
    downlink_lost_packets: u64,
    seq_state: HashMap<u32, SeqState>,
}

impl NetworkMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Called for every packet. Calculates metrics based on server IP direction.
    pub fn process_packet(&mut self, record: &RtpRecord) {
        let is_uplink = record.uplink;
        let is_downlink = !record.uplink;
        let payload = (record.udp_len as u64).saturating_sub(8);

        // 1. Calculate Packet Loss
        let mut lost_this_packet = 0;
        let mut recovered_this_packet = 0;
        match self.seq_state.get_mut(&record.ssrc) {
            Some(state) => {
                let diff = record.seq_num.wrapping_sub(state.last_seq) as i16;
                if diff > 0 {
                    if diff > 1 {
                        // Cap the maximum inferred loss to 1000 packets for a single jump
                        lost_this_packet = std::cmp::min(diff - 1, 1000) as u64;
                    }
                    state.last_seq = record.seq_num;
                } else if diff < 0 && diff > -100 {
                    // Late packet! We previously counted this as lost, so we recover it
                    recovered_this_packet = 1;
                }
            }
            None => {
                self.seq_state.insert(
                    record.ssrc,
                    SeqState {
                        last_seq: record.seq_num,
                    },
                );
            }
        }

        // 2. Route the data to the correct Uplink/Downlink bucket
        if is_uplink {
            self.uplink_bytes += payload;
            self.uplink_packets += 1;
            self.uplink_lost_packets += lost_this_packet;
            self.uplink_lost_packets = self.uplink_lost_packets.saturating_sub(recovered_this_packet);
        } else if is_downlink {
            self.downlink_bytes += payload;
            self.downlink_packets += 1;
            self.downlink_lost_packets += lost_this_packet;
            self.downlink_lost_packets = self.downlink_lost_packets.saturating_sub(recovered_this_packet);
        }
    }

    /// Returns true if there was any traffic in this bin.
    pub fn has_data(&self) -> bool {
        self.uplink_packets > 0 || self.downlink_packets > 0
    }

    /// Helper to calculate percentage safely (prevents dividing by zero)
    fn calculate_loss_pct(received: u64, lost: u64) -> f64 {
        let expected = received + lost;
        if expected == 0 {
            0.0
        } else {
            (lost as f64 / expected as f64) * 100.0
        }
    }

    /// Fields of `session_metrics` (vc_combined names; old names in docs/METRICS.md).
    pub fn to_influx_fields(&self, bin_duration_sec: f64) -> String {
        let up_loss_pct = Self::calculate_loss_pct(self.uplink_packets, self.uplink_lost_packets);
        let down_loss_pct = Self::calculate_loss_pct(self.downlink_packets, self.downlink_lost_packets);
        format!(
            "throughput_uplink_bps={:.1},throughput_downlink_bps={:.1},pps_uplink={:.2},pps_downlink={:.2},\
             bytes_uplink={}i,bytes_downlink={}i,rtp_loss_pct_uplink={:.4},rtp_loss_pct_downlink={:.4}",
            self.uplink_bytes as f64 * 8.0 / bin_duration_sec,
            self.downlink_bytes as f64 * 8.0 / bin_duration_sec,
            self.uplink_packets as f64 / bin_duration_sec,
            self.downlink_packets as f64 / bin_duration_sec,
            self.uplink_bytes,
            self.downlink_bytes,
            up_loss_pct,
            down_loss_pct
        )
    }

    /// Reset all counters for the next 5-second window.
    pub fn reset_bin(&mut self) {
        self.uplink_bytes = 0;
        self.downlink_bytes = 0;
        self.uplink_packets = 0;
        self.downlink_packets = 0;
        self.uplink_lost_packets = 0;
        self.downlink_lost_packets = 0;
        // Notice we do NOT clear `seq_state`! 
        // We must remember the last sequence number crossing into the next 5 seconds!
    }
}
