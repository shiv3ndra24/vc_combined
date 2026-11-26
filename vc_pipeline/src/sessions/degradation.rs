//! # sessions/degradation.rs (unchanged rule since the thesis code; field names updated in vc_combined)
//!
//! Per SSRC (all packets > 400 B, both directions): a lifetime histogram of RTP-timestamp gaps
//! classifies the stream Camera or Screenshare; only Camera streams with >= 2 frames in the bin
//! are judged, degraded = frames / 5 s < 15. Fields: `bin_degraded`, `session_degradation_pct`,
//! `camera_streams_active`, `camera_streams_degraded`. The Zoom-style per-direction
//! `degraded_<dir>` / `video_streams_degraded_<dir>` are computed in streams.rs.
use crate::models::RtpRecord;
use std::collections::{HashMap, HashSet};

const MODAL_CLUSTERING_THRESH: f64 = 70.0;
const HISTOGRAM_BIN_SIZE: u32 = 500;
const HISTOGRAM_BINS: usize = 360; // 0 to 180,000

#[derive(Clone, Copy, PartialEq)]
enum StreamType {
    Camera,
    Screenshare,
}

struct StreamDegradationState {
    // Unique RTP timestamps in the current bin
    current_bin_frames: HashSet<u32>,
    
    // For gap histogram (used for classification)
    last_rtp_timestamp: Option<u32>,
    gap_histogram: [u32; HISTOGRAM_BINS],
    total_gaps: u32,
    
    // FPS history for baseline calculation (REPLACED by static threshold counters)
    total_active_bins: u64,
    degraded_bins: u64,
}

impl StreamDegradationState {
    fn new() -> Self {
        Self {
            current_bin_frames: HashSet::new(),
            last_rtp_timestamp: None,
            gap_histogram: [0; HISTOGRAM_BINS],
            total_gaps: 0,
            
            total_active_bins: 0,
            degraded_bins: 0,
        }
    }

    fn record_frame(&mut self, rtp_timestamp: u32) {
        self.current_bin_frames.insert(rtp_timestamp);
        
        if let Some(last_ts) = self.last_rtp_timestamp {
            let gap = rtp_timestamp.wrapping_sub(last_ts);
            
            // Only consider reasonable positive gaps
            // If packets arrive out of order, gap will be a huge wrapped u32, which is filtered out here.
            if gap > 0 && gap < (HISTOGRAM_BINS as u32 * HISTOGRAM_BIN_SIZE) {
                let bin_idx = (gap / HISTOGRAM_BIN_SIZE) as usize;
                if bin_idx < HISTOGRAM_BINS {
                    self.gap_histogram[bin_idx] += 1;
                    self.total_gaps += 1;
                }
            }
        }
        self.last_rtp_timestamp = Some(rtp_timestamp);
    }
    
    fn classify(&self) -> StreamType {
        if self.total_gaps < 10 {
            return StreamType::Camera;
        }
        
        // Find the mode bin
        let mut mode_idx = 0;
        let mut max_count = 0;
        for (i, &count) in self.gap_histogram.iter().enumerate() {
            if count > max_count {
                max_count = count;
                mode_idx = i;
            }
        }
        
        if max_count == 0 {
            return StreamType::Camera;
        }
        
        let mode_gap = (mode_idx as u32 * HISTOGRAM_BIN_SIZE) + (HISTOGRAM_BIN_SIZE / 2);
        let tol = (mode_gap as f64 * 0.2) as u32;
        
        let min_gap = mode_gap.saturating_sub(tol);
        let max_gap = mode_gap.saturating_add(tol);
        
        let mut clustered = 0;
        for (i, &count) in self.gap_histogram.iter().enumerate() {
            let bin_gap = (i as u32 * HISTOGRAM_BIN_SIZE) + (HISTOGRAM_BIN_SIZE / 2);
            if bin_gap >= min_gap && bin_gap <= max_gap {
                clustered += count;
            }
        }
        
        let clustering_pct = (clustered as f64 / self.total_gaps as f64) * 100.0;
        if clustering_pct >= MODAL_CLUSTERING_THRESH {
            StreamType::Camera
        } else {
            StreamType::Screenshare
        }
    }
}

pub struct DegradationTracker {
    streams: HashMap<u32, StreamDegradationState>,
}

impl Default for DegradationTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl DegradationTracker {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    pub fn process_packet(&mut self, record: &RtpRecord) {
        // Only process video packets (>400 bytes)
        if record.udp_len > 400 {
            let stream = self.streams.entry(record.ssrc).or_insert_with(StreamDegradationState::new);
            stream.record_frame(record.rtp_timestamp);
        }
    }

    pub fn to_influx_fields(&mut self, bin_duration_sec: f64) -> String {
        let mut active_streams = 0;
        let mut degraded_streams = 0;
        let mut camera_deg_pcts: Vec<f64> = Vec::new();

        for stream in self.streams.values_mut() {
            let n_frames = stream.current_bin_frames.len();
            if n_frames < 2 {
                continue; // Not active enough to evaluate
            }
            
            let stream_type = stream.classify();
            if stream_type != StreamType::Camera {
                continue; // ONLY evaluate Camera streams per the new logic
            }
            
            active_streams += 1;
            stream.total_active_bins += 1;
            
            let fps = n_frames as f64 / bin_duration_sec;
            
            // FPS_THRESHOLD = 15.0 (Static threshold)
            if fps < 15.0 {
                stream.degraded_bins += 1;
                degraded_streams += 1;
            }
            
            let stream_pct = (stream.degraded_bins as f64 / stream.total_active_bins as f64) * 100.0;
            camera_deg_pcts.push(stream_pct);
        }
        
        // Red Box logic: If any camera stream is degraded in this bin
        let bin_degraded = degraded_streams > 0;
        
        let session_degradation_pct = if camera_deg_pcts.is_empty() {
            0.0
        } else {
            let sum: f64 = camera_deg_pcts.iter().sum();
            sum / camera_deg_pcts.len() as f64
        };

        format!(
            // vc_combined: the two counts were `video_streams_active` / `video_streams_degraded`;
            // renamed because `video_streams_active_<dir>` now has Zoom's meaning (all qualified
            // camera streams with packets), while these count Camera-classified streams only.
            "bin_degraded={},session_degradation_pct={:.2},camera_streams_active={}i,camera_streams_degraded={}i",
            bin_degraded, session_degradation_pct, active_streams, degraded_streams
        )
    }

    pub fn reset_bin(&mut self) {
        for stream in self.streams.values_mut() {
            stream.current_bin_frames.clear();
        }
    }
}
