//! vc_pipeline: the Teams + Meet engine of `vc_capture`, independent of Retina.
//!
//! Packet path (see `engine::try_take`):
//! ```text
//! capture core: quick_precheck (ip_ranges.rs: Teams/Meet table, direction)
//!            -> identify_protocol (protocol.rs: RFC 7983, RTP only continues)
//!            -> parse_rtp_record (models/: record + fingerprint + first snaplen bytes)
//!            -> record channel
//! records thread (channels/record.rs): dedup (fp|off) -> CSV row -> pcap frame -> batch
//! session thread (sessions/): 5 s bins per client -> session_metrics / rtp_stream lines
//! influx thread: HTTP to the common target, or a .lp file
//! ```
pub mod channels;
pub mod dedup;
pub mod engine;
pub mod files;
pub mod ip_ranges;
pub mod models;
pub mod protocol;
pub mod sessions;
