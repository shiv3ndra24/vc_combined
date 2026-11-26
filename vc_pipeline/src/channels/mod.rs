//! # channels/
//!
//! One bounded MPSC channel decouples the capture cores from everything else:
//!
//! | Module | Channel carries | Thread | Writes |
//! |--------|-----------------|--------|--------|
//! | record | parsed `RtpRecord` (+ the first `snaplen` frame bytes with `--pcap`) | `records_thread` | de-dup, then `teams_/meet_record_NNNN.csv` and `.pcap` (kept packets only), then the session layer |
//!
//! vc_combined removed the second channel (`packet.rs`, raw frames to a pcap writer): it fed
//! the pcap BEFORE de-dup. The pcap is now written by the records thread after the verdict,
//! so with `--dedup fp` the pcap and the CSV hold exactly the same packets.

pub mod record;

pub use record::{RECORD_TX, RecordMessage, RecordOpts, init_record_channel, records_thread};
