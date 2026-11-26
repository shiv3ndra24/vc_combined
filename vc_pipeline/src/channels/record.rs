//! # channels/record.rs
//!
//! **What this file does**
//! - Receives `RtpRecord`s from the capture cores via `RECORD_TX`.
//! - For every record, in this order:
//!     1. asks `crate::dedup::Dedup` whether it is a mirror twin (`--dedup fp|off`);
//!        a twin goes nowhere: not into the CSV, not into the pcap, not into the metrics
//!     2. writes a CSV row (`--csv`) to `teams_record_NNNN.csv` / `meet_record_NNNN.csv`
//!     3. writes the frame (first `snaplen` bytes) to `teams_record_NNNN.pcap` / `meet_record_NNNN.pcap` (`--pcap`)
//!     4. hands the record to the session layer (batches of 5 000 or every 5 s)
//! - Steps 2 and 3 charge every byte to the shared budget (`--capture-max-mb`, summed over
//!   all platforms and both file kinds). When it is used up the files stop; steps 1 and 4 go on.
//!
//! Example of the after-de-dup rule: a Meet packet and its CAPWAP twin 11 us later. The first
//! gets one CSV row, one pcap frame and one count in `pps_downlink`; the twin gets nothing but
//! +1 in `dups_dropped`. With `--dedup off` both get everything.

use crate::dedup::{Dedup, DedupMode, Verdict};
use crate::files::{ByteBudget, Put, RotFile, pcap_global_header, pcap_record_header};
use crate::models::{Platform, RtpRecord};
use crate::sessions::{BATCH_SIZE, Batch, push_batch};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, bounded};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// Maximum time before a partial batch is sent to the session layer.
const BATCH_WINDOW: Duration = Duration::from_secs(5);

/// First line of every Teams / Meet CSV part. `tools/check_dups.py`, `csv_fps_check.py` and
/// `csv_timeline_report.py` read the columns by these names (unchanged by vc_combined).
pub const CSV_HEADER: &str = "arrival_epoch_ns,src_ip,dst_ip,ip_proto,ip_len,src_port,dst_port,udp_len,\
                              rtp_ssrc,rtp_timestamp,rtp_seq,rtp_pt,rtp_marker";

// ─────────────────────────────────────────────────────────────────────────────
//  Counters (read by the engine for the status line, capture_health and run_info)
// ─────────────────────────────────────────────────────────────────────────────
macro_rules! counter {
    ($name:ident, $get:ident, $doc:literal) => {
        static $name: AtomicU64 = AtomicU64::new(0);
        #[doc = $doc]
        pub fn $get() -> u64 {
            $name.load(Ordering::Relaxed)
        }
    };
}
counter!(RECORDS_IN, records_in, "Records received from the capture cores.");
counter!(KEPT, kept_records, "Records kept by de-dup (went to CSV/pcap/metrics).");
counter!(DUPLICATES, duplicate_records, "Records dropped by de-dup (mirror twins).");
counter!(CSV_ROWS, csv_rows, "CSV rows written.");
counter!(CSV_BYTES, csv_bytes, "CSV bytes written (headers included).");
counter!(CSV_SKIPPED, csv_skipped, "Kept records with no CSV row because the shared limit was reached.");
counter!(PCAP_FRAMES, pcap_frames, "pcap frames written.");
counter!(PCAP_BYTES, pcap_bytes, "pcap bytes written (file and record headers included).");
counter!(PCAP_SKIPPED, pcap_skipped, "Kept records with no pcap frame because the shared limit was reached.");
counter!(FILE_ERRORS, file_errors, "CSV / pcap write errors (disk full, ...).");
counter!(RECORD_DROPS, record_drops, "Records lost because the capture-to-records channel was full.");
counter!(BATCH_DROPS, batch_drops, "Batches lost because the session queue was full.");
counter!(FP_EVICTED_LIVE, fp_evicted_live, "`fp` slot overwrites (upper bound of missed twins); final value set at exit.");
counter!(CSV_PARTS, csv_parts, "CSV parts opened (both platforms).");
counter!(PCAP_PARTS, pcap_parts, "pcap parts opened (both platforms).");

/// Called from the capture path when `try_send` fails.
pub fn inc_record_drops() {
    RECORD_DROPS.fetch_add(1, Ordering::Relaxed);
}

/// Options for the records thread.
#[derive(Clone)]
pub struct RecordOpts {
    pub dedup: DedupMode,
    pub csv: bool,
    pub pcap: bool,
    /// bytes per frame in the pcap
    pub snaplen: usize,
    /// new part after this many bytes
    pub rotate_bytes: u64,
    /// the ONE budget shared with the Zoom engine
    pub budget: Arc<dyn ByteBudget>,
}

pub enum RecordMessage {
    Record(RtpRecord),
    Shutdown,
}

pub static RECORD_TX: OnceLock<Sender<RecordMessage>> = OnceLock::new();

/// Create the capture-to-records channel (once). Returns the receiver for `records_thread`.
pub fn init_record_channel(capacity: usize) -> Receiver<RecordMessage> {
    let (tx, rx) = bounded::<RecordMessage>(capacity);
    RECORD_TX.set(tx).expect("Record channel already initialised");
    rx
}

/// A pair of files (Teams, Meet) of one kind.
struct Pair {
    teams: RotFile,
    meet: RotFile,
}

impl Pair {
    fn open(ext: &'static str, header: Vec<u8>, o: &RecordOpts) -> Pair {
        let open = |stem: &str| {
            RotFile::open(stem, ext, header.clone(), o.rotate_bytes, o.budget.clone())
                .unwrap_or_else(|e| panic!("cannot create {stem}_0001.{ext} in the run folder: {e}"))
        };
        Pair { teams: open("teams_record"), meet: open("meet_record") }
    }
    fn get(&mut self, p: Platform) -> &mut RotFile {
        match p {
            Platform::Teams => &mut self.teams,
            Platform::Meet => &mut self.meet,
        }
    }
    fn flush(&mut self) {
        let _ = self.teams.flush();
        let _ = self.meet.flush();
    }
    fn parts(&self) -> u64 {
        (self.teams.parts + self.meet.parts) as u64
    }
}

fn csv_row(r: &RtpRecord, out: &mut Vec<u8>) {
    out.clear();
    let _ = writeln!(
        out,
        "{},{},{},{},{},{},{},{},0x{:08X},{},{},{},{}",
        r.arrival_epoch_ns,
        r.src_ip,
        r.dst_ip,
        r.ip_proto,
        r.ip_len,
        r.src_port,
        r.dst_port,
        r.udp_len,
        r.ssrc,
        r.rtp_timestamp,
        r.seq_num,
        r.payload_type,
        r.marker as u8
    );
}

fn flush_batch(pending: &mut Vec<RtpRecord>, seq: &mut u64) {
    if pending.is_empty() {
        return;
    }
    *seq += 1;
    let records = std::mem::replace(pending, Vec::with_capacity(BATCH_SIZE));
    if !push_batch(Batch { records, seq: *seq }) {
        BATCH_DROPS.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn records_thread(rx: Receiver<RecordMessage>, opts: RecordOpts) {
    let mut csv = opts.csv.then(|| {
        let mut h = CSV_HEADER.as_bytes().to_vec();
        h.push(b'\n');
        Pair::open("csv", h, &opts)
    });
    let mut pcap = opts.pcap.then(|| Pair::open("pcap", pcap_global_header(opts.snaplen as u32), &opts));
    let sync_bytes = |csv: &Option<Pair>, pcap: &Option<Pair>| {
        if let Some(c) = csv {
            CSV_BYTES.store(c.teams.bytes + c.meet.bytes, Ordering::Relaxed);
            CSV_PARTS.store(c.parts(), Ordering::Relaxed);
        }
        if let Some(p) = pcap {
            PCAP_BYTES.store(p.teams.bytes + p.meet.bytes, Ordering::Relaxed);
            PCAP_PARTS.store(p.parts(), Ordering::Relaxed);
        }
    };
    sync_bytes(&csv, &pcap);

    let mut pending: Vec<RtpRecord> = Vec::with_capacity(BATCH_SIZE);
    let mut seq: u64 = 0;
    let mut dedup = Dedup::new(opts.dedup);
    let mut row = Vec::with_capacity(256);
    let mut last_flush = Instant::now();

    loop {
        match rx.recv_timeout(BATCH_WINDOW) {
            Ok(RecordMessage::Record(mut r)) => {
                RECORDS_IN.fetch_add(1, Ordering::Relaxed);
                // 0. time trigger: also while packets keep arriving (recv_timeout alone fires only on silence)
                if last_flush.elapsed() >= BATCH_WINDOW {
                    flush_batch(&mut pending, &mut seq);
                    if let Some(c) = csv.as_mut() {
                        c.flush();
                    }
                    if let Some(p) = pcap.as_mut() {
                        p.flush();
                    }
                    sync_bytes(&csv, &pcap);
                    last_flush = Instant::now();
                }
                // 1. de-dup: a twin goes nowhere
                if dedup.check(r.fp, r.arrival_epoch_ns / 1000) == Verdict::Duplicate {
                    DUPLICATES.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                KEPT.fetch_add(1, Ordering::Relaxed);
                // 2. CSV row
                if let Some(c) = csv.as_mut() {
                    csv_row(&r, &mut row);
                    match c.get(r.platform).put(&[&row]) {
                        Ok(Put::Written) => {
                            CSV_ROWS.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(Put::LimitReached) => {
                            CSV_SKIPPED.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            FILE_ERRORS.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                // 3. pcap frame (same timestamp as the CSV row)
                if let Some(frame) = r.frame.take() {
                    if let Some(p) = pcap.as_mut() {
                        let hdr = pcap_record_header(r.arrival_epoch_ns, frame.len() as u32, r.frame_len);
                        match p.get(r.platform).put(&[&hdr, &frame]) {
                            Ok(Put::Written) => {
                                PCAP_FRAMES.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(Put::LimitReached) => {
                                PCAP_SKIPPED.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_) => {
                                FILE_ERRORS.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                // 4. session layer
                pending.push(r);
                if pending.len() >= BATCH_SIZE {
                    flush_batch(&mut pending, &mut seq);
                    last_flush = Instant::now();
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                flush_batch(&mut pending, &mut seq);
                if let Some(c) = csv.as_mut() {
                    c.flush();
                }
                if let Some(p) = pcap.as_mut() {
                    p.flush();
                }
                sync_bytes(&csv, &pcap);
                last_flush = Instant::now();
            }
            Ok(RecordMessage::Shutdown) | Err(RecvTimeoutError::Disconnected) => {
                // The session layer is told to stop by `engine::stop` (after the last
                // capture_health line), not here, so that line still reaches InfluxDB.
                flush_batch(&mut pending, &mut seq);
                break;
            }
        }
    }
    if let Some(c) = csv.as_mut() {
        c.flush();
    }
    if let Some(p) = pcap.as_mut() {
        p.flush();
    }
    sync_bytes(&csv, &pcap);
    FP_EVICTED_LIVE.store(dedup.evicted_live(), Ordering::Relaxed);
}
