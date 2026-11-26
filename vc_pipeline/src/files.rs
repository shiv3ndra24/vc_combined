//! # files.rs: rotating capture files charged to ONE shared byte budget
//!
//! vc_combined writes six kinds of capture file (CSV + pcap for Teams, Meet and Zoom). The user
//! asked for **one size limit summed over all of them** (`--capture-max-mb`). The Zoom engine
//! already has such a budget (`zoom_pipeline::capture_files::DiskBudget`); this crate only sees
//! it through the [`ByteBudget`] trait, so `vc_pipeline` does not depend on `zoom_pipeline`.
//! The binary wraps the one Zoom budget and hands the same object to both engines.
//!
//! What "summed" means, with numbers: `--capture-max-mb 1000`. After 20 minutes Zoom has
//! written 900 MB (pcap + CSV) and Teams 99 MB. The next Meet row of 110 B still fits
//! (999 MB + 110 B < 1000 MB); the first write that would cross 1000 MB trips the budget, and
//! from then on NO platform writes any capture file (metrics and Influx go on). Trade-off the
//! user accepted: a busy platform can use up the budget of a quiet one.
//!
//! Files roll over after `rotate_bytes` (default 256 MiB, as the Zoom engine): `teams_record_0001.csv`,
//! `teams_record_0002.csv`, ... Every part starts with its own header (CSV header line, pcap
//! global header), so each part opens on its own in Wireshark / pandas.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

/// A byte budget shared by every capture-file writer.
pub trait ByteBudget: Send + Sync {
    /// Reserve `n` bytes; false (and closed for good) if they do not fit.
    fn reserve(&self, n: u64) -> bool;
    /// False once the limit was reached.
    fn is_open(&self) -> bool;
    /// Bytes reserved so far.
    fn used(&self) -> u64;
}

/// Stand-alone budget (tests, or a Teams/Meet-only build).
pub struct LocalBudget {
    max: u64,
    used: AtomicU64,
    tripped: AtomicBool,
}

impl LocalBudget {
    /// `max` bytes; `u64::MAX` = no limit.
    pub fn new(max: u64) -> Arc<LocalBudget> {
        Arc::new(LocalBudget { max, used: AtomicU64::new(0), tripped: AtomicBool::new(false) })
    }
}

impl ByteBudget for LocalBudget {
    fn reserve(&self, n: u64) -> bool {
        let mut cur = self.used.load(Relaxed);
        loop {
            if self.tripped.load(Relaxed) || cur.saturating_add(n) > self.max {
                self.tripped.store(true, Relaxed);
                return false;
            }
            match self.used.compare_exchange_weak(cur, cur + n, Relaxed, Relaxed) {
                Ok(_) => return true,
                Err(v) => cur = v,
            }
        }
    }
    fn is_open(&self) -> bool {
        !self.tripped.load(Relaxed)
    }
    fn used(&self) -> u64 {
        self.used.load(Relaxed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Put {
    Written,
    /// the shared limit was reached: nothing was written
    LimitReached,
}

/// One logical file (`teams_record.csv`), written as numbered parts.
pub struct RotFile {
    stem: String,
    ext: &'static str,
    header: Vec<u8>,
    rotate_bytes: u64,
    budget: Arc<dyn ByteBudget>,
    w: Option<BufWriter<File>>,
    file_bytes: u64,
    index: u32,
    /// bytes written to all parts (headers included)
    pub bytes: u64,
    /// parts opened
    pub parts: u32,
}

impl RotFile {
    /// Opens part 1 at once, so a bad folder fails at start-up and not an hour in.
    pub fn open(stem: &str, ext: &'static str, header: Vec<u8>, rotate_bytes: u64, budget: Arc<dyn ByteBudget>) -> io::Result<RotFile> {
        let mut f = RotFile { stem: stem.to_string(), ext, header, rotate_bytes: rotate_bytes.max(1), budget, w: None, file_bytes: 0, index: 0, bytes: 0, parts: 0 };
        f.open_next()?;
        Ok(f)
    }

    /// Name of part `n` (`teams_record_0001.csv`).
    pub fn part_name(stem: &str, ext: &str, n: u32) -> PathBuf {
        PathBuf::from(format!("{stem}_{n:04}.{ext}"))
    }

    fn open_next(&mut self) -> io::Result<()> {
        if let Some(mut w) = self.w.take() {
            w.flush()?;
        }
        self.index += 1;
        self.file_bytes = 0;
        if !self.budget.reserve(self.header.len() as u64) {
            return Ok(()); // limit reached: do not even create the file
        }
        let mut w = BufWriter::with_capacity(1 << 20, File::create(Self::part_name(&self.stem, self.ext, self.index))?);
        w.write_all(&self.header)?;
        self.file_bytes = self.header.len() as u64;
        self.bytes += self.header.len() as u64;
        self.parts += 1;
        self.w = Some(w);
        Ok(())
    }

    /// Write one record (never split across parts).
    pub fn put(&mut self, parts: &[&[u8]]) -> io::Result<Put> {
        if !self.budget.is_open() {
            return Ok(Put::LimitReached);
        }
        let total: u64 = parts.iter().map(|p| p.len() as u64).sum();
        let hdr = self.header.len() as u64;
        if self.w.is_none() || (self.file_bytes + total > self.rotate_bytes && self.file_bytes > hdr) {
            self.open_next()?;
            if self.w.is_none() {
                return Ok(Put::LimitReached);
            }
        }
        if !self.budget.reserve(total) {
            self.flush()?;
            return Ok(Put::LimitReached);
        }
        let w = self.w.as_mut().expect("opened above");
        for p in parts {
            w.write_all(p)?;
        }
        self.file_bytes += total;
        self.bytes += total;
        Ok(Put::Written)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        match self.w.as_mut() {
            Some(w) => w.flush(),
            None => Ok(()),
        }
    }
}

/// Classic libpcap global header: little endian, microsecond timestamps, Ethernet.
pub fn pcap_global_header(snaplen: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(24);
    h.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    h.extend_from_slice(&2u16.to_le_bytes());
    h.extend_from_slice(&4u16.to_le_bytes());
    h.extend_from_slice(&0i32.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());
    h.extend_from_slice(&snaplen.to_le_bytes());
    h.extend_from_slice(&1u32.to_le_bytes());
    h
}

/// pcap record header for a frame captured at `epoch_ns`.
pub fn pcap_record_header(epoch_ns: u64, caplen: u32, orig_len: u32) -> [u8; 16] {
    let us = epoch_ns / 1000;
    let mut h = [0u8; 16];
    h[0..4].copy_from_slice(&((us / 1_000_000) as u32).to_le_bytes());
    h[4..8].copy_from_slice(&((us % 1_000_000) as u32).to_le_bytes());
    h[8..12].copy_from_slice(&caplen.to_le_bytes());
    h[12..16].copy_from_slice(&orig_len.to_le_bytes());
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn in_tmp<F: FnOnce()>(tag: &str, f: F) {
        // RotFile writes into the current directory (the run folder in production)
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let d = std::env::temp_dir().join(format!("vcp_files_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let old = std::env::current_dir().unwrap();
        std::env::set_current_dir(&d).unwrap();
        f();
        std::env::set_current_dir(old).unwrap();
    }

    #[test]
    fn rotates_with_a_header_in_every_part_and_respects_the_shared_limit() {
        in_tmp("rot", || {
            // 4 parts of (10 B header + one 30 B record), then room for one more header only
            let b = LocalBudget::new(4 * (10 + 30) + 10 + 3);
            let budget: Arc<dyn ByteBudget> = b.clone();
            let mut f = RotFile::open("x_record", "csv", b"head\n12345".to_vec(), 50, budget).unwrap();
            for _ in 0..4 {
                assert_eq!(f.put(&[&[b'a'; 30]]).unwrap(), Put::Written);
            }
            // 4 records of 30 B, 50 B per part -> one record per part after the header
            assert_eq!(f.parts, 4);
            assert_eq!(f.put(&[&[b'a'; 30]]).unwrap(), Put::LimitReached, "header of part 5 fits, the record does not");
            assert!(!b.is_open());
            f.flush().unwrap();
            assert_eq!(std::fs::read("x_record_0001.csv").unwrap(), [b"head\n12345".as_slice(), &[b'a'; 30]].concat());
            assert!(std::path::Path::new("x_record_0004.csv").exists());
            assert_eq!(b.used(), 4 * 40 + 10, "the header of part 5 was charged, the refused record was not");
        });
    }

    #[test]
    fn pcap_headers_are_classic_little_endian() {
        let g = pcap_global_header(128);
        assert_eq!(&g[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(u32::from_le_bytes([g[16], g[17], g[18], g[19]]), 128);
        let r = pcap_record_header(1_700_000_000_123_456_789, 128, 1000);
        assert_eq!(u32::from_le_bytes([r[0], r[1], r[2], r[3]]), 1_700_000_000);
        assert_eq!(u32::from_le_bytes([r[4], r[5], r[6], r[7]]), 123_456);
        assert_eq!(u32::from_le_bytes([r[12], r[13], r[14], r[15]]), 1000);
    }
}
