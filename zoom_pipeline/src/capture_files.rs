//! Optional on-disk capture: a pcap of the unique Zoom packets, and the
//! per-packet debug CSV (`csvdump.rs`). Both are OFF by default.
//!
//! ## Why this is not a copy of the thesis' pcap/CSV code
//! The thesis (`capture_data`) writes both files always, to fixed names that
//! the next run truncates, through two `bounded(2_000_000)` channels. We
//! measured that crossbeam commits those slots up front: 1,568 B x 2M is
//! about 3 GB resident before the first packet, and every RTP packet also
//! allocates two `String`s on the capture core. Here the *files and columns*
//! are the same idea, the *mechanism* keeps the rules of the rest of this
//! crate: no allocation and no I/O on the capture core, bounded memory,
//! every loss counted.
//!
//! ## pcap contents (decision of 2026-10-09)
//! * **unique packets only**: taken after de-dup, so second copies (the CAPWAP tunnel leg and the wired leg of one frame) are not in
//!   the file (the twins stay visible in the CSV with `dup=1`);
//! * **first `snaplen` bytes** (default 128). Ethernet(14)+VLAN(<=12)+IPv6(40)
//!   +UDP(8)+SFU(8)+media header and RTP (<=39) is at most about 121 bytes, so
//!   128 B holds every header the RTP validation needs, and the payload is
//!   encrypted media with no QoE value. About 7x smaller than full frames.
//! * file names `zoom_<start-epoch-s>_<NNNN>.pcap`, so a new run never
//!   overwrites an old one (the thesis truncates).
//!
//! ### If you ever need full frames ("option 2")
//! Run with `--pcap-snaplen 1536`. Nothing else changes. What to expect:
//! * disk: about 1.2 GB/h per video-heavy client instead of about 0.18 GB/h
//!   (one client of the 629 s sample: ~349 unique packets/s, ~2.7 Mbit/s);
//! * memory: the buffer pool is `pool_slots x snaplen`, so 16,384 slots is
//!   about 25 MB instead of 2 MB (still tiny);
//! * the file then contains the encrypted media of real users: decide
//!   whether you are allowed to keep it before you turn it on.
//!
//! ## Limits (the "modifiable field in code")
//! Edit the three constants below, or set `PipelineConfig.limits` /
//! `PipelineConfig.pcap`, or pass `--pcap-rotate-mb`, `--capture-max-mb`,
//! `--pcap-snaplen` on the command line. When the **total** written to pcap
//! files plus CSV files reaches `max_total_bytes` the on-disk capture stops
//! (metrics keep running), `capture_limit_tripped` goes to 1 in
//! `capture_health`, and the packets that could not be saved are counted.
//!
//! ## How the packet path stays cheap
//! Each capture core owns a *batch* (32 records packed in one preallocated
//! buffer). `offer` copies at most `snaplen` bytes into it: no allocation, no
//! system call, no cross-core traffic. Once per 32 packets (or when the first
//! packet in the batch is 100 ms old on the packet clock) the batch is queued
//! for the writer thread with one `try_send`, and a fresh one is taken from the
//! free list with one `try_recv`. A pool of `pool_slots / 32 + cores` batches
//! circulates; when the writer falls behind by the whole pool the capture core
//! counts the loss and carries on. It never waits. Batching exists because the
//! per-packet hand-off measured +100..150 ns per packet (`bench_pcap`), as
//! much as the rest of the packet path. A batch that is still partly filled
//! when capture stops is handed over by `Pipeline::shutdown`.

use crate::health::CoreCounters;
use crossbeam_channel::{bounded, Receiver, Sender, TryRecvError};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ===========================================================================
//  EDIT HERE: defaults for the on-disk capture limits
// ===========================================================================
/// Start a new file after this many bytes (pcap and CSV alike).
pub const DEFAULT_ROTATE_BYTES: u64 = 256 * 1024 * 1024;
/// Stop writing capture files once this many bytes (pcap + CSV together) have
/// been written. `u64::MAX` means no limit.
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 10 * 1024 * 1024 * 1024;
/// Bytes kept per packet. 128 = headers only; 1536 = whole frame.
pub const DEFAULT_PCAP_SNAPLEN: usize = 128;
/// Buffers in the pool = most packets that can be waiting for the disk.
pub const DEFAULT_PCAP_POOL_SLOTS: usize = 16_384;
// ===========================================================================

/// How long a writer thread sleeps when its queue is empty.
///
/// WHY the writers poll instead of blocking in `recv`: a blocked receiver is
/// registered with the channel, and the next `send` from the capture core then
/// has to wake it with a system call (a futex wake, microseconds, and on a
/// virtual machine more). That cost lands on the capture core, once per
/// hand-off, whenever the writer is faster than the traffic, which is the
/// normal case. A polling writer is never registered, so the capture core's
/// send is two atomic operations. The price is a wake-up every few ms on a
/// thread that is not on the hot path, and up to this much delay before a
/// batch reaches the file (the pool absorbs it: 2 ms of 1 Mpps traffic is
/// about 63 batches of the default 512).
pub const WRITER_POLL: Duration = Duration::from_millis(2);
/// A writer flushes its file buffer after this long without new data.
pub const IDLE_FLUSH: Duration = Duration::from_millis(300);

/// Smallest and largest snaplen accepted (below 64 B not even the IP/UDP
/// headers plus the Zoom header fit; above 9216 B is beyond a jumbo frame).
pub const MIN_SNAPLEN: usize = 64;
pub const MAX_SNAPLEN: usize = 9216;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureLimits {
    /// roll over to a new file after this many bytes
    pub rotate_bytes: u64,
    /// stop all on-disk capture after this many bytes in total (`u64::MAX` = unlimited)
    pub max_total_bytes: u64,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        CaptureLimits { rotate_bytes: DEFAULT_ROTATE_BYTES, max_total_bytes: DEFAULT_MAX_TOTAL_BYTES }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcapCfg {
    pub snaplen: usize,
    pub pool_slots: usize,
}

impl Default for PcapCfg {
    fn default() -> Self {
        PcapCfg { snaplen: DEFAULT_PCAP_SNAPLEN, pool_slots: DEFAULT_PCAP_POOL_SLOTS }
    }
}

impl PcapCfg {
    /// Clamp to sane values (never panics, never allocates a silly pool).
    pub fn clamped(self) -> PcapCfg {
        PcapCfg { snaplen: self.snaplen.clamp(MIN_SNAPLEN, MAX_SNAPLEN), pool_slots: self.pool_slots.clamp(16, 4_000_000) }
    }
    /// Memory held by the buffer pool: `pool_slots` packets of (16 B record
    /// header + `snaplen`), plus one batch in progress per core (a few KB each).
    pub fn pool_bytes(&self) -> usize {
        (REC_HDR + self.snaplen) * self.pool_slots
    }
}

// ---------------------------------------------------------------- budget

/// Shared byte budget for every capture file. Two writer threads call
/// `reserve`; the capture cores only read `is_open`.
pub struct DiskBudget {
    limits: CaptureLimits,
    used: AtomicU64,
    tripped: AtomicBool,
}

impl DiskBudget {
    pub fn new(limits: CaptureLimits) -> DiskBudget {
        DiskBudget { limits, used: AtomicU64::new(0), tripped: AtomicBool::new(false) }
    }
    pub fn limits(&self) -> CaptureLimits {
        self.limits
    }
    /// Reserve `n` bytes. Returns false (and trips the budget for good) if
    /// they would exceed the total limit.
    pub fn reserve(&self, n: u64) -> bool {
        let mut cur = self.used.load(Relaxed);
        loop {
            if self.tripped.load(Relaxed) || cur.saturating_add(n) > self.limits.max_total_bytes {
                self.tripped.store(true, Relaxed);
                return false;
            }
            match self.used.compare_exchange_weak(cur, cur + n, Relaxed, Relaxed) {
                Ok(_) => return true,
                Err(v) => cur = v,
            }
        }
    }
    #[inline]
    pub fn is_open(&self) -> bool {
        !self.tripped.load(Relaxed)
    }
    pub fn used(&self) -> u64 {
        self.used.load(Relaxed)
    }
}

// ----------------------------------------------------------------- stats

/// Written by the two writer threads, read by `Pipeline::health()`.
#[derive(Default)]
pub struct CaptureFileStats {
    pub pcap_pkts: AtomicU64,
    pub pcap_bytes: AtomicU64,
    pub pcap_files: AtomicU64,
    /// packets dequeued by the writer but not written because the limit was reached
    pub pcap_drop_limit_writer: AtomicU64,
    pub csv_rows: AtomicU64,
    pub csv_bytes: AtomicU64,
    pub csv_files: AtomicU64,
    pub csv_drop_limit: AtomicU64,
    pub io_errors: AtomicU64,
}

/// Everything a writer thread needs besides its own queue.
#[derive(Clone)]
pub struct FileCtx {
    pub stats: Arc<CaptureFileStats>,
    pub budget: Arc<DiskBudget>,
    /// Unix time of pipeline time 0, in nanoseconds (taken once at start, so
    /// the CSV and the pcap use the same clock)
    pub start_epoch_ns: i128,
}

impl FileCtx {
    pub fn new(limits: CaptureLimits, start: Instant) -> FileCtx {
        FileCtx {
            stats: Arc::new(CaptureFileStats::default()),
            budget: Arc::new(DiskBudget::new(limits)),
            start_epoch_ns: start_epoch_ns(start),
        }
    }
    /// vc_combined: share a budget owned by someone else (one limit for every platform's files).
    pub fn with_budget(budget: Arc<DiskBudget>, start: Instant) -> FileCtx {
        FileCtx { stats: Arc::new(CaptureFileStats::default()), budget, start_epoch_ns: start_epoch_ns(start) }
    }
    pub fn rotate_bytes(&self) -> u64 {
        self.budget.limits().rotate_bytes
    }
    /// pipeline time (us since start) -> Unix microseconds
    pub fn epoch_us(&self, t_us: u64) -> u64 {
        ((self.start_epoch_ns / 1000) as u64).saturating_add(t_us)
    }
}

/// Unix time (ns) that corresponds to `start`.
pub fn start_epoch_ns(start: Instant) -> i128 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as i128;
    now - start.elapsed().as_nanos() as i128
}

// -------------------------------------------------------- rotating writer

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileKind {
    Pcap,
    Csv,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Put {
    Written,
    /// the total-size limit was reached; nothing was written
    LimitReached,
}

/// A file that rolls over after `rotate_bytes`, repeats `header` at the top
/// of every file, and charges every byte to the shared [`DiskBudget`].
pub struct Rotating {
    name: Box<dyn Fn(u32) -> PathBuf + Send>,
    header: Vec<u8>,
    rotate_bytes: u64,
    kind: FileKind,
    ctx: FileCtx,
    w: Option<BufWriter<std::fs::File>>,
    file_bytes: u64,
    index: u32,
}

impl Rotating {
    /// Create file number 1 now (so an unwritable path fails at start-up).
    pub fn open(name: Box<dyn Fn(u32) -> PathBuf + Send>, header: Vec<u8>, kind: FileKind, ctx: &FileCtx) -> io::Result<Rotating> {
        let mut r = Rotating { name, header, rotate_bytes: ctx.rotate_bytes().max(1), kind, ctx: ctx.clone(), w: None, file_bytes: 0, index: 0 };
        r.open_next()?;
        Ok(r)
    }

    /// Path of the file currently being written.
    pub fn current_path(&self) -> PathBuf {
        (self.name)(self.index)
    }

    fn open_next(&mut self) -> io::Result<()> {
        if let Some(mut w) = self.w.take() {
            w.flush()?;
        }
        self.index += 1;
        self.file_bytes = 0;
        // the header counts against the budget like any other byte; if it does
        // not fit, do not even create the file
        if !self.header.is_empty() && !self.ctx.budget.reserve(self.header.len() as u64) {
            return Ok(()); // limit reached: leave the writer closed (w = None)
        }
        let path = (self.name)(self.index);
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let mut w = BufWriter::with_capacity(1 << 20, std::fs::File::create(&path)?);
        if !self.header.is_empty() {
            w.write_all(&self.header)?;
            self.file_bytes = self.header.len() as u64;
            self.count_bytes(self.header.len() as u64);
        }
        let files = match self.kind {
            FileKind::Pcap => &self.ctx.stats.pcap_files,
            FileKind::Csv => &self.ctx.stats.csv_files,
        };
        files.fetch_add(1, Relaxed);
        self.w = Some(w);
        Ok(())
    }

    fn count_bytes(&self, n: u64) {
        let c = match self.kind {
            FileKind::Pcap => &self.ctx.stats.pcap_bytes,
            FileKind::Csv => &self.ctx.stats.csv_bytes,
        };
        c.fetch_add(n, Relaxed);
    }

    /// Write one record made of `parts` (kept whole: never split across files).
    pub fn put(&mut self, parts: &[&[u8]]) -> io::Result<Put> {
        if !self.ctx.budget.is_open() {
            return Ok(Put::LimitReached);
        }
        let total: u64 = parts.iter().map(|p| p.len() as u64).sum();
        let need_roll = self.w.is_none() || (self.file_bytes + total > self.rotate_bytes && self.file_bytes > self.header.len() as u64);
        if need_roll {
            self.open_next()?;
            if self.w.is_none() {
                return Ok(Put::LimitReached);
            }
        }
        if !self.ctx.budget.reserve(total) {
            self.flush()?;
            return Ok(Put::LimitReached);
        }
        let w = self.w.as_mut().expect("opened above");
        for p in parts {
            w.write_all(p)?;
        }
        self.file_bytes += total;
        self.count_bytes(total);
        Ok(Put::Written)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        match self.w.as_mut() {
            Some(w) => w.flush(),
            None => Ok(()),
        }
    }
}

// ------------------------------------------------------------ pcap format

/// Classic libpcap file header, little endian, microsecond timestamps,
/// LINKTYPE_ETHERNET (readable by tcpdump, Wireshark, dpkt, scapy).
pub fn pcap_global_header(snaplen: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(24);
    h.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic (us)
    h.extend_from_slice(&2u16.to_le_bytes()); // version 2.4
    h.extend_from_slice(&4u16.to_le_bytes());
    h.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    h.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    h.extend_from_slice(&snaplen.to_le_bytes());
    h.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    h
}

/// 16-byte per-packet record header.
pub fn pcap_record_header(epoch_us: u64, caplen: u32, orig_len: u32) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0..4].copy_from_slice(&((epoch_us / 1_000_000) as u32).to_le_bytes());
    h[4..8].copy_from_slice(&((epoch_us % 1_000_000) as u32).to_le_bytes());
    h[8..12].copy_from_slice(&caplen.to_le_bytes());
    h[12..16].copy_from_slice(&orig_len.to_le_bytes());
    h
}

// ------------------------------------------------------------ pcap queues

/// Packets per hand-off between a capture core and the writer thread.
///
/// WHY a batch and not one buffer per packet: the first version moved one
/// pooled buffer per packet (a `try_recv` on the free list and a `try_send` on
/// the queue on the capture core, the mirror image on the writer). `bench_pcap`
/// measured +100..150 ns per packet for that, as much as the entire rest of
/// the packet path, because every channel operation moves a cache line between
/// two cores. A batch of 32 records divides those moves by 32; the capture
/// core now does one memcpy into memory it already owns.
pub const BATCH_RECS: usize = 32;
/// A partly filled batch is handed over anyway once its first packet is this
/// old (packet clock, so no clock read), so a quiet link does not hold packets
/// back. A batch that never gets another packet waits for `Pipeline::shutdown`.
pub const FLUSH_AFTER_US: u64 = 100_000;
/// Bytes of record header inside a batch: `t_us: u64, caplen: u32, orig_len: u32`.
const REC_HDR: usize = 16;

/// A group of captured packets in flight between a capture core and the
/// writer. Records are packed back to back: `[t_us u64][caplen u32][orig_len u32][bytes]`.
pub struct PcapBatch {
    data: Vec<u8>,
    recs: u32,
    first_t_us: u64,
}

impl PcapBatch {
    fn new(snaplen: usize) -> PcapBatch {
        let cap = BATCH_RECS * (REC_HDR + snaplen);
        let mut data = vec![0u8; cap];
        data.fill(0); // touch every page now, not on the capture core
        data.clear();
        PcapBatch { data, recs: 0, first_t_us: 0 }
    }
    /// Empty the batch so it can go back to the free list.
    pub fn clear(&mut self) {
        self.data.clear();
        self.recs = 0;
    }
    /// `(t_us, caplen, orig_len, bytes)` for every record in the batch.
    fn records(&self) -> BatchIter<'_> {
        BatchIter { d: &self.data, pos: 0 }
    }
    /// Number of packets in the batch.
    pub fn len(&self) -> usize {
        self.recs as usize
    }
    pub fn is_empty(&self) -> bool {
        self.recs == 0
    }
}

struct BatchIter<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for BatchIter<'a> {
    type Item = (u64, u32, u32, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        let h = self.d.get(self.pos..self.pos + REC_HDR)?;
        let t_us = u64::from_le_bytes(h[0..8].try_into().ok()?);
        let caplen = u32::from_le_bytes(h[8..12].try_into().ok()?);
        let orig = u32::from_le_bytes(h[12..16].try_into().ok()?);
        let body = self.d.get(self.pos + REC_HDR..self.pos + REC_HDR + caplen as usize)?;
        self.pos += REC_HDR + caplen as usize;
        Some((t_us, caplen, orig, body))
    }
}

/// One capture core's batch in progress. 128-byte aligned so two cores never
/// share a cache line; the mutex is only ever locked by that core (and once at
/// shutdown), so it costs one uncontended atomic.
#[repr(align(128))]
struct CoreSlot(Mutex<Option<PcapBatch>>);

/// Capture-core side. `offer` never allocates, blocks or does I/O.
pub struct PcapTap {
    tx: Sender<PcapBatch>,
    free_rx: Receiver<PcapBatch>,
    free_tx: Sender<PcapBatch>,
    slots: Box<[CoreSlot]>,
    snaplen: usize,
    budget: Arc<DiskBudget>,
}

/// Writer-thread side.
pub struct PcapWriterParts {
    pub rx: Receiver<PcapBatch>,
    pub free_tx: Sender<PcapBatch>,
    pub cfg: PcapCfg,
}

/// Build the tap (capture side) and the parts the writer thread needs.
/// `cores` = number of capture cores (`PipelineConfig.shards`): each one owns a
/// batch in progress, so the pool holds `pool_slots / BATCH_RECS + cores` batches.
pub fn new_pcap(cfg: PcapCfg, budget: Arc<DiskBudget>, cores: usize) -> (PcapTap, PcapWriterParts) {
    let cfg = cfg.clamped();
    let cores = cores.max(1);
    let n_batches = cfg.pool_slots.div_ceil(BATCH_RECS) + cores;
    let (tx, rx) = bounded::<PcapBatch>(n_batches);
    let (free_tx, free_rx) = bounded::<PcapBatch>(n_batches);
    for _ in 0..n_batches {
        // preallocated and page-touched once, here; the packet path only moves them around
        let _ = free_tx.try_send(PcapBatch::new(cfg.snaplen));
    }
    let slots: Vec<CoreSlot> = (0..cores).map(|_| CoreSlot(Mutex::new(None))).collect();
    (
        PcapTap { tx, free_rx, free_tx: free_tx.clone(), slots: slots.into_boxed_slice(), snaplen: cfg.snaplen, budget },
        PcapWriterParts { rx, free_tx, cfg },
    )
}

impl PcapTap {
    /// Copy up to `snaplen` bytes of `frame` into this core's batch; hand the
    /// batch to the writer when it is full or old. Every way of not saving the
    /// packet is counted on `c`:
    /// * `pcap_drop_limit`: the size limit was reached (tap closed);
    /// * `pcap_drop_pool`: no free batch (the writer is behind by the whole pool);
    /// * `pcap_drop_queue`: the hand-off failed (writer gone), or two threads
    ///   used the same core index at once (we never wait for the other one).
    #[inline]
    pub fn offer(&self, core: usize, t_us: u64, frame: &[u8], c: &CoreCounters) {
        if !self.budget.is_open() {
            CoreCounters::bump(&c.pcap_drop_limit);
            return;
        }
        let Ok(mut g) = self.slots[core % self.slots.len()].0.try_lock() else {
            CoreCounters::bump(&c.pcap_drop_queue);
            return;
        };
        if g.is_none() {
            match self.free_rx.try_recv() {
                Ok(b) => *g = Some(b),
                Err(_) => {
                    CoreCounters::bump(&c.pcap_drop_pool);
                    return;
                }
            }
        }
        let Some(b) = g.as_mut() else { return };
        let n = frame.len().min(self.snaplen);
        if b.recs == 0 {
            b.first_t_us = t_us;
        }
        b.data.extend_from_slice(&t_us.to_le_bytes());
        b.data.extend_from_slice(&(n as u32).to_le_bytes());
        b.data.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        b.data.extend_from_slice(&frame[..n]);
        b.recs += 1;
        if b.recs as usize >= BATCH_RECS || t_us.saturating_sub(b.first_t_us) >= FLUSH_AFTER_US {
            if let Some(full) = g.take() {
                self.hand_off(full, c);
            }
        }
    }

    /// Send a batch to the writer; if that is impossible count its packets as
    /// queue drops and recycle the buffer.
    fn hand_off(&self, b: PcapBatch, c: &CoreCounters) {
        if let Err(e) = self.tx.try_send(b) {
            let mut b = e.into_inner();
            CoreCounters::bump_by(&c.pcap_drop_queue, b.recs as u64);
            b.clear();
            let _ = self.free_tx.try_send(b);
        }
    }

    /// Hand over whatever core `core` still holds. `Pipeline::shutdown` calls
    /// this for every core before the writer is told to stop; it may wait for
    /// the core's lock because capture has stopped by then.
    pub fn flush(&self, core: usize, c: &CoreCounters) {
        let mut g = match self.slots[core % self.slots.len()].0.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(mut b) = g.take() {
            if b.is_empty() {
                b.clear();
                let _ = self.free_tx.try_send(b);
            } else {
                self.hand_off(b, c);
            }
        }
    }
}

/// File name of pcap number `n` (vc_combined: `zoom_record_0001.pcap`, `_0002`, ...; the run
/// folder already says when it started, so the start time is no longer in the name).
pub fn pcap_name(dir: &Path, _start_epoch_s: u64, n: u32) -> PathBuf {
    dir.join(format!("{PCAP_STEM}_{n:04}.pcap"))
}

/// Stem of the Zoom capture files (`zoom_record_NNNN.pcap` / `.csv`).
pub const PCAP_STEM: &str = "zoom_record";

/// An opened pcap writer. Opening is separate from running so that an
/// unwritable directory is reported at start-up, before capture begins.
pub struct PcapWriter {
    parts: PcapWriterParts,
    out: Rotating,
}

impl PcapWriter {
    pub fn open(parts: PcapWriterParts, dir: &Path, ctx: &FileCtx) -> io::Result<PcapWriter> {
        let start_s = (ctx.start_epoch_ns / 1_000_000_000) as u64;
        let dir_owned = dir.to_path_buf();
        let out = Rotating::open(
            Box::new(move |n| pcap_name(&dir_owned, start_s, n)),
            pcap_global_header(parts.cfg.snaplen as u32),
            FileKind::Pcap,
            ctx,
        )?;
        Ok(PcapWriter { parts, out })
    }

    /// Drain the queue into rotating pcap files until `stop` is set and the
    /// queue is empty. Returns the number of packets written. Buffers always go
    /// back to the pool, also after the limit was reached or an I/O error, so
    /// the pool never leaks.
    pub fn run(mut self, ctx: &FileCtx, stop: &AtomicBool) -> io::Result<u64> {
        let mut written = 0u64;
        let mut broken = false; // after an I/O error stop writing, keep draining
        let (mut dirty, mut last_batch) = (false, Instant::now());
        loop {
            let mut batch = match self.parts.rx.try_recv() {
                Ok(b) => b,
                Err(TryRecvError::Empty) => {
                    if dirty && last_batch.elapsed() >= IDLE_FLUSH {
                        let _ = self.out.flush();
                        dirty = false;
                    }
                    if stop.load(Relaxed) && self.parts.rx.is_empty() {
                        break;
                    }
                    std::thread::sleep(WRITER_POLL);
                    continue;
                }
                Err(TryRecvError::Disconnected) => break,
            };
            dirty = true;
            last_batch = Instant::now();
            for (t_us, caplen, orig_len, bytes) in batch.records() {
                if !broken {
                    let hdr = pcap_record_header(ctx.epoch_us(t_us), caplen, orig_len);
                    match self.out.put(&[&hdr, bytes]) {
                        Ok(Put::Written) => {
                            written += 1;
                            ctx.stats.pcap_pkts.fetch_add(1, Relaxed);
                        }
                        Ok(Put::LimitReached) => {
                            ctx.stats.pcap_drop_limit_writer.fetch_add(1, Relaxed);
                        }
                        Err(_) => {
                            ctx.stats.io_errors.fetch_add(1, Relaxed);
                            broken = true;
                        }
                    }
                } else {
                    ctx.stats.io_errors.fetch_add(1, Relaxed);
                }
            }
            batch.clear();
            let _ = self.parts.free_tx.try_send(batch);
        }
        self.out.flush()?;
        Ok(written)
    }
}

/// Convenience for tests and small tools: open and run in one call.
pub fn run_pcap_writer(parts: PcapWriterParts, dir: &Path, ctx: &FileCtx, stop: &AtomicBool) -> io::Result<u64> {
    PcapWriter::open(parts, dir, ctx)?.run(ctx, stop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering::Relaxed;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "zc_cf_{}_{}_{}",
            tag,
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// minimal independent pcap reader for the tests: (snaplen, [(sec, usec, caplen, orig, bytes)])
    fn read_pcap(path: &Path) -> (u32, Vec<(u32, u32, u32, u32, Vec<u8>)>) {
        let b = std::fs::read(path).unwrap();
        assert_eq!(&b[0..4], &[0xd4, 0xc3, 0xb2, 0xa1], "magic");
        assert_eq!(u16::from_le_bytes([b[4], b[5]]), 2);
        assert_eq!(u16::from_le_bytes([b[6], b[7]]), 4);
        assert_eq!(u32::from_le_bytes([b[20], b[21], b[22], b[23]]), 1, "ethernet");
        let snap = u32::from_le_bytes([b[16], b[17], b[18], b[19]]);
        let mut i = 24;
        let mut v = vec![];
        while i < b.len() {
            let g = |o: usize| u32::from_le_bytes([b[i + o], b[i + o + 1], b[i + o + 2], b[i + o + 3]]);
            let (sec, usec, cap, orig) = (g(0), g(4), g(8), g(12));
            v.push((sec, usec, cap, orig, b[i + 16..i + 16 + cap as usize].to_vec()));
            i += 16 + cap as usize;
        }
        (snap, v)
    }

    fn files_in(d: &Path) -> Vec<PathBuf> {
        let mut v: Vec<_> = std::fs::read_dir(d).unwrap().map(|e| e.unwrap().path()).collect();
        v.sort();
        v
    }

    fn ctx(limits: CaptureLimits) -> FileCtx {
        FileCtx::new(limits, Instant::now())
    }

    #[test]
    fn budget_trips_once_and_stays_tripped() {
        let b = DiskBudget::new(CaptureLimits { rotate_bytes: 100, max_total_bytes: 10 });
        assert!(b.reserve(6));
        assert!(b.is_open());
        assert!(!b.reserve(5), "6 + 5 > 10");
        assert!(!b.is_open());
        assert!(!b.reserve(1), "stays tripped even for a request that would fit");
        assert_eq!(b.used(), 6);
    }

    #[test]
    fn unlimited_budget_never_trips() {
        let b = DiskBudget::new(CaptureLimits { rotate_bytes: 1, max_total_bytes: u64::MAX });
        for _ in 0..1000 {
            assert!(b.reserve(u64::MAX / 4000));
        }
        assert!(b.is_open());
    }

    #[test]
    fn pcap_file_is_readable_and_truncation_keeps_orig_len() {
        let dir = tmpdir("fmt");
        let cx = ctx(CaptureLimits::default());
        let cfg = PcapCfg { snaplen: 128, pool_slots: 64 };
        let (tap, parts) = new_pcap(cfg, cx.budget.clone(), 1);
        let counters = CoreCounters::default();
        let stop = Arc::new(AtomicBool::new(false));
        let h = {
            let (cx, dir, stop) = (cx.clone(), dir.clone(), stop.clone());
            std::thread::spawn(move || run_pcap_writer(parts, &dir, &cx, &stop))
        };
        let big: Vec<u8> = (0..1400u32).map(|i| (i % 251) as u8).collect();
        let small: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        tap.offer(0, 1_500_000, &big, &counters);
        tap.offer(0, 2_000_001, &small, &counters);
        tap.flush(0, &counters); // what Pipeline::shutdown does
        std::thread::sleep(Duration::from_millis(100));
        stop.store(true, Relaxed);
        assert_eq!(h.join().unwrap().unwrap(), 2);
        let files = files_in(&dir);
        assert_eq!(files.len(), 1);
        let (snap, recs) = read_pcap(&files[0]);
        assert_eq!(snap, 128);
        assert_eq!(recs.len(), 2);
        let base = cx.epoch_us(0);
        assert_eq!((recs[0].2, recs[0].3), (128, 1400), "caplen is cut, orig_len is the real length");
        assert_eq!(recs[0].4, big[..128]);
        assert_eq!(recs[1].4, small);
        let ts = |r: &(u32, u32, u32, u32, Vec<u8>)| r.0 as u64 * 1_000_000 + r.1 as u64;
        assert_eq!(ts(&recs[0]), base + 1_500_000);
        assert_eq!(ts(&recs[1]), base + 2_000_001);
        assert_eq!(cx.stats.pcap_pkts.load(Relaxed), 2);
        assert_eq!(cx.stats.pcap_files.load(Relaxed), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn files_rotate_and_every_file_starts_with_a_pcap_header() {
        let dir = tmpdir("rot");
        // each record is 16 + 100 = 116 B; header 24 B; rotate at 400 B => 3 records per file
        let cx = ctx(CaptureLimits { rotate_bytes: 400, max_total_bytes: u64::MAX });
        let (tap, parts) = new_pcap(PcapCfg { snaplen: 100, pool_slots: 64 }, cx.budget.clone(), 1);
        let counters = CoreCounters::default();
        let stop = Arc::new(AtomicBool::new(false));
        let h = {
            let (cx, dir, stop) = (cx.clone(), dir.clone(), stop.clone());
            std::thread::spawn(move || run_pcap_writer(parts, &dir, &cx, &stop))
        };
        for i in 0..10u8 {
            tap.offer(0, i as u64 * 1000, &[i; 100], &counters);
        }
        tap.flush(0, &counters);
        std::thread::sleep(Duration::from_millis(150));
        stop.store(true, Relaxed);
        assert_eq!(h.join().unwrap().unwrap(), 10);
        let files = files_in(&dir);
        assert_eq!(files.len(), 4, "10 records at 3 per file");
        let mut seen = vec![];
        for f in &files {
            let (_, recs) = read_pcap(f);
            assert!(std::fs::metadata(f).unwrap().len() <= 400);
            seen.extend(recs.into_iter().map(|r| r.4[0]));
        }
        assert_eq!(seen, (0..10u8).collect::<Vec<_>>(), "no record lost or reordered across files");
        assert!(files[1].to_string_lossy().ends_with("_0002.pcap"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn total_limit_stops_writing_counts_the_loss_and_never_exceeds_the_cap() {
        let dir = tmpdir("cap");
        // 24 header + 3 x 116 = 372 fits; the 4th record would make 488 > 400
        let cx = ctx(CaptureLimits { rotate_bytes: 10_000, max_total_bytes: 400 });
        let (tap, parts) = new_pcap(PcapCfg { snaplen: 100, pool_slots: 64 }, cx.budget.clone(), 1);
        let counters = CoreCounters::default();
        let stop = Arc::new(AtomicBool::new(false));
        let h = {
            let (cx, dir, stop) = (cx.clone(), dir.clone(), stop.clone());
            std::thread::spawn(move || run_pcap_writer(parts, &dir, &cx, &stop))
        };
        for i in 0..6u8 {
            tap.offer(0, i as u64, &[i; 100], &counters);
        }
        tap.flush(0, &counters);
        std::thread::sleep(Duration::from_millis(150));
        // after the trip the capture core stops queueing and counts it
        tap.offer(0, 99, &[9; 100], &counters);
        stop.store(true, Relaxed);
        assert_eq!(h.join().unwrap().unwrap(), 3);
        assert!(!cx.budget.is_open());
        assert!(cx.budget.used() <= 400);
        assert_eq!(cx.stats.pcap_drop_limit_writer.load(Relaxed), 3);
        assert_eq!(CoreCounters::get(&counters.pcap_drop_limit), 1);
        let (_, recs) = read_pcap(&files_in(&dir)[0]);
        assert_eq!(recs.len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pool_exhaustion_is_counted_and_buffers_come_back() {
        let cx = ctx(CaptureLimits::default());
        // pool_slots 16 is clamped up to 16 = 1 batch of 32, plus 1 batch for the one core = 2 batches = 64 packets
        let (tap, parts) = new_pcap(PcapCfg { snaplen: 64, pool_slots: 16 }, cx.budget.clone(), 1);
        let counters = CoreCounters::default();
        // no writer running: 64 packets fit, the rest are dropped and counted
        for i in 0..70u32 {
            tap.offer(0, i as u64, &[i as u8; 80], &counters);
        }
        assert_eq!(CoreCounters::get(&counters.pcap_drop_pool), 6, "70 offered, 64 fit");
        assert_eq!(parts.rx.len(), 2, "two full batches queued");
        // drain like a writer would and give the batches back: offers work again
        let mut seen = 0;
        while let Ok(mut b) = parts.rx.try_recv() {
            seen += b.records().count();
            b.clear();
            parts.free_tx.try_send(b).unwrap();
        }
        assert_eq!(seen, 64);
        tap.offer(0, 100, &[1; 80], &counters);
        assert_eq!(CoreCounters::get(&counters.pcap_drop_pool), 6, "no new drop");
        tap.flush(0, &counters);
        assert_eq!(parts.rx.len(), 1);
        assert_eq!(CoreCounters::get(&counters.pcap_drop_queue), 0);
    }

    #[test]
    fn a_batch_is_handed_over_when_full_or_when_old_and_not_before() {
        let cx = ctx(CaptureLimits::default());
        let (tap, parts) = new_pcap(PcapCfg { snaplen: 64, pool_slots: 256 }, cx.budget.clone(), 1);
        let c = CoreCounters::default();
        for i in 0..(BATCH_RECS as u64 - 1) {
            tap.offer(0, 10 + i, &[7; 70], &c);
        }
        assert_eq!(parts.rx.len(), 0, "31 of 32: still being filled");
        tap.offer(0, 50, &[7; 70], &c);
        assert_eq!(parts.rx.len(), 1, "the 32nd packet sends the batch");
        // age: 3 packets, the last one 100 ms after the first
        tap.offer(0, 1_000_000, &[8; 70], &c);
        tap.offer(0, 1_000_001, &[8; 70], &c);
        assert_eq!(parts.rx.len(), 1);
        tap.offer(0, 1_000_000 + FLUSH_AFTER_US, &[9; 70], &c);
        assert_eq!(parts.rx.len(), 2, "old batch goes out with only 3 records");
        let _full = parts.rx.try_recv().unwrap();
        let old = parts.rx.try_recv().unwrap();
        let recs: Vec<_> = old.records().collect();
        assert_eq!(recs.len(), 3);
        assert_eq!((recs[0].0, recs[0].1, recs[0].2), (1_000_000, 64, 70), "t_us, caplen cut to 64, orig_len 70");
        assert_eq!(recs[2].3, &[9u8; 64][..]);
    }

    #[test]
    fn each_core_fills_its_own_batch() {
        let cx = ctx(CaptureLimits::default());
        let (tap, parts) = new_pcap(PcapCfg { snaplen: 64, pool_slots: 64 }, cx.budget.clone(), 2);
        let (c0, c1) = (CoreCounters::default(), CoreCounters::default());
        tap.offer(0, 1, &[0xA0; 70], &c0);
        tap.offer(1, 2, &[0xB1; 70], &c1);
        tap.offer(2, 3, &[0xA2; 70], &c0); // core index 2 maps to slot 0
        assert_eq!(parts.rx.len(), 0);
        tap.flush(0, &c0);
        tap.flush(1, &c1);
        let b0 = parts.rx.try_recv().unwrap();
        let b1 = parts.rx.try_recv().unwrap();
        let firsts: Vec<u8> = [&b0, &b1].iter().map(|b| b.records().next().unwrap().3[0]).collect();
        assert_eq!(firsts, vec![0xA0, 0xB1]);
        assert_eq!((b0.len(), b1.len()), (2, 1));
    }

    #[test]
    fn a_busy_core_slot_is_never_waited_for() {
        let cx = ctx(CaptureLimits::default());
        let (tap, parts) = new_pcap(PcapCfg::default(), cx.budget.clone(), 1);
        let c = CoreCounters::default();
        let held = tap.slots[0].0.lock().unwrap(); // another thread "inside" this core
        tap.offer(0, 1, &[1; 70], &c); // must return at once, not block
        drop(held);
        assert_eq!(CoreCounters::get(&c.pcap_drop_queue), 1);
        assert_eq!(parts.rx.len(), 0);
    }

    /// Two capture threads and the writer running at the same time: every offered
    /// packet is either in a file exactly once or counted as dropped, and each core's
    /// packets keep their order. This is the property the batching must not break.
    fn two_producers_case(pool_slots: usize) -> (u64, u64) {
        let dir = tmpdir("conc");
        let cx = ctx(CaptureLimits { rotate_bytes: 8 * 1024 * 1024, max_total_bytes: u64::MAX });
        let (tap, parts) = new_pcap(PcapCfg { snaplen: 64, pool_slots }, cx.budget.clone(), 2);
        let tap = Arc::new(tap);
        let stop = Arc::new(AtomicBool::new(false));
        let writer = {
            let (cx, dir, stop) = (cx.clone(), dir.clone(), stop.clone());
            std::thread::spawn(move || run_pcap_writer(parts, &dir, &cx, &stop))
        };
        const N: u32 = 150_000;
        let producers: Vec<_> = (0..2usize)
            .map(|core| {
                let tap = tap.clone();
                std::thread::spawn(move || {
                    let c = CoreCounters::default();
                    for i in 0..N {
                        // payload = [core, i as 4 bytes], padded to 70 B so snaplen 64 cuts it
                        let mut f = [0u8; 70];
                        f[0] = core as u8;
                        f[1..5].copy_from_slice(&i.to_be_bytes());
                        tap.offer(core, i as u64 * 7, &f, &c);
                    }
                    tap.flush(core, &c);
                    (CoreCounters::get(&c.pcap_drop_pool), CoreCounters::get(&c.pcap_drop_queue))
                })
            })
            .collect();
        let mut dropped = 0u64;
        for h in producers {
            let (pool, queue) = h.join().unwrap();
            assert_eq!(queue, 0, "the queue has room for every batch; only the pool can run dry");
            dropped += pool;
        }
        stop.store(true, Relaxed);
        let written = writer.join().unwrap().unwrap();
        assert_eq!(written + dropped, 2 * N as u64, "every packet is written or counted");
        let mut last = [None::<u32>; 2];
        let mut seen = 0u64;
        for f in files_in(&dir) {
            let (_, recs) = read_pcap(&f);
            for r in recs {
                let (core, i) = (r.4[0] as usize, u32::from_be_bytes([r.4[1], r.4[2], r.4[3], r.4[4]]));
                assert_eq!((r.2, r.3), (64, 70));
                if let Some(prev) = last[core] {
                    assert!(i > prev, "core {core}: {i} after {prev}");
                }
                last[core] = Some(i);
                seen += 1;
            }
        }
        assert_eq!(seen, written);
        let _ = std::fs::remove_dir_all(&dir);
        (written, dropped)
    }

    /// Pool far smaller than the burst: the writer cannot keep up, most packets are dropped.
    /// Whatever is written must still be exact, in order, and the rest must be counted.
    #[test]
    fn two_producers_and_a_slow_writer_count_every_drop_and_keep_per_core_order() {
        let (written, dropped) = two_producers_case(512);
        assert!(written > 0 && dropped > 0, "the test is meant to exercise both paths: {written} written, {dropped} dropped");
    }

    /// Pool big enough for the whole burst: nothing may be lost.
    #[test]
    fn two_producers_and_a_writer_with_room_lose_nothing() {
        let (written, dropped) = two_producers_case(400_000);
        assert_eq!((written, dropped), (300_000, 0));
    }

    #[test]
    fn a_vanished_writer_counts_every_packet_of_the_batch() {
        let cx = ctx(CaptureLimits::default());
        let (tap, parts) = new_pcap(PcapCfg::default(), cx.budget.clone(), 1);
        let c = CoreCounters::default();
        drop(parts); // the writer (the only receiver of the queue) is gone
        for i in 0..BATCH_RECS as u64 {
            tap.offer(0, i, &[1; 70], &c);
        }
        assert_eq!(CoreCounters::get(&c.pcap_drop_queue), BATCH_RECS as u64);
    }

    #[test]
    fn clamping_keeps_snaplen_and_pool_sane() {
        let c = PcapCfg { snaplen: 1, pool_slots: 0 }.clamped();
        assert_eq!((c.snaplen, c.pool_slots), (MIN_SNAPLEN, 16));
        let c = PcapCfg { snaplen: 1 << 30, pool_slots: usize::MAX }.clamped();
        assert_eq!((c.snaplen, c.pool_slots), (MAX_SNAPLEN, 4_000_000));
        assert_eq!(PcapCfg::default().pool_bytes(), (16 + 128) * 16_384);
    }

    #[test]
    fn rotating_header_is_charged_to_the_budget_and_limit_before_first_record_is_clean() {
        let dir = tmpdir("hdr");
        let cx = ctx(CaptureLimits { rotate_bytes: 1000, max_total_bytes: 10 });
        // 24 B header cannot be reserved: the writer must not panic and must report the limit
        let d2 = dir.clone();
        let mut r = Rotating::open(Box::new(move |n| d2.join(format!("f{n}.bin"))), pcap_global_header(128), FileKind::Pcap, &cx).unwrap();
        assert_eq!(r.put(&[b"abc"]).unwrap(), Put::LimitReached);
        assert!(!cx.budget.is_open());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
