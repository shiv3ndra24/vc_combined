//! HttpSink and the whole exporter against a local mock of InfluxDB's
//! `/api/v2/write`. Real InfluxDB is still to be tested on campus; this
//! checks our side of the HTTP exchange: request shape, status handling,
//! retries, outage behaviour, and an end-to-end run (frames in, line
//! protocol out of the HTTP server).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zoom_pipeline::export::{run_exporter, ExportCfg, ExportStats, HttpSink, Sink};
use zoom_pipeline::ipset::IpSet;
use zoom_pipeline::net::build::{frame, Spec};
use zoom_pipeline::net::Addr;
use zoom_pipeline::pipeline::{Pipeline, PipelineConfig};

#[derive(Clone, Debug)]
struct Req {
    request_line: String,
    auth: String,
    content_type: String,
    body: String,
}

/// Minimal HTTP/1.1 server. `script(n)` returns (status, delay) for the nth request.
struct Mock {
    addr: String,
    reqs: Arc<Mutex<Vec<Req>>>,
    stop: Arc<AtomicBool>,
}

impl Mock {
    fn start(script: impl Fn(usize) -> (u16, Duration) + Send + Sync + 'static) -> Mock {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let reqs = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (r2, s2) = (reqs.clone(), stop.clone());
        let n = Arc::new(AtomicUsize::new(0));
        let script = Arc::new(script);
        std::thread::spawn(move || {
            while !s2.load(Ordering::Relaxed) {
                match l.accept() {
                    Ok((s, _)) => {
                        let (r3, n, script) = (r2.clone(), n.clone(), script.clone());
                        std::thread::spawn(move || handle(s, r3, n, script));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Mock { addr, reqs, stop }
    }
    fn url(&self) -> String {
        format!("http://{}/api/v2/write?org=teams&bucket=qoe&precision=ns", self.addr)
    }
    fn requests(&self) -> Vec<Req> {
        self.reqs.lock().unwrap().clone()
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn handle(mut s: TcpStream, reqs: Arc<Mutex<Vec<Req>>>, n: Arc<AtomicUsize>, script: Arc<dyn Fn(usize) -> (u16, Duration) + Send + Sync>) {
    s.set_nonblocking(false).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // keep-alive: serve requests until the client closes
    loop {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let head_end;
        loop {
            match s.read(&mut tmp) {
                Ok(0) | Err(_) => return,
                Ok(k) => buf.extend_from_slice(&tmp[..k]),
            }
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                head_end = p + 4;
                break;
            }
        }
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let mut clen = 0usize;
        let (mut auth, mut ctype) = (String::new(), String::new());
        for l in head.lines() {
            let low = l.to_ascii_lowercase();
            if let Some(v) = low.strip_prefix("content-length:") {
                clen = v.trim().parse().unwrap_or(0);
            }
            if low.starts_with("authorization:") {
                auth = l["authorization:".len()..].trim().to_string();
            }
            if low.starts_with("content-type:") {
                ctype = l["content-type:".len()..].trim().to_string();
            }
        }
        while buf.len() < head_end + clen {
            match s.read(&mut tmp) {
                Ok(0) | Err(_) => return,
                Ok(k) => buf.extend_from_slice(&tmp[..k]),
            }
        }
        let body = String::from_utf8_lossy(&buf[head_end..head_end + clen]).to_string();
        let idx = n.fetch_add(1, Ordering::SeqCst);
        reqs.lock().unwrap().push(Req { request_line: head.lines().next().unwrap_or("").to_string(), auth, content_type: ctype, body });
        let (status, delay) = script(idx);
        std::thread::sleep(delay);
        let (text, payload) = match status {
            204 => ("No Content", String::new()),
            401 => ("Unauthorized", r#"{"code":"unauthorized","message":"unauthorized access"}"#.into()),
            400 => ("Bad Request", r#"{"code":"invalid","message":"unable to parse"}"#.into()),
            _ => ("Server Error", r#"{"code":"internal error"}"#.into()),
        };
        let resp = format!("HTTP/1.1 {status} {text}\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{payload}", payload.len());
        if s.write_all(resp.as_bytes()).is_err() {
            return;
        }
    }
}

#[test]
fn request_shape_and_success() {
    let m = Mock::start(|_| (204, Duration::ZERO));
    let mut sink = HttpSink::new(m.url(), "tok123".into());
    sink.send("a,b=c x=1i 1\na,b=d x=2i 2\n").unwrap();
    let r = &m.requests()[0];
    assert!(r.request_line.starts_with("POST /api/v2/write?org=teams&bucket=qoe&precision=ns"), "{}", r.request_line);
    assert_eq!(r.auth, "Token tok123");
    assert!(r.content_type.starts_with("text/plain"));
    assert_eq!(r.body, "a,b=c x=1i 1\na,b=d x=2i 2\n");
}

#[test]
fn status_classification() {
    let m = Mock::start(|n| (match n { 0 => 500, 1 => 401, 2 => 400, _ => 204 }, Duration::ZERO));
    let mut sink = HttpSink::new(m.url(), "t".into());
    let e = sink.send("x").unwrap_err();
    assert!(e.retryable, "500 is retryable: {e:?}");
    let e = sink.send("x").unwrap_err();
    assert!(!e.retryable && e.msg.contains("401"), "401 is not retryable: {e:?}");
    let e = sink.send("x").unwrap_err();
    assert!(!e.retryable && e.msg.contains("400"), "400 is not retryable: {e:?}");
    sink.send("x").unwrap();
}

#[test]
fn connection_refused_is_retryable_and_fast() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/api/v2/write", l.local_addr().unwrap());
    drop(l); // nothing listens
    let mut sink = HttpSink::new(url, "t".into());
    let t = Instant::now();
    let e = sink.send("x").unwrap_err();
    assert!(e.retryable, "{e:?}");
    assert!(t.elapsed() < Duration::from_secs(3));
}

#[test]
fn server_slower_than_the_timeout_is_a_retryable_error_not_a_hang() {
    let m = Mock::start(|_| (204, Duration::from_secs(7)));
    let mut sink = HttpSink::new(m.url(), "t".into());
    let t = Instant::now();
    let e = sink.send("x").unwrap_err();
    assert!(e.retryable, "{e:?}");
    assert!(t.elapsed() < Duration::from_secs(6), "read timeout is 5 s: took {:?}", t.elapsed());
}

fn zoom_frame(client: u8, seq: u16) -> Vec<u8> {
    let mut p = vec![0u8; 900];
    p[0] = 5;
    p[1..3].copy_from_slice(&seq.to_be_bytes()); // SFU counter
    p[7] = 0;
    p[8] = 16;
    p[17..19].copy_from_slice(&seq.to_be_bytes());
    p[19..23].copy_from_slice(&(seq as u32 * 3000).to_be_bytes());
    // a real RTP header where the deck puts it for video (SFU header 8 + media offset 24): V=2, PT 98, SSRC per client
    p[32] = 0x80;
    p[33] = 98;
    p[34..36].copy_from_slice(&seq.to_be_bytes());
    p[36..40].copy_from_slice(&(seq as u32 * 3000).to_be_bytes());
    p[40..44].copy_from_slice(&(0x1000 + client as u32).to_be_bytes());
    frame(&Spec::new(Addr::from_v4([10, 184, 0, client]), Addr::from_v4([170, 114, 107, 187]), 50000, 8801, &p))
}

/// frames in -> pipeline -> exporter -> HTTP -> mock server body
#[test]
#[cfg(feature = "dedup")] // the frames include mirror twins
fn end_to_end_over_http() {
    let m = Mock::start(|_| (204, Duration::ZERO));
    let b = Pipeline::new(PipelineConfig { shards: 2, ..Default::default() }, IpSet::zoom_default());
    let p = b.pipeline;
    let st = Arc::new(ExportStats::default());
    let (st2, start) = (st.clone(), p.start());
    let sink = HttpSink::new(m.url(), "tok".into());
    let h = std::thread::spawn(move || run_exporter(b.export_rx, Box::new(sink), ExportCfg { host: "t1".into(), ..Default::default() }, start, st2));
    // 3 clients x 3 virtual bins x 25 packets (10 ms apart, so every stream qualifies inside bin 0),
    // plus a second copy of each packet. The first packet of each stream is only a probation
    // sighting: it is counted, but as unq_video, not as video.
    let mut want_bytes = 0u64;
    for bin in 0..3u64 {
        for c in 1..=3u8 {
            for k in 0..25u16 {
                let t = bin * 5_000_000 + 100_000 + k as u64 * 10_000;
                let f = zoom_frame(c, (bin * 100 + k as u64) as u16 + c as u16 * 1000);
                p.on_frame_at((c % 2) as usize, t, &f);
                p.on_frame_at((c % 2) as usize, t + 12, &f); // twin
                want_bytes += 900;
            }
        }
    }
    let unq_first = 3 * 900; // one sighting per client
    p.sweep_once(30_000_000);
    p.shutdown();
    h.join().unwrap();
    let all: String = m.requests().iter().map(|r| r.body.clone()).collect();
    let metrics: Vec<&str> = all.lines().filter(|l| l.starts_with("session_metrics")).collect();
    assert_eq!(metrics.len(), 9, "3 clients x 3 bins:\n{all}");
    assert_eq!(all.lines().filter(|l| l.starts_with("client_no_media")).count(), 0, "every bin has media");
    // sum of uplink video bytes over all lines = everything but the three sighting packets (twins removed)
    let field_sum = |name: &str| -> f64 {
        metrics.iter().map(|l| l.split(&format!(",{name}=")).nth(1).unwrap().split(',').next().unwrap().parse::<f64>().unwrap()).sum::<f64>() * 5.0 / 8.0
    };
    let (got, got_unq) = (field_sum("video_bitrate_uplink_bps"), field_sum("unq_video_bitrate_uplink_bps"));
    assert!((got - (want_bytes - unq_first) as f64).abs() < 10.0, "got {got} want {}", want_bytes - unq_first);
    assert!((got_unq - unq_first as f64).abs() < 10.0, "unq_video {got_unq} want {unq_first}");
    // one session per client, and it starts at that client's first media packet (100 ms into bin 0)
    let sums: std::collections::BTreeSet<&str> = all.lines().filter(|l| l.starts_with("session_summary")).map(|l| l.split(',').nth(2).unwrap()).collect();
    assert_eq!(sums.len(), 3, "{all}");
    assert!(all.contains("capture_health,host=t1,engine=zoom pkts_in=450i"), "{}", all.lines().filter(|l| l.starts_with("capture_health")).collect::<Vec<_>>().join("\n"));
    assert!(all.contains("dups_dropped=225i"));
    assert_eq!(st.lines_dropped.load(Ordering::Relaxed), 0);
    assert!(m.requests().iter().all(|r| r.auth == "Token tok"));
}

#[test]
fn influx_outage_then_recovery_loses_only_what_the_retry_budget_cannot_cover() {
    use zoom_pipeline::export::run_exporter_clocked;
    // First 5 requests fail with 503, later ones succeed. Retry budget is 3 (4 attempts per batch).
    let m = Mock::start(|n| (if n < 5 { 503 } else { 204 }, Duration::ZERO));
    let b = Pipeline::new(PipelineConfig { shards: 1, ..Default::default() }, IpSet::zoom_default());
    let p = b.pipeline;
    let st = Arc::new(ExportStats::default());
    let vnow = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (st2, start, vn) = (st.clone(), p.start(), vnow.clone());
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(move || vn.load(Ordering::Relaxed));
    let sink = HttpSink::new(m.url(), "t".into());
    let cfg = ExportCfg { backoff_start: Duration::from_millis(10), backoff_max: Duration::from_millis(40), flush_every: Duration::from_millis(50), settle_us: 1_000, ..Default::default() };
    let h = std::thread::spawn(move || run_exporter_clocked(b.export_rx, Box::new(sink), cfg, start, st2, clock));
    // bin 0, client 1: its batch meets 4 consecutive 503s (requests 0..3) and is dropped
    for k in 0..10u16 {
        p.on_frame_at(0, 100_000 + k as u64 * 1000, &zoom_frame(1, k));
    }
    p.sweep_once(6_000_000);
    vnow.store(10_000_000, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(st.batches_failed.load(Ordering::Relaxed), 1, "first batch dropped after its retry budget");
    assert_eq!(st.retries.load(Ordering::Relaxed), 3);
    // bin 1, client 2: request 4 is the last 503, request 5 succeeds on the first retry
    for k in 0..10u16 {
        p.on_frame_at(0, 5_100_000 + k as u64 * 1000, &zoom_frame(2, 100 + k));
    }
    p.sweep_once(12_000_000);
    vnow.store(20_000_000, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(st.batches_ok.load(Ordering::Relaxed), 1, "exporter must recover when the server comes back");
    p.shutdown();
    h.join().unwrap();
    let ok_bodies: String = m.requests().iter().skip(5).map(|r| r.body.clone()).collect();
    assert!(ok_bodies.contains("client_ip=10.184.0.2"), "data produced after recovery must arrive:\n{ok_bodies}");
    // the dropped bin is gone for good (bounded memory), but the session summary (an upsert) still arrives
    assert!(!ok_bodies.lines().any(|l| l.starts_with("session_metrics") && l.contains("client_ip=10.184.0.1,")), "dropped batch must not be resent forever");
    assert!(st.lines_dropped.load(Ordering::Relaxed) >= 1);
}
