#!/usr/bin/env python3
"""Independent check of the Stage-2 metrics: recompute them from packets.csv, compare with the
line protocol the Rust exporter wrote.

    demo_capture OUT_DIR --stage2 OUT_DIR/metrics.lp          # synthetic call, real pipeline + exporter
    python3 -I tools/verify_metrics.py OUT_DIR/packets.csv OUT_DIR/metrics.lp

Python 3 standard library only.  Exit code 0 = every number matched, 1 = at least one mismatch.

WHY this exists
  The Rust code computes the metrics ONLINE (one pass, bounded memory, state per stream).  This
  script computes them OFFLINE from the per-packet CSV with the whole capture in memory, written from
  the rules in STAGE2_DESIGN.md and not from the Rust source: sets instead of a 128-bit bitmap for
  reordering, list-based population standard deviation instead of Welford/Chan merging, interval
  merging instead of an incremental session state machine.  A bug that lives in only one of the two
  implementations shows up as a mismatch.  (It does NOT validate the rules themselves against real
  Zoom traffic; that needs a campus capture.)

WHAT is compared, per (client, 5 s bin)
  * the line type: session_metrics (an open media session) or client_no_media;
  * volume: pps and bitrate of every group (video, audio, screen, screen13, screen30, fec, rtcp, other,
    nohdr, type21, unq_*, nonmedia, unq_media), totals, bin_cover_s;
  * per-stream metrics, aggregated: fps, frame gap sigma, RFC 3550 jitter, stalls, retransmissions,
    FEC share, degraded, uplink loss, downlink sequence gaps, audio activity, screen frames / FPS,
    capture-missing (SFU counter), share_active, session_age_s;
  * the `zoom_rtp_stream` lines one by one;
  * sessions: start, end, bins, bytes, had_*, and that two sessions never share an id;
  * hub counters in capture_health: rtp_qualified, rtp_failed_qual, rtp_probation_skipped.

THE RULES (what the script implements; the numbers in brackets are the Rust constants)
  qualification   a media-typed packet whose RTP version is 2 belongs to a stream (client, direction,
                  type byte, payload type, SSRC).  The FIRST packet of a stream is only a sighting
                  (counted as unq_*); a second sighting within 5 s creates the stream.  It qualifies at
                  its 20th counted packet if >= 90 % of the sequence steps are forward by 1..100; after
                  64 packets without qualifying it has failed.  Held packets are released into the
                  bin in which the stream qualifies, failed ones become unq_* of the failing bin.
  loss            thesis rule with reordering: a skipped number counts as lost, taken back when it
                  arrives late (128-number window); forward jump over 1000 (RTP) / 100 (SFU) = resync.
  frame           a new RTP timestamp not among the last 8; gap = difference of the LAST packet
                  arrival of consecutive frames, known when the next frame starts and counted in
                  the bin of that next frame's first packet.
  jitter          RFC 3550 at frame level: D = gap_ms - dts/90, J += (|D| - J)/16, dts in 1500..90000.
  stall           gap > 200 ms with a forward timestamp (video only).
  session         per client IP, starts at the first qualified media packet (either direction; the
                  stream's first sighting counts), ends 120 s after the last one.
  type-13 gate    (p7b) a type-13 packet carries RTP only if media byte 7 == 0x1e.  The CSV column `media_b7`
                  holds that byte.  0x15 = probe padding in a Type-13 envelope (group t13_probe), any other value
                  = control (group t13_ctrl); both are counted instead of being read as RTP, whatever the packet's
                  `rtp_*` cells say.  This script applies the rule ITSELF from `media_b7` rather than trusting the
                  empty RTP cells, so a Rust gate that stopped working (cells filled again) is a mismatch here.
                  What stays `unq_screen` is the RTP-shaped remainder: byte 7 == 0x1e but the packet is not a
                  qualified stream member (first sightings, short packets, failed streams).
  not checked     the video layout rule (media byte 20 -> RTP offset +24 / +28 / +20): the `rtp_*` cells are taken as
                  written.  That rule is checked by tools/validate_rtp_csv.py (position-independent statistics) and
                  by the Rust unit tests.
"""
import argparse
import csv
import ipaddress
import math
import statistics
import struct
import sys
from collections import defaultdict, deque

BIN_US = 5_000_000
GAP_US = 120_000_000
PROB_TTL_US = 5_000_000
QUAL_MIN, QUAL_GIVE_UP, QUAL_FWD, QUAL_STEP = 20, 64, 0.9, 100
RTP_JUMP, SFU_JUMP, WINDOW = 1000, 100, 128
STALL_US = 200_000
MIN_TICKS, MAX_TICKS = 1500, 90_000
AUDIO_ACTIVE = 20
FEC_PT = 110
MIN_FPS_COVER_S, FULL_COVER_S, DEGRADED_FPS = 1.0, 4.0, 15.0
MEDIA_CLASSES = ("video", "audio", "screen")
DIRS = ("uplink", "downlink")
GROUPS = ["video", "audio", "screen", "screen13", "screen30", "fec", "rtcp", "other", "nohdr", "type21",
          "unq_video", "unq_audio", "unq_screen", "t13_probe", "t13_ctrl", "nonmedia", "unq_media"]
T13_SUBTYPE_RTP, T13_SUBTYPE_PROBE = 0x1E, 0x15


def f32(x):
    return struct.unpack("f", struct.pack("f", x))[0]


def norm_ip(s):
    return ipaddress.ip_address(s).compressed


# ------------------------------------------------------------------------------ input

def to_int(s, base=10):
    s = (s or "").strip()
    if not s:
        return 0
    return int(s, 16) if s.startswith("0x") else int(s, base)


def load_rows(path):
    rows = []
    base_ns = None
    with open(path, newline="") as fh:
        rd = csv.DictReader(fh)
        if "media_b7" not in (rd.fieldnames or []):
            sys.exit(f"{path}: no media_b7 column; this CSV predates p7b. Regenerate it with the p7b demo_capture "
                     "(the column is what the type-13 sub-type rule is checked against).")
        for n, d in enumerate(rd):
            if d["dup"] != "0":
                continue
            up = d["dir"] == "up"
            t = round(float(d["time_offset_s"]) * 1e6)
            if base_ns is None and d.get("arrival_epoch_ns"):
                base_ns = int(d["arrival_epoch_ns"]) - t * 1000
            cls = d["class"]
            rows.append(dict(
                n=n, t=t, plen=int(d["udp_len"]) - 8, dir=0 if up else 1,
                client=norm_ip(d["src_ip"] if up else d["dst_ip"]),
                cport=int(d["src_port"] if up else d["dst_port"]),
                cls=cls, ty=to_int(d["media_type_byte"]), sfu=to_int(d["sfu_seq"]), has_sfu=cls != "nohdr",
                ssrc=to_int(d["rtp_ssrc"]), rts=to_int(d["rtp_timestamp"]), rseq=to_int(d["rtp_seq"]),
                pt=to_int(d["rtp_pt"]), ver_ok=d["rtp_ver_ok"] == "1",
                b7=int(d["media_b7"]) if d["media_b7"].strip() else None))
    rows.sort(key=lambda r: (r["t"], r["n"]))
    return rows, base_ns or 0


def split_fields(s):
    """Split a field set on the commas OUTSIDE double quotes (a string field may contain commas)."""
    out, cur, q = [], [], False
    for ch in s:
        if ch == '"':
            q = not q
        if ch == "," and not q:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def parse_lp(path):
    """-> list of dict(meas, tags, fields, ts) in file order; '#' lines carry nothing we need."""
    out = []
    with open(path) as fh:
        for ln in fh:
            ln = ln.rstrip("\n")
            if not ln or ln.startswith("#"):
                continue
            head, fields, ts = ln.rsplit(" ", 2)
            parts = head.split(",")
            tags = dict(p.split("=", 1) for p in parts[1:])
            f = {}
            for kv in split_fields(fields):
                k, v = kv.split("=", 1)
                if v.startswith('"'):
                    f[k] = v[1:-1]          # string field (p7b: capture_health.video_rtp20_bytes = "90,91")
                else:
                    f[k] = int(v[:-1]) if v.endswith("i") else float(v)
            out.append(dict(meas=parts[0], tags=tags, fields=f, ts=int(ts), raw=ln))
    return out


# ---------------------------------------------------------------- sequence rules (sets, not bitmaps)

class SeqSet:
    def __init__(self, cap):
        self.cap = cap
        self.highest = None
        self.recent = set()

    def step(self, seq):
        """-> ('first'|'fwd'|'jump'|'late'|'repeat'|'old', missing)"""
        if self.highest is None:
            self.highest, self.recent = seq, {seq}
            return "first", 0
        d = (seq - self.highest) & 0xFFFF
        if d >= 0x8000:
            d -= 0x10000
        if d > 0:
            if d > self.cap:
                self.highest, self.recent = seq, {seq}
                return "jump", 0
            self.highest = seq
            self.recent.add(seq)
            self.recent = {x for x in self.recent if ((self.highest - x) & 0xFFFF) < WINDOW}
            return "fwd", d - 1
        if d == 0:
            return "repeat", 0
        if -d >= WINDOW:
            return "old", 0
        if seq in self.recent:
            return "repeat", 0
        self.recent.add(seq)
        return "late", 0


# ------------------------------------------------------------------------------ one RTP stream

class Stream:
    def __init__(self, key, kind, first_us):
        self.key, self.kind, self.first_us = key, kind, first_us
        self.state = "prob"
        self.fed = self.fwd_ok = 0
        self.last_seq = None
        self.recs = []
        self.q_index = None
        self.q_bin = None
        self.seq = SeqSet(RTP_JUMP)
        # frames
        self.ring = deque(maxlen=8)
        self.cur_ts = self.prev_ts = None
        self.cur_end = self.last_end = None
        self.jitter = 0.0

    def feed(self, r):
        t = r["t"]
        rec = dict(t=t, bin=t // BIN_US, plen=r["plen"], sec=(t % BIN_US) // 1_000_000,
                   rx=0, lost=0, retx=0, frame=0, gap=None, stall=0)
        ev, miss = self.seq.step(r["rseq"])
        if ev in ("first", "jump"):
            rec["rx"] = 1
        elif ev == "fwd":
            rec["rx"], rec["lost"] = 1, miss
        elif ev == "late":
            rec["rx"], rec["lost"] = 1, -1
        elif ev == "repeat":
            rec["retx"] = 1
        if r["pt"] != FEC_PT and self.kind in ("video", "screen"):
            self.frame_step(r["rts"], t, rec)
        rec["jitter"] = f32(self.jitter)
        # qualification
        if self.fed > 0:
            d = (r["rseq"] - self.last_seq) & 0xFFFF
            if 1 <= d <= QUAL_STEP:
                self.fwd_ok += 1
        self.last_seq = r["rseq"]
        self.fed += 1
        self.recs.append(rec)
        if self.state == "prob":
            if self.fed >= QUAL_MIN and self.fwd_ok >= QUAL_FWD * (self.fed - 1):
                self.state, self.q_index, self.q_bin = "qual", len(self.recs) - 1, rec["bin"]
            elif self.fed >= QUAL_GIVE_UP:
                self.state = "failed"

    def frame_step(self, ts, t, rec):
        if self.cur_ts is not None and ts == self.cur_ts:
            self.cur_end = t
            return
        if ts in self.ring:
            return
        if self.cur_ts is not None:
            if self.last_end is not None:
                gap_us = self.cur_end - self.last_end
                dts = (self.cur_ts - self.prev_ts) & 0xFFFFFFFF
                if self.kind == "video":
                    if 0 < dts < 0x80000000 and gap_us > STALL_US:
                        rec["stall"] = 1
                    if MIN_TICKS <= dts <= MAX_TICKS:
                        gap_ms = gap_us / 1000.0
                        rec["gap"] = gap_ms
                        d = gap_ms - dts / 90.0
                        self.jitter += (abs(d) - self.jitter) / 16.0
            self.last_end = self.cur_end
            self.prev_ts = self.cur_ts
        self.cur_ts, self.cur_end = ts, t
        self.ring.append(ts)
        rec["frame"] = 1


# ------------------------------------------------------------------------------ classification

def classify(rows):
    """-> vol units, stream records (per stream and accounting bin), SFU units, counters."""
    streams, prob = {}, {}
    vol = []            # (client, dir, bin, group, pkts, bytes, first, last)
    skipped = 0

    def unq(r, grp=None):
        g = grp or "unq_" + r["cls"]
        vol.append((r["client"], r["dir"], r["t"] // BIN_US, g, 1, r["plen"], r["t"], r["t"]))

    def flush_unq(st, bin_):
        recs = st.recs
        grp = "unq_" + st.kind
        vol.append((st.key[0], st.key[1], bin_, grp, len(recs), sum(x["plen"] for x in recs),
                    st.first_us, max(x["t"] for x in recs)))

    for r in rows:
        cls = r["cls"]
        if cls == "screen" and r["ty"] == 13 and r["b7"] != T13_SUBTYPE_RTP:
            # p7b gate: not RTP, whatever the rtp cells say (b7 None = packet too short to hold byte 7 -> control)
            unq(r, "t13_probe" if r["b7"] == T13_SUBTYPE_PROBE else "t13_ctrl")
        elif cls in MEDIA_CLASSES and r["ver_ok"]:
            key = (r["client"], r["dir"], r["ty"], r["pt"], r["ssrc"])
            st = streams.get(key)
            if st is None:
                s0 = prob.get(key)
                if s0 is not None and r["t"] - s0 <= PROB_TTL_US:
                    del prob[key]
                    st = streams[key] = Stream(key, cls, s0)
                else:
                    prob[key] = r["t"]
                    skipped += 1
                    unq(r)
                    continue
            elif st.state == "failed":
                unq(r)
                continue
            st.feed(r)
            if st.state == "failed":
                flush_unq(st, r["t"] // BIN_US)
        elif cls in MEDIA_CLASSES:
            unq(r)
        elif cls == "rtcp":
            unq(r, "rtcp")
        elif cls == "nohdr":
            unq(r, "nohdr")
        else:
            unq(r, "type21" if r["ty"] == 21 else "other")
    qualified, failed = 0, 0
    recs = []           # per stream and accounting bin
    for st in streams.values():
        if st.state == "failed":
            failed += 1
        elif st.state == "prob":
            flush_unq(st, st.recs[-1]["bin"])
        else:
            qualified += 1
            groups = {}
            for i, x in enumerate(st.recs):
                b = st.q_bin if i <= st.q_index else x["bin"]
                groups.setdefault(b, []).append(x)
            for n, (b, xs) in enumerate(sorted(groups.items())):
                gaps = [x["gap"] for x in xs if x["gap"] is not None]
                secs = [0] * 8
                for x in xs:
                    secs[min(x["sec"], 7)] += 1
                client, d, ty, pt, ssrc = st.key
                recs.append(dict(
                    client=client, dir=d, type=ty, pt=pt, ssrc=ssrc, kind=st.kind, bin=b,
                    pkts=len(xs), bytes=sum(x["plen"] for x in xs),
                    first=st.first_us if n == 0 else min(x["t"] for x in xs), last=max(x["t"] for x in xs),
                    frames=sum(x["frame"] for x in xs), rx=sum(x["rx"] for x in xs), lost=sum(x["lost"] for x in xs),
                    retx=sum(x["retx"] for x in xs), gaps=gaps, stalls=sum(x["stall"] for x in xs),
                    jitter=xs[-1]["jitter"], active=sum(1 for c in secs if c > AUDIO_ACTIVE) if st.kind == "audio" else 0))
    # SFU counter: one tracker per (client, client port, direction), the packet's own bin
    sfu = defaultdict(lambda: [0, 0])      # (client, dir, bin) -> [seen, missed]
    flows = {}
    for r in rows:
        if not r["has_sfu"]:
            continue
        tr = flows.setdefault((r["client"], r["cport"], r["dir"]), SeqSet(SFU_JUMP))
        ev, miss = tr.step(r["sfu"])
        a = sfu[(r["client"], r["dir"], r["t"] // BIN_US)]
        if ev in ("first", "jump"):
            a[0] += 1
        elif ev == "fwd":
            a[0] += 1
            a[1] += miss
        elif ev == "late":
            a[0] += 1
            a[1] -= 1
    return vol, recs, sfu, dict(qualified=qualified, failed=failed, skipped=skipped)


# ------------------------------------------------------------------------------ per (client, bin)

class Slot:
    def __init__(self):
        self.pkts = self.bytes = self.fec_pkts = self.fec_bytes = self.streams = self.frames = 0
        self.rx = self.lost = self.retx = self.stalls = 0
        self.fps, self.full, self.gaps = [], [], []
        self.jit_sum = self.jit_w = 0.0
        self.active = 0


class Wide:
    def __init__(self):
        self.vol = [defaultdict(lambda: [0, 0]), defaultdict(lambda: [0, 0])]
        self.slot = [defaultdict(Slot), defaultdict(Slot)]
        self.sfu = [[0, 0], [0, 0]]
        self.first = None
        self.last = 0
        self.mfirst = None
        self.mlast = 0
        self.streams = []

    def span(self, a, b):
        self.first = a if self.first is None else min(self.first, a)
        self.last = max(self.last, b)


def build_wides(vol, recs, sfu):
    W = defaultdict(Wide)
    for client, d, b, g, p, by, first, last in vol:
        w = W[(client, b)]
        v = w.vol[d][g]
        v[0] += p
        v[1] += by
        w.span(first, last)
    for x in recs:
        w = W[(x["client"], x["bin"])]
        d = x["dir"]
        w.span(x["first"], x["last"])
        w.mfirst = x["first"] if w.mfirst is None else min(w.mfirst, x["first"])
        w.mlast = max(w.mlast, x["last"])
        w.streams.append(x)
        name = "video" if x["kind"] == "video" else "audio" if x["kind"] == "audio" else ("s30" if x["type"] == 30 else "s13")
        m = w.slot[d][name]
        m.pkts += x["pkts"]
        m.bytes += x["bytes"]
        m.retx += x["retx"]
        if x["pt"] == FEC_PT:
            m.fec_pkts += x["pkts"]
            m.fec_bytes += x["bytes"]
            continue
        m.streams += 1
        m.frames += x["frames"]
        m.rx += x["rx"]
        m.lost += x["lost"]
        m.stalls += x["stalls"]
        m.gaps += x["gaps"]
        m.jit_sum += x["jitter"] * x["pkts"]
        m.jit_w += x["pkts"]
        m.active = max(m.active, x["active"])
        if x["kind"] != "audio":
            cover = (x["last"] - x["first"]) / 1e6
            if cover >= MIN_FPS_COVER_S:
                fps = x["frames"] / cover
                m.fps.append(fps)
                if cover >= FULL_COVER_S:
                    m.full.append(fps)
    for (client, d, b), (seen, missed) in sfu.items():
        w = W[(client, b)]
        w.sfu[d][0] += seen
        w.sfu[d][1] += missed
    return W


def pct(part, rest):
    p = max(part, 0)
    den = rest + p
    return 100.0 * p / den if den > 0 else None


def group_value(w, d, g):
    v = lambda n: tuple(w.vol[d][n]) if n in w.vol[d] else (0, 0)
    s = lambda n: w.slot[d][n] if n in w.slot[d] else Slot()
    add = lambda a, b: (a[0] + b[0], a[1] + b[1])
    m = lambda n: (s(n).pkts, s(n).bytes)
    f = lambda n: (s(n).fec_pkts, s(n).fec_bytes)
    return {
        "video": m("video"), "audio": m("audio"), "screen": add(m("s13"), m("s30")), "screen13": m("s13"), "screen30": m("s30"),
        "fec": add(add(f("video"), f("s13")), f("s30")),
        "rtcp": v("rtcp"), "other": v("other"), "nohdr": v("nohdr"), "type21": v("type21"),
        "unq_video": v("unq_video"), "unq_audio": v("unq_audio"), "unq_screen": v("unq_screen"),
        "t13_probe": v("t13_probe"), "t13_ctrl": v("t13_ctrl"),
        "nonmedia": add(add(v("rtcp"), v("other")), v("nohdr")),
        # p7b: unq_media keeps its p7a meaning (everything media-typed that is not a qualified stream member), so the
        # two type-13 groups that were part of unq_screen in p7a are added back
        "unq_media": add(add(add(add(v("unq_video"), v("unq_audio")), v("unq_screen")), v("t13_probe")), v("t13_ctrl")),
    }[g]


def expected_fields(w, bin_end_us, sess_first_us):
    """name -> (value, decimals); decimals None = integer.  Mirrors the field list of the exporter."""
    f = {}
    bs = BIN_US / 1e6

    def tot(d):
        p = b = 0
        for g in w.vol[d].values():
            p += g[0]
            b += g[1]
        for s in w.slot[d].values():
            p += s.pkts
            b += s.bytes
        return p, b

    for d in (0, 1):
        f[f"throughput_{DIRS[d]}_bps"] = (tot(d)[1] * 8 / bs, 1)
    for d in (0, 1):
        f[f"pps_{DIRS[d]}"] = (tot(d)[0] / bs, 2)
    for g in GROUPS:
        for d in (0, 1):
            f[f"{g}_bitrate_{DIRS[d]}_bps"] = (group_value(w, d, g)[1] * 8 / bs, 1)
        for d in (0, 1):
            f[f"{g}_pps_{DIRS[d]}"] = (group_value(w, d, g)[0] / bs, 2)
    f["bin_cover_s"] = (0.0 if w.first is None else (w.last - w.first) / 1e6, 3)
    if sess_first_us is None:
        return f
    f["session_age_s"] = ((bin_end_us - sess_first_us) / 1e6, 1)
    share = any(w.slot[d][n].streams > 0 for d in (0, 1) for n in ("s13", "s30") if n in w.slot[d])
    f["share_active"] = (int(share), None)
    for d in (0, 1):
        n = DIRS[d]
        S = lambda k: w.slot[d][k] if k in w.slot[d] else Slot()
        v, a, s13, s30 = S("video"), S("audio"), S("s13"), S("s30")
        f[f"video_streams_active_{n}"] = (v.streams, None)
        f[f"video_frames_{n}"] = (v.frames, None)
        if v.fps:
            f[f"fps_{n}"] = (sum(v.fps) / len(v.fps), 2)
        if len(v.gaps) >= 2:
            f[f"frame_gap_std_ms_{n}"] = (statistics.pstdev(v.gaps), 3)
        if v.jit_w > 0 and v.gaps:
            f[f"jitter_ms_{n}"] = (v.jit_sum / v.jit_w, 3)
        f[f"stalls_{n}"] = (v.stalls, None)
        f[f"retransmits_{n}"] = (v.retx + a.retx + s13.retx + s30.retx, None)
        if v.bytes > 0:
            f[f"fec_share_{n}"] = (v.fec_bytes / v.bytes, 4)
        if not share and v.full:
            f[f"degraded_{n}"] = (int(sum(v.full) / len(v.full) < DEGRADED_FPS), None)
            f[f"video_streams_degraded_{n}"] = (sum(1 for x in v.full if x < DEGRADED_FPS), None)
        p = pct(v.lost, v.rx)
        if p is not None:
            pn, cn, en = ("loss_pct", "lost_pkts", "expected_pkts") if d == 0 else ("seq_gap_pct", "seq_gap_pkts", "seq_expected_pkts")
            f[f"{pn}_{n}"] = (p, 3)
            f[f"{cn}_{n}"] = (max(v.lost, 0), None)
            f[f"{en}_{n}"] = (max(v.lost, 0) + v.rx, None)
        if a.streams > 0:
            f[f"audio_active_s_{n}"] = (a.active, None)
            p = pct(a.lost, a.rx)
            if p is not None:
                f[f"audio_seq_gap_pct_{n}"] = (p, 3)
        sn = s13.streams + s30.streams
        f[f"screen_streams_active_{n}"] = (sn, None)
        f[f"screen_frames_{n}"] = (s13.frames + s30.frames, None)
        fps = s13.fps + s30.fps
        if fps:
            f[f"screen_fps_{n}"] = (sum(fps) / len(fps), 2)
        seen, missed = w.sfu[d]
        if seen > 0:
            p = pct(missed, seen)
            name = "capture_missing" if d == 0 else "sfu_gap"
            if p is not None:
                f[f"{name}_pct_{n}"] = (p, 3)
                f[f"{name}_pkts_{n}"] = (max(missed, 0), None)
    return f


# ------------------------------------------------------------------------------ sessions

def plan_sessions(W):
    """Per client: merge the media intervals of the bins whose gap is <= 120 s (interval merging),
    then decide for every bin of the client whether it belongs to a session."""
    by_client = defaultdict(list)
    for (client, b), w in W.items():
        by_client[client].append(b)
    out_bin = {}        # (client, bin) -> session index or None
    sessions = []       # dict(client, first, last, bins, media_bins, ...)
    for client, bins in by_client.items():
        bins.sort()
        media = [(W[(client, b)].mfirst, W[(client, b)].mlast, b) for b in bins if W[(client, b)].mfirst is not None]
        groups = []
        for mf, ml, b in media:
            if groups and mf - groups[-1]["last"] <= GAP_US:
                groups[-1]["last"] = max(groups[-1]["last"], ml)
                groups[-1]["media_bins"].append(b)
            else:
                groups.append(dict(client=client, first=mf, last=ml, media_bins=[b], bins=[]))
        for g in groups:
            sessions.append(g)
        for b in bins:
            w = W[(client, b)]
            sess = None
            if w.mfirst is not None:
                for g in groups:
                    if b in g["media_bins"]:
                        sess = g
            else:
                # last media strictly before this bin
                best = None
                for g in groups:
                    ends = [W[(client, mb)].mlast for mb in g["media_bins"] if mb < b]
                    if ends and (best is None or max(ends) > best[0]):
                        best = (max(ends), g)
                if best and b * BIN_US - best[0] <= GAP_US:
                    sess = best[1]
            out_bin[(client, b)] = sess
            if sess is not None:
                sess["bins"].append(b)
    return out_bin, sessions


# ------------------------------------------------------------------------------ comparison

class Report:
    def __init__(self):
        self.checks = 0
        self.bad = []

    def eq(self, what, got, want, dec=None):
        self.checks += 1
        if dec is None:
            ok = got == want
        else:
            tol = 0.51 * 10 ** (-dec) + 2e-6 * abs(want)
            ok = abs(got - want) <= tol
        if not ok:
            self.bad.append(f"{what}: exporter {got!r}, recomputed {want!r}")

    def true(self, what, cond, detail=""):
        self.checks += 1
        if not cond:
            self.bad.append(f"{what} {detail}".strip())


def compare(rows, base_ns, lp, rep, verbose):
    vol, recs, sfu, cnt = classify(rows)
    W = build_wides(vol, recs, sfu)
    out_bin, sessions = plan_sessions(W)

    def pipe_us(ts):
        return (ts - base_ns) / 1e3

    def bin_of(ts):
        return round(pipe_us(ts) / BIN_US) - 1

    # ---- one line per (client, bin), of the right type
    lines = {}
    for L in lp:
        if L["meas"] in ("session_metrics", "client_no_media"):
            key = (norm_ip(L["tags"]["client_ip"]), bin_of(L["ts"]))
            rep.true(f"duplicate bin line {key}", key not in lines)
            lines[key] = L
    rep.true("set of (client, bin) lines", set(lines) == set(W),
             f"exporter-only {sorted(set(lines) - set(W))[:5]}, recomputed-only {sorted(set(W) - set(lines))[:5]}")
    sid_of_session = {}
    for key, w in sorted(W.items()):
        L = lines.get(key)
        if L is None:
            continue
        sess = out_bin[key]
        want_type = "session_metrics" if sess is not None else "client_no_media"
        rep.true(f"{key}: line type", L["meas"] == want_type, f"exporter {L['meas']}, recomputed {want_type}")
        if sess is not None and L["meas"] == "session_metrics":
            sid = L["tags"]["session_id"]
            prev = sid_of_session.setdefault(id(sess), sid)
            rep.true(f"{key}: all bins of one session carry one id", prev == sid, f"{prev} vs {sid}")
            sess["sid"] = sid
        first = sess["first"] if sess is not None else None
        want = expected_fields(w, (key[1] + 1) * BIN_US, first)
        have = L["fields"]
        rep.true(f"{key}: field set", set(want) == set(have), f"only exporter {sorted(set(have) - set(want))}, only recomputed {sorted(set(want) - set(have))}")
        for name, (val, dec) in want.items():
            if name in have:
                rep.eq(f"{key} {name}", have[name], val if dec is not None else int(val), dec)

    # ---- per-stream lines
    sl = defaultdict(list)
    for L in lp:
        if L["meas"] == "zoom_rtp_stream":
            t = L["tags"]
            sl[(norm_ip(t["client_ip"]), bin_of(L["ts"]), DIRS.index(t["direction"]), int(t["ssrc"], 16), int(t["pt"]), int(t["type"]))].append(L)
    want_streams = {}
    for (client, b), w in W.items():
        if out_bin[(client, b)] is None:
            continue
        for x in w.streams:
            want_streams[(client, b, x["dir"], x["ssrc"], x["pt"], x["type"])] = x
    rep.true("set of zoom_rtp_stream lines", set(sl) == set(want_streams),
             f"only exporter {sorted(set(sl) - set(want_streams))[:3]}, only recomputed {sorted(set(want_streams) - set(sl))[:3]}")
    for key, x in want_streams.items():
        if key not in sl:
            continue
        have = sl[key][0]["fields"]
        k = f"stream {key}"
        rep.eq(k + " packets", have["packets"], x["pkts"])
        rep.eq(k + " bytes", have["bytes"], x["bytes"])
        rep.eq(k + " lost_packets", have["lost_packets"], max(x["lost"], 0))
        p = pct(x["lost"], x["rx"])
        rep.true(k + " loss_pct present", (p is not None) == ("loss_pct" in have))
        if p is not None and "loss_pct" in have:
            rep.eq(k + " loss_pct", have["loss_pct"], p, 3)
        rep.eq(k + " throughput_bps", have["throughput_bps"], x["bytes"] * 8 / (BIN_US / 1e6), 1)
        cover = (x["last"] - x["first"]) / 1e6
        want_fps = x["kind"] != "audio" and cover >= MIN_FPS_COVER_S
        rep.true(k + " fps present", want_fps == ("fps" in have))
        if want_fps and "fps" in have:
            rep.eq(k + " fps", have["fps"], x["frames"] / cover, 2)
        rep.true(k + " frame_jitter present", (len(x["gaps"]) >= 2) == ("frame_jitter_ms" in have))
        if len(x["gaps"]) >= 2 and "frame_jitter_ms" in have:
            rep.eq(k + " frame_jitter_ms", have["frame_jitter_ms"], statistics.pstdev(x["gaps"]), 3)
        rep.true(k + " rfc3550 present", (len(x["gaps"]) > 0) == ("rfc3550_jitter_ms" in have))
        if x["gaps"] and "rfc3550_jitter_ms" in have:
            rep.eq(k + " rfc3550_jitter_ms", have["rfc3550_jitter_ms"], x["jitter"], 3)
        rep.eq(k + " stalls", have["stalls"], x["stalls"])
        rep.eq(k + " retransmits", have["retransmits"], x["retx"])

    # ---- sessions
    finals = {}
    for L in lp:
        if L["meas"] == "session_summary":
            finals[(norm_ip(L["tags"]["client_ip"]), L["tags"]["session_id"])] = L      # file order: the last write wins
    rep.true("number of sessions", len(finals) == len(sessions), f"exporter {len(finals)}, recomputed {len(sessions)}")
    rep.true("session ids are unique per (client, start)", len({k[1] for k in finals}) == len(finals))
    for sess in sessions:
        sid = sess.get("sid")
        L = finals.get((sess["client"], sid)) if sid else None
        if L is None:
            rep.true(f"session of {sess['client']} at {sess['first']}", False, "no session_summary found")
            continue
        h = L["fields"]
        k = f"session {sess['client']} @ {sess['first'] / 1e6:.3f}s"
        rep.true(k + " start", abs(pipe_us(h["start_epoch_ns"]) - sess["first"]) < 500_000, f"{pipe_us(h['start_epoch_ns'])} vs {sess['first']}")
        rep.true(k + " end", abs(pipe_us(h["end_epoch_ns"]) - sess["last"]) < 500_000, f"{pipe_us(h['end_epoch_ns'])} vs {sess['last']}")
        rep.eq(k + " duration_s", h["duration_s"], (sess["last"] - sess["first"]) / 1e6, 1)
        bins = sorted(set(sess["bins"]))
        rep.eq(k + " bins", h["bins"], len(bins))
        rep.eq(k + " media_bins", h["media_bins"], len(sess["media_bins"]))
        ws = [W[(sess["client"], b)] for b in bins]
        up = sum(sum(g[1] for g in w.vol[0].values()) + sum(s.bytes for s in w.slot[0].values()) for w in ws)
        dn = sum(sum(g[1] for g in w.vol[1].values()) + sum(s.bytes for s in w.slot[1].values()) for w in ws)
        rep.eq(k + " bytes_uplink", h["bytes_uplink"], up)
        rep.eq(k + " bytes_downlink", h["bytes_downlink"], dn)
        mw = [W[(sess["client"], b)] for b in sess["media_bins"]]
        has = lambda w, n: any(w.slot[d][n].pkts > 0 for d in (0, 1) if n in w.slot[d])
        vb = sum(1 for w in mw if has(w, "video"))
        ab = sum(1 for w in mw if has(w, "audio"))
        sb = sum(1 for w in mw if any(w.slot[d][n].streams > 0 for d in (0, 1) for n in ("s13", "s30") if n in w.slot[d]))
        rep.eq(k + " video_bins", h["video_bins"], vb)
        rep.eq(k + " audio_bins", h["audio_bins"], ab)
        rep.eq(k + " screen_bins", h["screen_bins"], sb)
        rep.eq(k + " had_video", h["had_video"], int(vb > 0))
        rep.eq(k + " had_audio", h["had_audio"], int(ab > 0))
        rep.eq(k + " had_screen", h["had_screen"], int(sb > 0))

    # ---- hub counters
    health = [L for L in lp if L["meas"] == "capture_health"]
    if health:
        h = health[-1]["fields"]
        rep.eq("capture_health rtp_qualified", h.get("rtp_qualified"), cnt["qualified"])
        rep.eq("capture_health rtp_failed_qual", h.get("rtp_failed_qual"), cnt["failed"])
        rep.eq("capture_health rtp_probation_skipped", h.get("rtp_probation_skipped"), cnt["skipped"])
        rep.eq("capture_health matched = unique packets in the CSV", h.get("matched"), len(rows))
    if verbose:
        print(f"unique packets {len(rows)}, streams qualified {cnt['qualified']} failed {cnt['failed']}, sightings {cnt['skipped']}, "
              f"(client,bin) lines {len(W)}, sessions {len(sessions)}")
    return len(rows), len(W), len(sessions)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("csv")
    ap.add_argument("lp")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    rows, base_ns = load_rows(a.csv)
    lp = parse_lp(a.lp)
    rep = Report()
    n, nb, ns = compare(rows, base_ns, lp, rep, a.verbose)
    print(f"verify_metrics: {n} unique packets, {nb} (client, bin) lines, {ns} sessions, {rep.checks} comparisons")
    if rep.bad:
        print(f"MISMATCH: {len(rep.bad)}")
        for m in rep.bad[:40]:
            print("  " + m)
        if len(rep.bad) > 40:
            print(f"  ... and {len(rep.bad) - 40} more")
        sys.exit(1)
    print("PASS: every recomputed number matches the exporter")


if __name__ == "__main__":
    main()
