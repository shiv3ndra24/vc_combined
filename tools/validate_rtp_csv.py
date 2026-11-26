#!/usr/bin/env python3
"""Check that the RTP offsets in a zoom_capture packet CSV are right (v2.2, p7b).

Run it once on a campus capture, BEFORE any RTP-based metric is built:

    python3 -I tools/validate_rtp_csv.py packets.csv [--pcap pcap_dir_or_file]

Python 3 standard library only.  Reads the CSV as a stream (a few hundred MB
is fine), keeps small per-stream state, and never prints an IP address, so the
text report can be pasted into a chat or an email on its own (clients are
shown as client#1, client#2, ... by traffic volume).

WHY these checks (and not just "the RTP version bits are 2"):
  The version field is two bits, so wrong bytes still look like "version 2"
  one time in four.  Real RTP has structure that random bytes do not:

    check                        a wrong offset gives          the right offset gives
    ---------------------------  ----------------------------  ------------------------
    version bits == 2            ~25 % of packets              ~100 %
    payload type in a tiny set   ~2/128 = 1.6 % in the set     ~100 % (98 video, 116 audio ...)
    SSRC repeats                 a new "SSRC" for every pkt    a few SSRCs, thousands of pkts each
    sequence goes +1             ~0 % steps of +1              mostly +1, rest small forward steps
    timestamp advances at a      meaningless rate              90000 Hz video, 48000 Hz audio ...
    fixed clock rate
    one timestamp per frame      many per frame_seq group      1 per frame_seq group
    marker bit                   random                        set on the last packet of a frame

  A PASS needs all of them, which is why the verdict is a conjunction.

WHAT CHANGED in v2 (all of it comes from the first two campus captures):
  * Second copies ("twins": every frame arrives twice on the campus link, once on the CAPWAP tunnel
    leg and once on the wired leg) are collapsed by CONTENT (identical 5-tuple, Zoom and RTP
    fields and IP id/TTL within 10 ms), not only by the pipeline's `dup` flag.
    v1 counted a missed twin as "sequence step 0" and reported 58 % forward
    steps for what is really ~96 %.  The report also says how many twins the
    pipeline's de-dup missed and, when the CSV has a `core` column, on which
    core pair: that is the direct proof of the cross-core cause.
  * Streams are keyed by (client, direction, SSRC, payload type).  Video PT 110
    shares the RTP timestamp of PT 98 frames but has its own sequence
    numbers (it looks like FEC), so mixing them broke sequence continuity.
  * Audio PT 114 is a normal audio stream (own SSRC), so the expected set is
    {113, 114, 116}.
  * Screen share (type 13) is judged only on packets that belong to a stable
    RTP-looking stream; the small type-13 packets are not RTP at +27.
  * Sequence gaps are explained: which unparsed packet types (7, 21, ...) sit
    inside them.  On the campus data, type 7 fills about three quarters of
    audio gaps (they are audio packets with another header layout).
  * A client table with a heuristic PC / mobile label (see classify_client(): in p7b terms "mobile-like"
    means "mostly Type-21 probe padding and no video").  --exclude-mobile and
    --clients restrict the statistics to the clients you care about.

WHAT CHANGED in v2.1 (from the third campus capture, s3):
  * A missed twin is two UNFLAGGED rows with identical content.  The CSV is
    written in per-core batches, so it is not in time order and a flagged copy
    can precede the copy that survived; v2 paired the survivor with it and
    called it "missed" (294 of 304 on the s3 slice).
  * New section "capture completeness": the share of SFU-header counter values
    that never appear, per client and over all flows.  The counter ticks once
    per packet of a flow whatever its media type, so this measures the packets
    the CAPTURE lost, independent of RTP parsing.  A pooled share above 1 %
    makes the verdict GO WITH CAVEATS: rates read low by that share and an RTP
    sequence gap of that size is not evidence of network loss.

WHAT CHANGED in v2.2 (p7b; the offsets below are the p7b pipeline's rules, see headers.rs):
  * Video has THREE layouts, chosen by media byte 20: 0x02 -> RTP at +24, 0x0a -> RTP at +28, and any byte
    with the top bits `10` (0x80-0xBF; only 0x90 has been seen) -> RTP at +20, because there byte 20 IS the
    first byte of the RTP header.  rtp_offset() applies this when it re-reads the pcap.  The range 0x80-0xBF
    is an INFERENCE (V=2 in the top two bits), the value 0x90 is what the campus capture shows.
  * A type-13 packet carries RTP only if media byte 7 is 0x1e (deck2 T13-*).  Byte 0x15 is Type-21 probe
    padding in a Type-13 envelope, anything else is control.  rtp_from_payload() returns 'none' for those, so a
    pcap/CSV disagreement about them is reported (a p7a CSV, which read +27 on every type-13 packet, would show
    mismatches here: that is the intended difference).
  * Wording: the old "mirror twin" is the SECOND COPY of a frame (the CAPWAP tunnel leg plus the wired leg of the
    same frame, try4 CONFIRMED), not a SPAN artefact.  The tool's internal names (twin) are unchanged.
  * Type 21 is probe padding (94 %), not video: the old client labels that read it as "the phone's video type"
    are explained as what they are, a heuristic (classify_client()).

Exit code: 0 = GO, 1 = GO WITH CAVEATS / missing data, 2 = NO-GO.
"""
import argparse
import csv
import glob
import json
import os
import re
import struct
import sys
from array import array
from collections import Counter, defaultdict, deque
from operator import itemgetter

# ---- what the deck / the code assume.  Edit here if the data disagrees.
TYPE_NAME = {16: "video", 15: "audio", 13: "screen13", 30: "screen30", 33: "rtcp", 34: "rtcp"}
# 110 = FEC-like companion of PT 98 (same RTP timestamp, own sequence numbers).
EXPECT_PT = {"video": {98, 110}, "audio": {113, 114, 116}, "screen13": {99, 110}}
FEC_PT = {"video": 110}
# RTP header offset from the start of the media header (pipeline headers.rs).
# p7a: type 30 is +20 (p6 had +27, a guess that the 2026-10 captures disproved: 99.994 % of type-30
# packets have RTP version 2 at +20).
# p7b: type 13 +27 holds ONLY for packets whose media byte 7 is 0x1e (T13_RTP_SUBTYPE); the others are probe
#      padding (0x15) or control and have no RTP.
# Video has three layouts, chosen by media byte 20 (see rtp_offset()):
#      0x0a -> RTP at +28 (burst), top bits 10 (0x80-0xBF, seen: 0x90) -> RTP at +20, anything else -> +24.
RTP_OFF = {16: 24, 15: 19, 13: 27, 30: 20}
VIDEO_BURST_BYTE, VIDEO_BURST_OFF = 0x0A, 28
VIDEO_RTP20_OFF = 20
T13_SUBTYPE_POS, T13_RTP_SUBTYPE = 7, 0x1E
RTCP_OFF = {33: 16, 34: 16}
STD_CLOCKS = [8000, 16000, 24000, 32000, 44100, 48000, 90000]
CORE = ("video", "audio")  # these two must PASS for Stage 2 to be GO
SELECT_TYPES = ("screen13", "screen30")  # judged on qualifying streams only
STREAM_MIN_PKTS = 20
STREAM_MIN_VER = 0.95
MIN_N = {"rtcp": 50}  # per type; default 200.  Fewer unique packets than this => "NO DATA", not a verdict
DEFAULT_MIN_N = 200
TWIN_WINDOW_NS = 10_000_000  # same as the pipeline's de-dup window
CAPTURE_MIN_PKTS = 500  # a flow needs this many typed packets before its SFU-sequence gaps are judged
CAPTURE_MAX_GAP = 100  # a forward step wider than this is a counter restart / jump, not a run of missed packets
CAPTURE_NOTE_PCT = 1.0  # above this pooled miss share (all flows, weighted by packets), say so in the verdict.  Not the median over flows: many tiny control flows pull a median down (s3: median 0.9-1.3 %, pooled 2.7-3.2 %, busy media flows ~5 %)
# identical in both copies of a doubled packet (CAPWAP tunnel leg + wired leg)
TWIN_COLS = ["src_ip", "dst_ip", "src_port", "dst_port", "udp_len", "sfu_seq", "media_type_byte",
             "media_sequence", "media_timestamp", "ip_id", "ip_ttl", "rtp_ssrc", "rtp_seq", "rtp_timestamp"]


class Stream:
    __slots__ = ("n", "ver", "pt", "last_seq", "last_sfu", "step", "fwd", "back", "other", "t0", "t1",
                 "ts_first", "ts_un", "ts_last", "cur_ts", "cur_pt", "cur_markers", "cur_last_marker")

    def __init__(self):
        self.n = self.ver = 0
        self.pt = 0
        self.last_seq = None
        self.last_sfu = None
        self.step = self.fwd = self.back = self.other = 0
        self.t0 = self.t1 = 0.0
        self.ts_first = self.ts_un = self.ts_last = 0
        self.cur_ts = None
        self.cur_pt = 0
        self.cur_markers = 0
        self.cur_last_marker = 0


class TypeStats:
    def __init__(self):
        self.rows = 0
        self.with_rtp = 0
        self.ver_ok = 0
        self.pt = Counter()
        self.seq_eq_media_seq = 0
        self.seq_cmp = 0
        # frame groups (video / screen only)
        self.fg_groups = 0
        self.fg_one_rtp_ts = 0
        self.fg_one_enc_ts = 0
        # marker
        self.mk = defaultdict(lambda: [0, 0, 0])  # pt -> [frames, exactly one marker, marker on last]
        self.rtcp_pt = Counter()
        self.rtcp_ssrc_known = 0
        self.rtcp_ssrc_total = 0


class TwinFilter:
    """Marks an UNFLAGGED row as the second copy ("twin") if an identical unflagged row was seen < 10 ms apart.

    Rows the pipeline flagged (dup=1) are ignored on purpose.  The CSV is written
    in per-core batches, so it is NOT in timestamp order: a flagged copy can
    appear in the file *before* the copy that survived.  Pairing a flagged row
    with the survivor would count a correctly removed twin as "missed" (s3: 294
    of the 304 "missed" twins in the first 400k rows were this file-order
    artefact; the true misses were 10).  A real miss is two *unflagged* rows."""

    def __init__(self, getter):
        self.get = getter
        self.seen = {}
        self.order = deque()

    def check(self, row, ep, core, flagged=False):
        if flagged:
            return False, None
        key = self.get(row)
        lim = ep - 4 * TWIN_WINDOW_NS
        order, seen = self.order, self.seen
        while order and order[0][0] < lim:
            e, k = order.popleft()
            v = seen.get(k)
            if v is not None and v[0] == e:
                del seen[k]
        v = seen.get(key)
        if v is not None and abs(ep - v[0]) < TWIN_WINDOW_NS:
            return True, v[1]
        seen[key] = (ep, core)
        order.append((ep, key))
        return False, None


def csv_files(path):
    """File 1 is exactly `path`; rotated files are stem.N.ext (csvdump.rs csv_name), or, for
    vc_capture, zoom_record_0001.csv -> zoom_record_0002.csv ..."""
    stem, ext = os.path.splitext(path)
    m4 = re.fullmatch(r"(.*_)0001", stem)
    if m4:
        parts = sorted(glob.glob(glob.escape(m4.group(1)) + "[0-9][0-9][0-9][0-9]" + ext))
        return [path] + [q for q in parts if q != path]
    rot = []
    for p in glob.glob(glob.escape(stem) + ".*" + ext):
        m = re.fullmatch(re.escape(stem) + r"\.(\d+)" + re.escape(ext), p)
        if m:
            rot.append((int(m.group(1)), p))
    return [path] + [p for _, p in sorted(rot)]


def s32(d):
    d &= 0xFFFFFFFF
    return d - (1 << 32) if d >= (1 << 31) else d


def nearest_clock(hz):
    best = min(STD_CLOCKS, key=lambda c: abs(c - hz) / c)
    return best if abs(best - hz) / best <= 0.05 else None


# ------------------------------------------------------------------ clients
def classify_client(c):
    """Heuristic device label from the packet-type mix (seen on two campus captures; not a proof).

    p7b note: "mobile-like" means "a lot of Type 21 and (almost) no video".  The label was chosen when Type 21
    was believed to be the phone's video type.  Deck2 (T21-2 CONFIRMED, T21-4 REFUTED) shows Type 21 is probe
    padding, 94 % of its packets, so the label now only says "mostly probe padding, no video".  A phone is ONE
    possible reason for that, a PC with its camera off is another.  The flag --exclude-mobile keeps its name
    so that old command lines still work."""
    tot = sum(c["types"].values()) or 1
    f = lambda t: c["types"].get(t, 0) / tot
    if f(-1) >= 0.95:
        return "control-only (no media header)"
    if f(16) >= 0.05 and f(21) < 0.40:
        return "pc-like"
    if f(21) >= 0.40 and f(16) < 0.05:
        return "mobile-like"
    if f(21) >= 0.40 and f(16) >= 0.05:
        return "mixed (video + type 21)"
    if f(15) >= 0.50:
        return "audio-only"
    return "other"


def scan_clients(paths, max_rows):
    """Pass 1: per-client packet-type mix, flows and time span (twins not collapsed: proportions are unaffected)."""
    cl = {}
    n = 0
    cols = None
    for path in paths:
        with open(path, newline="") as fh:
            rd = csv.reader(fh)
            header = next(rd)
            if cols is None:
                cols = {name: i for i, name in enumerate(header)}
                i_dir, i_src, i_dst, i_mt = cols["dir"], cols["src_ip"], cols["dst_ip"], cols["media_type_byte"]
                i_sp, i_dp, i_dup, i_ep = cols["src_port"], cols["dst_port"], cols["dup"], cols["arrival_epoch_ns"]
                i_lab = cols.get("client_label")
            for row in rd:
                if row[i_dup] == "1":
                    continue
                n += 1
                if n > max_rows:
                    return cl
                up = row[i_dir] == "up"
                client = row[i_src] if up else row[i_dst]
                c = cl.get(client)
                if c is None:
                    c = cl[client] = dict(types=Counter(), flows=set(), t0=None, t1=None, up=0, n=0, mark="")
                try:
                    tb = int(row[i_mt])
                except ValueError:
                    tb = -1
                c["types"][tb] += 1
                if i_lab is not None and row[i_lab] and not c["mark"]:
                    c["mark"] = row[i_lab]  # name given with anonymize_csv.py --label
                c["n"] += 1
                c["up"] += up
                if len(c["flows"]) < 500:
                    c["flows"].add((row[i_sp] if up else row[i_dp], up))
                ep = int(row[i_ep]) if row[i_ep] else 0
                if c["t0"] is None:
                    c["t0"] = ep
                c["t1"] = ep
    return cl


def label_clients(cl):
    order = sorted(cl, key=lambda k: -cl[k]["n"])
    labels = {ip: "client#%d" % (i + 1) for i, ip in enumerate(order)}
    for ip, c in cl.items():
        c["label"] = labels[ip]
        c["cls"] = classify_client(c)
    return labels


# ------------------------------------------------------------------ capture completeness
def capture_summary(sfu_flows):
    """How many packets did the capture lose?  Judged from the SFU header counter.

    The 8-byte SFU header carries a 16-bit counter that goes up by one for every
    packet of a flow, whatever its media type (video, audio, type 7, 21 ...).  A
    number that never shows up in the capture is therefore a packet that was sent
    and not captured, independent of any RTP parsing.  Runs of missing numbers up
    to CAPTURE_MAX_GAP count as missed packets; a wider step is a counter restart
    and is only counted as a jump.  -> {client: {flows, pkts, missing, jumps, flow_pcts}}"""
    out = {}
    for (client, _cport, _dir), (_hi, arr) in sfu_flows.items():
        if len(arr) < CAPTURE_MIN_PKTS:
            continue
        vals = sorted(set(arr))
        miss = jumps = 0
        prev = vals[0]
        for v in vals[1:]:
            d = v - prev
            if d > 1:
                if d - 1 <= CAPTURE_MAX_GAP:
                    miss += d - 1
                else:
                    jumps += 1
            prev = v
        c = out.setdefault(client, dict(flows=0, pkts=0, missing=0, jumps=0, flow_pcts=[]))
        c["flows"] += 1
        c["pkts"] += len(vals)
        c["missing"] += miss
        c["jumps"] += jumps
        c["flow_pcts"].append(100.0 * miss / (len(vals) + miss))
    return out


# ------------------------------------------------------------------ main pass
def read_csv(paths, max_rows, keep_for_pcap, client_ok):
    types = defaultdict(TypeStats)
    streams = {}
    frame_state = {}  # (type, client, dir) -> [frame_seq, set(rtp_ts), set(enc_ts)]
    rtcp_by_client = defaultdict(set)
    media_ssrc_by_client = defaultdict(set)
    other_types = Counter()
    other_sizes = defaultdict(Counter)
    by_us = defaultdict(list) if keep_for_pcap else None
    recent_media_ts = {}  # (client, dir, ssrc) -> deque of recent PT98 frame timestamps
    fec = dict(rows=0, ts_match=0)
    flow_other = {}  # (client, cport, dir) -> deque of (sfu_seq, type) for unparsed media types
    sfu_flows = {}  # (client, cport, dir) -> [highest extended sfu_seq, array of extended sfu_seq]
    gaps = defaultdict(lambda: dict(gaps=0, missing=0, filled=0, by_type=Counter(), unexplained=0))
    tw = dict(flagged=0, missed=0, missed_same_core=0, missed_diff_core=0, pairs_core=Counter(), skipped_clients=0)
    total = unique = 0
    first_t = last_t = None
    stopped_early = False
    cols = None
    twin = None
    for path in paths:
        with open(path, newline="") as fh:
            rd = csv.reader(fh)
            header = next(rd)
            if cols is None:
                cols = {name: i for i, name in enumerate(header)}
                need = ["dir", "src_ip", "dst_ip", "src_port", "dst_port", "udp_len", "media_type_byte", "dup",
                        "rtp_ssrc", "rtp_timestamp", "rtp_seq", "rtp_pt", "rtp_marker", "rtp_ver_ok",
                        "arrival_epoch_ns", "frame_seq", "media_sequence", "media_timestamp", "sfu_seq",
                        "ip_id", "ip_ttl"]
                miss = [c for c in need if c not in cols]
                if miss:
                    sys.exit("ERROR: %s lacks columns %s.  Was it written by a zoom_capture build (p5 or later) with --packet-csv? The p7b build adds two columns, media_b20 and media_b7, which this tool does not require." % (path, miss))
                twin = TwinFilter(itemgetter(*[cols[c] for c in TWIN_COLS]))
            ci = cols
            i_dir, i_src, i_dst, i_mt = ci["dir"], ci["src_ip"], ci["dst_ip"], ci["media_type_byte"]
            i_sp, i_dp, i_ul = ci["src_port"], ci["dst_port"], ci["udp_len"]
            i_dup, i_ssrc, i_rts = ci["dup"], ci["rtp_ssrc"], ci["rtp_timestamp"]
            i_rseq, i_pt = ci["rtp_seq"], ci["rtp_pt"]
            i_mk, i_ok, i_ep = ci["rtp_marker"], ci["rtp_ver_ok"], ci["arrival_epoch_ns"]
            i_fs, i_ms, i_mts, i_sfu = ci["frame_seq"], ci["media_sequence"], ci["media_timestamp"], ci["sfu_seq"]
            i_core = ci.get("core")
            for row in rd:
                total += 1
                ep = int(row[i_ep]) if row[i_ep] else 0
                flagged = row[i_dup] == "1"
                core = row[i_core] if i_core is not None else None
                is_twin, first_core = twin.check(row, ep, core, flagged)
                if flagged:
                    tw["flagged"] += 1
                elif is_twin:
                    tw["missed"] += 1
                    if core is not None:
                        if core == first_core:
                            tw["missed_same_core"] += 1
                        else:
                            tw["missed_diff_core"] += 1
                            tw["pairs_core"]["%s->%s" % (first_core, core)] += 1
                if flagged:
                    continue
                direction = row[i_dir]
                up = direction == "up"
                client = row[i_src] if up else row[i_dst]
                # ---- the pcap holds every packet the pipeline did not flag, twins it missed included
                if by_us is not None:
                    try:
                        tb0 = int(row[i_mt])
                    except ValueError:
                        tb0 = None
                    if tb0 is None or (tb0 not in TYPE_NAME) or row[i_ok] == "":
                        rec = (tb0, 0, 0, 0, 0)
                    elif TYPE_NAME[tb0] == "rtcp":
                        rec = (tb0, int(row[i_ssrc], 16) if row[i_ssrc] else -1, 0, 0, int(row[i_pt]) if row[i_pt] else -1)
                    else:
                        rec = (tb0, int(row[i_ssrc], 16) if row[i_ssrc] else -1, int(row[i_rseq]), int(row[i_rts]),
                               int(row[i_pt]) if row[i_pt] else -1)
                    by_us[ep // 1000].append(rec)
                if is_twin:
                    continue
                if client_ok is not None and client not in client_ok:
                    tw["skipped_clients"] += 1
                    continue
                unique += 1
                if unique > max_rows:
                    stopped_early = True
                    break
                cport = row[i_sp] if up else row[i_dp]
                try:
                    tb = int(row[i_mt])
                except ValueError:
                    other_types["no Zoom header"] += 1
                    other_sizes["no Zoom header"][row[i_ul]] += 1
                    continue
                name = TYPE_NAME.get(tb)
                sfu = int(row[i_sfu]) if row[i_sfu] else None
                if sfu is not None:
                    # capture completeness: the 16-bit SFU counter ticks once per packet of the flow whatever the media
                    # type, so numbers that never show up are packets this capture lost (see capture_summary)
                    fl = sfu_flows.get((client, cport, direction))
                    if fl is None:
                        fl = sfu_flows[(client, cport, direction)] = [sfu, array("q")]
                    hi = fl[0]
                    ext = hi + (((sfu - (hi & 0xFFFF) + 0x8000) & 0xFFFF) - 0x8000)
                    if ext > hi:
                        fl[0] = ext
                    fl[1].append(ext)
                if name is None:
                    other_types["type byte %d" % tb] += 1
                    other_sizes["type byte %d" % tb][row[i_ul]] += 1
                    if sfu is not None:
                        dq = flow_other.get((client, cport, direction))
                        if dq is None:
                            dq = flow_other[(client, cport, direction)] = deque(maxlen=256)
                        dq.append((sfu, tb))
                    continue
                st = types[name]
                st.rows += 1
                ok = row[i_ok]
                t = ep / 1e9
                if first_t is None:
                    first_t = t
                last_t = t
                if ok == "":
                    continue
                st.with_rtp += 1
                if ok == "1":
                    st.ver_ok += 1
                ssrc = int(row[i_ssrc], 16) if row[i_ssrc] else -1
                pt = int(row[i_pt]) if row[i_pt] else -1
                st.pt[pt] += 1
                if name == "rtcp":
                    st.rtcp_pt[pt] += 1
                    rtcp_by_client[client].add(ssrc)
                    continue
                media_ssrc_by_client[client].add(ssrc)
                seq = int(row[i_rseq])
                ts = int(row[i_rts])
                mk = int(row[i_mk]) if row[i_mk] else 0
                if row[i_ms] != "":
                    st.seq_cmp += 1
                    if int(row[i_ms]) == seq:
                        st.seq_eq_media_seq += 1
                is_fec = FEC_PT.get(name) == pt
                sname = name + "-fec" if is_fec else name
                if is_fec:
                    fec["rows"] += 1
                    rm = recent_media_ts.get((client, direction, ssrc))
                    if rm is not None and ts in rm:
                        fec["ts_match"] += 1
                elif name == "video":
                    rm = recent_media_ts.get((client, direction, ssrc))
                    if rm is None:
                        rm = recent_media_ts[(client, direction, ssrc)] = deque(maxlen=64)
                    if not rm or rm[-1] != ts:
                        rm.append(ts)
                key = (sname, client, direction, ssrc, pt)
                s = streams.get(key)
                if s is None:
                    s = streams[key] = Stream()
                    s.t0 = t
                    s.ts_first = s.ts_un = s.ts_last = ts
                    s.last_seq = seq
                    s.cur_ts = ts
                    s.cur_pt = pt
                    s.pt = pt
                else:
                    d = (seq - s.last_seq) & 0xFFFF
                    if d == 1:
                        s.step += 1
                    elif 2 <= d <= 50:
                        s.fwd += 1
                        # explain the gap: unparsed packet types of the same flow between the two packets
                        if name in ("video", "audio") and not is_fec:
                            g = gaps[name]
                            g["gaps"] += 1
                            g["missing"] += d - 1
                            dq = flow_other.get((client, cport, direction))
                            if dq is not None and s.last_sfu is not None and sfu is not None:
                                span = (sfu - s.last_sfu) & 0xFFFF
                                tys = set()
                                if 2 <= span <= 400:
                                    for sq, ty in dq:
                                        if 0 < ((sq - s.last_sfu) & 0xFFFF) < span:
                                            tys.add(ty)
                                if tys:
                                    g["filled"] += 1
                                    for ty in tys:
                                        g["by_type"][ty] += 1
                                else:
                                    g["unexplained"] += 1
                            else:
                                g["unexplained"] += 1
                    elif d >= 0xFFFF - 100:
                        s.back += 1
                    else:
                        s.other += 1
                    s.last_seq = seq
                    s.ts_un += s32(ts - s.ts_last)
                    s.ts_last = ts
                    # marker bookkeeping: a frame = a run of packets with the same rtp_ts in one stream
                    if ts != s.cur_ts:
                        if name != "audio" and not is_fec:
                            m = st.mk[s.cur_pt]
                            m[0] += 1
                            m[1] += 1 if s.cur_markers == 1 else 0
                            m[2] += 1 if s.cur_last_marker else 0
                        s.cur_ts, s.cur_pt, s.cur_markers, s.cur_last_marker = ts, pt, 0, 0
                s.n += 1
                s.ver += ok == "1"
                s.t1 = t
                s.last_sfu = sfu
                s.cur_markers += mk
                s.cur_last_marker = mk
                if name in ("video", "screen13", "screen30") and not is_fec and row[i_fs]:
                    fkey = (name, client, direction)
                    fs = row[i_fs]
                    g = frame_state.get(fkey)
                    if g is None or g[0] != fs:
                        if g is not None:
                            st.fg_groups += 1
                            st.fg_one_rtp_ts += 1 if len(g[1]) == 1 else 0
                            st.fg_one_enc_ts += 1 if len(g[2]) == 1 else 0
                        g = frame_state[fkey] = [fs, set(), set()]
                    g[1].add(ts)
                    g[2].add(row[i_mts])
            if stopped_early:
                break
    for fkey, g in frame_state.items():
        st = types[fkey[0]]
        st.fg_groups += 1
        st.fg_one_rtp_ts += 1 if len(g[1]) == 1 else 0
        st.fg_one_enc_ts += 1 if len(g[2]) == 1 else 0
    # RTCP SSRC cross-check: does an RTCP SSRC also appear as a media SSRC of the same client?
    for client, ss in rtcp_by_client.items():
        for x in ss:
            types["rtcp"].rtcp_ssrc_total += 1
            if x in media_ssrc_by_client.get(client, ()):
                types["rtcp"].rtcp_ssrc_known += 1
    meta = dict(total=total, unique=min(unique, max_rows), twins_flagged=tw["flagged"], twins_missed=tw["missed"],
                twins_missed_same_core=tw["missed_same_core"], twins_missed_diff_core=tw["missed_diff_core"],
                twin_core_pairs=dict(tw["pairs_core"].most_common(8)), has_core_column=i_core is not None,
                rows_of_skipped_clients=tw["skipped_clients"], capture_raw=capture_summary(sfu_flows),
                other_types=other_types, span_s=(last_t - first_t) if first_t is not None else 0.0,
                stopped_early=stopped_early)
    other_info = {k: dict(rows=other_types[k], top_sizes=[(int(sz), n) for sz, n in v.most_common(3)])
                  for k, v in other_sizes.items()}
    return types, streams, meta, by_us, dict(fec), {k: v for k, v in gaps.items()}, other_info


def synthetic_ssrc(x):
    """SSRC values a real endpoint does not pick: one byte repeated (0x01010101, 0x02020202 ...) or a small number (0x3E8).
    On s3 the screen-share flows carried ~30 s of 1,051-byte packets with such 'SSRCs' (a counter pattern, the PT field
    counting 1, 2, 3 ... once a second): padding/probe packets, not screen content."""
    if x is None or x < 0:
        return False
    b = x.to_bytes(4, "big")
    return len(set(b)) == 1 or x <= 0xFFFF


def qualifying(s):
    return s.n >= STREAM_MIN_PKTS and s.ver >= STREAM_MIN_VER * s.n


def summarize(types, streams, fec, gaps):
    out = {}
    for name in ("video", "audio", "screen13", "screen30", "rtcp"):
        st = types.get(name)
        if st is None or st.rows == 0:
            out[name] = dict(rows=0)
            continue
        ss = [s for k, s in streams.items() if k[0] == name]
        sel = name in SELECT_TYPES
        use = [s for s in ss if qualifying(s)] if sel else ss
        if sel:
            # judge only packets inside RTP-looking streams; report how much of the type that is
            rows = sum(s.n for s in use)
            r = dict(rows=rows, with_rtp=rows, no_rtp_pct=0.0,
                     ver_pass=(sum(s.ver for s in use) / rows) if rows else 0.0,
                     coverage=(rows / st.rows) if st.rows else 0.0, all_rows=st.rows,
                     probe_like=(sum(s.n for k, s in streams.items() if k[0] == name and not qualifying(s) and synthetic_ssrc(k[3])) / st.rows) if st.rows else 0.0)
            pt = Counter()
            for s in use:
                pt[s.pt] += s.n
        else:
            r = dict(rows=st.rows, with_rtp=st.with_rtp,
                     no_rtp_pct=100.0 * (st.rows - st.with_rtp) / st.rows,
                     ver_pass=(st.ver_ok / st.with_rtp) if st.with_rtp else 0.0)
            pt = st.pt
        r["pt_top"] = pt.most_common(6)
        exp = EXPECT_PT.get(name)
        tot_pt = sum(pt.values())
        if exp is not None and tot_pt:
            r["pt_in_set"] = sum(v for k, v in pt.items() if k in exp) / tot_pt
        if name == "rtcp":
            tot = sum(st.rtcp_pt.values()) or 1
            r["rtcp_pt_200_207"] = sum(v for k, v in st.rtcp_pt.items() if 200 <= k <= 207) / tot
            r["rtcp_ssrc_known"] = (st.rtcp_ssrc_known / st.rtcp_ssrc_total) if st.rtcp_ssrc_total else None
        else:
            pkts = sum(s.n for s in use)
            r["streams"] = len(use)
            r["stable_ssrc_share"] = (sum(s.n for s in use if s.n >= 20) / pkts) if pkts else 0.0
            pairs = sum(s.step + s.fwd + s.back + s.other for s in use)
            r["seq_plus1"] = (sum(s.step for s in use) / pairs) if pairs else 0.0
            r["seq_forward_ok"] = (sum(s.step + s.fwd for s in use) / pairs) if pairs else 0.0
            r["seq_backward"] = (sum(s.back for s in use) / pairs) if pairs else 0.0
            clocks = []
            for s in use:
                if s.n >= 50 and (s.t1 - s.t0) >= 5.0:
                    clocks.append((s.ts_un - s.ts_first) / (s.t1 - s.t0))
            r["clock_hz_median"] = sorted(clocks)[len(clocks) // 2] if clocks else None
            r["clock_streams"] = len(clocks)
            r["clock_std_share"] = (sum(1 for c in clocks if nearest_clock(c)) / len(clocks)) if clocks else None
            r["clock_std_nearest"] = nearest_clock(r["clock_hz_median"]) if clocks else None
            if st.seq_cmp and not sel:
                r["rtp_seq_eq_media_seq"] = st.seq_eq_media_seq / st.seq_cmp
            if st.fg_groups and not sel:
                r["frame_groups"] = st.fg_groups
                r["fg_one_rtp_ts"] = st.fg_one_rtp_ts / st.fg_groups
                r["fg_one_encap_ts"] = st.fg_one_enc_ts / st.fg_groups
            if st.mk and not sel:
                r["marker"] = {pt_: dict(frames=v[0], exactly_one=(v[1] / v[0]) if v[0] else None,
                                         on_last=(v[2] / v[0]) if v[0] else None)
                               for pt_, v in sorted(st.mk.items()) if v[0] >= 50}
            g = gaps.get(name)
            if g and g["gaps"]:
                r["gaps"] = dict(gaps=g["gaps"], missing_packets=g["missing"], explained_by_unparsed_types=g["filled"],
                                 by_type={str(k): v for k, v in g["by_type"].most_common(5)}, unexplained=g["unexplained"])
        out[name] = r
    # FEC companion of video
    fs = [s for k, s in streams.items() if k[0] == "video-fec"]
    if fs:
        pairs = sum(s.step + s.fwd + s.back + s.other for s in fs)
        out["video_fec"] = dict(rows=fec["rows"], share_of_video=fec["rows"] / max(1, out.get("video", {}).get("rows", 0) + fec["rows"]),
                                streams=len(fs), same_rtp_ts_as_a_media_frame=(fec["ts_match"] / fec["rows"]) if fec["rows"] else None,
                                own_seq_forward_ok=(sum(s.step + s.fwd for s in fs) / pairs) if pairs else None)
    return out


def verdict(name, r):
    """-> (label, [reasons])"""
    need = MIN_N.get(name, DEFAULT_MIN_N)
    if r.get("rows", 0) < need:
        if name in SELECT_TYPES and r.get("all_rows", 0) > 0:
            return "NO DATA", ["no RTP-looking %s stream (>= %d packets with version 2 >= %d%%); %d type-%s packets seen, none usable"
                               % (name, STREAM_MIN_PKTS, 100 * STREAM_MIN_VER, r["all_rows"], name[6:])]
        return "NO DATA", ["%d unique packets (need >= %d); capture a call that uses this media type" % (r.get("rows", 0), need)]
    why = []
    fail = warn = False
    vp = r["ver_pass"]
    if vp < 0.90:
        fail = True
        why.append("RTP version==2 only %.1f %% (need >= 99 %%)" % (100 * vp))
    elif vp < 0.99:
        warn = True
        why.append("RTP version==2 %.1f %% (want >= 99 %%)" % (100 * vp))
    if name == "rtcp":
        p = r["rtcp_pt_200_207"]
        if p < 0.90:
            fail = True
            why.append("RTCP PT in 200..207 only %.1f %%" % (100 * p))
        k = r.get("rtcp_ssrc_known")
        if k is not None and k < 0.5:
            warn = True
            why.append("only %.0f %% of RTCP SSRCs match a media SSRC of the same client" % (100 * k))
        return ("FAIL" if fail else "WARN" if warn else "PASS"), why
    if "coverage" in r and r["coverage"] + r.get("probe_like", 0.0) < 0.5:
        warn = True
        why.append("only %.0f %% of the type-%s packets belong to an RTP-looking stream and %.0f %% more are probe/padding-like; %.0f %% are another format"
                   % (100 * r["coverage"], name[6:], 100 * r.get("probe_like", 0.0), 100 * (1 - r["coverage"] - r.get("probe_like", 0.0))))
    pis = r.get("pt_in_set")
    if pis is not None:
        if pis < 0.60:
            fail = True
            why.append("payload type in %s only %.1f %% (random bytes would give ~1.6 %%)" % (sorted(EXPECT_PT[name]), 100 * pis))
        elif pis < 0.90:
            warn = True
            why.append("payload type in %s %.1f %%: other PTs present, see histogram" % (sorted(EXPECT_PT[name]), 100 * pis))
    sh = r["stable_ssrc_share"]
    if sh < 0.50:
        fail = True
        why.append("only %.1f %% of packets belong to an SSRC seen >= 20 times (random bytes: ~0 %%)" % (100 * sh))
    elif sh < 0.95:
        warn = True
        why.append("%.1f %% of packets are in stable SSRCs (want >= 95 %%)" % (100 * sh))
    sq = r["seq_forward_ok"]
    if sq < 0.50:
        fail = True
        why.append("sequence number advances (+1..+50) in only %.1f %% of steps" % (100 * sq))
    elif sq < 0.90:
        warn = True
        why.append("sequence advances in %.1f %% of steps (want >= 90 %%)" % (100 * sq))
    cs = r.get("clock_std_share")
    if cs is not None and cs < 0.5:
        warn = True
        why.append("estimated timestamp clock is a standard rate for only %.0f %% of streams (median %.0f Hz)" % (100 * cs, r["clock_hz_median"]))
    return ("FAIL" if fail else "WARN" if warn else "PASS"), why


def run_info_next_to(csv_path):
    p = os.path.join(os.path.dirname(os.path.abspath(csv_path)), "run_info.txt")
    info = {}
    if os.path.exists(p):
        for line in open(p):
            if "=" in line and not line.startswith("#"):
                k, v = line.rstrip("\n").split("=", 1)
                info[k] = v
    return info


def dedup_verdict(meta, csv_path=None):
    """The pipeline's de-dup must catch (almost) every second copy (twin), or counts are inflated."""
    seen = meta["twins_flagged"] + meta["twins_missed"]
    info = run_info_next_to(csv_path) if csv_path else {}
    if seen < 200 and info.get("program", "").startswith("vc_capture"):
        # vc_capture writes kept packets only (twins go nowhere), so the CSV cannot show what de-dup
        # removed. Its counters can: report them instead of a misleading NO DATA.
        try:
            d, m = int(info["final_zoom_dups_dropped"]), int(info["final_zoom_matched"])
            share = 100.0 * d / (d + m) if d + m else 0.0
            note = "vc_capture CSV holds kept packets only; run_info.txt: dedup=%s, %d twins dropped = %.1f %% of Zoom packets (about 50 %% on the doubled mirror, about 0 %% once it is fixed)" % (info.get("dedup"), d, share)
        except (KeyError, ValueError):
            note = "vc_capture CSV holds kept packets only; run_info.txt has no end block (run still going or killed)"
        return "FROM RUN_INFO", [note]
    if seen < 200:
        return "NO DATA", ["fewer than 200 twin rows in the capture; nothing to judge"]
    miss = meta["twins_missed"] / seen
    if miss <= 0.005:
        return "PASS", []
    msg = "%.1f %% of the twin rows (%d of %d) were NOT flagged by the pipeline: counts and throughput are inflated by up to %.2fx" % (
        100 * miss, meta["twins_missed"], seen, 1 + miss)
    if meta["has_core_column"] and meta["twins_missed"]:
        msg += "; %d of the missed copies were received on a different core than the first copy, %d on the same core" % (
            meta["twins_missed_diff_core"], meta["twins_missed_same_core"])
    msg += " (expected only if the run used --no-dedup)"
    return "FAIL", [msg]


# ------------------------------------------------------------------ pcap
def pcap_files(p):
    if os.path.isdir(p):
        return sorted(glob.glob(os.path.join(p, "*.pcap")))
    return [p]


def parse_frame(buf):
    """Ethernet(+VLAN) / IPv4 or IPv6 / UDP -> (payload_bytes, udp_payload_len) or None."""
    if len(buf) < 14:
        return None
    et = struct.unpack(">H", buf[12:14])[0]
    o = 14
    while et in (0x8100, 0x88A8, 0x9100) and len(buf) >= o + 4:
        et = struct.unpack(">H", buf[o + 2:o + 4])[0]
        o += 4
    if et == 0x0800:
        if len(buf) < o + 20:
            return None
        ihl = (buf[o] & 0x0F) * 4
        if buf[o + 9] != 17:
            return None
        o += ihl
    elif et == 0x86DD:
        if len(buf) < o + 40 or buf[o + 6] != 17:
            return None
        o += 40
    else:
        return None
    if len(buf) < o + 8:
        return None
    ulen = struct.unpack(">H", buf[o + 4:o + 6])[0]
    return buf[o + 8:], ulen - 8


def rtp_offset(tb, pl):
    """Media-header-relative RTP offset of one packet (pl = UDP payload incl. the 8-byte SFU header).

    Video (type 16): media byte 20 = 0x0a -> +28; top two bits 10 (0x80-0xBF, 0x90 seen) -> +20, where byte 20 is
    the first byte of the RTP header itself; anything else -> +24.  A packet too short to hold byte 20 keeps +24."""
    if tb == 16 and len(pl) > 8 + 20:
        b20 = pl[8 + 20]
        if b20 == VIDEO_BURST_BYTE:
            return VIDEO_BURST_OFF
        if b20 >> 6 == 2:
            return VIDEO_RTP20_OFF
    return RTP_OFF[tb]


def rtp_from_payload(pl):
    """Independent RTP reader: -> ('rtp', tb, ssrc, seq, ts, pt) | ('cut', tb) | ('none', tb|None)."""
    if len(pl) < 9 or pl[0] != 0x05:
        return ("none", None)
    tb = pl[8]
    if tb == 13 and (len(pl) < 8 + T13_SUBTYPE_POS + 1 or pl[8 + T13_SUBTYPE_POS] != T13_RTP_SUBTYPE):
        return ("none", tb)         # p7b: probe padding (0x15) or control, not RTP
    if tb in RTP_OFF:
        o = 8 + rtp_offset(tb, pl)
        if len(pl) < o + 12:
            return ("cut", tb)
        if pl[o] >> 6 != 2:
            return ("none", tb)
        return ("rtp", tb, struct.unpack(">I", pl[o + 8:o + 12])[0], struct.unpack(">H", pl[o + 2:o + 4])[0],
                struct.unpack(">I", pl[o + 4:o + 8])[0], pl[o + 1] & 0x7F)
    if tb in RTCP_OFF:
        o = 8 + RTCP_OFF[tb]
        if len(pl) < o + 8:
            return ("cut", tb)
        return ("rtcp", tb, struct.unpack(">I", pl[o + 4:o + 8])[0], 0, 0, pl[o + 1])
    return ("none", tb)


def check_pcap(path, by_us):
    res = dict(files=0, records=0, bad_magic=0, linktype=set(), snaplen_field=set(), ts_backwards=0,
               truncated=0, cut_before_rtp=0, cut_types=Counter(), no_csv_row=0, matched=0, mismatched=0,
               rtp_parsed=0, plain_matched=0, csv_rows_not_in_pcap=None, bytes_overhead=Counter(), max_caplen=0)
    seen = Counter()
    for fp in pcap_files(path):
        res["files"] += 1
        with open(fp, "rb") as fh:
            gh = fh.read(24)
            if len(gh) < 24:
                continue
            magic = struct.unpack("<I", gh[:4])[0]
            if magic == 0xA1B2C3D4:
                e, scale = "<", 1
            elif magic == 0xD4C3B2A1:
                e, scale = ">", 1
            elif magic == 0xA1B23C4D:
                e, scale = "<", 1000
            else:
                res["bad_magic"] += 1
                continue
            _, _, _, _, snaplen, link = struct.unpack(e + "HHiIII", gh[4:])
            res["linktype"].add(link)
            res["snaplen_field"].add(snaplen)
            last = None
            while True:
                rh = fh.read(16)
                if len(rh) < 16:
                    break
                sec, sub, cap, orig = struct.unpack(e + "IIII", rh)
                buf = fh.read(cap)
                res["records"] += 1
                res["max_caplen"] = max(res["max_caplen"], cap)
                us = sec * 1_000_000 + sub // scale
                if last is not None and us < last:
                    res["ts_backwards"] += 1
                last = us
                if cap < orig:
                    res["truncated"] += 1
                fr = parse_frame(buf)
                if fr is None:
                    continue
                pl, ulen = fr
                res["bytes_overhead"][orig - ulen] += 1
                r = rtp_from_payload(pl)
                if r[0] == "cut":
                    res["cut_before_rtp"] += 1
                    res["cut_types"][r[1]] += 1
                    continue
                if by_us is None:
                    continue
                seen[us] += 1
                rows = by_us.get(us)
                if not rows:
                    res["no_csv_row"] += 1
                    continue
                if r[0] == "none":
                    # no RTP fields to compare: the CSV must say "same header state" (type byte or none)
                    if any(x[0] == r[1] for x in rows):
                        res["plain_matched"] += 1
                    else:
                        res["mismatched"] += 1
                elif r[0] in ("rtp", "rtcp"):
                    res["rtp_parsed"] += 1
                    want = (r[1], r[2], r[3], r[4], r[5]) if r[0] == "rtp" else (r[1], r[2], 0, 0, r[5])
                    if want in rows:
                        res["matched"] += 1
                    else:
                        res["mismatched"] += 1
    if by_us is not None:
        csv_n = sum(len(v) for v in by_us.values())
        res["csv_rows_not_in_pcap"] = csv_n - sum(min(len(by_us.get(k, ())), v) for k, v in seen.items())
        res["csv_rows"] = csv_n
    return res


# ------------------------------------------------------------------ report
def pct(x):
    return "n/a" if x is None else "%.1f%%" % (100 * x)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", help="zoom_record_0001.csv (vc_capture --csv) or packets.csv (zoom_capture --packet-csv); later parts are picked up")
    ap.add_argument("--pcap", help="pcap directory or file from --pcap-dir: cross-check against the CSV")
    ap.add_argument("--max-rows", type=int, default=5_000_000, help="stop after this many unique rows (default 5M, ~1 min)")
    ap.add_argument("--json", help="also write the numbers to this file (no IPs)")
    ap.add_argument("--exclude-mobile", action="store_true",
                    help="leave out clients labelled mobile-like (= mostly Type-21 probe padding, no video; a heuristic) or control-only in the client table")
    ap.add_argument("--clients", help="comma list of client numbers (e.g. 1,3,4) or of names given with --mark / anonymize_csv.py --label: analyse only these")
    ap.add_argument("--mark", help="IP=name,IP=name: tag your own devices in the client table (names are printed, IPs are not)")
    ap.add_argument("--client-map", help="write 'label,ip,class' to this file for use on this machine only; it contains IPs, do not upload it")
    a = ap.parse_args()

    files = csv_files(a.csv)
    for f in files:
        if not os.path.isfile(f):
            sys.exit("ERROR: %s not found" % f)

    # pass 1: who is in the capture
    cl = scan_clients(files, a.max_rows)
    label_clients(cl)
    marks = {ip: c["mark"] for ip, c in cl.items() if c.get("mark")}
    if a.mark:
        for item in a.mark.split(","):
            if "=" in item:
                ip, nm = item.split("=", 1)
                marks[ip.strip()] = nm.strip()
    if a.client_map:
        with open(a.client_map, "w") as fh:
            fh.write("label,ip,class,mark\n")
            for ip, c in sorted(cl.items(), key=lambda kv: kv[1]["label"]):
                fh.write("%s,%s,%s,%s\n" % (c["label"], ip, c["cls"], marks.get(ip, "")))
    client_ok = None
    if a.clients:
        want = set()
        for x in a.clients.split(","):
            x = x.strip()
            if x:
                want.add("client#%d" % int(x) if x.isdigit() else x)
        client_ok = {ip for ip in cl if cl[ip]["label"] in want or marks.get(ip) in want}
        if not client_ok:
            sys.exit("ERROR: --clients %s matches no client (see the client table; names come from --mark or anonymize_csv.py --label)" % a.clients)
    elif a.exclude_mobile:
        client_ok = {ip for ip, c in cl.items() if not c["cls"].startswith(("mobile-like", "control-only"))}

    types, streams, meta, by_us, fec, gaps, other_info = read_csv(files, a.max_rows, keep_for_pcap=bool(a.pcap), client_ok=client_ok)
    summ = summarize(types, streams, fec, gaps)
    verd = {n: verdict(n, summ[n]) for n in ("video", "audio", "screen13", "screen30", "rtcp")}
    dd = dedup_verdict(meta, a.csv)
    cap = {}
    for ip, c in meta.pop("capture_raw", {}).items():
        cap[marks.get(ip) or cl.get(ip, {}).get("label", "?")] = c
    cap_pkts = sum(c["pkts"] for c in cap.values())
    cap_miss = sum(c["missing"] for c in cap.values())
    cap_pct = 100.0 * cap_miss / (cap_pkts + cap_miss) if cap_pkts else None
    allflows = sorted(x for c in cap.values() for x in c["flow_pcts"])
    cap_med = allflows[len(allflows) // 2] if allflows else None

    L = []
    w = L.append
    w("== zoom_capture RTP offset check (validator v2.1) ==")
    w("csv files: %d   rows: %d   unique packets after collapsing second copies (twins): %d   time span: %.0f s%s" % (
        len(files), meta["total"], meta["unique"], meta["span_s"],
        "   [stopped early at --max-rows]" if meta["stopped_early"] else ""))
    if client_ok is not None:
        w("restricted to %d of %d clients (%d rows of the others left out)" % (len(client_ok), len(cl), meta["rows_of_skipped_clients"]))
    w("")
    w("-- de-duplication --")
    w("   second copies (twins): %d flagged by the pipeline, %d NOT flagged (found here by identical content within 10 ms)  ->  %s" % (
        meta["twins_flagged"], meta["twins_missed"], dd[0]))
    for line in dd[1]:
        w("   !! " + line)
    if meta["twin_core_pairs"]:
        w("   missed twins by core pair (first copy -> second copy): " + ", ".join("%s: %d" % kv for kv in meta["twin_core_pairs"].items()))
    elif not meta["has_core_column"]:
        w("   (this CSV has no `core` column; capture again with the current build to see which cores the copies reached)")
    w("")
    w("-- clients (labels by traffic volume; heuristic device class from the packet-type mix) --")
    w("   %-10s %9s %5s %6s %5s %5s %5s %5s  %-30s" % ("client", "packets", "flows", "span_s", "t16%", "t15%", "t21%", "t13%", "class"))
    for ip, c in sorted(cl.items(), key=lambda kv: -kv[1]["n"])[:14]:
        tot = c["n"] or 1
        f = lambda t: 100.0 * c["types"].get(t, 0) / tot
        span = ((c["t1"] or 0) - (c["t0"] or 0)) / 1e9
        nm = ("  <- " + marks[ip]) if ip in marks else ""
        w("   %-10s %9d %5d %6.0f %5.0f %5.0f %5.0f %5.0f  %-30s%s" % (
            c["label"], c["n"], len(c["flows"]), span, f(16), f(15), f(21), f(13), c["cls"], nm))
    if len(cl) > 14:
        w("   ... %d more clients" % (len(cl) - 14))
    w("   t16 = video, t15 = audio, t21 = type 21 (probe padding, 94 % of its packets: deck2 T21-2; NOT video), t13 = screen share")
    w("")
    w("-- capture completeness (from the SFU counter, which ticks once per packet of a flow, any media type) --")
    if cap_pct is None:
        w("   no flow with >= %d typed packets: nothing to judge" % CAPTURE_MIN_PKTS)
    else:
        w("   %-10s %5s %9s %9s %8s" % ("client", "flows", "packets", "missing", "missing%"))
        for lab, c in sorted(cap.items(), key=lambda kv: -kv[1]["pkts"])[:8]:
            w("   %-10s %5d %9d %9d %7.1f%%" % (lab, c["flows"], c["pkts"], c["missing"], 100.0 * c["missing"] / (c["pkts"] + c["missing"])))
        w("   all: %.1f %% of the packets of these flows are missing from the capture (median over %d flows: %.1f %%)" % (cap_pct, len(allflows), cap_med))
        if cap_pct > CAPTURE_NOTE_PCT:
            w("   !! the capture itself loses packets.  Consequences: byte/packet rates are low by about this much, and an RTP sequence")
            w("      gap smaller than this is NOT evidence of network loss.  Check the NIC counters (imissed / rx_nombuf), then the SPAN port.")
    w("")
    if meta["other_types"]:
        w("media types without an RTP offset (not checked): " + ", ".join("%s x%d" % kv for kv in meta["other_types"].most_common(6)))
        for k, v in sorted(other_info.items(), key=lambda kv: -kv[1]["rows"])[:5]:
            w("   %-16s most common UDP lengths: %s" % (k, ", ".join("%d B x%d" % kv for kv in v["top_sizes"])))
    w("")
    w("%-9s %9s %8s %9s %11s %8s  %-8s" % ("type", "packets", "ver==2", "PT in set", "SSRC stable", "seq +1", "verdict"))
    for n in ("video", "audio", "screen13", "screen30", "rtcp"):
        r, (lab, _) = summ[n], verd[n]
        if r.get("rows", 0) == 0:
            w("%-9s %9d %8s %9s %11s %8s  %-8s" % (n, 0, "-", "-", "-", "-", "NO DATA"))
            continue
        if n == "rtcp":
            w("%-9s %9d %8s %9s %11s %8s  %-8s" % (n, r["rows"], pct(r["ver_pass"]), pct(r["rtcp_pt_200_207"]) + "*", pct(r.get("rtcp_ssrc_known")) + "+", "-", lab))
        else:
            if n == "screen30":
                lab = {"PASS": "LOOKS OK", "WARN": "UNSURE", "FAIL": "NOT RTP?", "NO DATA": "NO DATA"}[lab]
            w("%-9s %9d %8s %9s %11s %8s  %-8s" % (n, r["rows"], pct(r["ver_pass"]), pct(r.get("pt_in_set")), pct(r["stable_ssrc_share"]), pct(r["seq_plus1"]), lab))
    w("   * rtcp column 'PT in set' = PT in 200..207;  + rtcp 'SSRC stable' = SSRC also seen as a media SSRC of that client")
    w("   screen rows are packets inside RTP-looking streams only (see the coverage line); screen30 is read at +20 (p6 guessed +27; the p7a offset is confirmed)")
    w("")
    for n in ("video", "audio", "screen13", "screen30", "rtcp"):
        r = summ[n]
        if r.get("rows", 0) == 0:
            continue
        w("-- %s: %d packets%s" % (n, r["rows"], "" if "coverage" in r else ", %.1f%% had too few bytes for an RTP header" % r["no_rtp_pct"]))
        if "coverage" in r:
            w("   coverage: %.0f%% of the %d type-%s packets are in RTP-looking streams (>= %d packets, version 2 >= %d%%)" % (
                100 * r["coverage"], r["all_rows"], n[6:], STREAM_MIN_PKTS, 100 * STREAM_MIN_VER))
            w("   the rest: %.0f%% have a synthetic SSRC (one repeated byte or a small number: padding/probe packets, not screen content), %.0f%% are small control packets or another layout (try tools/probe_unknown_types.py --residual %s)" % (
                100 * r.get("probe_like", 0.0), 100 * (1 - r["coverage"] - r.get("probe_like", 0.0)), n[6:]))
        w("   payload types seen: " + ", ".join("PT%d x%d" % kv for kv in r["pt_top"]))
        if n != "rtcp":
            w("   streams (client,dir,SSRC,PT): %d    seq: +1 %s, forward<=50 %s, backward/reorder %s" % (
                r["streams"], pct(r["seq_plus1"]), pct(r["seq_forward_ok"]), pct(r["seq_backward"])))
            if r["clock_hz_median"] is not None:
                near = r["clock_std_nearest"]
                w("   timestamp clock (from %d long streams): median %.0f Hz -> %s" % (
                    r["clock_streams"], r["clock_hz_median"], ("standard rate %d Hz" % near) if near else "NOT a standard rate"))
            else:
                w("   timestamp clock: no stream with >= 50 packets over >= 5 s")
            if r.get("frame_groups", 0) >= 20:
                w("   frame_seq groups: %d    exactly one RTP timestamp: %s    exactly one encapsulation media_timestamp: %s" % (
                    r["frame_groups"], pct(r["fg_one_rtp_ts"]), pct(r["fg_one_encap_ts"])))
            for pt, m in r.get("marker", {}).items():
                w("   marker bit, PT%d (%d frames): exactly one marker per frame %s, marker on last packet %s" % (
                    pt, m["frames"], pct(m["exactly_one"]), pct(m["on_last"])))
            if "rtp_seq_eq_media_seq" in r:
                w("   RTP seq == encapsulation media_sequence: %s" % pct(r["rtp_seq_eq_media_seq"]))
            g = r.get("gaps")
            if g:
                bt = ", ".join("type %s x%s" % kv for kv in g["by_type"].items())
                w("   sequence gaps (forward steps of 2..50): %d, ~%d packets not seen; %d (%.0f%%) have unparsed packets of the same flow inside: %s" % (
                    g["gaps"], g["missing_packets"], g["explained_by_unparsed_types"],
                    100.0 * g["explained_by_unparsed_types"] / g["gaps"], bt or "-"))
                if n == "video":
                    w("      most video gaps lie BETWEEN frames (the SFU does not forward every frame to every receiver):")
                    w("      do not read them as network loss without the frame-level view in the Stage 2 design")
        for line in verd[n][1]:
            w("   !! " + line)
        w("")
    if "video_fec" in summ:
        f = summ["video_fec"]
        w("-- video PT 110 (FEC-like companion): %d packets (%.1f%% of video), %d streams; RTP timestamp equals a PT98 frame of the same stream: %s; own sequence space forward steps: %s" % (
            f["rows"], 100 * f["share_of_video"], f["streams"], pct(f["same_rtp_ts_as_a_media_frame"]), pct(f["own_seq_forward_ok"])))
        w("   it is kept out of the video sequence statistics above; loss and gap metrics must treat it separately")
        w("")

    pc = None
    if a.pcap:
        pc = check_pcap(a.pcap, by_us)
        w("== pcap cross-check (independent reader, struct only) ==")
        if pc["files"] == 0:
            w("   no .pcap files found at %s" % a.pcap)
        else:
            w("files %d, records %d, link types %s, snaplen field %s, longest record %d B" % (
                pc["files"], pc["records"], sorted(pc["linktype"]), sorted(pc["snaplen_field"]), pc["max_caplen"]))
            if pc["bad_magic"]:
                w("   !! %d file(s) with an unknown pcap magic" % pc["bad_magic"])
            w("timestamps going backwards inside a file: %d  (normal: several cores write one file)" % pc["ts_backwards"])
            w("records cut by the snaplen: %d   of which cut BEFORE the end of the RTP header: %d %s" % (
                pc["truncated"], pc["cut_before_rtp"],
                ("(types %s -> raise --pcap-snaplen)" % dict(pc["cut_types"])) if pc["cut_before_rtp"] else ""))
            if pc["bytes_overhead"]:
                w("frame bytes minus UDP payload bytes (14 Ethernet + 4 per VLAN tag + 20/40 IP): " + ", ".join(
                    "%d B x%d" % kv for kv in pc["bytes_overhead"].most_common(4)))
            if by_us is not None:
                tot = pc["matched"] + pc["mismatched"] + pc["plain_matched"]
                w("packets re-parsed from the pcap bytes vs the CSV row with the same microsecond: %d / %d agree" % (pc["matched"] + pc["plain_matched"], tot))
                w("   (%d with RTP/RTCP fields compared: type, SSRC, seq, timestamp, PT;  %d without RTP compared on header state only)" % (pc["matched"], pc["plain_matched"]))
                w("pcap records with no CSV row at that microsecond: %d    unflagged CSV rows with no pcap record: %s" % (
                    pc["no_csv_row"], pc["csv_rows_not_in_pcap"]))
                if meta["stopped_early"] or client_ok is not None:
                    w("   (the CSV was cut by --max-rows or a client filter, so some pcap records show up as 'no CSV row')")
            w("   note: this confirms the two files describe the same packets and the writers are consistent; it reuses the")
            w("   same offset table as the pipeline, so only the statistics above can confirm the table itself.")
        w("")

    # overall
    labs = {n: verd[n][0] for n in verd}
    if (any(labs[n] == "FAIL" for n in ("video", "audio", "screen13", "rtcp")) or any(labs[n] in ("FAIL", "NO DATA") for n in CORE)
            or dd[0] == "FAIL"):
        overall, code = "NO-GO", 2
    elif any(labs[n] in ("WARN", "NO DATA") for n in ("video", "audio", "screen13", "rtcp")) or dd[0] == "NO DATA":
        overall, code = "GO WITH CAVEATS", 1
    else:
        overall, code = "GO", 0
    if pc and pc["cut_before_rtp"]:
        if overall == "GO":
            overall, code = "GO WITH CAVEATS", 1
    cap_note = None
    if cap_pct is not None and cap_pct > CAPTURE_NOTE_PCT:
        cap_note = "capture loses about %.1f %% of the packets (pooled over flows; busy media flows can lose more, see the per-client table): rates are biased low by that much and RTP loss below it is not measurable" % cap_pct
        if overall == "GO":
            overall, code = "GO WITH CAVEATS", 1
    w("== STAGE 2 (RTP metrics): %s ==" % overall)
    w("   %-9s %s%s" % ("de-dup", dd[0], ("; " + "; ".join(dd[1])) if dd[1] else ""))
    for n in ("video", "audio", "screen13", "screen30", "rtcp"):
        extra = ("; " + "; ".join(verd[n][1])) if verd[n][1] else ""
        w("   %-9s %s%s" % (n, labs[n], extra))
    if cap_note:
        w("   %-9s CAVEAT; %s" % ("capture", cap_note))
    if overall != "GO":
        w("   GO needs video and audio PASS, de-dup PASS, and no FAIL elsewhere.  NO DATA on screen/rtcp only means that kind of")
        w("   traffic was not in the capture: metrics for it stay disabled until a capture contains it.")
    text = "\n".join(L)
    print(text)
    if a.json:
        def clean(o):
            if isinstance(o, dict):
                return {str(k): clean(v) for k, v in o.items()}
            if isinstance(o, (list, tuple, set)):
                return [clean(v) for v in o]
            return o
        clients_json = [dict(label=c["label"], cls=c["cls"], packets=c["n"], flows=len(c["flows"]),
                             types={str(k): v for k, v in c["types"].most_common()}, mark=marks.get(ip))
                        for ip, c in sorted(cl.items(), key=lambda kv: -kv[1]["n"])]
        with open(a.json, "w") as fh:
            json.dump(clean(dict(meta=meta, summary=summ, verdict={k: v[0] for k, v in verd.items()}, dedup=dict(verdict=dd[0], notes=dd[1]),
                                 overall=overall, gaps=gaps, unparsed=other_info, clients=clients_json, pcap=pc,
                                 capture=dict(by_client={k: {kk: vv for kk, vv in v.items() if kk != "flow_pcts"} for k, v in cap.items()},
                                              pooled_missing_pct=cap_pct, median_flow_missing_pct=cap_med))), fh, indent=1)
    sys.exit(code)


if __name__ == "__main__":
    main()
