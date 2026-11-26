#!/usr/bin/env python3
"""Look for duplicate RTP packets in the CSV and PCAP files of a capture_data run.

    tools/check_dups.py captures/run_20261101_120000            # finds the standard files itself
    tools/check_dups.py --csv teams_rtp_records.csv --pcap teams_traffic_rtp.pcap
    tools/check_dups.py RUN_DIR --horizon-s 30 --examples 10 --json report.json

Exit code: 0 = nothing wrong, 1 = duplicate rows in a CSV that should have none (or a counter
mismatch), 2 = bad usage or unreadable file.   Needs only the Python 3 standard library.

WHAT COUNTS AS A DUPLICATE
  Two packets with the same (RTP SSRC, sequence number, RTP timestamp) that arrive within
  --horizon-s seconds of each other.  The timestamp is part of the key on purpose: the 16-bit
  sequence number wraps every 65 536 packets (about 22 s of a 3 000 packet/s video stream), and a
  wrapped number comes back with a different RTP timestamp, so it is NOT a duplicate.
  Each repeat is put in one class:

    byte_identical         PCAP only. Same flow, whole frame equal, byte for byte.
    same_packet_other_hdr  PCAP only. Same flow, same IP-ID and UDP payload, but the frame differs
                           (other MAC addresses, TTL, VLAN tag). This is the "tunnel leg + wired leg"
                           twin of the campus Wi-Fi (project notes, dup-check try4).
    same_fields            CSV only. Same flow and same ip_len, udp_len, payload type, marker. The CSV
                           has no payload, so it cannot tell the two kinds above apart.
    content_differs        Same key and flow, but length/payload differ. Should be ~0; a large number
                           means sequence/timestamp reuse or a corrupted capture, not twins.
    cross_flow             Same key, but a different (src ip, dst ip, src port, dst port). The sequence
                           rule (--dedup seq) does NOT look at the flow, so it silently drops the
                           second flow's packet; the fingerprint rule (--dedup fp) keeps it. Two cases
                           look the same here: a forwarded stream (SFU sends one sender's packet to two
                           campus clients: real, different packets) and a twin that was rewritten (NAT).
                           Look at the examples to decide.

WHAT TO EXPECT
  PCAP  holds every RTP frame BEFORE dedup  -> twins are normal there; the script only counts them.
  CSV   holds the packets AFTER dedup:
    --dedup seq (formerly "on")  the repeat count should be 0.
    --dedup fp                   a repeat in the CSV is either a MISSED TWIN (same flow, less than 10 ms
                                 after the first copy: a table-slot collision, a handful per
                                 100 000 packets in the synthetic tests, a problem above 1 %) or a packet kept on purpose
                                 (same flow, 10 ms or more later: a retransmission or a probe; another
                                 flow: the SFU sent the packet to two clients). Those are reported, not failed.
    --dedup off                  the CSV keeps the twins, so it has about as many repeats as the PCAP.
  If both files are given, the script also reconciles them:  PCAP frames - CSV rows  should equal the
  twins found in the PCAP (seq), the same-flow repeats under 10 ms minus the missed twins in the CSV (fp),
  or 0 (off), unless a cap, a queue drop or a "too old" drop got in the way; the difference is printed
  so you can see it.

LIMITS (OPEN, said once so they are not forgotten)
  * A repeat further apart than --horizon-s (default 10 s) is not seen: memory is kept bounded by
    forgetting packets older than that.  A twin is normally < 10 ms apart.
  * The program stamps packets with the wall clock when its callback runs (not the NIC time), and the
    PCAP stores microseconds, so gaps below ~10 us are indicative only.
  * Fragmented IP packets, IPv6 extension headers and pcapng files are not parsed (counted as 'skipped').
"""
import argparse
import collections
import json
import os
import socket
import struct
import sys
import zlib

GAP_EDGES_NS = [10_000, 100_000, 1_000_000, 10_000_000, 100_000_000]
GAP_LABELS = ["<10 us", "10-100 us", "0.1-1 ms", "1-10 ms", "10-100 ms", ">=100 ms"]
CLASSES = ["byte_identical", "same_packet_other_hdr", "same_fields", "content_differs", "cross_flow"]


def gap_bin(gap_ns):
    for i, edge in enumerate(GAP_EDGES_NS):
        if gap_ns < edge:
            return i
    return len(GAP_EDGES_NS)


def ip_text(b):
    try:
        if isinstance(b, str):
            return b
        return socket.inet_ntop(socket.AF_INET if len(b) == 4 else socket.AF_INET6, b)
    except Exception:
        return repr(b)


def same_flow_repeats_under_10ms(c):
    """Repeats of one flow closer than 10 ms (the fp window): twins, or retransmissions the 10 ms window also drops."""
    return sum(c.gaps[cls][i] for cls in CLASSES if cls != "cross_flow" for i in range(4))


def flow_text(flow):
    src, dst, sp, dp = flow
    a, b = ip_text(src), ip_text(dst)
    fa = f"[{a}]" if ":" in a else a
    fb = f"[{b}]" if ":" in b else b
    return f"{fa}:{sp} -> {fb}:{dp}"


class Counter2:
    """Streaming duplicate finder with bounded memory (forgets packets older than the horizon)."""

    def __init__(self, horizon_ns, kind, max_examples):
        self.horizon = horizon_ns
        self.kind = kind  # "csv" or "pcap"
        self.max_examples = max_examples
        self.seen = {}  # key -> [t_first, flow, sig, copies, where]
        self.q = collections.deque()  # (t_first, key) of first sightings, oldest first
        self.now = 0
        self.rows = 0
        self.dups = 0
        self.classes = collections.Counter()
        self.gaps = {c: [0] * (len(GAP_EDGES_NS) + 1) for c in CLASSES}
        self.max_gap = {c: 0 for c in CLASSES}  # largest gap per class (ns): the headroom of the 10 ms window of --dedup fp
        self.multiplicity = collections.Counter()  # copies seen -> number of keys
        self.flow_rows = collections.Counter()
        self.flow_dups = collections.Counter()
        self.examples = {c: [] for c in CLASSES}
        self.t_min = None
        self.t_max = None
        self.out_of_order = 0

    def _evict(self):
        limit = self.now - self.horizon
        q, seen = self.q, self.seen
        while q and q[0][0] < limit:
            t, key = q.popleft()
            e = seen.get(key)
            if e is not None and e[0] == t:
                self.multiplicity[e[3]] += 1
                del seen[key]

    def add(self, t, key, flow, sig, where):
        self.rows += 1
        self.flow_rows[flow] += 1
        if self.t_min is None or t < self.t_min:
            self.t_min = t
        if self.t_max is None or t > self.t_max:
            self.t_max = t
        if t < self.now:
            self.out_of_order += 1
        else:
            self.now = t
        self._evict()
        e = self.seen.get(key)
        if e is None:
            self.seen[key] = [t, flow, sig, 1, where]
            self.q.append((t, key))
            return
        e[3] += 1
        self.dups += 1
        self.flow_dups[flow] += 1
        if flow != e[1]:
            cls = "cross_flow"
        elif self.kind == "pcap":
            if sig[0] == e[2][0]:
                cls = "byte_identical"
            elif sig[1] == e[2][1]:
                cls = "same_packet_other_hdr"
            else:
                cls = "content_differs"
        else:
            cls = "same_fields" if sig == e[2] else "content_differs"
        self.classes[cls] += 1
        gap = max(0, t - e[0])
        self.gaps[cls][gap_bin(gap)] += 1
        if gap > self.max_gap[cls]:
            self.max_gap[cls] = gap
        ex = self.examples[cls]
        if len(ex) < self.max_examples:
            ex.append({"first": e[4], "repeat": where, "gap_us": round(gap / 1000, 1),
                       "ssrc": f"0x{key[0]:08X}", "seq": key[1], "rtp_ts": key[2],
                       "flow": flow_text(flow), "first_flow": flow_text(e[1])})

    def finish(self):
        for e in self.seen.values():
            self.multiplicity[e[3]] += 1
        self.seen.clear()
        self.q.clear()


# ───────────────────────────── readers ─────────────────────────────
def iter_csv(path, stats):
    """Yield (line_no, t_ns, flow, key, sig) per row. Counts malformed rows in stats['bad']."""
    with open(path, "r", newline="", buffering=1 << 20) as f:
        header = f.readline().rstrip("\r\n").split(",")
        want = ["arrival_epoch_ns", "src_ip", "dst_ip", "ip_len", "src_port", "dst_port", "udp_len",
                "rtp_ssrc", "rtp_timestamp", "rtp_seq", "rtp_pt", "rtp_marker"]
        missing = [w for w in want if w not in header]
        if missing:
            raise ValueError(f"{path}: not a capture_data CSV, missing columns {missing}")
        ix = {n: header.index(n) for n in want}
        n_cols = len(header)
        i_t, i_s, i_d, i_il, i_sp, i_dp, i_ul = (ix[k] for k in
            ("arrival_epoch_ns", "src_ip", "dst_ip", "ip_len", "src_port", "dst_port", "udp_len"))
        i_ssrc, i_ts, i_seq, i_pt, i_m = (ix[k] for k in
            ("rtp_ssrc", "rtp_timestamp", "rtp_seq", "rtp_pt", "rtp_marker"))
        for ln, line in enumerate(f, start=2):
            p = line.rstrip("\r\n").split(",")
            if len(p) != n_cols:
                stats["bad"] += 1  # e.g. last line cut off when the run was killed
                continue
            try:
                t = int(p[i_t])
                flow = (p[i_s], p[i_d], int(p[i_sp]), int(p[i_dp]))
                key = (int(p[i_ssrc], 16), int(p[i_seq]), int(p[i_ts]))
                sig = (p[i_il], p[i_ul], p[i_pt], p[i_m])
            except ValueError:
                stats["bad"] += 1
                continue
            yield ln, t, flow, key, sig


def iter_pcap(path, stats):
    """Yield (frame_no, t_ns, flow, key, sig) per RTP frame. Classic pcap only."""
    with open(path, "rb", buffering=1 << 20) as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise ValueError(f"{path}: shorter than a pcap header")
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            end, ns = "<", False
        elif magic == b"\xa1\xb2\xc3\xd4":
            end, ns = ">", False
        elif magic == b"\x4d\x3c\xb2\xa1":
            end, ns = "<", True
        elif magic == b"\xa1\xb2\x3c\x4d":
            end, ns = ">", True
        elif magic == b"\x0a\x0d\x0d\x0a":
            raise ValueError(f"{path}: pcapng is not supported (capture_data writes classic pcap)")
        else:
            raise ValueError(f"{path}: not a pcap file (magic {magic.hex()})")
        link = struct.unpack(end + "I", gh[20:24])[0]
        if link != 1:
            raise ValueError(f"{path}: link type {link}, expected 1 (Ethernet)")
        hdr = struct.Struct(end + "IIII")
        n = 0
        while True:
            h = f.read(16)
            if not h:
                break
            if len(h) < 16:
                stats["truncated"] = True
                break
            sec, frac, incl, _orig = hdr.unpack(h)
            data = f.read(incl)
            if len(data) < incl:
                stats["truncated"] = True
                break
            n += 1
            r = parse_frame(data)
            if r is None:
                stats["skipped"] += 1
                continue
            flow, key, ip_id, pay_crc = r
            t = sec * 1_000_000_000 + (frac if ns else frac * 1000)
            yield n, t, flow, key, (zlib.crc32(data), (ip_id, pay_crc))


def parse_frame(d):
    """Ethernet(+VLAN) / IPv4 or IPv6 / UDP / RTP  ->  (flow, (ssrc, seq, ts), ip_id, payload_crc) or None."""
    n = len(d)
    if n < 14:
        return None
    o = 12
    et = (d[o] << 8) | d[o + 1]
    o += 2
    tags = 0
    while et in (0x8100, 0x88A8, 0x9100, 0x9200) and tags < 4:
        if n < o + 4:
            return None
        et = (d[o + 2] << 8) | d[o + 3]
        o += 4
        tags += 1
    if et == 0x0800:
        if n < o + 20:
            return None
        ihl = (d[o] & 15) * 4
        if d[o + 9] != 17 or ihl < 20 or n < o + ihl + 8:
            return None
        if ((d[o + 6] << 8) | d[o + 7]) & 0x3FFF:  # more-fragments flag or offset
            return None
        ip_id = (d[o + 4] << 8) | d[o + 5]
        src, dst = bytes(d[o + 12:o + 16]), bytes(d[o + 16:o + 20])
        u = o + ihl
    elif et == 0x86DD:
        if n < o + 48 or d[o + 6] != 17:
            return None
        ip_id = 0
        src, dst = bytes(d[o + 8:o + 24]), bytes(d[o + 24:o + 40])
        u = o + 40
    else:
        return None
    sport, dport, ulen = struct.unpack_from("!HHH", d, u)
    pay = u + 8
    end = min(n, u + ulen)
    if end - pay < 12:
        return None
    b0, b1 = d[pay], d[pay + 1]
    if (b0 >> 6) != 2 or 200 <= b1 <= 207:  # RTP version 2; byte 1 of 200-207 is RTCP (the program's own rule, protocol.rs)
        return None
    seq, ts, ssrc = struct.unpack_from("!HII", d, pay + 2)
    return (src, dst, sport, dport), (ssrc, seq, ts), ip_id, zlib.crc32(d[pay:end])


# ───────────────────────────── run_info.txt ─────────────────────────────
def read_run_info(run_dir):
    p = os.path.join(run_dir, "run_info.txt") if run_dir else None
    if not p or not os.path.exists(p):
        return None
    info = {}
    for line in open(p):
        if "=" in line:
            k, v = line.rstrip("\n").split("=", 1)
            info[k] = v
    return info


# ───────────────────────────── analysis + report ─────────────────────────────
def analyse(path, kind, args):
    stats = {"bad": 0, "skipped": 0, "truncated": False}
    c = Counter2(int(args.horizon_s * 1e9), kind, args.examples)
    it = iter_csv(path, stats) if kind == "csv" else iter_pcap(path, stats)
    label = "line" if kind == "csv" else "frame"
    for no, t, flow, key, sig in it:
        c.add(t, key, flow, sig, f"{label} {no}")
        if c.rows % 5_000_000 == 0:
            print(f"  ... {os.path.basename(path)}: {c.rows:,} {kind} rows read", file=sys.stderr)
    c.finish()
    return {"path": path, "kind": kind, "c": c, "stats": stats}


def pct(a, b):
    return f"{100.0 * a / b:.4f}%" if b else "n/a"


def print_file_report(r, top_flows):
    c, st = r["c"], r["stats"]
    name = os.path.basename(r["path"])
    span = ((c.t_max - c.t_min) / 1e9) if c.t_min is not None else 0
    print(f"\n=== {name}  ({r['kind'].upper()})")
    print(f"  packets read            : {c.rows:,}   (span {span:.1f} s)")
    extra = []
    if st["bad"]:
        extra.append(f"{st['bad']} malformed rows")
    if st["skipped"]:
        extra.append(f"{st['skipped']} frames not parsed as UDP/RTP (skipped)")
    if st["truncated"]:
        extra.append("file ends in the middle of a record (run killed?)")
    if c.out_of_order:
        extra.append(f"{c.out_of_order} rows earlier than a previous row (eviction uses the latest time seen)")
    if extra:
        print("  note                    : " + "; ".join(extra))
    print(f"  distinct packets        : {c.rows - c.dups:,}")
    print(f"  repeats (duplicates)    : {c.dups:,}   = {pct(c.dups, c.rows)} of packets")
    if c.dups:
        print("  by class:")
        for cls in CLASSES:
            if c.classes[cls]:
                print(f"    {cls:<22}: {c.classes[cls]:>10,}  ({pct(c.classes[cls], c.rows)})")
        print("  gap between first copy and repeat (all classes):")
        tot = [sum(c.gaps[cls][i] for cls in CLASSES) for i in range(len(GAP_LABELS))]
        print("    " + "   ".join(f"{lab}: {n:,}" for lab, n in zip(GAP_LABELS, tot) if n))
        print("  largest gap per class   : " + "   ".join(
            f"{cls} {c.max_gap[cls] / 1e6:.3f} ms" for cls in CLASSES if c.classes[cls])
            + "   (--dedup fp drops a repeat only if it is closer than 10 ms)")
        mult = ", ".join(f"{k} copies: {v:,}" for k, v in sorted(c.multiplicity.items()) if k > 1)
        print(f"  packets seen more than once: {mult}")
        print(f"  top flows by repeats (of {len(c.flow_rows)} flows):")
        for flow, n in c.flow_dups.most_common(top_flows):
            print(f"    {flow_text(flow)}: {n:,} repeats of {c.flow_rows[flow]:,} packets ({pct(n, c.flow_rows[flow])})")
        for cls in CLASSES:
            if c.examples[cls]:
                print(f"  examples, {cls}:")
                for ex in c.examples[cls]:
                    print(f"    {ex['first']} then {ex['repeat']} (+{ex['gap_us']} us)  ssrc {ex['ssrc']} seq {ex['seq']} "
                          f"rtp_ts {ex['rtp_ts']}  {ex['flow']}" + (f"  (first: {ex['first_flow']})" if ex['first_flow'] != ex['flow'] else ""))


def platform_of(path):
    b = os.path.basename(path).lower()
    return "teams" if b.startswith("teams") else "meet" if b.startswith("meet") else b


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir", nargs="?", help="run folder holding teams_/meet_record_NNNN.csv/.pcap (vc_capture) or teams_/meet_rtp_records.csv, *_traffic_rtp.pcap (capture_data), and run_info.txt")
    ap.add_argument("--csv", action="append", default=[], help="a CSV file (repeatable)")
    ap.add_argument("--pcap", action="append", default=[], help="a PCAP file (repeatable)")
    ap.add_argument("--horizon-s", type=float, default=10.0, help="forget packets older than this many seconds (default 10)")
    ap.add_argument("--examples", type=int, default=3, help="example pairs to print per class (default 3)")
    ap.add_argument("--top-flows", type=int, default=5, help="flows to list (default 5)")
    ap.add_argument("--json", metavar="FILE", help="also write the numbers as JSON")
    args = ap.parse_args()

    csvs, pcaps = list(args.csv), list(args.pcap)
    info = None
    if args.run_dir:
        if not os.path.isdir(args.run_dir):
            ap.error(f"{args.run_dir} is not a folder")
        info = read_run_info(args.run_dir)
        # old capture_data names, then the vc_capture parts (teams_record_0001.csv, ...).
        # Zoom files (zoom_record_*) have another layout and are not read here.
        import glob
        for n in ("teams_rtp_records.csv", "meet_rtp_records.csv"):
            if os.path.exists(os.path.join(args.run_dir, n)):
                csvs.append(os.path.join(args.run_dir, n))
        for n in ("teams_traffic_rtp.pcap", "meet_traffic_rtp.pcap"):
            if os.path.exists(os.path.join(args.run_dir, n)):
                pcaps.append(os.path.join(args.run_dir, n))
        for plat in ("teams", "meet"):
            csvs += sorted(glob.glob(os.path.join(args.run_dir, f"{plat}_record_[0-9][0-9][0-9][0-9].csv")))
            pcaps += sorted(glob.glob(os.path.join(args.run_dir, f"{plat}_record_[0-9][0-9][0-9][0-9].pcap")))
    if not csvs and not pcaps:
        ap.error("nothing to check: give a run folder or --csv / --pcap files "
                 "(a run started without --csv/--pcap writes none; see run_info.txt)")
    if info is None and csvs:
        info = read_run_info(os.path.dirname(os.path.abspath(csvs[0])))

    dedup_mode = info.get("dedup") if info else None
    if dedup_mode == "on":          # old name of --dedup seq (runs made before fp existed)
        dedup_mode = "seq"
    print("check_dups: duplicate = same (RTP ssrc, seq, rtp timestamp) within "
          f"{args.horizon_s:g} s")
    if info:
        print(f"run_info.txt: csv={info.get('csv')} pcap={info.get('pcap')} dedup={dedup_mode}"
              f" csv_max_bytes={info.get('csv_max_bytes')} pcap_max_bytes={info.get('pcap_max_bytes')}"
              + ("" if "finished_unix" in info else "   (no final counters: the run did not finish cleanly)"))

    results = []
    try:
        for p in csvs:
            results.append(analyse(p, "csv", args))
        for p in pcaps:
            results.append(analyse(p, "pcap", args))
    except (OSError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    for r in results:
        print_file_report(r, args.top_flows)

    # ── reconcile CSV with PCAP, per platform ────────────────────────────────
    problems = []
    notes = []
    recon = {}
    by = {(platform_of(r["path"]), r["kind"]): r for r in results}
    capped = False
    if info and "finished_unix" in info:
        capped = info.get("final_csv_full") == "true" or info.get("final_pcap_full") == "true"
    for plat in ("teams", "meet"):
        cs, pc = by.get((plat, "csv")), by.get((plat, "pcap"))
        if not cs or not pc:
            continue
        csv_rows, pcap_rows, pcap_dups = cs["c"].rows, pc["c"].rows, pc["c"].dups
        diff = pcap_rows - csv_rows
        if dedup_mode == "fp":
            # fp drops same-flow repeats under 10 ms, keeps the rest (retransmissions, other flows) and misses a few twins
            pcap_dups = same_flow_repeats_under_10ms(pc["c"]) - same_flow_repeats_under_10ms(cs["c"])
        recon[plat] = {"pcap_frames": pcap_rows, "csv_rows": csv_rows, "difference": diff,
                       "pcap_repeats": pcap_dups, "unexplained": diff - pcap_dups if dedup_mode != "off" else diff}
        print(f"\n=== reconcile {plat}: PCAP frames {pcap_rows:,} - CSV rows {csv_rows:,} = {diff:,}")
        if capped:
            print("  a --csv-max-mb / --pcap-max-mb limit was reached in this run, so the two files cover "
                  "different stretches of time and the counts are not comparable.")
            continue
        if dedup_mode == "off":
            print(f"  dedup was off: expected 0.  Unexplained: {diff:,}")
            if diff:
                notes.append(f"{plat}: dedup off but PCAP and CSV differ by {diff:,} (record-queue drops, a killed run?)")
        else:
            un = diff - pcap_dups
            if dedup_mode == "fp":
                print(f"  same-flow repeats under 10 ms in the PCAP, minus the ones left in the CSV: {pcap_dups:,}"
                      f"  ->  not explained by them: {un:,}")
            else:
                print(f"  repeats found in the PCAP: {pcap_dups:,}  ->  not explained by repeats: {un:,}")
            if un > 0:
                print("  (frames the program dropped that are not repeats by this key: 'too old' drops - see the "
                      "final statistics - or record-queue drops)")
            elif un < 0:
                print("  (fewer rows were removed than repeats exist: dedup may be off, or repeats were more than "
                      f"{args.horizon_s:g} s apart / not seen by the program's own rule)")
                notes.append(f"{plat}: PCAP holds {-un:,} more repeats than were removed from the CSV")

    # ── compare with the program's own counters ──────────────────────────────
    if info and "finished_unix" in info:
        csv_total = sum(r["c"].rows for r in results if r["kind"] == "csv")
        pcap_total = sum(r["c"].rows for r in results if r["kind"] == "pcap")
        if info.get("csv") == "on" and csvs:
            want = int(info.get("final_csv_rows", -1))
            ok = want == csv_total
            print(f"\nprogram counter final_csv_rows={want:,} vs rows read {csv_total:,}: {'match' if ok else 'MISMATCH'}")
            if not ok:
                problems.append(f"CSV rows read ({csv_total:,}) differ from the program's counter ({want:,})")
        if info.get("pcap") == "on" and pcaps:
            want = int(info.get("final_pcap_frames", -1))
            ok = want == pcap_total + sum(r["stats"]["skipped"] for r in results if r["kind"] == "pcap")
            print(f"program counter final_pcap_frames={want:,} vs frames read {pcap_total:,} "
                  f"(+{sum(r['stats']['skipped'] for r in results if r['kind'] == 'pcap')} skipped): {'match' if ok else 'MISMATCH'}")
            if not ok:
                problems.append("PCAP frames read differ from the program's counter")

    # ── verdict ───────────────────────────────────────────────────────────────
    print("\n=== verdict")
    csv_dups = sum(r["c"].dups for r in results if r["kind"] == "csv")
    pcap_dups = sum(r["c"].dups for r in results if r["kind"] == "pcap")
    code = 0
    if csvs and dedup_mode == "fp":
        csv_rows_total = sum(r["c"].rows for r in results if r["kind"] == "csv")
        missed = sum(same_flow_repeats_under_10ms(r["c"]) for r in results if r["kind"] == "csv")
        cross_csv = sum(r["c"].classes["cross_flow"] for r in results if r["kind"] == "csv")
        later = csv_dups - missed - cross_csv
        pct = 100.0 * missed / csv_rows_total if csv_rows_total else 0.0
        print(f"  CSV : {csv_dups:,} repeated packets (dedup fp): {missed:,} missed twins (same flow, under 10 ms; "
              f"{pct:.3f} % of the rows; a few table-slot collisions are normal, more than 1 % is a problem), {later:,} identical packets of the same flow 10 ms or more "
              f"later (retransmissions, probes: kept on purpose), {cross_csv:,} on another flow (the SFU sent the packet to "
              f"two clients, or a probe: kept on purpose)")
        if pct > 1.0:
            problems.append(f"{missed:,} twins left in the CSV ({pct:.2f} % of the rows) although the run had --dedup fp: "
                            "table too small for this rate, or twins further apart than the window?")
    elif csvs:
        if csv_dups == 0:
            print("  CSV : no repeated packets" + (f" (as expected with dedup {dedup_mode})" if dedup_mode == "seq" else ""))
        elif dedup_mode == "off":
            print(f"  CSV : {csv_dups:,} repeated packets - expected, the run had --dedup off")
        else:
            print(f"  CSV : {csv_dups:,} repeated packets"
                  + (" although the run had --dedup seq: dedup missed them (more than 64 sequence numbers apart, "
                     "other SSRC state, or a different file)" if dedup_mode == "seq"
                     else " (run_info.txt not found: cannot tell whether dedup was on)"))
            problems.append(f"{csv_dups:,} duplicate rows in CSV")
    if pcaps:
        print(f"  PCAP: {pcap_dups:,} repeated packets (raw capture, before dedup: twins are expected here)")
    cross = sum(r["c"].classes["cross_flow"] for r in results)
    if cross:
        if dedup_mode == "fp":
            print(f"  note: {cross:,} repeats are 'cross_flow' (same ssrc/seq/timestamp, different flow). --dedup fp "
                  "keeps those (the flow is part of the fingerprint); check the examples above.")
        else:
            print(f"  note: {cross:,} repeats are 'cross_flow' (same ssrc/seq/timestamp, different flow). --dedup seq "
                  "does not look at the flow and drops those too; check the examples above.")
    for n in notes:
        print("  note:", n)
    for p in problems:
        print("  PROBLEM:", p)
        code = 1

    if args.json:
        out = {"horizon_s": args.horizon_s, "run_info": info, "reconcile": recon, "files": []}
        for r in results:
            c = r["c"]
            out["files"].append({"path": r["path"], "kind": r["kind"], "packets": c.rows, "repeats": c.dups,
                                 "classes": dict(c.classes), "gaps": {k: v for k, v in c.gaps.items() if sum(v)},
                                 "gap_labels": GAP_LABELS, "multiplicity": {str(k): v for k, v in c.multiplicity.items()},
                                 "bad_rows": r["stats"]["bad"], "skipped_frames": r["stats"]["skipped"],
                                 "examples": {k: v for k, v in c.examples.items() if v}})
        with open(args.json, "w") as f:
            json.dump(out, f, indent=1)
        print(f"\nJSON written to {args.json}")
    return code


if __name__ == "__main__":
    sys.exit(main())
