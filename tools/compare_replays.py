#!/usr/bin/env python3
"""Compare two replays of the SAME pcap: p7a (baseline) against p7b.  New in p7b (roadmap Step 1).

    replay_pcap --no-dedup --lp p7a.lp eve_part1.pcap eve_part2.pcap        # built from the p7a tree
    replay_pcap --no-dedup --lp p7b.lp eve_part1.pcap eve_part2.pcap        # built from the p7b tree
    python3 -I tools/compare_replays.py p7a.lp p7b.lp [--json out.json]

Python 3 standard library only.  Exit code 0 = every identity holds and every difference is one that p7b
is SUPPOSED to make; 1 = something else changed (the report says what); 2 = the files could not be aligned.

WHY this exists.  p7b changes how a few packets are READ (a third video layout, a sub-type gate for type 13),
and the roadmap's acceptance test is "the 21 other sessions are unchanged".  "Unchanged" must be a diff, not a
feeling.  Both replays see exactly the same packets, so almost everything has to match to the last digit:

  IDENTITY 1  total volume.  Per client and direction, summed over the whole replay, packets (pps_*) and bytes
              (throughput_*_bps) are identical.  p7b moves packets between accounting buckets, it never adds
              or removes one.  (Replay with --no-dedup on the unique-packet pcaps, or with the same de-dup
              setting in both runs.)  Per bin the same holds EXCEPT around a stream's qualification: its
              first packets are held and released into the bin in which it qualifies, so a few packets can
              sit one bin later in one run; the report counts such cells as information, not as failure.
  IDENTITY 2  the type-13 split.  p7a unq_screen == p7b unq_screen + t13_probe + t13_ctrl, per client and
              direction, packets and bytes, summed over the replay.  Type-13 packets whose media byte 7 is not
              0x1e left `unq_screen` and went into the two new groups; nothing else about them changed.
  IDENTITY 3  video moves, it does not vanish.  Per client and direction, summed over the whole replay,
              (video + unq_video + fec) is the same in both runs.  Packets of a second video stream (media byte 20
              = 0x90, RTP at +20) were unq_video in p7a and are `video` in p7b once the stream qualifies.
              (Per bin this need not hold: a stream's first packets are held until it qualifies.)
  UNCHANGED   a (client, bin) whose volume groups are all identical must be identical in EVERY other field
              too (fps, jitter, loss, stalls, FEC, degraded, session age ...), except the fields p7b added.

Differences are then sorted into: identical / only the type-13 groups differ (expected) / the video side
differs (expected only if p7b really saw rtp20 or type-13 gating at work, see capture_health) / anything else
(UNEXPECTED: shown with the first differing fields).

How the two files are aligned.  replay_pcap stamps lines with the replay's wall clock, so the absolute times
differ between runs.  Bin edges are multiples of 5 s of capture time, so each file's own first
session_metrics / client_no_media timestamp is taken as bin 0 and every other line is placed by
round((ts - first) / 5 s).  Both files see the same first packet, so bin 0 is the same bin in both; the tool
checks that every timestamp is within 1 ms of a bin edge and stops otherwise.  Session ids are hashes of the
wall-clock start and differ between runs; sessions are matched by client and order, not by id.

Not checked here: the new rules themselves.  The Rust unit tests and tools/validate_rtp_csv.py do that; this
tool only shows the EFFECT of the rules on a real capture and that nothing else moved.
"""
import argparse
import json
import sys
from collections import Counter, defaultdict

BIN_NS = 5_000_000_000
LINE_TYPES = ("session_metrics", "client_no_media")
DIRS = ("uplink", "downlink")
# fields p7b added: ignored when deciding "identical", checked by identity 2 instead
NEW_PREFIXES = ("t13_probe_", "t13_ctrl_")
NEW_HEALTH = ("video_layout_rtp20", "video_rtp20_bytes", "t13_probe", "t13_ctrl")
VOLUME_PREFIXES = ("video_", "audio_", "screen_", "screen13_", "screen30_", "fec_", "rtcp_", "other_", "nohdr_", "type21_",
                   "unq_", "t13_", "nonmedia_", "throughput_", "pps_")
TOL_ABS = 0.06
# every field a second video stream can move: the video volume group, the per-stream video metrics, and the
# per-flow loss / sequence-gap numbers that are computed over the video streams
VIDEO_SIDE = ("video_", "unq_video_", "fec_", "fps_", "jitter_", "frame_gap_", "stalls_", "retransmits_", "degraded_",
              "loss_pct_", "lost_pkts_", "expected_pkts_", "seq_gap_", "seq_expected_", "unq_media_", "throughput_", "pps_")


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


def parse_line(ln):
    """-> (measurement, tags dict, fields dict of raw text, ts int) or None"""
    ln = ln.rstrip("\n")
    if not ln or ln.startswith("#"):
        return None
    head, fields, ts = ln.rsplit(" ", 2)
    parts = head.split(",")
    tags = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
    f = {}
    for kv in split_fields(fields):
        k, v = kv.split("=", 1)
        f[k] = v
    return parts[0], tags, f, int(ts)


def num(v):
    if v is None:
        return 0.0
    if v.endswith("i"):
        return float(v[:-1])
    return float(v)


def load(path):
    """-> dict with 'bins': {(client, k): (meas, fields)}, 'health', 'summaries': {client: [fields]}, 'streams': Counter, 'ref', 'n'"""
    rows = []
    health = None
    summaries = defaultdict(list)
    streams = {}
    with open(path) as fh:
        for ln in fh:
            r = parse_line(ln)
            if r is None:
                continue
            meas, tags, f, ts = r
            if meas in LINE_TYPES:
                rows.append((ts, tags.get("client_ip", "?"), meas, f))
            elif meas == "capture_health":
                health = f
            elif meas == "session_summary":
                summaries[tags.get("client_ip", "?")].append(f)
            elif meas == "zoom_rtp_stream":
                streams[(tags.get("client_ip", "?"), tags.get("ssrc", tags.get("stream", "?")), ts)] = f
    if not rows:
        sys.exit(f"{path}: no session_metrics / client_no_media lines (empty replay, or not a replay_pcap file)")
    ref = min(r[0] for r in rows)
    bins = {}
    worst = 0
    for ts, client, meas, f in rows:
        k = round((ts - ref) / BIN_NS)
        worst = max(worst, abs((ts - ref) - k * BIN_NS))
        bins[(client, k)] = (meas, f)
    return dict(bins=bins, health=health or {}, summaries=summaries, streams=streams, ref=ref, n=len(rows), worst=worst,
                last=max(k for _, k in bins))


def fmt_ns(ns):
    return "%.3f ms" % (ns / 1e6)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("a", help="baseline .lp (p7a)")
    ap.add_argument("b", help="new .lp (p7b)")
    ap.add_argument("--json", help="write the numbers to this file")
    ap.add_argument("--show", type=int, default=5, help="how many examples to print per problem (default 5)")
    args = ap.parse_args()

    A, B = load(args.a), load(args.b)
    L = []
    w = L.append
    out = {}
    bad = 0                                                       # count of UNEXPECTED findings
    for name, X in (("A", A), ("B", B)):
        if X["worst"] > 1_000_000:
            print(f"cannot align: file {name} has a line {fmt_ns(X['worst'])} away from a 5 s bin edge (replay_pcap bins should sit on edges).", file=sys.stderr)
            sys.exit(2)
    w("== compare_replays: A = %s   B = %s ==" % (args.a, args.b))
    w("lines: A %d, B %d    last bin: A %d, B %d    clients: A %d, B %d" % (
        A["n"], B["n"], A["last"], B["last"], len({c for c, _ in A["bins"]}), len({c for c, _ in B["bins"]})))
    if "video_layout_rtp20" in A["health"] or any(k.startswith(NEW_PREFIXES) for _, (_, f) in list(A["bins"].items())[:50] for k in f):
        w("   !! file A already has p7b fields (video_layout_rtp20 / t13_probe_*): it is not a p7a replay. Identity 2 compares p7a's unq_screen with")
        w("      p7b's split groups and will report differences if A is also p7b. Build replay_pcap from the p7a tree for A.")
    only_a = sorted(set(A["bins"]) - set(B["bins"]))
    only_b = sorted(set(B["bins"]) - set(A["bins"]))
    both = sorted(set(A["bins"]) & set(B["bins"]))
    w("(client, bin) lines in both: %d   only in A: %d   only in B: %d" % (len(both), len(only_a), len(only_b)))
    if only_a or only_b:
        bad += 1
        w("   !! the two replays do not have the same lines. Examples (client token, bin): A-only %s   B-only %s" % (only_a[:args.show], only_b[:args.show]))
        w("      (a different last bin means the replays did not read the same packets; check the file lists and --max-packets)")
    out["lines"] = dict(both=len(both), only_a=len(only_a), only_b=len(only_b))

    # ---- identity 1 and 2 are checked on the TOTAL per client and direction over the whole replay (exact), and per
    # bin as information: a stream that qualifies holds its first packets and releases them into the bin in which it
    # qualifies, so a few packets can sit one bin later in one run than in the other without any packet being lost.
    def tot(X, key_fn):
        """-> {(client, dir): [packets, bytes]} summed over all bins; key_fn(fields, dir) -> (pps, bps)"""
        t = defaultdict(lambda: [0.0, 0.0])
        for (client, k), (meas, f) in X["bins"].items():
            for d in DIRS:
                p_, b_ = key_fn(f, d)
                t[(client, d)][0] += p_ * 5
                t[(client, d)][1] += b_ * 5 / 8
        return t

    def g(f, d, name):
        return num(f.get("%s_pps_%s" % (name, d))), num(f.get("%s_bitrate_%s_bps" % (name, d)))

    def totals_only(f, d):
        return num(f.get("pps_%s" % d)), num(f.get("throughput_%s_bps" % d))

    def screen_a(f, d):
        return g(f, d, "unq_screen")

    def screen_b(f, d):
        x, y, z = g(f, d, "unq_screen"), g(f, d, "t13_probe"), g(f, d, "t13_ctrl")
        return x[0] + y[0] + z[0], x[1] + y[1] + z[1]

    def diff_totals(ta, tb):
        return [(k, ta[k], tb[k]) for k in sorted(set(ta) | set(tb)) if abs(ta[k][0] - tb[k][0]) > 0.5 or abs(ta[k][1] - tb[k][1]) > 1.0]

    def perbin(fn_a, fn_b):
        n = 0
        for key in both:
            fa, fb = A["bins"][key][1], B["bins"][key][1]
            for d in DIRS:
                x, y = fn_a(fa, d), fn_b(fb, d)
                if abs(x[0] - y[0]) > 0.011 or abs(x[1] - y[1]) > TOL_ABS:
                    n += 1
        return n

    i1 = diff_totals(tot(A, totals_only), tot(B, totals_only))
    n1 = perbin(totals_only, totals_only)
    w("")
    w("IDENTITY 1  total volume per client and direction over the whole replay: %d (client, direction) pairs differ" % len(i1))
    w("   (information: %d (client, bin, direction) cells differ in the same bin; held packets released at stream qualification move between bins)" % n1)
    if i1:
        bad += 1
        for key, x, y in i1[:args.show]:
            w("   !! %s %s: A %.0f pkts %.0f B   B %.0f pkts %.0f B" % (key[0], key[1], x[0], x[1], y[0], y[1]))
    out["identity1_mismatches"] = len(i1)

    ta, tb = tot(A, screen_a), tot(B, screen_b)
    i2 = diff_totals(ta, tb)
    n2 = perbin(screen_a, screen_b)
    moved = {d: [0.0, 0.0] for d in DIRS}
    for (client, d), v in tot(B, lambda f, d: tuple(a + b for a, b in zip(g(f, d, "t13_probe"), g(f, d, "t13_ctrl")))).items():
        moved[d][0] += v[0]
        moved[d][1] += v[1]
    w("")
    w("IDENTITY 2  p7a unq_screen == p7b (unq_screen + t13_probe + t13_ctrl), per client and direction over the whole replay: %d pairs differ" % len(i2))
    w("   (information: %d cells differ in the same bin)" % n2)
    w("   moved out of unq_screen by the type-13 gate: uplink %.0f packets / %.0f bytes, downlink %.0f packets / %.0f bytes" % (
        moved["uplink"][0], moved["uplink"][1], moved["downlink"][0], moved["downlink"][1]))
    if i2:
        bad += 1
        for key, x, y in i2[:args.show]:
            w("   !! %s %s: A unq_screen %.0f pkts %.0f B   B sum %.0f pkts %.0f B" % (key[0], key[1], x[0], x[1], y[0], y[1]))
    out["identity2_mismatches"] = len(i2)
    out["t13_moved_packets"] = {d: moved[d][0] for d in DIRS}

    # ---- identity 3: video moves (per client + direction, whole replay)
    sums = {"A": defaultdict(float), "B": defaultdict(float)}
    vid_pkts = {"A": Counter(), "B": Counter()}
    for tag, X in (("A", A), ("B", B)):
        for (client, k), (meas, f) in X["bins"].items():
            for d in DIRS:
                for g in ("video", "unq_video", "fec"):
                    v = num(f.get("%s_pps_%s" % (g, d))) * 5
                    sums[tag][(client, d)] += v
                    if g == "video":
                        vid_pkts[tag][(client, d)] += v
    i3 = [(key, sums["A"][key], sums["B"][key]) for key in sorted(set(sums["A"]) | set(sums["B"])) if abs(sums["A"][key] - sums["B"][key]) > 0.5]
    gained = {key: vid_pkts["B"][key] - vid_pkts["A"][key] for key in set(vid_pkts["A"]) | set(vid_pkts["B"]) if abs(vid_pkts["B"][key] - vid_pkts["A"][key]) > 0.5}
    w("")
    w("IDENTITY 3  video + unq_video + fec per client and direction over the whole replay: %d differ" % len(i3))
    w("   client/direction pairs whose `video` packet count changed: %d  (total change %+.0f packets)" % (len(gained), sum(gained.values())))
    if i3:
        bad += 1
        for key, x, y in i3[:args.show]:
            w("   !! %s %s: A %.0f  B %.0f packets" % (key[0], key[1], x, y))
    out["identity3_mismatches"] = len(i3)
    out["video_gained_packets"] = sum(gained.values())

    # ---- classification of the differences, per client
    # A video-side METRIC (fps, jitter, loss ...) may differ only for a client whose video VOLUME (video_*, unq_video_*, fec_*)
    # or session state also differs somewhere: a second video stream shows up as packets first. A jitter difference
    # on a client whose video packets are accounted identically has no explanation in p7b.
    VIDEO_VOLUME = ("video_bitrate", "video_pps", "unq_video_", "fec_", "unq_media_", "line_type")
    diffs = {}
    for key in both:
        fa, fb = A["bins"][key][1], B["bins"][key][1]
        diff = {f for f in set(fa) | set(fb) if not f.startswith(NEW_PREFIXES) and fa.get(f) != fb.get(f)}
        if A["bins"][key][0] != B["bins"][key][0]:
            diff.add("line_type")           # client_no_media <-> session_metrics: a session opened or closed
        diffs[key] = diff
    video_volume_changed = defaultdict(bool)
    for (client, k), diff in diffs.items():
        if any(f.startswith(VIDEO_VOLUME) for f in diff):
            video_volume_changed[client] = True
    per_client = defaultdict(lambda: dict(bins=0, same=0, t13_only=0, video=0, other=0))
    examples_other = []
    for key in both:
        diff = diffs[key]
        c = per_client[key[0]]
        c["bins"] += 1
        if not diff:
            c["same"] += 1
            continue
        t13 = {f for f in diff if f.startswith("unq_screen_")}
        rest = diff - t13
        if not rest:
            c["t13_only"] += 1
            continue
        video_side = {f for f in rest if f.startswith(VIDEO_SIDE) or f == "line_type"}
        other = rest - video_side
        if not video_volume_changed[key[0]]:
            other = rest                    # video-side metrics changed without any video packet moving: unexplained
        if not other:
            c["video"] += 1
        else:
            c["other"] += 1
            if len(examples_other) < args.show:
                examples_other.append((key, sorted(other)[:6]))
    n_cl = len(per_client)
    ident = [c for c, v in per_client.items() if v["same"] == v["bins"]]
    t13c = [c for c, v in per_client.items() if v["same"] != v["bins"] and v["video"] == 0 and v["other"] == 0]
    vidc = [c for c, v in per_client.items() if v["video"] and not v["other"]]
    othc = [c for c, v in per_client.items() if v["other"]]
    w("")
    w("PER CLIENT   %d clients with lines in both replays" % n_cl)
    w("   identical in every bin and every field (the 'unchanged sessions' of the roadmap): %d" % len(ident))
    w("   differ only in the type-13 groups (expected where the client shared a screen / was probed): %d" % len(t13c))
    w("   differ on the video side (expected only where a second video stream exists, see below): %d" % len(vidc))
    w("   differ in some OTHER field: %d" % len(othc))
    if othc:
        bad += 1
        for key, fl in examples_other:
            w("   !! %s bin %d: %s" % (key[0], key[1], ", ".join(fl)))
    out["clients"] = dict(total=n_cl, identical=len(ident), t13_only=len(t13c), video_side=len(vidc), other=len(othc))

    # ---- the explanation for the video-side differences comes from capture_health
    ha, hb = A["health"], B["health"]
    w("")
    w("CAPTURE_HEALTH (last line of each replay; p7a has no layout counters for rtp20)")
    keys = ["rtp_qualified", "rtp_failed_qual", "rtp_probation_skipped", "rtp_streams_rejected", "rtp_short",
            "rtp_ok_video", "rtp_bad_video", "rtp_ok_screen13", "rtp_bad_screen13", "rtp_ok_screen30", "rtp_bad_screen30",
            "video_layout_02", "video_layout_0a", "video_layout_rtp20", "video_layout_other", "video_rtp20_bytes"]
    for k in keys:
        if k in ha or k in hb:
            w("   %-24s A %-12s B %s" % (k, ha.get(k, "-"), hb.get(k, "-")))
    rtp20 = int(num(hb.get("video_layout_rtp20")))
    other = int(num(hb.get("video_layout_other")))
    out["health"] = {k: [ha.get(k), hb.get(k)] for k in keys}
    if vidc and rtp20 == 0:
        bad += 1
        w("   !! video-side differences exist but p7b saw no rtp20 packet: something other than the new layout changed the video numbers")
    if rtp20 > 0 and not vidc:
        w("   note: p7b saw %d rtp20 packets but no client's video numbers differ (the stream may never have qualified: look at rtp_failed_qual)" % rtp20)
    if other > 0:
        w("   !! p7b saw %d video packets with a media byte 20 outside 0x02 / 0x0a / 0x80-0xBF (layout `other`): a fourth layout? Look at them with tools/probe_unknown_types.py" % other)

    # ---- streams that only B has (needs --ssrc-lines in both runs)
    if A["streams"] or B["streams"]:
        ka = {(c, s) for c, s, _ in A["streams"]}
        kb = {(c, s) for c, s, _ in B["streams"]}
        new = sorted(kb - ka)
        lost = sorted(ka - kb)
        w("")
        w("STREAMS (zoom_rtp_stream lines): A %d streams, B %d streams; only in B: %d (the new rtp20 streams, expected), only in A: %d" % (len(ka), len(kb), len(new), len(lost)))
        if lost:
            bad += 1
            w("   !! streams that p7a had and p7b lost: %s" % lost[:args.show])
        out["streams"] = dict(a=len(ka), b=len(kb), only_b=len(new), only_a=len(lost))

    # ---- sessions
    sess_diff = []
    for c in sorted(set(A["summaries"]) | set(B["summaries"])):
        sa, sb = A["summaries"].get(c, []), B["summaries"].get(c, [])
        if len(sa) != len(sb):
            sess_diff.append((c, "session count A %d B %d" % (len(sa), len(sb))))
            continue
        for i, (x, y) in enumerate(zip(sa, sb)):
            d = [f for f in ("bytes_uplink", "bytes_downlink", "bins", "media_bins", "had_video", "had_audio", "had_screen", "duration_s") if x.get(f) != y.get(f)]
            if d:
                sess_diff.append((c, "session %d: %s" % (i + 1, ", ".join(d))))
    w("")
    w("SESSIONS (matched by client and order; start/end/id differ by wall clock and are not compared): %d clients, %d with a difference" % (
        len(set(A["summaries"]) | set(B["summaries"])), len({c for c, _ in sess_diff})))
    for c, msg in sess_diff[:args.show]:
        w("   %s %s" % (c, msg))
    out["session_differences"] = len(sess_diff)

    w("")
    if bad:
        w("RESULT: %d finding(s) marked !! above: p7b changed something it should not have, or the two runs did not read the same packets." % bad)
    else:
        w("RESULT: PASS. Every identity holds; every difference is in the type-13 groups or on the video side where p7b saw a new layout.")
    print("\n".join(L))
    if args.json:
        out["unexpected_findings"] = bad
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=1)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
