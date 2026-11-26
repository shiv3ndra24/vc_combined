#!/usr/bin/env python3
"""Per-second timeline of a zoom_capture packet CSV: small, anonymous, whole run.

    python3 -I tools/timeline_summary.py packets.csv timeline.csv --mark 10.1.2.3=my-pca,10.1.2.9=my-pcb

Why this exists.  To compare a run with what you did during it ("a's video on at
75 s, screen share 195-256 s ...") we need the WHOLE run, but the packet CSV is
big (140 MB for a 5-minute run) and holds campus IPs.  `anonymize_csv.py
--max-rows` shrinks it by cutting the END off, which is exactly where the later
events are.  This tool shrinks it by counting instead: one row per
(second, device, direction, packet type) with the packet count and bytes.  A
5-minute run with two devices is a few thousand rows (~300 KB), covers every
second, and contains no IP address (devices appear under the names you give
with --mark; every other client is summed into "other").

Output columns of timeline.csv
    sec       whole second since the capture start (time_offset_s, floor)
    who       the --mark name, or "other"
    dir       up (client -> server) or down
    type      media_type_byte, or -1 when the packet has no Zoom media header
    class     the pipeline's class (video, audio, screen, rtcp, other, nohdr)
    pkts      packets in that second (second copies the pipeline flagged as duplicates are NOT counted)
    udp_bytes sum of the UDP length fields
    frames    distinct (rtp_ssrc, rtp_timestamp) pairs: video frames / screen frames
              completed or started in that second (0 when the packet has no RTP header)

Besides the file it prints, per device, the first and last second in which each
(direction, type) carried at least --min-pkts packets, i.e. the on/off times of
video, audio, screen share, probes ... so a glance at the console already
answers "did the video start when I turned it on?".

Rotated files (packets.1.csv, ...) are read too, like the validator does.
"""
import argparse
import csv
import glob
import os
import re
import sys
from collections import defaultdict


def csv_files(path):
    stem, ext = os.path.splitext(path)
    rot = []
    for p in glob.glob(glob.escape(stem) + ".*" + ext):
        m = re.fullmatch(re.escape(stem) + r"\.(\d+)" + re.escape(ext), p)
        if m:
            rot.append((int(m.group(1)), p))
    return [path] + [p for _, p in sorted(rot)]


def summarise(paths, marks):
    cells = defaultdict(lambda: [0, 0, set()])  # (sec, who, dir, type, class) -> [pkts, bytes, frames]
    n_rows = n_flagged = 0
    for path in paths:
        with open(path, newline="") as f:
            rd = csv.reader(f)
            head = next(rd)
            ix = {c: i for i, c in enumerate(head)}
            need = ["time_offset_s", "udp_len", "src_ip", "dst_ip", "dir", "class", "media_type_byte", "dup"]
            miss = [c for c in need if c not in ix]
            if miss:
                sys.exit("ERROR: %s lacks columns %s; is it a zoom_capture --packet-csv file?" % (path, miss))
            i_t, i_len, i_s, i_d, i_dir = ix["time_offset_s"], ix["udp_len"], ix["src_ip"], ix["dst_ip"], ix["dir"]
            i_cls, i_mt, i_dup = ix["class"], ix["media_type_byte"], ix["dup"]
            i_ssrc, i_rts = ix.get("rtp_ssrc"), ix.get("rtp_timestamp")
            for row in rd:
                n_rows += 1
                if row[i_dup] == "1":
                    n_flagged += 1
                    continue
                try:
                    sec = int(float(row[i_t]))
                except ValueError:
                    continue
                up = row[i_dir] == "up"
                who = marks.get(row[i_s] if up else row[i_d], "other")
                try:
                    mt = int(row[i_mt]) if row[i_mt] else -1
                except ValueError:
                    mt = -1
                c = cells[(sec, who, row[i_dir], mt, row[i_cls])]
                c[0] += 1
                try:
                    c[1] += int(row[i_len])
                except ValueError:
                    pass
                if i_ssrc is not None and row[i_ssrc] and row[i_rts]:
                    c[2].add((row[i_ssrc], row[i_rts]))
    return cells, n_rows, n_flagged


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src", help="packets.csv written by zoom_capture --packet-csv (raw, with IPs; stays on this machine)")
    ap.add_argument("dst", help="timeline.csv to write (no IPs; safe to upload)")
    ap.add_argument("--mark", required=True, help="IP=name,IP=name  your own devices (client IP -> name); everybody else becomes 'other'")
    ap.add_argument("--min-pkts", type=int, default=5, help="a second counts as 'active' for the on/off summary at this many packets (default 5)")
    a = ap.parse_args()
    marks = {}
    for item in a.mark.split(","):
        if "=" in item:
            ip, nm = item.split("=", 1)
            marks[ip.strip()] = nm.strip().replace(",", "_")
    if not marks:
        sys.exit("ERROR: --mark IP=name,... is empty")
    paths = csv_files(a.src)
    cells, n_rows, n_flag = summarise(paths, marks)
    seen = {w for (_, w, _, _, _) in cells}
    for ip, nm in marks.items():
        if nm not in seen:
            print("WARNING: device %s produced no rows in this file (wrong address?)" % nm)
    with open(a.dst, "w", newline="") as fo:
        w = csv.writer(fo, lineterminator="\n")
        w.writerow(["sec", "who", "dir", "type", "class", "pkts", "udp_bytes", "frames"])
        for key in sorted(cells):
            c = cells[key]
            w.writerow(list(key) + [c[0], c[1], len(c[2])])
    print("read %d rows from %d file(s), %d flagged duplicates skipped -> %d summary rows in %s" % (n_rows, len(paths), n_flag, len(cells), a.dst))

    # on/off summary
    per = defaultdict(lambda: defaultdict(int))  # (who,dir,type,class) -> sec -> pkts
    for (sec, who, d, mt, cls), c in cells.items():
        per[(who, d, mt, cls)][sec] += c[0]
    print("\nactive seconds (>= %d packets/s) per device, direction and packet type; first - last (number of active seconds)" % a.min_pkts)
    for who in sorted({k[0] for k in per} - {"other"}) + (["other"] if "other" in {k[0] for k in per} else []):
        print("\n  %s" % who)
        for key in sorted(k for k in per if k[0] == who):
            secs = sorted(s for s, n in per[key].items() if n >= a.min_pkts)
            if not secs:
                continue
            _, d, mt, cls = key
            print("    %-4s type %-3s %-6s %4d - %-4d s  (%d s active)" % (d, mt, cls, secs[0], secs[-1], len(secs)))


if __name__ == "__main__":
    main()
