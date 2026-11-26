#!/usr/bin/env python3
"""csv_timeline_report.py  --  READ-ONLY. Works on the program's own CSV (meet_rtp_records.csv), no PCAP needed.

    python3 csv_timeline_report.py RUN_DIR/meet_rtp_records.csv
    python3 csv_timeline_report.py RUN_DIR/meet_rtp_records.csv --client 10.184.15.225 --client 10.184.4.232 \
            --client 2001:df4:e000:3fd2:17d4:ef69:c5aa:727
    python3 csv_timeline_report.py RUN_DIR/meet_rtp_records.csv --min-s 10 --max-lines 80

WHY IT EXISTS: the PCAP stops at --pcap-max-mb (2000 MB = 6-9 minutes on this feed) but the CSV (600 MB cap)
covers the whole run. The CSV only holds packets that SURVIVED the dedup, so a swallowed stream is simply
missing - but that is exactly what leaves a recognisable trace:

  1) the client's downlink video is zero (by the program's own rule) while the client is alive;
  2) the stream that finally appears was already in the dedup table: its first counted packet is within 64
     sequence numbers of the newest number held for that SSRC by ANOTHER flow (a normal new stream would be
     thousands away: P(|d| < 64) is about 0.4 % for a random start). That is the moment the swallow ended.
  3) the same SSRC value appears as uplink on one client and downlink on another (lineage).

Output (local time of the machine running it):
  1) clients: first/last packet, rows
  2) downlink video per client: first counted video, zero intervals while the client is alive
  3) flows that entered the dedup table "within 64 of an existing maximum" = swallow that just ended
  4) SSRCs seen as uplink on one client and downlink on another

Numbers use the same rules as the program: video = udp_len > 400; a stream counts in a 5 s bin (epoch-aligned)
if it has >= 2 distinct RTP timestamps and one sorted gap in [1500, 90000]; down_fps = mean over such streams of
(distinct timestamps / 5).  Needs only the Python 3 standard library; about 1 minute per 3-4 million rows.
"""
import argparse
import collections
import datetime
import ipaddress
import sys

BIN_S = 5
MIN_GAP, MAX_GAP = 1500, 90000
MEET_NETS = ["74.125.250.0/24", "74.125.247.128/32", "142.250.82.0/24",
             "2001:4860:4864:5::/64", "2001:4860:4864:6::/64", "2001:4860:4864:4:8000::/128"]


def hms(t):
    return datetime.datetime.fromtimestamp(t).strftime("%H:%M:%S")


def valid_fps(ts_sets):
    f = []
    for ts in ts_sets:
        if len(ts) < 2:
            continue
        s = sorted(ts)
        if any(MIN_GAP <= ((s[i] - s[i - 1]) & 0xFFFFFFFF) <= MAX_GAP for i in range(1, len(s))):
            f.append(len(ts) / BIN_S)
    return sum(f) / len(f) if f else 0.0


def i16(d):
    d &= 0xFFFF
    return d - 65536 if d >= 32768 else d


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="+")
    ap.add_argument("--client", action="append", default=[])
    ap.add_argument("--server-net", action="append", default=[])
    ap.add_argument("--min-s", type=int, default=15, help="shortest zero interval to list (seconds)")
    ap.add_argument("--max-lines", type=int, default=60, help="max lines per section")
    ap.add_argument("--dump-fps", metavar="FILE", help="also write client,bin_start_epoch,influx_point_epoch (= bin end, what Grafana shows),down_fps,up_fps,down_small_pkts per 5 s bin")
    a = ap.parse_args()

    nets = [ipaddress.ip_network(x) for x in MEET_NETS + a.server_net]
    cache = {}

    def is_server(ip):
        r = cache.get(ip)
        if r is None:
            o = ipaddress.ip_address(ip)
            r = cache[ip] = any(o in n for n in nets if n.version == o.version)
        return r

    roster = {}                                   # client -> [t0, t1, up_rows, down_rows]
    bins = {}                                     # (client, bin) -> [down_ts{ssrc:set}, down_small, up_ts{ssrc:set}, up_other]
    mx = {}                                       # ssrc -> [max_seq, holder_flow, holder_time]
    flows = {}                                    # (client, dir, ssrc) -> [t0, t1, n, pts, entry]
    rows = 0
    for path in a.csv:
        with open(path) as f:
            f.readline()
            for ln in f:
                p = ln.split(",")
                if len(p) < 13:
                    continue
                rows += 1
                t = int(p[0]) / 1e9
                src, dst = p[1], p[2]
                if is_server(dst):
                    client, d = src, "up"
                elif is_server(src):
                    client, d = dst, "down"
                else:
                    continue
                ulen = int(p[7])
                ssrc = int(p[8], 16)
                rts = int(p[9])
                seq = int(p[10])
                pt = int(p[11])
                r = roster.get(client)
                if r is None:
                    r = roster[client] = [t, t, 0, 0]
                r[1] = t
                r[2 if d == "up" else 3] += 1
                b = (client, int(t // BIN_S))
                e = bins.get(b)
                if e is None:
                    e = bins[b] = [collections.defaultdict(set), 0, collections.defaultdict(set), 0]
                if d == "down":
                    if ulen > 400:
                        e[0][ssrc].add(rts)
                    else:
                        e[1] += 1
                else:
                    if ulen > 400:
                        e[2][ssrc].add(rts)
                    else:
                        e[3] += 1
                # dedup table as the program holds it: only kept rows move the maximum
                fk = (client, d, ssrc)
                fl = flows.get(fk)
                m = mx.get(ssrc)
                if fl is None:
                    entry = None
                    if m is not None and m[1] != (client, d):
                        entry = (i16(seq - m[0]), m[1], m[2])
                    fl = flows[fk] = [t, t, 0, set(), entry]
                fl[1] = t
                fl[2] += 1
                fl[3].add(pt)
                if m is None:
                    mx[ssrc] = [seq, (client, d), t]
                else:
                    if 0 < i16(seq - m[0]):
                        m[0] = seq
                    m[1], m[2] = (client, d), t

    if not rows:
        sys.exit("no rows")
    show = lambda c: not a.client or c in a.client
    print(f"CSV rows read {rows}; clients {len(roster)}")
    t_all0 = min(r[0] for r in roster.values())
    t_all1 = max(r[1] for r in roster.values())
    print(f"time span {hms(t_all0)} - {hms(t_all1)}  ({t_all1 - t_all0:.0f} s)\n")

    if a.dump_fps:
        with open(a.dump_fps, "w") as out:
            out.write("client,bin_start_epoch,influx_point_epoch,down_fps,up_fps,down_small_pkts\n")
            for (c, b), e in sorted(bins.items()):
                if show(c):
                    out.write(f"{c},{b * BIN_S},{b * BIN_S + BIN_S},{valid_fps(e[0].values()):.2f},{valid_fps(e[2].values()):.2f},{e[1]}\n")

    # 1 clients
    print("1) Clients (first/last counted packet, rows)")
    n = 0
    for c, r in sorted(roster.items(), key=lambda x: x[1][0]):
        if show(c):
            n += 1
            if n <= a.max_lines:
                print(f"   {c:42s} {hms(r[0])} - {hms(r[1])}  up rows {r[2]:>8d}  down rows {r[3]:>8d}")
    for c in a.client:
        if c not in roster:
            print(f"   {c:42s} NOT IN THIS CSV (no counted packet to/from a Meet server range)")
    print()

    # 2 downlink video timeline
    print("2) Downlink video per client (zero = the program's down_fps would be 0.00)")
    allb = collections.defaultdict(dict)
    for (c, b), e in bins.items():
        allb[c][b] = e
    for c, d in sorted(allb.items(), key=lambda x: roster[x[0]][0]):
        if not show(c):
            continue
        b0, b1 = min(d), max(d)
        state = []
        for b in range(b0, b1 + 1):
            e = d.get(b)
            if e is None:
                state.append((b, "silent", 0.0, 0, 0.0))
                continue
            fps = valid_fps(e[0].values())
            ufps = valid_fps(e[2].values())
            dl = sum(len(v) for v in e[0].values()) + e[1]
            if fps > 0:
                state.append((b, "video", fps, dl, ufps))
            elif dl > 0:
                state.append((b, "zero_dl", 0.0, dl, ufps))
            else:
                state.append((b, "zero_ul", 0.0, 0, ufps))
        first_v = next((s for s in state if s[1] == "video"), None)
        print(f"   client {c}: first packet {hms(roster[c][0])}, "
              + (f"first downlink video counted {hms(first_v[0] * BIN_S)} (+{max(0.0, first_v[0] * BIN_S - roster[c][0]):.0f} s)" if first_v else "downlink video NEVER counted"))
        i, lines = 0, 0
        while i < len(state):
            if state[i][1] in ("zero_dl", "zero_ul"):
                j = i
                while j + 1 < len(state) and state[j + 1][1] in ("zero_dl", "zero_ul", "silent"):
                    j += 1
                seg = [s for s in state[i:j + 1] if s[1] != "silent"]
                secs = (j - i + 1) * BIN_S
                if secs >= a.min_s and seg:
                    dl_active = sum(1 for s in seg if s[1] == "zero_dl")
                    ufps = sum(s[4] for s in seg) / len(seg)
                    lines += 1
                    if lines <= a.max_lines:
                        print(f"      zero {hms(state[i][0] * BIN_S)} - {hms((state[j][0] + 1) * BIN_S)} ({secs:>4d} s)  "
                              f"downlink packets in {dl_active}/{len(seg)} bins, uplink video {ufps:4.1f} fps; "
                              + (f"video resumes {hms(state[j + 1][0] * BIN_S)}" if j + 1 < len(state) else "no video until the CSV ends"))
                i = j + 1
            else:
                i += 1
    print()

    # 3 flows that entered within 64 of an existing maximum
    print("3) Flows whose FIRST counted packet is within 64 of the newest number another flow left for the same SSRC")
    print("   (a fresh stream would be thousands away; |d| < 64 means a swallow that just ended - or the same stream moving between flows)")
    hits = []
    for (c, d, ssrc), fl in flows.items():
        en = fl[4]
        if en is None or ssrc == 0 or not show(c):
            continue
        if -64 < en[0] <= 64:
            hits.append((fl[0], c, d, ssrc, en, fl))
    for t0, c, d, ssrc, en, fl in sorted(hits)[:a.max_lines]:
        print(f"   {hms(t0)}  {c:36s} {d:4s} 0x{ssrc:08X} pt {','.join(map(str, sorted(fl[3])))}: first seq is {en[0]:+d} from the maximum held by "
              f"{en[1][0]} ({en[1][1]}), last updated {hms(en[2])} ({t0 - en[2]:.0f} s before); client first seen {hms(roster[c][0])}, "
              f"flow rows {fl[2]}")
    if not hits:
        print("   none")
    print()

    # 4 lineage
    print("4) SSRCs seen as uplink on one client and downlink on another")
    byss = collections.defaultdict(lambda: {"up": [], "down": []})
    for (c, d, ssrc), fl in flows.items():
        byss[ssrc][d].append((c, fl))
    k = 0
    for ssrc, v in sorted(byss.items(), key=lambda x: x[0]):
        if ssrc == 0:
            continue
        for cu, fu in v["up"]:
            for cd, fd in v["down"]:
                if cu != cd and (show(cu) or show(cd)) and fu[2] > 20 and fd[2] > 20:
                    k += 1
                    if k <= a.max_lines:
                        print(f"   0x{ssrc:08X}: up@{cu} {hms(fu[0])}-{hms(fu[1])} ({fu[2]} rows, pt {','.join(map(str, sorted(fu[3])))})  |  "
                              f"down@{cd} {hms(fd[0])}-{hms(fd[1])} ({fd[2]} rows, pt {','.join(map(str, sorted(fd[3])))})")
    if not k:
        print("   none")
    print("\nLimits: the CSV cannot show packets the dedup removed, so a zero here is a candidate swallow, not proof; section 3 and the")
    print("PCAP report (dedup_swallow_report.py) are what turn it into proof. 'silent' bins (no counted packet at all) are not listed as zero.")


if __name__ == "__main__":
    main()