#!/usr/bin/env python3
"""dedup_swallow_report.py  --  READ-ONLY diagnostic for the capture_data duplicate filter.

    python3 dedup_swallow_report.py RUN_DIR/<capture>.pcap
    python3 dedup_swallow_report.py x.pcap --csv RUN_DIR/meet_rtp_records.csv
    python3 dedup_swallow_report.py x.pcap --client 10.184.4.232 --server-net 142.251.0.0/16

It changes nothing: it re-reads a PCAP (which holds every RTP frame BEFORE the program's dedup),
re-plays the program's dedup rule on it (src/dedup.rs: key = SSRC only, 16-bit sequence number,
64-packet window, "64 or more behind" is dropped and does not move the window), and prints, per
client and 5 s bin, what was ON THE WIRE next to what the program KEPT.  So you can tell apart
    * a real zero      (no video packets for that client on the wire)
    * a swallowed zero (video packets are on the wire but the dedup rule dropped them)
    * an unrecognised  (video-sized packets exist but fail the program's "valid stream" rule)

Needs only the Python 3 standard library.  Classic .pcap only (the program writes that).

WHAT IT APPROXIMATES (said once): the RFC 7983 demux is reduced to "first byte 0x80-0xBF and
second byte not 200-207" (RTP v2, not RTCP); the server gate uses the Meet ranges from
src/ip_ranges.rs plus any --server-net you add; fragmented IP and IPv6 extension headers are
skipped.  If --csv is given the kept counts are checked against the program's own CSV, which
shows whether this replay is faithful for YOUR run (it should match exactly when nothing was
dropped by a size cap or a full queue).
"""
import argparse
import collections
import csv
import datetime
import ipaddress
import socket
import struct
import sys

BIN_S = 5
MIN_GAP, MAX_GAP = 1500, 90000          # program: valid video stream = a tick gap in this range
MEET_NETS = ["74.125.250.0/24", "74.125.247.128/32", "142.250.82.0/24",
             "2001:4860:4864:5::/64", "2001:4860:4864:6::/64", "2001:4860:4864:4:8000::/128"]


# ───────────────────────── dedup rule: line-for-line copy of src/dedup.rs ─────────────────────────
class Dedup:
    NEW, DUP, OLD = "new", "dup", "too_old"

    def __init__(self):
        self.s = {}                      # ssrc -> [max_seq, window]

    def check(self, ssrc, seq):
        e = self.s.get(ssrc)
        if e is None:
            self.s[ssrc] = [seq, 1]
            return self.NEW, 0
        d = (seq - e[0]) & 0xFFFF
        d = d - 65536 if d >= 32768 else d       # i16, wrap-safe
        if d == 0:
            return self.DUP, 0
        if d > 0:
            e[1] = 1 if d >= 64 else ((e[1] << d) | 1) & 0xFFFFFFFFFFFFFFFF
            e[0] = seq
            return self.NEW, d
        off = -d
        if off >= 64:
            return self.OLD, d
        bit = 1 << off
        if e[1] & bit:
            return self.DUP, d
        e[1] |= bit
        return self.NEW, d


# ───────────────────────── minimal pcap + packet parsing ─────────────────────────
def read_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            sys.exit("not a pcap file")
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            en = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            en = ">"
        else:
            sys.exit("not a classic pcap (pcapng is not supported)")
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        link = struct.unpack(en + "I", gh[20:24])[0]
        if link != 1:
            sys.exit(f"link type {link} not supported (need Ethernet)")
        hdr = struct.Struct(en + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            s, frac, cap, _orig = hdr.unpack(h)
            data = f.read(cap)
            if len(data) < cap:
                return
            yield s + frac / (1e9 if nano else 1e6), data


def parse(data):
    """-> (src_ip_str, dst_ip_str, sport, dport, udp_len, seq, ts, ssrc, pt) or None"""
    n = len(data)
    if n < 14:
        return None
    et = (data[12] << 8) | data[13]
    off = 14
    if et == 0x88A8:
        if n < 22:
            return None
        et = (data[16] << 8) | data[17]
        off = 18
        if et == 0x8100:
            et = (data[20] << 8) | data[21]
            off = 22
    elif et == 0x8100:
        if n < 18:
            return None
        et = (data[16] << 8) | data[17]
        off = 18
    if et == 0x0800:
        if n < off + 20 or data[off + 9] != 17:
            return None
        ihl = (data[off] & 15) * 4
        if ihl < 20 or ((data[off + 6] & 0x3F) << 8 | data[off + 7]):      # fragment
            return None
        src = socket.inet_ntop(socket.AF_INET, bytes(data[off + 12:off + 16]))
        dst = socket.inet_ntop(socket.AF_INET, bytes(data[off + 16:off + 20]))
        u = off + ihl
    elif et == 0x86DD:
        if n < off + 40 or data[off + 6] != 17:
            return None
        src = socket.inet_ntop(socket.AF_INET6, bytes(data[off + 8:off + 24]))
        dst = socket.inet_ntop(socket.AF_INET6, bytes(data[off + 24:off + 40]))
        u = off + 40
    else:
        return None
    if n < u + 8 + 12:
        return None
    sp, dp, ulen = struct.unpack("!HHH", data[u:u + 6])
    r = u + 8
    b0, b1 = data[r], data[r + 1]
    if (b0 & 0xC0) != 0x80 or 200 <= b1 <= 207:        # not RTP v2, or RTCP
        return None
    seq, ts, ssrc = struct.unpack("!HII", data[r + 2:r + 12])
    return src, dst, sp, dp, ulen, seq, ts, ssrc, b1 & 0x7F


def hms(t):
    return datetime.datetime.fromtimestamp(t).strftime("%H:%M:%S")


def valid_fps(ts_sets):
    """program rule: mean over valid streams of unique timestamps / 5 ; 0.0 if no valid stream."""
    fps = []
    for ts in ts_sets:
        if len(ts) < 2:
            continue
        s = sorted(ts)
        if any(MIN_GAP <= ((s[i] - s[i - 1]) & 0xFFFFFFFF) <= MAX_GAP for i in range(1, len(s))):
            fps.append(len(ts) / BIN_S)
    return sum(fps) / len(fps) if fps else 0.0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--csv", action="append", default=[], help="program CSV(s) to cross-check kept counts")
    ap.add_argument("--client", action="append", default=[], help="only show these client IPs")
    ap.add_argument("--server-net", action="append", default=[], help="extra server CIDR (repeatable)")
    ap.add_argument("--min-episode-pkts", type=int, default=30, help="smallest swallow episode to list")
    ap.add_argument("--max-packets", type=int, default=0)
    a = ap.parse_args()

    nets = [ipaddress.ip_network(x) for x in MEET_NETS + a.server_net]
    cache = {}

    def is_server(ip):
        r = cache.get(ip)
        if r is None:
            ipo = ipaddress.ip_address(ip)
            r = cache[ip] = any(ipo in n for n in nets if n.version == ipo.version)
        return r

    dd = Dedup()
    t_first = None
    total = gated = 0
    kept_by = collections.Counter()                  # (src,dst,ssrc) -> kept rows (replay)
    ss = {}                                          # (client,dir,ssrc) -> stats
    ssrc_clients = collections.defaultdict(lambda: collections.defaultdict(list))   # (dir,ssrc)->client->[t0,t1]
    bins = {}                                        # (client,bin,ssrc) -> [wire_ts,kept_ts,wire_n,kept_n,old_n]
    audio_dl = collections.Counter()                 # (client,bin) -> downlink small packets on wire
    episodes = []                                    # swallow episodes
    open_ep = {}                                     # (ssrc,client) -> episode dict
    tot_v = collections.Counter()

    for t, data in read_pcap(a.pcap):
        total += 1
        if a.max_packets and total > a.max_packets:
            break
        p = parse(data)
        if p is None:
            continue
        src, dst, sp, dp, ulen, seq, rts, ssrc, pt = p
        up = is_server(dst)
        down = is_server(src)
        if not (up or down):
            continue
        gated += 1
        if t_first is None:
            t_first = t
        client, direction = (src, "up") if up else (dst, "down")
        v, d = dd.check(ssrc, seq)
        tot_v[v] += 1
        if v == Dedup.NEW:
            kept_by[(src, dst, ssrc)] += 1
        st = ss.get((client, direction, ssrc))
        if st is None:
            st = ss[(client, direction, ssrc)] = dict(n=0, kept=0, dup=0, old=0, big=0, t0=t, t1=t, pts=set(), hist=[0, 0, 0, 0])
        st["n"] += 1
        st["t1"] = t
        st["pts"].add(pt)
        if ulen > 400:
            st["big"] += 1
        st["hist"][0 if ulen <= 200 else 1 if ulen <= 400 else 2 if ulen <= 800 else 3] += 1
        if v == Dedup.NEW:
            st["kept"] += 1
        elif v == Dedup.DUP:
            st["dup"] += 1
        else:
            st["old"] += 1
        c = ssrc_clients[(direction, ssrc)][client]
        if not c:
            c.extend([t, t])
        c[1] = t
        # swallow episodes (consecutive too_old for the same ssrc+client)
        key = (ssrc, client)
        if v == Dedup.OLD:
            ep = open_ep.get(key)
            if ep is None:
                ep = open_ep[key] = dict(ssrc=ssrc, client=client, dir=direction, t0=t, t1=t, n=0, first_diff=d)
                episodes.append(ep)
            ep["n"] += 1
            ep["t1"] = t
        elif key in open_ep and v == Dedup.NEW:
            del open_ep[key]
        # per-bin downlink video accounting (what the program's session engine would see)
        b = int(t // BIN_S)
        if direction == "down":
            if ulen > 400:
                e = bins.get((client, b, ssrc))
                if e is None:
                    e = bins[(client, b, ssrc)] = [set(), set(), 0, 0, 0]
                e[0].add(rts)
                e[2] += 1
                if v == Dedup.NEW:
                    e[1].add(rts)
                    e[3] += 1
                elif v == Dedup.OLD:
                    e[4] += 1
            else:
                audio_dl[(client, b)] += 1

    if t_first is None:
        sys.exit("no RTP packets from/to the known server ranges (try --server-net)")

    def show_client(c):
        return not a.client or c in a.client

    print(f"PCAP {a.pcap}")
    print(f"  frames read {total}, RTP via server gate {gated}")
    print(f"  replay of src/dedup.rs: kept {tot_v['new']}, window-duplicates {tot_v['dup']}, "
          f"too-old (>=64 behind, dropped) {tot_v['too_old']}")
    print("  -> compare with the run's 'Duplicates dropped ... of which N only because 64+ sequence numbers behind'")
    print("     (dup+too_old here = Duplicates dropped; too_old = 'of which'). Twins on the wire are normal;")
    print("     what matters for a downlink zero is the too_old part.\n")

    # 1. SSRCs seen by more than one client
    print("1) SSRCs used by more than one client in the same direction  (dedup keys on SSRC only!)")
    shared = [(k, v) for k, v in ssrc_clients.items() if len(v) > 1]
    if not shared:
        print("   none\n")
    else:
        for (direction, ssrc), cl in sorted(shared, key=lambda x: x[0][1]):
            parts = "; ".join(f"{c} {hms(x[0])}-{hms(x[1])}" for c, x in sorted(cl.items(), key=lambda y: y[1][0]))
            print(f"   {direction:4s} 0x{ssrc:08X}: {parts}")
        print()

    # 2. per SSRC table
    print("2) Per client / direction / SSRC   (video = packets with udp_len > 400)")
    print("   client                     dir   ssrc        pts        pkts   kept  window-dup  too_old  udp_len %: <=200 <=400 <=800 >800   first-last")
    for (client, direction, ssrc), s in sorted(ss.items(), key=lambda x: (x[0][0], x[0][1], x[1]["t0"])):
        if not show_client(client) or s["n"] < 20:
            continue
        print(f"   {client:26s} {direction:4s}  0x{ssrc:08X}  {','.join(map(str, sorted(s['pts']))):9s} {s['n']:>7d} {s['kept']:>6d} "
              f"{s['dup']:>10d} {s['old']:>8d}   {'':9s}{100.0 * s['hist'][0] / s['n']:>4.0f} {100.0 * s['hist'][1] / s['n']:>5.0f} {100.0 * s['hist'][2] / s['n']:>5.0f} {100.0 * s['hist'][3] / s['n']:>4.0f}   {hms(s['t0'])}-{hms(s['t1'])}")
    print("   (the program counts only udp_len > 400 as video: a video SSRC with a big '<=400' share is under-counted, not lost)\n")

    # 3. swallow episodes
    eps = [e for e in episodes if e["n"] >= a.min_episode_pkts and show_client(e["client"])]
    print(f"3) Swallow episodes: runs of consecutive 'too old' drops of one SSRC for one client  (>= {a.min_episode_pkts} packets)")
    if not eps:
        print("   none\n")
    else:
        print("   client                     dir   ssrc         start     end     secs   dropped   jump(first pkt)")
        for e in sorted(eps, key=lambda x: x["t0"]):
            print(f"   {e['client']:26s} {e['dir']:4s}  0x{e['ssrc']:08X}  {hms(e['t0'])}  {hms(e['t1'])}  "
                  f"{e['t1'] - e['t0']:>6.0f}  {e['n']:>8d}   {e['first_diff']:+d} behind max")
        print()

    # 4. per client downlink video timeline
    print("4) Downlink video per client  (wire = what the PCAP holds; kept = what the program counts; fps by the program's rule)")
    clients = sorted({k[0] for k in bins if show_client(k[0])})
    allbins = sorted({k[1] for k in bins})
    if not allbins:
        print("   no downlink packets > 400 B at all")
    for c in clients:
        rows = []
        for b in range(allbins[0], allbins[-1] + 1):
            ents = [e for (cc, bb, _), e in bins.items() if cc == c and bb == b]
            if not ents and not audio_dl.get((c, b)):
                rows.append((b, None))
                continue
            wire = valid_fps([e[0] for e in ents])
            kept = valid_fps([e[1] for e in ents])
            wn = sum(e[2] for e in ents)
            kn = sum(e[3] for e in ents)
            on = sum(e[4] for e in ents)
            if wn == 0:
                lab = "NO VIDEO ON WIRE (downlink audio only)"
            elif wire == 0:
                lab = "video-sized pkts present but not a valid stream"
            elif kept == 0:
                lab = "SWALLOWED (on wire, program counts 0)"
            elif kept < 0.8 * wire:
                lab = "PARTLY SWALLOWED"
            else:
                lab = "ok"
            rows.append((b, (lab, wire, kept, wn, kn, on)))
        print(f"   client {c}")
        print("      from      to        wire_fps  kept_fps  wire_pkts  kept_pkts  too_old   state")
        cur = None
        def flush(cur):
            lab, b0, b1, ws, ks, wn, kn, on, n = cur
            print(f"      {hms(b0 * BIN_S)}  {hms((b1 + 1) * BIN_S)}  {ws / n:>8.2f}  {ks / n:>8.2f}  {wn:>9d}  {kn:>9d}  {on:>7d}   {lab}")
        for b, r in rows:
            if r is None:
                if cur:
                    flush(cur)
                    cur = None
                continue
            lab, w, k, wn, kn, on = r
            if cur and cur[0] == lab and cur[2] == b - 1:
                cur[2] = b
                cur[3] += w; cur[4] += k; cur[5] += wn; cur[6] += kn; cur[7] += on; cur[8] += 1
            else:
                if cur:
                    flush(cur)
                cur = [lab, b, b, w, k, wn, kn, on, 1]
        if cur:
            flush(cur)
    print()

    # 5. cross-check with the program's CSV
    if a.csv:
        print("5) Cross-check against the program's CSV (kept rows per src,dst,ssrc)")
        got = collections.Counter()
        for path in a.csv:
            with open(path, newline="") as f:
                for r in csv.DictReader(f):
                    got[(r["src_ip"], r["dst_ip"], int(r["rtp_ssrc"], 16))] += 1
        bad = 0
        for k in sorted(set(got) | set(kept_by)):
            if got[k] != kept_by[k]:
                bad += 1
                if bad <= 15:
                    print(f"   MISMATCH {k[0]} -> {k[1]} 0x{k[2]:08X}: csv {got[k]} vs replay {kept_by[k]}")
        print(f"   total csv rows {sum(got.values())}, replay kept {sum(kept_by.values())}, "
              f"flows with a different count: {bad}")
        print("   -> 0 mismatches = this replay reproduces the program for your run; a mismatch usually means a size cap,"
              " a full queue, a different server list, or packets the demux treated differently.")


if __name__ == "__main__":
    main()