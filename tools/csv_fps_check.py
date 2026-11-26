#!/usr/bin/env python3
"""Recompute frame rate and sequence gaps straight from teams_rtp_records.csv / meet_rtp_records.csv,
without using any of the program's session code, so the numbers on screen / in InfluxDB can be checked.

    python3 -I tools/csv_fps_check.py captures/run_X/teams_rtp_records.csv [--client 10.184.5.20] [--min-pkts 20]

One line per (client, stream, direction, 5 s bin). Rules copied from the program so the numbers are comparable:
  * bins are epoch-aligned: bin = arrival_epoch_ns // 5_000_000_000 (the program's BIN_SIZE_NS)
  * 'video' = udp_len > 400, else 'audio'. This is the PROGRAM'S rule (size), not a
    property of Teams/Meet; it is repeated here only so the two can be compared.
  * frames = number of DISTINCT rtp_timestamp values in the bin; fps = frames / 5
  * direction: the side whose address is the server is 'downlink' when it is the source. Server test
    = the same prefix lists as the program, restricted to what the CSV can show (IPv4 + the IPv6 prefixes).
  * lost = sequence numbers missing between the lowest and highest seen in the bin (reordering ignored)
The first and last bin of a stream are partial, so their fps is lower than the real rate.
"""
import csv, sys
from collections import defaultdict

BIN = 5_000_000_000
TEAMS = ("52.112.", "52.113.", "52.114.", "52.115.", "52.122.", "52.123.",
         "2603:1010", "2603:1027", "2603:1037", "2603:1047", "2603:1057", "2603:1063", "2620:1ec")
MEET = ("74.125.250.", "74.125.247.128", "142.250.82.",
        "2001:4860:4864:5:", "2001:4860:4864:4:8000:", "2001:4860:4864:6:")

def main():
    args = [a for a in sys.argv[1:]]
    if not args or args[0].startswith("-"):
        print(__doc__); sys.exit(2)
    path = args[0]
    client_filter = args[args.index("--client") + 1] if "--client" in args else None
    min_pkts = int(args[args.index("--min-pkts") + 1]) if "--min-pkts" in args else 20
    servers = MEET if "meet" in path.lower() else TEAMS
    is_srv = lambda ip: ip.startswith(servers)
    acc = defaultdict(lambda: {"n": 0, "ts": set(), "seqs": set(), "bytes": 0})
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            src, dst = r["src_ip"], r["dst_ip"]
            if is_srv(src): client, d = dst, "downlink"
            elif is_srv(dst): client, d = src, "uplink"
            else: continue
            if client_filter and client != client_filter: continue
            kind = "video" if int(r["udp_len"]) > 400 else "audio"
            k = (client, r["rtp_ssrc"], kind, d, int(r["arrival_epoch_ns"]) // BIN)
            a = acc[k]; a["n"] += 1; a["ts"].add(r["rtp_timestamp"]); a["seqs"].add(int(r["rtp_seq"])); a["bytes"] += int(r["udp_len"])
    print(f"{'client':<18}{'ssrc':<12}{'kind':<6}{'dir':<9}{'bin_end_epoch_s':<16}{'pkts':>6}{'frames':>7}{'fps':>7}{'lost':>6}{'kbit/s':>9}")
    for (client, ssrc, kind, d, b), a in sorted(acc.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][4])):
        if a["n"] < min_pkts: continue
        lo, hi = min(a["seqs"]), max(a["seqs"])
        span = (hi - lo + 1) if hi - lo < 30000 else len(a["seqs"])  # ignore 16-bit wrap inside a bin
        lost = max(0, span - len(a["seqs"]))
        fps = f"{len(a['ts'])/5:.1f}" if kind == "video" else "-"
        print(f"{client:<18}{ssrc:<12}{kind:<6}{d:<9}{(b+1)*5:<16}{a['n']:>6}{len(a['ts']):>7}{fps:>7}{lost:>6}{a['bytes']*8/5/1000:>9.0f}")

main()
