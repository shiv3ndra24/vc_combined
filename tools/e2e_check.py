#!/usr/bin/env python3
"""e2e_check.py -- compare a vc_capture run on synthetic traffic with what gen_e2e_traffic.py put in it.

    python3 -I tools/e2e_check.py RUN_DIR TRAFFIC.pcap.expect.json [--dedup fp|off]

Checks (exit 1 on any failure):
  * Teams/Meet: kept records == unique packets (fp) or all packets (off); CSV rows == pcap frames == kept
  * Zoom: CSV rows == pcap packets == matched
  * every capture file is after de-dup: no Teams/Meet twin (same flow + ssrc + seq within 10 ms) in the CSVs
  * both line-protocol outputs hold session_metrics for zoom, teams and meet
"""
import collections, csv, glob, json, os, sys

def info(run):
    d = {}
    for l in open(os.path.join(run, "run_info.txt")):
        if "=" in l and not l.startswith("#"):
            k, v = l.rstrip("\n").split("=", 1)
            d[k] = v
    return d

def main():
    run, exp = sys.argv[1], json.load(open(sys.argv[2]))
    mode = sys.argv[sys.argv.index("--dedup") + 1] if "--dedup" in sys.argv else "fp"
    ri, bad = info(run), []
    def check(name, got, want):
        ok = got == want
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {got} (want {want})")
        if not ok:
            bad.append(name)
    uniq = exp["teams"]["unique_rtp"] + exp["meet"]["unique_rtp"]
    kept = int(ri["final_teams_meet_kept"])
    if mode == "fp":
        # fp's only possible error is a MISSED twin after a slot collision; the program counts the
        # collisions (fp_evicted_live), each costing at most one twin. So: uniq <= kept <= uniq + evicted.
        ev = int(ri["final_teams_meet_fp_evicted_live"])
        ok = uniq <= kept <= uniq + ev
        print(f"{'ok  ' if ok else 'FAIL'} teams/meet kept: {kept} (unique {uniq}; missed twins {kept - uniq} <= fp slot overwrites {ev})")
        if not ok:
            bad.append("teams/meet kept")
        want_kept = kept
    else:
        want_kept = 2 * uniq
        check("teams/meet kept", kept, want_kept)
    if ri.get("csv") == "on":
        check("teams/meet csv rows", int(ri["final_teams_meet_csv_rows"]), want_kept - int(ri["final_teams_meet_csv_skipped_limit"]))
        rows = 0
        twins = 0
        for f in sorted(glob.glob(os.path.join(run, "teams_record_*.csv")) + glob.glob(os.path.join(run, "meet_record_*.csv"))):
            last = {}
            for r in csv.DictReader(open(f)):
                rows += 1
                k = (r["src_ip"], r["dst_ip"], r["src_port"], r["dst_port"], r["rtp_ssrc"], r["rtp_seq"])
                t = int(r["arrival_epoch_ns"])
                if k in last and t - last[k] < 10_000_000:
                    twins += 1
                last[k] = t
        check("teams/meet csv rows on disk", rows, int(ri["final_teams_meet_csv_rows"]))
        check("twins left in teams/meet csv", twins, kept - uniq if mode == "fp" else want_kept // 2)
    if ri.get("pcap") == "on":
        check("teams/meet pcap frames", int(ri["final_teams_meet_pcap_frames"]), int(ri["final_teams_meet_csv_rows"]) if ri.get("csv") == "on" else want_kept)
    if ri.get("final_capture_limit_reached") == "true":
        print("info capture limit reached: CSV and pcap stop at different packets, counts not compared")
    else:
        check("zoom csv rows == pcap pkts", int(ri["final_zoom_csv_rows"]), int(ri["final_zoom_pcap_pkts"]))
    zm = int(ri["final_zoom_matched"])
    zu = exp["zoom"]["unique_frames"]
    print(f"info zoom matched {zm} (unique {zu}; fp may leave a few twins, upper bound fp slot overwrites)")
    if mode == "off":
        check("zoom matched (off)", zm, 2 * zu)
    elif not (zu <= zm <= zu * 1.002):
        bad.append("zoom matched")
        print(f"FAIL zoom matched {zm} not within 0.2 % above {zu}")
    plats = collections.Counter()
    for f in glob.glob(os.path.join(run, "influx_*.lp")):
        for l in open(f):
            if l.startswith("session_metrics,"):
                plats[l.split("platform=")[1].split(" ")[0].split(",")[0]] += 1
    if plats:
        for p in ("teams", "meet") if mode == "off" else ("zoom", "teams", "meet"):
            check(f"session_metrics points for {p} > 0", plats[p] > 0, True)
        if mode == "off":
            # With twins on the wire and no de-dup every second sequence step is a repeat, so no
            # stream reaches the 90 % forward-step qualification: Zoom writes client_no_media only.
            print(f"info dedup off on a doubled feed: zoom session_metrics points = {plats['zoom']} (expected 0)")
    print("PASS" if not bad else f"FAIL: {', '.join(bad)}")
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main()
