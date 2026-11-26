#!/usr/bin/env python3
"""Self-test for check_dups.py:  python3 tools/test_check_dups.py     (no capture, no network, ~2 s)

Builds tiny CSV and PCAP files in a temp folder whose duplicates are known by construction and checks
that check_dups.py reports exactly those, and nothing else.  Each case names what would go wrong if
the script were broken in that spot (a 'mutation' it must catch).
"""
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "check_dups.py")
HEADER = ("arrival_epoch_ns,src_ip,dst_ip,ip_proto,ip_len,src_port,dst_port,udp_len,"
          "rtp_ssrc,rtp_timestamp,rtp_seq,rtp_pt,rtp_marker")


def row(t, ssrc=0x1003, seq=100, ts=9000, src="52.113.64.10", dst="10.184.5.20", sp=3480, dp=50012,
        ip_len=1048, udp_len=1028, pt=102, m=0):
    return f"{t},{src},{dst},17,{ip_len},{sp},{dp},{udp_len},0x{ssrc:08X},{ts},{seq},{pt},{m}"


def write_csv(path, rows):
    with open(path, "w") as f:
        f.write(HEADER + "\n")
        for r in rows:
            f.write(r + "\n")


def frame(ssrc=0x1003, seq=100, ts=9000, src_mac=2, ttl=64, ip_id=7, payload=b"\0" * 100, sport=3480, dport=50012,
          src="52.113.64.10", dst="10.184.5.20"):
    rtp = struct.pack("!BBHII", 0x80, 102, seq, ts, ssrc) + payload
    udp = struct.pack("!HHHH", sport, dport, 8 + len(rtp), 0) + rtp
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ip_id, 0x4000, ttl, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return bytes([2, 0, 0, 0, 0, src_mac]) + bytes([2, 0, 0, 0, 0, 1]) + b"\x08\x00" + ip + udp


def write_pcap(path, frames):
    """frames: list of (t_seconds_float, bytes)"""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, fr in frames:
            s = int(t)
            f.write(struct.pack("<IIII", s, int(round((t - s) * 1e6)), len(fr), len(fr)) + fr)


def run(*argv):
    p = subprocess.run([sys.executable, "-I", SCRIPT, *argv], capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def report(*argv):
    """Run with --json and return (exit code, parsed json, stdout)."""
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as t:
        name = t.name
    try:
        code, out, err = run(*argv, "--json", name)
        data = None
        if os.path.getsize(name):
            with open(name) as f:
                data = json.load(f)
        return code, data, out + err
    finally:
        os.unlink(name)


T0 = 1_800_000_000_000_000_000  # ns


class CheckDups(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def p(self, name):
        return os.path.join(self.d, name)

    def info(self, text):
        with open(self.p("run_info.txt"), "w") as f:
            f.write(text)

    # ---------- CSV ----------
    def test_csv_clean_file_has_no_repeats_and_exit_0(self):
        write_csv(self.p("c.csv"), [row(T0 + i * 1000, seq=100 + i, ts=9000 + 3000 * i) for i in range(50)])
        code, js, out = report("--csv", self.p("c.csv"))
        self.assertEqual(code, 0, out)
        self.assertEqual(js["files"][0]["packets"], 50)
        self.assertEqual(js["files"][0]["repeats"], 0)

    def test_csv_exact_repeat_is_found_and_exit_1(self):
        # mutation caught: key ignored / always 0 repeats
        rows = [row(T0 + i * 1000, seq=100 + i, ts=9000 + 3000 * i) for i in range(10)]
        rows.insert(5, row(T0 + 4 * 1000 + 40, seq=104, ts=9000 + 3000 * 4))  # twin of the packet at i=4, 40 ns later
        write_csv(self.p("c.csv"), rows)
        code, js, out = report("--csv", self.p("c.csv"))
        self.assertEqual(code, 1, out)
        f = js["files"][0]
        self.assertEqual((f["packets"], f["repeats"]), (11, 1))
        self.assertEqual(f["classes"], {"same_fields": 1})

    def test_csv_repeat_is_not_a_failure_when_run_had_dedup_off(self):
        rows = [row(T0, seq=1, ts=1), row(T0 + 500, seq=1, ts=1)]
        write_csv(self.p("teams_rtp_records.csv"), rows)
        self.info("csv=on\npcap=off\ndedup=off\ncsv_max_bytes=0\npcap_max_bytes=0\n")
        code, js, out = report(self.d)
        self.assertEqual(code, 0, out)
        self.assertIn("expected, the run had --dedup off", out)
        # same file, but the run said dedup was ON: that is a leak
        self.info("csv=on\npcap=off\ndedup=on\ncsv_max_bytes=0\npcap_max_bytes=0\n")
        code, js, out = report(self.d)
        self.assertEqual(code, 1, out)
        self.assertIn("dedup missed them", out)

    def test_sequence_wrap_with_new_timestamp_is_not_a_repeat(self):
        # mutation caught: key without rtp_timestamp (would flag every wrap-around)
        rows = [row(T0, seq=500, ts=1000), row(T0 + 22_000_000_000, seq=500, ts=1000 + 22 * 90000)]
        write_csv(self.p("c.csv"), rows)
        code, js, out = report("--csv", self.p("c.csv"), "--horizon-s", "60")
        self.assertEqual(code, 0, out)
        self.assertEqual(js["files"][0]["repeats"], 0)

    def test_cross_flow_and_content_differs_are_separate_classes(self):
        rows = [row(T0, seq=1, ts=1),
                row(T0 + 100, seq=1, ts=1, dst="10.184.9.77", dp=51000),  # same key, other client
                row(T0 + 200, seq=1, ts=1, udp_len=500, ip_len=520)]      # same flow, other length
        write_csv(self.p("c.csv"), rows)
        code, js, out = report("--csv", self.p("c.csv"))
        self.assertEqual(js["files"][0]["classes"], {"cross_flow": 1, "content_differs": 1})

    def test_horizon_forgets_old_packets(self):
        # mutation caught: horizon ignored (memory grows without bound / far repeats counted)
        rows = [row(T0, seq=1, ts=1), row(T0 + 15_000_000_000, seq=1, ts=1)]
        write_csv(self.p("c.csv"), rows)
        _, js10, _ = report("--csv", self.p("c.csv"), "--horizon-s", "10")
        _, js30, _ = report("--csv", self.p("c.csv"), "--horizon-s", "30")
        self.assertEqual(js10["files"][0]["repeats"], 0)
        self.assertEqual(js30["files"][0]["repeats"], 1)

    def test_csv_cut_off_last_line_is_counted_not_fatal(self):
        write_csv(self.p("c.csv"), [row(T0, seq=1, ts=1)])
        with open(self.p("c.csv"), "a") as f:
            f.write("1800000000000000999,52.113.64.10,10.184")  # killed mid-write
        code, js, out = report("--csv", self.p("c.csv"))
        self.assertEqual(code, 0, out)
        self.assertEqual(js["files"][0]["bad_rows"], 1)

    def test_csv_without_the_expected_columns_is_exit_2(self):
        with open(self.p("x.csv"), "w") as f:
            f.write("a,b,c\n1,2,3\n")
        code, _, out = run("--csv", self.p("x.csv"))
        self.assertEqual(code, 2)
        self.assertIn("missing columns", out)

    # ---------- PCAP ----------
    def test_pcap_byte_identical_and_other_header_twins(self):
        # mutation caught: both twin kinds counted as one, or the second kind missed
        a = frame(seq=10, ts=1000)
        frames = [
            (1.000000, a),
            (1.000010, a),                                                    # byte-identical twin
            (1.010000, frame(seq=11, ts=1300)),
            (1.010020, frame(seq=11, ts=1300, src_mac=9, ttl=63)),            # other MAC and TTL, same IP-ID and payload
            (1.020000, frame(seq=12, ts=1600)),                               # single
        ]
        write_pcap(self.p("p.pcap"), frames)
        code, js, out = report("--pcap", self.p("p.pcap"))
        self.assertEqual(code, 0, out)  # twins in a raw PCAP are normal
        f = js["files"][0]
        self.assertEqual((f["packets"], f["repeats"]), (5, 2))
        self.assertEqual(f["classes"], {"byte_identical": 1, "same_packet_other_hdr": 1})

    def test_pcap_noise_and_non_rtp_are_skipped_not_counted(self):
        junk = bytes(range(60))
        rtcp_like = frame()[:42] + struct.pack("!BBH", 0x81, 200, 6) + bytes(30)
        write_pcap(self.p("p.pcap"), [(1.0, junk), (1.1, rtcp_like), (1.2, frame(seq=1))])
        code, js, out = report("--pcap", self.p("p.pcap"))
        self.assertEqual(js["files"][0]["packets"], 1)
        self.assertEqual(js["files"][0]["skipped_frames"], 2)

    def test_pcap_nanosecond_and_vlan_and_truncation(self):
        # ns magic + one 802.1Q tag + a file that ends mid-record
        fr = frame(seq=5, ts=50)
        vl = fr[:12] + b"\x81\x00\x00\x64" + fr[12:]
        with open(self.p("p.pcap"), "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
            for t_ns in (1_000_000_000, 1_000_002_000):
                f.write(struct.pack("<IIII", 1, t_ns - 1_000_000_000, len(vl), len(vl)) + vl)
            f.write(struct.pack("<IIII", 2, 0, 500, 500) + b"\0" * 10)  # cut off
        code, js, out = report("--pcap", self.p("p.pcap"))
        f = js["files"][0]
        self.assertEqual((f["packets"], f["repeats"]), (2, 1))
        self.assertIn("ends in the middle of a record", out)

    def test_pcap_ipv6(self):
        udp_rtp = struct.pack("!BBHII", 0x80, 102, 1, 1, 0x3001) + bytes(50)
        udp = struct.pack("!HHHH", 3480, 50020, 8 + len(udp_rtp), 0) + udp_rtp
        ip6 = struct.pack("!IHBB16s16s", 0x60000000, len(udp), 17, 64,
                          socket.inet_pton(socket.AF_INET6, "2603:1063:5::10"), socket.inet_pton(socket.AF_INET6, "2001:db8::5"))
        fr = bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]) + b"\x86\xdd" + ip6 + udp
        write_pcap(self.p("p.pcap"), [(1.0, fr), (1.00001, fr)])
        _, js, _ = report("--pcap", self.p("p.pcap"))
        self.assertEqual((js["files"][0]["packets"], js["files"][0]["repeats"]), (2, 1))

    # ---------- reconcile ----------
    def test_reconcile_explains_difference_by_pcap_twins(self):
        frames = [(1.0 + i * 0.01, frame(seq=i, ts=i * 3000)) for i in range(20)]
        frames.insert(8, (1.0 + 7 * 0.01 + 0.00001, frames[7][1]))  # one twin
        write_pcap(self.p("teams_traffic_rtp.pcap"), frames)
        write_csv(self.p("teams_rtp_records.csv"), [row(T0 + i * 10_000_000, seq=i, ts=i * 3000) for i in range(20)])
        self.info("csv=on\npcap=on\ndedup=on\ncsv_max_bytes=0\npcap_max_bytes=0\n")
        code, js, out = report(self.d)
        self.assertEqual(code, 0, out)
        self.assertEqual(js["reconcile"]["teams"]["difference"], 1)
        self.assertEqual(js["reconcile"]["teams"]["unexplained"], 0)

    def test_program_counter_mismatch_is_a_problem(self):
        write_csv(self.p("teams_rtp_records.csv"), [row(T0 + i, seq=i, ts=i) for i in range(5)])
        self.info("csv=on\npcap=off\ndedup=on\ncsv_max_bytes=0\npcap_max_bytes=0\n"
                  "finished_unix=1\nfinal_csv_rows=9\nfinal_csv_full=false\n")
        code, js, out = report(self.d)
        self.assertEqual(code, 1, out)
        self.assertIn("MISMATCH", out)

    # ---------- --dedup fp ----------
    def test_fp_mode_keeps_retransmissions_and_other_flows_and_counts_missed_twins(self):
        # CSV of a run with --dedup fp: 200 packets; one missed twin (same flow, 20 us later), one retransmission
        # (same flow, 100 ms later), one packet forwarded to a second client (other flow).
        rows = [row(T0 + i * 10_000_000, seq=i, ts=i * 3000) for i in range(200)]
        rows.append(row(T0 + 7 * 10_000_000 + 20_000, seq=7, ts=7 * 3000))                     # missed twin
        rows.append(row(T0 + 30 * 10_000_000 + 100_000_000, seq=30, ts=30 * 3000))             # retransmission
        rows.append(row(T0 + 50 * 10_000_000 + 15_000, seq=50, ts=50 * 3000, dst="10.184.9.9"))  # other flow
        rows.sort(key=lambda r: int(r.split(",")[0]))
        write_csv(self.p("teams_rtp_records.csv"), rows)
        self.info("csv=on\npcap=off\ndedup=fp\ncsv_max_bytes=0\npcap_max_bytes=0\n")
        code, js, out = report(self.d)
        self.assertEqual(code, 0, out)                     # none of these is a failure under fp
        self.assertIn("1 missed twins", out)
        self.assertIn("1 identical packets of the same flow 10 ms or more later", out)
        self.assertIn("1 on another flow", out)

    def test_fp_mode_with_many_twins_left_is_a_problem(self):
        rows = []
        for i in range(100):
            rows.append(row(T0 + i * 10_000_000, seq=i, ts=i * 3000))
            rows.append(row(T0 + i * 10_000_000 + 11_000, seq=i, ts=i * 3000))   # every packet still has its twin
        write_csv(self.p("teams_rtp_records.csv"), rows)
        self.info("csv=on\npcap=off\ndedup=fp\ncsv_max_bytes=0\npcap_max_bytes=0\n")
        code, js, out = report(self.d)
        self.assertEqual(code, 1, out)
        self.assertIn("twins left in the CSV", out)

    def test_fp_mode_reconcile_explains_the_difference_by_twins_under_10_ms(self):
        frames = [(1.0 + i * 0.01, frame(seq=i, ts=i * 3000)) for i in range(20)]
        frames.insert(8, (1.0 + 7 * 0.01 + 0.00001, frames[7][1]))                 # twin, 10 us later
        frames.append((1.0 + 3 * 0.01 + 0.5, frames[3][1]))                         # retransmission 500 ms later
        frames.sort(key=lambda x: x[0])
        write_pcap(self.p("teams_traffic_rtp.pcap"), frames)
        # CSV after fp: the twin is gone, the retransmission was kept
        write_csv(self.p("teams_rtp_records.csv"),
                  [row(T0 + i * 10_000_000, seq=i, ts=i * 3000) for i in range(20)]
                  + [row(T0 + 3 * 10_000_000 + 500_000_000, seq=3, ts=3 * 3000)])
        self.info("csv=on\npcap=on\ndedup=fp\ncsv_max_bytes=0\npcap_max_bytes=0\n")
        code, js, out = report(self.d)
        # PCAP 22 frames (20 + twin + retransmission), CSV 21 rows (the twin is gone): difference 1 = the twin
        self.assertEqual(js["reconcile"]["teams"]["difference"], 1)
        self.assertEqual(js["reconcile"]["teams"]["pcap_repeats"], 1)        # under-10-ms repeats only; the 500 ms one is kept
        self.assertEqual(js["reconcile"]["teams"]["unexplained"], 0)
        self.assertEqual(code, 0, out)

    def test_largest_gap_per_class_is_reported(self):
        write_pcap(self.p("p.pcap"), [(1.0, frame(seq=1, ts=1)), (1.0000123, frame(seq=1, ts=1, src_mac=9)),
                                       (1.0 + 0.0094, frame(seq=1, ts=1, src_mac=8))])
        code, out, err = (lambda r: (r[0], r[1], r[2]))(run("--pcap", self.p("p.pcap")))
        self.assertIn("largest gap per class", out)
        self.assertIn("same_packet_other_hdr 9.400 ms", out)

    def test_old_name_on_means_seq(self):
        rows = [row(T0, seq=1, ts=1), row(T0 + 500, seq=1, ts=1)]
        write_csv(self.p("teams_rtp_records.csv"), rows)
        self.info("csv=on\npcap=off\ndedup=on\ncsv_max_bytes=0\npcap_max_bytes=0\n")
        code, js, out = report(self.d)
        self.assertEqual(code, 1, out)
        self.assertIn("although the run had --dedup seq", out)

    def test_nothing_to_check_is_exit_2(self):
        code, _, out = run(self.d)
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
