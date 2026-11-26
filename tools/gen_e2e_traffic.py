#!/usr/bin/env python3
"""gen_e2e_traffic.py -- synthetic Zoom + Teams + Meet traffic for an end-to-end test of vc_capture.

Writes one classic pcap (little endian, microseconds) and a JSON file with the numbers the
run must reproduce. The traffic is MADE UP; it only follows the header layouts.

    python3 -I tools/gen_e2e_traffic.py OUT.pcap --zoom-pcap DIR_WITH_ZOOM_PCAPS [--secs 40]

* Zoom: the frames of zoom_pipeline's `demo_capture` (written with --snaplen 1536), re-timed.
  demo_capture writes UNIQUE packets, so a twin (other source MAC, +11 us) is added here.
* Teams 10.184.5.20 <-> 52.113.64.10: uplink video 30 fps x 3 packets (udp_len 1020) + audio
  50 pkt/s (udp_len 160); downlink video 30 fps for the first half, then 12 fps; 1 % of the
  downlink video packets missing; downlink audio.
* Meet 10.184.4.232 <-> 142.250.82.219: downlink video 25 fps x 2 packets (udp_len 1100) with
  ONE 400 ms gap (a stall) at 10 s; uplink video 15 fps; audio both ways; ONE retransmission
  (a downlink video packet repeated 150 ms later); 3 SSRC-0 probe packets (seq 1..3).
* Meet IPv6 2001:df4:e000:3fd2:17d4:ef69:c5aa:727 <-> 2001:4860:4864:5::17: audio only.
* Noise: DNS to 8.8.8.8 (no platform).
Every Teams/Meet packet is sent twice, 11 us apart, with another source MAC (the CAPWAP twin).
"""
import argparse, glob, json, random, struct

def pcap_frames(path):
    b = open(path, "rb").read()
    assert b[:4] == b"\xd4\xc3\xb2\xa1", path
    i, out = 24, []
    while i + 16 <= len(b):
        s, us, cap, orig = struct.unpack("<IIII", b[i:i + 16])
        out.append((s * 1_000_000 + us, b[i + 16:i + 16 + cap]))
        i += 16 + cap
    return out

def csum(_):
    return 0

def eth(mac_last, ethertype):
    return bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x66, 0x77, 0x88, 0x99, mac_last]) + struct.pack("!H", ethertype)

def v4(a):
    return bytes(int(x) for x in a.split("."))

def v6(a):
    import ipaddress
    return ipaddress.ip_address(a).packed

def udp_frame(src, dst, sp, dp, payload, mac_last=1):
    udp = struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload
    if ":" in src:
        ip = struct.pack("!IHBB", 6 << 28, len(udp), 17, 64) + v6(src) + v6(dst)
        return eth(mac_last, 0x86DD) + ip + udp
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0) + v4(src) + v4(dst)
    return eth(mac_last, 0x0800) + ip + udp

def rtp(pt, seq, ts, ssrc, udp_len, seed):
    hdr = struct.pack("!BBHII", 0x80, pt, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc)
    n = udp_len - 8 - 12
    rnd = random.Random(seed * 1_000_003 + seq)
    return hdr + bytes(rnd.getrandbits(8) for _ in range(n))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--zoom-pcap", required=True, help="folder with demo_capture's zoom_record_*.pcap")
    ap.add_argument("--secs", type=int, default=40)
    ap.add_argument("--start-us", type=int, default=0)
    a = ap.parse_args()
    S = a.secs
    ev = []  # (t_us, frame, platform, is_twin)
    expect = {"teams": {}, "meet": {}, "zoom": {}}

    def emit(t, src, dst, sp, dp, payload, plat):
        ev.append((t, udp_frame(src, dst, sp, dp, payload, 1), plat, False))
        ev.append((t + 11, udp_frame(src, dst, sp, dp, payload, 2), plat, True))

    # ---- Teams
    T_C, T_S = "10.184.5.20", "52.113.64.10"
    seq = {}
    def nxt(k):
        seq[k] = (seq.get(k, 999) + 1) & 0xFFFF
        return seq[k]
    rnd = random.Random(7)
    missing = 0
    for k in range(S * 30):  # uplink video 30 fps
        for p in range(3):
            emit(k * 33_333 + p * 300, T_C, T_S, 50020, 3478, rtp(102, nxt("tuv"), 90_000 + k * 3000, 0x11110001, 1020, 1), "teams")
    for k in range(S * 50):  # audio both ways
        emit(k * 20_000 + 5, T_C, T_S, 50020, 3478, rtp(111, nxt("tua"), k * 960, 0x11110002, 160, 2), "teams")
        emit(k * 20_000 + 7_000, T_S, T_C, 3478, 50020, rtp(111, nxt("tda"), k * 960, 0x22220002, 160, 3), "teams")
    half = S // 2
    t = 0.0
    k = 0
    while t < S * 1e6:
        fps = 30 if t < half * 1e6 else 12
        for p in range(3):
            s = nxt("tdv")
            if rnd.random() < 0.01:
                missing += 1
                continue
            emit(int(t) + 1_000 + p * 300, T_S, T_C, 3478, 50020, rtp(102, s, 500_000 + k * (90_000 // fps), 0x22220001, 1020, 4), "teams")
        t += 1e6 / fps
        k += 1
    expect["teams"]["down_video_missing"] = missing

    # ---- Meet IPv4
    M_C, M_S = "10.184.4.232", "142.250.82.219"
    stall_at = 10_000_000
    retx_done = False
    t, k = 0, 0
    while t < S * 1_000_000:
        for p in range(2):
            s = nxt("mdv")
            pl = rtp(96, s, 100_000 + k * 3600, 0x77890EDC, 1100, 5)
            emit(t + 2_000 + p * 400, M_S, M_C, 19305, 60158, pl, "meet")
            if not retx_done and t > 20_000_000:
                emit(t + 2_000 + p * 400 + 150_000, M_S, M_C, 19305, 60158, pl, "meet")  # retransmission, 150 ms later
                retx_done = True
        t += 40_000
        if stall_at <= t < stall_at + 40_000:
            t += 400_000  # one 400 ms gap
        k += 1
    for k in range(S * 15):
        for p in range(2):
            emit(k * 66_667 + p * 500, M_C, M_S, 60158, 19305, rtp(96, nxt("muv"), 7_000 + k * 6000, 0x1A0B0001, 1100, 6), "meet")
    for k in range(S * 50):
        emit(k * 20_000 + 3_000, M_C, M_S, 60158, 19305, rtp(111, nxt("mua"), k * 960, 0x00001A0A, 140, 7), "meet")
        emit(k * 20_000 + 9_000, M_S, M_C, 19305, 60158, rtp(111, nxt("mda"), k * 960, 0x00001A0C, 140, 8), "meet")
    for s in (1, 2, 3):  # SSRC-0 probes
        emit(1_000_000 + s * 1000, M_S, M_C, 19305, 60158, rtp(96, s, 0, 0, 1200, 9), "meet")

    # ---- Meet IPv6 audio
    V6C, V6S = "2001:df4:e000:3fd2:17d4:ef69:c5aa:727", "2001:4860:4864:5::17"
    for k in range(S * 50):
        emit(k * 20_000 + 11_000, V6C, V6S, 40000, 3478, rtp(111, nxt("v6u"), k * 960, 0x0000BEEF, 150, 10), "meet")

    # ---- noise
    for k in range(S * 5):
        ev.append((k * 200_000 + 77, udp_frame("10.184.9.9", "8.8.8.8", 5353, 53, b"\x12\x34" + b"\x00" * 30), "none", False))

    # ---- Zoom (demo_capture output, unique packets; add the twin)
    zf = []
    for p in sorted(glob.glob(f"{a.zoom_pcap}/*.pcap")):
        zf += pcap_frames(p)
    zf.sort(key=lambda x: x[0])
    z0 = zf[0][0]
    nz = 0
    for t0, fr in zf:
        t = t0 - z0
        if t >= S * 1_000_000:
            continue
        nz += 1
        ev.append((t, fr, "zoom", False))
        tw = bytearray(fr)
        tw[11] ^= 0x5A  # other source MAC
        ev.append((t + 11, bytes(tw), "zoom", True))
    expect["zoom"]["unique_frames"] = nz

    ev.sort(key=lambda e: e[0])
    for p in ("teams", "meet"):
        expect[p]["unique_rtp"] = sum(1 for e in ev if e[2] == p and not e[3])
        expect[p]["twins"] = sum(1 for e in ev if e[2] == p and e[3])
    with open(a.out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, fr, _, _ in ev:
            tt = a.start_us + t
            f.write(struct.pack("<IIII", tt // 1_000_000, tt % 1_000_000, len(fr), len(fr)))
            f.write(fr)
    expect["frames_total"] = len(ev)
    json.dump(expect, open(a.out + ".expect.json", "w"), indent=1)
    print(json.dumps(expect))

if __name__ == "__main__":
    main()
