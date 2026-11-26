#!/usr/bin/env python3
"""Find where the RTP header sits in the Zoom packet types we do not parse yet (7, 21, 10, 32 ...).

    python3 -I tools/probe_unknown_types.py PCAP_DIR_OR_FILE [--types 7,21] [--residual 13] [--no-split] [--hex 48] [--json out.json]

Python 3 standard library only; reads the pcap written by zoom_capture --pcap-dir
(first 128 bytes of every unique Zoom packet), LOCALLY.  It prints no IP address
and no payload bytes unless you ask for them with --hex.

WHY this exists.  The first two campus captures showed that the packets we log
as "type byte 7" are not noise: they sit inside the sequence-number gaps of the
audio streams of the same flow (RTP seq 27993, [a type 7 packet], 27995), and
about one audio packet in fifteen is one of them.  They are audio packets with
another header layout, so a loss or jitter metric that ignores them over-counts
loss by about 7 % on audio.  We did not know their RTP offsets; this tool measures
them instead of guessing.

p7b note on Type 21: the p6 text here called Type 21 "the main media type of the phone
clients" and looked for an RTP header in it.  Deck2 (T21-2 CONFIRMED, T21-4 REFUTED)
settled it: Type 21 is probe padding (94 % of its packets: a 36-byte header plus 1000 filler
bytes) plus control reports, it is NOT RTP.  The tool still probes it (a self-consistency
result of "no offset" is the expected answer and a useful regression check), it just no
longer expects an RTP header there.

TWO INDEPENDENT TESTS (an offset is believed only when they agree, or one of
them is overwhelming):

  1. GAP FILL (decisive for types that are mixed into a known stream, e.g. 7).
     Whenever a known audio/video stream jumps by 2..4 sequence numbers, the
     unknown-type packets of the same flow that arrived in between are the
     missing packets.  If a 12-byte RTP header starts at payload offset r, then
         u32 at r+8 == the stream's SSRC    and    u16 at r+2 == a missing seq
     A chance match of both is 2^-48, so a handful of hits at one r settles it.

  2. SELF-CONSISTENCY (for types with a stream of their own).
     For consecutive packets of the same flow and type, at the right r:
     version bits == 2, the u16 at r+2 goes up by 1, the u32 at r+4 never goes
     backwards, and the u32 at r+8 does not change.  Fields in a constant header
     region pass the "does not change" test but not the "+1" test; a media
     sequence counter passes "+1" but not the SSRC and timestamp tests together.

SIZE CLASSES.  A type byte can hide several packet layouts.  On the s3 run, type 7
gave 48 % gap-fill hits at payload offset 39 and 47 % at offset 34 from the same
11,329 candidates, i.e. two layouts mixed (small 34-160 B control packets next to
~1000 B media packets).  Mixed together each layout dilutes the other, so by
default every type is analysed separately per UDP-payload size class (<=64, 65-200,
201-700, >700 bytes); --no-split restores one line per type.  A class where one
offset reaches ~100 % is a layout; a class at ~0 % is not RTP (control data).

RESIDUALS.  --residual 13 probes the packets of a KNOWN type that do NOT carry
RTP version 2 at the known offset, as a separate line "13*".  On s3 only 40 % of
the screen-share packets (type 13) were RTP at +27 (SSRC 0x01000403, PT 99); 32 %
were padding/probe packets with patterned SSRCs (0x01010101, 0x02020202 ...) and
22 % were something else of 300-1100 B that is only seen while a screen is being
shared, and the receiver sees more of it than the sender sends.  "13*" asks
whether that rest is RTP in another layout (the same story as type 7 for audio).

p7b: with the media-byte-7 gate, "the packets of a known type that do not carry RTP at the
known offset" now INCLUDES every type-13 packet whose media byte 7 is not 0x1e (probe
padding and control), whatever bytes sit at +27.  The new section "type-13 sub-type
census" counts media byte 7 per direction, and, for the downlink packets p7b files as
control, how many have 0x15 at media byte 15.  That is the open question about the
downlink probe envelope (deck2 slide 41 puts the probe marker at byte 15 there, untested):
a large count means t13_ctrl contains probe padding and Type13Kind in headers.rs needs a
second rule.

Offsets are printed twice: from the start of the UDP payload (the SFU header is
8 bytes) and from the start of the media header (what headers.rs uses: video
+24 (+28 when media byte 20 is 0x0a, +20 when its top bits are 10), audio +19,
type 13 +27 (only if media byte 7 is 0x1e), type 30 +20, RTCP +16).

Exit code 0 always (this is a measuring tool, not a gate).
"""
import argparse
import glob
import heapq
import json
import os
import struct
import sys
from collections import Counter, defaultdict

RTP_OFF = {16: 24, 15: 19, 13: 27, 30: 20}  # known: media-header-relative (p7a: type 30 is +20, was a +27 guess)
VIDEO_BURST_BYTE, VIDEO_BURST_OFF = 0x0A, 28  # p7a: video with media byte 20 == 0x0a has its RTP header at +28
VIDEO_RTP20_OFF = 20  # p7b: video whose media byte 20 has the top bits 10 (0x80-0xBF, 0x90 seen): byte 20 IS the RTP byte 0
T13_SUBTYPE_POS, T13_RTP, T13_PROBE = 7, 0x1E, 0x15  # p7b: type 13 has RTP at +27 only if media byte 7 == 0x1e
T13_DOWN_MARKER_POS = 15  # OPEN: where deck2 slide 41 puts the probe marker on the downlink
# padding signature (deck2 T13-3): `03 e8` (= 1000) at UDP-payload byte 37 on the uplink, 45 on the downlink (8-byte prefix)
T13_SIG, T13_SIG_POS = b"\x03\xe8", {"up": 37, "down": 45}
RTCP_TYPES = {33, 34}
R_LO, R_HI = 8, 70  # candidate RTP start offsets inside the UDP payload
REORDER_US = 500_000  # records of one flow can be out of order by up to a batch flush (100 ms): sort within 0.5 s
MIN_PAIRS = 30


def pcap_files(p):
    if os.path.isdir(p):
        return sorted(glob.glob(os.path.join(p, "*.pcap")))
    return [p]


def iter_pcap(path):
    for fp in pcap_files(path):
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
                continue
            while True:
                rh = fh.read(16)
                if len(rh) < 16:
                    break
                sec, sub, cap, orig = struct.unpack(e + "IIII", rh)
                buf = fh.read(cap)
                yield sec * 1_000_000 + sub // scale, buf


def parse_frame(buf):
    """-> (flow, payload, udp_payload_len) for Ethernet(+VLAN)/IPv4|IPv6/UDP, else None.  The flow tuple is never printed."""
    if len(buf) < 14:
        return None
    et = struct.unpack(">H", buf[12:14])[0]
    o = 14
    while et in (0x8100, 0x88A8, 0x9100) and len(buf) >= o + 4:
        et = struct.unpack(">H", buf[o + 2:o + 4])[0]
        o += 4
    if et == 0x0800:
        if len(buf) < o + 20 or buf[o + 9] != 17:
            return None
        ihl = (buf[o] & 0x0F) * 4
        a, b = bytes(buf[o + 12:o + 20]), None
        o += ihl
        ips = (a[:4], a[4:])
    elif et == 0x86DD:
        if len(buf) < o + 40 or buf[o + 6] != 17:
            return None
        ips = (bytes(buf[o + 8:o + 24]), bytes(buf[o + 24:o + 40]))
        o += 40
    else:
        return None
    if len(buf) < o + 8:
        return None
    sp, dp, ulen = struct.unpack(">HHH", buf[o:o + 6])
    return (ips[0], ips[1], sp, dp), buf[o + 8:], ulen - 8


RESID = 1000  # type byte + RESID = the leftovers of that type (reported as "13*")


def tname(tb):
    return "%d*" % (tb - RESID) if tb >= RESID else "%d" % tb


def size_class(n):
    return "<=64 B" if n <= 64 else "65-200 B" if n <= 200 else "201-700 B" if n <= 700 else ">700 B"


def u16(b, i):
    return (b[i] << 8) | b[i + 1]


def u32(b, i):
    return (b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]


class TypeStats:
    def __init__(self):
        self.n = 0
        self.flows = set()
        self.sizes = Counter()
        self.gap_cands = 0
        self.gap_hits = Counter()  # r -> packets whose bytes at r look like the RTP header of the missing packet
        self.pairs = Counter()
        self.v2 = Counter()
        self.plus1 = Counter()
        self.ts_fwd = Counter()
        self.same_ssrc = Counter()
        self.pair_total = 0
        self.examples = []


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", help="pcap directory or file from zoom_capture --pcap-dir")
    ap.add_argument("--types", help="comma list of media type bytes to probe (default: every type that is not video/audio/screen/RTCP)")
    ap.add_argument("--max-packets", type=int, default=3_000_000, help="stop after this many Zoom packets")
    ap.add_argument("--sample", type=int, default=20_000, help="consecutive-pair samples per type for the self-consistency test")
    ap.add_argument("--residual", help="comma list of KNOWN media types (e.g. 13): also probe their packets that are not RTP at the known offset, reported as '13*'")
    ap.add_argument("--no-split", action="store_true", help="do not split each type by packet-size class")
    ap.add_argument("--hex", type=int, default=0, help="also print the first N payload bytes of 3 example packets per type (payload bytes, no IPs)")
    ap.add_argument("--json", help="write the numbers to this file")
    a = ap.parse_args()
    want = {int(x) for x in a.types.split(",")} if a.types else None
    resid = {int(x) for x in a.residual.split(",")} if a.residual else set()

    stats = defaultdict(TypeStats)
    c13 = {"up": Counter(), "down": Counter()}      # direction -> media byte 7 (or "short") of every type-13 packet
    c13_b15 = {"up": Counter(), "down": Counter()}  # direction -> media byte 15 of the type-13 packets that are neither 0x1e nor 0x15
    c13_sig = {"up": Counter(), "down": Counter()}  # direction -> "n" / "sig" (padding signature at the direction's position) / "sig_other_dir"
    last_seq = {}  # (flow, ssrc) -> last RTP seq of a known media stream
    pending = {}  # flow -> [(type, payload)] unknown-type packets since the last known media packet
    last_unknown = {}  # (flow, type) -> previous payload
    total = zoom = known_media = gap_events = 0

    def census13(flow, pl):
        d = "down" if 8801 <= flow[2] <= 8810 else "up"     # the server side holds port 88xx
        if len(pl) < 8 + T13_SUBTYPE_POS + 1:
            c13[d]["short"] += 1
            return
        b7 = pl[8 + T13_SUBTYPE_POS]
        c13[d][b7] += 1
        if b7 not in (T13_RTP, T13_PROBE):
            c13_b15[d][pl[8 + T13_DOWN_MARKER_POS] if len(pl) > 8 + T13_DOWN_MARKER_POS else "short"] += 1
            c13_sig[d]["n"] += 1
            for dd, pos in T13_SIG_POS.items():
                if pl[pos:pos + 2] == T13_SIG:
                    c13_sig[d]["sig" if dd == d else "sig_other_dir"] += 1

    def process(rec):
        nonlocal known_media, gap_events
        flow, tb, pl, ulen = rec
        off = RTP_OFF.get(tb)
        if tb == 16 and len(pl) > 8 + 20:
            if pl[8 + 20] == VIDEO_BURST_BYTE:
                off = VIDEO_BURST_OFF
            elif pl[8 + 20] >> 6 == 2:
                off = VIDEO_RTP20_OFF
        gated13 = False
        if tb == 13:
            gated13 = len(pl) < 8 + T13_SUBTYPE_POS + 1 or pl[8 + T13_SUBTYPE_POS] != T13_RTP
            census13(flow, pl)
        base = tb
        if off is not None:
            o = 8 + off
            if gated13 or len(pl) < o + 12 or pl[o] >> 6 != 2:
                if tb not in resid:
                    return
                tb += RESID  # leftovers of a known type: probe them like an unknown type
                off = None
        if off is not None:
            known_media += 1
            seq, ssrc = u16(pl, o + 2), u32(pl, o + 8)
            key = (flow, ssrc)
            prev = last_seq.get(key)
            last_seq[key] = seq
            pend = pending.pop(flow, None)
            if prev is not None and pend:
                d = (seq - prev) & 0xFFFF
                if 2 <= d <= 4:
                    gap_events += 1
                    missing = {(prev + i) & 0xFFFF for i in range(1, d)}
                    for pkey, pb in pend:
                        st = stats[pkey]
                        st.gap_cands += 1
                        for r in range(R_LO, min(len(pb) - 11, R_HI)):
                            if pb[r] >> 6 == 2 and u32(pb, r + 8) == ssrc and u16(pb, r + 2) in missing:
                                st.gap_hits[r] += 1
            return
        if base in RTCP_TYPES or (want is not None and base not in want and base not in resid):
            return
        skey = (tb, "" if a.no_split else size_class(ulen))
        st = stats[skey]
        st.n += 1
        st.flows.add(flow)
        st.sizes[ulen] += 1
        if a.hex and len(st.examples) < 3:
            st.examples.append(pl[:a.hex].hex())
        pending.setdefault(flow, []).append((skey, pl))
        if len(pending[flow]) > 16:
            del pending[flow][0]
        k = (flow, skey)
        prev = last_unknown.get(k)
        last_unknown[k] = pl
        if prev is not None and st.pair_total < a.sample:
            st.pair_total += 1
            hi = min(len(pl), len(prev)) - 11
            for r in range(R_LO, min(hi, R_HI)):
                if pl[r] >> 6 == 2 and prev[r] >> 6 == 2:
                    st.pairs[r] += 1
                    if ((u16(pl, r + 2) - u16(prev, r + 2)) & 0xFFFF) == 1:
                        st.plus1[r] += 1
                    if ((u32(pl, r + 4) - u32(prev, r + 4)) & 0xFFFFFFFF) < 0x80000000:
                        st.ts_fwd[r] += 1
                    if pl[r + 8:r + 12] == prev[r + 8:r + 12]:
                        st.same_ssrc[r] += 1

    heap = []
    n = 0
    for us, buf in iter_pcap(a.pcap):
        total += 1
        fr = parse_frame(buf)
        if fr is None:
            continue
        flow, pl, ulen = fr
        if len(pl) < 9 or pl[0] != 0x05:
            continue
        zoom += 1
        if zoom > a.max_packets:
            break
        n += 1
        heapq.heappush(heap, (us, n, (flow, pl[8], pl, ulen)))
        while heap and heap[0][0] < us - REORDER_US:
            process(heapq.heappop(heap)[2])
    while heap:
        process(heapq.heappop(heap)[2])

    out = {}
    L = []
    w = L.append
    w("== probe of unparsed Zoom packet types ==")
    w("pcap records read: %d   Zoom-framed: %d   known audio/video/screen packets used as anchors: %d   sequence gaps of 2..4 examined: %d" % (
        total, zoom, known_media, gap_events))
    w("(offsets: 'payload' = bytes after the UDP header; 'media' = payload offset - 8, the convention of headers.rs)")
    w("")
    for skey in sorted(stats, key=lambda t: -stats[t].n):
        st = stats[skey]
        tb, cls = skey
        if st.n < 20:
            continue
        name = "%s [%s]" % (tname(tb), cls) if cls else tname(tb)
        res = dict(packets=st.n, flows=len(st.flows), top_sizes=[(s, c) for s, c in st.sizes.most_common(3)])
        w("-- type %s: %d packets in %d flows, most common UDP payload lengths (full length, not the snaplen): %s" % (
            name, st.n, len(st.flows), ", ".join("%d B x%d" % kv for kv in st.sizes.most_common(3))))
        # test 1
        if st.gap_cands >= 5:
            top = st.gap_hits.most_common(2)
            res["gap_fill"] = dict(candidates=st.gap_cands, top=[(r, c) for r, c in top])
            if top and top[0][1] >= 5 and top[0][1] >= 0.5 * st.gap_cands:
                r, c = top[0]
                w("   GAP FILL: %d of the %d packets that sit inside a known stream's sequence gap carry that stream's SSRC and the" % (c, st.gap_cands))
                w("             missing sequence number at payload offset %d (media offset +%d)  ->  RTP header found, same stream as the neighbours" % (r, r - 8))
                res["verdict_gap_fill"] = dict(payload_offset=r, media_offset=r - 8, share=c / st.gap_cands)
            elif top and top[0][1] >= 3:
                r, c = top[0]
                w("   GAP FILL: weak evidence: %d of %d at payload offset %d (media +%d)" % (c, st.gap_cands, r, r - 8))
            else:
                w("   GAP FILL: %d packets sat inside a known stream's gap but none carried its SSRC + missing seq at any offset %d..%d" % (
                    st.gap_cands, R_LO, R_HI))
                w("             (so they are not packets of that stream in RTP form at these offsets)")
        else:
            w("   GAP FILL: not applicable (%d packets inside gaps of a known stream; need >= 5)" % st.gap_cands)
        # test 2
        if st.pair_total >= MIN_PAIRS:
            rows = []
            for r in range(R_LO, R_HI):
                p = st.pairs[r]
                if p >= MIN_PAIRS:
                    rows.append((st.plus1[r] / p * st.same_ssrc[r] / p * st.ts_fwd[r] / p, r, p, st.plus1[r] / p, st.ts_fwd[r] / p, st.same_ssrc[r] / p))
            rows.sort(reverse=True)
            res["self_consistency"] = [dict(payload_offset=r, media_offset=r - 8, pairs=p, plus1=a1, ts_fwd=a2, ssrc_same=a3, score=s)
                                       for s, r, p, a1, a2, a3 in rows[:3]]
            if rows and rows[0][0] >= 0.5 and (len(rows) < 2 or rows[0][0] >= 2 * rows[1][0]):
                s, r, p, a1, a2, a3 = rows[0]
                w("   SELF-CONSISTENCY: RTP-like header at payload offset %d (media +%d): seq +1 in %.0f%%, timestamp never backwards %.0f%%, SSRC unchanged %.0f%%  (%d pairs)" % (
                    r, r - 8, 100 * a1, 100 * a2, 100 * a3, p))
                res["verdict_self"] = dict(payload_offset=r, media_offset=r - 8, score=s)
            elif rows:
                w("   SELF-CONSISTENCY: no clear winner; best candidates (payload offset: seq+1 / ts fwd / ssrc same):")
                for s, r, p, a1, a2, a3 in rows[:3]:
                    w("      %d (media +%d): %.0f%% / %.0f%% / %.0f%%  (%d pairs)" % (r, r - 8, 100 * a1, 100 * a2, 100 * a3, p))
            else:
                w("   SELF-CONSISTENCY: no offset with version bits 2 in enough consecutive packets: probably not RTP at all (control data?)")
        else:
            w("   SELF-CONSISTENCY: only %d consecutive same-flow pairs (need %d): this type is too sparse or too spread over flows" % (st.pair_total, MIN_PAIRS))
        if st.examples:
            w("   first %d payload bytes of 3 example packets:" % a.hex)
            for e in st.examples:
                w("      " + e)
        out[("%s/%s" % (tname(tb), cls)) if cls else tname(tb)] = res
        w("")
    if not out:
        w("no unparsed type with >= 20 packets in this pcap")
    n13 = sum(sum(c.values()) for c in c13.values())
    if n13:
        w("== type-13 sub-type census (media byte 7; p7b: 0x1e = screen-share RTP at +27, 0x15 = Type-21 probe padding, anything else = control) ==")
        census = {}
        for d, label in (("up", "uplink  "), ("down", "downlink")):
            c = c13[d]
            tot = sum(c.values())
            if not tot:
                continue
            top = ", ".join("%s x%d" % ("0x%02x" % k if isinstance(k, int) else k, v) for k, v in c.most_common(6))
            w("   %s %7d packets: %s" % (label, tot, top))
            other = tot - c[T13_RTP] - c[T13_PROBE]
            marker15 = c13_b15[d][T13_PROBE]
            sig = c13_sig[d]["sig"]
            census[d] = dict(packets=tot, rtp_0x1e=c[T13_RTP], probe_0x15=c[T13_PROBE], other=other, other_with_0x15_at_byte_15=marker15,
                             other_with_padding_signature=sig)
            if other:
                w("      filed as control by p7b: %d; of those, media byte 15 = 0x15 in %d (%.1f %%), padding signature 03 e8 at payload byte %d in %d (%.1f %%)" % (
                    other, marker15, 100.0 * marker15 / other, T13_SIG_POS[d], sig, 100.0 * sig / other))
        u_other = census.get("up", {}).get("other", 0)
        u_sig = census.get("up", {}).get("other_with_padding_signature", 0)
        if u_other >= 50 and u_sig >= 0.05 * u_other:
            w("   !! uplink: %.0f %% of the control-filed type-13 packets carry the padding signature although media byte 7 is not 0x15:" % (100.0 * u_sig / u_other))
            w("      the byte-7 rule misses part of the probe padding (the deck counts 30,383 padding packets but 25,839 with 0x15 at byte 7); consider a second rule")
        d_other = census.get("down", {}).get("other", 0)
        d_m15 = census.get("down", {}).get("other_with_0x15_at_byte_15", 0)
        if d_other >= 50:
            if d_m15 >= 0.05 * d_other:
                w("   !! downlink: %.0f %% of the control-filed type-13 packets have 0x15 at media byte 15 -> the probe marker sits there on the downlink (deck2 slide 41):" % (100.0 * d_m15 / d_other))
                w("      p7b files them as t13_ctrl; extend Type13Kind in headers.rs with a second rule and re-run")
            else:
                w("   downlink: no sign of probe padding at media byte 15 among the control-filed packets (%d of %d): the OPEN question looks closed (still: one capture)" % (d_m15, d_other))
        else:
            w("   downlink: fewer than 50 control-filed packets, nothing to conclude about the OPEN downlink-envelope question")
        w("")
        out["type13_census"] = census
    print("\n".join(L))
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(out, fh, indent=1)


if __name__ == "__main__":
    main()
