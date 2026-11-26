#!/usr/bin/env python3
"""
filter_by_ip.py - filter every CSV and PCAP/PCAPNG in a directory by IP list.

Only rows / packets whose source IP OR destination IP is in the list are kept.
Results are written to an output directory that mirrors the input layout.

Usage
-----
  python filter_by_ip.py INPUT_DIR IP_LIST [-o OUTPUT_DIR] [options]

  IP_LIST  a text file with one IP or CIDR per line ('#' starts a comment;
           commas / spaces also work).  If the argument is not an existing
           file it is read as an inline comma-separated list, e.g.
           "2001:df4:e000:3fd3:48b5:bcc8:6905:7459,10.0.0.0/8"

Behaviour
---------
  * IPv4 and IPv6, exact addresses and CIDR ranges.
  * CSV: header is always kept; rows are matched on the src_ip / dst_ip
    columns (change with --src-col / --dst-col).
  * PCAP and PCAPNG (any endianness, micro/nanosecond): packets are copied
    byte-for-byte (timestamps untouched), only non-matching packets are
    dropped.  Packets with no IP header (ARP, etc.) are dropped.
  * pcap files are detected by their magic bytes, not just the extension.
  * Other files are ignored unless --copy-others is given.
  * Pure standard library - no scapy / tshark needed.
"""

import argparse
import csv
import ipaddress
import os
import shutil
import struct
import sys
from functools import lru_cache
from pathlib import Path

# --------------------------------------------------------------------------- #
# IP matching
# --------------------------------------------------------------------------- #
V4_MAPPED_PREFIX = b"\x00" * 10 + b"\xff\xff"


class IPFilter:
    def __init__(self, entries):
        self.exact = set()   # packed bytes (4 or 16)
        self.nets = []       # (n_bytes, network_int, netmask_int)
        for tok in entries:
            self._add(tok)
        if not self.exact and not self.nets:
            raise ValueError("IP list is empty")
        self.match_raw = lru_cache(maxsize=1 << 20)(self._match_raw)
        self.match_text = lru_cache(maxsize=1 << 20)(self._match_text)

    @staticmethod
    def _clean(tok):
        tok = tok.strip().strip("[]")
        if "%" in tok:                       # IPv6 zone id
            tok = tok.split("%", 1)[0]
        return tok

    def _add(self, tok):
        tok = self._clean(tok)
        if not tok:
            return
        net = ipaddress.ip_network(tok, strict=False)
        if net.prefixlen == net.max_prefixlen:
            raw = net.network_address.packed
            if len(raw) == 16 and raw.startswith(V4_MAPPED_PREFIX):
                raw = raw[12:]
            self.exact.add(raw)
        else:
            self.nets.append((len(net.network_address.packed),
                              int(net.network_address), int(net.netmask)))

    def _match_raw(self, raw):
        if len(raw) == 16 and raw.startswith(V4_MAPPED_PREFIX):
            raw = raw[12:]
        if raw in self.exact:
            return True
        if self.nets:
            n, val = len(raw), int.from_bytes(raw, "big")
            for nb, net, mask in self.nets:
                if nb == n and (val & mask) == net:
                    return True
        return False

    def _match_text(self, text):
        text = self._clean(text)
        if not text:
            return False
        try:
            raw = ipaddress.ip_address(text).packed
        except ValueError:
            return False
        return self._match_raw(raw)


def load_ip_filter(arg):
    if os.path.isfile(arg):
        text = Path(arg).read_text(encoding="utf-8-sig", errors="replace")
    else:
        text = arg.replace(",", "\n")
    entries = []
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        entries.extend(line.replace(",", " ").split())
    return IPFilter(entries)


# --------------------------------------------------------------------------- #
# Packet -> (src, dst) extraction
# --------------------------------------------------------------------------- #
SUPPORTED_LINKTYPES = {0, 1, 12, 14, 101, 108, 113, 228, 229, 276}
_warned = set()


def warn(msg):
    print(f"  [warn] {msg}", file=sys.stderr)


def _ipv4(d, off):
    if len(d) >= off + 20 and d[off] >> 4 == 4:
        return d[off + 12:off + 16], d[off + 16:off + 20]
    return None


def _ipv6(d, off):
    if len(d) >= off + 40 and d[off] >> 4 == 6:
        return d[off + 8:off + 24], d[off + 24:off + 40]
    return None


def _by_version(d, off):
    if len(d) <= off:
        return None
    v = d[off] >> 4
    if v == 4:
        return _ipv4(d, off)
    if v == 6:
        return _ipv6(d, off)
    return None


def _by_ethertype(d, etype, off):
    if etype == 0x0800:
        return _ipv4(d, off)
    if etype == 0x86DD:
        return _ipv6(d, off)
    return None


def extract_ips(linktype, d):
    n = len(d)
    if linktype == 1:                                   # Ethernet (+VLAN/QinQ)
        if n < 14:
            return None
        etype, off = (d[12] << 8) | d[13], 14
        while etype in (0x8100, 0x88A8, 0x9100) and n >= off + 4:
            etype, off = (d[off + 2] << 8) | d[off + 3], off + 4
        return _by_ethertype(d, etype, off)
    if linktype == 113:                                 # Linux cooked v1
        if n < 16:
            return None
        return _by_ethertype(d, (d[14] << 8) | d[15], 16)
    if linktype == 276:                                 # Linux cooked v2
        if n < 20:
            return None
        return _by_ethertype(d, (d[0] << 8) | d[1], 20)
    if linktype in (12, 14, 101, 228, 229):             # raw IP
        return _by_version(d, 0)
    if linktype in (0, 108):                            # BSD loopback / null
        return _by_version(d, 4)
    return None


def packet_matches(flt, linktype, data):
    ips = extract_ips(linktype, data)
    return ips is not None and (flt.match_raw(ips[0]) or flt.match_raw(ips[1]))


def check_linktype(lt):
    if lt not in SUPPORTED_LINKTYPES and lt not in _warned:
        _warned.add(lt)
        warn(f"unsupported link type {lt}: its packets cannot be matched and are dropped")


# --------------------------------------------------------------------------- #
# Classic PCAP
# --------------------------------------------------------------------------- #
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",   # microsecond
    b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",   # nanosecond
}
SHB_TYPE = b"\x0a\x0d\x0d\x0a"


def filter_pcap(src, dst, flt):
    total = kept = 0
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        hdr = fi.read(24)
        if len(hdr) < 24 or hdr[:4] not in PCAP_MAGICS:
            raise ValueError("not a valid pcap file")
        endian = PCAP_MAGICS[hdr[:4]]
        linktype = struct.unpack(endian + "I", hdr[20:24])[0] & 0x0FFFFFFF
        check_linktype(linktype)
        fo.write(hdr)
        rec = struct.Struct(endian + "IIII")
        while True:
            rh = fi.read(16)
            if not rh:
                break
            if len(rh) < 16:
                warn("truncated record header at end of file")
                break
            incl = rec.unpack(rh)[2]
            data = fi.read(incl)
            if len(data) < incl:
                warn("truncated packet at end of file")
                break
            total += 1
            if packet_matches(flt, linktype, data):
                fo.write(rh)
                fo.write(data)
                kept += 1
    return total, kept


# --------------------------------------------------------------------------- #
# PCAPNG
# --------------------------------------------------------------------------- #
def filter_pcapng(src, dst, flt):
    total = kept = 0
    endian = None
    ifaces = []                        # link type per interface (current section)
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while True:
            head = fi.read(8)
            if not head:
                break
            if len(head) < 8:
                warn("truncated block header at end of file")
                break

            if head[:4] == SHB_TYPE:                       # section header
                bom = fi.read(4)
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise ValueError("bad pcapng byte-order magic")
                blen = struct.unpack(endian + "I", head[4:8])[0]
                if blen < 12 or blen % 4:
                    raise ValueError("corrupt pcapng section header")
                block = head + bom + fi.read(blen - 12)
                ifaces = []
                btype = 0x0A0D0D0A
            else:
                if endian is None:
                    raise ValueError("not a valid pcapng file")
                btype, blen = struct.unpack(endian + "II", head)
                if blen < 12 or blen % 4:
                    raise ValueError("corrupt pcapng block length")
                block = head + fi.read(blen - 8)

            if len(block) < blen:
                warn("truncated block at end of file")
                break

            if btype == 0x00000001:                        # interface description
                lt = struct.unpack(endian + "H", block[8:10])[0]
                ifaces.append(lt)
                check_linktype(lt)
                fo.write(block)
            elif btype == 0x00000006:                      # enhanced packet
                iface, = struct.unpack(endian + "I", block[8:12])
                caplen, = struct.unpack(endian + "I", block[20:24])
                data = block[28:28 + caplen]
                lt = ifaces[iface] if iface < len(ifaces) else -1
                total += 1
                if packet_matches(flt, lt, data):
                    fo.write(block)
                    kept += 1
            elif btype == 0x00000003:                      # simple packet
                data = block[12:blen - 4]
                lt = ifaces[0] if ifaces else -1
                total += 1
                if packet_matches(flt, lt, data):
                    fo.write(block)
                    kept += 1
            elif btype == 0x00000002:                      # obsolete packet block
                iface, = struct.unpack(endian + "H", block[8:10])
                caplen, = struct.unpack(endian + "I", block[20:24])
                data = block[28:28 + caplen]
                lt = ifaces[iface] if iface < len(ifaces) else -1
                total += 1
                if packet_matches(flt, lt, data):
                    fo.write(block)
                    kept += 1
            else:                                          # SHB, NRB, ISB, custom...
                fo.write(block)
    return total, kept


# --------------------------------------------------------------------------- #
# CSV
# --------------------------------------------------------------------------- #
csv.field_size_limit(2**31 - 1)


def filter_csv(src, dst, flt, src_col, dst_col):
    with open(src, "rb") as f:
        sample = f.read(65536)
    lineterm = "\r\n" if b"\r\n" in sample else "\n"
    total = kept = 0
    with open(src, newline="", encoding="utf-8-sig", errors="surrogateescape") as fi, \
         open(dst, "w", newline="", encoding="utf-8", errors="surrogateescape") as fo:
        reader = csv.reader(fi)
        writer = csv.writer(fo, lineterminator=lineterm)
        header = next(reader, None)
        if header is None:
            return 0, 0
        names = [h.strip().lower() for h in header]
        idx = [names.index(c.lower()) for c in (src_col, dst_col) if c.lower() in names]
        if not idx:
            raise ValueError(f"no '{src_col}' or '{dst_col}' column in header")
        writer.writerow(header)
        for row in reader:
            total += 1
            for i in idx:
                if i < len(row) and flt.match_text(row[i]):
                    writer.writerow(row)
                    kept += 1
                    break
    return total, kept


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def sniff(path):
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return None
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == SHB_TYPE:
        return "pcapng"
    return None


def main():
    ap = argparse.ArgumentParser(
        description="Keep only CSV rows / pcap packets whose src or dst IP is in a list.")
    ap.add_argument("input_dir")
    ap.add_argument("ip_list", help="file with IPs/CIDRs (one per line) or an inline comma-separated list")
    ap.add_argument("-o", "--output", help="output directory (default: <input_dir>_filtered)")
    ap.add_argument("--src-col", default="src_ip", help="CSV source-IP column (default src_ip)")
    ap.add_argument("--dst-col", default="dst_ip", help="CSV destination-IP column (default dst_ip)")
    ap.add_argument("--no-recursive", action="store_true", help="do not descend into sub-directories")
    ap.add_argument("--copy-others", action="store_true",
                    help="copy files that are neither CSV nor pcap unchanged")
    ap.add_argument("--skip-empty", action="store_true",
                    help="do not write output files that end up with no matches")
    args = ap.parse_args()

    in_dir = Path(args.input_dir).resolve()
    if not in_dir.is_dir():
        sys.exit(f"Input directory not found: {in_dir}")
    out_dir = Path(args.output).resolve() if args.output else in_dir.with_name(in_dir.name + "_filtered")
    if out_dir == in_dir:
        sys.exit("Output directory must differ from the input directory.")

    try:
        flt = load_ip_filter(args.ip_list)
    except ValueError as e:
        sys.exit(f"Bad IP list: {e}")
    print(f"Loaded {len(flt.exact)} address(es) and {len(flt.nets)} network(s).")

    out_dir.mkdir(parents=True, exist_ok=True)
    n_done = n_err = n_copied = n_ignored = 0
    tot_in = tot_out = 0

    for root, dirs, files in os.walk(in_dir):
        dirs[:] = sorted(d for d in dirs if (Path(root) / d).resolve() != out_dir)
        if args.no_recursive:
            dirs[:] = []
        for name in sorted(files):
            src = Path(root) / name
            rel = src.relative_to(in_dir)
            dst = out_dir / rel
            kind = "csv" if name.lower().endswith(".csv") else sniff(src)

            if kind is None:
                if args.copy_others:
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)
                    n_copied += 1
                else:
                    n_ignored += 1
                continue

            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = dst.with_name(dst.name + ".part")
            try:
                if kind == "csv":
                    total, kept = filter_csv(src, tmp, flt, args.src_col, args.dst_col)
                elif kind == "pcap":
                    total, kept = filter_pcap(src, tmp, flt)
                else:
                    total, kept = filter_pcapng(src, tmp, flt)
            except Exception as e:                        # one bad file must not stop the run
                tmp.unlink(missing_ok=True)
                print(f"[error] {rel}: {e}", file=sys.stderr)
                n_err += 1
                continue

            unit = "rows" if kind == "csv" else "packets"
            if kept == 0 and args.skip_empty:
                tmp.unlink(missing_ok=True)
                print(f"[{kind:6}] {rel}: 0 / {total:,} {unit} matched - skipped")
            else:
                os.replace(tmp, dst)
                print(f"[{kind:6}] {rel}: kept {kept:,} / {total:,} {unit}")
            n_done += 1
            tot_in += total
            tot_out += kept

    print(f"\nDone. Processed {n_done} file(s), kept {tot_out:,} of {tot_in:,} records. "
          f"Errors: {n_err}. Copied: {n_copied}. Ignored: {n_ignored}.")
    print(f"Output: {out_dir}")


if __name__ == "__main__":
    main()