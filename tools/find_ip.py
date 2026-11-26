#!/usr/bin/env python3
"""
Find IPv6 addresses of the form  2001:df4:....:....:....:....:....:..727
in CSV files with the header:

arrival_epoch_ns,src_ip,dst_ip,ip_proto,ip_len,src_port,dst_port,udp_len,
rtp_ssrc,rtp_timestamp,rtp_seq,rtp_pt,rtp_marker

An address matches when
  * it lies inside the prefix (default 2001:df4::/32), and
  * its last hex digits equal the suffix (default "727"), regardless of how
    the address is written (compressed or fully expanded).

Usage examples
--------------
  python find_ip.py capture.csv
  python find_ip.py data/                       # every *.csv in the folder
  python find_ip.py "logs/*.csv" -o matches.csv
  python find_ip.py data/ --columns dst_ip      # only check dst_ip
  python find_ip.py data/ --prefix 2001:df4::/32 --suffix 727
"""

import argparse
import csv
import glob
import ipaddress
import os
import sys
from collections import Counter
from functools import lru_cache


def collect_files(inputs, recursive):
    files = []
    for item in inputs:
        if os.path.isdir(item):
            pattern = "**/*.csv" if recursive else "*.csv"
            files.extend(glob.glob(os.path.join(item, pattern), recursive=recursive))
        else:
            hits = glob.glob(item, recursive=recursive)
            files.extend(hits if hits else [item])
    # de-duplicate, keep order
    return list(dict.fromkeys(files))


def make_matcher(prefix, suffix):
    net = ipaddress.IPv6Network(prefix, strict=False)
    suffix = suffix.lower().lstrip("0x") or "0"
    bits = 4 * len(suffix)
    mask = (1 << bits) - 1
    want = int(suffix, 16)

    @lru_cache(maxsize=1_000_000)
    def matches(value):
        try:
            ip = ipaddress.IPv6Address(value.strip())
        except ValueError:
            return False
        return ip in net and (int(ip) & mask) == want

    return matches


def main():
    ap = argparse.ArgumentParser(description="Find IPv6 addresses 2001:df4:...727 in CSV files.")
    ap.add_argument("inputs", nargs="+", help="CSV files, folders or glob patterns")
    ap.add_argument("-o", "--output", help="write matching rows to this CSV file")
    ap.add_argument("--prefix", default="2001:df4::/32", help="IPv6 prefix (default 2001:df4::/32)")
    ap.add_argument("--suffix", default="727", help="trailing hex digits (default 727)")
    ap.add_argument("--columns", default="src_ip,dst_ip",
                    help="comma-separated columns to check (default src_ip,dst_ip)")
    ap.add_argument("-r", "--recursive", action="store_true", help="search folders recursively")
    args = ap.parse_args()

    columns = [c.strip() for c in args.columns.split(",") if c.strip()]
    matches = make_matcher(args.prefix, args.suffix)
    files = collect_files(args.inputs, args.recursive)
    if not files:
        sys.exit("No input files found.")

    ip_counts = Counter()
    total_rows = matched_rows = 0
    out_fh = out_writer = None

    try:
        for path in files:
            try:
                fh = open(path, newline="", encoding="utf-8-sig", errors="replace")
            except OSError as e:
                print(f"[skip] {path}: {e}", file=sys.stderr)
                continue

            with fh:
                reader = csv.DictReader(fh)
                missing = [c for c in columns if c not in (reader.fieldnames or [])]
                if missing:
                    print(f"[skip] {path}: missing column(s) {missing}", file=sys.stderr)
                    continue

                for row in reader:
                    total_rows += 1
                    hit = False
                    for col in columns:
                        val = row.get(col) or ""
                        if matches(val):
                            ip_counts[val.strip().lower()] += 1
                            hit = True
                    if not hit:
                        continue

                    matched_rows += 1
                    if args.output:
                        if out_writer is None:
                            out_fh = open(args.output, "w", newline="", encoding="utf-8")
                            out_writer = csv.writer(out_fh)
                            out_writer.writerow(["source_file"] + reader.fieldnames)
                        out_writer.writerow([path] + [row.get(f, "") for f in reader.fieldnames])
                    else:
                        print(f"{path}: " + ",".join(row.get(f, "") for f in reader.fieldnames))
    finally:
        if out_fh:
            out_fh.close()

    print("\n--- Summary ---", file=sys.stderr)
    print(f"Files scanned : {len(files)}", file=sys.stderr)
    print(f"Rows scanned  : {total_rows}", file=sys.stderr)
    print(f"Rows matched  : {matched_rows}", file=sys.stderr)
    print(f"Unique IPs    : {len(ip_counts)}", file=sys.stderr)
    for ip, n in ip_counts.most_common():
        print(f"  {ip}  ({n} rows)", file=sys.stderr)
    if args.output and matched_rows:
        print(f"Matching rows written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()