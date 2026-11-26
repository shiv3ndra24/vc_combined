#!/usr/bin/env python3
"""Replace the CLIENT IP of every row of a zoom_capture packet CSV by a random token.

    python3 -I tools/anonymize_csv.py packets.csv packets_anon.csv [--label IP=name,IP=name] [--only-labelled]
                                      [--from-s T] [--to-s T] [--max-rows N]

Why: the CSV holds campus user IPs. Stage 2 needs to know which rows belong to
the same client (streams are keyed by client + direction + SSRC), not who the
client is. A token keeps the grouping and drops the identity.

* the client side is src_ip when dir == "up" and dst_ip when dir == "down";
  the Zoom server side stays as it is (public address, needed to see which
  servers carry which traffic);
* the token is HMAC-SHA256(random 16-byte key, ip) cut to 8 hex digits; the key
  exists only inside this process and is never written, so nobody (including
  you, tomorrow) can map a token back to an address;
* nothing else changes, so tools/validate_rtp_csv.py gives the same verdicts on
  the anonymised file. That includes the p7b columns `media_b20` and `media_b7`:
  they are two bytes of the Zoom media header (video layout byte, type-13 sub-type
  byte), protocol structure that identifies nobody, so they pass through unchanged;
* --label 10.1.2.3=my-pc,10.1.2.9=phone-1 appends a column `client_label`
  holding the name you chose for those clients' rows (empty for everybody
  else). The name is yours, the address is not written, and the token stays
  random. This is how you tell the analysis "these rows are my PC application"
  without handing over the IP: the validator shows the name next to the client
  and --clients can then select it.

* --only-labelled keeps ONLY the rows of the devices named with --label (your own
  PCs) and drops every other client of the campus capture. Prefer it over
  --max-rows: the file stays small WITHOUT cutting the run short (s3 was cut at
  146 s of 318 s by --max-rows 400000 and so missed the audio, screen share and
  stop events), and the packets of people who are not part of the experiment
  never leave the machine at all.
* --from-s / --to-s keep only rows whose time_offset_s lies in [from, to]
  (e.g. --from-s 190 --to-s 270 for the screen-share minute).

The pcap is not anonymised by this script: it contains full IPs and MAC
addresses. Keep pcap files on the campus machine unless you decide otherwise;
the validator reads them locally with --pcap.
"""
import argparse
import csv
import hashlib
import hmac
import os
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--max-rows", type=int, default=0, help="keep only the first N rows (0 = all). Cuts the END of the run off; prefer --only-labelled")
    ap.add_argument("--only-labelled", action="store_true", help="keep only the rows of the devices named with --label")
    ap.add_argument("--from-s", type=float, default=None, help="keep rows with time_offset_s >= this")
    ap.add_argument("--to-s", type=float, default=None, help="keep rows with time_offset_s <= this")
    ap.add_argument("--label", default="", help="IP=name,IP=name  names for your own devices (client IP -> name); adds a client_label column")
    a = ap.parse_args()
    if a.only_labelled and not a.label:
        sys.exit("ERROR: --only-labelled needs --label IP=name,... to say which devices to keep")
    key = os.urandom(16)
    cache = {}
    labels = {}
    for item in a.label.split(","):
        if "=" in item:
            ip, nm = item.split("=", 1)
            labels[ip.strip()] = nm.strip().replace(",", "_")
    used = set()

    def tok(ip):
        t = cache.get(ip)
        if t is None:
            t = cache[ip] = "c-" + hmac.new(key, ip.encode(), hashlib.sha256).hexdigest()[:8]
        return t

    n = 0
    with open(a.src, newline="") as fi, open(a.dst, "w", newline="") as fo:
        rd, wr = csv.reader(fi), csv.writer(fo, lineterminator="\n")
        head = next(rd)
        idx = {c: i for i, c in enumerate(head)}
        for c in ("dir", "src_ip", "dst_ip"):
            if c not in idx:
                sys.exit("ERROR: column %s not found; is this a zoom_capture --packet-csv file?" % c)
        i_dir, i_src, i_dst = idx["dir"], idx["src_ip"], idx["dst_ip"]
        i_t = idx.get("time_offset_s")
        if (a.from_s is not None or a.to_s is not None) and i_t is None:
            sys.exit("ERROR: column time_offset_s not found, cannot apply --from-s/--to-s")
        wr.writerow(head + (["client_label"] if labels else []))
        for row in rd:
            if i_t is not None and (a.from_s is not None or a.to_s is not None):
                try:
                    ts = float(row[i_t])
                except ValueError:
                    continue
                if (a.from_s is not None and ts < a.from_s) or (a.to_s is not None and ts > a.to_s):
                    continue
            client = row[i_src] if row[i_dir] == "up" else row[i_dst]
            if a.only_labelled and client not in labels:
                continue
            if row[i_dir] == "up":
                ip, row[i_src] = row[i_src], tok(row[i_src])
            else:
                ip, row[i_dst] = row[i_dst], tok(row[i_dst])
            if labels:
                nm = labels.get(ip, "")
                if nm:
                    used.add(ip)
                row.append(nm)
            wr.writerow(row)
            n += 1
            if a.max_rows and n >= a.max_rows:
                break
    print("wrote %d rows, %d distinct clients -> %s" % (n, len(cache), a.dst))
    if labels:
        missing = [labels[ip] for ip in labels if ip not in used]
        print("labelled %d of %d devices%s" % (len(used), len(labels), ("; NOT seen in this file: " + ", ".join(missing)) if missing else ""))


if __name__ == "__main__":
    main()
