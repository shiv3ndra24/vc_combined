# vc_capture: metrics guide

Everything `vc_capture` exports: each measurement, tag and field, with its definition, its formula,
and what it was called before (in `zoom_capture` p7b or in the Teams/Meet crate `capture_data`).
The formulas were checked against the code (file and function given where it helps). The worked
numbers in section 9 come from the end-to-end test run (synthetic traffic, `devtools/run_e2e.sh`).

Contents
0. Conventions
1. Measurements at a glance
2. Shared `session_metrics` fields (same name means same rule)
3. `session_metrics` fields that only Teams/Meet has
4. `session_metrics` fields that only Zoom has, plus `client_no_media` and `session_summary`
5. `rtp_stream` (per SSRC)
6. `capture_health` and `capture_health_core`
7. Files: CSV columns, pcap, `run_info.txt`
8. Old name to new name tables
9. Worked examples
10. Constants
11. Differences between the engines that remain, and quirks

---

## 0. Conventions (both engines)

| Rule | Value | Example |
|---|---|---|
| Unit of a point | one client IP, one 5 s bin. Uplink = client -> server, downlink = server -> client | 10.184.5.20 -> 52.113.64.10 is uplink |
| Direction suffix | `_uplink` / `_downlink` (for example `fps_downlink`) | |
| Timestamp | the **end** of the bin | a point stamped 10:00:10 holds 10:00:05-10:00:10 |
| Bin alignment | Teams/Meet: epoch (`t / 5 s`). Zoom: process start (`t_since_start / 5 s`), points written once the bin has settled (3 s) | see section 11 |
| Rates | `x / 5.0 s`: the nominal bin, also for partial bins. `bin_cover_s` tells you how much of the bin had traffic | a client that starts 1 s before the bin ends reads about 1/5 of its rate |
| Bytes | **UDP payload** (`udp_len - 8`), the thesis' throughput definition. The Teams/Meet crate used to count the 8-byte UDP header too | 140 pkt/s: 140 x 8 x 8 = 8 960 bit/s less than before |
| After de-dup | with `--dedup fp` a mirror twin is counted nowhere | |
| Undefined = absent | a field that has no value in a bin is **not written** (no `0.00`). Counts (`..._active`, `stalls`) are always written | no counted video stream: `video_streams_active_downlink=0i` and no `fps_downlink` |
| Types | no suffix = float, `i` = integer, `true/false` = boolean | |
| `platform` tag | `zoom`, `teams`, `meet` | |
| `session_id` tag | `Z_` / `T_` / `M_` + 16 hex digits of hash(client IP, first packet time) | new id after 120 s of silence |

**Why "undefined = absent".** Before, the Teams/Meet crate wrote `down_fps=0.00` when there was no
valid video stream in the bin. In the 2026-11-04 Meet runs that zero was read as "the video stalled"
when it meant "no stream was counted" (handoff section 1). An absent field draws as a gap in Grafana,
and `video_streams_active_downlink=0i` states the reason explicitly.

---

## 1. Measurements at a glance

| Measurement | Written by | Tags | When | Previously |
|---|---|---|---|---|
| `session_metrics` | both | `client_ip`, `session_id`, `platform` | per client and bin | Zoom: same name. Teams/Meet: `teams_session_qoe` |
| `rtp_stream` | both (`--ssrc-lines`) | `client_ip`, `session_id`, `ssrc` (`0x%08X`), `stream_type`, `direction`, `platform`, `pt` (+ `type` for Zoom) | per SSRC and bin | Zoom: `zoom_rtp_stream` (opt-in). Teams/Meet: `teams_rtp_stream` (always) |
| `capture_health` | both | `host`, `engine` (`zoom` / `teams_meet`) | every `--health-secs` (5 s) | Zoom: same name, no `engine` tag. Teams/Meet: new (printed only before) |
| `capture_health_core` | Zoom | `host`, `engine=zoom`, `core` | same | same, no `engine` tag |
| `client_no_media` | Zoom | `client_ip`, `platform` | per client and bin without an open session | unchanged |
| `session_summary` | Zoom | `client_ip`, `session_id`, `platform` | upsert every 60 s and at close | unchanged |

`--ssrc-lines` default `teams-meet`: the Teams/Meet per-SSRC lines stay on (as before), Zoom's stay
off (as before; every call adds `ssrc` and `session_id` series). `all` turns both on, `none` both off.

---

## 2. Shared `session_metrics` fields: same name means same rule

These 47 field names appear in the points of all three platforms (checked on the e2e output). The
formula is the same. What can differ is the **input**: what the engine knows a packet or a stream is.

* **Zoom** knows the media type from the Zoom header: type 16 is video, 15 audio, 13/30 screen.
* **Teams/Meet** has encrypted SRTP and no such header, so the old size rule decides.
  * A stream is **video** if, over its life, more of its packets had `udp_len > 400` than `<= 400`.
    Otherwise it is **audio**.
  * A video stream is **screen** if its RTP-timestamp gaps are not clustered (the old degradation
    classifier). Example: gaps of 3 000 ticks 95 % of the time is a camera; 200 / 3 000 / 45 000
    ticks mixed is a screen share.
  * Only packets with `udp_len > 400` count toward frames.

**Qualification (both engines).** A stream is "media" only after at least 20 packets, of which at
least 90 % moved the RTP sequence number forward by 1..100. A stream not qualified after 64 packets
has failed. The stream key is (client, direction, SSRC); Zoom adds the header type and PT. Packets
of streams that are not (yet) qualified are counted only in `throughput_*`, `pps_*` and
`unq_media_*`. The bin in which a stream qualifies counts whole.

Example: Meet sent 3 packets with SSRC 0 and sequence numbers 1-3 (probes). They never reach 20
packets, so they add 0.6 pkt/s to `unq_media_pps_downlink` and nothing to `video_*`. This was seen in
the e2e test, first bin.

### 2.1 Volume

| Field | Definition / formula | Previously (Zoom / Teams-Meet) |
|---|---|---|
| `throughput_<dir>_bps` | 8 x Σ UDP payload bytes of every counted packet of that direction / 5. Zoom: every packet of the client on the Zoom gate (media, RTCP, type 21, probes...). Teams/Meet: every RTP packet (RTCP/STUN/DTLS are removed by the RFC 7983 demux before metrics) | same / `up_bps`, `down_bps` (included the 8-byte UDP header) |
| `pps_<dir>` | packets / 5 | same / `up_pps`, `down_pps` |
| `video_bitrate_<dir>_bps`, `video_pps_<dir>` | 8 x payload bytes / 5, packets / 5, of **qualified video** streams. Zoom: FEC (PT 110) included, see `fec_*` | same / downlink only: `video_total_bps` (every packet > 400 B, any stream) |
| `audio_bitrate_<dir>_bps`, `audio_pps_<dir>` | same for qualified audio streams | same / downlink only: `audio_bps` (every packet <= 400 B) |
| `screen_bitrate_<dir>_bps`, `screen_pps_<dir>` | same for qualified screen streams (Zoom: type 13 sub-type 0x1e + type 30) | same / new |
| `unq_media_bitrate_<dir>_bps`, `unq_media_pps_<dir>` | packets of media streams that are not qualified (first packets, probes, failed streams) | same / new |
| `bin_cover_s` | last minus first packet time of the client in the bin, in seconds | same / new |

Partition (Teams/Meet): `pps = video_pps + audio_pps + screen_pps + unq_media_pps`.
Zoom: `pps = video + audio + screen + rtcp + other + nohdr + type21 + unq_video + unq_audio + unq_screen + t13_probe + t13_ctrl` (section 4).

### 2.2 Video quality: qualified camera-video streams, per direction

| Field | Definition / formula | Previously (Zoom / Teams-Meet) |
|---|---|---|
| `video_streams_active_<dir>` | number of qualified video streams with packets in the bin | same / new (the old `video_streams_active` is now `camera_streams_active`, section 3) |
| `video_frames_<dir>` | Σ frames started in the bin. A frame starts at an RTP timestamp not among the stream's last 8 distinct timestamps (a late packet of an older frame is not a new frame) | same / new |
| `fps_<dir>` | **mean over streams** of `frames / covered s`, for streams whose packets cover >= 1 s of the bin. Covered = last minus first packet time of that stream. Teams/Meet also needs >= 1 frame gap of 1 500-90 000 ticks (a camera cadence) | same / `up_fps`, `down_fps` = frames / 5 s; screen streams included; `0.00` when there was none |
| `frame_gap_std_ms_<dir>` | population sigma, `sqrt(M2 / n)`, of the gaps between consecutive frame **end** times (last packet of each frame), pooled over the streams (parallel Welford). Only gaps whose RTP timestamp step is 1 500-90 000 ticks count. Needs n >= 2 | same / `up_frame_jitter_ms`, `down_frame_jitter_ms` = mean of per-stream sigmas over all gaps |
| `jitter_ms_<dir>` | **RFC 3550 interarrival jitter at frame level** (decision 2026-11-06). Per stream, at each frame boundary: `D = (ET_i - ET_i-1) - (TS_i - TS_i-1) / 90 kHz` in ms, then `J += (abs(D) - J) / 16`, only for timestamp steps 1 500-90 000. The value at the end of the bin, packet-weighted mean over streams | same / new |
| `stalls_<dir>` | number of frame gaps longer than 200 ms with a forward timestamp | same / new |
| `retransmits_<dir>` | packets whose RTP sequence number had already been received (128-number bitmap) and that survived de-dup. All qualified streams of that direction (Zoom: video + audio + screen, FEC included) | same / new |
| `degraded_<dir>` | 1 if the mean fps of the streams that cover >= 4 s of the bin is below 15, else 0. **Not written while a screen share is active** (`share_active = 1`) or when no stream covers 4 s | same / new (the old flag is `bin_degraded`, section 3) |
| `video_streams_degraded_<dir>` | number of those >= 4 s streams below 15 fps | same / new |

Why "frames / covered s" and not "/ 5": a client that joins 2 s before a bin ends sent 60 frames of
a 30 fps camera. Divided by 5 that reads as 12 fps, a false "degraded". Divided by the 2 s covered it
reads as 30. The price is a small fencepost effect: 150 frames whose packets span 4.967 s read
**30.20**, not 30.00. This is the same on all three platforms (e2e: Zoom 30.20, Teams 30.20).

### 2.3 Audio and screen

| Field | Definition / formula | Previously (Zoom / Teams-Meet) |
|---|---|---|
| `audio_active_s_<dir>` | seconds of the bin in which an audio stream had more than 20 packets (second = (t mod 5 s) / 1 s); the maximum over audio streams. Written when an audio stream exists | same / new |
| `screen_streams_active_<dir>` | qualified screen streams with packets | same / new |
| `screen_frames_<dir>` | frames of those streams | same / new |
| `screen_fps_<dir>` | mean over screen streams covering >= 1 s of `frames / covered s` | same / new (screen used to be inside `up_fps` / `down_fps`) |
| `share_active` | 1 if any screen stream (either direction) has packets in the bin | same / new |
| `session_age_s` | bin end minus the session's first packet, in seconds. Zoom: first **qualified media** packet | same / `session_age_ns` (last packet of the bin minus first packet, in ns) |

---

## 3. `session_metrics` fields that only Teams/Meet has

| Field | Definition / formula | Previously |
|---|---|---|
| `bytes_uplink`, `bytes_downlink` (int) | Σ UDP payload bytes per direction in the bin | `up_throughput`, `down_throughput` (bytes despite the name, with UDP header) |
| `rtp_loss_pct_<dir>` | **unchanged formula** (you chose no loss upgrade). Per SSRC (no direction in the key): `diff = seq - last_seq` (signed 16 bit). `diff > 1`: lost += min(diff - 1, 1000). `-100 < diff < 0`: one loss taken back. Then lost / (received + lost) x 100, all SSRCs of the direction pooled (audio + video) | `up_loss_pct`, `down_loss_pct` |
| `video_stream_bitrate_mean_<dir>_bps` | mean over the video streams that have an `fps` of 8 x payload bytes / 5 | downlink only: `video_bitrate_bps` |
| `bin_degraded` (bool) | old rule, unchanged: any Camera stream (gap-histogram classifier, both directions, >= 2 frames) with frames / 5 s < 15 | same name |
| `session_degradation_pct` | old rule: per Camera stream degraded bins / active bins x 100 since the session started, mean over the streams active now | same name |
| `camera_streams_active`, `camera_streams_degraded` (int) | the Camera streams judged by `bin_degraded` | `video_streams_active`, `video_streams_degraded` (renamed: these names now have Zoom's meaning, with a direction) |

Why the loss field is not `loss_pct_<dir>`: Zoom's `loss_pct_uplink` covers video streams only, and
on the downlink Zoom writes `seq_gap_pct_downlink`, because its server forwards a subset of frames
with the sender's numbering. The Teams/Meet number pools audio and video in both directions with
another rule. Same name, different quantity, is what the naming rule forbids. Example (the
synthetic call of the old METRICS.md): 7 of 450 downlink video packets missing. The stream line says
1.56 %; the pooled session line says 7 / (443 + 250 + 7) = 1.00 %.

---

## 4. Fields that only Zoom has

(Unchanged from `zoom_capture` p7b; full background in `claude/zoom_capture-p6-metrics-catalogue.md`.)

### 4.1 Volume groups: `<g>_bitrate_<dir>_bps` and `<g>_pps_<dir>`, formulas as in 2.1

| Group `<g>` | Contains |
|---|---|
| `screen13`, `screen30` | qualified screen streams of type 13 (sub-type 0x1e) and type 30 (`screen` = their sum) |
| `fec` | PT 110 of video and screen; a **subset** of `video` / `screen`, never added to them |
| `rtcp` | types 33, 34 |
| `type21` | type 21 (probe padding, never media) |
| `other` | any other SFU-headed type |
| `nohdr` | UDP payload without the 0x05 SFU header |
| `unq_video`, `unq_audio`, `unq_screen` | type 16 / 15 / 13+30 not in a qualified stream (`unq_media` = their sum + t13_*) |
| `t13_probe`, `t13_ctrl` | type 13 with media byte 7 = 0x15 (probe padding) / any other non-0x1e sub-type (control) |
| `nonmedia` | rtcp + other + nohdr |

### 4.2 Quality and capture floor

| Field | Definition / formula |
|---|---|
| `loss_pct_uplink`, `lost_pkts_uplink`, `expected_pkts_uplink` | video streams: reorder-aware bitmap loss (jump > 1000 = resync, late fill takes a loss back), lost / (rx + lost) x 100 |
| `seq_gap_pct_downlink`, `seq_gap_pkts_downlink`, `seq_expected_pkts_downlink` | the same arithmetic on the downlink, named "gap" (the server forwards a subset) |
| `fec_share_<dir>` | FEC bytes / video bytes |
| `audio_seq_gap_pct_<dir>` | audio sequence gaps (over-counts until type 7 is parsed) |
| `capture_missing_pct_uplink`, `capture_missing_pkts_uplink` | SFU counter (bytes 1-2) skipped values: what the **capture** missed |
| `sfu_gap_pct_downlink`, `sfu_gap_pkts_downlink` | the same on the downlink |

### 4.3 `client_no_media` and `session_summary`
* `client_no_media`: volume fields only (2.1 + 4.1), for a client bin without an open session. A
  session opens at the first qualified media packet.
* `session_summary`: `start_epoch_ns`, `end_epoch_ns`, `duration_s`, `bytes_uplink`, `bytes_downlink`,
  `bins`, `media_bins`, `video_bins`, `audio_bins`, `screen_bins`, `had_video`, `had_audio`,
  `had_screen`. The timestamp is the session start (an upsert).

---

## 5. `rtp_stream` (per SSRC and bin)

Tags: `client_ip`, `session_id`, `ssrc` (`0x%08X`, upper case for both engines), `stream_type`
(`video` / `audio` / `screen`), `direction` (`uplink` / `downlink`), `platform`, `pt`, and for Zoom
`type` (header type byte).

| Field | Zoom | Teams/Meet | Previously |
|---|---|---|---|
| `packets`, `bytes` (int) | packets, payload bytes | same | Teams/Meet `bytes` included the UDP header |
| `throughput_bps` | 8 x bytes / 5 | same | same |
| `fps` | frames / covered s, non-audio, cover >= 1 s | same, plus >= 1 cadence gap | Teams/Meet: frames / 5, `0.00` when not valid |
| `frame_gap_std_ms` | sigma of frame gaps (n >= 2) | same | **both**: `frame_jitter_ms` (renamed to match the session field) |
| `rfc3550_jitter_ms` | frame-level RFC 3550, value at bin end | same (new for Teams/Meet) | Zoom: same |
| `stalls`, `retransmits` (int) | as in 2.2, for this stream | same (new for Teams/Meet) | |
| `lost_packets`, `loss_pct` | Zoom bitmap loss (on a downlink stream this is a sequence gap) | — | Zoom: same |
| `rtp_lost_packets`, `rtp_loss_pct` | — | old per-stream rule, unchanged: `diff > 1` -> + (diff - 1), no cap, no late-packet credit | Teams/Meet: `lost_packets`, `loss_pct` |
| `qualified` (int 0/1) | — (Zoom writes qualified streams only) | 1 if the stream passed qualification | new |

Teams/Meet streams are keyed by (direction, SSRC). Before, the key was the SSRC alone and the
direction was fixed by the first packet. Meet sends a client its own uplink SSRC back on the
downlink (10.184.33.83, 2026-11-04). With the old key, the two were one stream.

---

## 6. `capture_health` and `capture_health_core`

All fields are cumulative counters since start, unless noted.

**`engine=teams_meet`** (`vc_pipeline/src/engine.rs::health_line`):

| Field | Meaning |
|---|---|
| `teams_udp`, `meet_udp` | UDP packets on the Teams / Meet address gate |
| `teams_rtp`, `meet_rtp`, `rtcp`, `stun`, `dtls`, `quic`, `unknown`, `rtp_short` | RFC 7983 demux outcome; `rtp_short` = RTP with fewer than 12 header bytes |
| `records_in`, `kept`, `dups_dropped`, `fp_evicted_live` | records into de-dup, kept, twins dropped, fp slot overwrites (the upper bound of missed twins) |
| `record_queue_drops`, `batch_drops` | lost to a full capture-to-records queue or session queue (must be 0) |
| `sessions_open` (gauge) | open client sessions |
| `csv_rows`, `csv_bytes`, `csv_files`, `csv_drop_limit` | Teams + Meet CSV parts; rows not written because the shared limit was reached |
| `pcap_pkts`, `pcap_bytes`, `pcap_files`, `pcap_drop_limit` | the same for the pcaps |
| `file_io_errors` | write errors |
| `capture_limit_tripped` (0/1), `capture_disk_bytes` | the **shared** budget: tripped, and bytes used by **all** platforms (the same value in both engines' points) |
| `export_writes_ok`, `export_writes_failed`, `export_lines_ok`, `export_lines_dropped` | InfluxDB writes (or file writes) |

**`engine=zoom`**: the 58 p7b fields, unchanged in meaning: gates (`pkts_in`, `parse_fail`,
`port_filtered`, `ip_filtered`, `zoom_like_unlisted`), de-dup (`dups_dropped`, `dup_ttl_*`,
`dup_id_same`), `matched`, the hub, the exporter, the RTP self-check (`rtp_ok_*`, `rtp_bad_*`,
`rtp_short`), video layouts and the files (`pcap_*`, `csv_*`, `capture_limit_tripped`,
`capture_disk_bytes`). One change: `capture_disk_bytes` is now the shared total.
`capture_health_core` gives `pkts_in` and `dups_dropped` per RX core.

---

## 7. Files

### 7.1 CSV (with `--csv`, after de-dup, rotating parts `_0001`, `_0002`, ...)

**`teams_record_NNNN.csv`, `meet_record_NNNN.csv`** (13 columns, unchanged from `capture_data`):
`arrival_epoch_ns, src_ip, dst_ip, ip_proto, ip_len, src_port, dst_port, udp_len, rtp_ssrc (0x%08X),
rtp_timestamp, rtp_seq, rtp_pt, rtp_marker`. Before: `teams_rtp_records.csv` / `meet_rtp_records.csv`,
one file.

**`zoom_record_NNNN.csv`** (27 columns, unchanged from p7b): `time_offset_s, udp_len, src_ip, dst_ip,
src_port, dst_port, dir, class, media_type_byte, sfu_seq, media_sequence, media_timestamp, frame_seq,
frame_pkt_count, ip_ttl, ip_id, dup, rtp_ssrc, rtp_timestamp, rtp_seq, rtp_pt, rtp_marker, rtp_ver_ok,
arrival_epoch_ns, core, media_b20, media_b7`. Change: twins are no longer written (`dup` is always 0).
Before: the `--packet-csv FILE` path, with parts named `NAME.2.csv`.

### 7.2 pcap (with `--pcap`, after de-dup, `--pcap-snaplen` bytes per packet, default 128)
`teams_record_NNNN.pcap`, `meet_record_NNNN.pcap`, `zoom_record_NNNN.pcap`: classic pcap, Ethernet,
microsecond timestamps, `orig_len` = the frame length on the wire. Teams/Meet frames carry the same
timestamp as their CSV row, so with `--dedup fp` PCAP frames = CSV rows. Before: Teams/Meet 1536 B,
**before** de-dup (both twins in the file); Zoom `zoom_<start>_NNNN.pcap`.

Why 128 B is enough to recompute every metric:
* **Teams/Meet:** the metrics read only addresses, ports, the UDP length field, the 12-byte RTP
  header and the arrival time. The `fp` fingerprint's 48 payload bytes end by byte 118 even with
  two VLAN tags and IPv6.
* **Zoom:** the deepest RTP header (+28 media offset) also ends by about byte 118.
* **Bytes:** these come from the UDP length field, so a 128-byte copy of a 1 080-byte Meet video
  packet still counts 1 072 payload bytes and is still video.

### 7.3 `run_info.txt` (always)
`key=value` lines, which `tools/check_dups.py` reads.
* **Start block:** program, start time (`started_unix`, `started_utc`), config, `dedup`,
  `dedup_compiled`, `csv`, `pcap`, `pcap_snaplen`, `capture_max_bytes`, `rotate_bytes`,
  `ssrc_lines`, `influx_zoom` and `influx_teams_meet` (target, no token), `iplist_<p>` (file or
  compiled-in), `iplist_<p>_fnv64` (hash of the list text), `iplist_<p>_ranges`, `zoom_ports`.
* **End block:** `finished_*`, `duration_s`, `final_capture_bytes`, `final_capture_limit_reached`,
  `final_zoom_*` (17 counters), `final_teams_meet_*` (31 counters).
* **Final console lines, verbatim:** `zoom_final_line=` (Zoom's `final:` line) and the Teams/Meet
  statistics block as `# ` lines.

---

## 8. Old name to new name

### 8.1 Teams/Meet (`teams_session_qoe` -> `session_metrics`)

| Old | New | Formula change |
|---|---|---|
| `up_throughput`, `down_throughput` | `bytes_uplink`, `bytes_downlink` | now integer; payload bytes (−8 B per packet) |
| `up_bps`, `down_bps` | `throughput_uplink_bps`, `throughput_downlink_bps` | payload bytes |
| `up_pps`, `down_pps` | `pps_uplink`, `pps_downlink` | none |
| `up_loss_pct`, `down_loss_pct` | `rtp_loss_pct_uplink`, `rtp_loss_pct_downlink` | none |
| `up_fps`, `down_fps` | `fps_uplink`, `fps_downlink` | frames / covered s (>= 1 s); qualified camera streams only; absent instead of 0.00 |
| `up_frame_jitter_ms`, `down_frame_jitter_ms` | `frame_gap_std_ms_uplink`, `frame_gap_std_ms_downlink` | pooled sigma, cadence gaps only |
| `video_bitrate_bps` | `video_stream_bitrate_mean_downlink_bps` (+ `_uplink`) | payload bytes |
| `video_total_bps` | `video_bitrate_downlink_bps` (+ `screen_bitrate_downlink_bps`) | by stream class, qualified only, payload bytes |
| `audio_bps` | `audio_bitrate_downlink_bps` | by stream class, qualified only, payload bytes |
| `video_streams_active`, `video_streams_degraded` | `camera_streams_active`, `camera_streams_degraded` | none |
| `bin_degraded`, `session_degradation_pct` | same | none |
| `session_age_ns` | `session_age_s` | bin end − first packet, seconds |
| — | `video_bitrate_uplink_bps`, `audio_bitrate_uplink_bps`, `screen_*`, `unq_media_*`, `*_pps_*`, `video_streams_active_*`, `video_frames_*`, `jitter_ms_*`, `stalls_*`, `retransmits_*`, `degraded_*`, `video_streams_degraded_*`, `audio_active_s_*`, `screen_streams_active_*`, `screen_frames_*`, `screen_fps_*`, `share_active`, `bin_cover_s` | new (ported from Zoom) |

`teams_rtp_stream` -> `rtp_stream`: `lost_packets` -> `rtp_lost_packets`, `loss_pct` -> `rtp_loss_pct`,
`frame_jitter_ms` -> `frame_gap_std_ms`. New fields: `rfc3550_jitter_ms`, `stalls`, `retransmits`,
`qualified`. `stream_type` can now also be `screen`.

### 8.2 Zoom
`zoom_rtp_stream` -> `rtp_stream`. `frame_jitter_ms` -> `frame_gap_std_ms` (per-stream line). `ssrc`
tag `0x%08x` -> `0x%08X`. `capture_health` and `capture_health_core` get the `engine=zoom` tag.
Byte counts come from the UDP length field (identical on live traffic). No field of
`session_metrics`, `client_no_media` or `session_summary` changed.

### 8.3 Environment and buckets
`TEAMS_QOE_INFLUX_URL/TOKEN` and `ZOOM_QOE_INFLUX_URL/TOKEN` -> **`VC_QOE_INFLUX_URL/TOKEN`** (one common
target), with optional `VC_QOE_ZOOM_*` / `VC_QOE_TEAMS_MEET_*` overrides (USAGE.md 6.3).

---

## 9. Worked examples (from the e2e test, `devtools/run_e2e.sh`)

**Throughput, Teams uplink.** 30 fps x 3 packets of `udp_len` 1 020, plus audio at 50 pkt/s with `udp_len` 160:
450 x 1 012 + 250 x 152 = 493 400 payload bytes per bin. 493 400 x 8 / 5 = **789 440** =
`throughput_uplink_bps` in the output. The old rule (with the UDP header) would have given 798 400.

**fps and degraded, Teams downlink.** 30 fps for 20 s, then 12 fps: `fps_downlink` 30.20, then 12.20,
and `degraded_downlink=1i`, `video_streams_degraded_downlink=1i` in the 12 fps bins.

**Stall and jitter, Meet downlink.** A 25 fps stream with one 400 ms gap at 10 s:
* The 10-15 s bin: `stalls_downlink=1i`, `frame_gap_std_ms_downlink=37.1`, `jitter_ms_downlink=7.50`.
* The neighbouring bins: 0, about 0.05 and about 0.03.
* By hand: frames 3 600 ticks (40 ms) apart that arrive 440 ms apart give D = 400 ms, so J jumps
  to about 400 / 16 = 25 ms. It then decays by 15/16 per normal frame (D close to 0).
  25 x (15/16)^n = 7.50 gives n = 18.7. So the stall fell about 19 frames (0.76 s) before the end
  of that bin; the replay started mid-bin, and Teams/Meet bins are epoch-aligned. Over the next full
  bin it decays back to the noise floor (0.055).

**RFC 3550 jitter, by hand.** Frames 3 000 ticks (33.33 ms) apart arriving 41.33 ms apart: D = 8 ms,
J1 = 8 / 16 = **0.5 ms** (unit test `rfc3550_jitter_follows_the_frame_level_rule`).

**Retransmit.** One Meet video packet repeated 150 ms later: kept by `fp` (outside the 10 ms window),
`retransmits_downlink=1i` in the 20-25 s bin, and one 150 ms repeat in `check_dups.py`.

---

## 10. Constants

| Constant | Value | Where |
|---|---|---|
| bin | 5 s | both |
| session timeout | 120 s | both |
| qualification | 20 packets, 90 % steps of 1..100, give up at 64 | `streams.rs`, Zoom `metrics.rs` |
| stall | frame gap > 200 ms | both |
| frame cadence | 1 500-90 000 ticks (60-1 fps at 90 kHz) | both |
| fps coverage / full bin / degraded | 1 s / 4 s / 15 fps | both |
| audio active second | > 20 packets | both |
| retransmit window | 128 sequence numbers | both |
| video size rule (Teams/Meet) | `udp_len > 400` | `streams.rs`, `degradation.rs` |
| old loss rule (Teams/Meet) | cap 1 000 per jump, late window 100 | `network_metrics.rs` |
| de-dup | 48 payload bytes, 10 ms, 16 384 slots | both |

---

## 11. Differences that remain, and quirks

1. **Classifier.** Zoom uses its header type; Teams/Meet uses the 400-byte rule. A Teams/Meet video
   frame made only of packets of 400 B or less is not seen (H3 in the handoff). Roadmap step 5
   (PT + clock rate) removes this.
2. **Throughput scope.** Zoom counts every packet on its gate (RTCP, probes, type 21). Teams/Meet
   counts RTP only.
3. **Bin alignment.** Teams/Meet bins are epoch-aligned, Zoom's are aligned to process start. The
   timestamps of the two engines differ by up to 5 s for the same wall-clock interval. Compare them
   over 1-minute windows, or use `aggregateWindow` in Grafana.
4. **Sessions.** A Zoom session starts at the first qualified media packet. A Teams/Meet session
   starts at its first RTP packet.
5. **`--dedup off` while the mirror still doubles packets.** Every twin is a repeat, so streams fail
   qualification: there are no `fps_*` / `video_*` values (everything is `unq_media_*`), Zoom writes
   only `client_no_media`, and `retransmits_*` counts the twins. Use `off` only once the mirror sends
   one copy. In the e2e test with twins and `off`, Teams `unq_media_pps_downlink` read 159-171.
6. **Partial bins.** Rates are divided by 5 s; `bin_cover_s` shows the coverage. `bin_degraded`
   (old rule, frames / 5 s) still flags partial first and last bins; `degraded_*` does not.
7. **fps fencepost.** frames / covered s reads about 0.7 % high in a full bin (30.20 for 30 fps).
8. **15 fps threshold.** Meet's own uplink runs at about 14.3 fps, so `degraded_uplink` and
   `bin_degraded` can be permanently 1 for Meet senders (H6 in the handoff).
