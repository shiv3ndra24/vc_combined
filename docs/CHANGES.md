# vc_combined: change sets (2026-11-06)

Sources: `zoom_campus_p7b.zip` (`zoom_pipeline`, `zoom_capture`) and `Video_Conferencing_run.zip`
(`services/capture_data`). Decisions are in the project doc `claude/combined-pipeline-design-proposal.md`
(section 8). Each change below gives its reason and the test that covers it.

## V1. One binary, a router in the callback (structure P1)
* **What.** `vc_capture/src/main.rs`: one `#[filter("udp")]` callback. `vc_pipeline::engine::try_take`
  takes Teams/Meet packets, and every other packet goes to the unchanged `zoom_pipeline::Pipeline::on_frame`.
* **Why.** The user chose P1: both engines stay the code they were validated as. Teams/Meet goes
  first because the three lists are disjoint (checked at start-up), so the order changes no result.
  Zoom keeps seeing all other UDP, so its `ip_filtered` / `port_filtered` / `zoom_like_unlisted`
  keep their meaning.
* **Test.** e2e: Zoom `pkts_in=30560` = every non-Teams/Meet frame of the 69 116.

## V2. Teams/Meet crate turned into a library (`vc_pipeline`)
* **What.** `main.rs` (callback, counters, statistics) moved to `engine.rs`. `channels/packet.rs`
  (the pcap writer before de-dup) was removed.
* **Why.** It can be tested without DPDK, as `zoom_pipeline` is. The Retina macros must stay in the
  binary.
* **Test.** `cargo test -p vc_pipeline`: 30 tests.

## V3. De-dup: `fp` default, `seq` removed, feature `dedup` (steps 1 and 4)
* **What.**
  * `--dedup fp|off` drives both engines.
  * `vc_pipeline/src/dedup.rs` keeps the `fp` table and its tests; `seq` and its tests are gone.
  * A cargo feature `dedup` exists in all three crates; `default = []` in `vc_capture/Cargo.toml`
    compiles it out.
  * Zoom: `cfg.dedup && DEDUP_COMPILED`.
* **Why.** De-dup is temporary until the mirror is fixed: a flag or one line switches it off. `seq`
  swallowed genuine packets (213 s of downlink video, run 195835), and the A/B stays possible offline.
* **Test.** Unit tests in both builds; the default build refuses nothing, and the no-de-dup build
  refuses `--dedup fp`; e2e `fp` and `off` runs.

## V4. CSV and pcap after de-dup, for all three platforms (step 4)
* **What.**
  * Teams/Meet: the first `snaplen` bytes of a frame travel with its record (only with `--pcap`).
    The records thread writes CSV row and pcap frame **after** the verdict, with the same timestamp.
  * Zoom: a twin returns before the debug-CSV dump (it used to be written with `dup=1`).
* **Why.** The user's rule: dedup on, both files after de-dup; dedup off, both files hold everything.
* **Test.**
  * e2e `fp`: Teams/Meet 19 278 kept = CSV rows = pcap frames, and 0 twins left
    (`e2e_check.py`, `check_dups.py`); Zoom CSV 15 184 = pcap 15 184.
  * e2e `off`: 38 556 / 30 360, everything doubled.
  * Updated Zoom tests: `a_twin_received_on_a_different_core_is_still_removed`,
    `dump_rows_carry_the_inner_rtp_fields_and_twins_are_not_dumped`.

## V5. Snaplen 128 B for all pcaps (`--pcap-snaplen`)
* **Why.** The user's condition: every metric must be recomputable from headers. Checked:
  * Teams/Meet metrics read addresses, ports, `udp_len` and the RTP header (by byte 118 worst case);
  * Zoom's deepest RTP header ends by byte ~118.
* **Side change (Z2).** Zoom counts bytes as `udp_len - 8` instead of the bytes held. This is
  identical on live traffic, and replays of 128 B pcaps then keep the bitrates right (p7b's
  `replay_pcap` doc warned they did not).
* **Test.** All Zoom tests unchanged and green; e2e Zoom `throughput_downlink_bps` normal.

## V6. One size limit summed over all platforms and both file kinds (D8)
* **What.**
  * One `zoom_pipeline::capture_files::DiskBudget`, used by Zoom through
    `Pipeline::with_start_budget` and `FileCtx::with_budget`, and by Teams/Meet through the
    `files::ByteBudget` trait.
  * `--capture-max-mb` (default 10 240), `--rotate-mb` (default 256) for every file.
  * Names `<platform>_record_NNNN.{csv,pcap}`.
* **Test.**
  * e2e with `--capture-max-mb 3`: 2 999 931 of 3 000 000 bytes, every file stopped, metrics complete.
  * e2e with `--rotate-mb 1`: parts `_0002`/`_0003` for each kind.
  * Unit tests `rotates_with_a_header_in_every_part_and_respects_the_shared_limit`, `csv_name` cases.

## V7. IP lists in three files, one list per platform used by gate AND metrics (step 2, D9)
* **What.** `ip_lists/{zoom,teams,meet}.txt`, read with `--ip-dir`, compiled in as the fallback.
  * Teams/Meet: `ip_ranges.rs::IpTable` (binary search). The gate decides the direction
    (`RtpRecord::uplink`), and the text-prefix lists in `network_metrics.rs` are gone.
  * Policy: add new, remove nothing. Zoom added `3.235.96.26/31`, `3.235.96.158/31`,
    `69.174.110.0/23` (inside old ranges: no effect) and UDP ports 3478/3479.
  * Teams: ID 11 = old list; the ID 12 IPv6 prefixes are kept. The old metrics-only `2603:1010`
    prefix is listed but commented out, because it never admitted a packet.
  * Meet: unchanged.
* **Why.** One list per platform cannot drift (the old `2603:1063` bug).
* **Test.** `builtin_lists_parse_and_hold_the_published_ranges` (with the /38 boundary),
  `overlapping_lists_are_refused`, `precheck_gives_platform_and_direction`; start-up refuses a Zoom
  range inside Teams/Meet.

## V8. Metrics ported to Teams/Meet, common names (step 3, D7)
* **What.** `sessions/streams.rs`: per (direction, SSRC):
  * qualification;
  * volume split video / audio / screen / unq_media per direction;
  * frames, fps over covered time;
  * pooled frame-gap sigma;
  * frame-level RFC 3550 jitter;
  * stalls, retransmits (128-bit repeat detector);
  * degraded / video_streams_degraded per direction;
  * audio-active seconds;
  * screen streams.

  Same rules as Zoom's `metrics.rs` / `export.rs`, and the same field names
  (47 shared `session_metrics` fields, checked on the e2e output). Measurements are `session_metrics`
  and `rtp_stream` for both. Undefined fields are omitted.
* **Not changed (user decision).** The loss formula (now `rtp_loss_pct_*` / `rtp_lost_packets`),
  `bin_degraded` / `session_degradation_pct`.
* **Renamed.** See METRICS.md section 8.
* **Test.** 7 unit tests in `streams.rs` (30 fps, RFC 3550 step by hand, stall, retransmit + old
  loss, probe never qualifies, audio-active seconds, same SSRC in two directions). e2e values: Teams
  789 440 bps uplink checked by hand; 30.2 then 12.2 fps with `degraded_downlink=1`; Meet stall in
  the 10 s bin; the retransmit in the 20 s bin; the probe only in `unq_media`.

## V9. One InfluxDB target, optional per-engine overrides (D7)
* **What.** `VC_QOE_INFLUX_URL/TOKEN` for both engines, with optional `VC_QOE_ZOOM_*` /
  `VC_QOE_TEAMS_MEET_*`. No URL: `influx_zoom.lp` / `influx_teams_meet.lp`. Zoom `capture_health`
  gets `engine=zoom`; Teams/Meet gets its own `capture_health` with `engine=teams_meet`.
* **Test.** Mock InfluxDB: routing by bucket, token header, and no token in the logs or `run_info.txt`.

## V10. `run_info.txt` for the whole run (step 5)
* **What.** Start block (flags, list sources + FNV-64 hashes, Influx targets without token); end
  block (`final_zoom_*`, `final_teams_meet_*`, shared byte total); the final console lines verbatim.
* **Test.** e2e; `check_dups.py` reads it (`dedup=fp`).

## V11. Two shutdown fixes found by the e2e test
* **Zoom.** The pcap writers stopped on the same flag as the sweeper, so they could exit before
  `pipe.shutdown()` handed over each core's partial batch. The e2e showed `pcap_drop_queue=37`
  (the same order as `zoom_capture`). Now a separate `files_stop` is set after `shutdown()`.
  Result: pcap 15 184 = CSV 15 184.
* **Teams/Meet.** The last `capture_health` line was pushed after the session layer had already
  stopped the Influx writer (`influx lines 1` dropped). Now the records thread no longer stops the
  session layer; `engine::stop` does it after the last health line. Result: 0 dropped, and the final
  health line carries the final counters.

## V12. Tools
* `check_dups.py` finds `teams_/meet_record_NNNN.*` in a run folder (its 20 self-tests pass).
* `validate_rtp_csv.py` picks up `zoom_record_0002.csv` ... and reports `de-dup FROM RUN_INFO` instead
  of `NO DATA`.
* New: `gen_e2e_traffic.py`, `e2e_check.py`, `devtools/run_e2e.sh` + `devtools/retina_stub`.

## Not checked
* The real Retina build. The binary compiles and runs against a stub with the same API; the API
  calls are the ones both crates already used on the box. `[[online.ports]]` and the DPDK options are
  read by the real Retina only.
* Any metric on real campus traffic.
* `fp` on real Teams/Meet traffic: the first runs of this binary are that test (handoff section 2).
* CPU cost at campus rate of the Teams/Meet records thread with `--pcap` (one 128 B allocation per
  RTP packet).

## Tempting but not done
* Removing the two `String` allocations per RTP packet in `parse_rtp_record`: a separate change
  set, since it changes the record type every module uses.
* Epoch-aligning Zoom's bins: changes Zoom's exporter; roadmap "shared core".
* PT + clock-rate classifier instead of the 400-byte rule (roadmap step 5).
* A port gate for Teams/Meet: could only remove traffic.
* Separate Influx targets for Teams and Meet: they are one engine; filter by `platform`.
* Putting `rtp_loss_pct` on Zoom's bitmap rule: declined by the user (loss upgrade).
