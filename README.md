# vc_combined: one capture for Zoom, Teams and Meet

`vc_capture` is one Retina binary. A router in the capture callback hands every UDP packet to the
Teams/Meet engine (`vc_pipeline`) or to the Zoom engine (`zoom_pipeline`). Each engine keeps its own
rules. They share:
* one CLI;
* one run folder;
* one de-dup switch (`--dedup fp|off`, or the cargo feature `dedup`);
* one size limit for all capture files;
* one InfluxDB target;
* one `run_info.txt`.

```bash
cd <retina root> && cargo build --release -p vc_capture            # after adding "vc_combined/vc_capture" to the workspace
cd vc_combined/vc_capture && ./run.sh --dry --csv --pcap          # 40 min, no InfluxDB, all files
```

* `docs/USAGE.md`: setup, build, test, run, every flag, InfluxDB (and how to separate targets).
* `docs/METRICS.md`: every measurement and field, its formula, and its previous name.
* `docs/CHANGES.md`: what changed against `zoom_capture` p7b and `capture_data`, why, and how it was tested.
* `devtools/run_e2e.sh`: end-to-end test without DPDK.
