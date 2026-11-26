# vc_capture: usage guide (setup, build, test, run)

One Retina capture for **Zoom, Teams and Meet**. It replaces `zoom_capture` (p7b) and the Teams/Meet
`capture_data` (`runteameet.sh`). What every exported number means is in `docs/METRICS.md`.

```text
Retina "udp" callback, per RX core
  router: is src/dst in ip_lists/teams.txt or meet.txt?
    yes -> Teams/Meet engine (vc_pipeline): RFC 7983 demux -> records thread -> de-dup (fp|off)
             kept -> teams_/meet_record_NNNN.csv + .pcap -> session metrics -> InfluxDB
    no  -> Zoom engine (zoom_pipeline, unchanged): port 8801-8810/3478/3479 + ip_lists/zoom.txt
             -> de-dup (fp|off) -> kept -> zoom_record_NNNN.csv + .pcap -> metrics -> InfluxDB
all capture files share ONE size limit; both engines write to ONE InfluxDB target; run_info.txt at the end
```

Contents: 1 Layout · 2 Setup · 3 Build · 4 Test · 5 Run (all flags) · 6 InfluxDB · 7 Outputs and
tools · 8 Turning de-dup off · 9 Updating the IP lists · 10 Checks and troubleshooting ·
11 Old command to new command

---

## 1. Layout

```text
<retina root>/                      the Retina tree on the capture box (has core/, filtergen/, datatypes/)
  vc_combined/
    vc_capture/      the binary: src/main.rs, run.sh, config.toml (8 h), config.observe.toml (40 min), vc_qoe.env.example
    vc_pipeline/     Teams/Meet engine (library; tested without DPDK)
    zoom_pipeline/   Zoom engine (library; p7b with the vc_combined changes; tested without DPDK)
    ip_lists/        zoom.txt, teams.txt, meet.txt (one CIDR per line; also compiled into the binary)
    tools/           Python 3 tools (standard library only)
    docs/            USAGE.md (this file), METRICS.md, CHANGES.md
    devtools/        Retina stub + run_e2e.sh (test without DPDK; never copy the stub into the real tree)
```

---

## 2. Setup (once)

### 2.1 Put the folder into the Retina tree
```bash
cd /home/netmon/retina                     # your Retina root (it holds core/ and filtergen/)
unzip ~/vc_combined.zip                    # creates ./vc_combined
```
Add the binary to the Retina workspace, in the root `Cargo.toml`, `[workspace] members = [...]`:
```toml
members = [ ..., "vc_combined/vc_capture" ]
```
Why only `vc_capture`: `vc_pipeline` and `zoom_pipeline` are path dependencies inside the workspace
folder, so Cargo includes them automatically.

If you place `vc_combined` one level deeper, add one `../` to the three `retina-*` paths in
`vc_capture/Cargo.toml`. They must reach `core/`, `filtergen/` and `datatypes/`.

Toolchain: Rust >= 1.85 (edition 2024; the box already builds `capture_data`, which needs the same).
```bash
rustc --version
```

### 2.2 InfluxDB: one bucket, one write-only token
The setup in the old README (Docker `influxdb:2` on port 8087, org `teams`) stays. Then:
1. Create the bucket **`vc_qoe`** in org `teams`: Load Data -> Buckets -> Create Bucket.
2. Create a **custom API token** with **write** on `vc_qoe` only. Not "All Access": a token that
   leaks from a shared box should not be able to read or delete data.
3. Write the token into the env file (2.3). Never into a script, a chat or a ticket.

Why one bucket: you asked for one common target, and the measurement names are now shared across
the platforms (`session_metrics` with `platform=zoom|teams|meet`). One Grafana query can then show
all three. To separate them later, see 6.3.

### 2.3 The env file
```bash
cd vc_combined/vc_capture
cp vc_qoe.env.example vc_qoe.env && chmod 600 vc_qoe.env
nano vc_qoe.env           # set VC_QOE_INFLUX_URL (in double quotes!) and VC_QOE_INFLUX_TOKEN
```
The URL **must** be in double quotes. `run.sh` loads the file with the shell, and an unquoted `&`
silently cuts the URL at `&bucket=`.

### 2.4 Grafana
Data source: InfluxDB, query language **Flux**, URL `http://10.238.80.90:8087`, org `teams`,
default bucket `vc_qoe`, the read token. Example query: downlink fps of every client on all three
platforms:
```flux
from(bucket: "vc_qoe")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "session_metrics" and r._field == "fps_downlink")
  |> group(columns: ["platform", "client_ip"])
  |> aggregateWindow(every: 10s, fn: mean, createEmpty: false)
```
The old dashboards used `teams_session_qoe` / `up_fps` and so on. Rename them with the table in
METRICS.md section 8.

---

## 3. Build

On the capture box, from the Retina root:
```bash
cd /home/netmon/retina
cargo build --release -p vc_capture                         # -> target/release/vc_capture
cargo build --release -p vc_capture --no-default-features   # the same, WITHOUT any de-dup code (section 8)
cargo build -p vc_capture                                   # debug build (slow at runtime; smoke tests only)
target/release/vc_capture --help                            # every flag with its default
```
The `release` profile is the one in the Retina root `Cargo.toml`.

---

## 4. Test

### 4.1 Unit tests (no DPDK needed: the two engines are plain libraries)
```bash
cd /home/netmon/retina
cargo test --release -p zoom_pipeline                         # 142 unit + 6 HTTP tests
cargo test --release -p vc_pipeline                           # 30 tests (1 benchmark ignored)
cargo test --release -p zoom_pipeline --no-default-features   # 136 + 5: the build without de-dup
cargo test --release -p vc_pipeline --no-default-features     # 16
cargo test --release -p vc_pipeline -- --ignored --nocapture bench   # de-dup speed (ns per packet)
```
In the no-de-dup builds the tests that exercise de-dup are skipped (marked `#[cfg(feature = "dedup")]`),
and `built_without_the_dedup_feature_nothing_is_dropped` checks that a twin is kept.

### 4.2 Tools
```bash
cd vc_combined
python3 -I tools/test_check_dups.py            # 20 tests of check_dups.py
```

### 4.3 End to end without a NIC (any Linux machine with Rust and Python 3)
```bash
cd vc_combined
devtools/run_e2e.sh /tmp/vc_e2e                # about 3 minutes: build + two 40 s real-time runs
```
What it does:
1. Builds the binary against `devtools/retina_stub`, in its own folder. The stub has the same API
   as Retina, and its `Runtime::run` replays a pcap through the callback in real time on 4 threads.
2. Makes a synthetic Zoom call (`demo_capture`) plus Teams and Meet calls with twins
   (`tools/gen_e2e_traffic.py`).
3. Runs `--dedup fp` and `--dedup off` and checks each run with `tools/e2e_check.py`:
   * kept = unique packets (`fp`) or all packets (`off`);
   * CSV rows = pcap frames;
   * twins left in the CSVs <= `fp_evicted_live`. A slot collision can cost at most one missed twin;
     most runs miss 0, one run missed 2 of 19 278 with 10 overwrites;
   * `session_metrics` exists for all three platforms.

Expected last line of each check: `PASS`. You can also replay any classic pcap of your own:
```bash
RETINA_STUB_PCAP=/path/x.pcap /tmp/vc_e2e/ws/target/release/vc_capture \
   -c vc_combined/vc_capture/config.observe.toml -o /tmp/vc_e2e/myrun --csv --pcap --influx-file
```
A pcap written by `vc_capture` holds kept packets only, so replay it with `--dedup off`. The stub
paces by the pcap timestamps, so the 10 ms de-dup window and the fps clock behave as live.

---

## 5. Run

### 5.1 With `run.sh` (recommended)
```bash
cd /home/netmon/retina/vc_combined/vc_capture
./run.sh --dry                                     # 40 min, nothing to InfluxDB: line protocol -> files in the run folder
./run.sh                                           # 40 min, live to the InfluxDB target(s) in vc_qoe.env
./run.sh -c config.toml                            # 8 h production config
./run.sh --csv --pcap                              # + the six capture files (after de-dup, 128 B per packet)
./run.sh --csv --pcap --capture-max-mb 8000        # ... with ONE 8 GB limit for all of them together
./run.sh -o captures/meet_test_1 --csv --pcap      # choose the run folder
./run.sh --dedup off                               # once the mirror no longer doubles packets (section 8)
```
`Ctrl+C` stops the run cleanly: both engines flush, every file is closed, and `run_info.txt` gets
its end block. Before it starts, `run.sh` does four things:
* refuses to start if another capture (`vc_capture`, `capture_data`, `zoom_capture`, `rawcap*`) is
  running. The box is shared: never kill someone else's process; ask. `FORCE=1 ./run.sh` overrides;
* prints the hugepage and DPDK state;
* creates the run folder as **you**, not root, so you can delete it later;
* passes the token through `sudo -E` (environment), never on the command line.

`run.sh`'s own options: `--dry`, `-c/--config FILE`, `-o/--out-dir DIR`, `--ip-dir DIR` (default
`../ip_lists`), `--debug` (use `target/debug`). Everything else is passed to `vc_capture` unchanged.
Environment: `RETINA=/path` (if it guesses the Retina root wrong), `VC_QOE_ENV=/path/file` (another
env file), `FORCE=1`.

### 5.2 Direct call (what `run.sh` runs)
```bash
sudo -E env "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" target/release/vc_capture \
     -c vc_combined/vc_capture/config.observe.toml -o captures/run_x --ip-dir vc_combined/ip_lists --csv --pcap
```

### 5.3 Every flag of `vc_capture`

| Flag | Default | What it does |
|---|---|---|
| `-c, --config FILE` | required | Retina config. `config.toml` = 8 h, `config.observe.toml` = 40 min; same NIC `0000:05:00.0`, cores `[2,4,6,8]`, mempool 262 144 |
| `-o, --out-dir DIR` | `captures/run_<UTC yyyymmdd_HHMMSS>` | run folder; refused if it already holds `run_info.txt`, `*_record_*` or `influx_*` files (one folder = one run). **UTC**: 01:28 IST is `run_..._195835` of the previous day |
| `--dedup fp\|off` | `fp` (`off` without the `dedup` feature) | mirror-twin filter, both engines |
| `--csv` | off | write `teams_/meet_/zoom_record_NNNN.csv` |
| `--pcap` | off | write `teams_/meet_/zoom_record_NNNN.pcap` |
| `--pcap-snaplen BYTES` | 128 | bytes per packet in every pcap (64..9216). 128 = headers only, enough to recompute every metric. 1536 = whole frames, including users' encrypted media: decide first |
| `--capture-max-mb MB` | 10240 | ONE limit for all capture files together (CSV + pcap x 3 platforms). When reached, every capture file stops; metrics and InfluxDB go on. 0 = no limit. MB = 1 000 000 bytes |
| `--rotate-mb MB` | 256 | start part `_0002`, `_0003`, ... after this many MB |
| `--ip-dir DIR` | compiled-in lists | read `zoom.txt`, `teams.txt`, `meet.txt` from DIR (`run.sh` always passes `../ip_lists`) |
| `--ssrc-lines none\|teams-meet\|all` | `teams-meet` | per-SSRC `rtp_stream` points (the previous behaviour of both crates) |
| `--influx-file` | off | ignore the InfluxDB URL; write `influx_zoom.lp` / `influx_teams_meet.lp` in the run folder (`run.sh --dry`) |
| `--health-secs S` | 5 | status lines and `capture_health` points every S seconds |
| `--host NAME` | `/etc/hostname` | `host` tag of `capture_health` |
| `--zoom-shards N` | number of `cores` in the config | Zoom aggregation shards |
| `--zoom-max-streams N` | 65 536 | Zoom flows per shard |
| `--zoom-max-rtp-streams N` | 65 536 | Zoom RTP streams |
| `--zoom-channel-cap N` | 262 144 | Zoom capture-to-exporter queue |
| `--zoom-pcap-pool N` | 16 384 | Zoom packets that can wait for the pcap writer |
| `--vc-record-queue N` | 2 000 000 | Teams/Meet capture-to-records queue |

Memory, roughly: Teams/Meet queue 2 M records x about 150 B (+128 B per record with `--pcap`, only
while queued), Zoom pcap pool 16 384 x 144 B. The old `--pcap` of `capture_data` pre-touched 3.2 GB;
that queue is gone.

### 5.4 Size limit, with numbers
`--capture-max-mb 1000`. Twenty minutes in: Zoom has written 900 MB (pcap + CSV), Teams 99 MB, Meet
0.9 MB. The next write that would pass 1 000 000 000 bytes trips the limit, and from then on **no**
platform writes any file. The console shows `!! capture size limit reached`, and `run_info.txt`
records `final_capture_limit_reached=true`. Metrics are not affected.

This is the "summed" limit you chose. The trade-off: busy Zoom traffic can use up the space before
a quiet Meet call is written. If you need a Meet capture of a long run, keep the Zoom files small:
* use `--pcap` without `--csv` (the Zoom CSV is the biggest file);
* or raise the limit. For scale: at 128 B a packet costs at most 144 B in a pcap (16 B record header +
  128 B) instead of up to 1 552 B, and with `--dedup fp` only one copy of each twin is written. The
  25-minute 2026-11-04 Meet runs needed about 8 GB at 1536 B before de-dup (handoff section 6). The
  128 B, after-de-dup size of such a run has not been measured.

---

## 6. InfluxDB

### 6.1 One common target (the default)
`vc_qoe.env`:
```bash
VC_QOE_INFLUX_URL="http://10.238.80.90:8087/api/v2/write?org=teams&bucket=vc_qoe&precision=ns"
VC_QOE_INFLUX_TOKEN="..."
```
Both engines write there, each with its own writer thread. The start-up line shows both (no token):
```
[INFO] influx     : zoom -> http://...bucket=vc_qoe... (common target, token not shown)
[INFO]              teams/meet -> http://...bucket=vc_qoe... (common target, token not shown)
```

### 6.2 No target (dry run)
Without a URL, or with `--influx-file` / `run.sh --dry`, the line protocol goes to
`influx_zoom.lp` and `influx_teams_meet.lp` in the run folder. Load it later with
`influx write -b vc_qoe -f influx_zoom.lp`.

### 6.3 If the targets must be separated
Reasons to separate: different retention, a different team or organisation, or keeping Zoom's high
series count away from the thesis bucket. Each engine looks first for its own variables and falls
back to the common ones:

| Engine | URL | Token (falls back to `VC_QOE_INFLUX_TOKEN`) |
|---|---|---|
| Zoom | `VC_QOE_ZOOM_INFLUX_URL` | `VC_QOE_ZOOM_INFLUX_TOKEN` |
| Teams + Meet | `VC_QOE_TEAMS_MEET_INFLUX_URL` | `VC_QOE_TEAMS_MEET_INFLUX_TOKEN` |

Steps (example: Zoom into its own bucket `zoom_qoe`, Teams/Meet stay in `vc_qoe`):
1. In InfluxDB: create bucket `zoom_qoe` and a write-only token for it (2.2).
2. In `vc_qoe.env`, remove the `#` in front of:
   ```bash
   VC_QOE_ZOOM_INFLUX_URL="http://10.238.80.90:8087/api/v2/write?org=teams&bucket=zoom_qoe&precision=ns"
   VC_QOE_ZOOM_INFLUX_TOKEN="<the zoom_qoe token>"
   ```
   (Leave out the token line if the common token may also write `zoom_qoe`.)
3. Restart the capture. The start-up line now says `zoom -> ...bucket=zoom_qoe... (separate target)`,
   and `run_info.txt` records `influx_zoom=...`.
4. In Grafana, add a second data source for `zoom_qoe`, or use `union()` of two `from()` calls in one
   Flux query. The measurement and field names do not change, so the panels stay the same.

To separate all three platforms (Teams and Meet into different buckets), there is no setting: both
come from one engine. Filter by the `platform` tag in Grafana instead, or open a change request.
Example of what would be needed: a third pair of variables, and choosing the writer by
`platform_tag()` in `vc_pipeline/src/sessions/mod.rs`.

Checked in the e2e test with a mock InfluxDB, with only `VC_QOE_ZOOM_INFLUX_URL` set:
* every Zoom line (6 measurements) went to `bucket=zoom_only`, using the common token;
* every Teams/Meet line went to `bucket=vc_qoe`;
* the token appeared in no log and not in `run_info.txt`.

---

## 7. Outputs and tools

### 7.1 A run folder
```text
captures/run_20261106_101500/            (UTC)
  run_info.txt                           always: flags, IP-list hashes, end counters, final console lines
  teams_record_0001.csv  .pcap           --csv / --pcap; parts _0002 ... after --rotate-mb
  meet_record_0001.csv   .pcap
  zoom_record_0001.csv   .pcap
  influx_zoom.lp  influx_teams_meet.lp   only without an InfluxDB target
```
Everything in the CSVs and pcaps is **after de-dup** with `--dedup fp`, and everything is kept with
`--dedup off`.

### 7.2 Console
* Every 5 s, a `[zoom] [  15s] in=... zoom=... dups=... (50.0% of zoom) ...` line. Expect about 50 %
  dups on the doubled mirror, and 0 % once it is fixed.
* Every 15 s, `[teams/meet] rtp teams=... meet=... | kept=... dups=... | csv=... pcap=... | queue_drops=0 | influx ok=... fail=0`.
* At the end, the Zoom `final:` line, the Teams/Meet statistics block, and the total bytes of all
  capture files. The same lines are in `run_info.txt`.

### 7.3 Tools (Python 3, standard library; run with `-I`)
```bash
R=captures/run_20261106_101500
cat $R/run_info.txt                                                      # what ran and what was counted
python3 -I tools/check_dups.py $R                                        # twins/repeats left in the Teams/Meet CSV and pcap
python3 -I tools/csv_timeline_report.py $R/meet_record_0001.csv --client 10.184.4.232 --dump-fps fps.csv
python3 -I tools/csv_fps_check.py $R/teams_record_0001.csv --client 10.184.5.20
python3 -I tools/validate_rtp_csv.py $R/zoom_record_0001.csv --pcap $R   # Zoom RTP offsets, GO / NO-GO (later parts are picked up)
python3 -I tools/timeline_summary.py $R/zoom_record_0001.csv tl.csv --mark 10.184.4.232=tablet
cargo build --release -p zoom_pipeline --bins                            # once: builds replay_pcap, demo_capture, ...
target/release/replay_pcap --no-dedup --lp z.lp $R/zoom_record_0*.pcap   # Zoom pcap -> line protocol again
```
* **More than one part:** concatenate the CSVs with `head -1 a_0001.csv; tail -qn +2 a_0*.csv`, or
  pass the parts one by one.
* **Analysing what de-dup removed** (the replay `dedup_swallow_report.py --rule fp|seq` and the
  PCAP-vs-CSV reconciliation of `check_dups.py`): these need a capture that still holds the twins,
  and since `--pcap` is after de-dup (your decision) that means a `--dedup off` run. Example:
  ```bash
  python3 -I tools/dedup_swallow_report.py $R/meet_record_0001.pcap --rule seq --csv $R/meet_record_0001.csv
  ```
  This shows what `seq` would have done on the same traffic.
* `validate_rtp_csv.py` judged de-dup from the twin rows of the CSV. `vc_capture` no longer writes
  twin rows, so it now reports `de-dup FROM RUN_INFO` with the counters of `run_info.txt`
  (example: `15176 twins dropped = 50.0 % of Zoom packets`).
* `csv_timeline_report.py` and `dedup_swallow_report.py` print times in the local time of the
  machine that runs them (`TZ=Asia/Kolkata` for IST).

---

## 8. Turning de-dup off (once the campus network team fixes the mirror)

**Check first** that the twins are really gone. Run 10 minutes with `--dedup fp` and look at:
* the `[zoom] ... dups=...` share: it should go from ~50 % to ~0 %;
* the `dups_dropped` and `final_teams_meet_duplicates_dropped` counters in `run_info.txt`;
* the `dups_dropped` field of `capture_health` (both engines).

Why this matters: `--dedup off` on a doubled feed counts every packet twice, and every twin then
looks like a retransmission. Streams then fail qualification, so there are no `fps_*` values
(METRICS.md 11.5).

Two ways to switch it off, from cheapest to cleanest:
1. **Flag:** `./run.sh --dedup off ...`. Neither engine computes a fingerprint.
2. **One line at build time (removes the code):** in `vc_combined/vc_capture/Cargo.toml` change
   ```toml
   default = ["dedup"]
   ```
   to
   ```toml
   default = []
   ```
   and rebuild (`cargo build --release -p vc_capture`). The same effect without editing:
   `--no-default-features`. Every de-dup branch then becomes dead code that the compiler removes.
   `--dedup` defaults to `off`, and `--dedup fp` is refused at start-up with a clear message;
   `run_info.txt` records `dedup_compiled=false`.

To delete the source later: `vc_pipeline/src/dedup.rs` and the `dedup.check` call in
`channels/record.rs`, and in Zoom `zoom_pipeline/src/dedup.rs` and the `if let Some(d) = self.dedup`
block in `pipeline.rs::on_frame_at`.

---

## 9. Updating the IP lists

The lists are plain text in `vc_combined/ip_lists/`, one CIDR per line, with `#` comments and their
source and date. Policy (2026-11-06): **add** what the vendors publish, **remove nothing**.

| Platform | Source |
|---|---|
| Zoom | https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0060548 and https://assets.zoom.us/docs/ipranges/ZoomMeetings.txt |
| Teams | https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges (ID 11 = media, UDP 3478-3481) |
| Meet | https://support.google.com/a/answer/1279090 (step 3) |

1. Edit the file. `run.sh` reads `ip_lists/` at every start, so no rebuild is needed.
   Rebuild only to refresh the compiled-in fallback.
2. Start once with `--dry` and read the start-up line `[INFO] ip lists : zoom N ranges (.../zoom.txt), ...`.
   A typo stops the start with the line number. Overlapping lists are refused, because a packet
   must belong to one platform.
3. `run_info.txt` records the file used and its hash (`iplist_zoom_fnv64=...`), so every run says
   which list it ran with.

The early warning of a stale Zoom list: `zoom_like_unlisted` in Zoom's `capture_health`. It counts
packets that look like Zoom (SFU header) from an unlisted address. There is no such canary for
Teams/Meet: a short unfiltered `tcpdump` on a test client is the check.

---

## 10. Checks and troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| `[ERROR] ... already holds run_info.txt` | reused run folder | new `-o`, or let it default |
| `[ERROR] an InfluxDB URL is set for ZOOM but no token` | separated URL without any token | set `VC_QOE_INFLUX_TOKEN` or `VC_QOE_ZOOM_INFLUX_TOKEN` |
| `influx ... fail=` rising, `[WARN] [teams/meet] InfluxDB write failed` | wrong token, bucket missing, InfluxDB down | `curl --noproxy '*' "$VC_QOE_INFLUX_URL"` from the box (do not echo the token) |
| `dups` ~0 % on the `[zoom]` line while the mirror still doubles | `--dedup off`, or the capture point sees one leg only | check `dedup=` in `run_info.txt` |
| `queue_drops` > 0, or `bins_dropped` / `record_queue_drops` > 0 | a writer cannot keep up | raise `--vc-record-queue` / `--zoom-channel-cap`, check disk and CPU |
| `!! capture size limit reached` | the shared limit is used up | expected at the limit; raise `--capture-max-mb` or write fewer files |
| no `fps_downlink` for a client that has video | no qualified camera stream covered >= 1 s; frames <= 400 B; or video never reached the mirror | `video_streams_active_downlink`, `unq_media_pps_downlink` and `rtp_stream` with `qualified=0`; then `csv_timeline_report.py` |
| `zoom_like_unlisted` > 0 | Zoom uses an address that is not on the list | add the range (section 9) |
| build error `failed to load manifest ... core` | `vc_combined` is not directly under the Retina root | fix the three `retina-*` paths (2.1) |

Before trusting a run, check in `run_info.txt`:
* `final_teams_meet_record_queue_drops=0`, `final_teams_meet_batch_drops=0`;
* `final_zoom_bins_dropped=0`, `final_zoom_export_lines_dropped=0`;
* `final_teams_meet_influx_lines_dropped=0`;
* `final_capture_limit_reached=false` if you need complete files.

---

## 11. Old command to new command

| Before | Now |
|---|---|
| `./runteameet.sh --dry` | `./run.sh --dry` |
| `./runteameet.sh --csv --pcap --csv-max-mb 500 --pcap-max-mb 2000` | `./run.sh --csv --pcap --capture-max-mb 2500` (one limit for all files) |
| `--dedup seq` / `--dedup on` | removed (A/B offline: `dedup_swallow_report.py --rule seq` on a `--dedup off` capture) |
| `zoom_capture ... --no-dedup` | `--dedup off` |
| `zoom_capture ... --packet-csv FILE` | `--csv` (name fixed: `zoom_record_NNNN.csv`) |
| `zoom_capture ... --pcap-dir DIR` | `--pcap` (into the run folder) |
| `--pcap-rotate-mb N` | `--rotate-mb N` (all files) |
| `--capture-max-mb N` (Zoom files only) | `--capture-max-mb N` (all six kinds of file) |
| `--ip-list FILE` (Zoom) | `--ip-dir DIR` (zoom.txt, teams.txt, meet.txt) |
| `--ssrc-lines` (Zoom) | `--ssrc-lines all` |
| `--shards`, `--max-streams`, `--max-rtp-streams`, `--channel-cap`, `--pcap-pool` | the same with a `--zoom-` prefix |
| `TEAMS_QOE_INFLUX_URL/TOKEN`, `ZOOM_QOE_INFLUX_URL/TOKEN` | `VC_QOE_INFLUX_URL/TOKEN` (+ optional per-engine overrides, 6.3) |
| `teams_qoe.env`, `zoom_qoe.env` | `vc_qoe.env` |
