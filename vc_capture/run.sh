#!/usr/bin/env bash
# Run vc_capture: ONE capture for Zoom, Teams and Meet (replaces runteameet.sh and zoom_capture/run.sh).
#
#   ./run.sh --dry                     observe only: line protocol goes to files in the run folder, nothing to InfluxDB
#   ./run.sh                           live: InfluxDB target(s) from vc_qoe.env
#   ./run.sh -o captures/test1         choose the run folder (default captures/run_<UTC yyyymmdd_HHMMSS>)
#   ./run.sh -c config.toml            the 8-hour production config (default: config.observe.toml, 40 min)
#   ./run.sh --debug                   use target/debug instead of target/release (slow; smoke tests only)
#
# Every other option is passed to vc_capture unchanged, for example:
#   --csv --pcap                       write <platform>_record_NNNN.csv / .pcap (after de-dup)
#   --capture-max-mb 8000              ONE limit for all capture files together (default 10240; 0 = none)
#   --rotate-mb 256                    new part every N MB
#   --pcap-snaplen 128                 bytes per packet in the pcaps (default 128 = headers only)
#   --dedup off                        once the campus mirror sends one copy only (default fp)
#   --ssrc-lines none|teams-meet|all   per-SSRC rtp_stream points (default teams-meet)
#   --ip-dir DIR                       read zoom.txt / teams.txt / meet.txt from DIR (default: ./ip_lists next to this script)
# Full list: docs/USAGE.md section 5, or  <binary> --help
#
# Secrets: the token lives only in vc_qoe.env (chmod 600, never committed, see vc_qoe.env.example).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOP="$(cd "$HERE/.." && pwd)"                      # vc_combined/
find_retina() {                                     # nearest parent holding core/ and filtergen/
  local d="$TOP"
  while [ "$d" != "/" ]; do
    if [ -f "$d/core/Cargo.toml" ] && [ -d "$d/filtergen" ]; then echo "$d"; return; fi
    d="$(dirname "$d")"
  done
  echo "$TOP"
}
RETINA="${RETINA:-$(find_retina)}"
ENV_FILE="${VC_QOE_ENV:-$HERE/vc_qoe.env}"
CONFIG="$HERE/config.observe.toml"
PROFILE=release
DRY=0
OUT=""
IPDIR="$TOP/ip_lists"
EXTRA=()

while [ $# -gt 0 ]; do
  case "$1" in
    --dry)     DRY=1 ;;
    --debug)   PROFILE=debug ;;
    --release) PROFILE=release ;;
    -c|--config)  CONFIG="${2:?-c needs a file}"; shift ;;
    -o|--out-dir) OUT="${2:?-o needs a folder}"; shift ;;
    --ip-dir)     IPDIR="${2:?--ip-dir needs a folder}"; shift ;;
    -h|--help) awk 'NR>1 && /^set -euo/ {exit} NR>1 {print}' "$0"; exit 0 ;;
    *) EXTRA+=("$1") ;;
  esac
  shift
done

die() { echo "[run] ERROR: $*" >&2; exit 2; }

# ── 1. binary, config, ip lists ─────────────────────────────────────────────
BIN=""
for cand in "${CARGO_TARGET_DIR:-/nonexistent}/$PROFILE/vc_capture" "$RETINA/target/$PROFILE/vc_capture" "$TOP/target/$PROFILE/vc_capture"; do
  [ -x "$cand" ] && { BIN="$cand"; break; }
done
[ -n "$BIN" ] || die "no $PROFILE build found. Build it first:  cd $RETINA && cargo build --release -p vc_capture"
[ -f "$CONFIG" ] || die "config not found: $CONFIG"
[ -d "$IPDIR" ] || die "ip list folder not found: $IPDIR"
echo "[run] binary : $BIN"
echo "[run] config : $CONFIG  ($(grep -E '^\s*duration' "$CONFIG" | head -1 | tr -s ' ' | sed 's/^ //'))"
echo "[run] ip     : $IPDIR"

# ── 2. InfluxDB settings (or --dry) ─────────────────────────────────────────
if [ "$DRY" -eq 1 ]; then
  unset VC_QOE_INFLUX_URL VC_QOE_INFLUX_TOKEN VC_QOE_ZOOM_INFLUX_URL VC_QOE_ZOOM_INFLUX_TOKEN VC_QOE_TEAMS_MEET_INFLUX_URL VC_QOE_TEAMS_MEET_INFLUX_TOKEN
  EXTRA+=("--influx-file")
  echo "[run] mode   : DRY. Line protocol goes to influx_zoom.lp and influx_teams_meet.lp in the run folder."
else
  [ -f "$ENV_FILE" ] || die "$ENV_FILE not found. Copy vc_qoe.env.example to it, put the write-only token in, chmod 600.  (or use --dry)"
  perm="$(stat -c %a "$ENV_FILE")"
  case "$perm" in *00) ;; *) echo "[run] WARNING: $ENV_FILE is mode $perm; run: chmod 600 $ENV_FILE" >&2 ;; esac
  set -a; . "$ENV_FILE"; set +a
  [ -n "${VC_QOE_INFLUX_URL:-}" ]   || die "VC_QOE_INFLUX_URL is missing or empty in $ENV_FILE (is the URL in double quotes? an unquoted & drops the rest)"
  [ -n "${VC_QOE_INFLUX_TOKEN:-}" ] || die "VC_QOE_INFLUX_TOKEN is empty in $ENV_FILE"
  for u in "${VC_QOE_INFLUX_URL:-}" "${VC_QOE_ZOOM_INFLUX_URL:-}" "${VC_QOE_TEAMS_MEET_INFLUX_URL:-}"; do
    [ -z "$u" ] && continue
    case "$u" in *"org="*"bucket="*) ;; *) die "InfluxDB URL without org= and bucket= (quotes?): $u" ;; esac
  done
  echo "[run] mode   : LIVE -> $VC_QOE_INFLUX_URL   (token not shown)"
  [ -n "${VC_QOE_ZOOM_INFLUX_URL:-}" ] && echo "[run]          Zoom separated -> $VC_QOE_ZOOM_INFLUX_URL"
  [ -n "${VC_QOE_TEAMS_MEET_INFLUX_URL:-}" ] && echo "[run]          Teams/Meet separated -> $VC_QOE_TEAMS_MEET_INFLUX_URL"
  export VC_QOE_INFLUX_URL VC_QOE_INFLUX_TOKEN
  [ -n "${VC_QOE_ZOOM_INFLUX_URL:-}" ] && export VC_QOE_ZOOM_INFLUX_URL
  [ -n "${VC_QOE_ZOOM_INFLUX_TOKEN:-}" ] && export VC_QOE_ZOOM_INFLUX_TOKEN
  [ -n "${VC_QOE_TEAMS_MEET_INFLUX_URL:-}" ] && export VC_QOE_TEAMS_MEET_INFLUX_URL
  [ -n "${VC_QOE_TEAMS_MEET_INFLUX_TOKEN:-}" ] && export VC_QOE_TEAMS_MEET_INFLUX_TOKEN
fi

# ── 3. is the NIC / hugepage pool already in use? (shared box: never kill someone else's process)
busy="$(ps -eo pid=,user=,etime=,comm=,args= | awk '$4 ~ /^(vc_capture|capture_data|zoom_capture|dup_capture|rawcap.*|video_conferenc.*)$/ {print}' | cut -c1-150 || true)"
if [ -n "$busy" ] && [ "${FORCE:-0}" != "1" ]; then
  echo "[run] A capture program already appears to be running (pid user elapsed name args):" >&2
  echo "$busy" | sed 's/^/        /' >&2
  die "not starting. If it is yours and finished, stop it; if it is someone else's, ask them. (FORCE=1 overrides.)"
fi
grep -E 'HugePages_(Total|Free)' /proc/meminfo | tr -s ' ' | sed 's/^/[run] /'
ls /var/run/dpdk 2>/dev/null | sed 's/^/[run] DPDK file-prefix in use: /' || true

# ── 4. run folder: made by YOU (not root) so you can delete it later ───────
[ -n "$OUT" ] || OUT="$HERE/captures/run_$(date -u +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
echo "[run] output : $OUT"
echo "[run] flags  : ${EXTRA[*]:-(none: no CSV, no PCAP, dedup fp)}"
echo "[run] starting. Ctrl+C stops the run cleanly and flushes the files."

# sudo -E keeps the VC_QOE_* variables (so the token is never on a command line)
exec sudo -E env "LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}" "$BIN" -c "$CONFIG" -o "$OUT" --ip-dir "$IPDIR" ${EXTRA[@]+"${EXTRA[@]}"}
