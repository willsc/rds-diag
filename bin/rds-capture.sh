#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  rds-capture.sh --host HOST --port PORT [--duration SECONDS] [--iface IFACE] [--snaplen BYTES] [--outdir DIR]

Captures packets between this Linux host and the resolved IPs for the RDS endpoint.

Examples:
  sudo ./bin/rds-capture.sh --host db.example.ap-southeast-1.rds.amazonaws.com --port 5432
  sudo ./bin/rds-capture.sh --host db.example.ap-southeast-1.rds.amazonaws.com --port 3306 --duration 120
EOF
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must run as root because tcpdump typically requires elevated privileges." >&2
    exit 1
  fi
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

resolve_ips() {
  local host="$1"
  if command -v getent >/dev/null 2>&1; then
    getent ahostsv4 "$host" | awk '{print $1}' | sort -u
    return 0
  fi
  if command -v dig >/dev/null 2>&1; then
    dig +short A "$host" | awk 'NF' | sort -u
    return 0
  fi
  if command -v host >/dev/null 2>&1; then
    host "$host" | awk '/has address/ {print $4}' | sort -u
    return 0
  fi
  echo "Unable to resolve host: install getent, dig, or host." >&2
  exit 1
}

HOST=""
PORT=""
DURATION=60
IFACE="any"
SNAPLEN=0
OUTDIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --duration) DURATION="${2:-}"; shift 2 ;;
    --iface) IFACE="${2:-}"; shift 2 ;;
    --snaplen) SNAPLEN="${2:-}"; shift 2 ;;
    --outdir) OUTDIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$HOST" || -z "$PORT" ]]; then
  usage
  exit 1
fi

need_root
require_cmd tcpdump

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SAFE_HOST="$(printf '%s' "$HOST" | tr -c 'A-Za-z0-9._-' '_')"
OUTDIR="${OUTDIR:-captures/${STAMP}-${SAFE_HOST}-${PORT}}"
mkdir -p "$OUTDIR"

mapfile -t IPS < <(resolve_ips "$HOST")
if [[ "${#IPS[@]}" -eq 0 ]]; then
  echo "No IPv4 addresses resolved for $HOST" >&2
  exit 1
fi

FILTER="tcp port ${PORT} and ("
for ip in "${IPS[@]}"; do
  FILTER+="host ${ip} or "
done
FILTER="${FILTER% or }"
FILTER+=")"

PCAP="${OUTDIR}/capture-${STAMP}.pcap"
META="${OUTDIR}/capture-${STAMP}.txt"
DECODE="${OUTDIR}/capture-${STAMP}.decoded.txt"
SUMMARY="${OUTDIR}/capture-${STAMP}.summary.txt"

{
  echo "timestamp_utc=${STAMP}"
  echo "host=${HOST}"
  echo "port=${PORT}"
  echo "iface=${IFACE}"
  echo "snaplen=${SNAPLEN}"
  echo "duration_seconds=${DURATION}"
  echo "resolved_ips=${IPS[*]}"
  echo "tcpdump_filter=${FILTER}"
} | tee "$META"

echo "Starting capture: ${PCAP}"
timeout "${DURATION}" tcpdump -i "$IFACE" -nn -U -B 4096 -s "$SNAPLEN" -w "$PCAP" "$FILTER" || true
echo "Capture finished: ${PCAP}"

{
  echo "### tcpdump summary"
  tcpdump -nn -r "$PCAP" -q 2>/dev/null | sed -n '1,200p' || true
} >"$SUMMARY"

{
  echo "### verbose decode"
  tcpdump -nn -tttt -vvv -S -x -r "$PCAP" 2>/dev/null | sed -n '1,400p' || true
} >"$DECODE"

echo "Wrote summary: ${SUMMARY}"
echo "Wrote verbose decode: ${DECODE}"
