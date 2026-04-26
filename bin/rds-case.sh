#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  rds-case.sh --host HOST --port PORT [--duration SECONDS] [--attempts N] [--iface IFACE] [--outdir DIR]

Creates a timestamped evidence bundle for RDS connectivity timeout analysis.
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

HOST=""
PORT=""
DURATION=60
ATTEMPTS=5
IFACE="any"
OUTDIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --duration) DURATION="${2:-}"; shift 2 ;;
    --attempts) ATTEMPTS="${2:-}"; shift 2 ;;
    --iface) IFACE="${2:-}"; shift 2 ;;
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

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SAFE_HOST="$(printf '%s' "$HOST" | tr -c 'A-Za-z0-9._-' '_')"
OUTDIR="${OUTDIR:-cases/${STAMP}-${SAFE_HOST}-${PORT}}"
mkdir -p "$OUTDIR"

echo "Writing case data to ${OUTDIR}"
"${ROOT_DIR}/bin/rds-probe.sh" \
  --host "$HOST" \
  --port "$PORT" \
  --attempts "$ATTEMPTS" \
  --outdir "$OUTDIR"

"${ROOT_DIR}/bin/rds-capture.sh" \
  --host "$HOST" \
  --port "$PORT" \
  --duration "$DURATION" \
  --iface "$IFACE" \
  --outdir "$OUTDIR"

echo "Case bundle complete: ${OUTDIR}"
echo "Optional summary:"
echo "  ${ROOT_DIR}/bin/rds-pcap-summary.sh ${OUTDIR}/capture-*.pcap"
