#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  rds-pcap-summary.sh CAPTURE.pcap

Prints a quick summary of TCP handshake behavior from a packet capture.
EOF
}

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

PCAP="$1"

if [[ ! -f "$PCAP" ]]; then
  echo "Capture not found: $PCAP" >&2
  exit 1
fi

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "Missing required command: tcpdump" >&2
  exit 1
fi

TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

tcpdump -nn -tttt -r "$PCAP" 'tcp' >"$TMP_FILE" 2>/dev/null || true

echo "Capture: $PCAP"
echo
echo "Flag counts:"
printf 'SYN: '
grep -c 'Flags \[S\]' "$TMP_FILE" || true
printf 'SYN-ACK: '
grep -c 'Flags \[S\.\]' "$TMP_FILE" || true
printf 'ACK: '
grep -c 'Flags \[\.\]' "$TMP_FILE" || true
printf 'RST: '
grep -c 'Flags \[R\]' "$TMP_FILE" || true
printf 'RST-ACK: '
grep -c 'Flags \[R\.\]' "$TMP_FILE" || true
printf 'FIN: '
grep -c 'Flags \[F\.\]' "$TMP_FILE" || true
printf 'PSH-ACK: '
grep -c 'Flags \[P\.\]' "$TMP_FILE" || true

echo
echo "Handshake tuples:"
awk '
/Flags \[S\]/ && $3 ~ />/ {
  src=$3; dst=$5;
  gsub(/:$/, "", dst);
  syn[src "->" dst]++
}
/Flags \[S\.\]/ && $3 ~ />/ {
  src=$3; dst=$5;
  gsub(/:$/, "", dst);
  synack[src "->" dst]++
}
/Flags \[R/ && $3 ~ />/ {
  src=$3; dst=$5;
  gsub(/:$/, "", dst);
  rst[src "->" dst]++
}
END {
  print "SYN tuples:"
  for (k in syn) print syn[k], k
  print ""
  print "SYN-ACK tuples:"
  for (k in synack) print synack[k], k
  print ""
  print "RST tuples:"
  for (k in rst) print rst[k], k
}
' "$TMP_FILE"

echo
echo "First 40 TCP packets:"
sed -n '1,40p' "$TMP_FILE"

echo
echo "Interpretation:"
SYN_COUNT="$(grep -c 'Flags \[S\]' "$TMP_FILE" || true)"
SYNACK_COUNT="$(grep -c 'Flags \[S\.\]' "$TMP_FILE" || true)"
RST_COUNT="$(grep -c 'Flags \[R\]' "$TMP_FILE" || true)"

if [[ "$SYN_COUNT" -gt 0 && "$SYNACK_COUNT" -eq 0 ]]; then
  echo "Outbound SYNs were seen without SYN-ACK replies. This usually indicates packet loss, filtering, or routing issues upstream of the client."
elif [[ "$SYNACK_COUNT" -gt 0 && "$RST_COUNT" -gt 0 ]]; then
  echo "The remote side or an intermediary is actively resetting connections."
elif [[ "$SYNACK_COUNT" -gt 0 ]]; then
  echo "The TCP handshake is at least partially succeeding. Focus next on TLS, authentication, engine response, or application timeouts."
else
  echo "No clear TCP handshake pattern was detected from this filtered capture."
fi
