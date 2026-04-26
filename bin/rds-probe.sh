#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  rds-probe.sh --host HOST --port PORT [--attempts N] [--connect-timeout SECONDS] [--iface IFACE] [--outdir DIR]

Runs repeatable client-side diagnostics for an RDS endpoint.
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    return 1
  fi
}

discover_interfaces() {
  if require_cmd ip; then
    ip -o link show | awk -F': ' '{print $2}' | awk '$1 != "lo" {print $1}'
    return 0
  fi
  return 1
}

discover_source_ip() {
  local ip="$1"
  if require_cmd ip; then
    ip route get "$ip" 2>/dev/null | awk '
      {
        for (i = 1; i <= NF; i++) {
          if ($i == "src") {
            print $(i + 1)
            exit
          }
        }
      }
    '
    return 0
  fi
  return 1
}

resolve_ips() {
  local host="$1"
  if require_cmd getent; then
    getent ahostsv4 "$host" | awk '{print $1}' | sort -u
    return 0
  fi
  if require_cmd dig; then
    dig +short A "$host" | awk 'NF' | sort -u
    return 0
  fi
  if require_cmd host; then
    host "$host" | awk '/has address/ {print $4}' | sort -u
    return 0
  fi
  echo "Unable to resolve host: install getent, dig, or host." >&2
  exit 1
}

run_if_present() {
  local logfile="$1"
  shift
  if require_cmd "$1"; then
    "$@" >>"$logfile" 2>&1 || true
  else
    echo "SKIP: missing command: $1" >>"$logfile"
  fi
}

probe_tcp() {
  local host="$1"
  local port="$2"
  local timeout_s="$3"
  local logfile="$4"

  if require_cmd nc; then
    timeout "$timeout_s" nc -vz "$host" "$port" >>"$logfile" 2>&1 || true
    return 0
  fi

  if require_cmd bash && require_cmd timeout; then
    timeout "$timeout_s" bash -c "exec 3<>/dev/tcp/${host}/${port}" >>"$logfile" 2>&1 || true
    return 0
  fi

  echo "SKIP: neither nc nor timeout/bash /dev/tcp probe available" >>"$logfile"
}

run_section() {
  local logfile="$1"
  local title="$2"
  shift 2
  {
    echo "### ${title}"
    "$@" 2>&1 || true
    echo
  } >>"$logfile"
}

maybe_tcp_traceroute() {
  local ip="$1"
  local port="$2"
  local logfile="$3"

  if require_cmd traceroute; then
    run_section "$logfile" "traceroute -n -T -p ${port} ${ip}" traceroute -n -T -p "$port" "$ip"
    return 0
  fi

  if require_cmd tcptraceroute; then
    run_section "$logfile" "tcptraceroute ${ip} ${port}" tcptraceroute "$ip" "$port"
    return 0
  fi

  echo "SKIP: missing traceroute/tcptraceroute" >>"$logfile"
}

maybe_syn_probe() {
  local ip="$1"
  local port="$2"
  local timeout_s="$3"
  local logfile="$4"

  if require_cmd hping3; then
    run_section "$logfile" "hping3 SYN probe ${ip}:${port}" timeout "$timeout_s" hping3 -S -p "$port" -c 3 "$ip"
    return 0
  fi

  echo "SKIP: missing hping3" >>"$logfile"
}

HOST=""
PORT=""
ATTEMPTS=5
CONNECT_TIMEOUT=5
IFACE=""
OUTDIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="${2:-}"; shift 2 ;;
    --port) PORT="${2:-}"; shift 2 ;;
    --attempts) ATTEMPTS="${2:-}"; shift 2 ;;
    --connect-timeout) CONNECT_TIMEOUT="${2:-}"; shift 2 ;;
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

MAIN_LOG="${OUTDIR}/probe.log"
DNS_LOG="${OUTDIR}/dns.log"
ROUTE_LOG="${OUTDIR}/route.log"
PATH_LOG="${OUTDIR}/path.log"
SOCKET_LOG="${OUTDIR}/socket.log"
VERSIONS_LOG="${OUTDIR}/versions.log"
LINK_LOG="${OUTDIR}/link.log"
STACK_LOG="${OUTDIR}/stack.log"
FIREWALL_LOG="${OUTDIR}/firewall.log"
BGP_LOG="${OUTDIR}/bgp.log"
NEIGHBOR_LOG="${OUTDIR}/neighbor.log"
RULES_LOG="${OUTDIR}/policy-routing.log"

{
  echo "timestamp_utc=${STAMP}"
  echo "host=${HOST}"
  echo "port=${PORT}"
  echo "attempts=${ATTEMPTS}"
  echo "connect_timeout_seconds=${CONNECT_TIMEOUT}"
  echo
  echo "[system]"
  uname -a || true
  echo
} >"$MAIN_LOG"

mapfile -t IPS < <(resolve_ips "$HOST")

{
  echo "host=${HOST}"
  printf 'resolved_ips='
  printf '%s ' "${IPS[@]}"
  printf '\n'
  echo
  run_if_present "$DNS_LOG" getent ahostsv4 "$HOST"
  run_if_present "$DNS_LOG" getent ahosts "$HOST"
  run_if_present "$DNS_LOG" dig +short A "$HOST"
  run_if_present "$DNS_LOG" dig +short AAAA "$HOST"
  run_if_present "$DNS_LOG" dig +trace "$HOST"
  run_if_present "$DNS_LOG" host "$HOST"
} >"$DNS_LOG"

{
  run_if_present "$ROUTE_LOG" ip rule show
  run_if_present "$ROUTE_LOG" ip route show table main
  run_if_present "$ROUTE_LOG" ip route show table all
  run_if_present "$ROUTE_LOG" ip -s route show table all
  for ip in "${IPS[@]}"; do
    SRC_IP="$(discover_source_ip "$ip" || true)"
    echo "### ip route get ${ip}"
    run_if_present "$ROUTE_LOG" ip route get "$ip"
    if [[ -n "$SRC_IP" ]]; then
      run_if_present "$ROUTE_LOG" ip route get "$ip" from "$SRC_IP"
    else
      echo "SKIP: could not discover source IP for ${ip}" >>"$ROUTE_LOG"
    fi
    echo
  done
} >"$ROUTE_LOG"

{
  echo "### ss -tan"
  run_if_present "$SOCKET_LOG" ss -tan
  echo
  echo "### ss -ti state syn-sent"
  run_if_present "$SOCKET_LOG" ss -ti state syn-sent
  echo
  echo "### ss -ti dst :${PORT}"
  run_if_present "$SOCKET_LOG" ss -ti "( dport = :${PORT} or sport = :${PORT} )"
} >"$SOCKET_LOG"

{
  run_if_present "$VERSIONS_LOG" tcpdump --version
  run_if_present "$VERSIONS_LOG" nc -h
  run_if_present "$VERSIONS_LOG" mtr --version
  run_if_present "$VERSIONS_LOG" tracepath -V
  run_if_present "$VERSIONS_LOG" traceroute --version
  run_if_present "$VERSIONS_LOG" tcptraceroute --help
  run_if_present "$VERSIONS_LOG" hping3 --version
  run_if_present "$VERSIONS_LOG" ethtool --version
} >"$VERSIONS_LOG"

{
  for ip in "${IPS[@]}"; do
    echo "### target ${ip}:${PORT}"
    run_if_present "$PATH_LOG" tracepath -n "$ip"
    run_if_present "$PATH_LOG" tracepath -n -p "$PORT" "$ip"
    maybe_tcp_traceroute "$ip" "$PORT" "$PATH_LOG"
    run_if_present "$PATH_LOG" mtr -n -T -P "$PORT" -r -c 10 "$ip"
    maybe_syn_probe "$ip" "$PORT" "$CONNECT_TIMEOUT" "$PATH_LOG"
    echo
  done
} >"$PATH_LOG"

{
  if [[ -n "$IFACE" ]]; then
    INTERFACES=("$IFACE")
  else
    mapfile -t INTERFACES < <(discover_interfaces || true)
  fi

  run_if_present "$LINK_LOG" ip -br link
  run_if_present "$LINK_LOG" ip -br addr
  run_if_present "$LINK_LOG" ip -s link
  for iface in "${INTERFACES[@]:-}"; do
    echo "### interface ${iface}" >>"$LINK_LOG"
    run_if_present "$LINK_LOG" ethtool -k "$iface"
    run_if_present "$LINK_LOG" ethtool -S "$iface"
    run_if_present "$LINK_LOG" ethtool "$iface"
  done
} >"$LINK_LOG"

{
  run_if_present "$STACK_LOG" sysctl net.ipv4.tcp_syn_retries
  run_if_present "$STACK_LOG" sysctl net.ipv4.tcp_synack_retries
  run_if_present "$STACK_LOG" sysctl net.ipv4.tcp_mtu_probing
  run_if_present "$STACK_LOG" sysctl net.ipv4.ip_no_pmtu_disc
  run_if_present "$STACK_LOG" sysctl net.ipv4.conf.all.rp_filter
  run_if_present "$STACK_LOG" sysctl net.ipv4.conf.default.rp_filter
  run_if_present "$STACK_LOG" nstat -az
  run_if_present "$STACK_LOG" netstat -s
} >"$STACK_LOG"

{
  run_if_present "$FIREWALL_LOG" nft list ruleset
  run_if_present "$FIREWALL_LOG" iptables-save
  run_if_present "$FIREWALL_LOG" ip6tables-save
} >"$FIREWALL_LOG"

{
  run_if_present "$BGP_LOG" birdc show protocols
  run_if_present "$BGP_LOG" birdc show route
  run_if_present "$BGP_LOG" vtysh -c "show ip bgp summary"
  run_if_present "$BGP_LOG" vtysh -c "show ip bgp"
  run_if_present "$BGP_LOG" vtysh -c "show bgp ipv4 unicast summary"
  run_if_present "$BGP_LOG" gobgp neighbor
  run_if_present "$BGP_LOG" gobgp global rib
} >"$BGP_LOG"


{
  run_if_present "$NEIGHBOR_LOG" ip neigh show
  run_if_present "$NEIGHBOR_LOG" arp -an
} >"$NEIGHBOR_LOG"

{
  run_if_present "$RULES_LOG" ip rule show
  run_if_present "$RULES_LOG" ip route show table local
  run_if_present "$RULES_LOG" ip route show cache
} >"$RULES_LOG"

for attempt in $(seq 1 "$ATTEMPTS"); do
  {
    echo "### attempt ${attempt} at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    probe_tcp "$HOST" "$PORT" "$CONNECT_TIMEOUT" "$MAIN_LOG"
    run_if_present "$MAIN_LOG" ss -nti "( dport = :${PORT} or sport = :${PORT} )"
    echo
  } >>"$MAIN_LOG"
  sleep 1
done

echo "Probe results written to: ${OUTDIR}"
