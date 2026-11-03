# Shared burst sender for Signalbay. Sourced, not executed.
# shellcheck shell=bash

HOST="${SYSLOG_HOST:-192.168.2.59}"
HOSTNAME="$(scutil --get LocalHostName 2>/dev/null || hostname -s)"
BURST="${BURST:-10}"
INTERVAL="${INTERVAL:-20}"
DURATION="${DURATION:-240}"

default_port() {
  case "$1" in
    udp) echo 514 ;;
    tcp) echo 601 ;;
    tls) echo 6514 ;;
    relp) echo 2514 ;;
  esac
}

line_for() {
  local pri="$1" app="$2" msg="$3" ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")"
  echo "<${pri}>1 ${ts} ${HOSTNAME}.local ${app} $$ - - ${msg}"
}

payloads() {
  local i="$1"
  case $((i % 10)) in
    0) echo "86 sshd Failed password for burstuser from 203.0.113.$((10 + i % 40)) port $((22000 + i)) ssh2" ;;
    1) echo "85 sshd Invalid user admin from 198.51.100.$((20 + i % 30)) port $((40000 + i))" ;;
    2) echo "4 kernel pf: dropped in on en0 proto tcp from 192.0.2.$((i % 50 + 1)) to 10.0.0.8 port 445" ;;
    3) echo "14 sandboxd deny(1) file-read-data /etc/ssh/sshd_config" ;;
    4) echo "6 sudo ${USER:-david} : TTY=ttys001 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/whoami" ;;
    5) echo "3 endpointsecurity ES_EVENT_TYPE_NOTIFY_EXEC /usr/bin/curl https://example.invalid/payload" ;;
    6) echo "10 syslogd possible CVE-2024-21762 exploitation attempt in httpd access log" ;;
    7) echo "13 firewall socketfilterfw allow sshd lport=22 uid=0" ;;
    8) echo "4 trustd OCSP status revoked=(null) fetchFailed=0 timedOut=0" ;;
    9) echo "14 unifiedlog burst packet $i of $BURST" ;;
  esac
}

send_udp_burst() {
  local port="$1" n line pri app msg
  for n in $(seq 1 "$BURST"); do
    read -r pri app msg <<<"$(payloads "$n")"
    line="$(line_for "$pri" "$app" "$msg")"
    printf '%s\n' "$line" | nc -u -w1 "$HOST" "$port" >/dev/null 2>&1 || true
  done
}

send_tcp_burst() {
  local port="$1" n line pri app msg
  {
    for n in $(seq 1 "$BURST"); do
      read -r pri app msg <<<"$(payloads "$n")"
      line_for "$pri" "$app" "$msg"
    done
  } | nc -w2 "$HOST" "$port" >/dev/null 2>&1 || true
}

send_tls_burst() {
  local port="$1" n
  {
    for n in $(seq 1 "$BURST"); do
      read -r pri app msg <<<"$(payloads "$n")"
      line_for "$pri" "$app" "$msg"
    done
  } | openssl s_client -quiet -connect "${HOST}:${port}" >/dev/null 2>&1 || true
}

send_relp_burst() {
  local port="$1" n line len tx
  {
    printf '1 open 0\n'
    tx=2
    for n in $(seq 1 "$BURST"); do
      read -r pri app msg <<<"$(payloads "$n")"
      line="$(line_for "$pri" "$app" "$msg")"
      len="$(printf '%s' "$line" | wc -c | tr -d ' ')"
      printf '%s syslog %s %s\n' "$tx" "$len" "$line"
      tx=$((tx + 1))
    done
    printf '%s close 0\n' "$tx"
  } | nc -w2 "$HOST" "$port" >/dev/null 2>&1 || true
}

run_bursts() {
  local proto="$1"
  local port="${2:-$(default_port "$proto")}"
  local started now elapsed burst_no=0
  local total=$((DURATION / INTERVAL))
  echo "Signalbay $proto burst → ${HOST}:${port}"
  echo "${BURST} packets every ${INTERVAL}s for ${DURATION}s (${total} bursts)."
  echo "Live Dashboard, not Demo. Ctrl+C to stop."
  echo
  started="$(date +%s)"
  while true; do
    now="$(date +%s)"
    elapsed=$((now - started))
    if (( elapsed >= DURATION )); then
      break
    fi
    burst_no=$((burst_no + 1))
    echo "$(date '+%H:%M:%S')  burst ${burst_no}/${total}  ${proto} ${BURST} packets"
    case "$proto" in
      udp) send_udp_burst "$port" ;;
      tcp) send_tcp_burst "$port" ;;
      tls) send_tls_burst "$port" ;;
      relp) send_relp_burst "$port" ;;
    esac
    now="$(date +%s)"
    elapsed=$((now - started))
    if (( elapsed + INTERVAL >= DURATION && burst_no >= total )); then
      break
    fi
    if (( elapsed >= DURATION )); then
      break
    fi
    sleep "$INTERVAL"
  done
  echo
  echo "Done. ${burst_no} bursts on ${proto} :${port}"
}
