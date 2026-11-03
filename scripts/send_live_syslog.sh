#!/usr/bin/env bash
# Send real syslog to the Signalbay Live Dashboard (not Demo).
# Usage: ./scripts/send_live_syslog.sh [count] [udp|tcp|tls|relp] [port]
set -euo pipefail

COUNT="${1:-8}"
PROTO="${2:-udp}"
HOST="${SYSLOG_HOST:-127.0.0.1}"
HOSTNAME="$(scutil --get LocalHostName 2>/dev/null || hostname -s)"

default_port() {
  case "$1" in
    udp) echo 514 ;;
    tcp) echo 601 ;;
    tls) echo 6514 ;;
    relp) echo 2514 ;;
    *) echo "" ;;
  esac
}

case "$PROTO" in
  udp|tcp|tls|relp|all) ;;
  *)
    echo "protocol must be udp, tcp, tls, relp, or all" >&2
    exit 1
    ;;
esac
PORT="${3:-$(default_port "$PROTO")}"

line_for() {
  local pri="$1"
  local app="$2"
  local msg="$3"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")"
  echo "<${pri}>1 ${ts} ${HOSTNAME}.local ${app} $$ - - ${msg}"
}

send_udp() {
  local line="$1"
  if command -v nc >/dev/null 2>&1; then
    printf '%s\n' "$line" | nc -u -w1 "$HOST" "$PORT"
  else
    printf '%s\n' "$line" >/dev/udp/"$HOST"/"$PORT"
  fi
}

send_tcp() {
  local line="$1"
  printf '%s\n' "$line" | nc -w1 "$HOST" "$PORT"
}

send_tls() {
  local line="$1"
  printf '%s\n' "$line" | openssl s_client -quiet -connect "${HOST}:${PORT}" >/dev/null 2>&1
}

send_relp() {
  local line="$1"
  local len
  len="$(printf '%s' "$line" | wc -c | tr -d ' ')"
  {
    printf '1 open 0\n'
    printf '2 syslog %s %s\n' "$len" "$line"
    printf '3 close 0\n'
  } | nc -w1 "$HOST" "$PORT" >/dev/null
}

send() {
  local line
  line="$(line_for "$1" "$2" "$3")"
  case "$PROTO" in
    udp) send_udp "$line" ;;
    tcp) send_tcp "$line" ;;
    tls) send_tls "$line" ;;
    relp) send_relp "$line" ;;
  esac
  printf 'sent  [%s] %s\n' "$PROTO" "$line"
}

burst() {
  echo "Sending ${COUNT} ${PROTO} syslog messages to ${HOST}:${PORT} (Live Dashboard)"
  echo "Open SIEM Live Dashboard — not Demo."
  echo
  local i
  for i in $(seq 1 "$COUNT"); do
    case $((i % 8)) in
      1) send 86 sshd "Failed password for testuser from 203.0.113.$((10 + i % 40)) port $((22000 + i)) ssh2" ;;
      2) send 85 sshd "Invalid user admin from 198.51.100.$((20 + i % 30)) port $((40000 + i))" ;;
      3) send 4 kernel "pf: dropped in on en0 proto tcp from 192.0.2.$((i % 50 + 1)) to 10.0.0.8 port 445" ;;
      4) send 14 sandboxd "deny(1) file-read-data /etc/ssh/sshd_config" ;;
      5) send 6 sudo "${USER:-david} : TTY=ttys001 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/whoami" ;;
      6) send 3 endpointsecurity "ES_EVENT_TYPE_NOTIFY_EXEC /usr/bin/curl https://example.invalid/payload" ;;
      7) send 10 syslogd "possible CVE-2024-21762 exploitation attempt in httpd access log" ;;
      0) send 13 firewall "socketfilterfw allow sshd lport=22 uid=0" ;;
    esac
    sleep 0.1
  done
  echo
  echo "Done. Check SIEM Live Dashboard → ${PROTO} stream."
  echo
}

if [ "$PROTO" = "all" ]; then
  for PROTO in udp tcp tls relp; do
    PORT="$(default_port "$PROTO")"
    burst
  done
else
  burst
fi
