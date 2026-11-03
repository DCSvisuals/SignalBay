# Signalbay terminal UI helpers. Sourced, not executed.
# shellcheck shell=bash

TUI_CYAN=$'\033[38;5;87m'
TUI_DIM=$'\033[38;5;245m'
TUI_BOLD=$'\033[1m'
TUI_RESET=$'\033[0m'
TUI_HIDE=$'\033[?25l'
TUI_SHOW=$'\033[?25h'

tui_init() {
  tui_stty_restore="$(stty -g 2>/dev/null || true)"
  stty -echo -icanon time 0 min 0 2>/dev/null || true
  printf '\033[2J\033[H%s' "$TUI_HIDE"
}

tui_restore() {
  printf '%s\033[?25h\n' "$TUI_SHOW"
  if [[ -n "${tui_stty_restore:-}" ]]; then
    stty "$tui_stty_restore" 2>/dev/null || true
  fi
}

tui_bar() {
  local pct="${1:-0}"
  local width="${2:-28}"
  local filled empty i
  if (( pct < 0 )); then pct=0; fi
  if (( pct > 100 )); then pct=100; fi
  filled=$((width * pct / 100))
  empty=$((width - filled))
  printf '['
  for ((i = 0; i < filled; i++)); do printf '#'; done
  for ((i = 0; i < empty; i++)); do printf '-'; done
  printf '] %3d%%' "$pct"
}

tui_clip() {
  local s="${1-}"
  local n="${2:-70}"
  s="${s//$'\t'/ }"
  printf '%-*.*s' "$n" "$n" "$s"
}

tui_frame() {
  local version="$1"
  local pct="$2"
  local statustext="$3"
  local body="$4"
  local footer="${5:-}"
  printf '\033[H'
  printf '%s' "$TUI_CYAN"
  printf '+--------------------------------------------------------------------------+\n'
  printf '|  %sSignalbay%s  v%-6s   macOS Web-SIEM · localhost only           %s|\n' "$TUI_BOLD" "$TUI_RESET$TUI_CYAN" "$version" "$TUI_CYAN"
  printf '+--------------------------------------------------------------------------+\n'
  printf '|  %s%s%s|\n' "$TUI_RESET" "$(tui_clip "$(tui_bar "$pct")" 70)" "$TUI_CYAN"
  printf '|  %s%s%s|\n' "$TUI_DIM" "$(tui_clip "$statustext" 70)" "$TUI_CYAN"
  printf '+--------------------------------------------------------------------------+\n'
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && line=" "
    printf '|  %s%s%s|\n' "$TUI_RESET" "$(tui_clip "$line" 70)" "$TUI_CYAN"
  done <<<"$body"
  printf '+--------------------------------------------------------------------------+\n'
  if [[ -n "$footer" ]]; then
    printf '|  %s%s%s|\n' "$TUI_RESET" "$(tui_clip "$footer" 70)" "$TUI_CYAN"
  fi
  printf '|  %s%s%s|\n' "$TUI_DIM" "$(tui_clip "R = Reset to first launch   B = Dashboard   H = Health   Q = Quit" 70)" "$TUI_CYAN"
  printf '+--------------------------------------------------------------------------+\n'
  printf '%s' "$TUI_RESET"
  printf '\033[J'
}

tui_read_key() {
  local key=""
  # Bash 3.2 on macOS: -t 0 returns immediately. Never block startup.
  IFS= read -r -t "${1:-0}" -n 1 key || true
  printf '%s' "$key"
}

host_ipv4() {
  if [[ -n "${HOST_IPV4:-}" ]]; then
    printf '%s' "$HOST_IPV4"
    return 0
  fi
  local iface ip
  iface="$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')"
  if [[ -n "$iface" ]]; then
    ip="$(ipconfig getifaddr "$iface" 2>/dev/null || true)"
  fi
  if [[ -z "$ip" ]]; then
    ip="$(ipconfig getifaddr en0 2>/dev/null || true)"
  fi
  if [[ -z "$ip" ]]; then
    ip="$(ifconfig 2>/dev/null | awk '/inet / && $2 != "127.0.0.1" { print $2; exit }')"
  fi
  if [[ -z "$ip" || "$ip" == *:* ]]; then
    ip="none"
  fi
  printf '%s' "$ip"
}

health_json() {
  curl -sf -H 'Accept: application/json' --max-time 1 \
    'http://127.0.0.1:3001/api/health?format=json' 2>/dev/null || true
}

health_lines() {
  local out
  out="$(HEALTH_PAYLOAD="${1-}" python3 - <<'PY' 2>/dev/null || true
import json, os
raw = (os.environ.get("HEALTH_PAYLOAD") or "").strip()
host = os.environ.get("HOST_IPV4") or "none"
if not raw:
    raise SystemExit(1)
try:
    h = json.loads(raw)
except Exception:
    raise SystemExit(1)
ui = h.get("dashboardUrl") or os.environ.get("UI") or "http://127.0.0.1:5173"

def port(name, key):
    v = h.get(key)
    return f"{name:<12} 127.0.0.1:{v}" if v else f"{name:<12} not listening"
print(f"{'Host IPv4':<12} {host}")
print(port("UDP syslog", "udpPort"))
print(port("TCP syslog", "tcpPort"))
print(port("TLS syslog", "tlsPort"))
print(port("RELP", "relpPort"))
bind = os.environ.get("SIEM_BIND") or "127.0.0.1"
api_host = host if bind == "0.0.0.0" and host not in ("none", "127.0.0.1", "") else "127.0.0.1"
print(f"{'HTTP API':<12} {api_host}:3001")
print(f"{'Dashboard':<12} {ui}")
llm = h.get("llm") or {}
state = llm.get("state") or "idle"
msg = (llm.get("message") or "")[:42]
print(f"AI engine     {state} · {msg}")
print(f"Clients       {h.get('clients', 0)} connected")
print("Health        Signalbay is running." if h.get("ok") else "Health        problem reported")
PY
)"
  if [[ -n "$out" ]]; then
    printf '%s\n' "$out"
    return 0
  fi
  echo "Host IPv4     ${HOST_IPV4:-none}"
  echo "HTTP API      127.0.0.1:3001  (waiting)"
  echo "Dashboard     ${UI:-http://127.0.0.1:5173}  (waiting)"
  echo "UDP syslog    pending"
  echo "TCP syslog    pending"
  echo "TLS syslog    pending"
  echo "RELP          pending"
}
