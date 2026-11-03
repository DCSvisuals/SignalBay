#!/usr/bin/env bash
# Signalbay launcher: Metal-compiled node-llama-cpp backend + React dashboard.
set -euo pipefail

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/tui.sh
source "$ROOT/scripts/tui.sh"

SERVER_DIR="$ROOT/server"
CLIENT_DIR="$ROOT/client"
LOG_DIR="$ROOT/.run"
SERVER_LOG="$LOG_DIR/server.log"
CLIENT_LOG="$LOG_DIR/client.log"
API="http://127.0.0.1:3001/api/health"
APP="/Users/david/Desktop/LocalSIEM.app"
APP_SUPPORT="$HOME/Library/Application Support/LocalSIEM"
VERSION="$(tr -d '[:space:]' <"$ROOT/VERSION" 2>/dev/null || echo 1.0.0)"
NODE="/opt/homebrew/bin/node"
LAB_MODE="${LAB_MODE:-0}"
if [[ "$LAB_MODE" == "1" || "$LAB_MODE" == "true" ]]; then
  export SIEM_BIND=0.0.0.0
else
  export SIEM_BIND="${SIEM_BIND:-127.0.0.1}"
fi
UI_PORT=5173
if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:5173 -sTCP:LISTEN >/dev/null 2>&1; then
  UI_PORT=5174
fi
HOST_IPV4="$(host_ipv4)"
export HOST_IPV4
if [[ "$SIEM_BIND" == "0.0.0.0" && -n "$HOST_IPV4" && "$HOST_IPV4" != "none" ]]; then
  UI="http://${HOST_IPV4}:${UI_PORT}"
else
  UI="http://127.0.0.1:${UI_PORT}"
fi
export UI
export UI_PORT

mkdir -p "$LOG_DIR"
export NODE_LLAMA_CPP_GPU="${NODE_LLAMA_CPP_GPU:-metal}"
export CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"

draw() {
  local health
  health="$(health_lines "$(health_json)")"
  if [[ -z "$health" ]]; then
    health="$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s' \
      "Host IPv4     ${HOST_IPV4:-none}" \
      "HTTP API      127.0.0.1:3001  (starting)" \
      "Dashboard     $UI  (starting)" \
      "UDP syslog    pending" \
      "TCP syslog    pending" \
      "TLS syslog    pending" \
      "RELP          pending")"
  fi
  tui_frame "$VERSION" "$PCT" "$STATUS" "$health"$'\n'"$BODY" "Ctrl+C or Q stops Signalbay. Server pid ${SERVER_PID:-—}"
}

confirm_reset() {
  tui_restore
  local choice
  choice="$(osascript <<'EOF'
try
  set theButton to button returned of (display dialog "Reset Signalbay to a first launch?

This wipes:
• the SQLite database (events, incidents, FIM, inventory)
• local cache, TLS collector cert, and saved prompts
• the downloaded AI model (it will download again)
• run logs

Your project files on Desktop/CyberNews are not deleted.

Signalbay will quit and open again." buttons {"Cancel", "Reset and Quit and Open"} default button "Cancel" with title "Reset Signalbay" with icon caution)
  return theButton
on error
  return "Cancel"
end try
EOF
)" || choice="Cancel"
  tui_init
  [[ "$choice" == "Reset and Quit and Open" ]]
}

do_reset() {
  STATUS="Resetting to first launch…"
  PCT=10
  BODY="Stopping processes and wiping cache."
  draw
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
  [[ -n "${CLIENT_PID:-}" ]] && kill "$CLIENT_PID" 2>/dev/null || true
  sleep 0.4
  rm -rf "$APP_SUPPORT" "$LOG_DIR"
  mkdir -p "$LOG_DIR"
  PCT=100
  STATUS="Reset complete."
  BODY="Quit and Open to start as a first launch."
  draw
  sleep 0.6
  tui_restore
  open "$APP"
  exit 0
}

handle_key() {
  local key="${1:-}"
  case "$key" in
    q|Q) exit 0 ;;
    b|B) open "$UI" 2>/dev/null || true ;;
    h|H) open "$API" 2>/dev/null || true ;;
    r|R)
      if confirm_reset; then
        do_reset
      fi
      ;;
  esac
}

poll_key() {
  handle_key "$(tui_read_key "${1:-0}")"
}

tui_init
STATUS="Opening Signalbay control screen…"
PCT=1
BODY="localhost collectors · dashboard · API health"
draw

if [[ ! -x "$NODE" ]]; then
  STATUS="Node is missing at /opt/homebrew/bin/node"
  BODY="Close this window and open LocalSIEM.app to install Homebrew and Node."
  draw
  tui_restore
  echo "Node is not at $NODE."
  echo "Open LocalSIEM.app so it can warn you and install Homebrew + Node."
  read -r -p "Press Return to close. " || true
  exit 1
fi
export PATH="$(dirname "$NODE"):$PATH"

STATUS="Starting…"
PCT=2
BODY="Preparing localhost collectors and dashboard."
draw

cleanup() {
  tui_restore
  echo
  echo "==> stopping Signalbay"
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
  [[ -n "${CLIENT_PID:-}" ]] && kill "$CLIENT_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if curl -sf --max-time 1 -H 'Accept: application/json' "$API?format=json" >/dev/null 2>&1; then
  STATUS="Signalbay is already running — live status"
  PCT=100
  BODY="This window is the control screen. Q stops Signalbay. R resets to first launch."
  SERVER_PID="$(lsof -nP -iTCP:3001 -sTCP:LISTEN -t 2>/dev/null | head -1 || true)"
  CLIENT_PID="$(lsof -nP -iTCP:5174 -sTCP:LISTEN -t 2>/dev/null | head -1 || true)"
  if [[ -z "$CLIENT_PID" ]]; then
    CLIENT_PID="$(lsof -nP -iTCP:5173 -sTCP:LISTEN -t 2>/dev/null | head -1 || true)"
  fi
  draw
  while true; do
    draw
    poll_key 1
  done
fi

PCT=8
STATUS="Checking Node and npm…"
BODY="Using $NODE"
draw
poll_key 0

PCT=18
STATUS="Installing server dependencies…"
BODY="npm install in server/ if needed."
draw
(
  cd "$SERVER_DIR"
  if [[ ! -d node_modules ]]; then
    npm install
  fi
) >/dev/null 2>&1 || true
poll_key 0

PCT=32
STATUS="Apple Metal GPU — using cached backend (no download on launch)"
if [[ -f "$LOG_DIR/gpu-inspect.txt" ]] && grep -qi metal "$LOG_DIR/gpu-inspect.txt"; then
  BODY="Metal already recorded. Skipping node-llama-cpp inspect so startup cannot hang."
else
  BODY="Metal compile runs inside the API server, not this loading screen."
fi
draw
poll_key 0

PCT=44
STATUS="Installing dashboard dependencies…"
BODY="npm install in client/ if needed."
draw
(
  cd "$CLIENT_DIR"
  if [[ ! -d node_modules ]]; then
    npm install
  fi
) >/dev/null 2>&1 || true
poll_key 0

PCT=55
STATUS="Starting API server on ${SIEM_BIND}:3001…"
BODY="Syslog collectors on 0.0.0.0 · UI bind ${SIEM_BIND}."
draw
(
  cd "$SERVER_DIR"
  npm run dev
) >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

for i in $(seq 1 80); do
  PCT=$((55 + i / 4))
  STATUS="Waiting for API health on 127.0.0.1:3001…"
  BODY="server pid $SERVER_PID"
  draw
  poll_key 0
  if curl -sf --max-time 1 -H 'Accept: application/json' "$API?format=json" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    tui_restore
    echo "backend exited during startup; last log lines:" >&2
    tail -n 80 "$SERVER_LOG" >&2
    exit 1
  fi
  sleep 0.25
  if [[ "$i" -eq 80 ]]; then
    tui_restore
    echo "backend did not become healthy; last log lines:" >&2
    tail -n 80 "$SERVER_LOG" >&2
    exit 1
  fi
done

PCT=78
STATUS="Starting dashboard UI…"
BODY="Vite on $UI"
draw
(
  cd "$CLIENT_DIR"
  npx vite --host "$SIEM_BIND" --port "$UI_PORT"
) >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!

for i in $(seq 1 60); do
  PCT=$((78 + i / 4))
  STATUS="Waiting for dashboard $UI …"
  draw
  poll_key 0
  if curl -sf --max-time 1 "$UI" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    tui_restore
    echo "vite exited during startup; last log lines:" >&2
    tail -n 80 "$CLIENT_LOG" >&2
    exit 1
  fi
  sleep 0.2
  if [[ "$i" -eq 60 ]]; then
    tui_restore
    echo "dashboard did not become reachable; last log lines:" >&2
    tail -n 80 "$CLIENT_LOG" >&2
    exit 1
  fi
done

open "$UI" 2>/dev/null || true
PCT=100
STATUS="Signalbay is running on localhost."
BODY="Press Q to quit. Press R to wipe logs/cache and start like first launch."
draw

while kill -0 "$SERVER_PID" 2>/dev/null && kill -0 "$CLIENT_PID" 2>/dev/null; do
  draw
  poll_key 1
done
