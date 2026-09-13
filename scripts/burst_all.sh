#!/usr/bin/env bash
# All four collectors at once: 10 packets each, every 20s, for 4 minutes.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=burst_lib.sh
source "$ROOT/burst_lib.sh"

echo "LocalSIEM all-protocol burst on ${HOST}"
echo "UDP ${HOST}:514  TCP ${HOST}:601  TLS ${HOST}:6514  RELP ${HOST}:2514"
echo "${BURST} packets × 4 transports every ${INTERVAL}s for ${DURATION}s."
echo "Live Dashboard, not Demo. Ctrl+C stops all."
echo

pids=()
cleanup() {
  for pid in "${pids[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

run_bursts udp 514 &
pids+=($!)
run_bursts tcp 601 &
pids+=($!)
run_bursts tls 6514 &
pids+=($!)
run_bursts relp 2514 &
pids+=($!)
wait
echo
echo "All protocol bursts finished."
