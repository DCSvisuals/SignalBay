#!/usr/bin/env bash
# 10 RELP syslog packets every 20s for 4 minutes → 192.168.2.59:2514
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=burst_lib.sh
source "$ROOT/burst_lib.sh"
run_bursts relp "${1:-2514}"
