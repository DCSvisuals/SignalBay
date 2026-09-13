#!/usr/bin/env bash
# 10 TLS syslog packets every 20s for 4 minutes → 192.168.2.59:6514
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=burst_lib.sh
source "$ROOT/burst_lib.sh"
run_bursts tls "${1:-6514}"
