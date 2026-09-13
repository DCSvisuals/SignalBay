#!/usr/bin/env bash
# Home-lab mode: dashboard + API on this Mac's LAN IPv4. Syslog already
# listens on 0.0.0.0. Other devices on 192.168.x / 10.x can send logs and
# open the UI. Do not use on school or public Wi-Fi.
set -euo pipefail
export LAB_MODE=1
export SIEM_BIND=0.0.0.0
exec /bin/bash /Users/david/Desktop/CyberNews/start_platform.sh
