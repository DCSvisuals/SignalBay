#!/bin/bash
# Loads the Signalbay pf anchor. The anchor name stays localsiem. Does not edit /etc/pf.conf unless --write-pf-conf is passed.
set -euo pipefail

SUPPORT="${HOME}/Library/Application Support/LocalSIEM"
ANCHOR="${SUPPORT}/localsiem.pf.conf"
WRITE_MAIN=0
if [[ "${1:-}" == "--write-pf-conf" ]]; then
  WRITE_MAIN=1
fi

if [[ ! -f "$ANCHOR" ]]; then
  mkdir -p "$SUPPORT"
  cat > "$ANCHOR" <<'EOF'
table <localsiem> persist { }
block drop in quick from <localsiem> to any
block drop out quick from any to <localsiem>
EOF
  echo "Wrote $ANCHOR"
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Re-run with sudo so pfctl can load the anchor:"
  echo "  sudo \"$0\"${WRITE_MAIN:+ --write-pf-conf}"
  exit 1
fi

pfctl -a localsiem -f "$ANCHOR"
echo "Loaded anchor localsiem from $ANCHOR"

if [[ "$WRITE_MAIN" -eq 1 ]]; then
  if ! grep -q 'anchor "localsiem"' /etc/pf.conf; then
    printf '\nanchor "localsiem"\nload anchor "localsiem" from "%s"\n' "$ANCHOR" >> /etc/pf.conf
    echo "Appended the localsiem anchor to /etc/pf.conf"
  fi
  pfctl -f /etc/pf.conf
  echo "Reloaded /etc/pf.conf"
else
  echo "Main ruleset was not changed. Traffic is blocked only if /etc/pf.conf already calls anchor \"localsiem\"."
  echo "To add that hook: sudo \"$0\" --write-pf-conf"
fi

echo
echo "Optional passwordless sudo for the operator account (edit with visudo, do not paste blindly):"
echo "  $SUDO_USER ALL=(root) NOPASSWD: /sbin/pfctl -a localsiem -f $ANCHOR, /sbin/pfctl -t localsiem -T show"
