#!/bin/bash
# Opened by LocalSIEM.app (Signalbay) via Terminal. Do not use ./exec — macOS can
# return "Operation not permitted" for scripts on Desktop.
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
cd /Users/david/Desktop/CyberNews || {
  echo "Could not open /Users/david/Desktop/CyberNews"
  read -r -p "Press Return to close. "
  exit 1
}
exec /bin/bash /Users/david/Desktop/CyberNews/start_platform.sh
