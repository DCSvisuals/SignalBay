#!/usr/bin/env bash
# Install Homebrew (if needed) then Node at /opt/homebrew/bin/node, then Quit and Open.
set -euo pipefail

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tui.sh
source "$ROOT/scripts/tui.sh"
VERSION="$(tr -d '[:space:]' <"$ROOT/VERSION" 2>/dev/null || echo 1.0.0)"
APP="/Users/david/Desktop/LocalSIEM.app"
NODE="/opt/homebrew/bin/node"
BREW="/opt/homebrew/bin/brew"

tui_init
draw() {
  local pct="$1" status="$2" extra="${3:-}"
  local body
  body="$(printf '%s\n%s\n%s\n%s' \
    "Target node:  $NODE" \
    "Homebrew:     $BREW" \
    "This Mac:     $(uname -m) $(sw_vers -productVersion 2>/dev/null || true)" \
    "$extra")"
  tui_frame "$VERSION" "$pct" "$status" "$body" "Installing tools so LocalSIEM can start."
}

quit_and_open() {
  tui_restore
  local choice
  choice="$(osascript <<EOF
try
  set theButton to button returned of (display dialog "Homebrew and Node are ready at:
$NODE

LocalSIEM needs to quit and open again to use this Node install." buttons {"Later", "Quit and Open"} default button "Quit and Open" with title "LocalSIEM" with icon note)
  return theButton
on error
  return "Later"
end try
EOF
)" || choice="Later"
  if [[ "$choice" == "Quit and Open" ]]; then
    open "$APP"
  fi
}

if [[ -x "$NODE" ]]; then
  draw 100 "Node is already installed." "Nothing to install."
  sleep 1
  quit_and_open
  exit 0
fi

draw 8 "Homebrew and Node are not at $NODE" "You confirmed the install warning."
sleep 1

if [[ ! -x "$BREW" ]]; then
  draw 15 "Installing Homebrew (password prompt may appear)…" "Official installer from Homebrew."
  tui_restore
  echo
  echo "=== Homebrew install (you may be asked for your Mac password) ==="
  NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  if [[ -x /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  fi
  tui_init
fi

if [[ ! -x "$BREW" ]]; then
  draw 0 "Homebrew install did not finish." "Open LocalSIEM again after Homebrew is installed."
  sleep 3
  exit 1
fi

eval "$(/opt/homebrew/bin/brew shellenv)"
draw 55 "Homebrew is installed. Installing Node…" "brew install node"
tui_restore
echo
echo "=== brew install node ==="
brew install node
tui_init

if [[ ! -x "$NODE" ]]; then
  draw 70 "Node is not yet at $NODE. Linking…" "brew link node"
  tui_restore
  brew link --overwrite node || true
  tui_init
fi

if [[ ! -x "$NODE" ]]; then
  draw 0 "Node still missing at $NODE" "Homebrew finished but Node is not on Apple Silicon path."
  sleep 4
  exit 1
fi

draw 100 "Node is installed at $NODE" "$($NODE --version 2>/dev/null || true)"
sleep 1
quit_and_open
