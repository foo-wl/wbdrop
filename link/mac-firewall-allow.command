#!/bin/bash
# WBDrop - let the macOS Application Firewall accept connections FROM Windows.
#
# Symptom this fixes:
#   Mac can reach Windows (probe = ok), but Windows cannot reach the Mac.
#   Mac has a listener on the direct-link IP and ARP/routing are fine, so the
#   remaining blocker is macOS ALF: WBDrop is an unsigned CLI binary and is not
#   in the "allow incoming connections" list.
#
# Usage:
#   ./mac-firewall-allow.command [path-to-wbdrop-binary]
#   OFF=1 ./mac-firewall-allow.command    # temporarily disable ALF to verify
#   ON=1  ./mac-firewall-allow.command    # re-enable ALF after the test
#
# Requires sudo (you will be asked for your password in the Terminal window).

set -u
FW=/usr/libexec/ApplicationFirewall/socketfilterfw
PORT="${WBDROP_PORT:-18432}"

echo ""
echo "  WBDrop - macOS inbound firewall fix"
echo "  ========================================================"
echo ""

if [ "${OFF:-0}" = "1" ]; then
    echo "  Turning the macOS Application Firewall OFF (temporary verification)..."
    sudo "$FW" --setglobalstate off
    echo "  Now click 'Save and test' on Windows. If it turns green, ALF was the cause."
    echo "  Then run:  ON=1 ./mac-firewall-allow.command"
    echo ""
    exit 0
fi

if [ "${ON:-0}" = "1" ]; then
    echo "  Turning the macOS Application Firewall back ON..."
    sudo "$FW" --setglobalstate on
    sudo "$FW" --getglobalstate
    echo ""
    exit 0
fi

BIN="${1:-}"
if [ -z "$BIN" ]; then
    PID="$(lsof -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | head -1)"
    if [ -n "$PID" ]; then
        BIN="$(lsof -p "$PID" 2>/dev/null | awk '$4=="txt" { print $9; exit }')"
    fi
fi
if [ -z "$BIN" ]; then
    BIN="$(cd "$(dirname "$0")/.." && pwd)/dist/wbdrop-macos-amd64"
fi

if [ ! -f "$BIN" ]; then
    echo "  [FAIL] binary not found: $BIN"
    echo "  Pass its path explicitly:  ./mac-firewall-allow.command /path/to/wbdrop-macos-amd64"
    exit 1
fi

echo "  binary : $BIN"
echo "  state  : $("$FW" --getglobalstate 2>&1)"
echo ""

echo "  [1/2] adding WBDrop to the firewall application list ..."
sudo "$FW" --add "$BIN"
echo "  [2/2] allowing incoming connections for WBDrop ..."
sudo "$FW" --unblockapp "$BIN"
echo ""
"$FW" --getappblocked "$BIN"
echo ""
echo "  Entries now in the firewall list:"
"$FW" --listapps 2>&1 | grep -i -A 1 'wbdrop' || echo "  (no wbdrop entry found - check the output above)"
echo ""
echo "  IMPORTANT: quit and relaunch WBDrop now."
echo "  ALF marks a running process at launch time; a process that was already"
echo "  running when the rule was added usually needs a restart to pick it up."
echo ""
echo "  After relaunching, Mac must still listen on the direct-link IP:"
echo "     lsof -nP -iTCP:$PORT -sTCP:LISTEN"
echo "  expect BOTH 127.0.0.1:$PORT and 10.20.30.116:$PORT"
echo ""
echo "  Then click 'Save and test' on Windows again."
echo ""
