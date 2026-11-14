#!/bin/bash
# WBDrop - recover the direct-link listener after the USB ethernet goes away.
#
# Typical cause: Mac sleeps / USB adapter power-cycles / cable unplugged.
# The en6 interface becomes "inactive", macOS drops 10.20.30.116, and WBDrop
# (if restarted during that window) forgets its bind. Windows can then still
# ping the address from a stale ARP entry or another device, but nothing is
# listening on :18432 -> "ping works, port does not".
#
# This script does NOT change any network setting. The manual IP config is
# already stored in macOS ("USB 10/100 LAN" -> 10.20.30.116/24, Router empty)
# and comes back by itself as soon as the cable/adapter is alive again.
# It only re-points the RUNNING WBDrop at that address via POST /api/config.
#
# Usage:  ./mac-link-recover.command
# Env:    WBDROP_BIND / WBDROP_PEER / WBDROP_PORT

set -u
PORT="${WBDROP_PORT:-18432}"
BIND="${WBDROP_BIND:-10.20.30.116}"
PEER="${WBDROP_PEER:-10.20.30.216}"

echo ""
echo "  WBDrop - direct link recovery (Mac)"
echo "  ========================================================"
echo ""

# --- 1. is the direct-link address actually on this Mac right now? ---------
DEV=""
for d in $(ifconfig -l); do
    if ifconfig "$d" 2>/dev/null | grep -q "inet ${BIND} "; then DEV="$d"; break; fi
done

if [ -z "$DEV" ]; then
    echo "  [BLOCKED] $BIND is NOT assigned to any interface right now."
    echo ""
    echo "  The USB ethernet link is down. Do this first:"
    echo "    1. re-plug the USB-to-RJ45 adapter (try another port), and the cable"
    echo "    2. System Settings > Network: 'USB 10/100 LAN' must turn green"
    echo "    3. run this script again"
    echo ""
    echo "  Saved macOS network config (should already be correct):"
    networksetup -getinfo "USB 10/100 LAN" 2>&1 | sed -n '1,6p' | sed 's/^/    /'
    echo ""
    echo "  Current interface state:"
    ifconfig en6 2>/dev/null | grep -E 'status:|inet ' | sed 's/^/    /'
    echo ""
    echo "  Nothing was changed."
    exit 1
fi

echo "  [ok] $BIND is live on $DEV"
echo "  [note] default route must stay on Wi-Fi; do NOT fill Router with $PEER's gateway"
route -n get default 2>/dev/null | grep -E 'gateway|interface' | sed 's/^/    /'
echo ""

# --- 2. WBDrop running? ---------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
if ! curl -s --max-time 4 -o "$TMP/get.json" "http://127.0.0.1:$PORT/api/config" || [ ! -s "$TMP/get.json" ]; then
    echo "  [BLOCKED] WBDrop is not running on 127.0.0.1:$PORT."
    echo "  Double-click wbdrop-macos-amd64 first, keep it running, then rerun this."
    exit 1
fi

# --- 3. GET -> patch bind -> POST the FULL config -------------------------
# POST /api/config is a full replace: sending only {"bind":...} would erase
# code / peers / active. python3 emits ASCII-safe JSON so Chinese aliases
# survive the round trip byte-exactly.
python3 - "$TMP/get.json" "$BIND" > "$TMP/post.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
c = d.get("config") or {}
c["bind"] = sys.argv[2]
if not isinstance(c.get("peers"), list):
    c["peers"] = []
print(json.dumps(c, separators=(",", ":")))
PY

RES="$(curl -s --max-time 6 -X POST -H 'Content-Type: application/json' \
        --data-binary "@$TMP/post.json" "http://127.0.0.1:$PORT/api/config")"
echo "  POST /api/config -> $RES"
echo ""

if ! echo "$RES" | grep -q '"ok"[[:space:]]*:[[:space:]]*true'; then
    echo "  [FAIL] WBDrop rejected the bind. Read the error above."
    exit 1
fi

# --- 4. verify -------------------------------------------------------------
echo "  Listeners now:"
lsof -nP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | tail -n +2 | sed 's/^/    /'
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | grep -q "${BIND}:${PORT}"; then
    echo ""
    echo "  [OK] direct-link listener restored on $BIND:$PORT"
    echo "  Go back to Windows and test again:"
    echo "     Test-NetConnection $BIND -Port $PORT -InformationLevel Quiet"
    echo "  Then click 'Save and test' / drag the file."
else
    echo ""
    echo "  [WARN] listener not visible yet; wait 3s and check:"
    echo "     lsof -nP -iTCP:$PORT -sTCP:LISTEN"
fi
echo ""
