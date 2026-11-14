#!/bin/bash
# WBDrop - macOS side: restore the USB ethernet adapter to DHCP after a
# static-IP transfer, and re-point WBDrop at whatever address comes back
# (normally a fresh 169.254.x.x link-local address).
#
# Usage: ./mac-eth-back-dhcp.command
set -u

PORT="${WBDROP_PORT:-18432}"

echo ""
echo "  WBDrop - restore DHCP (macOS)"
echo "  ========================================"

SVC=$(networksetup -listallhardwareports |
  awk '/^Hardware Port:/ { hp = substr($0, 16); gsub(/^ +| +$/, "", hp) }
       /^Device:/        { print hp }' |
  grep -Ei 'USB|LAN|Ethernet|AX88|RTL|Realtek' |
  grep -vi 'Wi-Fi|AirPort|Thunderbolt' |
  head -1)
DEV=$(networksetup -listallhardwareports |
  awk -v want="$SVC" '/^Hardware Port:/ { hp = substr($0, 16); gsub(/^ +| +$/, "", hp) }
                      /^Device:/ { if (hp == want) { print $2; exit } }')

if [ -z "$SVC" ] || [ -z "$DEV" ]; then
  echo "  [FAIL] no USB ethernet adapter found. Nothing to restore."
  echo ""
  read -r -p "  press Enter to close..." _
  exit 1
fi

echo "  service   : $SVC ($DEV)"
if sudo networksetup -setdhcp "$SVC"; then
  echo "  now       : DHCP (auto)"
else
  echo "  [!] failed. Set by hand: 系统设置 -> 网络 -> $SVC -> 详细信息 -> TCP/IP -> 使用 DHCP"
fi

# APIPA takes a few seconds to appear.
NEWIP=""
for _ in 1 2 3 4 5 6 7 8; do
  sleep 1
  NEWIP=$(ifconfig "$DEV" 2>/dev/null |
    awk '/inet /{print $2; exit}' | grep -E '^(169\.254\.|10\.|172\.|192\.168\.)' || true)
  [ -n "$NEWIP" ] && break
done
echo "  address   : ${NEWIP:-<none yet>}"

# Rebind WBDrop to the new address. IMPORTANT: never write an empty bind.
# An empty bind kills the direct listener, which makes this machine reachable
# as a sender but invisible as a receiver ("A connects, B cannot connect").
if [ -z "$NEWIP" ]; then
  echo "  WBDrop    : no new address yet - existing binding kept unchanged"
  echo "              if the old address is gone, pick one in 设置 -> 直连网卡"
else
  CFG=$(curl -s --noproxy '*' -m 3 "http://127.0.0.1:$PORT/api/config" 2>/dev/null || true)
  if [ -n "$CFG" ]; then
    BODY=$(printf '%s' "$CFG" | python3 -c '
import sys, json
try:
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    d = json.load(sys.stdin)["config"]
    d["bind"] = sys.argv[1]
    print(json.dumps(d))
except Exception:
    print("")
' "$NEWIP")
    if [ -n "$BODY" ]; then
      RES=$(curl -s --noproxy '*' -m 3 -X POST \
        -H 'Content-Type: application/json' -d "$BODY" \
        "http://127.0.0.1:$PORT/api/config" 2>/dev/null || true)
      if printf '%s' "$RES" | grep -q '"ok":true'; then
        echo "  WBDrop    : rebound to $NEWIP"
      else
        echo "  [WARN] WBDrop rebind failed; check 设置 -> 直连网卡"
      fi
    fi
  else
    echo "  WBDrop    : not running, nothing to rebind"
  fi
fi

echo ""
echo "  Reminder: plug the intranet cable back only AFTER closing WBDrop."
echo ""
read -r -p "  press Enter to close..." _
