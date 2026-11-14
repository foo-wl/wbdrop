#!/bin/bash
# WBDrop - macOS side: leave the link and reconnect to the previous network.
set -u

STATE="$HOME/.wbdrop-prev-ssid"

IF="${WBDROP_IFACE:-}"
if [ -z "$IF" ]; then
  IF=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/{getline; print $2; exit}')
fi
IF="${IF:-en0}"

echo ""
echo "  WBDrop link down (macOS)"
echo "  ========================================"
echo "  interface : $IF"

prev=""
[ -f "$STATE" ] && prev=$(cat "$STATE")

if [ -z "$prev" ]; then
  echo "  no saved network."
  echo "  use the Wi-Fi menu to reconnect manually."
else
  echo "  reconnecting to: $prev"
  if ! networksetup -setairportnetwork "$IF" "$prev"; then
    echo "  [!] failed. The network may need a password again."
    echo "      use the Wi-Fi menu to connect manually."
  fi
  sleep 3
  ip=$(ifconfig "$IF" 2>/dev/null | awk '/inet /{print $2; exit}')
  echo "  local ip  : ${ip:-<none>}"
fi

echo ""
read -r -p "  press Enter to close..." _
