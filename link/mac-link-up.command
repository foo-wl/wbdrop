#!/bin/bash
# WBDrop - macOS side: join the Windows soft AP.
# No sudo needed: only the SSID is switched, the address comes from APIPA.
set -u

SSID="${WBDROP_SSID:-WBDrop-Link}"
PASS="${WBDROP_PASS:-wbdrop2026}"
STATE="$HOME/.wbdrop-prev-ssid"

IF="${WBDROP_IFACE:-}"
if [ -z "$IF" ]; then
  IF=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/{getline; print $2; exit}')
fi
IF="${IF:-en0}"

echo ""
echo "  WBDrop link up (macOS)"
echo "  ========================================"
echo "  interface : $IF"

prev=$(networksetup -getairportnetwork "$IF" | sed -E 's/^[^:：]*[:：][[:space:]]*//')
case "$prev" in
  *"not associated"*|*"未关联"*|*"not a Wi-Fi"*) prev="" ;;
esac

if [ -n "$prev" ] && [ "$prev" != "$SSID" ]; then
  printf '%s' "$prev" > "$STATE"
  echo "  saved     : $prev"
  echo "              (restore with mac-link-down.command)"
else
  echo "  saved     : none"
fi

echo "  joining   : $SSID ..."
if ! networksetup -setairportnetwork "$IF" "$SSID" "$PASS"; then
  echo ""
  echo "  [FAIL] cannot join $SSID."
  echo "         Make sure the Windows side is running win-start-link.bat."
  echo ""
  read -r -p "  press Enter to close..." _
  exit 1
fi

sleep 4
ip=$(ifconfig "$IF" 2>/dev/null | awk '/inet /{print $2; exit}')

echo "  local ip  : ${ip:-<none>}"
echo ""

if [ -z "$ip" ]; then
  echo "  [!] no address yet. Wait a few seconds, then check:"
  echo "        ifconfig $IF | grep 'inet '"
elif [ "${ip%%.*}" = "169" ]; then
  echo "  link is up. Peer should be reachable at 169.254.1.1"
else
  echo "  [!] expected a 169.254.x.x address, got $ip"
  echo "      The Windows side may have fallen back to 192.168.137.1."
  echo "      If so, set a static address:"
  echo "        sudo networksetup -setmanual Wi-Fi 192.168.137.2 255.255.255.0 192.168.137.1"
  echo "      and restore DHCP later with:"
  echo "        sudo networksetup -setdhcp Wi-Fi"
fi

echo ""
echo "  WARNING: internet is DOWN while you stay on this link."
echo "  next   : open http://localhost:18432"
echo ""
read -r -p "  press Enter to close..." _
