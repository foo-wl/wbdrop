#!/usr/bin/env bash
# WBDrop - macOS LAN listener diagnostics.
# Use this before/after quitting (or whitelisting) Proxifier / AdGuard.
# Read-only: it never changes network settings, firewall rules or WBDrop config.
#
# IMPORTANT: double-click this file in Finder. Results produced from inside an
# AI agent shell / sandboxed terminal are NOT reliable (that sandbox fakes
# failures for LAN addresses). Only a normal Terminal/Finder run counts.
set -u

PORT=18432
echo "=== WBDrop Mac LAN diagnostics  $(date '+%Y-%m-%d %H:%M:%S') ==="
echo

echo "--- 1. Network extensions (transparent proxy / content filter) ---"
EXT=$(systemextensionsctl list 2>&1)
echo "$EXT" | sed -n '1,20p' | sed 's/^/    /'
echo "    ^ [activated enabled]  = loaded and filtering"
echo "      [activated disabled] = SWITCHED OFF, but a provider already loaded"
echo "                             may stay resident until its app really quits"
echo "                             (or until a reboot)."
echo

echo "--- 2. Are the proxy apps still running? ---"
FOUND=0
for pat in 'Proxifier' 'AdGuard'; do
  hits=$(pgrep -fl "$pat" 2>/dev/null | grep -v 'pgrep' | head -8)
  if [ -n "$hits" ]; then
    FOUND=1
    echo "    [$pat] RUNNING:"
    echo "$hits" | sed 's/^/      /'
  else
    echo "    [$pat] not running  OK"
  fi
done
echo
if [ "$FOUND" = "1" ]; then
  echo "    NOTE: disabling the extension in System Settings does NOT quit the app."
  echo "          A resident network-extension provider keeps intercepting until the"
  echo "          app fully exits (Cmd-Q) / is force-quit, or the Mac is rebooted."
fi
echo

echo "--- 3. Application firewall ---"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate --getblockall --getstealthmode 2>&1 | sed 's/^/    /'
echo

echo "--- 4. WBDrop listeners ---"
lsof -nP -iTCP:${PORT} -sTCP:LISTEN 2>/dev/null | sed 's/^/    /'
echo

LAN=$(curl -s --noproxy '*' --max-time 3 "http://127.0.0.1:${PORT}/api/config" 2>/dev/null \
      | python3 -c 'import sys,json; print(json.load(sys.stdin)["config"]["bind"])' 2>/dev/null)
if [ -z "$LAN" ]; then LAN="10.20.30.116"; fi
echo "    direct-link bind address: $LAN"
echo

echo "--- 5. Self-connect test (loopback must work; direct IP must too) ---"
for ip in 127.0.0.1 "$LAN"; do
  code=$(curl -s --noproxy '*' --max-time 5 -o /dev/null -w '%{http_code}' "http://${ip}:${PORT}/" 2>/dev/null)
  printf "    %-16s -> HTTP %s" "$ip:$PORT/" "$code"
  if [ "$code" = "200" ]; then echo "   OK"; else echo "   <-- BLOCKED / connection closed"; fi
done
echo

echo "--- 6. Route to the direct IP (should be lo0 for own address) ---"
route -n get "$LAN" 2>&1 | grep -E 'destination|interface|flags' | sed 's/^/    /'
echo

echo "--- VERDICT ---"
LB=$(curl -s --noproxy '*' --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/" 2>/dev/null)
DR=$(curl -s --noproxy '*' --max-time 5 -o /dev/null -w '%{http_code}' "http://${LAN}:${PORT}/" 2>/dev/null)
if [ "$LB" = "200" ] && [ "$DR" = "200" ]; then
  echo "  [OK] Both listeners answer. The Mac side is healthy."
  echo "       Go back to Windows and re-test http://${LAN}:${PORT}/ and 'save and test'."
elif [ "$LB" = "200" ] && [ "$DR" != "200" ]; then
  echo "  [BLOCKED] Loopback works but the direct-link IP is closed/reset."
  echo "       Not a WBDrop bug, not a port issue, not the app firewall."
  echo "       A network filter is intercepting connections to this Mac."
  echo
  if [ "$FOUND" = "1" ]; then
    echo "  >>> A proxy/filter app is STILL RUNNING (see section 2). Do this FIRST:"
    echo "      1) Cmd-Q in Proxifier and AdGuard (menu bar icon -> Quit)."
    echo "         If it will not quit: Activity Monitor -> force quit the app."
    echo "      2) RUN THIS SCRIPT AGAIN by double-clicking it in Finder."
    echo "      3) Both lines in section 5 must read HTTP 200."
  else
    echo "  >>> All proxy apps are gone but it is still blocked. The network"
    echo "      extension provider is still loaded in the kernel. Do this:"
    echo "      1) REBOOT the Mac (most reliable way to unload the provider)."
    echo "      2) Start WBDrop again, then run this script again."
  fi
  echo
  echo "  Long term (re-enable them with a bypass instead of keeping them off):"
  echo "      Proxifier : add rule  10.20.30.*  -> Direct  (place it FIRST)"
  echo "      AdGuard   : add WBDrop / 10.20.30.0/24 to the filter allowlist"
else
  echo "  [CHECK] Loopback itself returned HTTP $LB. Is WBDrop running?"
  echo "          Start it first, then run this script again."
fi
echo
echo "=== END (no settings were changed) ==="
