#!/bin/bash
# WBDrop - macOS side of the STATIC IP scenario.
#
# The Windows box has a manually configured IP (DHCP disabled), so it does NOT
# fall back to 169.254.x.x when the intranet cable is unplugged. The Mac would
# sit at 169.254.x.x and Windows at 10.x.x.x -> no route between them.
#
# Rule: NEVER touch the Windows machine's IP / mask / MAC. Make the Mac join
# the Windows subnet instead. Router is deliberately left EMPTY, so this link
# can never become a default gateway.
#
# Usage (double-click also works, it will prompt):
#   ./mac-eth-join-static.command <windows-ip> [netmask]
#   ./mac-eth-join-static.command 10.20.30.40 255.255.255.0
#
# It also:
#   - rejects a subnet that overlaps the Mac's Wi-Fi subnet (routing + policy risk)
#   - picks a free address automatically (you do not have to invent one)
#   - tells the running WBDrop to rebind immediately (no UI clicking)
#   - verifies the default route still points at Wi-Fi
#
# Restore afterwards: ./mac-eth-back-dhcp.command
set -u

PORT="${WBDROP_PORT:-18432}"
WINIP="${1:-}"
MASK="${2:-}"
DRY="${WBDRY:-0}"

echo ""
echo "  WBDrop - join static subnet (macOS)"
echo "  ========================================================"

if ! command -v python3 >/dev/null 2>&1; then
  echo "  [FAIL] python3 not found; install Xcode Command Line Tools."
  echo ""
  read -r -p "  press Enter to close..." _
  exit 1
fi

if [ -z "$WINIP" ]; then
  read -r -p "  Windows IPv4 (from ipconfig): " WINIP
fi
if [ -z "$MASK" ]; then
  read -r -p "  Subnet mask [255.255.255.0]: " MASK
  MASK="${MASK:-255.255.255.0}"
fi

# ---- locate the USB ethernet service and the internet-facing interface ----
SVC=$(networksetup -listallhardwareports |
  awk '/^Hardware Port:/ { hp = substr($0, 16); gsub(/^ +| +$/, "", hp) }
       /^Device:/        { print hp }' |
  grep -Ei 'USB|LAN|Ethernet|AX88|RTL|Realtek' |
  grep -vi 'Wi-Fi|AirPort|Thunderbolt' |
  head -1)
DEV=$(networksetup -listallhardwareports |
  awk -v want="$SVC" '/^Hardware Port:/ { hp = substr($0, 16); gsub(/^ +| +$/, "", hp) }
                      /^Device:/ { if (hp == want) { print $2; exit } }')
GWIF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')

# ---- compute subnet, free address, overlap check --------------------------
# Overlap is only checked against the DEFAULT-ROUTE interface (normally Wi-Fi).
# The direct-link adapter itself is excluded, otherwise a previously configured
# static address on en6 would be reported as a false conflict.
PLAN=$(python3 - "$WINIP" "$MASK" "${DEV:-}" "${GWIF:-}" <<'PY'
import sys, re, subprocess
import ipaddress

win_s, mask_s = sys.argv[1].strip(), sys.argv[2].strip()
direct_dev, gw_if = sys.argv[3], sys.argv[4]
try:
    peer = ipaddress.IPv4Address(win_s)
    net = ipaddress.IPv4Network(f"{win_s}/{mask_s}", strict=False)
except Exception as e:
    print("ERR=" + str(e)); sys.exit(0)
if peer not in net:
    print("ERR=peer IP is outside the given mask"); sys.exit(0)

# Existing IPv4 interfaces on this Mac (for overlap detection).
try:
    out = subprocess.check_output(["ifconfig"], text=True, stderr=subprocess.DEVNULL)
except Exception:
    out = ""
cur, overlaps, taken, direct_ips = "", [], set(), []
for line in out.splitlines():
    m = re.match(r"^([A-Za-z0-9]+):\s+flags=", line)
    if m:
        cur = m.group(1)
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask 0x([0-9a-fA-F]+)", line)
    if not m:
        continue
    ip = ipaddress.IPv4Address(m.group(1))
    mask = ipaddress.IPv4Address(int(m.group(2), 16))
    if cur == direct_dev:            # the direct-link adapter is not a conflict
        direct_ips.append(str(ip))
        continue
    taken.add(str(ip))
    if ip.is_loopback or str(ip).startswith("169.254."):
        continue
    if gw_if and cur != gw_if:       # only the internet-facing interface matters
        continue
    other = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    if other.overlaps(net):
        overlaps.append(f"{cur}:{ip}/{mask}-default-route")

# Pick a free host address near the peer, away from .0/.1/.254/.255/gateways.
last = int(peer.packed[-1])
# Reuse the address already sitting on the direct adapter when it is a valid
# host in the target subnet. Only the broken /32 mask then needs fixing.
preferred = [int(a.split(".")[-1]) for a in direct_ips
             if ipaddress.IPv4Address(a) in net and a != str(peer)]
candidates = list(preferred)
for delta in (100, -100, 60, -60, 30, -30, 7, -7, 1, -1, 2, -2):
    candidates.append(last + delta)
for host in range(200, 2, -1):
    candidates.append(host)
chosen = None
for cand in candidates:
    if not (2 <= cand <= 253):
        continue
    a = ipaddress.IPv4Address(net.network_address.packed[:3] + bytes([cand]))
    if a not in net or a == peer or str(a) in taken:
        continue
    if a in (net.network_address, net.broadcast_address):
        continue
    chosen = str(a); break
if not chosen:
    print("ERR=no free host address in this subnet"); sys.exit(0)

print("WINIP=" + str(peer))
print("MASK=" + str(net.netmask))
print("MACIP=" + chosen)
print("NET=" + str(net))
print("OVERLAP=" + (",".join(overlaps) if overlaps else "none"))
PY
)

if printf '%s' "$PLAN" | grep -qE '[[:space:]]'; then
  echo "  [FAIL] internal error: unexpected whitespace in computed values"
  echo ""
  read -r -p "  press Enter to close..." _
  exit 1
fi
if [ -z "$PLAN" ] || printf '%s' "$PLAN" | grep -q '^ERR='; then
  echo "  [FAIL] $(printf '%s' "$PLAN" | sed -n 's/^ERR=//p')"
  echo "         Check the Windows IP and mask, then run again."
  echo ""
  read -r -p "  press Enter to close..." _
  exit 1
fi
eval "$PLAN"

echo "  Windows IP  : $WINIP"
echo "  subnet      : $NET"
echo "  mask        : $MASK"
echo "  Mac will use: $MACIP   (auto-picked, free)"
echo "  router      : (none, on purpose)"
echo ""

if [ "$OVERLAP" != "none" ]; then
  echo "  ############################################################"
  echo "  #  WARNING: SUBNET OVERLAP                                   #"
  echo "  ############################################################"
  echo "  This subnet overlaps an already active Mac interface:"
  echo "    $OVERLAP"
  echo "  Most likely the Mac Wi-Fi (internet) uses the same 10.x range."
  echo " 后果: 两个接口同网段, 路由可能走错; 且 Mac 会在连互联网的同时挂上内网地址。"
  echo ""
  echo "  Safer options:"
  echo "    1) turn Mac Wi-Fi OFF during the transfer, then re-enable it"
  echo "    2) ask IT for a different static subnet for the direct link"
  echo "    3) use the USB-to-RJ45 'second adapter' approach with 169.254"
  echo ""
  read -r -p "  Continue anyway? type YES: " ACK
  if [ "$ACK" != "YES" ]; then
    echo "  Aborted. Nothing changed."
    echo ""
    read -r -p "  press Enter to close..." _
    exit 1
  fi
fi

# ---- adapter check --------------------------------------------------------
if [ -z "$SVC" ] || [ -z "$DEV" ]; then
  echo "  [FAIL] no USB ethernet adapter found. Detected ports:"
  networksetup -listallhardwareports | grep '^Hardware Port:' | sed 's/^/           /'
  echo ""
  read -r -p "  press Enter to close..." _
  exit 1
fi
CURRENT=$(ifconfig "$DEV" 2>/dev/null | awk '/inet /{print $2; exit}')
CURMASK=$(ifconfig "$DEV" 2>/dev/null | awk '/inet /{print $4; exit}')
echo "  adapter     : $SVC ($DEV)"
echo "  currently   : ${CURRENT:-<none>} / ${CURMASK:-?}"
echo "  internet via: ${GWIF:-<none>} (default route)"
if [ "$CURMASK" = "0xffffffff" ]; then
  echo "  [!] current mask is /32: 'Manually Using DHCP' was selected at some point."
  echo "      A /32 has no route to the peer. This script fixes it with -setmanual."
fi
if ! ifconfig "$DEV" 2>/dev/null | grep -q 'status: active'; then
  echo "  [WARN] $DEV is not 'active'. Is the direct cable plugged in?"
  echo "         Continuing, but the link may be down."
fi
echo ""

if [ "$DRY" = "1" ]; then
  echo "  [dry-run] would run:"
  echo "    sudo networksetup -setmanual \"$SVC\" $MACIP $MASK \"\""
  echo "    POST http://127.0.0.1:$PORT/api/config  bind=$MACIP"
  exit 0
fi

# ---- configure ------------------------------------------------------------
echo "  Applying (sudo may ask for your password)..."
if ! sudo networksetup -setmanual "$SVC" "$MACIP" "$MASK" "" 2>/dev/null; then
  echo "  [!] automatic configuration failed. Set it by hand:"
  echo "        系统设置 -> 网络 -> $SVC -> 详细信息 -> TCP/IP"
  echo "        配置 IPv4: 手动 / IP: $MACIP / 掩码: $MASK / 路由器: 留空"
  echo ""
  read -r -p "  press Enter to close..." _
  exit 1
fi

sleep 2
GOT=$(ifconfig "$DEV" 2>/dev/null | awk '/inet /{print $2; exit}')
echo "  now         : ${GOT:-<no address>}"

if [ "$GOT" != "$MACIP" ]; then
  echo "  [!] address did not stick. Check: networksetup -getinfo \"$SVC\""
  echo ""
  read -r -p "  press Enter to close..." _
  exit 1
fi

# The USB service must not steal the default route from Wi-Fi.
GWIF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
if [ -z "$GWIF" ]; then
  echo "  [WARN] no default route -> Mac may be offline."
  echo "         系统设置 -> 网络 -> ... -> 设定服务顺序, 把 Wi-Fi 拖到 USB 网卡之上"
elif [ "$GWIF" = "$DEV" ]; then
  echo "  [WARN] default route now points at $DEV (direct link), not Wi-Fi."
  echo "         系统设置 -> 网络 -> ... -> 设定服务顺序, 把 Wi-Fi 拖到最上面"
else
  echo "  default route: still via $GWIF (internet intact)"
fi

# ---- tell WBDrop to rebind immediately ------------------------------------
CFG=$(curl -s --noproxy '*' -m 3 "http://127.0.0.1:$PORT/api/config" 2>/dev/null || true)
if [ -n "$CFG" ]; then
  BODY=$(printf '%s' "$CFG" | python3 -c '
import sys, json
try:
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    d = json.load(sys.stdin)["config"]
    d["bind"] = sys.argv[1]
    print(json.dumps(d))   # ensure_ascii: safe for curl -d
except Exception:
    print("")
' "$MACIP")
  if [ -n "$BODY" ]; then
    RES=$(curl -s --noproxy '*' -m 3 -X POST \
      -H 'Content-Type: application/json' -d "$BODY" \
      "http://127.0.0.1:$PORT/api/config" 2>/dev/null || true)
    if printf '%s' "$RES" | grep -q '"ok":true'; then
      echo "  WBDrop      : rebound to $MACIP automatically"
    else
      echo "  [WARN] WBDrop rebind failed -> in UI: 设置 -> 直连网卡 -> 选 $MACIP -> 保存"
    fi
  fi
else
  echo "  WBDrop      : not running. Start it, then 设置 -> 直连网卡 -> 选 $MACIP -> 保存"
fi

# ---- connectivity reference (Windows firewall may block ICMP) ------------
if ping -c 1 -t 2 "$WINIP" >/dev/null 2>&1; then
  echo "  ping $WINIP : ok"
else
  echo "  ping $WINIP : no reply (Windows firewall often blocks ICMP; not fatal)"
fi

echo ""
echo "  IMPORTANT: do NOT put the Windows gateway (e.g. 10.20.30.1) into this"
echo "            adapter's Router field. It must stay empty, otherwise the Mac"
echo "            loses its internet default route."
echo ""
echo "  OK. Remaining steps:"
echo "    1. Windows (if not done yet): run link\\win-prepare-static.bat"
echo "       -> firewall rule + WBDrop bind + pair code"
echo "    2. Both UIs: 设置 -> 添加对端 (alias + peer IP + peer pair code)"
echo "    3. Drag files into the browser window"
echo ""
echo "  Restore after transfer: ./mac-eth-back-dhcp.command"
echo ""
read -r -p "  press Enter to close..." _
