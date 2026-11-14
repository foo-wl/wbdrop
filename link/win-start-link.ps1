# WBDrop - Windows side link setup
# Creates a Wi-Fi soft AP (hosted network) WITHOUT Internet Connection Sharing.
# All output is ASCII on purpose: PowerShell 5.1 misreads UTF-8 without BOM.

$SSID   = "WBDrop-Link"
$KEY    = "wbdrop2026"
$HOSTIP = "169.254.1.1"
$MASK   = "255.255.0.0"
$PORT   = 18432

function Fail($msg) {
    Write-Host ""
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "  WBDrop link setup (Windows)" -ForegroundColor Cyan
Write-Host "  ========================================"
Write-Host ""

# --- 1. admin ------------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "Administrator rights required. Right-click the .bat and choose 'Run as administrator'."
}
Write-Host "  [1/6] administrator ......... ok"

# --- 2. WLAN service ----------------------------------------------------
$svc = Get-Service -Name WlanSvc -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne "Running") {
    Fail "WLAN AutoConfig service is not running. Enable Wi-Fi first."
}
Write-Host "  [2/6] WLAN service .......... ok"

# --- 3. driver capability ----------------------------------------------
$drvText = (netsh wlan show drivers) -join "`n"
$supportValue = $null
if ($drvText -match "(?m)^\s*(?:Hosted network supported|.*\p{IsCJKUnifiedIdeographs}.*)\s*:\s*(\S+)\s*$") {
    $supportValue = $matches[1]
}
$supported = $true
if ($supportValue -and ($supportValue -match '^(no|No|NO|否)$')) { $supported = $false }

if (-not $supported) {
    Write-Host "  [3/6] hosted network ........ NOT SUPPORTED" -ForegroundColor Red
    Write-Host ""
    Write-Host "  This Wi-Fi adapter cannot host a soft AP." -ForegroundColor Yellow
    Write-Host "  Typical for Intel CNVi adapters (AC 9560 / AX201 / AX211)."
    Write-Host ""
    Write-Host "  Run this to confirm:"
    Write-Host "      netsh wlan show drivers"
    Write-Host "  and look at the line about hosted network support."
    Write-Host ""
    Write-Host "  Fallback options:"
    Write-Host "    1. Bluetooth transfer (slow, ~150 KB/s)"
    Write-Host "    2. A USB-C to Ethernet adapter (fast, but needs hardware)"
    Write-Host ""
    exit 1
}
Write-Host "  [3/6] hosted network ........ supported"

# --- 4. create + start --------------------------------------------------
$out = (netsh wlan set hostednetwork mode=allow ssid="$SSID" key="$KEY" 2>&1) -join "`n"
if ($LASTEXITCODE -ne 0) { Fail "cannot configure hosted network:`n$out" }

$out = (netsh wlan start hostednetwork 2>&1) -join "`n"
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [4/6] start ................. FAILED" -ForegroundColor Red
    Write-Host $out
    Fail "cannot start the soft AP. Make sure Wi-Fi is switched on and not connected to any other network."
}
Write-Host "  [4/6] soft AP started ....... ok"

Start-Sleep -Seconds 2

# --- 5. assign link-local address --------------------------------------
$adapter = Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceDescription -match "Hosted Network" } |
    Select-Object -First 1

if (-not $adapter) {
    Fail "virtual AP adapter not found. Run 'netsh wlan show hostednetwork' to inspect."
}

$ipOk = $true
$null = (netsh interface ipv4 set address name="$($adapter.Name)" static $HOSTIP $MASK 2>&1)
if ($LASTEXITCODE -ne 0) {
    # 169.254/16 may be rejected on some builds; fall back to a private range.
    $HOSTIP = "192.168.137.1"
    $MASK   = "255.255.255.0"
    $null = (netsh interface ipv4 set address name="$($adapter.Name)" static $HOSTIP $MASK 2>&1)
    if ($LASTEXITCODE -ne 0) { Fail "cannot assign $HOSTIP to '$($adapter.Name)'." }
    $ipOk = $false
}
Write-Host "  [5/6] host address .......... $HOSTIP  ($($adapter.Name))"

# --- 6. firewall --------------------------------------------------------
$null = (netsh advfirewall firewall delete rule name="WBDrop" 2>&1)
$null = (netsh advfirewall firewall add rule name="WBDrop" dir=in action=allow protocol=TCP localport=$PORT profile=any 2>&1)
Write-Host "  [6/6] firewall rule ......... TCP $PORT allowed"

# --- summary ------------------------------------------------------------
Write-Host ""
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host "   SSID      : $SSID"
Write-Host "   PASSWORD  : $KEY"
Write-Host "   HOST IP   : $HOSTIP"
Write-Host "   PORT      : $PORT"
Write-Host "  ========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  On the Mac: run mac-link-up.command, then open http://localhost:$PORT"
if (-not $ipOk) {
    Write-Host ""
    Write-Host "  NOTE: 169.254.x.x was rejected by this Windows build." -ForegroundColor Yellow
    Write-Host "  The Mac will get a 169.254 address from APIPA and will NOT reach $HOSTIP."
    Write-Host "  Set the Mac manually: 192.168.137.2 / 255.255.255.0 / router 192.168.137.1"
}
Write-Host ""
Write-Host "  This AP does NOT share your LAN or Internet. No ICS is enabled."
Write-Host ""
