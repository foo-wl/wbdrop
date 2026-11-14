# WBDrop - Windows side of the STATIC IP scenario.
# All output is ASCII on purpose: PowerShell 5.1 misreads UTF-8 without BOM.
#
# Does three things:
#   1. reports this machine's manually configured IPv4 + mask (copy to the Mac script)
#   2. opens TCP 18432 inbound on the PUBLIC profile only
#   3. tells the running WBDrop to bind to that address (no UI clicking)
#
# It does NOT change the IP, mask, MAC, gateway or any adapter setting.
# It does NOT enable ICS / bridging / forwarding.
#
# PRECONDITION (enforced by a typed confirmation):
#   intranet cable UNPLUGGED, direct cable to the Mac PLUGGED.
#   If the intranet cable is still connected, binding WBDrop to 10.x would
#   expose the service to the intranet. Do not run it in that state.

$ErrorActionPreference = "Stop"
[System.Net.WebRequest]::DefaultWebProxy = $null
$PORT = if ($env:WBDROP_PORT) { [int]$env:WBDROP_PORT } else { 18432 }

function Fail($msg) {
    Write-Host ""
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "  WBDrop - static IP prepare (Windows)" -ForegroundColor Cyan
Write-Host "  ========================================================"
Write-Host ""

# --- 0. admin ------------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "Administrator required. Right-click the .bat -> Run as administrator."
}

# --- 1. find the manually configured Ethernet IPv4 -----------------------
$chosen = $null
$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue |
              Where-Object { $_.Status -eq "Up" -and $_.MediaType -eq "802.3" })
# Some USB/virtual adapters report an empty or nonstandard MediaType. If the
# strict filter finds nothing, fall back to every Up adapter (still excluding
# APIPA addresses below) instead of failing outright.
if ($adapters.Count -eq 0) {
    Write-Host "  [note] no 802.3 adapter reported; widening the adapter search" -ForegroundColor DarkGray
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue |
                  Where-Object { $_.Status -eq "Up" })
}
foreach ($a in $adapters) {
    $all = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Where-Object {
                 $_.IPAddress -ne "127.0.0.1" -and
                 $_.IPAddress -notlike "169.254.*"
             })
    # Prefer the manually configured address; fall back to any non-APIPA IPv4
    # in case this Windows build reports PrefixOrigin differently.
    $cand = $all | Where-Object { $_.PrefixOrigin -eq "Manual" } | Select-Object -First 1
    if (-not $cand) { $cand = $all | Select-Object -First 1 }
    if ($cand) { $chosen = $cand; break }
}
if (-not $chosen) {
    Fail "No manually configured IPv4 found on an active Ethernet adapter. Check: ipconfig /all"
}

function PrefixToMask([int]$p) {
    $bits = ("1" * $p).PadRight(32, "0")
    $b = @()
    for ($i = 0; $i -lt 4; $i++) { $b += [Convert]::ToByte($bits.Substring($i * 8, 8), 2) }
    return ($b -join ".")
}
$IP   = $chosen.IPAddress
$MASK = PrefixToMask ([int]$chosen.PrefixLength)

Write-Host "  Windows IP  : $IP"
Write-Host "  mask        : $MASK   (/$($chosen.PrefixLength))"
Write-Host "  adapter     : $($chosen.InterfaceAlias)"
Write-Host "  port        : $PORT"
Write-Host ""
Write-Host "  COPY THESE TWO VALUES into the Mac command:" -ForegroundColor Yellow
Write-Host "     ./mac-eth-join-static.command $IP $MASK"
Write-Host ""

# --- 2. hard confirmation -------------------------------------------------
Write-Host "  ############################################################" -ForegroundColor Yellow
Write-Host "  #  CONFIRM BEFORE CONTINUING                                 #" -ForegroundColor Yellow
Write-Host "  #  - intranet cable UNPLUGGED                                #" -ForegroundColor Yellow
Write-Host "  #  - direct cable to the Mac PLUGGED into that same port     #" -ForegroundColor Yellow
Write-Host "  #  - this adapter reaches ONLY the Mac, nothing else         #" -ForegroundColor Yellow
Write-Host "  ############################################################" -ForegroundColor Yellow
Write-Host ""
$ack = Read-Host "  Type YES to continue (anything else aborts)"
if ($ack -ne "YES") {
    Write-Host "  Aborted. Nothing changed."
    exit 0
}
Write-Host ""

# --- 3. firewall ----------------------------------------------------------
netsh advfirewall firewall delete rule name="WBDrop" | Out-Null
$r = netsh advfirewall firewall add rule name="WBDrop" dir=in action=allow protocol=TCP localport=$PORT profile=public
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [WARN] firewall rule failed. Add it by hand (see README section 4)." -ForegroundColor Yellow
} else {
    Write-Host "  [ok] firewall: TCP $PORT inbound allowed on PUBLIC profile only"
}

# --- 4. tell WBDrop to bind to this address -------------------------------
# Use curl.exe with byte-exact UTF-8 files. Invoke-RestMethod in PowerShell 5.1
# decodes JSON with the wrong charset and would corrupt Chinese peer aliases.
$CURL = Get-Command curl.exe -ErrorAction SilentlyContinue
$rebound = $false
$pcode = ""
if ($CURL) {
    try {
        $tmpIn  = [IO.Path]::GetTempFileName()
        $tmpOut = [IO.Path]::GetTempFileName()
        & $CURL.Source -s --noproxy "*" --max-time 3 -o $tmpIn "http://127.0.0.1:$PORT/api/config" | Out-Null
        $raw = [IO.File]::ReadAllText($tmpIn, [Text.Encoding]::UTF8)
        if ($raw -and $raw.Contains('"config"')) {
            $obj = $raw | ConvertFrom-Json
            $c = $obj.config
            if ($null -eq $c.peers) { $c.peers = @() }
            elseif ($c.peers -isnot [array]) { $c.peers = @($c.peers) }
            $pcode = [string]$c.code
            $c.bind = $IP
            $json = $c | ConvertTo-Json -Depth 10 -Compress
            [IO.File]::WriteAllText($tmpOut, $json, (New-Object Text.UTF8Encoding($false)))
            $res = (& $CURL.Source -s --noproxy "*" --max-time 3 -X POST `
                      -H "Content-Type: application/json" `
                      --data-binary "@$tmpOut" "http://127.0.0.1:$PORT/api/config") -join ""
            $rebound = ($res -match '"ok"\s*:\s*true')
        }
        Remove-Item $tmpIn, $tmpOut -Force -ErrorAction SilentlyContinue
    } catch {
        $rebound = $false
    }
}

if ($rebound) {
    Write-Host "  [ok] WBDrop rebound to $IP (all saved peers preserved)"
    Write-Host ""
    Write-Host "  THIS MACHINE'S PAIR CODE : $pcode" -ForegroundColor Green
    Write-Host "  (give this to the Mac; the Mac fills 'peer pair code')"
} else {
    Write-Host "  [WARN] WBDrop not running on 127.0.0.1:$PORT, or curl.exe unavailable." -ForegroundColor Yellow
    Write-Host "         Start wbdrop-windows-amd64.exe, then in UI:" -ForegroundColor Yellow
    Write-Host "         Settings -> direct NIC -> pick $IP -> Save" -ForegroundColor Yellow
    Write-Host "         The pair code is shown at the top of that Settings panel." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Next:"
Write-Host "    1. Mac: run the command printed above"
Write-Host "    2. Both UIs: Settings -> add peer (alias + peer IP + peer pair code)"
Write-Host "    3. Drag files into the browser window"
Write-Host ""
Write-Host "  Cleanup when done: win-stop-link.bat is NOT needed here." -ForegroundColor DarkGray
Write-Host "  Remove the firewall rule with:" -ForegroundColor DarkGray
Write-Host "     netsh advfirewall firewall delete rule name=`"WBDrop`"" -ForegroundColor DarkGray
Write-Host ""
