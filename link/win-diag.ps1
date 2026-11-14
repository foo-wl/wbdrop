# WBDrop - Windows side connectivity diagnostic (read-only).
# All output is ASCII on purpose: PowerShell 5.1 misreads UTF-8 without BOM.
#
# Use when "Mac can reach Windows, but Windows cannot reach Mac".
# It checks, layer by layer:
#   1. this machine's running WBDrop (version, bind, peers, pair codes)
#      -- tries BOTH 127.0.0.1 and the direct-link IP, so v1's single-listener
#         layout is detected instead of being reported as "not running"
#   2. IP layer  : ping + ARP entry for the Mac
#   3. TCP layer : sockets to 127.0.0.1, this PC's LAN IP, and the Mac
#   4. HTTP layer: GET /api/info on the Mac. NOTE: an unsigned request from a
#      remote host is EXPECTED to get 401 (auth wrapper). 200 or 401 both mean
#      "the Mac service is alive"; 000 means the HTTP exchange never completed.
#   5. WBDrop's own /api/probe result (HMAC auth included)
#   6. Windows firewall profiles + inbound rules (named AND per-program)
#
# It does NOT change any setting, IP, firewall rule or config file.
# A copy of the report is written next to this script as win-diag.txt.

$ErrorActionPreference = "Continue"
[System.Net.WebRequest]::DefaultWebProxy = $null

$PORT    = if ($env:WBDROP_PORT)     { [int]$env:WBDROP_PORT } else { 18432 }
$MACIP   = if ($env:WBDROP_MAC_IP)   { $env:WBDROP_MAC_IP }   else { "10.20.30.116" }
$WINIP   = if ($env:WBDROP_WIN_IP)   { $env:WBDROP_WIN_IP }   else { "10.20.30.216" }
$MACCODE = if ($env:WBDROP_MAC_CODE) { $env:WBDROP_MAC_CODE } else { "123456" }

$lines = New-Object System.Collections.Generic.List[string]
function P([string]$s) { Write-Host $s; $lines.Add($s) }
function Sec([string]$s) { P ""; P "--- $s ---" }

function TestTcp([string]$ip, [int]$port, [int]$ms) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($ip, $port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($ms, $false)) { return $false }
        $c.EndConnect($iar) | Out-Null
        return $true
    } catch { return $false }
    finally { $c.Close() }
}

# .NET HTTP check: independent of curl.exe, which is sometimes blocked by
# endpoint-control software on managed intranet PCs.
function HttpCode([string]$url, [int]$ms) {
    try {
        $req = [Net.HttpWebRequest]::Create($url)
        $req.Proxy = $null
        $req.Timeout = $ms
        $req.ReadWriteTimeout = $ms
        $req.UserAgent = "WBDrop-Diag"
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        $resp.Close()
        return [string]$code
    } catch [Net.WebException] {
        if ($_.Exception.Response) {
            try { return [string][int]$_.Exception.Response.StatusCode }
            catch { return "401?" }
        }
        return "ERR:" + $_.Exception.Status
    } catch { return "ERR" }
}

$CURL = Get-Command curl.exe -ErrorAction SilentlyContinue
function HttpGet([string]$url, [int]$sec, [switch]$WithCode) {
    if (-not $CURL) { return "(curl.exe unavailable)" }
    try {
        if ($WithCode) {
            $r = (& $CURL.Source -s --noproxy "*" --max-time $sec -w " HTTP=%{http_code}" $url) -join ""
        } else {
            # Plain body only: -w would append text and break ConvertFrom-Json.
            $r = (& $CURL.Source -s --noproxy "*" --max-time $sec $url) -join ""
        }
        return $r
    } catch { return "(request failed: $($_.Exception.Message))" }
}

P "WBDrop Windows diagnostic  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
P "target Mac IP : $MACIP    this PC LAN IP: $WINIP    port: $PORT"
P "expected Mac pair code: $MACCODE"
P "NOTE: run this in native Windows PowerShell, NOT inside WSL / a proxy shell."

# --- 1. local WBDrop config ----------------------------------------------
Sec "1. Local WBDrop config"
$rawCfg = HttpGet "http://127.0.0.1:$PORT/api/config" 4
$API    = "http://127.0.0.1:$PORT"
$viaLan = $false
if ($rawCfg -notmatch '"config"') {
    $rawLan = HttpGet "http://${WINIP}:$PORT/api/config" 4
    if ($rawLan -match '"config"') {
        $rawCfg = $rawLan
        $API    = "http://${WINIP}:$PORT"
        $viaLan = $true
        P "  127.0.0.1:$PORT : no answer"
        P "  ${WINIP}:$PORT : answered  <-- WBDrop listens ONLY on the LAN IP"
        P "  [WARN] This is v1 (single listener), or v2 started with an old -bind layout."
        P "         v2 always listens on 127.0.0.1 too. Replace the .exe with"
        P "         dist/wbdrop-windows-amd64.exe (2.0.2), quit the old process,"
        P "         and relaunch. v1's browser-side cross-origin fetch is a known"
        P "         cause of 'Windows cannot reach the Mac'." 
    }
}
$cfgOk  = $false
$active = ""
$bind   = ""
$ver    = ""
$localCode = ""
if ($rawCfg -match '"config"') {
    try {
        $o = $rawCfg | ConvertFrom-Json
        $cfgOk = $true
        $ver       = [string]$o.version
        $bind      = [string]$o.ip
        $localCode = [string]$o.config.code
        $active    = [string]$o.config.active
        P "  API base  : $API"
        P "  version   : $(if ($ver) { $ver } else { '(none -> v1 binary)' })"
        P "  name      : $($o.name)"
        P "  bind / ip : $bind   (config.bind = $($o.config.bind))"
        P "  local pair code (give to Mac) : $localCode"
        P "  all local IPs: $(($o.allIPs | ForEach-Object { "$($_.ip) [$($_.iface)]" }) -join ', ')"
        $peers = @($o.config.peers | Where-Object { $_ -and $_.ip })
        P "  peers count: $($peers.Count)   active: $active"
        foreach ($p in $peers) {
            P "    -> alias=$($p.alias)  ip=$($p.ip)  port=$($p.port)  code=$($p.code)  id=$($p.id)"
            if ([string]$p.ip -ne $MACIP) { P "       [WARN] peer IP is not the Mac's direct-link IP ($MACIP)" }
            if ([string]$p.code -ne $MACCODE) { P "       [WARN] peer code is not the Mac's pair code ($MACCODE) - fill the OTHER machine's code here" }
        }
        if ($peers.Count -eq 0) { P "    [WARN] no peer saved yet" }
        if ($bind -ne $WINIP) { P "  [WARN] bind IP is not $WINIP; check Settings -> direct NIC" }
    } catch { P "  [WARN] JSON parse failed: $($_.Exception.Message)" }
} else {
    P "  [FAIL] WBDrop is NOT running on either 127.0.0.1:$PORT or ${WINIP}:$PORT"
    P "  raw(127): $rawCfg"
}

# --- 2. IP layer ----------------------------------------------------------
Sec "2. IP layer (ping + ARP)"
$ping = & ping.exe -n 2 -w 1000 $MACIP 2>&1 | Out-String
P ($ping.Trim() -split "`r?`n" | ForEach-Object { "  $_" })
$arp = & arp.exe -a 2>&1 | Select-String -SimpleMatch $MACIP
if ($arp) { $arp | ForEach-Object { P "  ARP: $($_.ToString().Trim())" } }
else      { P "  ARP: no entry for $MACIP (Windows never resolved the Mac)" }

# --- 3. TCP layer ---------------------------------------------------------
Sec "3. TCP layer"
$tcpLoop = TestTcp "127.0.0.1" $PORT 1500
$tcpSelf = TestTcp $WINIP     $PORT 1500
$tcpMac  = TestTcp $MACIP     $PORT 3000
P "  127.0.0.1:$PORT : $(if ($tcpLoop) {'OPEN'} else {'CLOSED'})"
P "  ${WINIP}:$PORT : $(if ($tcpSelf) {'OPEN'} else {'CLOSED'})"
P "  ${MACIP}:$PORT : $(if ($tcpMac) {'OPEN  <-- Mac is reachable as a server'} else {'CLOSED / TIMEOUT  <-- inbound path is blocked'})"

# --- 4. HTTP layer --------------------------------------------------------
Sec "4. HTTP layer (GET /api/info on the Mac)"
P "  Expected for an unsigned remote request: 401 (auth is working)."
$codeDotNet = HttpCode "http://${MACIP}:$PORT/api/info" 5000
P "  .NET HttpWebRequest : HTTP $codeDotNet"
$info = HttpGet "http://${MACIP}:$PORT/api/info" 5 -WithCode
P "  curl.exe            : $info"

# --- 5. WBDrop probe ------------------------------------------------------
Sec "5. WBDrop probe (same request the UI's 'Save and test' makes)"
if ($cfgOk -and $active) {
    $pr = HttpGet "$API/api/probe?id=$active" 10
    P "  $pr"
} else {
    P "  skipped (no active peer / WBDrop not running)"
}

# --- 6. firewall ----------------------------------------------------------
Sec "6. Windows firewall"
try {
    Get-NetConnectionProfile -ErrorAction Stop |
        ForEach-Object { P "  profile: $($_.InterfaceAlias) -> $($_.NetworkCategory)" }
} catch { P "  Get-NetConnectionProfile unavailable" }
try {
    Get-NetFirewallProfile -ErrorAction Stop |
        ForEach-Object { P "  $($_.Name): enabled=$($_.Enabled) in=$($_.DefaultInboundAction) out=$($_.DefaultOutboundAction)" }
} catch { P "  Get-NetFirewallProfile unavailable" }
$rule = & netsh.exe advfirewall firewall show rule name="WBDrop" 2>&1 | Out-String
if ($rule -match "WBDrop") { P "  named rule 'WBDrop': PRESENT" }
else                       { P "  named rule 'WBDrop': MISSING (win-prepare-static.bat adds it)" }
$allRules = & netsh.exe advfirewall firewall show rule name=all 2>&1 | Out-String
if ($allRules -match '(?i)wbdrop') {
    P "  per-program WBDrop rule: PRESENT (Windows may have auto-created it on first run)"
} else {
    P "  per-program WBDrop rule: none found"
}

# --- verdict --------------------------------------------------------------
Sec "VERDICT"
if ($viaLan) {
    P "  ROOT CAUSE: Windows is running an OLD single-listener WBDrop."
    P "  127.0.0.1 is not listening, so the v2 backend-proxy UI never existed here;"
    P "  v1 makes the browser fetch the peer IP directly and that fails."
    P "  FIX: quit that process, replace the .exe with v2.0.2 from dist/, relaunch,"
    P "       then open http://127.0.0.1:18432 and re-add the peer."
} elseif (-not $cfgOk) {
    P "  WBDrop is not running on Windows (neither 127.0.0.1 nor $WINIP answers)."
    P "  FIX: double-click dist/wbdrop-windows-amd64.exe and KEEP the console window"
    P "       open, then run win-prepare-static.bat as administrator."
} elseif (-not $tcpMac) {
    P "  Windows cannot open a TCP socket to the Mac. Network layer above is good"
    P "  on the Mac side, so check macOS application firewall / Windows outbound."
    P "  On the Mac: ./mac-firewall-allow.command, then restart WBDrop."
} elseif ($codeDotNet -ne "401" -and $codeDotNet -ne "200" -and $info -notmatch "HTTP=(401|200)") {
    P "  TCP handshake succeeds but no HTTP response arrived. curl.exe may be"
    P "  blocked by endpoint-control software; the .NET result above is the"
    P "  reliable one. Check Mac-side ALF and Windows EDR."
} else {
    P "  Network + Mac service are fine. If 'Save and test' still fails, the problem"
    P "  is the saved peer IP / pair code (see [WARN] lines in section 1), or the"
    P "  Windows inbound firewall rule for the Mac's connection."
    P "  Mac pair code must be $MACCODE; Windows pair code is $localCode."
}
P ""
P "Report saved to: $PSScriptRoot\win-diag.txt"
P "Send this file (or paste this window) back for the next step."

$out = Join-Path $PSScriptRoot "win-diag.txt"
[IO.File]::WriteAllText($out, (($lines -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($false)))
