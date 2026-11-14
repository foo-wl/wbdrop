# WBDrop - Windows side one-shot diagnosis + auto fix + end-to-end self test.
# Run in NATIVE Windows PowerShell 5.1 (not WSL). Output goes to win-fix.txt
# next to this script. Nothing on the Mac is modified by this script.
param(
    [string]$MacIP   = "10.20.30.116",
    [string]$MacCode = "123456",
    [int]$Port       = 18432
)

$ErrorActionPreference = 'SilentlyContinue'
$script:LOG = New-Object System.Collections.ArrayList

function P([string]$m) {
    [void]$script:LOG.Add($m)
    Write-Host $m
}

function Save {
    $path = Join-Path $PSScriptRoot 'win-fix.txt'
    try {
        [IO.File]::WriteAllLines($path, [string[]]$script:LOG, (New-Object Text.UTF8Encoding($false)))
        Write-Host ""
        Write-Host "SAVED: $path"
    } catch {
        Write-Host "SAVE FAILED: $($_.Exception.Message)"
    }
}

function TcpOk([string]$ip, [int]$port, [int]$ms) {
    $c = New-Object Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($ip, $port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($ms, $false)) { return $false }
        $c.EndConnect($iar)
        return $true
    } catch { return $false }
    finally { $c.Close() }
}

# Raw HTTP via .NET: bypasses curl.exe (often blocked by endpoint-control software)
# and bypasses any system proxy.
function Req([string]$url, $hdr, [int]$sec, [string]$method, [byte[]]$body) {
    if (-not $method) { $method = 'GET' }
    $r = [System.Net.HttpWebRequest]::Create($url)
    $r.Method = $method
    $r.Timeout = $sec * 1000
    $r.ReadWriteTimeout = $sec * 1000
    try { $r.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy() } catch { try { $r.Proxy = $null } catch {} }
    if ($hdr) {
        foreach ($k in $hdr.Keys) {
            if ($k -eq 'Content-Type') { $r.ContentType = [string]$hdr[$k] }
            else { $r.Headers.Add($k, [string]$hdr[$k]) }
        }
    }
    if ($body) {
        $r.ContentLength = $body.Length
        $st = $r.GetRequestStream()
        $st.Write($body, 0, $body.Length)
        $st.Close()
    }
    try {
        $resp = $r.GetResponse()
        $sr = New-Object IO.StreamReader($resp.GetResponseStream())
        $txt = $sr.ReadToEnd(); $sr.Close()
        $code = [int]$resp.StatusCode
        $date = [string]$resp.Headers['Date']
        $resp.Close()
        return [pscustomobject]@{ Code = $code; Body = $txt; Date = $date }
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($resp) {
            $sr = New-Object IO.StreamReader($resp.GetResponseStream())
            $txt = $sr.ReadToEnd(); $sr.Close()
            $code = [int]$resp.StatusCode
            $resp.Close()
            return [pscustomobject]@{ Code = $code; Body = $txt; Date = '' }
        }
        return [pscustomobject]@{ Code = 0; Body = $_.Exception.Message; Date = '' }
    } catch {
        return [pscustomobject]@{ Code = 0; Body = $_.Exception.Message; Date = '' }
    }
}

# Reproduce exactly what WBDrop's handleProbe does: HMAC-SHA256(GET\n/api/info\n<ts>)
function ProbeMac([string]$code) {
    try { $ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString() }
    catch { $ts = [string][int](Get-Date -UFormat %s) }
    $hm = New-Object System.Security.Cryptography.HMACSHA256
    $hm.Key = [Text.Encoding]::UTF8.GetBytes($code)
    $hash = $hm.ComputeHash([Text.Encoding]::UTF8.GetBytes("GET`n/api/info`n$ts"))
    $sig = -join ($hash | ForEach-Object { $_.ToString('x2') })
    $hm.Dispose()
    $h = @{ 'X-Ts' = $ts; 'X-Sig' = $sig }
    return (Req "http://${MacIP}:$Port/api/info" $h 8 'GET' $null)
}

# ------------------------------------------------------------------ main
if (-not $PSBoundParameters.ContainsKey('MacCode')) {
    $ans = Read-Host "Mac PAIR CODE shown on Mac WBDrop (Enter = $MacCode)"
    if ($ans -and $ans.Trim() -ne '') { $MacCode = $ans.Trim() }
}

P "=== WBDrop Windows fix / self test  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="
P "target = ${MacIP}:$Port   MacCode = $MacCode"

if (-not (TcpOk '127.0.0.1' $Port 1500)) {
    P "[STOP] 127.0.0.1:$Port CLOSED  ->  Windows WBDrop is NOT v2 (or is not running)."
    P "  v2/v2.0.5 ALWAYS listens on loopback. This is the classic v1 single-listener symptom."
    P "  FIX: Task Manager -> end ALL wbdrop-windows-amd64.exe -> replace with the NEW"
    P "       dist/wbdrop-windows-amd64.exe (v2.0.5) -> double-click -> KEEP the console open"
    P "       -> open http://127.0.0.1:$Port in the browser -> re-run this script."
    Save
    return
}
P "[OK] loopback listener present (v2 style)"

# Listener inventory + inbound firewall. The Mac->Win direction is INBOUND on
# this PC and gets silently dropped (TCP timeout) when the rule is missing,
# while Win->Mac (outbound) still works. Both directions are independent.
try {
    $listen = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
                ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" })
    if ($listen.Count -gt 0) { P "LOCAL LISTEN: $($listen -join ', ')" }
} catch {}
try {
    $rules = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
               Where-Object { $_.DisplayName -like '*WBDrop*' -or $_.Name -like '*WBDrop*' })
    if ($rules.Count -gt 0) {
        P "FW INBOUND: $(($rules | ForEach-Object { $_.DisplayName }) -join ', ')"
    } else {
        P "[WARN] no enabled inbound allow-rule named WBDrop."
        P "       Mac -> Win SYNs may be DROPPED (i/o timeout) even though Win -> Mac works."
        P "       FIX: right-click win-prepare-static.bat -> Run as administrator -> type YES."
    }
} catch {
    P "[INFO] firewall rule query unavailable: $($_.Exception.Message)"
}

$g = Req "http://127.0.0.1:$Port/api/config" $null 6 'GET' $null
if ($g.Code -ne 200) {
    P "[STOP] /api/config returned HTTP $($g.Code) : $($g.Body)"
    P "  The process holding 127.0.0.1:$Port is not WBDrop v2. Replace the exe."
    Save
    return
}
try { $c = $g.Body | ConvertFrom-Json } catch {
    P "[STOP] /api/config is not valid JSON: $($g.Body)"
    Save
    return
}
$cfg = $c.config
P "[OK] version=$($c.version)  bind=$($c.ip)  myCode=$($cfg.code)  active=$($cfg.active)"
if ([string]$c.version -lt '2.0.5') {
    P "[WARN] older than v2.0.5 - upgrade after this test. v2.0.4 fixes a 1.5s probe timeout"
    P "       and reports the real transport error in 'detail'; v2.0.5 ships SIGNED macOS"
    P "       binaries (an unsigned one gets inbound connections closed -> HTTP EOF)."
}
$peers = @($cfg.peers)
if ($peers.Count -eq 0) { P "  PEERS: (none)" }
foreach ($p in $peers) {
    P ("  PEER alias={0} ip={1} port={2} code={3} id={4}" -f $p.alias, $p.ip, $p.port, $p.code, $p.id)
}
P "  allIPs(local) = $(($c.allIPs | ForEach-Object { $_.ip }) -join ',')"

# 0) Plain unsigned GET / - no auth, no custom headers. Compare with the
#    signed /api/info below: plain=200 but signed=EOF means the request
#    itself (headers/path), NOT the network, is being rejected.
$plain = Req "http://${MacIP}:$Port/" $null 8 'GET' $null
P "DIRECT(to Mac) PLAIN GET /     -> HTTP $($plain.Code)  bytes=$($plain.Body.Length)"
if ($plain.Code -eq 200) { P "  [OK] plain HTTP to the Mac works - the link and Mac listener are fine." }
else { P "  [INFO] plain HTTP also failed - suspect link/firewall, not WBDrop auth." }

# 1) Direct signed request to the Mac, with the code shown on the Mac.
$r0 = ProbeMac $MacCode
P "DIRECT(to Mac) with MacCode  -> HTTP $($r0.Code)  $($r0.Body)"
if ($r0.Date) {
    try {
        $mt = [DateTime]::Parse($r0.Date).ToUniversalTime()
        $skew = [math]::Abs(([DateTime]::UtcNow - $mt).TotalSeconds)
        P "CLOCK SKEW = $([int]$skew)s  (signature window is +/-300s)"
        if ($skew -gt 240) { P "[WARN] clocks differ too much - sync the Windows clock (or set it manually)." }
    } catch {}
}

$saved = $peers | Where-Object { $_.ip -eq $MacIP } | Select-Object -First 1
$r1 = $null
if ($saved) {
    $r1 = ProbeMac ([string]$saved.code)
    P "DIRECT(to Mac) with saved code -> HTTP $($r1.Code)  $($r1.Body)"
}

$needFix = $false
if (-not $saved) {
    $needFix = $true
    P "[FIX] no peer with ip=$MacIP -> will add one."
} elseif ($r1.Code -eq 401 -and $r0.Code -eq 200) {
    $needFix = $true
    P "[FIX] saved pair code is WRONG (401), MacCode works (200) -> will correct it."
} elseif ($r1.Code -eq 200) {
    P "[OK] saved pair code already matches the Mac."
} else {
    P "[INFO] could not confirm saved code (HTTP $($r1.Code)); will still try probe."
}

# 2) Auto-correct the Windows config through its own loopback API.
if ($needFix) {
    if ($r0.Code -ne 200) {
        P "[STOP] MacCode itself returned HTTP $($r0.Code) - cannot auto-fix."
        P "  Check: Mac PAIR CODE (shown in Mac WBDrop UI), clocks, macOS firewall."
        Save
        return
    }
    if (-not $saved) {
        $id = -join (1..16 | ForEach-Object { '0123456789abcdef'[(Get-Random -Max 16)] })
        $newp = [pscustomobject]@{ id = $id; alias = 'Mac'; ip = $MacIP; port = $Port; code = $MacCode }
        $peers = @($peers) + @($newp)
    } else {
        $saved.code = $MacCode
    }
    $cfg.peers = @($peers)
    $cfg.active = ($peers | Where-Object { $_.ip -eq $MacIP } | Select-Object -First 1).id
    # A stale bind (wrong IP / link was down) makes POST /api/config fail with 400.
    $localIPs = @($c.allIPs | ForEach-Object { [string]$_.ip })
    if ($cfg.bind -and ($localIPs -notcontains [string]$cfg.bind)) {
        $pick = $localIPs | Where-Object { $_ -like '10.20.30.*' } | Select-Object -First 1
        if (-not $pick) { $pick = '' }
        P "[FIX] stale bind '$($cfg.bind)' not on this PC -> set to '$pick'"
        $cfg.bind = $pick
    }
    $json = $cfg | ConvertTo-Json -Depth 8 -Compress
    $body = [Text.Encoding]::UTF8.GetBytes($json)
    $post = Req "http://127.0.0.1:$Port/api/config" @{ 'Content-Type' = 'application/json' } 10 'POST' $body
    P "[FIX] POST /api/config -> HTTP $($post.Code)  $($post.Body)"
    if ($post.Code -ne 200) {
        P "[STOP] config write rejected. Fix it manually in the browser settings page."
        Save
        return
    }
    $g2 = Req "http://127.0.0.1:$Port/api/config" $null 6 'GET' $null
    $c = $g2.Body | ConvertFrom-Json
    $cfg = $c.config
    $peers = @($cfg.peers)
    P "[FIX] saved. peers now = $(($peers | ForEach-Object { "$($_.ip):$($_.port)/$($_.code)" }) -join ', ')"
}

$active = [string]$cfg.active
if (-not $active) {
    $active = [string]($peers | Select-Object -First 1).id
    P "[INFO] active was empty, using first peer id=$active"
}

# 3) What the UI actually calls when you click "save and test".
$pr = Req "http://127.0.0.1:$Port/api/probe?id=$active" $null 12 'GET' $null
P "PROBE(local API) -> HTTP $($pr.Code)  $($pr.Body)"
$state = ''
try { $state = [string](($pr.Body | ConvertFrom-Json).state) } catch {}
P "PROBE STATE = '$state'   (ok = fully working; oneway = Mac cannot reach this PC; badcode = pair code; offline = HTTP request failed/closed)"

# 4) Real 1KB transfer Win -> Mac. Success is visible on the Mac in ~/Downloads/WBDrop/.
if ($state -eq 'ok') {
    $txt = "WBDrop self test $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n"
    $bytes = [Text.Encoding]::UTF8.GetBytes($txt)
    $url = "http://127.0.0.1:${Port}/api/send?peer=$active&name=wbdrop-selftest.txt&size=$($bytes.Length)"
    $sr = Req $url @{ 'Content-Type' = 'application/octet-stream' } 45 'POST' $bytes
    P "SEND SELFTEST -> HTTP $($sr.Code)  $($sr.Body)"
    if ($sr.Code -eq 200) { P "[DONE] transfer succeeded - check ~/Downloads/WBDrop/wbdrop-selftest.txt on the Mac." }
    else { P "[FAIL] transfer rejected - send the whole win-fix.txt back for analysis." }
} else {
    P "[SKIP] self test not run because probe state is not ok. Running deep diagnosis instead."

    # A bad pair code returns HTTP 401, it does NOT close the socket. Two
    # independent clients (Go probe + .NET) reporting "connection closed"
    # points at the transport, not WBDrop auth. On macOS the usual cause is
    # an UNSIGNED binary: the Application Firewall accepts then closes inbound
    # connections without writing a byte. Split it into layers:
    #   a) GET / has no auth at all -> if this works, Mac WBDrop CAN answer us
    #   b) raw TCP HTTP/1.0 -> shows exactly what bytes come back (if any)
    #   c) local /api/send -> WBDrop returns Go's underlying dial/read error
    $root = Req "http://${MacIP}:$Port/" $null 8 'GET' $null
    P "DEEP root / (no auth)      -> HTTP $($root.Code)  bytes=$($root.Body.Length)"
    if ($root.Code -eq 200) {
        P "  => Mac WBDrop CAN serve this PC. The fault is in /api/* auth/signing, not the link."
    }

    $c = New-Object Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($MacIP, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(6000, $false)) {
            P "DEEP raw TCP               -> CONNECT TIMEOUT"
        } else {
            $c.EndConnect($iar)
            $st = $c.GetStream()
            $st.ReadTimeout = 6000
            $st.WriteTimeout = 6000
            $rq = "GET /api/info HTTP/1.0`r`nHost: ${MacIP}:$Port`r`nConnection: close`r`n`r`n"
            $bb = [Text.Encoding]::ASCII.GetBytes($rq)
            $st.Write($bb, 0, $bb.Length)
            $buf = New-Object byte[] 4096
            $n = $st.Read($buf, 0, 4096)
            if ($n -le 0) {
                P "DEEP raw GET /api/info    -> EOF (peer closed the socket before any response byte)"
            } else {
                $one = ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -replace "`r`n", ' | ')
                P "DEEP raw GET /api/info    -> $one"
            }
        }
    } catch {
        P "DEEP raw GET /api/info    -> RAW-ERR $($_.Exception.Message)"
    } finally { $c.Close() }

    $diagBody = [Text.Encoding]::ASCII.GetBytes('diag')
    $sd = Req "http://127.0.0.1:${Port}/api/send?peer=$active&name=diag.txt&size=4" `
              @{ 'Content-Type' = 'application/octet-stream' } 20 'POST' $diagBody
    P "DEEP /api/send (Go error) -> HTTP $($sd.Code)  $($sd.Body)"

    $tn = Test-NetConnection -ComputerName $MacIP -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue
    P "DEEP Test-NetConnection   -> $tn  (True = TCP handshake completes)"
    $arpLine = @(& arp.exe -a | Select-String -SimpleMatch $MacIP)
    if ($arpLine.Count -gt 0) { P "DEEP arp -a                -> $($arpLine[0].Line.Trim())" }
    else { P "DEEP arp -a                -> no entry for $MacIP" }
    P "DEEP interpretation:"
    P "  TCP OK but ZERO response bytes, root / also EOF, Mac->Win works:"
    P "    => macOS Application Firewall closes INBOUND connections to an UNSIGNED"
    P "       WBDrop binary. Each rebuilt exe gets a new code identity, so the old"
    P "       'allow incoming' rule stops matching (getappblocked may still say permitted)."
    P "    FIX: on the Mac replace with dist/wbdrop-macos-amd64 v2.0.5 (ad-hoc signed"
    P "       by build.sh), QUIT the running WBDrop and start it again. Check with:"
    P "         codesign -dvv <binary>   # must show Signature=adhoc"
    P "       Changing the port or re-adding firewall rules does NOT help."
    P "  root / OK but signed /api/info closed -> pair code or clock skew (>300s)"
    P "  raw CONNECT TIMEOUT -> Mac not listening on the direct IP, or link down"
}

P "NOTE: this script tests the Win -> Mac direction (outbound on this PC)."
P "      The Mac -> Win direction is INBOUND here. If the Mac still reports"
P "      'offline' when probing this PC, the Windows inbound firewall is the cause:"
P "      right-click win-prepare-static.bat -> Run as administrator -> type YES."
P "      Keep the WBDrop console window OPEN the whole time."
P "=== END ==="
Save
