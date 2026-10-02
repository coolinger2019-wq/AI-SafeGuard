# One-click node console: opens SSH tunnel + browser (web console, F760).
# Optional -gui switch launches the egui remote console instead.
# Requires: asg-vps SSH alias (~/.ssh/config) and ~/aisafe-node.token
$ErrorActionPreference = 'Stop'

$localPort = 17420
$forward   = "${localPort}:127.0.0.1:7420"   # local port -> node loopback API
$exe       = 'C:\code\AI-safe\target\release\aisafeguard.exe'
$tokenFile = "$HOME\aisafe-node.token"
$url       = "http://127.0.0.1:$localPort/"

if ($args -contains '-gui' -and -not (Test-Path $tokenFile)) {
    throw "missing token file: $tokenFile (scp asg-vps:/var/lib/aisafeguard/api-token ~/aisafe-node.token)"
}

# Reuse a live tunnel (e.g. leftover from a previous crash), otherwise open one
$tun = $null
if (-not (Get-NetTCPConnection -LocalPort $localPort -State Listen -ErrorAction SilentlyContinue)) {
    $tun = Start-Process ssh -ArgumentList '-N','-o','BatchMode=yes','-L',$forward,'asg-vps' -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 2
    if ($tun.HasExited) { throw "SSH tunnel failed to start (check asg-vps alias / key)" }
}

if ($args -contains '-gui') {
    try {
        & $exe --remote $url --token-file $tokenFile
    } finally {
        if ($tun -and -not $tun.HasExited) { Stop-Process -Id $tun.Id -Force -ErrorAction SilentlyContinue }
    }
} else {
    # Web console: tunnel stays up (browser needs it); closing the tab is enough,
    # stale tunnels get reused next time.
    Start-Process $url
    Write-Host "Console opened at $url (tunnel kept running; rerun anytime - it reuses the tunnel)"
}
