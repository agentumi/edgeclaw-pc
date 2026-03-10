param(
    [int]$WebPort = 9444,
    [int]$AgentPort = 8443,
    [int]$WsPort = 0,
    [int]$MaxAgents = 4,
    [string]$ConfigPath = "",
    [string]$StoragePath = ""
)

$ErrorActionPreference = "Stop"

Write-Host "== EdgeClaw release build =="
cargo build --release

if ($WsPort -le 0) {
    $WsPort = $WebPort + $MaxAgents
}
if ($WsPort -ge $WebPort -and $WsPort -lt ($WebPort + $MaxAgents)) {
    $safePort = $WebPort + $MaxAgents
    Write-Host "[Port Fix] WS port $WsPort conflicts with WebUI range $WebPort-$($WebPort + $MaxAgents - 1). Using $safePort"
    $WsPort = $safePort
}

$argParts = @()
if ($ConfigPath -ne "") {
    $argParts += "--config `"$ConfigPath`""
}
if ($StoragePath -ne "") {
    $argParts += "--storage-path `"$StoragePath`""
}
$argParts += "--port $AgentPort"
$argParts += "--web-port $WebPort"
$argParts += "--ws-port $WsPort"

$runArgs = $argParts -join " "
$watchCmd = "run --release -- start $runArgs"

Write-Host "== Watch mode =="
Write-Host "Command: cargo watch -w src -w static -w config -x `"$watchCmd`""
Write-Host "Web UI: http://127.0.0.1:$WebPort"
Write-Host "WebSocket: ws://127.0.0.1:$WsPort"
Write-Host "Press Ctrl+C to stop."

cargo watch -w src -w static -w config -x "$watchCmd"
