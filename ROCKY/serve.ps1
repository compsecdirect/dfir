# serve.ps1

<##
[NON-ADMIN SCRIPT]
This script launches a local Python web server to view the EVTX visualizer.
Requires Python to be installed (can be local or in PATH).
##>

$port = 8000
$projectRoot = $PSScriptRoot

$pythonCmd = Join-Path $projectRoot "python.exe"

if (Get-Command python -ErrorAction SilentlyContinue) {
    Write-Host "[+] Starting Python HTTP server on port $port using global Python..."
    python -m http.server $port
} elseif (Test-Path $pythonCmd) {
    Write-Host "[+] Starting Python HTTP server on port $port using local python.exe..."
    python.exe -m http.server $port
} else {
    Write-Warning "Python not found. Please install Python or use another method to host the visualizer."
    Write-Host "Manual start:"
    Write-Host "  cd '$projectRoot'"
    Write-Host "  python -m http.server $port"
}
