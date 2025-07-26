# collect.ps1

# Step 1: Export logs to JSON
Write-Host "Exporting Windows logs to JSON..."
$logs = Get-WinEvent -LogName System, Security -MaxEvents 1000 | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ')
        Id = $_.Id
        LevelDisplayName = $_.LevelDisplayName
        Message = $_.Message
        ProviderName = $_.ProviderName
    }
}
$logPath = Join-Path $PSScriptRoot "log_data.json"
$logs | ConvertTo-Json -Depth 5 | Out-File $logPath -Encoding UTF8
Write-Host "Log data saved to $logPath"