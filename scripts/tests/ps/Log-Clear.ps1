#3. Defense Evasion & Log Tampering
# PowerShell Script (Clear Security Log – Event ID 1102)
# Defense Evasion & Log Tampering Simulation (Clear Security Log Event 1102 – MITRE T1070.001)
# This script clears the Windows Security event log to simulate log tampering.
# Clearing the Security log always triggers Event ID 1102 ("The audit log was cleared"):contentReference[oaicite:7]{index=7}.
# Use ONLY in a test environment, as it erases the Security log. Requires Administrator.

Write-Host "[INFO] Backing up Security log to C:\Temp\SecurityLog.evtx (optional backup)..."
if (!(Test-Path "C:\Temp")) { New-Item -Path C:\Temp -ItemType Directory -Force | Out-Null }
wevtutil epl Security "C:\Temp\SecurityLog.evtx" 2>$null

Write-Host "[INFO] Clearing the Security event log to simulate log clearing (Event 1102)..."
Clear-EventLog -LogName Security

Write-Host "[INFO] Security log cleared. Event ID 1102 should be generated in Security log (audit log cleared)."