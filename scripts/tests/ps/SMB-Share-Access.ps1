#5. File Share Access (SMB)
#PowerShell Script (SMB Share Access – Event ID 5140)

# File Share Access Simulation (SMB Share Event 5140 – MITRE T1021.002 Lateral Movement)
# This script creates a temporary network share, accesses it, and then deletes the share.
# Event ID 5140 ("Network share object was accessed") will be logged on first access:contentReference[oaicite:16]{index=16}.
# Event 5142 (share added) and 5144 (share removed) may also be logged. Requires Administrator/Normal User.

Write-Host "[INFO] Creating a folder and sharing it (TestShare) to simulate SMB share access..."
New-Item -Path C:\SharedTest -ItemType Directory -Force | Out-Null
New-SmbShare -Name "TestShare" -Path "C:\SharedTest" -FullAccess "Everyone" | Out-Null

Write-Host "[INFO] Accessing the network share to trigger Event ID 5140..."
# Access the share (reading the directory) to generate the access event
Get-ChildItem '\\localhost\TestShare' > $NULL

Write-Host "[INFO] Removing the TestShare share (cleanup)..."
Remove-SmbShare -Name "TestShare" -Force

Write-Host "[INFO] Share removed. Check Security log for Event ID 5140 (network share accessed)."