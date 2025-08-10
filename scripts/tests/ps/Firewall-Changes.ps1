#4. Configuration Changes & System Modification
# PowerShell Script (Add/Remove Firewall Rule – Event ID 4946)
# Configuration Change Simulation (Firewall Rule Added Event 4946 – MITRE T1562.004 Defense Evasion)
# This script adds a new inbound firewall rule and then removes it.
# A Windows Security Event ID 4946 ("Firewall rule added to exception list") will be logged:contentReference[oaicite:12]{index=12}.
# Requires admin privileges. The rule opens port 9999 (as an example) and is removed immediately after.

Write-Host "[INFO] Adding a test firewall rule to trigger Event ID 4946..."
New-NetFirewallRule -DisplayName "Allow_Test_Port_9999" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9999

Write-Host "[INFO] Test firewall rule added. Now deleting the test rule for cleanup..."
Remove-NetFirewallRule -DisplayName "Allow_Test_Port_9999"

Write-Host "[INFO] Firewall rule removed. Check Security log for Event ID 4946 (firewall rule added)."