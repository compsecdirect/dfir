#2. Persistence & Privilege Escalation
#PowerShell Script (New Service – Event ID 7045)
# Persistence & Privilege Escalation Simulation (New Service Event 7045 – MITRE T1543.003 Windows Service)
# This script creates a temporary Windows service and then deletes it.
# Event ID 7045 ("A service was installed in the system") will be logged:contentReference[oaicite:4]{index=4}.
# Requires Administrator privileges. The service is not started and is removed immediately.

Write-Host "[INFO] Creating a test service to trigger Event ID 7045 (service installed)..."
sc.exe create TestService binPath= "C:\Windows\System32\svchost.exe -k netsvcs" start= demand

Write-Host "[INFO] Service 'TestService' created. It will now be deleted (cleanup)..."
sc.exe delete TestService

Write-Host "[INFO] Cleanup done. Check System log for Event ID 7045 (New service installation)."