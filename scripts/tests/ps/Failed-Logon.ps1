# 1. Authentication & Access
# PowerShell Script (Failed Logon – Event ID 4625)

# Authentication & Access Simulation (Failed Logon Event 4625 – MITRE T1110 Brute Force)
# This script attempts a network logon with invalid credentials to trigger a failed login event (ID 4625).
# Run as Administrator/or Regular User in a test environment. No actual account is compromised; an event is logged for monitoring.

Write-Host "[INFO] Attempting an invalid network logon to generate Event ID 4625..."
# Using 'net use' to connect to IPC$ share with wrong username/password (this will fail and log an event)
net use \\127.0.0.1\IPC$ /user:FakeUser WrongPassword 2>$null

Write-Host "[INFO] Invalid logon attempt completed. Check Security log for Event ID 4625 (failed logon)."