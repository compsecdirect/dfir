@echo off
REM #2. Persistence & Privilege Escalation
REM Batch Script (New Service – Event ID 7045)
REM Persistence & Privilege Escalation Simulation (New Service Event 7045 – MITRE T1543.003 Windows Service)
REM Creates and deletes a dummy service to generate System Event ID 7045 ("A new service was installed"):contentReference[oaicite:5]{index=5}.
REM Requires admin privileges. Safe to run: the service uses an existing benign executable and is removed immediately.

echo [INFO] Creating a test service to trigger Event 7045...
sc create TestService binPath= "C:\Windows\System32\svchost.exe -k netsvcs" start= demand

echo [INFO] Test service created. Deleting the test service for cleanup...
sc delete TestService

echo [INFO] Service removed. Check the System event log for ID 7045 (New service was installed in the system).