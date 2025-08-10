@echo off
REM #5. File Share Access (SMB)
REM Batch Script (SMB Share Access – Event ID 5140)
REM File Share Access Simulation (SMB Share Event 5140 – MITRE T1021.002 Lateral Movement)
REM This batch creates a network share, accesses it, then deletes it.
REM The first access generates Security Event ID 5140 ("A network share object was accessed"):contentReference[oaicite:17]{index=17}.
REM Also logs Event 5142 (share created) and 5144 (share deleted). Run as Administrator.

echo [INFO] Creating a test folder and sharing it as 'TestShare'...
md C:\SharedTest 2>NUL
net share TestShare=C:\SharedTest /grant:Everyone,full >NUL

echo [INFO] Accessing the network share to trigger Event 5140...
dir \\%COMPUTERNAME%\TestShare >NUL

echo [INFO] Deleting the 'TestShare' network share and cleaning up...
net share TestShare /delete /y >NUL
rd C:\SharedTest

echo [INFO] Share removed. Event ID 5140 should be logged (share was accessed). Check Security log.