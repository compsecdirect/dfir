@echo off
REM #3. Defense Evasion & Log Tampering
REM Batch Script (Clear Security Log – Event ID 1102)
REM Defense Evasion & Log Tampering Simulation (Clear Security Log Event 1102 – MITRE T1070.001)
REM This batch clears the Security event log. Windows will log Event ID 1102 ("The audit log was cleared"):contentReference[oaicite:8]{index=8}.
REM Admin rights are required. Only run in a test environment, as it deletes the Security log contents.

echo [INFO] (Optional) Backing up Security log to C:\Temp\SecurityLog.evtx...
IF NOT EXIST C:\Temp\ NUL ( mkdir C:\Temp )
wevtutil epl Security C:\Temp\SecurityLog.evtx

echo [INFO] Clearing the Security event log to trigger Event 1102...
wevtutil cl Security

echo [INFO] Security log cleared. Event ID 1102 (Security log cleared) should now be present in the Security log.