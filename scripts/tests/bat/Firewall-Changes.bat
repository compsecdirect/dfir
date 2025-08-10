@echo off
REM #4. Configuration Changes & System Modification
REM Batch Script (Add/Remove Firewall Rule – Event ID 4946)
REM Configuration Change Simulation (Firewall Rule Added Event 4946 – MITRE T1562.004 Defense Evasion)
REM This batch uses netsh to add and then remove a firewall rule.
REM Adding a rule triggers Event ID 4946 in Security log ("Windows Firewall rule added"):contentReference[oaicite:13]{index=13}, indicating a policy change.
REM Run as Administrator. The rule (allowing TCP port 9999 inbound) is temporary and will be removed.

echo [INFO] Adding a test inbound firewall rule on port 9999...
netsh advfirewall firewall add rule name="Allow_Test_Port_9999" dir=in action=allow protocol=TCP localport=9999 >NUL

echo [INFO] Firewall rule added. Now deleting the test rule...
netsh advfirewall firewall delete rule name="Allow_Test_Port_9999" >NUL

echo [INFO] Firewall rule removed. Security Event ID 4946 should have been logged for the addition.