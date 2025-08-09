#1. Authentication & Access
#Batch Script (Failed Logon – Event ID 4625)

@echo off
REM Authentication & Access Simulation (Failed Logon Event 4625 – MITRE T1110 Brute Force)
REM This batch uses an invalid network logon to trigger a Security event ID 4625 (failed login):contentReference[oaicite:1]{index=1}.
REM Run as Administrator/Regular User in a test network. It is safe – the login fails and only an event is recorded.

echo [INFO] Triggering a failed login event (Event ID 4625)...
REM Attempt to connect to IPC$ share with wrong credentials to generate event 4625
net use \\127.0.0.1\IPC$ /user:FakeUser WrongPassword >NUL 2>NUL

echo [INFO] Finished. A Security log entry 4625 (account failed to log on) should be logged.
