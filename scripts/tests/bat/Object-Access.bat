@echo off
REM 6. Object Access (Permission Changes)
REM Batch Script (File Permission Change – Event ID 4670)
REM Object Access Simulation (Permission Change Event 4670 – MITRE T1222 File Permissions Modification)
REM This batch enables file auditing, then creates a file and modifies its permissions.
REM Changing the ACL triggers Security Event ID 4670 ("Permissions on an object were changed"):contentReference[oaicite:21]{index=21}.
REM Requires admin/user rights. The permission change is reverted and the test file is deleted at the end.

echo [INFO] Creating test file C:\ACLTestFolder\PermTest.txt...
md C:\ACLTestFolder 2>NUL
echo DummyData> C:\ACLTestFolder\PermTest.txt

echo [INFO] Modifying file ACL to add Everyone Full control (triggers Event 4670)...
icacls "C:\ACLTestFolder\PermTest.txt" /grant Everyone:F >NUL

echo [INFO] Reverting ACL change by removing Everyone access...
icacls "C:\ACLTestFolder\PermTest.txt" /remove:g Everyone >NUL

echo [INFO] Deleting test file and folder...
del C:\ACLTestFolder\PermTest.txt >NUL
rd C:\ACLTestFolder

echo [INFO] Done. A Security Event ID 4670 should have been generated for the permission change.
