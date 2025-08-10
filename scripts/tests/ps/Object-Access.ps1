#6. Object Access (Permission Changes)

#PowerShell Script (File Permission Change – Event ID 4670)
# Object Access Simulation (Permission Change Event 4670 – MITRE T1222 File Permissions Modification)
# This script enables auditing for file permissiochanges, then creates a test file and modifies its ACL.
# Adding/removing an ACE triggers Security Event ID 4670 ("Permissions on an object were changed"):contentReference[oaicite:20]{index=20}.
# Requires Administrator. Changes are reverted and the test file is removed.

Write-Host "[INFO] Creating a test file for ACL modification..."
New-Item -Path "C:\ACLTestFolder" -ItemType Directory -Force | Out-Null
New-Item -Path "C:\ACLTestFolder\PermTest.txt" -ItemType File -Force | Out-Null

Write-Host "[INFO] Changing file permissions to trigger Event 4670 (adding Everyone:F access)..."
icacls "C:\ACLTestFolder\PermTest.txt" /grant Everyone:F  >$NULL

Write-Host "[INFO] Reverting permission change (removing Everyone access)..."
icacls "C:\ACLTestFolder\PermTest.txt" /remove:g Everyone  >$NULL

Write-Host "[INFO] Cleaning up test file..."
Remove-Item -Path "C:\ACLTestFolder" -Recurse -Force

Write-Host "[INFO] Done. Security Event ID 4670 should be logged for the permission change on the object."