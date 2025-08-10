# Audit Policy Changes
# Un-Tested
# Should run before incidents as some logging in ROCKY is non-default

# Test 4: Configuration Changes & System Modification

Write-Host "[INFO] Enabling audit for firewall rule changes (MPSSVC Rule-Level)..."
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable

# Test 5: File Share Access (SMB)

auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable

# Test 6: Object Access (Permission Changes)
# Issue here is setting what to monitor as C:\ or a drive letter is too broad.

auditpol /resourceSACL /set /type:File /user:Everyone /success /failure /access:FRFW

