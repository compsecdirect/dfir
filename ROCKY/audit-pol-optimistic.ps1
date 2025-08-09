# Audit Policy Changes
# Un-Tested
# Should run before incidents as some logging in ROCKY is non-default

# Test 4: Configuration Changes & System Modification

Write-Host "[INFO] Enabling audit for firewall rule changes (MPSSVC Rule-Level)..."
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable 2>$null

# Test 5: File Share Access (SMB)

auditpol /set /subcategory:"File System" /success:enable /failure:enable 2>$null
auditpol /set /subcategory:"File Share" /success:enable /failure:enable 2>$null
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable 2>$null

# Test 6: Object Access (Permission Changes)
# Issue here is setting what to monitor as C:\ or a drive letter is too broad.

auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable 2>$null