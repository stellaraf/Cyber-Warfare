# Define the OU to target
$DomainOU = "OU=CTFUsers,DC=l33thackers,DC=stellar,DC=tech"

# Get all users in the OU
$users = Get-ADUser -SearchBase $DomainOU -Filter *

# Confirm before deletion
Write-Host "Found $($users.Count) users in $DomainOU."
Read-Host "Press ENTER to continue with deletion or Ctrl+C to cancel"

# Delete each user
foreach ($user in $users) {
    try {
        Remove-ADUser -Identity $user.DistinguishedName -Confirm:$false
        Write-Host "[+] Deleted user: $($user.SamAccountName)"
    }
    catch {
        Write-Warning "[-] Failed to delete user $($user.SamAccountName): $($_.Exception.Message)"
    }
}
