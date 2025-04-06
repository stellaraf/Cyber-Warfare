# Configuration
$DomainOU = "OU=CTFUsers,DC=l33thackers,DC=stellar,DC=tech"
$DONT_REQ_PREAUTH = 4194304

# Get users in the OU with their userAccountControl flag
$users = Get-ADUser -SearchBase $DomainOU -Filter * -Properties SamAccountName, userAccountControl

# Filter for users with pre-auth disabled
$asrepUsers = $users | Where-Object {
    ($_.userAccountControl -band $DONT_REQ_PREAUTH) -eq $DONT_REQ_PREAUTH
}

# Output
Write-Host "`n[!] Users with Kerberos Pre-Auth DISABLED (AS-REP vulnerable):"

if ($asrepUsers.Count -eq 0) {
    Write-Host "(None found)"
} else {
    $asrepUsers | ForEach-Object {
        Write-Host "$($_.SamAccountName)"
    }
}
