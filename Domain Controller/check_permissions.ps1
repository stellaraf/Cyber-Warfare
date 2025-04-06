# Verify group delegation and permissions in the domain

# --- Check effective permissions for a group on domain object ---
function Get-GroupPermissionsOnDomain {
    param (
        [string]$GroupName
    )
    $domainDN = (Get-ADDomain).DistinguishedName
    $ldapPath = "LDAP://$domainDN"
    $domainObj = [ADSI]$ldapPath
    $security = $domainObj.ObjectSecurity.Access

    Write-Host "`n[*] Permissions for group: $GroupName on Domain Root"
    $groupSID = (Get-ADGroup -Identity $GroupName).SID.Value

    foreach ($ace in $security) {
        if ($ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $groupSID) {
            Write-Host " - Right: $($ace.ActiveDirectoryRights) | AccessType: $($ace.AccessControlType)"
        }
    }
}

# --- Check group permissions on another group (used for GenericAll on Stellar Admins) ---
function Get-GroupPermissionsOnGroup {
    param (
        [string]$TargetGroup,
        [string]$DelegatedGroup
    )
    $groupDN = (Get-ADGroup -Identity $TargetGroup).DistinguishedName
    $ldapPath = "LDAP://$groupDN"
    $groupObj = [ADSI]$ldapPath
    $security = $groupObj.ObjectSecurity.Access
    $delegatedSID = (Get-ADGroup -Identity $DelegatedGroup).SID.Value

    Write-Host "`n[*] Permissions for group: $DelegatedGroup on group: $TargetGroup"
    foreach ($ace in $security) {
        if ($ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $delegatedSID) {
            Write-Host " - Right: $($ace.ActiveDirectoryRights) | AccessType: $($ace.AccessControlType)"
        }
    }
}

# --- Check if svcsql has ResetPassword right on Helpdesk Admin users ---
function CheckSvcsqlResetPermissionOnHelpdesk {
    $svcsqlSID = (Get-ADUser -Identity "svcsql").SID.Value
    $helpdeskUsers = Get-ADGroupMember -Identity "Helpdesk Admins" | Where-Object { $_.objectClass -eq "user" }
    $resetPasswordGuid = [Guid]"00299570-246d-11d0-a768-00aa006e0529"

    Write-Host "`n[*] Checking ResetPassword ACE for svcsql on Helpdesk Admin users..."
    foreach ($user in $helpdeskUsers) {
        $userPath = "LDAP://$($user.DistinguishedName)"
        $userADSI = [ADSI]$userPath
        $found = $false
        foreach ($ace in $userADSI.ObjectSecurity.Access) {
            $aceSID = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            if ($ace.ObjectType -eq $resetPasswordGuid -and $aceSID -eq $svcsqlSID) {
                Write-Host " - Found ResetPassword ACE on: $($user.SamAccountName)"
                $found = $true
                break
            }
        }
        if (-not $found) {
            Write-Warning " - Missing ResetPassword ACE on: $($user.SamAccountName)"
        }
    }
}

# --- Run Checks ---
Get-GroupPermissionsOnDomain -GroupName "Stellar Admins"
Get-GroupPermissionsOnGroup -TargetGroup "Stellar Admins" -DelegatedGroup "Account Operators"
CheckSvcsqlResetPermissionOnHelpdesk