# --- Configuration ---
$XatoPath = "C:\CTFSetup\xato.txt"
$RockyouPath = "C:\CTFSetup\rockyou.txt"
$DomainOU = "OU=CTFUsers,DC=l33thackers,DC=stellar,DC=tech"
$OUContainerPath = "DC=l33thackers,DC=stellar,DC=tech"
$LogFile = "C:\CTFSetup\ctf_users.csv"
$SampleSize = 300
$DONT_REQ_PREAUTH = 4194304
$UserPrincipalDomain = "l33thackers.stellar.tech"
$domainDN = (Get-ADDomain).DistinguishedName
$stellarAdmins = "CN=Stellar Admins,CN=Users,$domainDN"
$helpdeskAdmins = "CN=Helpdesk Admins,CN=Users,$domainDN"
$accountOperators = "CN=Account Operators,CN=Builtin,$domainDN"

# --- Ensure CTFUsers OU exists ---
try {
    $ouCheck = Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$DomainOU)" -ErrorAction Stop
    Write-Host "[*] OU already exists: $DomainOU"
} catch {
    try {
        New-ADOrganizationalUnit -Name "CTFUsers" -Path $OUContainerPath
        Write-Host "[+] Created OU: $DomainOU"
    } catch {
        Write-Error "[-] Failed to create OU: $_"
        exit 1
    }
}

# --- Sample 300 usernames safely ---
$sampledUsers = @()
Get-Content -Path $XatoPath -ReadCount 1000 | ForEach-Object {
    foreach ($line in $_) {
        $username = $line.Trim().ToLower()
        if ($username -match '^[a-z]+$' -and $username -notmatch '(.)\1\1' -and ($sampledUsers.Count -lt $SampleSize)) {
            if ((Get-Random -Minimum 0 -Maximum 10) -eq 0) {
                $sampledUsers += $username
            }
        }
    }
}
$sampledUsers = $sampledUsers | Get-Unique | Sort-Object { Get-Random } | Select-Object -First $SampleSize

# --- Select RockYou password ---
function Get-ValidRockyouPassword {
    param ([string]$Path)
    while ($true) {
        $rockyouIndex = Get-Random -Minimum 0 -Maximum 14000000
        $lineCounter = 0
        $reader = [System.IO.StreamReader]::new($Path)
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            if ($lineCounter -eq $rockyouIndex) {
                $candidate = $line.Trim()
                $reader.Close()
                if ($candidate.Length -ge 12 -and $candidate -match '[A-Z]' -and $candidate -match '[a-z]' -and $candidate -match '[0-9]') {
                    return $candidate
                }
                break
            }
            $lineCounter++
        }
        $reader.Close()
    }
}

$rockyouPassword = Get-ValidRockyouPassword -Path $RockyouPath
$specialUsername = Get-Random -InputObject $sampledUsers
@("Username,Password,IsRockyou") | Out-File -FilePath $LogFile -Encoding UTF8

# --- Create Users ---
foreach ($username in $sampledUsers) {
    $isRockyou = "No"
    $password = if ($username -eq $specialUsername) { $isRockyou = "Yes"; $rockyouPassword } else { "Password123!!" }

    try {
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        $upn = "$username@$UserPrincipalDomain"

        New-ADUser -Name $username -SamAccountName $username -UserPrincipalName $upn -AccountPassword $securePassword -Enabled $true -Path $DomainOU -ChangePasswordAtLogon $false

        if ($username -eq $specialUsername) {
            $maxAttempts = 5; $attempt = 0
            do {
                try {
                    $userObj = Get-ADUser -Identity $username -Properties userAccountControl -ErrorAction Stop
                    $newUAC = $userObj.userAccountControl -bor $DONT_REQ_PREAUTH
                    Set-ADUser -Identity $username -Replace @{ userAccountControl = $newUAC }
                    Write-Host "[+] Disabled pre-auth for AS-REP roastable account: $username"
                    break
                } catch { Start-Sleep -Seconds 2; $attempt++ }
            } while ($attempt -lt $maxAttempts)
        }

        "$username,$password,$isRockyou" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    } catch {
        Write-Warning ("[-] Failed to create user {0}: {1}" -f $username, $_.Exception.Message)
        continue
    }
}

Write-Host "`n[+] All users processed. Log saved to: $LogFile"
Write-Host "[*] Special AS-REP Roastable User: $specialUsername"

# --- Grant full control to AS-REP roastable user on \\localhost\victims share ---
try {
    $victimShare = "victims"
    $victimPath = "C:\victims"
    $shareUser = "$env:USERDOMAIN\$specialUsername"

    # Ensure the directory exists
    if (-not (Test-Path -Path $victimPath)) {
        New-Item -ItemType Directory -Path $victimPath -Force
        Write-Host "[+] Created directory: $victimPath"
    }

    # Ensure the share exists
    if (-not (Get-SmbShare -Name $victimShare -ErrorAction SilentlyContinue)) {
        New-SmbShare -Name $victimShare -Path $victimPath -FullAccess "Administrators"
        Write-Host "[+] Created SMB share: \\localhost\$victimShare"
    }

    # Grant share permissions to the special user
    Grant-SmbShareAccess -Name $victimShare -AccountName $shareUser -AccessRight Full -Force
    Write-Host "[+] Granted SMB share access to $shareUser"

    # Grant NTFS permissions
    $acl = Get-Acl $victimPath
    $permission = "$shareUser","FullControl","Allow"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    $acl.SetAccessRule($accessRule)
    Set-Acl $victimPath $acl
    Write-Host "[+] Granted NTFS FullControl permission on $victimPath to $shareUser"
} catch {
    Write-Warning "[-] Failed to assign share or NTFS permissions to $specialUsername: $_"
}

# --- Create Groups and Relationships ---
if (-not (Get-ADGroup -Filter "Name -eq 'Stellar Admins'" -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name "Stellar Admins" -Path "CN=Users,$domainDN" -GroupScope Global -GroupCategory Security
    Write-Host "[+] Created group: Stellar Admins"
}

if (-not (Get-ADGroup -Filter "Name -eq 'Helpdesk Admins'" -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name "Helpdesk Admins" -Path "CN=Users,$domainDN" -GroupScope Global -GroupCategory Security
    Write-Host "[+] Created group: Helpdesk Admins"
}

try {
    Add-ADGroupMember -Identity $accountOperators -Members $helpdeskAdmins
    Write-Host "[+] Added Helpdesk Admins to Account Operators"
} catch {
    Write-Warning "[-] Failed to add Helpdesk Admins to Account Operators: $_"
}

# --- Grant Stellar Admins WriteDACL on domain ---
try {
    $stellarGroup = Get-ADGroup "Stellar Admins"
    $domainObj = [ADSI]"LDAP://$domainDN"
    $stellarSID = New-Object System.Security.Principal.SecurityIdentifier($stellarGroup.SID)

    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
        $stellarSID,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $domainObj.ObjectSecurity.AddAccessRule($ace)
    $domainObj.CommitChanges()
    Write-Host "[+] Granted WriteDACL on domain to Stellar Admins"
} catch {
    Write-Warning "[-] Failed to grant WriteDACL to Stellar Admins: $_"
}

# --- Grant Account Operators GenericAll on Stellar Admins ---
try {
    $stellarGroupObj = [ADSI]"LDAP://$stellarAdmins"
    $aoGroup = Get-ADGroup "Account Operators"
    $aoSID = New-Object System.Security.Principal.SecurityIdentifier($aoGroup.SID)

    $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
        $aoSID,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $stellarGroupObj.ObjectSecurity.AddAccessRule($ace2)
    $stellarGroupObj.CommitChanges()
    Write-Host "[+] Granted GenericAll on Stellar Admins to Account Operators"
} catch {
    Write-Warning "[-] Failed to grant GenericAll on Stellar Admins: $_"
}

# --- Create user KingJames and add to Helpdesk Admins ---
try {
    if (-not (Get-ADUser -Filter "SamAccountName -eq 'KingJames'" -ErrorAction SilentlyContinue)) {
        $password = "Password123!!"
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        New-ADUser -Name "King James" -SamAccountName "KingJames" -UserPrincipalName "KingJames@$UserPrincipalDomain" -AccountPassword $securePassword -Enabled $true -Path "CN=Users,$OUContainerPath" -ChangePasswordAtLogon $false
        Add-ADGroupMember -Identity "Helpdesk Admins" -Members "KingJames"
        Write-Host "[+] Created user: KingJames and added to Helpdesk Admins"
        "KingJames,$password,No" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }
} catch {
    Write-Warning "[-] Failed to create or assign KingJames: $_"
}

# --- svcsql Setup ---
try {
    $svcsqlPassword = Get-ValidRockyouPassword -Path $RockyouPath
    $secureSvcPwd = ConvertTo-SecureString $svcsqlPassword -AsPlainText -Force

    if (-not (Get-ADUser -Filter "SamAccountName -eq 'svcsql'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name "svcsql" `
                   -SamAccountName "svcsql" `
                   -UserPrincipalName "svcsql@$UserPrincipalDomain" `
                   -AccountPassword $secureSvcPwd `
                   -Enabled $true `
                   -Path "CN=Users,$OUContainerPath" `
                   -ServicePrincipalNames "MSSQLSvc/svcsql.$UserPrincipalDomain" `
                   -ChangePasswordAtLogon $false
        Enable-ADAccount -Identity "svcsql"
        Add-ADGroupMember -Identity "Remote Management Users" -Members "svcsql"
        Write-Host "[+] Created svcsql service account with SPN and added to Remote Management Users"
        "svcsql,$svcsqlPassword,Yes" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }

    Set-ADUser -Identity "svcsql" -ServicePrincipalNames @{Add="MSSqlSvc/sql.l33thackers.stellar.tech:1433"}
    Write-Host "[+] Added additional SPN to svcsql: MSSqlSvc/sql.l33thackers.stellar.tech:1433"

    $svcsqlSID = (Get-ADUser -Identity "svcsql").SID
    $helpdeskMembers = Get-ADGroupMember -Identity "Helpdesk Admins" -Recursive | Where-Object { $_.objectClass -eq "user" }
    $resetPasswordGuid = [Guid]"00299570-246d-11d0-a768-00aa006e0529"

    foreach ($member in $helpdeskMembers) {
        $userPath = "LDAP://$($member.DistinguishedName)"

        try {
            $userADSI = [ADSI]$userPath
            $identity = New-Object System.Security.Principal.SecurityIdentifier($svcsqlSID)
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
                $identity,
                [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                [System.Security.AccessControl.AccessControlType]::Allow,
                $resetPasswordGuid,
                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None,
                [Guid]::Empty
            )
            $userADSI.ObjectSecurity.AddAccessRule($ace)
            $userADSI.CommitChanges()
            Write-Host "[+] Granted svcsql ResetPassword rights on: $($member.SamAccountName)"
        } catch {
            Write-Warning "[-] Failed to apply ACE for $($member.SamAccountName): $_"
        }
    }
} catch {
    Write-Warning "[-] Failed to create svcsql or assign rights: $_"
}