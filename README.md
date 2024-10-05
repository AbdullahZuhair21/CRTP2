# CRTP

# Lateral Movement 
```powershell
One-To-One
#Avoid using psexec as it is too noisy. instead, to use "Enter-PSSession" you need Admin Privs
Enter-PSSession -ComputerName <dcorp-adminsrv>
#After getting the access run `whomai` to get the username, run `hostname` to get the pc name
```
```powershell
One-To-Many

```

```powershell
storing the session in a variable
$var = Enter-PSSession -ComputerName dcorp-admin

Enter the session
Enter-PSSession -Session $var

Interact with the target machine
Invoke-Command -Session $var -ScriptBlock {ls env:}
```

```powershell
you can use winrs in place of PSRemoting to evade the logging (more stealthy)
winrs -r:dcorp-mgmt hostname;whoami  #run command to check whether we have access or not
winrs -r:dcorp-mgmt cmd  #get a cmd shell on mgmt machine
winrs -remote:server1 -u:server1\Administrator -p:Pass@123 hostname
```
