$computername = Read-host("Enter Computer Name")

&psexec \\$computername -s -d "C:\Temp\Testme\MS\AccessDatabaseEngine2016\v16.0.5044.1000\install.cmd"