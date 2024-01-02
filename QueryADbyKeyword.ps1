$logfile = "C:\Temp\DCIO_Groups"
Get-ADGroup -filter {name -like "*dcio*"} -SearchBase "OU=RD,OU=Agencies,DC=usda,DC=net" -Properties * | 
    Select Name,Description | export-csv -Path $logfile -NoTypeInformation