$Groupname = (Read-host "Enter Group Name to Query")
$logfile = "C:\Temp\DCIO_Groups.csv"
Get-ADGroup -filter {name -like  "*$Groupname*"}  -Properties * | 
    Select Name,Description | export-csv -Path $logfile -NoTypeInformation