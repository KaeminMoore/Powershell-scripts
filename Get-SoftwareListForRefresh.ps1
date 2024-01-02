$ComputerName = (Read-Host "Enter Computer Name to Query")
$Username = (Read-Host "Enter User Name")
$Build = (Read-Host "Enter Build Size")
$logdate = Get-Date -format yyyyMMdd
$logfile = "C:\Temp\SoftwareList\SoftwareList - "+$Username+" - "+$Build+" - "+$Computername+" - "+$logdate+".csv"


Get-WmiObject -Class Win32_Product -Computer $ComputerName -Property * | Select-Object Name, Version,InstallDate  | export-csv -Path $logfile -NoTypeInformation