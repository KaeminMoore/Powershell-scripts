$ComputerName = (Read-Host "Enter Computer Name to Query")
$Download = (Read-Host "Enter Computername that you would like to download to")
$Username = (Read-Host "Enter User Name")
$Build = (Read-Host "Enter Build Size")
$logdate = Get-Date -format yyyyMMdd
$logfile = "\\$Download\c$\Temp\SoftwareList\SoftwareList - "+$Username+" - "+$Build+" - "+$Computername+" - "+$logdate+".csv"


Invoke-command -Computername $Computername -Scriptblock {Get-CimInstance -query "SELECT * FROM SMS_InstalledSoftware" -namespace "root\CIMV2\sms" | Select-Object ProductName,ProductVersion,InstallDate } | export-csv -Path $logfile -NoTypeInformation 