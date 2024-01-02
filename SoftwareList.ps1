$ComputerName = (Read-Host "Enter Computer Name to Query")
$logdate = Get-Date -format yyyyMMdd
$logfile = "\\AIOMOSTL5000601\c$\Temp\Software List\SoftwareList - "+$Computername+" - "+$logdate+".csv"

##Change the above Logfile path to a network path on your personal computer where you would like to save the .csv file## 

Get-WmiObject -Class Win32_Product -Computer $ComputerName -Property * | Select-Object Name, Version,InstallDate  | export-csv -Path $logfile -NoTypeInformation 

