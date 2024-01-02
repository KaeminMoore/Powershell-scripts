import-module activedirectory 
$logdate = Get-Date -format yyyyMMdd
$Agency = Read-host "Which Agency Would You Like to Query"
$logfile = "c:\Temp\Myscripts\LoginReports\logs\ExpiredComputers - "+$Agency+" - "+$logdate+".csv"
$DaysInactive = read-host "How Many Days Inactive Would You Like to Query for"
$time = (Get-Date).Adddays(-"$DaysInactive")

 
# Change this line to the specific OU that you want to search
$searchOU = "OU=Windows10,OU=Workstations,OU=$Agency,OU=Agencies,DC=usda,DC=net"

# Get all AD computers with LastLogon less than our time
Get-ADComputer -searchbase $searchOU -Filter {(LastLogon -lt $time) -and (enabled -eq $true) -and (name -like "*MOSTL*") } -Properties LastLogon, description, name |
 
# Output hostname and LastLogon into CSV
select-object Name,DistinguishedName, description, enabled,@{Name="Stamp"; Expression={[DateTime]::FromFileTime($_.LastLogon)}} | export-csv $logfile -notypeinformation