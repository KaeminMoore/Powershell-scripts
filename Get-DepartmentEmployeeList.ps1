$a = (Read-host "Enter Department Name")
$Dept = "*$a*"

Get-ADUser -SearchBase "OU=Users,OU=RD,OU=Agencies,DC=usda,DC=net" -Filter {Description  -like $Dept} -Properties * | Format-table SamAccountName | Out-File -FilePath C:\Temp\"$a"EmployeeList.csv
