
Param(
      [String]$GroupName = (Read-Host "Enter AD Group Name")
      )

Import-csv "c:\temp\names.csv" | % {
Add-ADGroupMember -Identity $GroupName -Members $_.Users
}