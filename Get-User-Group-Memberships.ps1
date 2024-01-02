#This script will query an ad account and output all group memberships that they are a part of#

param(
    $UserName = (Read-host "Enter username to query")
    )

$Groups = (Get-ADUser -Identity $username -Properties memberof).memberof
$Groups | Get-ADGroup | Select-Object name | Sort-Object name | export-csv "c:\temp\Get_Group_membership.txt"