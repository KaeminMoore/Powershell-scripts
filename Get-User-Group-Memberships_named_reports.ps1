#This script will query an ad account and output all group memberships that they are a part of
#to a file located at c:\temp called "Get_Group_Memberships.txt

param(
    $UserName = (Read-host "Enter username to query")
    )
$CSV_path = "c:\temp + $CSV_file"
$CSV_file = "Get_Group_Membership + $username.txt"
$Groups = (Get-ADUser -Identity $username -Properties memberof).memberof
$Groups | Get-ADGroup | Select-Object name | Sort-Object name | export-csv $CSV_path