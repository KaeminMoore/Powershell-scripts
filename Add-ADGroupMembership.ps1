$UserName = (Read-Host "Enter User Name" )
$Groupname = (Read-Host "Enter Group Names")

Add-ADgroupMember -Identity $Groupname -Members $UserName