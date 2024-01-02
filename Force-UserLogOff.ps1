##run Command then execute the command logoff $sessionID.

$ComputerName = (Read-Host "Enter Computer Name to Query")
$UserName = (Read-host "Enter username")


$sessionID = ((quser /server:"$computername" | Where-Object { $_ -match "$username" }) -split ' +')[2]