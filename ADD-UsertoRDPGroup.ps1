$users = read-host "Please enter User Name"
$usergroup = "Remote Desktop Users"
$computername = read-host "Please enter Computer Name"

## This script will add a user account to a remote computer's REMOTE DESKTOP LOCAL group, & allow that user to RDP into the specified computer##

Invoke-Command -ComputerName $computername -ScriptBlock {  net localgroup $using:usergroup /add $using:users } -Verbose