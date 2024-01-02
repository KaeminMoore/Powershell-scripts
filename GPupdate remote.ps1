#This script will force an update of GroupPolicy on a target computer you specify
#And then run a gpresult command against the machine to verify it's been updated.

#The below code will cause the script to prompt you for the target computer's name
$TargetPC = (Read-host "Enter Computer Name for GPupdate") + ".usda.net"

#Forces the target computer to perform a gpupdate /force
Invoke-GPUpdate -Computer $TargetPC -Force
Write-Host "The Group Policy on the specified computer is now updating"

#Queries the computer for the last time Group Policy Updated to verify the script worked
gpresult /r /s $TargetPC /scope computer | find "Last time Group Policy was applied:"