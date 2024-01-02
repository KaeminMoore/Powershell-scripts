#This script will query a remote pc to find out who's logged into it
#When you execute the script, it will prompt you for the computer name to query

#Denotes the Variable called "ComputerName" and prompts you to enter the name for the Query
$ComputerName = (Read-Host "Enter Computer Name to Query")


Write-Host "If no computer name is displayed, it is either offline or on the NITC NAG"
#Queries the Remote Computer specified above searching for the user who's logged in
Get-WmiObject -Computername $ComputerName -Class Win32_ComputerSystem | Select-Object Username