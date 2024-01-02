#This script will query groups from a list and output the members to a file
#Copy the ENTIRE "Get-GroupMembersFromMultipleGroups" folder to C:\temp
###FOR THIS TO WORK AD TOOLS MUST BE INSTALLED ON THE COMPUTER YOUR RUNNING THIS FROM###

#Below is the path to the csv file that the script works from. You can edit the path if need be
$groups = Get-Content "C:\temp\Get-GroupMembersFromMultipleGroups\securitygroups.csv"
$resultsarray = @()
foreach ($group in $groups) {
    $resultsarray += Get-ADGroupMember -Identity $group | Select Name,@{Expression={$group};Label="Group Name"}}

#Your results will output to c:\temp\Get-GroupMembersFromMultipleGroups and be called Membership results.csv
$resultsarray | export-csv -path "C:\temp\Get-GroupMembersFromMultipleGroups\Membership Results.csv" -notypeinformation