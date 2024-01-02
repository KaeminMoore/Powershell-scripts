# This file contains the list of servers you want to copy files/folders to
$computers = Get-Content "C:\temp\DefenderFix\TargetPCs.txt"

# This is the file/folder(s) you want to copy to the servers in the $computer variable
$source = "C:\temp\DefenderFix\WinDefender_Exploitfix.xml"

# The destination location you want the file/folder(s) to be copied to
$destination = "c$\temp\"

foreach ($computer in $computers) {
if ((Test-Path -Path \\$computer\$destination)) {
Copy-Item $source -Destination \\$computer\$destination -Verbose  
Invoke-Command -ComputerName $Computer -ScriptBlock{set-processmitigation -file "c:\temp\windefender_exploitfix.xml"
} } }

