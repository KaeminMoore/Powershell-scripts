$RootHotfixPath = 'C:\Temp\Powershell\Vulnerability_Remediation\Install Hotfixes\Patches'
 
$Hotfixes = (Read-Host "Enter KB name")
$Computers = Get-Content 'C:\Temp\Powershell\Vulnerability_Remediation\Install Hotfixes\MachineList.txt'
 
foreach ($Hotfix in $Hotfixes){
    $HotfixPath = "$RootHotfixPath$Hotfix.msu"
    foreach ($Computer in $Computers){
        if (Test-Path "\\$Computer\c$\Temp"){
            Write-Host "Processing $Computer..."
            # Copy update package to local folder on server
            Copy-Item $Hotfixpath "\\$Computer\c$\Temp"
            # Run command as SYSTEM via PsExec (-s switch)
            &PsExec -s \\$computer wusa C:\Temp\$Hotfix.msu /quiet /norestart
            write-host "& C:\Windows\PsExec -s \\$Computer wusa C:\Temp\$Hotfix /quiet /norestart"
         
            
          
        } else {
            Write-Host "Folder C:\Temp does not exist on the target Computer"
        }
    }
}