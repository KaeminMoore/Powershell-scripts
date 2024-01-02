$updates = Get-ChildItem -Path C:\Temp\MyScripts\Vulnerability_Remediation\Install_MSP_Files\Patches\ | select -ExpandProperty name

foreach ($up in $updates)
{
        $file = "C:\Temp\MyScripts\Vulnerability_Remediation\Install_MSP_Files\Patches\$up"
        $silentArgs = "/passive"
        $additionalInstallArgs = ""
        Write-Debug "Running msiexec.exe /update $file $silentArgs"
        $msiArgs = "/p`"$file`""
        $msiArgs = "$msiArgs $silentArgs $additionalInstallArgs"


       $Computers = Get-Content 'C:\Temp\MyScripts\Vulnerability_Remediation\Install_MSP_Files\MachineList.txt'
       foreach ($Computer in $Computers){
       Invoke-Command -computername $computer Start-Process -FilePath msiexec -ArgumentList $msiArgs -Wait
       }
}