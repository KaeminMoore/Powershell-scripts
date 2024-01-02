$Computers = Get-Content 'C:\Temp\MyScripts\Vulnerability_Remediation\SetComputerReboot\MachineList.txt'



foreach ($Computer in $Computers){
invoke-command -computername $Computer -Scriptblock {schtasks /create /RU SYSTEM /f /tn "Reboot" /tr "powershell.exe Restart-Computer -Force" /sc once /st 20:00:00}
}