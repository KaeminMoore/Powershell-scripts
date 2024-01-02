$Names = Import-csv "C:\Temp\MyScripts\DISM Repair\Computers.csv" 


foreach($PC in $Names){
Invoke-Command  -ScriptBlock {DISM.exe /Online /Cleanup-image /Restorehealth} 

Start-Sleep 1800

Invoke-Command -ScriptBlock {sfc /scannow} 

}