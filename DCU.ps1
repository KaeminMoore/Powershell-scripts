$ComputerName= Read-Host "ComputerName"
$biosPassword =Read-host "Bios Password"
if (Test-Path "\\$ComputerName\C$\Program Files\Dell\CommandUpdate"){
        psexec \\$ComputerName "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe"  /configure -biosPassword="$BiosPassword"        psexec \\$ComputerName "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /scan
        psexec \\$ComputerName "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /applyUpdates
}else{

        psexec \\$ComputerName "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe"  /configure -biosPassword="$BiosPassword"
        psexec \\$ComputerName "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe" /scan
        psexec \\$ComputerName "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe" /applyUpdates

}
#Restart-Computer $ComputerName -Force
