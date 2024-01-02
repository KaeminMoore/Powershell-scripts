$machines = Get-content -Path C:\Temp\Myscripts\Vulnerability_Remediation\Uninstall_Software\Computers.txt
$number = Read-Host ("Enter Software ID Number")

ForEach($machine in $machines){
    $Software = Get-WmiObject Win32_Product -ComputerName $Machine | Where-Object {$_.IdentifyingNumber -eq $number}
        if ($Software) {
          $Number + 'is still installed on' + $Machine
        }
        else {
          $Number + ' is not installed on ' + $Machine
        }
}