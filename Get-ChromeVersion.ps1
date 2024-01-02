$machines = Get-content -Path C:\Temp\Myscripts\Vulnerability_Remediation\Update-Chrome\Computers.txt

ForEach($machine in $machines){
    $Version = gwmi win32_product -ComputerName $machine -Filter "Name='Google Chrome'" | Select -Expand Version
    "$machine - $Version"
}