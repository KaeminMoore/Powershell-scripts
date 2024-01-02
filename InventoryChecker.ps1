$computerName = Read-Host "Computer Name"
$systemInfo = Get-WmiObject -ComputerName $computerName -ClassName Win32_Bios 
$systemIP = Resolve-DNSName $computerName
$systemUser = (Get-WMIObject -ComputerName $computerName -ClassName Win32_ComputerSystem).Username
Write-Host ""
Write-Host "User: $systemUser"
Write-host "Serail Number: $($systemInfo.SerialNumber)"
Write-Host "System IP: $($systemIP.IPAddress)"
$systemInfo