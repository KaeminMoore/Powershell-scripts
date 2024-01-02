$ComputerName = (Read-Host "Enter Computer Name to restart RDP")

Invoke-command -ComputerName $Computername -ScriptBlock {
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0}

