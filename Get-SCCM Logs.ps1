Param(
    $ComputerName = (Read-Host "Enter Computer Name to Query")
    )

Get-item -Path "\\$computername\C$\Windows\CCM\Logs" | Copy-item -Destination "C:\Temp\SCCM Logs\$Computername"  -Recurse