$Computername = Read-Host ("Enter Computer Name")

foreach ($computer in $Computername){write-verbose "Working on $computer..." -Verbose
  Invoke-Command -ComputerName "$Computer" -ScriptBlock {
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\O365ProPlusRetail* |
    Select-Object DisplayName, DisplayVersion, Publisher
    }
    }