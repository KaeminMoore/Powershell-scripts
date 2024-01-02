foreach ($computer in (Get-Content "c:\Temp\MyScripts\O365Report\computers.txt")){
  write-verbose "Working on $computer..." -Verbose
  Invoke-Command -ComputerName "$Computer" -ScriptBlock {
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\O365ProPlusRetail* |
    Select-Object DisplayName, DisplayVersion, Publisher
  } | export-csv C:\Temp\MyScripts\O365Report\results.csv -Append -NoTypeInformation
}