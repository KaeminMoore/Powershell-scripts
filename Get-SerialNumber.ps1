﻿$Computer = Read-Host "Enter Computer Name to Query"
(Get-ADComputer $computer).Name | Foreach-Object{gwmi Win32_Bios -ComputerName $_ -ErrorAction SilentlyContinue | Select-Object PSComputerName,SerialNumber}