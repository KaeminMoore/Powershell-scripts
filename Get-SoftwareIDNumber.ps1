$Computer = Read-Host ("Enter Computer Name")

gwmi Win32_product -ComputerName $Computer | Select-Object -Property IdentifyingNumber,Name