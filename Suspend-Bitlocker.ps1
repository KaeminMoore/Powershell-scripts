$ComputerName = Read-Host ("Enter Computer Name or Names")
Get-ADComputer $ComputerName | %{manage-bde.exe -protectors -disable C: -cn $ComputerName}