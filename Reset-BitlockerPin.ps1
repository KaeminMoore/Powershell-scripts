[String[]]$ComputerName = Read-Host ("Enter Computer Name or Names")
                                         #could be -ChangePin
Get-ADComputer $ComputerName | %{manage-bde.exe -changepassword C: -cn $ComputerName}