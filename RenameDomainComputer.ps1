Param(
    [string]$ComputerName = (Read-host "Enter Current Computer Name"),
    [string]$NewName = (Read-host "Enter New Computer Name"),
    [string]$UserName = (Read-host "Enter your Admin Account")
)

Rename-Computer -ComputerName $ComputerName -NewName $NewName -DomainCredential $UserName -force -Restart