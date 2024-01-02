Param(
$ComputerName = (Read-Host "Enter Computer Name"),
$Password = (Read-Host "Enter Recovery Key")
    )
manage-bde.exe -cn $ComputerName -unlock C: -RecoveryPassword $Password
