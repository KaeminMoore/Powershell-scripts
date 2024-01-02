$DomainName = Read-Host " Enter Domain name"
$ComputerName = Read-Host " Enter Computer name"
$UserName = Read-Host " Enter User name"
$AdminGroup = [ADSI]"WinNT://$ComputerName/Administrators,group"
$User = [ADSI]"WinNT://$DomainName/$UserName,user"
$AdminGroup.Add($User.Path)