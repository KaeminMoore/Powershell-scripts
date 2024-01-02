$ComputerName = Read-Host " Enter Computer name"
$credential = Get-Credential
$session = New-PSSession -Credential $credential -ComputerName $ComputerName

Enter-PSSession $session


#<Run commands in remote session>
#Exit-PSSession
#Remove-PSSession $session