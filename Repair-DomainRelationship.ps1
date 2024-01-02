$ComputerName = (Read-Host "Enter Computer Name")

 Invoke-Command -computername $Computername -ScriptBlock {Test-ComputerSecureChannel -Repair -Credential (Get-credential) -Verbose}