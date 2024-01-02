$Computername = Read-Host ("Enter Computer Name")

invoke-command -ComputerName $computername -ScriptBlock{Disable-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional-amd64}