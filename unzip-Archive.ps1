$filePath = Read-Host ("Enter File Path to unzip to")

Get-ChildItem -Path $filePath -Filter *.exe | Rename-Item -NewName { $_.name -Replace '\.exe$','.zip' } 
Get-ChildItem -Path $filePath -filter *.zip | Expand-Archive -DestinationPath $filePath -Force