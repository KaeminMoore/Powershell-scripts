$sourceDir = read-host "Please enter source Dir"
$OutDir = read-host "Please Enter Destination Dir"

Get-Item -Path $sourceDir | Copy-item -Destination $OutDir -Recurse