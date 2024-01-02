$sourceDir = read-host "Please enter source Dir"
$format = read-host "Format to look for"
$OutDir = read-host "Please Enter Destination Dir"


$Dir = get-childitem $sourceDir -recurse
$files = $Dir | where {$_.extension -eq "$format"}
$files | move-item -destination $OutDir