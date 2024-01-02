$computername = Read-host("Enter Computer Name")
$software = Read-Host ("Enter Software name")
$sourcefile = "C:\Temp\Software\$Software"
$filePath = Read-Host ("Enter Powershell File Path")

foreach ($computer in $computername) 
{
    $destinationFolder = "\\$computer\C$\Temp"
   

    if (!(Test-Path -path $destinationFolder))
    {
        New-Item $destinationFolder -Type Directory
    }
    Copy-Item -Path $sourcefile -Recurse -Destination $destinationFolder
        
   
    &psexec \\$computername -s -d "C:\Temp\Testme\MS\AccessDatabaseEngine2016\v16.0.5044.1000\install.cmd"}

    ##Remember to remove the software folder from the filepath if you use copy and paste from the local directory.  