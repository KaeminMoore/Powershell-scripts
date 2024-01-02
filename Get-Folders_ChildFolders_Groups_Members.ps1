Get-ChildItem E:\Shared\Internal\cfo -Recurse | where{$_.psiscontainer} |
Get-Acl | % {
    $path = $_.path
    $_.Access | % {
        New-Object PSObject -Property @{
            Folder = $path.Replace("Microsoft.PowerShell.Core\FileSystem::","")
            Access = $_.FileSystemRights
            Control = $_.AccessControlType
            User = $_.IdentityReference
            Inheritance = $_.IsInherited
            }
        }
    } | Select-Object -Property User, Access, Folder | Export-Csv c:\temp\outputcfo.csv -force