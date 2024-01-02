import-module ActiveDirectory
Import-csv "C:\Temp\attachments\emails\Names.txt" | % {
Add-ADGroupMember -Identity "ARDG-MO-EO-AllUsers" -Member $_.Username
}

