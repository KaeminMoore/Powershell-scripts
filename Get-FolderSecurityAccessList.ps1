$FilePath = Read-Host ("Enter File Path to Query")

get-acl -path $FilePath | Format-List -property AccessToString