$computerName = Read-Host ("Enter Computer Name to Query")

cls

get-hotfix -computername $computerName | ft -autosize 
