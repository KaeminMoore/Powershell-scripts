$ComputerName = (Read-Host "Enter Computer Name to Query")
$LogType = (Read-host "Enter which log type you would like to query")
$Number = (Read-Host "How many of the latest entries would you like")

Get-Eventlog -Logname $LogType -computername $computername -EntryType Error -newest $Number | FL -Property *