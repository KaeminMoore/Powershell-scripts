$computername = Read-host ("Enter Computer Name to Query")

show-eventlog -ComputerName $computername