Param(
    [string]$ComputerName = (Read-host "Enter Computer Name to Query"),
    [string]$LogType = (Read-host "Application, Security, or System Logs?"),
    [int]$Number = (Read-host "How Many Entries Would you Like to View?")
)
Get-EventLog -Logname $LogType -Newest $Number -ComputerName $ComputerName |
     export-csv -Path 'C:\Temp\MyScripts\Get Event Logs\Events.csv'