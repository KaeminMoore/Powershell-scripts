Param(
    [string]$ComputerName = (Read-Host "Enter Computer Name to Query"),
    [string]$UserName = (Read-Host "Enter User Account to Query")
    )
get-GPResultantSetOfPolicy -ReportType html -Path C:\Temp\Myscripts\GetGPResults\Report.htm -user $UserName -Computer $ComputerName