Function Get-ScheduledTask
       {
       param([string]$ComputerName = "localhost")
       Write-Host "Computer: $ComputerName"
       $Command = "schtasks.exe /query /s $ComputerName"
       Invoke-Expression $Command
       Clear-Variable Command -ErrorAction SilentlyContinue
       }
$computers = get-content C:\Temp\MyScripts\Update-Firefox\Computers.txt
$task = "FirefoxUpdater"
foreach ($Computer in $Computers) {
    If ((Get-ScheduledTask -ComputerName $Computer) -match $task)
        {
        $Command1 = "schtasks.exe /Run /s $Computer /tn $task"
              Invoke-Expression $Command1
        Clear-Variable Command1 -ErrorAction SilentlyContinue
        }
    Else
        {
        Write-warning "Task $task not found on $computer"
        Write-Host "`n"
        } 
}
 
