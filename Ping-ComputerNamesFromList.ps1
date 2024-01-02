$names = Get-content "C:\Users\Michael.Meyer2\OneDrive - USDA\OneDrive-Backup\MyScripts\Vulnerability_Remediation\PingComputers\Computers.txt"

foreach ($name in $names){
  if (Test-Connection -ComputerName $name -Count 1 -ErrorAction SilentlyContinue){
    Write-Host "$name is up" -ForegroundColor Green
  }
  else{
    Write-Host "$name is down" -ForegroundColor Red
  }
}