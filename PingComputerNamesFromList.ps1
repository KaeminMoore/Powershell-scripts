$names = Get-content "C:\temp\Computernames.txt"

foreach ($name in $names){
  if (Test-Connection -ComputerName $name -Count 1 -ErrorAction SilentlyContinue){
    Write-Host "$name is up" -ForegroundColor Green
  }
  else{
    Write-Host "$name is down" -ForegroundColor Red
  }
}