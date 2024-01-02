$Computer = Read-Host ("Enter Computer Name")
$number = Read-Host ("Enter Software ID Number")

$Software = Get-WmiObject Win32_Product -ComputerName $Computer | Where-Object {$_.IdentifyingNumber -eq $number}
if ($Software) {
  $Software.Uninstall()
}
else {
  $number + ' is not installed on ' + $Computer
}