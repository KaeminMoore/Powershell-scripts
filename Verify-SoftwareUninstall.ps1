$Computer = Read-Host ("Enter Computer Name")
$number = Read-Host ("Enter Software ID Number")

$Software = Get-WmiObject Win32_Product -ComputerName $computer | Where-Object {$_.IdentifyingNumber -eq $number}
if ($Software) {
  $Number + 'is still installed on' + $Computer
}
else {
  $Number + ' is not installed on ' + $Computer
}