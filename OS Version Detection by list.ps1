#This script will query a list of computer names from a .csv or .txt document and tell you which OS, which version of the os, and last boot up time of the system was.
#Update the name of the CSV File to names.csv or update names.csv to reflect the name of your file and filepath
$Names = import-csv C:\scripts\names.csv
ForEach ($PC in $Names)
 {
  #Update the .PC_Name to the name of the column heading in your .csv file
  $PCName = $PC.PC_Name
  $os = gwmi win32_operatingsystem -Computername "$PCName" 
$os | select csname,Caption,Version, @{LABEL=’LastBootUpTime’;EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}} | fl *
}