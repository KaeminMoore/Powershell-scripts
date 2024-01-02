$Computername = Read-host "Enter Computername for Query"
gwmi win32reg_addRemovePrograms -computername $Computername | select-object DisplayName,Version,InstallDate | export-csv -Path 'C:\Temp\MyScripts\Get Software List\SoftwareList.csv' -NoTypeInformation 
