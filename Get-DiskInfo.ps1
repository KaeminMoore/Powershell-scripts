Param(
    [string]$ComputerName = (Read-host "Enter Computer Name to query"),
    [int]$DriveType = 3
)
gwmi -cn "$ComputerName" win32_logicaldisk -Filter "DriveType=$DriveType" | 
select @{n='Computername';e={$_.__SERVER}},
       @{n='Drive';e={$_.DeviceID}},
       @{n='FreeSpace(GB)';e={$_.Freespace / 1GB -as [int]}},
       @{n='SIZE(GB)';e={$_.Size / 1GB -as [int]}},
       @{n='FreePercent';e={"{0:N2}" -f ($_.FreeSpace / $_.Size * 100)}}
      