Param(
    $ComputerName = (Read-Host "Enter Computer Name to Query")
    )
$os = gwmi win32_operatingsystem -Computername $ComputerName
$model = gwmi win32_computersystem -ComputerName $ComputerName
$disk = gwmi -cn $ComputerName win32_logicaldisk -Filter "DriveType=3"
$bios = gwmi win32_Bios -ComputerName $ComputerName
$net =  gwmi win32_networkadapterconfiguration -computername $ComputerName -filter "IPEnabled='True'"
$adapter = gwmi win32_PnPSignedDriver -ComputerName $ComputerName | Where {$_.Description -like "*Ethernet Connection*"}
$User = gwmi -Class Win32_ComputerSystem -Computername $ComputerName | Select-Object Username
    switch($os.Version){
    '6.1.7600' {$wmi_build="Windows 7"}
    '6.1.7601' {$wmi_build="Windows 7 SP1"}
    '6.2.9200' {$wmi_build="Windows 8"}
    '6.3.9600' {$wmi_build="Windows 8.1"}
    '10.0.10240'{$wmi_build="1507"}
    '10.0.10586'{$wmi_build="1511"}
    '10.0.14393'{$wmi_build="1607"}
    '10.0.15063'{$wmi_build="1703"}
    '10.0.16299'{$wmi_build="1709"}
    '10.0.17134'{$wmi_build="1803"}
    '10.0.17763'{$wmi_build="1809"}
    '10.0.18362'{$wmi_build="1903"}
    '10.0.18363'{$wmi_build="1909"}
    '10.0.19042'{$wmi_build="20H2"}
    } 
 

    $props = [ordered] @{'Computer Name'=$os.__SERVER;
                'Computer Model'=$model.model;
                'Operating System'=$os.caption;
                'OS Version'=$wmi_build;
                'Last Logged in User'=$User
                'Free Disk Space(GB)'=$disk.Freespace / 1GB -as [int];
                'Physical Memory(GB)'=$model.TotalPhysicalMemory / 1GB -as [int];
                'Last Boot time'=[Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime);
                'Serial Number'=$bios.serialnumber;
                'Bios Version'=$bios.SMBIOSBIOSVersion;
                'IP Address'=$net.IPAddress;
                'Mac Address'=$net.MACAddress;
                'Ethernet Adapter'=$net.Description;
                'Driver Date'=[Management.ManagementDateTimeConverter]::ToDateTime($adapter.DriverDate)
               }
$obj = New-object -TypeName PSObject -Property $props
Write-Output $obj