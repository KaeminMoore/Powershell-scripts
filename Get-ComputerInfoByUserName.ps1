param(
    $UserName = (Read-host "Enter First Name and Last Name")
    )
$a = "*MOSTL*"
$b = "*$UserName*"
$c = get-adcomputer -filter {cn -like $a -and Description -like $b} -properties *
 
   switch($c.OperatingSystemVersion){
    '10.0 (10240)'{$wmi_build="1507"}
    '10.0 (10586)'{$wmi_build="1511"}
    '10.0 (14393)'{$wmi_build="1607"}
    '10.0 (15063)'{$wmi_build="1703"}
    '10.0 (16299)'{$wmi_build="1709"}
    '10.0 (17134)'{$wmi_build="1803"}
    '10.0 (17763)'{$wmi_build="1809"}
    '10.0 (18362)'{$wmi_build="1903"}
    '10.0 (18363)'{$wmi_build="1909"}
    } 

    $props = [ordered]@{
                     'Computer Name'=$c.Name;
                     'IP Address'=$c.IPv4Address;
                     'Operating Sytem'=$c.OperatingSystem;
                     'OS Version'=$wmi_build;
                     'last Login'=$c.LastLogonDate;
                     'Description'=$c.Description;
                     'OU'=$c.DistinguishedName;
                            
                    }
$obj = New-object -TypeName PSObject -Property $props
Write-Output $obj
