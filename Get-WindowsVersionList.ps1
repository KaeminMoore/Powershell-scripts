$a = "*MOSTL*"
 
   switch($c.OperatingSystemVersion){
    '10.0 (10240)'{$wmi_build="1507"}
    '10.0 (10586)'{$wmi_build="1511"}
    '10.0 (14393)'{$wmi_build="1607"}
    '10.0 (15063)'{$wmi_build="1703"}
    '10.0 (16299)'{$wmi_build="1709"}
    '10.0 (17134)'{$wmi_build="1803"}
    '10.0 (17686)'{$wmi_build="1809"}
    } 

    Import-csv "c:\temp\MyScripts\WindowsVersionList\Computers.csv" | % {
    $c = get-adcomputer -filter {cn -like $a } -properties *
    }

$props = [ordered]@{
                     'Computer Name'=$c.Name;
                     'OS Version'=$wmi_build;
                     'last Login'=$c.LastLogonDate;
                     'Description'=$c.Description;
                              
                    }

$obj = New-object -TypeName PSObject -Property $props | export-csv "c:\temp\MyScripts\WindowsVersionList\WinVerReport.csv"
