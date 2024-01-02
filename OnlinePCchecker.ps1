#This script will query a list of computernames located in c:\temp\vulns called vulns.csv
#It will then output a file to the same folder called VULNSreport.csv
#The file will list all names and IPs of machines sorted by IP
#Vulns can only be run against 199.159.xxx.xxx IP addresses

Get-Content "c:\temp\vulns\vulns.csv" | ForEach {

    $details = Test-Connection -ComputerName $_ -Count 1 -ErrorAction SilentlyContinue

    if ($details) {

        $props = @{
            ComputerName = $_
            IP = $details.IPV4Address.IPAddressToString
        }

        New-Object PsObject -Property $props
    }

    Else {    
        $props = @{
            ComputerName = $_
            IP = 'Unreachable'
        }

        New-Object PsObject -Property $props
    }

} | Sort IP | Export-Csv "c:\temp\vulns\VULNSreport.csv" -NoTypeInformation