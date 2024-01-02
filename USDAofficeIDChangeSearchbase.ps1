$OU = "OU=FBC,OU=Users,OU=FPAC,OU=Agencies,DC=usda,DC=net"
Get-ADUser -filter {uSDAOfficeID -eq '106205'} -Searchbase $OU | 
    Set-ADUser -Replace @{usdaOfficeID='110648'}  