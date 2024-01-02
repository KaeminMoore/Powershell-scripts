param( 
    [string]$UserName = (Read-Host "Enter UserName"),
    [string]$ComputerName = (Read-Host "Enter ComputerName"),
    [string]$GroupName = $Result 
)

    $Title = "Add Lincpass Exemption"
    $Message = "Which AD Group would you like to Add the User to?"
    $OCIO = New-Object System.Management.Automation.Host.ChoiceDescription "&OCIO","OCIO 30 Day Exemption Group"
    $RD = New-Object System.Management.Automation.Host.ChoiceDescription "&RD","RD 30 Day Exemption Group"
    $FPAC = New-Object System.Management.Automation.Host.ChoiceDescription "&FPAC","FPAC 30 Day Exemption Group"
    $NITC = New-Object System.Management.Automation.Host.ChoiceDescription "&NITC","NITC 30 Day Exemption Group"
    $Options = [System.Management.Automation.Host.ChoiceDescription[]]($OCIO,$RD,$FPAC,$NITC)
    $result = $host.ui.PromptForChoice($title, $message, $options, 0)

    Switch($result){
    0{Add-ADGroupMember "AIOG-PIV-User-30Day-Exempt"-Members $UserName ; Add-ADGroupMember -Identity "AIOG-PIV-Machine-30Day-Exempt" -Members (Get-ADComputer -Identity $ComputerName)}
    1{Add-ADGroupMember "ARDG-PIV-User-30Day-Exempt"-Members $UserName ; Add-ADGroupMember -Identity "ARDG-PIV-Machine-30Day-Exempt" -Members (Get-ADComputer -Identity $ComputerName)}
    2{Add-ADgroupMember "AFPG-PIV-User-30Day-Exempt"-Members $UserName ; Add-ADgroupMember -Identity "AFPG-PIV-Machine-30Day-Exempt" -Members (Get-ADComputer -Identity $ComputerName)}
    3{Add-ADgroupMember "ATCG-PIV-User-30Day-Exempt"-Members $UserName ; Add-ADgroupMember -Identity "ATCG-PIV-Machine-30Day-Exempt" -Members (Get-ADComputer -Identity $ComputerName)}
    }
