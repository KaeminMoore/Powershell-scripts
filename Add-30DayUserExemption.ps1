[CmdletBinding()] 
param( 
    [parameter(Mandatory=$true)] 
    [string]$UserName, 
    [string]$GroupName = $Result 
)

    $Title = "Add Lincpass Exemption"
    $Message = "Which AD Group would you like to Add the User to?"
    $OCIO = New-Object System.Management.Automation.Host.ChoiceDescription "&OCIO","OCIO 30 Day Exemption Group"
    $RD = New-Object System.Management.Automation.Host.ChoiceDescription "&RD","RD 30 Day Exemption Group"
    $FPAC = New-Object System.Management.Automation.Host.ChoiceDescription "&FPAC","FPAC 30 Day Exemption Group"
    $Options = [System.Management.Automation.Host.ChoiceDescription[]]($OCIO,$RD,$FPAC)
    $result = $host.ui.PromptForChoice($title, $message, $options, 0)

    Switch($result){
    0{Add-ADGroupMember "AIOG-PIV-User-30Day-Exempt"-Members $UserName}
    1{Add-ADGroupMember "ARDG-PIV-User-30Day-Exempt"-Members $UserName}
    2{Add-ADgroupMember "AFPG-PIV-User-30Day-Exempt"-Members $UserName}
    }


