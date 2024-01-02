[CmdletBinding()] 
param(  
    [string]$ComputerName =(Read-Host "Enter Computer Name"), 
    [string]$GroupName = $Result 
)
        
    $Title = "Add Lincpass Exemption"
    $Message = "Which AD Group would you like to Add the Computer to?"
    $OCIO = New-Object System.Management.Automation.Host.ChoiceDescription "&OCIO","OCIO 30 Day Exemption Group"
    $RD = New-Object System.Management.Automation.Host.ChoiceDescription "&RD","RD 30 Day Exemption Group"
    $FPAC = New-Object System.Management.Automation.Host.ChoiceDescription "&FPAC","FPAC 30 Day Exemption Group"
    $Options = [System.Management.Automation.Host.ChoiceDescription[]]($OCIO,$RD,$FPAC)
    $result = $host.ui.PromptForChoice($title, $message, $options, 0)

     Switch($result){
    0{Add-ADGroupMember -Identity "AIOG-PIV-Machine-30Day-Exempt" -Members (Get-ADComputer -Identity $ComputerName)}
    1{Add-ADGroupMember -Identity "ARDG-PIV-Machine-30Day-Exempt" -Members (Get-ADComputer -Identity $ComputerName)}
    2{Add-ADgroupMember -Identity "ASAG-PIV-Machine-30Day-Exempt" -Members (Get-ADComputer -Identity $ComputerName)}
    }