param( 
    [string]$UserName = (Read-Host "Enter UserName"),
    [string]$GroupName = $Result 
)

    $Title = "Delete Home Folder "
    $Message = "Which Home Folder Server Do you want to Delete From?"
    $AIOMOSTL3fp8 = New-Object System.Management.Automation.Host.ChoiceDescription "&AIOMOSTL3FP8","OCIO Home Folders"
    $MOSTLOUIS3s621 = New-Object System.Management.Automation.Host.ChoiceDescription "&MOSTLOUIS3S621","DCIO & NFAOC Home Folders"
    $AIOMOST23FP1 = New-Object System.Management.Automation.Host.ChoiceDescription "&AIOMOST23FP1","RD Home Folders"
    $MOSTLOUISs622 = New-Object System.Management.Automation.Host.ChoiceDescription "&MOSTLOUIS3S622","CSC Home Folders"
    $AIOMOSTL3fp9 = New-Object System.Management.Automation.Host.ChoiceDescription "&AIOMOSTL3FP9","FPAC Home Folders"
    $MOKA3 = New-Object System.Management.Automation.Host.ChoiceDescription "&MOKA3","NITC Home Folders"
    $COFT3 = New-Object System.Management.Automation.Host.ChoiceDescription "&COFT3","NRCS Home Folders"
    $Options = [System.Management.Automation.Host.ChoiceDescription[]]($AIOMOSTL3FP8,$MOSTLOUIS3s621,$AIOMOST23FP1,$MOSTLOUISs622,$AIOMOSTL3fp9,$MOKA3,$COFT3)
    $result = $host.ui.PromptForChoice($title, $message, $options, 0)

    Switch($result){
    0{get-item "\\aiomostl3fp8\Home`$\CTS\$userName" | remove-item -recurse -force}
    1{get-item "\\mostlouis3s621\Home\$userName" | remove-item -recurse -force}
    2{get-item "\\aiomost23fp1\Home$\RD\$userName" | remove-item -recurse -force}
    3{get-item "\\mostlouis3s622\Home\$userName" | remove-item -recurse -force}
    4{get-item "\\aiomostl3fp9\Home`$\FSA\$username" | remove-item -Recurse -Force}
    5{get-item "\\usda.net\ocio\HOME\MOKA3\DISC\$username" | remove-item -Recurse -force}
    6{get-item "\\usda.net\NRCS\HOME\COFT3\NRCS\$username" | remove-item -Recurse -force}
    }