Param(
    $UserName = (Read-Host "Enter User Name to Query")
    )

    Get-ADUser -Identity $username -Properties msExchHideFromAddressLists| Set-ADUser -Replace @{msExchHideFromAddressLists='FALSE'}