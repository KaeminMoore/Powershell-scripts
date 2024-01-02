Param(
    $UserName = (Read-Host "Enter User Name to Query")
    )


$AD = get-aduser $UserName -Properties * 


    $props = [ordered]@{
                     'User Name'=$AD.sAMAccountName;
                     'Display Name'=$AD.displayName;
                     'Department'=$AD.description;
                     'Office'=$AD.physicalDeliveryOfficeName;
                     'Phone Number'=$AD.telephoneNumber;
                     'Email'=$AD.mail;
                     'Home Folder'=$AD.HomeDirectory;
                     'Skype Login'=$AD.'msRTCSIP-PrimaryUserAddress';
                     'Last Login'=[DateTime]::FromFileTime($AD.LastLogon);
                     'Last Pwd Date'=[DateTime]::FromFileTime($AD.pwdLastSet);
                            
                    }


$obj = New-object -TypeName PSObject -Property $props
Write-Output $obj