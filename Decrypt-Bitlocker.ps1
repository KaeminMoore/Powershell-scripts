Param(
    $ComputerName = (Read-Host "Enter Computer Name")
)
$BitLocker = Get-WmiObject -Namespace "Root\cimv2\Security\MicrosoftVolumeEncryption" -Class "Win32_EncryptableVolume" -ComputerName $ComputerName -Filter "DriveLetter = 'c:'"

                $ReturnCode = $BitLocker.Decrypt()

                switch ($ReturnCode.ReturnValue){

                    "0"{$Return = "Uncryption started successfully.";break}

                    "2150694912"{$Return = "The volume is locked.";Break}

                    "2150694953" {$Return = "This volume cannot be decrypted because keys used to automatically unlock data volumes are available.";Break}

                    default {$Return = "Uknown return code.";break}

                }

return $return