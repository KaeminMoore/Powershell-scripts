﻿$Names = Import-csv "C:\Temp\MyScripts\RunClientActionsByList\Computers.csv"  
    Foreach($PC in $Names){
         $PCName = $PC.PC_Name
         $Actions ='{00000000-0000-0000-0000-000000000021}';
                   '{00000000-0000-0000-0000-000000000003}';
                   '{00000000-0000-0000-0000-000000000104}';
                   '{00000000-0000-0000-0000-000000000071}';
                   '{00000000-0000-0000-0000-000000000121}';
                   '{00000000-0000-0000-0000-000000000001}';
                   '{00000000-0000-0000-0000-000000000108}';
                   '{00000000-0000-0000-0000-000000000113}';
                   '{00000000-0000-0000-0000-000000000002}';
                   '{00000000-0000-0000-0000-000000000107}'
                  


      Invoke-WMIMethod -ComputerName $PCName -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "$Actions"
    }