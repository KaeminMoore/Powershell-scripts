
 
#Running Function

# Input the process you want to monitor, returns when the process is finished

Function Running($proc)

{

    $Now = "Exists"

    While ($Now -eq "Exists")

    {

        If(Get-Process $proc -ErrorAction silentlycontinue)

        {

            $Now = "Exists"

            "INFO   : $proc is running, waiting 15 seconds" >> $LogFile

            Sleep -Seconds 15

        }

        Else

        {

            $Now = "Nope"

            "INFO   : $proc has finished running" >> $LogFile

        }

    }

}

 

$Error.Clear()

$exe = "C:\Windows\ccmsetup\ccmsetup.exe"

$Uarg = "/uninstall"

$Iarg = "smssitecode=KCC"

$wmiC = "C:\temp\SCCM_Repair\wmirepair.exe"  #*** Change this to where you run from, I use push.bat (later post)

$wmiA = "/CMD"

$strComputer = Get-Content env:computername

 

"Working on $strComputer" 

 

If(Test-Path c:\temp\SCCM.log -ErrorAction SilentlyContinue)

{

    Remove-Item c:\temp\sccm.log

    IF (! $?) {"ERROR: Unable to delete old sccm.log"}

    ELSE {"SUCCESS: Removed old sccm.log"}

}

 

$LogFile = "C:\temp\sccm.log"

 

"Working on $strComputer" >> $LogFile

IF (! $?) {"ERROR: Unable to Create sccm.log"}

ELSE {"SUCCESS: Created sccm.log, logging continues there"

      "SUCCESS: Created sccm.log on $strComputer">> $LogFile}

 

If(Test-Path C:\Windows\ccmsetup\ccmsetup.exe -ErrorAction SilentlyContinue)

{

    "SUCCESS: Found existing CCMSetup.exe" >> $LogFile

 

    #Uninstall the Client

    "INFO   : Running $exe $Uarg on system $strComputer" >> $LogFile

    &$exe $Uarg 

    Running CCMSetup

    If (! $?) {"ERROR: The ccmsetup /uninstall did not exit cleanly" >> $LogFile

               "    I'm going to continue, the next steps may fix it" >> $LogFile

               $Error.clear}

    Else {"SUCCESS: Completed CCMSETUP.EXE /Uninstall" >> $LogFile }

 }

 





#Sleep 10 for WMI Startup

"INFO   : Sleeping 10 Seconds for WMI Shutdown" >> $LogFile

Sleep -Seconds 10

 

#Rename The Repository


# Step 1, check to see if there is an old backup repository.  Remove it.

If(Test-Path C:\Windows\System32\wbem\repository.old -ErrorAction SilentlyContinue)

    {

        Remove-Item -Path C:\Windows\System32\wbem\repository.old -Recurse -Force -ErrorAction SilentlyContinue

        If (! $?) {"ERROR: Could not delete the old repository backup, check permissions" >> $LogFile

               $Error.clear}

        Else {"SUCCESS: Removed the old repository back." >> $LogFile

              "    NOTE: You've done this before, there may be deeper system issues" >> $LogFile}

    }

 

# Step 2, rename existing repository directory.

Rename-Item -Path C:\Windows\System32\wbem\repository -NewName 'Repository.old' -Force -ErrorAction SilentlyContinue

If (! $?) {"ERROR: Could not rename the existing repository, check permissions" >> $LogFile

               $Error.clear}

Else {"SUCCESS: SUCCESS: Renamed Repository" >> $LogFile }







#Sleep 10 for WMI Startup

"Sleeping 10 Seconds for WMI Startup" >> $LogFile

Sleep -Seconds 10



#Start other services that WMI typically takes down with it

 

Start-Service iphlpsvc -ErrorAction SilentlyContinue 

If (! $?) {"ERROR: Could not start IP Helper, might not be needed in this environment" >> $LogFile

               $Error.clear}

Else {"SUCCESS: SUCCESS: Started IP Helper" >> $LogFile }    

       


 

#Sleep 1 Minute to allow the WMI Repository to Rebuild

"INFO   : Sleep 1 Minute to allow the WMI Repository to Rebuild" >> $LogFile

Sleep -Seconds 60

 



"INFO   : Running WMI Repair" >> $LogFile

&$wmiC $wmiA

Running WMIRepair

If (! $?) {"ERROR: WMIRepair encountered errors, check output" >> $LogFile

               $Error.clear}

Else {"SUCCESS: WMIRepair Success" >> $LogFile }    

 

#Sleep 10 just in case WMI is still trashing from WMIRepair; #SeenItOnce

"INFO   : Sleeping 10 Seconds for system stability" >> $LogFile

Sleep -Seconds 10



#Install the client

"Running $exe $Iarg" >> $LogFile

&$exe $Iarg

Running CCMSetup

If (! $?) {"ERROR: CCMSETUP install encountered errors, check ccmsetup.log" >> $LogFile

               $Error.clear}

Else {"SUCCESS: CCMSETUP install completed successfully" >> $LogFile }      

 

#Report Completion back to the command line

$CCMTime = Get-Item -Path C:\Windows\ccmsetup\ccmsetup.cab | Select-Object -Property CreationTime

"CCM Installed on $CCMTime" 
