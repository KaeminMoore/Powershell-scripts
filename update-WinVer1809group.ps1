<#
Phase 1 script to initite update to Win10-1809 after hours.
Must be run as admin and in an UNRESTRICTED PowerShell session (e.g. from a server)
A copy of psexec must be in the directory from which this is being run.
Use the RESULTS.TXT file as the input file for Phase 2.
V1.0 - Mike Bishop / USDA-OCIO-TSD-TX / 29 April 2019
            ___
           |   |
           |   '._   _
           |      ``` '|
       ____|           \
      `-.               |
         \ _           /
          ` `\       /`
              \   .'`
               \  \ 
                '-;
#>

Start-Transcript results.txt -append -IncludeInvocationHeader

# Prompt user for time of day to run this script
$StartTime = Read-Host -Prompt 'Enter time to start in HH:MM format (e.g., 7:00 PM as 19:00)'
Write-Host "Waiting for" $StartTime "... CTRL+C to bail out..."

# Check current time every 10 seconds and keep looping until start time comes
do 
{
Start-Sleep 10 
}
until
((get-date -UFormat %R) -ge (get-date -UFormat %R $StartTime))

foreach ($HostName in Get-Content computers.txt) { 

# First make sure target machine is awake
if (Test-Connection $HostName -quiet) {Write-Host $HostName "is alive"}
    else
    {
    Write-Host $HostName "is not online... skipping..."
        continue
    }

# See what version of Windows is currently installed on the target machine
$OSVersion = (Get-WmiObject Win32_OperatingSystem -ComputerName $HostName).version
Write-Host $OSVersion "installed on" $HostName

# Decide if we need to upgrade or skip it
if ($OSVersion.EndsWith("17763")) 
{
Write-Host $HostName "is already at version 1809... skipping"
continue}
    
# Add machine to the Win10-1809 deployment group in Active Directory
Add-ADGroupMember "AIOG-Deploy-Win10-1809" -Members $Hostname'$'

# Force a policy update on the machine
Write-Host "Updating polucy on" $Hostname
Invoke-GPUpdate -computer $Hostname -Force

# Launch insomnia on machine as a system process so it will stay awake indefinetly
# Note: this won't work if the target isn't already x64
# gotta throw errors into null because powershell interprets psexec's results as an error even though its not
Write-Host "Starting insomnia on" $Hostname
& psexec \\$Hostname -s -d "c:\Program Files (x86)\USDA\admin\bin\insomnia.exe" 2>$null

# wait a couple minutes to make sure policy updates are complete
Write-Host "Waiting 2 mins for policy updates..."
sleep -Seconds 120

# Trigger SMS cycles on machine
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
Invoke-WmiMethod -ComputerName $Hostname -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "$Actions"
Write-Host "Triggered SMS cycles on "$HostName

# Write out hostname to results.txt which will be used as the input file for the phase 2 script
Out-File .\output.txt -InputObject $HostName

}
Stop-Transcript
