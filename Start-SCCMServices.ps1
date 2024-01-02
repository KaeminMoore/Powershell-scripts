$services = "PeerDistSvc","bits","smstsmgr","CmRmService","RpcSs","RemoteRegistry","LanmanServer","CcmExec","Winmgmt","WinRM","wuauserv","LanmanWorkstation"
$Computername = (Read-Host "Enter Computer Name to start SCCM services")
get-service -computername $Computername -name $services | % {

 Write-host "$($_.name) on $Computername is $($_.status)"
 If ($_.status -eq 'stopped') {     
         Write-host "Starting $($_.name) ..."
         Write-host "$($_.name) is started"
         $_.Start()}
elseIf ($_.status -eq 'running') {
         Write-host "$($_.name) is Running"
          }
         }