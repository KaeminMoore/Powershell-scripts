
Param(
        [Parameter(Mandatory=$True,
                   ValueFromPipeline=$True,
                   ValueFromPipelineByPropertyName=$True)]
        [string[]]$ComputerName = (Read-Host "Enter Computer Names"),
        [string]$UserName = (Read-Host "Enter Your Admin Account"),
        
        [switch]$force,

        [Parameter(ParameterSetName='Logoff')]
        [Switch]$Logoff,

        [Parameter(ParameterSetName='Restart')]
        [Switch]$Restart,

        [Parameter(ParameterSetName='Shutdown')]
        [Switch]$Shutdown,

        [Parameter(ParameterSetName='PowerOff')]
        [Switch]$PowerOff

        )
        
        
    PROCESS {
        Foreach ($Computer in $ComputerName) {

        If(Test-Connection -ComputerName $Computer -Quiet) {
            $works = $True
              try {
                Get-WmiObject -Class Win32_BIOS -ErrorAction Stop -ComputerName $Computer
                } Catch {
                    $works = $False
                }
                }
            
        if($works) {
            $os = Get-WmiObject $Computer -Class Win32_OperatingSystem  -Credential 
            if($LogOff) {$arg = 0}
            if($Restart){$arg = 2}
            if($Shutdown){$arg = 1}
            if($PowerOff){$arg = 8}
            if($Force) {$arg += 4}
            try {
                $ErrorActionPreference = 'Stop'
                $os.Win32Shutdown($arg)
                $ErrorActionPreference = 'Continue'
                } catch {
                Write-Error "Action Failed"
                }
            }
        }
 }
   
