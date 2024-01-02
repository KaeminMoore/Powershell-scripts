Function Write-LogandHost {
<#
	.SYNOPSIS
       Produces log and host output

        .DESCRIPTION
        Produces log and host ouput
        Takes any strings separated by a return and adds them to the output
	In the log output the date and time at the beginning of the line in the format, [YYYY]-[MM]-[DD] [HH]:[MM]:[SS]
	In the host output at the beginning of the line an " * " is added.
	If the string passed to the function is null it will output a blank line to the host and log.
	The log and host output can be turned on or off.

        .PARAMETER LogFile
        Specifies the location and name of the log file.  If none is provided it will create the following, $Env:temp\Logs\Framework.log.  This is a string parameter.

        .PARAMETER Text
        Specifies string or strings to be included in the host and / or log output.  This is a string parameter.

        .PARAMETER Color
        Specifies the host output text color.  The default color is white.  It is looking for a System.ConsoleColor.

        .PARAMETER DisplayOutput
        Specifies whether or not the host output is displayed.  The default is true.  This is a boolean parameter.

        .PARAMETER LogOutput
        Specifies whether or not the log output is generated.  The default is true.  This is a boolean parameter.

        .PARAMETER NoNewLine
        Specifies that a new line in the log or host output is not generated.  This is a switch parameter.

        .PARAMETER NoDateInLog
        Specifies that a in the log output the date and time are not included.  This is a switch parameter.

        .PARAMETER NoStarInHost
        Specifies that a in the host output the " * " is not included.  This is a switch parameter.

        .INPUTS
        None

        .OUTPUTS
        Returns a text string to a log file.
	Returns a text string to the host.

        .EXAMPLE
        C:\PS> Write-LogandHost "This is a test." -logfile $LogFile -DisplayOutput $DisplayOutput
        " * This is a test" - will be displayed in the host.
	"[YYYY]-[MM]-[DD] [HH]:[MM]:[SS] - This is a test" - will be written to the log file.

    #>
	[CmdletBinding(SupportsShouldProcess=$true)]
	Param (
		[parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]
		[String] $LogFile = $env:temp + "\logs\Framework.log",
		[parameter(Mandatory=$True,ValueFromPipeline=$true)]
		[AllowEmptyString()]
		[AllowNull()]
		[String[]] $text,
		[parameter(Mandatory=$false,ValueFromPipeline=$true)]
		[System.ConsoleColor] $Color = [System.ConsoleColor]::White,
		[parameter(Mandatory=$false,ValueFromPipeline=$true)]
		[Bool] $DisplayOutput = $True,
		[parameter(Mandatory=$false,ValueFromPipeline=$true)]
		[Bool] $LogOutput = $True,
		[parameter(Mandatory=$false,ValueFromPipeline=$true)]
		[Switch] $NoNewLine,
		[parameter(Mandatory=$false,ValueFromPipeline=$true)]
		[Switch] $NoDateInLog,
		[parameter(Mandatory=$false,ValueFromPipeline=$true)]
		[Switch] $NoStarInHost
	)
	Begin {
		IF (!([String]::IsNullOrEmpty($LogFile))){
			$LogFilePath = Split-Path $LogFile
			IF (!(Test-Path -Path $LogFilePath)) {New-Item -itemtype directory -path $LogFilePath -Force > $Null}
		}
	}
	Process {
		$text -Split '\n' | Foreach-Object {
			$line = $_
			IF ([String]::IsNullOrEmpty($line)){
				IF ($LogOutput -eq $True) {" " | Out-File $LOGFILE -Append -Encoding utf8}
				IF ($DisplayOutput -eq $True) {Write-host }
			}
			Else {
				IF ($LogOutput -eq $True) {
					IF ($NoDateInLog) { 
						$line | Out-File -FilePath $LOGFILE -Append  -Encoding utf8 -NoNewline:$(if ($NoNewLine) {$true} else {$false})
					}					
					ELSE {
						$DateNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
						"$DateNow - $line" | Out-File -FilePath $LOGFILE -Append  -Encoding utf8 -NoNewline:$(if ($NoNewLine) {$true} else {$false})
					}
				}
				IF ($DisplayOutput -eq $True) {
					IF (!($NoStarInHost)) {$line = " * " + $line }
					Write-Host -Object $line -backgroundcolor "Black" -ForegroundColor $Color -NoNewline:$(if ($NoNewLine) {$true} else {$false})
				}
			}
		}
	}
	End {}
}
Function Test-AdminRights {
<#
	.SYNOPSIS
	Checks to see IF the user running the script has administrative rights
	.DESCRIPTION
	Checks to see IF the user running the script has administrative rights
	IF the user has administrative rights the script will return a boolean of true.
	IF the user does not have administrative rights the script will return a boolean of false.

        .PARAMETER User
        Specifies the user account to check for administrative rights.  This is a string parameter.  It is mandatory.
	
        .PARAMETER NotSilent
        Specifies that an output to the host / log will be written.  This is a switch parameter.

	.EXAMPLE
	C:\PS> Test-AdminRights -User $Env:Username -NotSilent
	Running in $User's context with administrative rights

	.EXAMPLE
	C:\PS> Test-AdminRights -User $Env:Username
	$True

#>
	[CmdletBinding( )]
	Param (
		[parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[String] $User,
		[Switch] $NotSilent
	)
	Begin {
		IF ([String]::IsNullOrWhiteSpace($Env:username)) {$User = "NT AUTHORITY\SYSTEM"} else {$User = $Env:Username}
		$UserPlural = $Env:Username + "'s"
	}
	Process {
		IF (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
			IF ($NotSilent) { Write-LogandHost "Running script in $UserPlural context without administrative rights" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) }
			Write-Output $False
		}
		else {
			IF ($NotSilent) { Write-LogandHost "Running in $UserPlural context with administrative rights" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) }
			Write-Output $True
		}
	}
	End {}
}
Function Get-SystemType {
<#
	.SYNOPSIS
	Finds the domain role of the system and uses that to determine IF the host is a server or workstation
	.DESCRIPTION

	It finds the domain role

	"0 = Standalone workstation"
	"1 = Member workstation"
	"2 = Standalone server"
	"3 = Member Server"
	"4 = Backup Domain Controller"
	"5 = Primary Domain Controller"

	If it is a server type it marks it with an S
	If it is a workstation type it marks it with a W
	
        .PARAMETER ComputerName
        Specifies the name of the system being checked.  This is a string parameter.  If no parameter is provided it will default to the name of the current system, $Env:Computername.

	.EXAMPLE
	C:\PS> Get-SystemType
	S

#>
	[CmdletBinding()]
	Param (
		[String]$ComputerName = $env:Computername
	)
	Begin {}
	Process {
		TRY {
			IF ($ComputerName -eq $env:Computername){
				$DomainRole = (Get-CimInstance -Class Win32_Computersystem).DomainRole.ToString()
			}
			Else {
				$DomainRole = (Get-CimInstance -Class Win32_Computersystem -ComputerName $ComputerName).DomainRole.ToString()
			}
			Write-Verbose "Domain Role: $DomainRole"
			Switch ($DomainRole) {
				0 {Write-Output "W"}
				1 {Write-Output "W"}
				2 {Write-Output "S"}
				3 {Write-Output "S"}
				4 {Write-Output "S"}
				5 {Write-Output "S"}
				Default {Write-Output ""}
			}
		}
		CATCH {
			Write-Warning "Unable to find System Type"
		}
	}
	End { }
}
Function Get-HostType {
<#
	.SYNOPSIS
	Determines if the system is physical or virtual.
	.DESCRIPTION
	Determines if the system is physical or virtual.
	The function gets the system model from Win32_Computersystem.
	Then checks to see if one of the following are part of the model.
		"Virtual Machine"
		"VMware Virtual Platform"
		"VirtualBox"
		"HVM domU"
	If any of the above exists the function returns a V for Virtual.
	If none of them exist the function returns a P for Physical.
	
        .PARAMETER ComputerName
        Specifies the name of the system being checked.  This is a string parameter.  If no parameter is provided it will default to the name of the current system, $Env:Computername.

	.EXAMPLE
	C:\PS> Get-HostType
	V
#>
	[CmdletBinding()]
	Param (
		[String]$ComputerName = $env:Computername
	)
	Begin {}
	Process {
		TRY {
			IF ($ComputerName -eq $env:Computername){
				$SystemModel = (Get-CimInstance -Class Win32_Computersystem).Model.ToString()
			}
			Else {
				$SystemModel = (Get-CimInstance -Class Win32_Computersystem -ComputerName $ComputerName).Model.ToString()
			}
			Write-Verbose "Domain Role: $SystemModel"
			Switch ($SystemModel) {                    
			    # Check for Hyper-V Machine Type
			    "Virtual Machine" {Write-Output "V"}
			    # Check for VMware Machine Type
			    "VMware Virtual Platform" {Write-Output "V"}
			    # Check for Oracle VM Machine Type
			    "VirtualBox" {Write-Output "V"}
			    # Check for Xen
			    "HVM domU" {Write-Output "V"}
			    # Check for KVM
			    # I need the values for the Model for which to check.
			    # Otherwise it is a physical Box
			    Default {Write-Output "P"}
                    }
		}
		CATCH {
			Write-Warning "Unable to find host Type"
		}
	}
	End { }
}
Function Get-SystemInformation {
<#
	.SYNOPSIS
	Creates a PS Object with system information in it
	.DESCRIPTION
	Creates a PS Object with system information in it
	The following information is added to the object.
		"SystemArch" = Processor Architecture from Win32_Processor
		"WinVersion" = Operating system version from [Environment]::OSVersion.Version
		"WinVerMajorMinor" = Operating system version, just the major and minor parts
		"RegistryWinVersion" = Operating system version from "HKLM:\Software\Microsoft\Windows NT\CurrentVersion"
		"OSName" = Operating system name from Win32_OperatingSystem
		"Startup" = The current user's startup folder from "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" Startup
		"PSVersion" = The PowerShell version the function is being run on.
		"InstallationRootFolder" = The drive, "$env:SystemDrive"
		"ProgramData" = The location of "$env:ProgramData"
		"SystemType" = Whether or not the system is a Server (S) or Workstation (W)
		"HostType" = Whether or not the system is a Physical (P) or Virtual (V)	
	
        .INPUTS
        None.

        .OUTPUTS
        PS Custom Object, System

	.EXAMPLE
	C:\PS> Get-SystemInformation
	[PSCustomObject]$System
#>
	[CmdletBinding ()]
	Param ()
	Begin {}
	Process {
		$System = [PSCustomObject]@{ 
			"SystemArch" = (Get-CimInstance -Class Win32_Processor | Where-Object { $_.deviceID -eq "CPU0" }).AddressWidth.ToString()
			"WinVersion" = [Environment]::OSVersion.Version
			"WinVerMajorMinor" = [System.Environment]::OSVersion.Version.Major.ToString() + "." + [System.Environment]::OSVersion.Version.Minor.ToString()
			"RegistryWinVersion" = (get-itemproperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion
			"OSName" = (Get-CimInstance -Query "Select Caption From Win32_OperatingSystem").Caption.ToString()
			"Startup" = (get-itemproperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders").Startup
			"PSVersion" = $Host.Version
			"InstallationRootFolder" = "$env:SystemDrive" + "\"
			"ProgramData" = "$env:ProgramData" + "\"
			"SystemType" = Get-SystemType
			"HostType" = Get-HostType
		}
	}
	End { Write-Output $System}
	
}
Function Write-Header {
<#
	.SYNOPSIS
	Writes header information for log or host output
	.DESCRIPTION
	Writes header information for log or host output.  This information is gathered from the system, the user, and the XML file provided.
	It includes the following information:
		Package Name
		Version of Package
		Change number
		Script Dir - The directory the package is being run from
		Log file
		Host name
		Operating System name
		Operating System version
		Operating System Architecture
		PowerShell Version.
	
        .PARAMETER EnvInfo
        Specifies the EnvInfo information that came from the XML file provided.  This parameter is mandatory.
        .PARAMETER Package
        Specifies the Package information that came from the XML file provided.  This parameter is mandatory.

	.EXAMPLE
	C:\PS> Write-Header -EnvInfo $EnvInfo -Package $Package
	2020-05-18 18:57:58 - ************************************************************************
	2020-05-18 18:57:58 - Branch Installation Wrapper Version 0.00.00.01
	2020-05-18 18:57:58 - ******************** PACKAGE INFORMATION *******************************
	2020-05-18 18:57:58 - Name: Test Package
	2020-05-18 18:57:58 - Version: 1.0.1.6
	2020-05-18 18:57:58 - Change #: CRQ00019
	2020-05-18 18:57:58 - Script Dir: C:\temp\SRC\PKG
	2020-05-18 18:57:58 - Log file: C:\ProgramData\Co\Dept\Agency\Dv\Branch\logs\CRQ00019-TestPackage\Host1.CRQ00019.ps1.log
	2020-05-18 18:57:58 - ******************** SYSTEM INFORMATION ********************************
	2020-05-18 18:57:58 - Host Name: Host1
	2020-05-18 18:57:58 - OS Name: Microsoft Windows 10 Enterprise
	2020-05-18 18:57:58 - OS Version: 10.0.18363.0
	2020-05-18 18:57:58 - OS Architecture: 64
	2020-05-18 18:57:58 - PowerShell Version: 5.1.18362.752
#>	
	[CmdletBinding( )]
	Param (
		[parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]
		$EnvInfo,
		[parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]
		$Package
	)
	Begin {}
	Process {
		# Check to see IF display output is necessary and begin displaying output
		Write-LogandHost "" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		Write-LogandHost "************************************************************************" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		Write-LogandHost "$FrameworkOwnerName Installation Wrapper Version $($Script.version)"  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green		
		Write-LogandHost "******************** PACKAGE INFORMATION *******************************" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		Write-LogandHost "Name: $($Package.PackageName)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Cyan
		Write-LogandHost "Version: $($Package.Version)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Cyan
		Write-LogandHost "Change #: $($Package.Change)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		Write-LogandHost "Script Dir: $($Script.Path)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		Write-LogandHost "Log file: $LogFile" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		Write-LogandHost "******************** SYSTEM INFORMATION ********************************" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		Write-LogandHost "Host Name: $env:Computername"  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Cyan
		Write-LogandHost "OS Name: $($System.OSName)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		Write-LogandHost "OS Version: $($System.WinVersion)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		Write-LogandHost "OS Architecture: $($System.SystemArch)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		Write-LogandHost "PowerShell Version: $($System.PSVersion)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)		
		# Check for the minimum PowerShell version
		IF ($System.PSVersion -lt $PowerShellMinimumVersion) {
			Write-LogandHost "Error: PowerShell must be at least $PowerShellMinimumVersion" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
			Stop-Framework -ExitCodes 197
		}
	}
	End {}	
}
Function Copy-ToCache {
<#
	.SYNOPSIS
	Caches the package to a specified location.
	.DESCRIPTION
	Caches the package to a specified location.
	This is done by copying the package and all the files and folders in its directory and subdirectories to the specified location
	
        .PARAMETER CachePath
        Specifies the path that the package should be cached to.  This parameter is mandatory.

	.EXAMPLE
	C:\PS> Copy-ToCache -CachePath $CachePath
	The package will be copied to the specified location and an object will be returned that contains the location.

#>
	[OutputType('System.Management.Automation.PSCustomObject')]
	[CmdletBinding(SupportsShouldProcess=$true)]
	Param (
		[String] $CachePath
	)
	Begin {
		$CacheInfo = [PSCustomObject]@{"Cached"=$null;"Location"=$null}
	}
	Process {
		Write-Verbose "Cache location: $CachePath"
		IF (!(Test-Path $CachePath)){
			New-Item -itemtype directory -path $CachePath -Force > $Null
		}
		Write-LogandHost "******************* CACHING PACKAGE ************************************" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		Write-LogandHost "Caching package to $CachePath" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green
		$Parent = $($Script.Path) |Split-Path
		IF ($Parent -ne $CachePath) {
			Copy-Item "$Parent\*" -Destination $CachePath -Recurse -Force > $Null
		}
		IF (Test-Path -Path "$CachePath\PKG") { $ScriptPath = $CachePath + "PKG" ; Set-Location -Path "$CachePath\PKG" } else {$ScriptPath = "$CachePath" ; Set-Location -Path "$CachePath"}
		Write-Verbose "Scripts Current Directory: $ScriptPath"
		$CacheInfo = [PSCustomObject]@{"Cached"=$True;"Location"=$ScriptPath}
		Write-Verbose "CacheInfo Location: $($CacheInfo.Location)"
		Write-OutPut $CacheInfo
	}
	End {}
}
Function Stop-Item {
<#
	.SYNOPSIS
	Checks to see a specified process exists and IF it does it attempts to end it
	.DESCRIPTION

	The specified process or list of processes is processed to see IF they are running.
	IF possible the script kills the running processes.

	The process should be provided without the file extension.
	IF you want to kill notepad.exe, specIFy notepad.

	.PARAMETER Processes
	This should a process or list of processes to be killed
	Ex. notepad
	This parameter is mandatory

	.PARAMETER Timeout
	This is the number of seconds the script waits for the graceful shutdown
	The default is five
	This parameter is non-mandatory

	.EXAMPLE
	PS:> Stop-Item notepad -verbose
	VERBOSE: Info: Attempting to kill the process: notepad
	VERBOSE: Success: Killed process, notepad

#>
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[string[]]$Processes,
		[parameter(Mandatory=$false, ValueFromPipeline=$false)]
		[int] $timeout = 5
	)
	Begin {}
	Process {
		Foreach ($Process in $Processes) {
			$processList = Get-Process $Process -ErrorAction SilentlyContinue
			IF ($processList) {
				Write-Verbose "Info: Attempting to kill the process: $Process"
				# Try gracefully shutdown first
				IF ($PSCmdlet.ShouldProcess("$Process","Closing the Process window")) {
					$processList.CloseMainWindow() | Out-Null
				}
				# Wait until all processes have terminated or until timeout
				for ($i = 0 ; $i -le $timeout; $i ++)
				{
					$AllHaveExited = $True
					$processList | ForEach-Object {
						$process = $_
						IF (!$process.HasExited) {
							$AllHaveExited = $False
						}
					}
					IF ($AllHaveExited) {
						Write-LogandHost "Task ($TasksProcessed): Success: Killed process, $($Process.ProcessName)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
						Break
					}
					Start-Sleep -s 1
				}
				# Else: kill
				$processList | Stop-Process -Force -ErrorAction SilentlyContinue -ErrorVariable ProcessError
				IF ($ProcessError) {Write-Warning "Error: Failed to end $Process"}
			}
		}
	}
	End { }
}
Function Compare-OS {
<#
	.SYNOPSIS
        Compares the allowed Operating Systems (OS's) to the OS of the host system if the OS is allowed it returns a true.

        .DESCRIPTION
	Compares the allowed Operating Systems (OS's) to the OS of the host system if the OS is allowed it returns a true.

        .PARAMETER OperatingSystems
        Specifies allowed OS's.  This parameter is not mandatory.
	If nothing is specified it allows any OS, greater than or equal to 5.1
	If there is more than one OS it should be separated by a "|".
	A plus sign, "+", indicates that it will allow any OS greater than or equal to that OS.

        .PARAMETER Extension
        Specifies the extension. "Txt" is the default.

        .INPUTS
        String of OS versions.

        .OUTPUTS
        Boolean

        .EXAMPLE
        C:\PS> Compare-OS -OperatingSystems 5.1|5.2|6.3+
        True
    #>
	[CmdletBinding()]
	Param (
		[parameter(Mandatory=$FALSE)]
		[String]$OperatingSystems = "5.1+"
	)
	Begin {
		# ASCII Character
		$plus=[char]43
		# Get System Information
		$System = Get-SystemInformation
		# Booleans
		$AllowedOS = $False
		# Begin
		Write-Verbose "Host OS: $WinVersion"
		Write-Verbose "All OS's being compared $OperatingSystems"
		IF ($OperatingSystems -Match "|") {$AllOperatingSystems = $OperatingSystems.Split("|")}
	}
	Process {
		Foreach ($OS in $AllOperatingSystems){
			Write-Verbose "OS being reviewed: $OS"
			#Check for plus sign, "+"
			IF ($OS -Match "\$plus") {
				Write-Verbose "Comparison should be greater than or equal to OS version"
				$OS = $OS -replace "[/\+/g]", ""
				$GE = $True
			}
			ELSE {
				Write-Verbose "Comparison should be equal to OS version"
				$GE = $False
			}
			IF ($GE -eq $True) {
				IF (([Version]$($System.WinVersion) -ge [Version]$OS) -OR ([Version]$($System.RegistryWinVersion) -ge [Version]$OS)) {
					Write-LogandHost "Task ($TasksProcessed): The host OS, $($System.WinVersion), is greater than or equal to the requested $OS, the task will run" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					$AllowedOS = $True
				}
			}
			ELSE {
				IF (([Version]$($System.WinVersion) -eq [Version]$OS) -OR ([Version]$($System.WinVerMajorMinor) -eq [Version]$OS) -OR ([Version]$($System.RegistryWinVersion) -eq [Version]$OS)) {
					Write-LogandHost "Task ($TasksProcessed): Requested OS, $($Task.OperatingSystem) matches the host OS, $($System.WinVersion), the task will run" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					$AllowedOS = $True
				}
			}
		}
	}
	End {
		Write-Output $AllowedOS
	}
}
Function Find-Path {
<#
	.SYNOPSIS
        Finds out if the directory or file exists on the system

        .DESCRIPTION
	Finds out if the directory or file exists on the system.
	It returns a PSCustomObject that contains whether or not the path was found, true, or not found.
	Depending on whether or not the switch was true or false the above will be reversed.

        .PARAMETER Path
        String path.  This parameter is mandatory.

        .PARAMETER Switch
        Boolean parameter.  Determines if the item should be found, $true, or not found, $false.
	This parameter is mandatory.

        .PARAMETER Wait
        This is a switch parameter.  If this is added when the function is called no host output will appear.
	This parameter is not mandatory

        .INPUTS
        String of path[s] to check

        .OUTPUTS
        PSCustomObject

        .EXAMPLE
        C:\PS> Find-Path -Path $Path -Switch $True
        True
    #>
	[OutputType('System.Management.Automation.PSCustomObject')]
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[string[]]$Path,
		[parameter(Mandatory=$true)]
		[Bool] $Switch,
		[parameter(Mandatory=$false)]
		[Switch] $Wait,
		[parameter(Mandatory=$false)]
		[Int] $WaitCounter
	)
	Begin {
		$PathStatus = [PSCustomObject]@{
			"ComputerName"=$env:computername
			"RequestedResult"=$Switch
			"ActualResult"=$null
		}
		
	}
	Process {
		foreach ($item in $Path){
			IF ((Test-Path $item) -eq $Switch){
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): The path, $item was verified to be $Switch" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
				}
				$PathStatus.ActualResult = $True
			}
			ELSE {
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): The path, $item was NOT verified to be $Switch" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
				}
				$PathStatus.ActualResult = $False
			}
			IF ($Path.Count -eq 1) {Write-Output $PathStatus.ActualResult}
			ELSE {Write-Output $PathStatus}
		}
	}
	End {}
}
Function Find-FileVersion {
<#
	.SYNOPSIS
        Checks to see if a file is the version specified.

        .DESCRIPTION
	Checks to see if a file is the version specified.

        .PARAMETER Path
        Specifies the path to the file where the version is to be checked and the version to be checked for separated by a "|".

        .PARAMETER Switch
        This is expecting a boolean and lets the function know if the version should match or not match. 

        .PARAMETER Wait
        This is a switch parameter.  If it exists no host output will be produced.	
	
        .INPUTS
        String path to file with extension.

        .OUTPUTS
       Boolean or PS CustomObject.  If one item is sent to the function a boolean is returned.  If multiple items are sent it returns a PS Object.

        .EXAMPLE
        C:\PS> Find-FileVersion -Path "%windir%\System32\Notepad.exe|10.2"
        $True

    #>
	[OutputType('System.Management.Automation.PSCustomObject')]
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[string[]]$Path,
		[parameter(Mandatory=$true)]
		[Bool] $Switch,
		[parameter(Mandatory=$false)]
		[Switch] $Wait,
		[parameter(Mandatory=$false)]
		[Int] $WaitCounter		
	)
	Begin {
		$FileVersionInfo = [PSCustomObject]@{
			"ComputerName"=$env:computername
			"FileName" = $null
			"RequestedVersion" = $null
			"FileVersion" = $null
			"ProductVersion" = $null
			"RequestedResult"=$Switch
			"ActualResult"=$null
		}
	}
	Process {
		foreach ($item in $Path){
			$FileVersionInfo.Filename,$FileVersionInfo.RequestedVersion = $item.Split("|")
			$FileVersionInfo.FileVersion = (Get-Command -Name $($FileVersionInfo.Filename) -ea SilentlyContinue).FileVersionInfo.FileVersion
			$FileVersionInfo.ProductVersion = (Get-Command -Name $($FileVersionInfo.Filename) -ea SilentlyContinue).FileVersionInfo.ProductVersion

			IF (Test-Path $FileVersionInfo.Filename) {
				Write-Verbose "The $($FileVersionInfo.Filename) exists, it will be checked for its version"
				IF ((($FileVersionInfo.FileVersion -eq $FileVersionInfo.RequestedVersion) -eq $Switch) -OR (($FileVersionInfo.ProductVersion -eq $FileVersionInfo.RequestedVersion) -eq $Switch)) {					
				    IF ($Wait -eq $True) {
					    # Do nothing wait is true
				    } 
				    ELSE {
					    Write-LogandHost "Task ($TasksProcessed): $item was verified to be $Switch, the task will run" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
				    }
					$FileVersionInfo.ActualResult = $True
				}
				ELSE {
				    IF ($Wait -eq $True) {
					    # Do nothing wait is true
				    } 
				    ELSE {
					    Write-LogandHost "Task ($TasksProcessed): $item was NOT verified to be $Switch, the task will NOT run" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
				    }
					$FileVersionInfo.ActualResult = $False
				}
			}
			ELSE {				
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): Warning: The $($FileVersionInfo.Filename) does Not exist, it will not be checked for its version" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
				}
				$FileVersionInfo.ActualResult = $False
			}
			IF ($Path.Count -eq 1) {Write-Output $FileVersionInfo.ActualResult}
			ELSE {Write-Output $FileVersionInfo}
		}
	}
	End {}
}
Function Compare-LocalDiskSpace {
<#
	.SYNOPSIS
        Checks to see the specified hard drive has the requested space.

        .DESCRIPTION
	Checks to see the specified hard drive has the requested space.
	The format is "[Drive letter]|[Space desired]|[Unit of measure]"
	The units of measure are PB, TB, GB, MB, and KB.

        .PARAMETER Path
        Specifies the drive letter, space desired, and unit of measure.
	The format is "[Drive letter]|[Space desired]|[Unit of measure]".

        .PARAMETER Wait
        This is a switch parameter.  If it exists no host output will be produced.	
	
        .INPUTS
        String path to file with extension.

        .OUTPUTS
       Boolean

        .EXAMPLE
        C:\PS> Compare-LocalDiskSpace -Path "C|10.2|PB"
        False

    #>
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[string]$Path,
		[parameter(Mandatory=$false)]
		[Switch] $Wait,
		[parameter(Mandatory=$false)]
		[Int] $WaitCounter	
	)
	Begin { }
	Process {
		TRY {
			$DriveLetterToCheck,$SpaceWanted,$UnitofMeasure = $Path.Split("|")
			$DriveLetterToCheck = $DriveLetterToCheck + ":"
			$SpaceWanted = [int]$SpaceWanted
			IF ($Wait -eq $True) {
				# Do nothing wait is true
			} 
			ELSE {
				Write-LogandHost "Task ($TasksProcessed): Checking $DriveLetterToCheck for $SpaceWanted $UnitofMeasure of free space ..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			}
			#Find actual free space on drive specified
			IF(Test-Path -Path $DriveLetterToCheck) {
				Write-Verbose "The drive, $DriveLetterToCheck, exists on $env:computername"
				#Get requested disk information
				$RequestedDiskInfo = Get-CimInstance -Class Win32_LogicalDisk |Where-Object {$_.DeviceID -eq "$DriveLetterToCheck"}
				$Freespace1 = $RequestedDiskInfo.FreeSpace

				Switch ($UnitofMeasure) {
					"PB" {$Actualspace = "{0:N2}" -f ($Freespace1 / 1PB)}
					"TB" {$Actualspace = "{0:N2}" -f ($Freespace1 / 1TB)}
					"GB" {$Actualspace = "{0:N2}" -f ($Freespace1 / 1GB)}
					"MB" {$Actualspace = "{0:N2}" -f ($Freespace1 / 1MB)}
					"KB" {$Actualspace = "{0:N2}" -f ($Freespace1 / 1KB)}
					default {$Actualspace = "{0:N2}" -f ($Freespace1 / 1MB)}
				}
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): Actual freespace on $DriveLetterToCheck = $Actualspace $UnitofMeasure" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
				}
				# $Actualspace = [int]$Actualspace
				IF([decimal]$Actualspace -ge $SpaceWanted) {
				    IF ($Wait -eq $True) {
					    # Do nothing wait is true
				    } 
				    ELSE {
					    Write-LogandHost "Task ($TasksProcessed): Success: $DriveLetterToCheck was found to have $SpaceWanted $UnitofMeasure!" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
				    }
					Write-OutPut $True
				}
				ELSE {
				    IF ($Wait -eq $True) {
					    # Do nothing wait is true
				    } 
				    ELSE {
					    Write-LogandHost "Task ($TasksProcessed): Error: $DriveLetterToCheck was found NOT to have $SpaceWanted $UnitofMeasure; actual drive space on $DriveLetterToCheck is $Actualspace $UnitofMeasure" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
				    }
					Write-OutPut $False
				}
			}
			ELSE {
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): Error: Drive letter, $DriveLetterToCheck, does not exist" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
				}
				Write-OutPut $False
			}
		}
		CATCH {
			IF ($Wait -eq $True) {
				# Do nothing wait is true
			} 
			ELSE {
				Write-LogandHost "Task ($TasksProcessed): Check Freespace Failed: Processing $Value - $_" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
			}
		}
	}
	End {}
}
Function Find-Process {
<#
	.SYNOPSIS
        Checks to see if the specified process is running

        .DESCRIPTION
	 Checks to see if the specified process is running
	 Multiple processes are split by the "|" symbol.

        .PARAMETER Process
        Specifies the process or processes that are being checked to see if they are running.

        .PARAMETER Wait
        This is a switch parameter.  If it exists no host output will be produced.	
	
        .INPUTS
        Name of process

        .OUTPUTS
	Boolean or PS CustomObject.  If one item is sent to the function a boolean is returned.  If multiple items are sent it returns a PS Object.

        .EXAMPLE
        C:\PS> Find-Process -Process "notepad"
        True

    #>
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[string[]]$Process,
		[parameter(Mandatory=$false)]
		[Switch] $Wait,
		[parameter(Mandatory=$false)]
		[Int] $WaitCounter
	)
	Begin {
		$ProcessInfo = [PSCustomObject]@{
			"ComputerName"=$env:computername
			"Name" = $null
			"Exists" = $null
		}
	}
	Process {
		$Process = $Process.Split("|")
		Foreach ($item in $Process) {
			$ProcessInfo.Name = $item
			IF ($Wait -eq $True) {
				# Do nothing wait is true
			} 
			ELSE {
				Write-LogandHost "Task ($TasksProcessed): Checking to see if $item is a running process ..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			}
			$ProcessList = Get-Process $item -ErrorAction SilentlyContinue
			IF ($ProcessList) {
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): The Process, $item exists" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
				}
				$ProcessInfo.Exists = $True
			}
			ELSE {
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): The Process, $item does NOT exist" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
				}
				$ProcessInfo.Exists = $False
			}
			IF ($Process.Count -eq 1) {Write-Output $ProcessInfo.Exists} ELSE {Write-Output $ProcessInfo}
		}
	}
	End {}
}
Function Find-OU {
<#
	.SYNOPSIS
        Checks to see if the host is within the specified Organizational Unit (OU)

        .DESCRIPTION
	 Checks to see if the host is within the specified OU
	 The OU must be in the format, "OU=Windows10,OU=Workstations,OU=[Sub-OU2],OU=[Sub-OU1],DC=[domain],DC=[root]"

        .PARAMETER OU
        Specifies the OU being checked

        .INPUTS
        OU being checked

        .OUTPUTS
	Boolean 

        .EXAMPLE
        C:\PS> Find-OU -OU "OU=Windows10,OU=Workstations,OU=[Sub-OU2],OU=[Sub-OU1],DC=[domain],DC=[root]"
        True

    #>
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[string]$OU,
		[parameter(Mandatory=$false)]
		[Switch] $Wait,
		[parameter(Mandatory=$false)]
		[Int] $WaitCounter
	)
	Begin { $loop = 3 ; $Count  = 0 }
	Process {
		TRY {
			Write-Verbose "Checking to see if the Host is within the specified OU: $OU ..."
			$strFilter = "(&(objectClass=computer)(name=$Env:Computername))"
			# Connect to the domain and create search object
			Do {
				$Count++
				$objDomain = New-Object System.DirectoryServices.DirectoryEntry
				IF ([String]::IsNullOrWhiteSpace($objDomain)){
					Write-Verbose "Could not bind directory services"
					Write-Verbose "Attempts: $Count"
					Start-Sleep -s 10
					$objDomain = New-Object System.DirectoryServices.DirectoryEntry
				}
				ELSE {
					$Count = $loop
				}
			} UNTIL ($Count -eq $loop)
			IF ([String]::IsNullOrWhiteSpace($objDomain)){
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): Check OU Failed: $_ " -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
				}
			}
			$objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher
			$objSearcher.SearchRoot = $objDomain
			$objSearcher.PageSize = 15000
			$objSearcher.Filter = $strFilter
			$objSearcher.SearchScope = "Subtree"
			# Search for System
			$AllObj = $objSearcher.FindAll()
			foreach ($ObjItem in $AllObj){ $MachineOUPath = $objItem.path }
			Write-Verbose "System OU Path: $MachineOUPath"
			if ($MachineOUPath -match $OU) {
				Write-Verbose "The Host is within the OU: $OU!"
				Write-Output $True
			}
			else {
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-Verbose "The Host is NOT within the OU: $OU"
				}
				Write-Output $False
			}
		#Return $strDNPath
		}
		CATCH {
			IF ($Wait -eq $True) {
				# Do nothing wait is true
			} 
			ELSE {
				Write-LogandHost "Task ($TasksProcessed): Eror: Check OU Failed: $_ " -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
			}
		}
	}
	End {}
}
Function Find-ServiceState {
<#
	.SYNOPSIS
        Checks to see if the specified service is in the desired state

        .DESCRIPTION
	 Checks to see if the specified service is in the desired state
	 

        .PARAMETER Service
        Specifies the service being requested followed by a pipe, "|" then the service state

        .INPUTS
        Service|State being checked

        .OUTPUTS
	Boolean 

        .EXAMPLE
        C:\PS> Find-ServiceState -Service "ccmexec|stopped"
        False

    #>
	[OutputType('System.Management.Automation.PSCustomObject')]
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[string[]]$Service,
		[parameter(Mandatory=$false)]
		[Switch] $Wait,
		[parameter(Mandatory=$false)]
		[Int] $WaitCounter
	)
	Begin {
		$ServiceInfo = [PSCustomObject]@{
			"ComputerName" = $env:computername
			"ServiceName" = $null
			"RequestedServiceState" = $null
			"ActualServiceState" = $null
			"Match" = $null
		}
	}
	Process {
		FOREACH ($Item in $Service) {
			TRY {
				$ServiceInfo.ServiceName,$ServiceInfo.RequestedServiceState = $Item.split("|")
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): Checking for service, $($ServiceInfo.ServiceName), with a status of $($ServiceInfo.RequestedServiceState) ..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
				}
				$AllServices = Get-Service
				FOREACH ($A in $AllServices) {
					$CurrServiceName = $A.ServiceName
					$CurrServiceStatus = $A.Status
					IF ($CurrServiceName -eq $ServiceInfo.ServiceName){
						$ServiceInfo.ActualServiceState = $A.Status
						IF ($CurrServiceStatus -eq $ServiceInfo.RequestedServiceState) {
							IF ($Wait -eq $True) {
								# Do nothing wait is true
							} 
							ELSE {
								Write-LogandHost "Task ($TasksProcessed): Success: $($ServiceInfo.ServiceName) was found, with a status of $($ServiceInfo.RequestedServiceState)!" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
							}
							$ServiceInfo.Match = $True
						}
						ELSE {
							IF ($Wait -eq $True) {
								# Do nothing wait is true
							} 
							ELSE {
								Write-LogandHost "Task ($TasksProcessed): Warning: $($ServiceInfo.ServiceName) was found, with a status of $($ServiceInfo.ActualServiceState) which did not match the requested state of $($ServiceInfo.RequestedServiceState)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
							}
							$ServiceInfo.Match = $False
						}
					}
				}
			} CATCH {
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): Check Service Failed: Processing $ServiceInfo - $_"  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
				}
			}
			IF ($Service.Count -eq 1) {Write-Verbose "Service Info Match: $($ServiceInfo.Match)" ; Write-Output $ServiceInfo.Match}
			ELSE {Write-Output $ServiceInfo}
		}
	}
	End {}
}
Function Find-RegistryValue {
<#
	.SYNOPSIS
        Checks to see if the specified service is in the desired state

        .DESCRIPTION
	 Checks to see if the specified service is in the desired state
	 

        .PARAMETER Value
        Specifies a registry key followed by a pipe, "|" then the value name followed by a pipe "|" then the value data

        .INPUTS
        String value, [Registry key]|[value name]|[Value data]

        .OUTPUTS
	Boolean 

        .EXAMPLE
        C:\PS> Find-RegistryValue -Value "[Registry key]|[value name]|[Value data]"
        True

    #>	
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[string]$Value,
		[parameter(Mandatory=$false)]
		[Switch] $Wait,
		[parameter(Mandatory=$false)]
		[Int] $WaitCounter
	)
	Begin { }
	Process {
		TRY {
			$RegistryPath,$ValueName,$ValueData = $Value.split("|")
			IF ($Wait -eq $True) {
				# Do nothing wait is true
			} 
			ELSE {
				Write-LogandHost "Task ($TasksProcessed): Checking to see if the Registry value name, $ValueName holds the data $ValueData ..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			}
			IF (Test-Path -Path $RegistryPath) {
				$ActualValueData = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): Actual Registry value data found, $ActualValueData" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
				}
				IF ($ActualValueData -eq $ValueData) {
					IF ($Wait -eq $True) {
						# Do nothing wait is true
					} 
					ELSE {
						Write-LogandHost "Task ($TasksProcessed): Actual value equals requested value" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					}
					Write-OutPut $True
				} 
				ELSE{
					IF ($Wait -eq $True) {
						# Do nothing wait is true
					} 
					ELSE {
						Write-LogandHost "Task ($TasksProcessed): Actual value does not equal requested value" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					}
					Write-OutPut $False
				}
			} 
			else { 
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): Error: The registry key being checked for, $RegistryPath, does not exist, the value cannot be evaluated" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
				}
				Write-OutPut $False
			}
		} 
		CATCH {
			IF ($Wait -eq $True) {
				# Do nothing wait is true
			} 
			ELSE {
				Write-LogandHost "Task ($TasksProcessed): Check Registry value Failed: $_" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
			}
		}
	}
	End {}
}
Function Find-GUID {
<#
	.SYNOPSIS
        Checks to see if the specified GUID is found in the registry.

        .DESCRIPTION
	 Checks to see if the specified GUID is found in the registry.
	 This is done to see if an item is installed on the system.
	 The function checks the following registry keys:
		'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
		'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'

        .PARAMETER GUIDs
        Specifies a GUID of program to check to see if it exists in the uninstall keys of the registry.
	ex. {282735F8-4BC2-419E-B443-9A4794E486DF}

        .INPUTS
        GUID

        .OUTPUTS
	Boolean 

        .EXAMPLE
        C:\PS> Find-GUID -GUIDs {282735F8-4BC2-419E-B443-9A4794E486DF}
        True
    #>
	[OutputType('System.Management.Automation.PSCustomObject')]
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[string[]]$GUIDs,
		[parameter(Mandatory=$false)]
		[Switch] $Wait,
		[parameter(Mandatory=$false)]
		[Int] $WaitCounter
	)
	Begin {
		$UninstallKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
		$UninstallInfo = [PSCustomObject]@{
			"ComputerName" = $env:computername
			"GUIDExists" = $null
			"UninstallKey" = $null
			"GUID" = $null
		}
	}
	Process {
		Foreach ($GUID in $GUIDs) {
			$Result = $null
			$Result = @()
			IF ($Wait -eq $True) {
				# Do nothing wait is true
			} 
			ELSE {
				Write-LogandHost "Task ($TasksProcessed): Checking for $GUID in Uninstall Registry Keys..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			}
			$UninstallInfo.GUID = $GUID
			Try {
				Foreach ($UninstallKey in $UninstallKeys) {
					Write-Verbose "Checking for Registry Key, $UninstallKey"
					$UninstallInfo.UninstallKey = $UninstallKey
					IF (Test-Path $UninstallKey) {
						$UninstallKeyGUID = "$UninstallKey\$GUID"
						IF (Test-Path $UninstallKeyGUID) {
							IF ($Wait -eq $True) {
								# Do nothing wait is true
							} 
							ELSE {
								Write-LogandHost "Task ($TasksProcessed): Uninstall GUID, $GUID was found in $UninstallKey" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
							}							
							$Result += $True
							# Write-OutPut $True
							BREAK
						}
						ELSE {
							IF ($Wait -eq $True) {
								# Do nothing wait is true
							} 
							ELSE {
								Write-LogandHost "Task ($TasksProcessed): Uninstall GUID, $GUID was not found in $UninstallKey" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
							}
							$Result += $False
						}
					}
				}
			} 
			Catch {
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): Check GUID Failed: $_" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
				}
				$Result += $False
			}
			IF ($Result -Contains $True) { $UninstallInfo.GUIDExists = $True } ELSE { $UninstallInfo.GUIDExists = $False }
			IF ($GUIDs.Count -eq 1) {Write-Output $UninstallInfo.GUIDExists}
			ELSE {Write-Output $UninstallInfo}
		}
	}
	End {}
}
Function Get-NestedGroupMember {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$FALSE,ValueFromPipeline=$true)]
		[string]$Group = "AITGFieldOpsServerAdmins"
	)

	Begin {
		$CNs = @()
		$AllGroups = @()
		Write-Verbose "$Group is being checked for nested groups..."
	}
	Process {
		$GroupFilter1 = "(&(objectClass=group)(cn=$Group))"
		$loop = 3 ; $Count  = 0
		Do {
			$Count++
			$DirectoryServices = New-Object System.DirectoryServices.DirectoryEntry
			IF ([String]::IsNullOrWhiteSpace($DirectoryServices)){
				Write-Verbose "Could not bind directory services"
				Write-Verbose "Attempts: $Count"
				Start-Sleep -s 10
				$DirectoryServices = New-Object System.DirectoryServices.DirectoryEntry
			} 
			ELSE {
				$Count = $loop
			}
		} UNTIL ($Count -eq $loop)
		$DirectorySearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher
		$DirectorySearcher.SearchRoot = $DirectoryServices
		$DirectorySearcher.PageSize = 15000
		$DirectorySearcher.Filter = $GroupFilter1
		$DirectorySearcher.SearchScope = "Subtree"
		# Search for System
		$AllObjectsInGroup1 = $DirectorySearcher.FindAll()
		$GroupMembers = $AllObjectsInGroup1.Properties.memberof
		$CNs = @()
		IF ([String]::IsNullOrWhiteSpace($GroupMembers)) {
			# Write-Warning -Message "No groups could be found within $Group"
		} 
		ELSE {		
			Foreach ($GroupMember in $GroupMembers) {
				$WithoutCN = $GroupMember -Split "CN="
				$WithoutCN = $WithoutCN | ForEach-Object {
					$_ -replace '\\, ','|'
				}				
				$SplitAtComma = $WithoutCN.split(",")| Where-Object { $_ -match '\S' }
				$CommonName = $($SplitAtComma[0]) 
				$CommonName = $CommonName.Replace("|",", ")
				Write-Verbose "Groupmember being processed, $CommonName ..."
				$CNs += $CommonName
			}
			Foreach ($CN in $CNs){
				Write-Verbose "CN being processed, $CN ..."
				$GroupFilter2 = "(&(objectClass=group)(cn=$CN))"
				$DirectorySearcher.Filter = $GroupFilter2
				$DirectorySearcher.SearchScope = "Subtree"
				# Search for System
				$AllObjectsInGroup2 = $DirectorySearcher.FindAll()
				IF ($AllObjectsInGroup2.Properties.objectclass -Match "group") {
					Write-Verbose "$CN is a group, will check for nested groups"
					$AllGroups += $CN
					Get-NestedGroupMember -Group $CN
				}
			}
		}
	}
	End{Write-OutPut $AllGroups}
}
Function Find-ADGroupMembership {
<#
	.SYNOPSIS
	Checks to see if a system is a direct member of a specified AD group 
	.DESCRIPTION

	The function checks to see if the specified system is a member of a specific group.

	If only one system and one group is passed to the function it returns a boolean of true 
	if the system is a member of the group and a boolean of false if it is not.  

	If multiple systems or groups are passed to the function it returns a PS Custom Object 
	where there are there are note properties for hostname, Group, and member of.

	.PARAMETER Hostname
	This parameter accepts one or multiple computer names
	Ex. AIOMDBE35100045
	This parameter is non-mandatory, it will default to the system running the function

	.PARAMETER Groupname
	This parameter accepts one or multiple group names
	Ex. AIOG-Deploy-TMB-WKS
	This parameter is non-mandatory,  it will default to the group, AIOG-Deploy-TMB-WKS

	.EXAMPLE
	C:\PS> Find-ADGroupMembership
	True

	.EXAMPLE
	PS C:\> Find-ADGroupMembership -Hostname $env:computername,  AIOMDBE35100045, AIOMDBE3410KR16

	ComputerName    Group               Memberof
	------------    -----               --------
	AIOMDBE35000054 AIOG-Deploy-TMB-WKS Yes
	AIOMDBE35100045 AIOG-Deploy-TMB-WKS Yes
	AIOMDBE3410KR16 AIOG-Deploy-TMB-WKS Yes

#>
	[OutputType('System.Management.Automation.PSCustomObject')]
	[CmdletBinding(SupportsShouldProcess=$true)]
	Param (
		[parameter(Mandatory=$FALSE)]
		[String[]] $Hostname = $env:Computername,
		[parameter(Mandatory=$FALSE)]
		[String[]] $GroupName = 'AIOG-Deploy-TMB-WKS',
		[parameter(Mandatory=$false)]
		[Switch] $Wait,
		[parameter(Mandatory=$false)]
		[Int] $WaitCounter
	)
	Begin {
		# ASCII Characters
		$tab = [char]9
		# Counters
		$intGroupCount = 0 ; $intUserCount = 0
		# Empty Variables
		$GroupStatus = $null
		# Begin
		$DateNow = Get-Date
		Write-verbose "$DateNow - Preparing Environment to Check AD Group Membership"
	}
	Process {
		$DateNow = Get-Date
		Write-verbose "$DateNow - Script to Check AD Group Membership started running"
		# Foreach ($computer in $Hostname)
		$Hostname|Foreach-Object {
			$computer = $_
			$intUserCount++
			# Get the user accounts AD properties	
			#Create Filter
			$strFilters = @("(&(objectClass=computer)(name=$Computer))")
			TRY {
				Write-verbose "Checking to see if computer, $Computer, can be found within the domain ..."
				# Connect to the domain and create search object
				$loop = 3 ; $Count  = 0
				Do {
					$Count++
					$objDomain = New-Object System.DirectoryServices.DirectoryEntry
					IF ([String]::IsNullOrWhiteSpace($objDomain)){
						Write-Verbose "Could not bind directory services"
						Write-Verbose "Attempts: $Count"
						Start-Sleep -s 10
						$objDomain = New-Object System.DirectoryServices.DirectoryEntry
					} 
					ELSE {
						$Count = $loop
					}
				} UNTIL ($Count -eq $loop)
				$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
				$objSearcher.SearchRoot = $objDomain
				$objSearcher.PageSize = 15000
				Foreach ($Filter in $strFilters) {
					$objSearcher.Filter = $Filter
					$objSearcher.SearchScope = "Subtree"
					# Search for the user
					$AllObj = $objSearcher.FindAll() 
					$ADComputer = $AllObj.Properties
					IF (!([String]::IsNullOrWhiteSpace($ADComputer))) {Break} 
				}
				IF ([String]::IsNullOrWhiteSpace($ADComputer)) {
					Write-Warning -Message "$computer could not be found in AD, group membership will not be checked"
				} 
				ELSE {
					Write-Verbose "Success: $computer was found in the domain"
					Foreach ($Group in $GroupName) {
						$intGroupCount++
						Write-Verbose "Group being checked: $Group"
						$GroupStatus = [PSCustomObject]@{
							"ComputerName"= $computer
							"Group" = $Group
							"Memberof"=$null
						}
						$Groups = $ADComputer.memberof
						$AllGroups = @()
						Foreach ($GroupMember in $Groups) {
							$WithoutCN = $GroupMember -Split "CN="
							$WithoutCN = $WithoutCN | ForEach-Object {
								$_ -replace '\\, ','|'
							}				
							$SplitAtComma = $WithoutCN.split(",")| Where { $_ -match '\S' }
							$CommonName = $($SplitAtComma[0]) 
							$CommonName = $CommonName.Replace("|",", ")
							Write-Verbose "Groupmember being processed, $CommonName ..."
							$AllGroups += $CommonName
						}
						$AllGroups += $AllGroups | Get-NestedGroupMember | sort-object | Get-Unique �AsString
						Foreach ($GroupCN in $AllGroups) {
							Write-Verbose "$tab Group DN being matched: $GroupCN"
							If ($GroupCN -like $Group) {$GroupStatus.Memberof = "Yes"; Break}
							ELSE {$GroupStatus.Memberof = "No"}
						}
						IF (($Hostname.count -eq 1) -and ($GroupName.count -eq 1) -and($GroupStatus.Memberof -eq "Yes")) {
							IF ($Wait -eq $True) {
								# Do nothing wait is true
							} 
							ELSE {
								Write-LogandHost "Task ($TasksProcessed): Success: The host $Hostname, is a member of the requested group, $GroupName" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green
							}
							Write-Output $True
						} 
						ELSEIF (($Hostname.count -eq 1) -and ($GroupName.count -eq 1) -and($GroupStatus.Memberof -eq "No")) {
							IF ($Wait -eq $True) {
								# Do nothing wait is true
							} 
							ELSE {
								Write-LogandHost "Task ($TasksProcessed): Warning: The host $Hostname, is not a member of the requested group, $GroupName" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
							}
							Write-Output $False
						}
						else {Write-output $GroupStatus}
					}
				}
			} 
			CATCH {
				Write-error "$tab Error: $_"
			}
		}
	}
	End { }
 }
Function Test-Host {
<#
	.SYNOPSIS
        Checks to see if the specified computername matches the name of the host system.

        .DESCRIPTION
	 Checks to see if the specified computername matches the name of the host system.
	 This is done to see if the system is an allowed or not allowed system.

        .PARAMETER ComputerName
        Specifies a computername

        .INPUTS
        computername

        .OUTPUTS
	Boolean 

        .EXAMPLE
        C:\PS>Test-Host -ComputerName Test1
        False
    #>
	[CmdletBinding()]
	Param (	
		[parameter(Mandatory=$FALSE)]
		[String[]]$ComputerName = $env:Computername,
		[parameter(Mandatory=$false)]
		[Switch] $Wait,
		[parameter(Mandatory=$false)]
		[Int] $WaitCounter
	)
	Begin {
		# Booleans
		$FoundMatch = $False
		# Begin
		$Hostname = $env:Computername
		Write-Verbose "Hostname: $env:Computername"
		IF ($ComputerName -Match "|") {$ComputerName = $ComputerName.Split("|")}
	}
	Process {
		Foreach ($PC in $ComputerName){
			Write-Verbose "$$$$ PC: $PC"
			IF ($Hostname -eq $PC) {
				Write-Verbose "$$$$$ Success: a match was found"
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): The task will not run on the host $Hostname, it matched a blocked host, $PC" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
				}
				$FoundMatch = $True
			}
			ELSE {
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-Verbose "$$$$$ Failure: a match was not found"
				}
			}
		}
	}
	End {
		IF ($FoundMatch -eq $True) {$Blockhost =$False} else {$Blockhost =$True}
		Write-Verbose "$$$$$ In Test host...output is $Blockhost"
		Write-Output $Blockhost
	}
} 
Function Compare-Checksum {
<#
	.SYNOPSIS
        Checks to see if the specified CheckSumInfo matches checksum of a specified file.

        .DESCRIPTION
	  Checks to see if the specified CheckSumInfo matches checksum of a specified file.
	  This is done using the SHA256 hash of the specified file

        .PARAMETER CheckSumInfo
        Specifies a file followed by a pipe "|" then the checksum that the specified file should be tested for

        .INPUTS
        String

        .OUTPUTS
	Boolean 

        .EXAMPLE
        C:\PS>Compare-Checksum -CheckSumInfo *WINDIR*\system32\notepad.exe|E5D90BEEB6F13F4613C3153DABBD1466F4A062B7252D931F37210907A7F914F7
        False
#>	
	[CmdletBinding()]
	Param (	
		[parameter(Mandatory=$True)]
		[String]$CheckSumInfo,
		[parameter(Mandatory=$false)]
		[Switch] $Wait,
		[parameter(Mandatory=$false)]
		[Int] $WaitCounter
	)	
	Begin {
		# Booleans
		$HashMatch = $False
		# Begin
		Write-Verbose "File and SHA256 Checksum being compared $CheckSumInfo"
		IF ($CheckSumInfo -Match "|") {$File, $ProvidedCheckSum = $CheckSumInfo.Split("|")} ELSE {Write-Warning "Both parameters, File and Checksum, were not provided, exiting validation" ; Write-Out $False ; exit}
		Write-Verbose "File: $File"
		Write-Verbose "Checksum: $ProvidedCheckSum"
	}
	Process {
		IF (Test-Path $File) {
			$ActualSHA256 = Get-FileHash -Path $File -Algorithm SHA256
			Write-Verbose "Actual Checksum: $($ActualSHA256.Hash)"
			IF ($($ActualSHA256.Hash) -eq $ProvidedCheckSum) {
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): Validation ($ValidationNumber): Success, the provided checksum matches the actual checksum" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green
				}
				$HashMatch = $True
			}
			ELSE {
				IF ($Wait -eq $True) {
					# Do nothing wait is true
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): Validation ($ValidationNumber): Error, the provided checksum does not match the actual checksum" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
				}
				$HashMatch = $False
			}
		}
		ELSE {
			Write-LogandHost "Task ($TasksProcessed): Validation ($ValidationNumber): Warning, the provided File, $File does not exist" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
			$HashMatch = $False
		}
	}
	End {
		Write-Output $HashMatch
	}
}
Function Test-PendingReboot {
<#
	.SYNOPSIS
        Checks to see if the host system has a pending reboot.

        .DESCRIPTION
	  Checks to see if the host system has a pending reboot.
	  It checks the following registry keys / values:
		HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing for RebootPending
		HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update for RebootRequired
		HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon for JoinDomain or AvoidSpnSet
		HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName for ComputerName
		HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName for ComputerName
		HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager for PendingFileRenameOperations
		HKLM:\ROOT\ccm\ClientSDK\CCM_ClientUtilities for DetermineIFRebootPending

        .PARAMETER ComputerName
        Specifies the system to check.  It defaults to the current system

        .INPUTS
        String

        .OUTPUTS
	PS Custom Object 

        .EXAMPLE
        C:\PS>Test-PendingReboot -ComputerName Test1
        False
#>	
	[CmdletBinding()]
	param(
		[Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias("CN", "Computer")]
		[String[]]
		$ComputerName = $env:COMPUTERNAME,
		[Parameter()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.CredentialAttribute()]
		$Credential,
		[Parameter()]
		[Switch]
		$Detailed,
		[Parameter()]
		[Switch]
		$SkipConfigurationManagerClientCheck,		
		[Parameter()]
		[Switch]
		$SkipPendingFileRenameOperationsCheck
	)
	Process {
		Foreach ($computer in $ComputerName) {
			Try {
				$invokeWmiMethodParameters = @{
					Namespace	= 'root/default'
					Class		= 'StdRegProv'
					Name		 = 'EnumKey'
					ComputerName = $computer
					ErrorAction  = 'Stop'
				}
				$hklm = [UInt32] "0x80000002"
				IF ($PSBoundParameters.ContainsKey('Credential')) {
					$invokeWmiMethodParameters.Credential = $Credential
				}
				## Query the Component Based Servicing Reg Key
				$invokeWmiMethodParameters.ArgumentList = @($hklm, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\')
				$registryComponentBasedServicing = (Invoke-WmiMethod @invokeWmiMethodParameters).sNames -contains 'RebootPending'

				## Query WUAU from the registry
				$invokeWmiMethodParameters.ArgumentList = @($hklm, 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\')
				$registryWindowsUpdateAutoUpdate = (Invoke-WmiMethod @invokeWmiMethodParameters).sNames -contains 'RebootRequired'

				## Query JoinDomain key from the registry - These keys are present IF pending a reboot from a domain join operation
				$invokeWmiMethodParameters.ArgumentList = @($hklm, 'SYSTEM\CurrentControlSet\Services\Netlogon')
				$registryNetlogon = (Invoke-WmiMethod @invokeWmiMethodParameters).sNames
				$pendingDomainJoin = ($registryNetlogon -contains 'JoinDomain') -or ($registryNetlogon -contains 'AvoidSpnSet')

				## Query ComputerName and ActiveComputerName from the registry and setting the MethodName to GetMultiStringValue
				$invokeWmiMethodParameters.Name = 'GetMultiStringValue'
				$invokeWmiMethodParameters.ArgumentList = @($hklm, 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\', 'ComputerName')
				$registryActiveComputerName = Invoke-WmiMethod @invokeWmiMethodParameters

				$invokeWmiMethodParameters.ArgumentList = @($hklm, 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\', 'ComputerName')
				$registryComputerName = Invoke-WmiMethod @invokeWmiMethodParameters

				$pendingComputerRename = $registryActiveComputerName -ne $registryComputerName -or $pendingDomainJoin

				## Query PendingFileRenameOperations from the registry
				IF (-not $PSBoundParameters.ContainsKey('SkipPendingFileRenameOperationsCheck')) {
					$invokeWmiMethodParameters.ArgumentList = @($hklm, 'SYSTEM\CurrentControlSet\Control\Session Manager\', 'PendingFileRenameOperations')
					$registryPendingFileRenameOperations = (Invoke-WmiMethod @invokeWmiMethodParameters).sValue
					$registryPendingFileRenameOperationsBool = [bool]$registryPendingFileRenameOperations
				}

				## Query ClientSDK for pending reboot status, unless SkipConfigurationManagerClientCheck is present
				IF (-not $PSBoundParameters.ContainsKey('SkipConfigurationManagerClientCheck')) {
					$invokeWmiMethodParameters.NameSpace = 'ROOT\ccm\ClientSDK'
					$invokeWmiMethodParameters.Class = 'CCM_ClientUtilities'
					$invokeWmiMethodParameters.Name = 'DetermineIFRebootPending'
					$invokeWmiMethodParameters.Remove('ArgumentList')

					Try {
						$sccmClientSDK = Invoke-WmiMethod @invokeWmiMethodParameters
						$systemCenterConfigManager = $sccmClientSDK.ReturnValue -eq 0 -and ($sccmClientSDK.IsHardRebootPending -or $sccmClientSDK.RebootPending)
					}
					Catch {
						$systemCenterConfigManager = $null
						Write-Verbose -Message ($script:localizedData.invokeWmiClientSDKError -f $computer)
					}
				}
				$isRebootPending = $registryComponentBasedServicing -or `
					$pendingComputerRename -or `
					$pendingDomainJoin -or `
					$registryPendingFileRenameOperationsBool -or `
					$systemCenterConfigManager -or `
					$registryWindowsUpdateAutoUpdate

				IF ($PSBoundParameters.ContainsKey('Detailed')) {
					[PSCustomObject]@{
						ComputerName					 = $computer
						ComponentBasedServicing		  = $registryComponentBasedServicing
						PendingComputerRenameDomainJoin  = $pendingComputerRename
						PendingFileRenameOperations	  = $registryPendingFileRenameOperationsBool
						PendingFileRenameOperationsValue = $registryPendingFileRenameOperations
						SystemCenterConfigManager		= $systemCenterConfigManager
						WindowsUpdateAutoUpdate		  = $registryWindowsUpdateAutoUpdate
						IsRebootPending				  = $isRebootPending
					}
				}
				Else 	{
					[PSCustomObject]@{
						ComputerName	= $computer
						IsRebootPending = $isRebootPending
					}
				}
			}
			Catch {
				Write-Verbose "$Computer`: $_"
			}
		}
	}
}
Function Find-Patch {
<#
	.SYNOPSIS
        Checks to see if the host system has the specified patch installed.

        .DESCRIPTION
	  Checks to see if the host system has the specified patch installed.
	  It checks the Win32_QuickFixEngineering class

        .PARAMETER Patch
        Specifies the patch to check.

        .INPUTS
        String

        .OUTPUTS
	Boolean 

        .EXAMPLE
        C:\PS>Find-Patch -Patch KB4346084
        True
#>	
	[OutputType('System.Management.Automation.PSCustomObject')]
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[string[]]$Patch,
		[parameter(Mandatory=$true)]
		[Bool] $Switch,
		[parameter(Mandatory=$false)]
		[Switch] $Wait,
		[parameter(Mandatory=$false)]
		[Int] $WaitCounter
	)
	Begin { }
	Process {
		$PatchExists = $null -ne (Get-CimInstance -Class Win32_QuickFixEngineering|Where-Object {$_.HotFixID -eq $Patch})
		IF ($PatchExists) {$ActionVerb = "does"} ELSE {$ActionVerb = "does NOT"}
		IF ($PatchExists -eq $Switch) {
			IF ($Wait -eq $True) {
				# Do nothing wait is true
			} 
			ELSE {
				Write-LogandHost "Task ($TasksProcessed): $Patch $ActionVerb exist" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			}
		}
		ELSE {
			IF ($Wait -eq $True) {
				# Do nothing wait is true
			} 
			ELSE {
				Write-LogandHost "Task ($TasksProcessed): $Patch $ActionVerb exist" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
			}
		}
		
	}
	End {
		Write-Output $PatchExists
	}
}
Function Start-Script {
<#
	.SYNOPSIS
        Runs the specified script on the system.

        .DESCRIPTION
	  Runs the specified script on the system.
	  

        .PARAMETER ScriptInfo
        Specifies the script followed by a pipe "|" any arguments that that should be passed to the script followed by a pipe "|" followed by a list of exit codes separated by commas
	.\Test\DoesNotExist.ps1|-arg|22,34

        .INPUTS
        String

        .OUTPUTS
	Boolean 

        .EXAMPLE
        C:\PS>Start-Script -ScriptInfo .\Test\DoesNotExist.ps1|-arg|22,34
        True
#>	
	[OutputType('System.Management.Automation.PSCustomObject')]
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[string]$ScriptInfo,
		[parameter(Mandatory=$true)]
		[Bool] $Switch
	)
	Begin {
		$quote = [char]34
		# Default Success codes
		$SuccessCodes = @(0,1641,3010)
		# Objects for later use
		$TaskResult = [PSCustomObject]@{
			"Host" = $env:Computername ; "Success" = "Unknown" ; "TaskName" = $null ; "ExitCode" = $null
			"Id" = 0 ; "StartTime" = Get-Date -Format "MM/dd/yyyy HH:mm:ss" ; "ExitTime" = $null ; "OutPut" = $null ; "RunspaceId" = $null
		}		
	}
	Process {
		IF ($ScriptInfo -Match "|") {
			# Has success codes and arguments in line
			Write-Verbose "The pipe character was found validation script, there will be additional success codes"
			$EXE,$Args,$TempSuccessCodes = $ScriptInfo.Split("|")
			IF ($TempSuccessCodes -match ",") { $TempSuccessCodes = ($TempSuccessCodes -Split (",")).Trim() }
			Write-Verbose "EXE: $EXE, Args: $Args, Temp Success Codes: $TempSuccessCodes"
			IF (!([String]::IsNullOrWhiteSpace($TempSuccessCodes))) { $SuccessCodes += $TempSuccessCodes}
		}
		ELSE{
			# Does not have success codes or arguments on line	
			$EXE = $ScriptInfo
		}
		# Match file extensions. Valid ones are PS1, CMD, BAT, everything else should produce an error
		IF ($EXE -Match ".ps1") {
			$Cmdline = "powershell.exe"
			$Args = " -ExecutionPolicy Bypass -NoProfile -File " + $quote + $EXE + $quote + " " + $Args
			Write-Verbose "$Cmdline"
		}
		ELSEIF (($EXE -Match ".bat") -OR ($EXE -Match ".cmd")) {
			IF ($Env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {$SystemPath="Sysnative"} ELSE {$SystemPath="System32"}
			$Cmdline = "$Env:Windir\$SystemPath\CMD.EXE"
			$Args = " /C $EXE " + $Args
			Write-Verbose "$Cmdline"
		}
		ELSE { 
			#Not a valid script, exit
			Write-LogandHost  "Task ($TasksProcessed): Error: Validation Script, $EXE, is not a valid script type" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
			Write-Output $False
		}		
		IF (Test-Path $EXE) {
			$InvokeCommandLine = @{ 
				"Executable" = $Cmdline ; "TaskName" = "Validation Script" ; "Arguments" = $Args
				"WaitTimeOut" = $null ; "WaitType" = "" ; "WaitSwitch" = $null ; "WaitItem" = $null ; "JobCount" = 3 ; "ScriptPath" = $($Script.Path) 
				"ShowProgress" = "$($Task.ShowProgress)" ; "Interactive" = $($Task.Interactive)
			}
			Write-LogandHost "Task ($TasksProcessed): Validation EXE: $Cmdline" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			IF (!([String]::IsNullOrWhiteSpace($Args))) { 
				Write-LogandHost "Task ($TasksProcessed): Validation Arguments: $Args" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) 
			} 
			ELSE {
				$InvokeCommandLine.Arguments = $null
			}
			Write-Verbose "Invoke Command Line: $($InvokeCommandLine.Executable), $($InvokeCommandLine.TaskName), $($InvokeCommandLine.Validation), $($InvokeCommandLine.Arguments), $($InvokeCommandLine.WaitTimeOut),  $($InvokeCommandLine.WaitType), $($InvokeCommandLine.WaitSwitch), $($InvokeCommandLine.WaitItem), $($InvokeCommandLine.JobCount), $($InvokeCommandLine.ScriptPath), $($InvokeCommandLine.ShowProgress), $($InvokeCommandLine.Interactive)"
			$InvokeCommandLine
			$TaskResult = Invoke-Task @InvokeCommandLine
			IF ([String]::IsNullOrWhiteSpace($($TaskResult.ExitCode))) {
				$TaskResult = [PSCustomObject]@{
					"Host" = $env:Computername ; "Success" = $True ; "TaskName" = "Validation Script" ; "ExitCode" = 0 
					"Id" = $null ; "StartTime" = $null ; "ExitTime" = Get-Date -Format "MM/dd/yyyy HH:mm:ss" ; "OutPut" = $null ;"RunspaceId" = $null
				}
			}			
		}
		ELSE {
			Write-LogandHost "Task ($TasksProcessed): $EXE does not exist" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			$TaskResult = [PSCustomObject]@{
				"Host" = $env:Computername ; "Id" = $null ; "TaskName" = "Validation Script" ; "StartTime" = $null
				"ExitTime" = Get-Date -Format "MM/dd/yyyy HH:mm:ss" ; "OutPut" = $null ; "ExitCode" = 2 ; "RunspaceId" = $null
				"Success" = "Skipped"
			}
		}
		Write-LogandHost "Task ($TasksProcessed): Validation Script Result Code: $($TaskResult.ExitCode)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		$ExitCode = ($TaskResult.ExitCode).ToString()
		Write-Verbose "Success Codes: $SuccessCodes"
		IF (Compare-SuccessCode -SplitCodes $SuccessCodes -ExitCode $ExitCode) {			
			$TaskResult | Add-Member -MemberType NoteProperty -Name "Success" -Value $True -Force
			$ExitCodes += $AllTaskResults.ExitCode
			$ScriptSuccess = $True
		}
		ELSE {			
			$TaskResult | Add-Member -MemberType NoteProperty -Name "Success" -Value $False -Force
			$ExitCodes = $($TaskResult.ExitCode)
			$ScriptSuccess = $False
		}
		IF ($ScriptSuccess -eq $Switch) {
			Write-LogandHost  "Task ($TasksProcessed): Validation Script completed successfully with exit code: $($TaskResult.ExitCode)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green
			$ScriptSuccess = $True
		}
		ELSE {
			Write-LogandHost  "Task ($TasksProcessed): Validation Script failed with exit code: $($TaskResult.ExitCode)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
			$ScriptSuccess = $False
		}
	}
	End {
		Write-Verbose "Script Success: $ScriptSuccess"
		Write-Output $ScriptSuccess
	}
}
Function Copy-Item2 {
<#
	.SYNOPSIS
        Copies items from their specified source to their destination

        .DESCRIPTION
	  Copies items from their specified source to their destination
	  

        .PARAMETER CopyJobs
        Specifies the items to be copied

        .INPUTS
        String

        .OUTPUTS
	Items have been copied to the requested location 

#>
	[CmdletBinding(SupportsShouldProcess=$true)]
	Param (	
		[parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true)]
		$CopyJobs
	)
	Begin {
		# Booleans
		$BadCopy = $False
		# Counters
		$CopyJobNum = 0 ; $CopyLoopsProcessed = 0 ; $CopyLoopsAllowed = 3
		# Begin
		Write-Verbose "In Copy item 2..."
		#$CopyJobs.CopyJob.Source	
	}
	Process {
		Foreach ($CopyJob in $CopyJobs.CopyJob){
			$CopyJobNum++
			Write-Verbose "Copy Job Source: $($CopyJob.Source)"
			Write-Verbose "Copy Job Destination: $($CopyJob.Destination)"
			# Trim Source and Destination
			$Source = ($CopyJob.Source).Trim()
			$Destination = ($CopyJob.Destination).Trim()
			# Find File being copied
			$FiletobeCopied = Split-Path $CopyJob.Source -Leaf
			$DestinationFullPath = $Destination + "\" + $FiletobeCopied
			IF (Test-Path -Path  $Source) {
				# Create destination directory if it does not exist
				IF (!(Test-Path -Path $Destination)) {New-Item -itemtype directory -path $Destination -Force > $Null}
				Do {
					$CopyLoopsProcessed++
					$Time = Measure-Command {copy-item $Source -destination $DestinationFullPath -force -recurse}
					IF ($Time.TotalSeconds -le 120) { $RunTime = $Time.TotalSeconds ; $Unit = "s"}
					ELSEIF ($Time.TotalMinutes -le 120) { $RunTime = $Time.TotalMinutes ; $Unit = "m"}
					ELSEIF ($Time.TotalHours -le 48) { $RunTime = $Time.TotalHours ; $Unit = "hs"} 
					ELSE { $RunTime = $Time.TotalSeconds}

					IF (Test-Path -Path $DestinationFullPath) {
						Write-LogandHost "Task ($TasksProcessed): Success: Copied $FiletobeCopied to $Destination in $RunTime $Unit" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green
						$CopyLoopsProcessed = $CopyLoopsAllowed
					}
					ELSE {
						Write-Warning "Task ($TasksProcessed): Copy of $FiletobeCopied to $Destination was not successful, waiting 10 seconds and trying again."
						Write-Verbose "Attempts: $CopyLoopsProcessed"
						Start-Sleep -s 10
						$BadCopy = $True
					}
				}
				Until ($CopyLoopsProcessed -eq $CopyLoopsAllowed)
				IF ($BadCopy -eq $True) {
					Write-LogandHost "Task ($TasksProcessed): $($Task.Name) is being skipped, failed to copy $FiletobeCopied to $Destination"  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
					Break
				}
			}
			ELSE {
				Write-LogandHost "Task ($TasksProcessed): $($Task.Name) File, $FiletobeCopied does not exist"  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
				$BadCopy = $True
				Break
			}
		}
	}
	End {
		IF ($BadCopy -eq $True) {Write-Output $True} ELSE {Write-Output $False}
	}
}
Function Invoke-Task {
<#
	.SYNOPSIS
        Runs an executable item and passes arguments to the item

        .DESCRIPTION
	Runs an executable item and passes arguments to the item.
	If the job is run interactively it can interact with the user running the function.
	If the job is not run interactively, it is run as a PowerShell job in the background.
	If the job is not being run interactively there is an option to show progress of the job.  This allows the user to see that something is still ocurring. The number of periods on that line will increase as the executable continues to run. 
	The function defaults to waiting for the executable to exit.
	There is a wait option that can be invoked.  Once it has been invoked you can have the function wait for certain conditions to exist on the system and if they exist the function will exit.	

        .PARAMETER Executable
        Specifies the item to execute. This is mandatory

        .PARAMETER TaskName
        Specifies the name of the task.  This is mandatory.
	
        .PARAMETER Arguments
        Specifies the arguments that should be passed to the executable.  This is not mandatory.

        .PARAMETER WaitTimeout
        Specifies the number of seconds the function should wait before continuing.  This is not mandatory.

        .PARAMETER WaitType
        Specifies the type of thing that will be checked for the wait.  This is mandatory.
	Valid types are Directory, File, Fileversion, Freespace, GUID, Process, OU, Registry Key, Registry Value, ServiceState, MemberOf, Checksum, and Patch

        .PARAMETER WaitSwitch
        Specifies whether the requested wait type should be true or false.  This is mandatory.

        .PARAMETER WaitItem
        Specifies item being waited on.  This is mandatory.

        .PARAMETER ScriptPath
        Specifies the path that you want the arguments to run from. This is mandatory.
	
        .PARAMETER ShowProgress
        Specifies if progress of the executable should be shown. This is not mandatory.

        .PARAMETER Interactive
        Specifies if the item being executed will be interactive to the user running the function. This is not mandatory.

        .OUTPUTS
        PS Custom Object 

        .EXAMPLE
        C:\PS> Invoke-Task -Executable msiexec.exe -TaskName "Install Acrobat" -Arguments "/i Acro.msi /l logfile.txt /qn /norestart"
        Host, Success, TaskName, ExitCode, Id, StartTime, ExitTime, OutPut, RunspaceId
#>
	[OutputType('System.Management.Automation.PSCustomObject')]
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$true)]
		[string] $Executable,
		[parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$true)]
		[string] $TaskName,			
		[parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true)]
		[string] $Arguments,	
		[parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true)]
		[string] $WaitTimeout,		
		[parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true)]
		[string] $WaitType,
		[parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true)]
		[string] $WaitSwitch,
		[parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true)]
		[string] $WaitItem,
		[parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true)]
		[Int] $JobCount = 3,
		[parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true)]
		[string] $ScriptPath,
		[parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true)]
		[string] $ShowProgress,
		[parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true)]
		[string] $Interactive = "False"
	)
	Begin {
		Write-Verbose "Beginning function to run task executables..."
		Write-Verbose "Script Path: $ScriptPath"
		$Interactive = $Interactive.Trim()
		Write-Verbose "Interactive: $Interactive"
		IF (($WaitTimeOut -Match "^$") -OR ($WaitTimeOut -eq $null)) {$Wait = $True} Else {$Wait = $False}
		# -OR ($WaitSwitch -eq $False)
		#IF ($Interactive -Match "^?") {$Interactive = $False}
		IF ($Interactive -eq "True") {$Interactive = $True}
		ELSE {$Interactive = $False}
		Write-Verbose "Interactive after conversion to boolean: $Interactive"
		Write-Verbose "Wait = $Wait"
		Write-Verbose "Executable = $Executable"
		Write-Verbose "Arguments: $Arguments"
		# Create script block
		$ScriptBlock = {
			[OutputType('System.Management.Automation.PSCustomObject')]
			[CmdletBinding(SupportsShouldProcess=$true)]
			Param(
				[Parameter(Mandatory=$False)]
				[string] $Executable,	
				[string] $Arguments,
				[string] $TaskName,
				[Bool] $Wait,
				[String] $ScriptPath
			)

			[Environment]::SetEnvironmentVariable("SEE_MASK_NOZONECHECKS","1","Process")
			$ProcessInfo = [PSCustomObject]@{
				"Host" = $env:computername
				"TaskName" = $TaskName
				"ExitCode" = $null
				"Id" = $null
				"StartTime" = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
				"ExitTime" = $null
				"OutPut" = $null
				"Success" = "Unknown"
			}
			#Prepare Process Start Information
			$ProcessStartInfo = $null
			$ProcessStartInfo = New-Object System.Diagnostics.ProcessStartInfo
			$ProcessStartInfo.FileName = $Executable
			$ProcessStartInfo.RedirectStandardError = $True
			$ProcessStartInfo.RedirectStandardOutput = $True
			$ProcessStartInfo.UseShellExecute = $False	
			IF (!([String]::IsNullOrWhiteSpace($Arguments))){$ProcessStartInfo.Arguments = $Arguments}
			#Prepare and Start Process
			$Process = $null
			$Process = New-Object System.Diagnostics.Process
			$Process.StartInfo = $ProcessStartInfo
			$Process.Start() | Out-Null
			IF ($Wait -eq $True) { $Process.WaitForExit() }
			$ProcessInfo.Id = $Process.Id
			$ProcessInfo.StartTime = $Process.StartTime
			$ProcessInfo.ExitTime = $Process.ExitTime
			$ProcessInfo.OutPut = $Process.StandardOutput.ReadToEnd()
			$ProcessInfo.ExitCode = $Process.ExitCode
			Write-OutPut $ProcessInfo
		}
		
	}
	Process {
		Write-Verbose "In the process block..."
		Write-Verbose "Creating a Job with Name, $TaskName"
		### Create Initial Job Result Object
		$JobResult = [PSCustomObject]@{
			"Host" = $env:Computername ; "TaskName" = $TaskName ; "ExitCode" = $null
			"Id" = "none" ; "StartTime" = Get-Date -Format "MM/dd/yyyy HH:mm:ss" ; "ExitTime" = $null  ; "OutPut" = $null
			"RunspaceId" = $null ; "Success" = "Not Started"
		}
		IF ($Interactive -eq $True) {
			Write-Verbose "Running interactively..."
			$JobResult = & $ScriptBlock -Executable $Executable -Arguments $Arguments -TaskName $TaskName -Wait $True -ScriptPath $ScriptPath
			$JobResult | Add-Member -MemberType NoteProperty -Name "RunspaceId" -Value $null
		}
		ELSE {
			Write-Verbose "Running as background job..."
			$Job = Start-Job -Name $TaskName -ScriptBlock $ScriptBlock -ArgumentList @($Executable, $Arguments, $TaskName, $Wait, $ScriptPath)
			IF ($Wait -eq $True) {
				#Wait for Process to exit before moving to the next one
				Write-Verbose "Waiting until job is completed"
				$JS = $null
				$JS = (Get-Job -Name $TaskName).State
				Write-Verbose "Job State: $JS"
				$JobCounter = 0
				DO {
					IF ($ShowProgress -eq "True") {
						IF ($JobCounter -eq 0){ Write-LogandHost "Task ($TasksProcessed): Executable Progress: ."  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -NoNewLine }
						ELSE { Write-LogandHost "."  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -NoNewLine -NoStarInHost -NoDateInLog }
					}				
					$JobState = (Get-Job -Name $TaskName).State
					Write-Verbose "Updated Job State: $($(Get-Job -Name $TaskName).State)"
					Start-sleep -Milliseconds 500
					$JobCounter++
				} UNTIL (($JobState -eq "Completed") -OR ($JobState -eq "Failed"))
				IF ($ShowProgress -eq "True") {
					Write-LogandHost "."  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -NoStarInHost -NoDateInLog
				}
			}
			ELSE {
				# Wait until the timeout occurs
				$StartTime = Get-Date
				$EndTime = $StartTime.AddSeconds($WaitTimeout)
				IF ([String]::IsNullOrWhiteSpace($WaitType)) { 
					Write-LogandHost "Task ($TasksProcessed): Waiting until $EndTime" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
				} 
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): Waiting until $EndTime or for $($WaitType.ToUpper()), $WaitItem to be $($WaitSwitch.ToUpper())" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
				}
				IF ($WaitSwitch -eq "True") {[BOOL]$WaitSwitch = $True} ELSE {[BOOL]$WaitSwitch = $False}
				$WaitCounter = 0
				DO {
					IF ($WaitCounter -eq 0){ Write-LogandHost "Task ($TasksProcessed): Waiting: ."  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -NoNewLine }
					ELSE { Write-LogandHost "."  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -NoNewLine -NoStarInHost -NoDateInLog }				
					$WaitCounter++
					$CurrentTime = Get-Date
					Switch ($WaitType) {
						"directory" { IF (Find-Path -Path $WaitItem -Switch $WaitSwitch -Wait -WaitCounter $WaitCounter) { $CurrentTime = $EndTime} }
						"file" {IF (Find-Path $WaitItem -Switch $WaitSwitch -Wait -WaitCounter $WaitCounter) {$CurrentTime = $EndTime}} 
						"registry key" {IF (Find-Path $WaitItem -Switch $WaitSwitch -Wait -WaitCounter $WaitCounter) {$CurrentTime = $EndTime}}
						"fileversion" { IF (Find-FileVersion $WaitItem -Switch $WaitSwitch -Wait -WaitCounter $WaitCounter) {$CurrentTime = $EndTime}}
						"freespace" { IF ((Compare-LocalDiskSpace $WaitItem -Wait -WaitCounter $WaitCounter) -eq $WaitSwitch) {$CurrentTime = $EndTime} }
						"GUID" { IF ((Find-GUID -GUIDS $WaitItem -Wait -WaitCounter $WaitCounter) -eq $WaitSwitch) {$CurrentTime = $EndTime} }
						"PROCESS" { IF ((Find-Process $WaitItem -Wait -WaitCounter $WaitCounter) -eq $WaitSwitch) {$CurrentTime = $EndTime} }
						"OU" { IF ((Find-OU -OU $WaitItem -Wait -WaitCounter $WaitCounter) -eq $WaitSwitch) {$CurrentTime = $EndTime} }
						"REGISTRY VALUE" { IF ((Find-RegistryValue -Value $WaitItem -Wait -WaitCounter $WaitCounter) -eq $WaitSwitch) {$CurrentTime = $EndTime}}
						"SERVICESTATE" { IF ((Find-ServiceState -Service $WaitItem -Wait -WaitCounter $WaitCounter) -eq $WaitSwitch) {$CurrentTime = $EndTime} }
						"MemberOf" { IF ((Find-ADGroupMembership -GroupName $WaitItem -Wait -WaitCounter $WaitCounter) -eq $WaitSwitch) {$CurrentTime = $EndTime} }
						"Checksum" { IF ((Compare-Checksum -CheckSumInfo $WaitItem -Wait -WaitCounter $WaitCounter) -eq $WaitSwitch) {$CurrentTime = $EndTime} }
						"PATCH" {IF (Find-Patch $WaitItem -Switch $WaitSwitch -Wait -WaitCounter $WaitCounter) { $CurrentTime = $EndTime } }
						Default {Write-Verbose "No Wait type specified, this will wait for $WaitTimeout before continuing to the next task"}
					}
					Start-sleep -Milliseconds 500
				} UNTIL ($CurrentTime -ge $EndTime)
				Write-LogandHost "."  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -NoStarInHost -NoDateInLog
			}
		}
	}
	End {
		Write-Verbose "Got to end of Invoke-Task"
		IF (!($Interactive -eq $True)) {
			Write-Verbose "Removing job..."
			$JobResult = Receive-Job -Name $TaskName -Force -Wait
			#Write-Host "Job Result: $JobResult"
			Remove-Job -Name $TaskName -Force 2> $null
		}
		Write-OutPut $JobResult
	}
}
Function Compare-SuccessCode {
<#
	.SYNOPSIS
        Compares the exit code of an executable to a list of allowed exit codes. 
	
        .DESCRIPTION
	Compares the exit code of an executable to a list of allowed exit codes.  
	If the exit code is on the list it returns a true.
	
        .PARAMETER SplitCodes
        Specifies the allowed exit codes. This is mandatory

        .PARAMETER ExitCode
        Specifies the exit code being checked.  This is mandatory.
	
        .OUTPUTS
        boolean 

        .EXAMPLE
        C:\PS> Compare-SuccessCode -SplitCodes 0,3010 -ExitCode 2
        False
#>
	[CmdletBinding()]
	param(
		[parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[AllowEmptyString()]
		[AllowNull()]
		[string[]]$SplitCodes,
		[Int]$ExitCode
	)
	Begin { }
	Process {
		Write-Verbose "Compare Success Codes to Exit Code of executable"
		Try {
			Foreach ($Code in $SplitCodes) {
				Write-Verbose "Success Code being compared: $Code"
				Write-Verbose "Exit Code being compared: $ExitCode"
				IF([int]$Code -eq [int]$ExitCode) { Return $True ; break }
			}        
			Return $False
		} Catch {
			Return $False
		}
	}
	End {}	
}
Function Set-RegistryValue {
<#
	.SYNOPSIS
	Creates a registry value at the location specified.
	
        .DESCRIPTION
	Creates a registry value at the location specified.  
	
        .PARAMETER RegistryPath
        Specifies the key the value should be created in. This is mandatory

        .PARAMETER ValueName
        Specifies the name of the registry value.  This is mandatory.

        .PARAMETER ValueData
        Specifies the data within the registry value.  This is mandatory.

        .PARAMETER Type
        Specifies the type of registry value.  This is mandatory.

        .OUTPUTS
        boolean 

        .EXAMPLE
        C:\PS> Set-RegistryValue -RegistryPath HKLM:\Software\Microsoft\Windows -ValueName Test -ValueData 12 -Type String
#>
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[string]$RegistryPath,
		[string]$ValueName,
		[string]$ValueData,
		[string]$type
	)
	Begin {}
	Process {
		Try {
			$RegValueInfo = $RegistryPath + "|" + $ValueName + "|" + $ValueData
			IF((Find-RegistryValue $RegValueInfo) -eq $True) {
				IF(-not (Test-Path -Path $RegistryPath)) {New-Item -Path $RegistryPath }
				New-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData -PropertyType $Type
			} 
			ELSE { 
				Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData 
			}
		} 
		Catch {
			Write-LogandHost "Fatal Exception: $_" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)  
		}
	}
	End {}
}
Function Disable-BDE {
<#
	.SYNOPSIS
	Disables the BitLocker protectors on the C drive  

        .OUTPUTS
        None

        .EXAMPLE
        C:\PS> Disable-BDE
#>
	Begin {
		IF ($Env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {$SystemPath="Sysnative"} ELSE {$SystemPath="System32"}
		$BDEExecutable="$Env:Windir\$SystemPath\CMD.EXE"
		$BDEArguments=" /C $Env:Windir\System32\Manage-bde.exe -protectors -disable c:"
		Write-Verbose "Disable BDE Executable = $BDEExecutable"
		Write-Verbose "Disable BDE Arguments = $BDEArguments"
		$AdminRights = Test-AdminRights -User $Env:Username
	}
	Process {
		IF ($AdminRights -eq $True) {
			Write-LogandHost "Checking BitLocker status on $env:SystemDrive..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			TRY {
				$BitLockerStatus = Get-BitLockerVolume $env:SystemDrive -erroraction Stop
				IF ($BitLockerStatus.ProtectionStatus -ne "Off") {
					Write-LogandHost "Suspending BitLocker protectors from $env:SystemDrive..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					$BitLockerVolume = Suspend-BitLocker -MountPoint "$env:SystemDrive" -RebootCount 1 -erroraction Stop
					IF ($BitLockerVolume.ProtectionStatus -eq "Off") {
						Write-LogandHost "Success: BitLocker protectors have been disabled." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green
					}
					ELSE {
						Write-LogandHost "Error: BitLocker protectors have not been disabled." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
					}
				} 
				ELSE {
					Write-LogandHost "Warning: BitLocker protection not enabled on this host.  Skipping..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
				}		
			}
			CATCH {
				IF (Test-Path "$Env:Windir\System32\Manage-bde.exe") {
					IF((Test-Path -Path ("$env:ProgramFiles\Microsoft\MDOP MBAM\MBAMAgent.exe")) -OR (Test-Path -Path ("${env:ProgramFiles(x86)}\Microsoft\MDOP MBAM\MBAMAgent.exe"))) {
						Write-LogandHost "Running BDE Bypass..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) 
						$ExitCode = (Start-Process -FilePath $BDEExecutable -ArgumentList $BDEArguments -Wait -Passthru -WindowStyle Hidden).ExitCode
						Write-Verbose "Manage-BDE exit code: $ExitCode"
						IF ($ExitCode -eq 0) {
							Write-LogandHost "Success: BitLocker protectors have been disabled." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green
						}
						ELSEIF ($ExitCode -eq -2144845809) { 
							Write-LogandHost "Warning: A compatible TPM security device cannot be found on this computer" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
						}
						ELSE {
							Write-LogandHost "Error: BitLocker protectors have not been disabled" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)  -Color Red
						}
					}
					ELSE {
						Write-LogandHost "Warning: BitLocker protection not enabled on this host.  Skipping..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)  -Color Yellow
					}
				}
				ELSE {
					Write-LogandHost "Warning: BitLocker protection not enabled on this host.  Skipping..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
				}	
			}
		}
		ELSE {
			Write-LogandHost "Warning: BitLocker protectors cannot be disabled due to the lack of administrative rights" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
		}
	}
	End {}
}
Function Disable-MEE {
<#
	.SYNOPSIS
	Disables the McAfee Endpoint Encryption protectors on the C drive
	
        .OUTPUTS
        None

        .EXAMPLE
        C:\PS> Disable-MEE
#>
	Begin {
		# Booleans
		$DoByPassMEE = $False
		# Begin
		IF(Test-Path -Path ("$env:ProgramFiles\McAfee\Endpoint Encryption for PC\SbAdmcl.exe")) {
			$MEEExecutable = "$env:ProgramFiles\McAfee\Endpoint Encryption for PC\SbAdmcl.exe"
			$DoByPassMEE = $True
		}
		ELSEIF(Test-Path -Path ("${env:ProgramFiles(x86)}\McAfee\Endpoint Encryption for PC\SbAdmcl.exe")) {
			$MEEExecutable = "${env:ProgramFiles(x86)}\McAfee\Endpoint Encryption for PC\SbAdmcl.exe"
			$DoByPassMEE = $True
		}
		ELSE { 
			Write-Verbose "McAfee Endpoint Encryption (BDE) could not be found on this system"
			$DoByPassMEE = $False
		}	
	}
	Process {
		Try {
			IF ($DoByPassMEE -eq $True) {
				$AdminRights = Test-AdminRights -User $Env:Username
				IF ($AdminRights -eq $True) {
					$MEEArguments=" -command:disablesecurity"
					Write-Verbose "Disable MEE Executable = $MEEExecutable"
					Write-Verbose "Disable MEE Arguments = $MEEArguments"
					Write-LogandHost "Running MEE Bypass..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					$ExitCode = (Start-Process -FilePath $MEEExecutable -ArgumentList $MEEArguments -Wait -Passthru -WindowStyle Normal).ExitCode
					Write-Verbose "MEE bypass exit code: $ExitCode"
					IF ($ExitCode -eq 0) {
						Write-LogandHost "Success: MEE pre-boot has been disabled" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)  -Color Green
					} ELSEIF ($ExitCode -eq -536543178) {
						Write-LogandHost "Warning: MEE Autoboot user already exists" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)  -Color Yellow
					} ELSE {
						Write-LogandHost "Error: MEE pre-boot NOT disabled, $ExitCode" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
					}
				}
				ELSE {
					Write-LogandHost "Warning: MEE pre-boot cannot be disabled due to the lack of administrative rights" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
				}
			}
		} 
		Catch { 
			Write-LogandHost "Error: Creating MEE Bypass - $_" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red 
		}
	}
	End {}
}
Function Restart-System {
<#
	.SYNOPSIS
	Restarts the specified system
	
        .DESCRIPTION
	Restarts the specified system in the specified amount of time.
	The reboot is initiated using Win32ShutdownTracker with the delay set to the value of RebootTimer or 60 seconds
	It will create an event in the Windows System Log with the following properties:
		Source: User32
		Event ID: 1074
		Reason: Application: Installation (Planned)
		Reason Code: 0x80040002
		Comment: "[Computername], is being rebooted for [Change] - [Package Name]"
	
        .PARAMETER ComputerName
        Specifies the key the value should be created in. This is mandatory

        .PARAMETER Timeout
        Specifies the name of the registry value.  This is mandatory.

        .OUTPUTS
        None

        .EXAMPLE
        C:\PS> Restart-System -ComputerName Test1 -Timeout 300
	The computer specified will restart in 300 seconds
#>
	[OutputType('System.Management.Automation.PSCustomObject')]
	[CmdletBinding(SupportsShouldProcess=$true)]	
	Param(
		[Parameter(Mandatory=$false, ValueFromPipeline=$true)]
		[string[]] $ComputerName = $env:Computername,
		[Parameter(Mandatory=$false, ValueFromPipeline=$false)]
		[int] $Timeout = 120
	)
	Begin {
		$Flag = 6
		# Begin
		Write-Verbose "Reboot Function..."
		$Comment = "$env:Computername, is being rebooted for $($Package.Change) - $($Package.PackageName)"
		Write-Verbose "Reboot Comment: $Comment"
		Write-Verbose "Reboot Timeout: $Timeout"
	}
	Process {
		$ComputerName|ForEach-Object {
			$DoReboot = $False
			Write-Verbose "Computer: $Computername"
			IF (Test-Connection -ComputerName $_ -Count 1 -Quiet){
				Write-Verbose "Success, was able to connect to $Computername"
				$DoReboot = $True
			}
			ELSEIF ($Computername -eq $env:Computername) {
				Write-Verbose "The computer is the localhost"
				$DoReboot = $True
			}
			ELSE {
				Write-Warning "Computer was not the local system and it was unable to be contacted, the reboot event will not take place"
				$DoReboot = $False
			}
			IF ($DoReboot -eq $True){
				Disable-BDE
				Disable-MEE				
				$TimeEvent = [PSCustomObject]@{
					"COMPUTERNAME" = $_
					"USERNAME" = $env:username
					"EVENTTYPE" = "Forceful Reboot"
					"DATE" = $null
					"TIME" = $null	
				}
				Write-Verbose "Time Event: $($TimeEvent.Eventtype)"
				Write-Verbose "Success: $_ will perform a $($TimeEvent.Eventtype)"
				Write-Verbose "Comment: $Comment"
				$TimeEvent.DATE = Get-Date -Format "yyyy-MM-dd"
				$TimeEvent.TIME = Get-Date -Format "HH:mm:ss"
				Write-Verbose $TimeEvent
				Try {
					Write-Verbose "Using the CIM instance"
					$arguments = @{
						"Timeout"    = [System.UInt32]$Timeout
						"Comment"    = $Comment
						"ReasonCode" = [System.UInt32]2147745794
						"Flags" = $Flag
					}					
					IF ($Computername -eq $env:Computername) {
						Invoke-CimMethod -Query 'SELECT * FROM Win32_OperatingSystem' -MethodName 'Win32ShutdownTracker' �Arguments $arguments > $nul
					}
					ELSE {
						Invoke-CimMethod -Query 'SELECT * FROM Win32_OperatingSystem' -MethodName 'Win32ShutdownTracker' �Arguments $arguments -ComputerName $_  > $nul
					}
				}
				Catch [Exception] {
					Write-Error "$($TimeEvent.Computername) could not be rebooted, because $Env:Username does not have the required rights"
				}
			}
		}
	}
	END { }
}
Function Stop-Framework {
<#
	.SYNOPSIS
	Exits the installation framework in a controlled manner.
	
        .DESCRIPTION
	Exits the installation framework in a controlled manner.  Returning the exit code to the starting process.
	If a 1641 is within the returned codes a reboot will be initiated and that code will be returned to the starting process.
	If a 3010 is within the returned codes the system will be setup to have a reboot performed later and that code will be returned to the starting process..  BDE or MEE will be bypassed after that reboot.
	
        .PARAMETER ExitCodes
        Specifies the exit codes to be passed to the function

        .OUTPUTS
        None

        .EXAMPLE
        C:\PS> Stop-Framework -ExitCodes 22,64,32,34,0,23
	The zero is returned to the starting process.
#>
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[parameter(Mandatory=$true, ValueFromPipeline=$true)]
		$ExitCodes
	)	
	Begin { 
		# ASCII Characters
		$tab= [char]9
		# Booleans
		$DoRestart = $False
		# Defaults
		$ReturnCode = 0
		# Begin
		Write-Verbose "Beginning Function to stop install framework"
		Write-LogandHost "************************************************************************" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
	}
	Process { 
		Write-Verbose "Exit Codes: $ExitCodes"
		IF ($ExitCodes -Contains 1641) {
			Write-LogandHost "An exit code of 1641 was found, $env:Computername will be rebooted" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			$ReturnCode = 1641
			$DoRestart = $True
		}
		ELSEIF ($ExitCodes -Contains 3010) {
			Write-LogandHost "An exit code of 3010 was found, $env:Computername will be setup so that it can be rebooted" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			$ReturnCode = 3010
			Disable-BDE
			Disable-MEE
		}
		ELSEIF ($ExitCodes -eq 197)  {$ReturnCode = 197}
		ELSEIF ($ExitCodes -eq 8344) {$ReturnCode = 8344}
		ELSEIF ($ExitCodes -Contains 0) {$ReturnCode = 0}
		ELSEIF ([String]::IsNullOrEmpty($ExitCodes)) {
			Write-LogandHost "The exit codes were null" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			$ReturnCode = 26001
		}
		ELSE {
			Write-LogandHost "A valid success code could not be found" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			$ReturnCode = $ExitCodes[-1]
		}
	}
	End { 
		IF ($DoRestart -eq $True) {Restart-System -Timeout $Task.RebootTimer}
		IF ($TasksProcessed -gt 0) {
			Write-LogandHost  "Total Tasks Processed: $TasksProcessed" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			Write-LogandHost "$tab Success(es): $SuccessCount" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green
			Write-LogandHost "$tab     Skipped: $SkipCount" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
			Write-LogandHost "$tab  Failure(s): $FailedCount" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
		}
		IF ($ExitCodeOut) {Write-LogandHost "Returning Final Exit Code: $ReturnCode" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
		Write-LogandHost "************************************************************************" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		Try {$ReturnCode=[int]$ReturnCode} Catch {$ReturnCode=26003}	
		IF ($ExitCodeOut) {
			[System.Environment]::Exit($ReturnCode)	
			Exit
		}
	}
}
Function Start-UninstallString  {
<#
	.SYNOPSIS
	Processes uninstall strings from a text file, uninstallstrings.txt.  It reads each string, finds out if the item is installed and uninstalls it.

        .DESCRIPTION
	Processes uninstall strings from a text file, uninstallstrings.txt.  It reads each string, finds out if the item is installed and uninstalls it.
	If the string contains a GUID, ex. {26A24AE4-039D-4CA4-87B4-2F83216032FF}, it will try to find out if it exists in the registy keys below
		'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
		'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
	If it exists it trys to uninstall it using the commandline, msiexec.exe "/X $GUID /qn /norestart /l* $LogFilePath$env:Computername.$PossibleGUIDorEXE.msi.Uninst.log"
	If the line contains a pipe "|" it processes the items to the right of it as exit codes separated by commas, ex. |0,22,34
	If the line does not contain a GUID it will try to process the line as an EXE.
	
        .PARAMETER Path
        Specifies the path to Uninstallstrings.txt.  This parameter is not mandatory.

        .PARAMETER ExitCodeOut
        Specifies that the function should return an exit code back to the starting process without it a PS Object will be returned.

        .INPUTS
        Path to uninstallstrings.txt

        .OUTPUTS
        PS Custom Object or Integer

        .EXAMPLE
        C:\PS> Start-UninstallString -Path .\Uninstallstrings.txt -ExitCodeOut
	0
#>
	[OutputType('System.Management.Automation.PSCustomObject')]
	[CmdletBinding(SupportsShouldProcess=$true)]
	param(
		[parameter(Mandatory=$False, ValueFromPipeline=$true)]
		[string]$Path = ".\Uninstallstrings.txt",
		[parameter(Mandatory=$False)]
		[Switch] $ObjectOut,
		[parameter(Mandatory=$False)]
		[Switch] $ExitCodeOut,
		[String] $TasksProcessed,
		[String] $Taskname,
		[String] $ScriptPath,
		[String] $Interactive
	)
	Begin {
		# Script Information
		$UninstallString = [PSCustomObject]@{ 
			"DefaultSuccessCodes" = @(0,1605,1641,3010)
			"DefaultTimeOut" = 60
			"Count" = 0
			"Path" = $Path
		}
		# ASCII Characters
		$quote = [char]34
		# Empty Arrays
		$AllTaskResults = @()
		# Empty Variables
		$TempSuccessCodes = $null ; $UninstallName = $null
		# Prepare Objects
		$TaskResult = [PSCustomObject]@{
			"Host" = $env:Computername ; "TaskName" = $Taskname ; "ExitCode" = $null
			"Id" = 0 ; "StartTime" = Get-Date -Format "MM/dd/yyyy HH:mm:ss" ; "ExitTime" = $null ; "OutPut" = $null
			"RunspaceId" = $null ; "Success" = "Unknown"
		}
		# Begin
		IF (Test-Path $($UninstallString.Path)) {
			Write-LogandHost "Task ($TasksProcessed): The Uninstall Strings text file will be processed..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			IF ($vl) {Write-LogandHost "Task ($TasksProcessed): Uninstallstrings Path: $($UninstallString.Path)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
			$UninstallStringsContent = Get-Content $($UninstallString.Path)
		}
		ELSE {
			Write-LogandHost "Task ($TasksProcessed): $Taskname is being skipped, Uninstallstrings.txt does not exist" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
			$TaskResult.ExitCode = 2
			$TaskResult.Success = "Skipped"
			$TaskResult.TaskName = "Task ($TasksProcessed): $Taskname no Uninstall strings file found"
			$TaskResult.ExitTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
			Return $TaskResult
		}
	}
	Process {
		$AllTaskResults += Foreach ($String in $UninstallStringsContent){
			$SuccessCodes = @()
			$UninstallString.Count++
			$UninstallName = "Task ($TasksProcessed): Uninstall String ($($UninstallString.Count)): $String"
			$TaskResult = [PSCustomObject]@{
				"Host" = $env:Computername ; "TaskName" = $UninstallName ; "ExitCode" = $null
				"Id" = 0 ; "StartTime" = Get-Date -Format "MM/dd/yyyy HH:mm:ss" ; "ExitTime" = $null ; "OutPut" = $null
				"RunspaceId" = $null ; "Success" = "Unknown"
			}
			Write-LogandHost "$UninstallName is being processed..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Cyan
			$InvokeCommandLine = @{ 
				"Executable" = "msiexec.exe" ; "TaskName" = $UninstallName ; "Arguments" = $null
				"WaitTimeOut" = $null ; "WaitType" = $null ; "WaitSwitch" = $null ; "WaitItem" = $null ; "JobCount" = 3 ; "ScriptPath" = $ScriptPath
				"ShowProgress" = "$($Task.ShowProgress)" ; "Interactive" = $Interactive
			}
			$SuccessCodes += $($UninstallString.DefaultSuccessCodes)
			IF ($String -Match "\|") {
				# Has success codes on line
				Write-Verbose "The pipe character was found in the current line of the uninstallstrings file, there will be additional success codes"
				$PossibleGUIDorEXE,$TempSuccessCodes = $String.Split("|")
				$TempSuccessCodes = ($TempSuccessCodes -Split (",")).Trim()
				$SuccessCodes += $TempSuccessCodes
			}
			ELSE{
				# Does not have success codes on line	
				$PossibleGUIDorEXE = $String
			}
			Write-Verbose "All Success Codes for this task: $SuccessCodes"
			$FirstChar = ($PossibleGUIDorEXE.SubString(0,1)).Trim()
			$LastChar = ($PossibleGUIDorEXE.SubString($PossibleGUIDorEXE.Length-1,1)).Trim()
			IF (($FirstChar -eq "{")-AND($LastChar -eq "}")){
				Write-Verbose "The first and last characters where found to be {} this will be processed as a GUID"
				IF ((Find-GUID -GUIDS $PossibleGUIDorEXE) -eq $True) {
					# This will be processed as a GUID
					$Arguments = "/X $PossibleGUIDorEXE /qn /norestart /l* $LogFilePath$env:Computername.$PossibleGUIDorEXE.msi.Uninst.log"
					$InvokeCommandLine = @{ 
						"Executable" = "msiexec.exe" ; "TaskName" = $UninstallName ; "Arguments" = $Arguments
						"WaitTimeOut" = $null ; "WaitType" = $null ; "WaitSwitch" = $null ; "WaitItem" = $null ; "JobCount" = 3 ; "ScriptPath" = $ScriptPath
						"ShowProgress" = "$($Task.ShowProgress)" ; "Interactive" = $Interactive
					}
				}
				ELSE {
					Write-LogandHost "$UninstallName $PossibleGUIDorEXE does not exist in the registry and will be skipped" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow				
					IF ($ExitCodeOut -eq $False) {
						$TaskResult.ExitCode = "a"
						$TaskResult.ExitTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
						$TaskResult.Success = "Skipped"
						Write-Output $TaskResult
					}
					$SkipCount++
					Continue
				}
			}
			ELSE {
				Write-Verbose "The first and last characters where NOT found to be {} this will be processed as a EXE"
				$junk,$EXE,$Args = $PossibleGUIDorEXE.Split($quote)
				IF (($null -ne $EXE) -AND (Test-Path $EXE)) {
					$InvokeCommandLine = @{ 
						"Executable" = $EXE ; "TaskName" = $UninstallName ; "Arguments" = $Args
						"WaitTimeOut" = $null ; "WaitType" = $null ; "WaitSwitch" = $null ; "WaitItem" = $null ; "JobCount" = 3 ; "ScriptPath" = $ScriptPath
						"ShowProgress" = "$($Task.ShowProgress)" ; "Interactive" = $Interactive
					}
				}
				ELSE {
					Write-LogandHost "$UninstallName $PossibleGUIDorEXE could not be turned into an executable and arguments or the $EXE does not exist" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					IF (!($ExitCodeOut)) {
						$TaskResult.ExitCode = "b"
						$TaskResult.ExitTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
						$TaskResult.Success = "Skipped"
						Write-Output $TaskResult
					}
					$SkipCount++
					Continue
				}
			}
			Write-LogandHost "$UninstallName Executable: $($InvokeCommandLine.Executable)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			Write-LogandHost "$UninstallName Arguments: $($InvokeCommandLine.Arguments)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			$TaskResult = Invoke-Task @InvokeCommandLine
			IF ([String]::IsNullOrWhiteSpace($($TaskResult.ExitCode))) {
				$TaskResult.ExitCode = 0
				$TaskResult.ExitTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
				$TaskResult.Success = $True
			}
#			$TaskResult | Add-Member -MemberType NoteProperty -Name "TaskName" -Value $UninstallName
			Write-LogandHost "$UninstallName Result Code: $($TaskResult.ExitCode)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			$ExitCode = ($TaskResult.ExitCode).ToString()
			Write-Verbose "Success Codes: $SuccessCodes"
			IF (Compare-SuccessCode -SplitCodes $SuccessCodes -ExitCode $ExitCode) {
				$SuccessCount++
				Write-LogandHost  "$UninstallName completed successfully with exit code: $($TaskResult.ExitCode)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green
				$TaskResult | Add-Member -MemberType NoteProperty -Name "Success" -Value $True -Force
				Write-Output $TaskResult
				$ExitCodes += $AllTaskResults.ExitCode
			}
			ELSE {
				$FailedCount++
				Write-LogandHost  "$UninstallName failed with exit code: $($TaskResult.ExitCode)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
				$TaskResult | Add-Member -MemberType NoteProperty -Name "Success" -Value $False -Force
				Write-Output $TaskResult
				$ExitCodes = $($TaskResult.ExitCode)
				Break
			}
		}
	}
	End {
		Write-OutPut $AllTaskResults
	}
}
Function Start-UninstallAll {
<#
	.SYNOPSIS
	Removes an installed program 
	.DESCRIPTION
	
	Removes an installed program from the system if it is similar to the given item.  If a user
	includes Java, it will uninstall all the installed version of the Java from the system.

	.PARAMETER DisplayNameLike
	This parameter accepts words that will be in the display name of an installed application.
	All applications with these words in the name will be uninstalled.
	Ex. Java
	This parameter is mandatory

	.PARAMETER Architecture
	This parameter takes the architecture that the user wants to look for regarding the uninstall
	The script will only search the relevant registry locations for the requested architecture
	If no parameter is passed to the function then it will check both registry locations
	'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
	'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall
	Valid Data Set = "32","64","B","Both"
	This parameter is non-mandatory
	
	.PARAMETER ItemsToExclude
	This parameter will exclude the items that are like the item given to this parameter
	Example: Start-UninstallAll -DisplayNameLike "Java" -ItemsToExclude "Development Kit"
			This will remove all the Java items and exclude Java SE development kit from being removed
	This parameter is non-mandatory

	.EXAMPLE
	C:\PS> Start-UninstallAll -DisplayNameLike "Java" -ItemsToExclude "Development Kit"
		Removing Java 8 Update 144...
		Removing Java Auto Updater...
		Removing Java 8 Update 112 (64-bit)...
		Removing Java 8 Update 144 (64-bit)...
#>	
	[OutputType('System.Management.Automation.PSCustomObject')]
	[Cmdletbinding(SupportsShouldProcess=$true,DefaultParameterSetName='RegKey')]
	param
	( 
		[parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$true,ParameterSetName="Similar")]
		[string]$DisplayNameLike,
		[parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true,ParameterSetName="Similar")]
		[ValidateSet("32","64","B","Both")]
		[string]$Architecture,
		[parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true,ParameterSetName="Similar")]
		[string[]]$ItemsToExclude,
		[parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$true,ParameterSetName="Similar")]
		[String]$Interactive = "False",
		[string[]]$SuccessCodes,
		[Switch] $ExitCodeOut,
		[String] $TasksProcessed,
		[String] $TaskName,
		[String] $ScriptPath
	)

	Begin {
		# ASCII Characters
		$quote = [char]34
		# Counters
		$UninstallStringsCount = 0 ; $i = 0
		# Get System Information
		$SystemArch = (Get-CimInstance -Class Win32_Processor | Where-Object { $_.deviceID -eq "CPU0" }).AddressWidth.ToString()
		# Empty Arrays
		$SuccessCodes = @() ; $AllTaskResults = @()
		# Prepare Variables
		$UninstallStrings = $Path ; $TempSuccessCodes = $null ; $DefaultSuccessCodes = @(0,1605,1641,3010)
		$TaskResult = [PSCustomObject]@{
			"Host" = $env:Computername ; "TaskName" = $Taskname ; "ExitCode" = $null ; "Id" = 0
			"StartTime" = Get-Date -Format "MM/dd/yyyy HH:mm:ss" ; "ExitTime" = $null ; "OutPut" = $null ; "RunspaceId" = $null ; "Success" = "Unknown"
		}
		# Begin		
		Write-LogandHost "Task ($TasksProcessed): All items with names like, $DisplayNameLike, will be uninstalled..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		IF (!([String]::IsNullOrWhiteSpace($ItemsToExclude))) {Write-LogandHost "Task ($TasksProcessed): Excluding items similar to $ItemsToExclude" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
		IF (!([String]::IsNullOrWhiteSpace($Architecture))) {Write-LogandHost "Task ($TasksProcessed): Architecture of Applications to be removed: $Architecture" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
		
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
		IF ($Architecture -eq "32") { 
			IF ($SystemArch -eq 32){$UninstallKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall') }
			ELSEIF ($SystemArch -eq 64){$UninstallKeys = @('HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall') }
			ELSE {}
		}
		ELSEIF ($Architecture -eq "64") {
			IF ($SystemArch -eq 32){write-error  "The system is 32-bit, there are no 64-bit items to remove"}
			ELSEIF ($SystemArch -eq 64){$UninstallKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall') }
			ELSE {}	
		}
		ELSEIF (($Architecture -eq "B") -OR ($Architecture -eq "Both")) {
			$UninstallKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
		}
		ELSE {
			$UninstallKeys = @( 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
		}
		Write-Verbose "Uninstall Registry keys being checked, $UninstallKeys"
		Write-Verbose "Start-UninstallAll, Interactive = $Interactive"
		IF ([String]::IsNullOrWhiteSpace($Interactive)) {$Interactive = $False ; Write-LogandHost "Task ($TasksProcessed): Running only non-interactive uninstalls..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
		ELSEIF (($Interactive -eq "True") -OR ($Interactive -eq $True)) {$Interactive = $True ; Write-LogandHost "Task ($TasksProcessed): This will process interactive and non-interactive uninstalls..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
		ELSE {$Interactive = $False ; Write-LogandHost "Task ($TasksProcessed): Defaulting to run only non-interactive uninstalls..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}		
		Write-Verbose "Start-UninstallAll, Interactive after boolean change = $Interactive"
	}
	Process{
		Write-Verbose "Processing the uninstall of items like, $DisplayNameLike"
		### Put in code to search for all the display names like $DisplayNameLike and items to exclude if they were provided
		If (!([String]::IsNullOrWhiteSpace($ItemsToExclude))) {
			$UninstallSearchFilter = {($_.GetValue('DisplayName') -like "*$DisplayNameLike*") -and ($_.GetValue('DisplayName') -notLike "*$ItemsToExclude*" )} 
		}
		ELSE {
			$UninstallSearchFilter = {($_.GetValue('DisplayName') -like "*$DisplayNameLike*")}
		}
		$AllTaskResults += Foreach ($Path  in $UninstallKeys) {
			If(Test-Path $Path) {
				Write-Verbose "Searching $Path for items like, $DisplayNameLike"
				Get-ChildItem $Path | Where-Object $UninstallSearchFilter |Foreach-Object {
					$i++
					$SuccessCodes = @()
					Write-Verbose "Removing $($_.GetValue('DisplayName'))..."
					$PossibleGUID = $($_.PSChildName)
					$PossibleGUID = $PossibleGUID.Trim()
					$FirstChar = ($PossibleGUID.SubString(0,1)).Trim()
					$LastChar = ($PossibleGUID.SubString($PossibleGUID.Length-1,1)).Trim()
					$UninstallString = $($_.GetValue('UninstallString'))
					$QuietUninstallString =  $($_.GetValue('QuietUninstallString'))
					$InstallLocation = $_.GetValue('InstallLocation')
					$InstallStatus = [PSCustomObject]@{
						"ComputerName"=$Env:Computername
						"UninstallRegKey"= $PossibleGUID
						"DisplayName"= $($_.GetValue('DisplayName'))
						"InstallationStatus"="Installed"
						"UninstallExitCode"=$null
					}
					$UninstallName = "Task ($TasksProcessed): Uninstall All ($i) - $($InstallStatus.DisplayName)"
					$TaskResult = [PSCustomObject]@{
						"Host" = $env:Computername ; "TaskName" = $UninstallName ; "ExitCode" = $null ; "Id" = 0
						"StartTime" = Get-Date -Format "MM/dd/yyyy HH:mm:ss" ; "ExitTime" = $null ; "OutPut" = $null ; "RunspaceId" = $null ; "Success" = "Unknown"
					}
					IF (($FirstChar -eq "{")-AND($LastChar -eq "}")){
						# This will be processed as a GUID
						$Arguments = "/X $PossibleGUID /qn /norestart /l* $LogFilePath" + "$env:Computername.$PossibleGUID.msi.Uninst.log"
						$InvokeCommandLine = @{ 
							"Executable" = "msiexec.exe" ; "TaskName" = $UninstallName ; "Arguments" = $Arguments
							"WaitTimeOut" = $null ; "WaitType" = $null ; "WaitSwitch" = $null ; "WaitItem" = $null ; "JobCount" = 3 ; "ScriptPath" = $ScriptPath ; 
							"ShowProgress" = "$($Task.ShowProgress)"  ; "Interactive" = $False
						}
					}
					ELSEIF ($Interactive -eq $True){
						IF (!([String]::IsNullOrWhiteSpace($QuietUninstallString))) {
							IF ($QuietUninstallString -Match $quote){
								$junk,$EXE,$Args = $QuietUninstallString.Split($quote)
							}
							ELSE {
								IF ($QuietUninstallString -Match (".exe ")){
									$EXE,$Args = $QuietUninstallString -split (".exe ")
									$EXE = $EXE + ".exe"
								}
								ELSE {
									$EXE,$Args = $QuietUninstallString.Split(" ")
								}
							}
							$InvokeCommandLine = @{ 
								"Executable" = $EXE ; "TaskName" = $UninstallName ; "Arguments" = $Args
								"WaitTimeOut" = $null ; "WaitType" = $null ; "WaitSwitch" = $null ; "WaitItem" = $null ; "JobCount" = 3 ; "ScriptPath" = $ScriptPath ; 
								"ShowProgress" = "$($Task.ShowProgress)" ; "Interactive" = $True
							}
						}
						ELSEIF (!([String]::IsNullOrWhiteSpace($UninstallString))) {
							IF ($UninstallString -Match $quote){
								$junk,$EXE,$Args = $UninstallString.Split($quote)
							}
							ELSE {
								IF ($UninstallString -Match (".exe ")){
									$EXE,$Args = $UninstallString -split (".exe ")
									$EXE = $EXE + ".exe"
								}
								ELSE {
									$EXE,$Args = $UninstallString.Split(" ")
								}
							}
							$InvokeCommandLine = @{ 
								"Executable" = $EXE ; "TaskName" = $UninstallName ; "Arguments" = $Args
								"WaitTimeOut" = $null ; "WaitType" = $null ; "WaitSwitch" = $null ; "WaitItem" = $null ; "JobCount" = 3 ; "ScriptPath" = $ScriptPath
								"ShowProgress" = "$($Task.ShowProgress)" ; "Interactive" = $True
							}
						}
					}
					ELSE {						
						Write-LogandHost "Unable to run uninstall for $PossibleGUID" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
						$TaskResult.ExitCode = 0
						$TaskResult.ExitTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
						$TaskResult.Success = "Skipped"
						IF (!($ExitCodeOut)) {
							Write-Output $TaskResult
						}
						#Continue
					}
					IF ($($TaskResult.Success) -ne "Skipped"){
						Write-LogandHost "$UninstallName is being processed" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Cyan
						Write-LogandHost "$UninstallName Executable: $($InvokeCommandLine.Executable)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
						Write-LogandHost "$UninstallName Arguments: $($InvokeCommandLine.Arguments)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
						$TaskResult = Invoke-Task @InvokeCommandLine
						IF ([String]::IsNullOrWhiteSpace($($TaskResult.ExitCode))) {
							$TaskResult.ExitCode = 0
							$TaskResult.ExitTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
							$TaskResult.Success = $True
							#Write-Output $TaskResult
						}
						#$TaskResult | Add-Member -MemberType NoteProperty -Name "TaskName" -Value $UninstallName
						Write-LogandHost "$UninstallName Result Code: $($TaskResult.ExitCode)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
						$ExitCode = ($TaskResult.ExitCode).ToString()
						$SuccessCodes += $($TaskResult.ExitCode)
						Write-Verbose "Success Codes: $SuccessCodes"
						IF (Compare-SuccessCode -SplitCodes $SuccessCodes -ExitCode $ExitCode) {
							$SuccessCount++
							Write-LogandHost  "$UninstallName completed successfully with exit code: $($TaskResult.ExitCode)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green
							$TaskResult | Add-Member -MemberType NoteProperty -Name "Success" -Value $True -Force
							IF (!($ExitCodeOut)) {Write-OutPut $TaskResult}
							# Write-Output $TaskResult
							# $ExitCodes += $AllTaskResults.ExitCode
							$InstallStatus.InstallationStatus = "Uninstalled"
						}
						ELSE {
							$FailedCount++
							Write-LogandHost  "$UninstallName failed with exit code: $($TaskResult.ExitCode)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
							$TaskResult | Add-Member -MemberType NoteProperty -Name "Success" -Value $False -Force
							IF (!($ExitCodeOut)) {Write-OutPut $TaskResult}
							Write-Output $TaskResult
							# $ExitCodes = $($TaskResult.ExitCode)
							$InstallStatus.InstallationStatus = "Installed"
							Break
						}
						Start-Sleep -s 5
						# Delete Install Location
						IF ([String]::IsNullOrEmpty($InstallLocation)) {}
						ELSE
						{
							IF (Test-Path $InstallLocation){
								Try {
									Remove-Item $InstallLocation -Force -Recurse -ErrorAction SilentlyContinue
									Write-Verbose "Successfully removed Install Location: $InstallLocation"
								}
								Catch {
									Write-LogandHost "Unable to remove item, $InstallLocation" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
								}
							}
						}
						# Removed Uninstall Registry Keys
						IF (Test-Path $_.PSPath){
							Try {
								Remove-Item $_.PSPath -Force -Recurse -ErrorAction SilentlyContinue
								Write-Verbose "Successfully removed Registry Key: $($_.PSPath)"
							}
							Catch {
								Write-LogandHost "Unable to remove item, $($_.PSPath)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
							}
						}
						# Cleanup HKEY_CLASSES_ROOT Registry hive
						$ClassesRootPath = �HKCR:\Installer\Products� 
						IF ($PSCmdlet.ShouldProcess("Remove Registry","HKCR:\Installer\Products installed product names")) {
							Get-ChildItem $ClassesRootPath | Where-Object { ($_.GetValue('ProductName') -like $($InstallStatus.DisplayName))} | Foreach-Object {
								Try {
									Remove-Item $_.PsPath -Force -Recurse -ErrorAction SilentlyContinue
									Write-Verbose "Successfully removed Classes Root Installer Product: $($_.PSPath)"
								}
								Catch {
									Write-LogandHost "Unable to remove item, $($_.PSPath)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
								}
							}
						}
					}
				} 
			}
		}
	}
	End {
		Remove-PSDrive -Name HKCR -Force
		Write-Verbose "$i items processed for uninstall"
		Write-OutPut $AllTaskResults
	}
}
Function Add-ChangeInformation {
<#
	.SYNOPSIS
	Makes a record of change on the systems registry.  This enables system changes to be auditable.

        .DESCRIPTION
	Makes a record of change on the systems registry.  This enables system changes to be auditable.
	The change is recorded in the following path on the system:  
		"HKLM\Software\[Co]\[Dept]\[Agency]\[Dv]\[Branch]\Changes\[Change]" - If running with administrative rights
		"HKLM\Software\WOW6432Node\[Co]\[Dept]\[Agency]\[Dv]\[Branch]\Changes\[Change]"  - If running with administrative rights and started from a 32-bit process on a 64-bit system.  An example process is "ccmexe.exe"
		"HKCU\Software\[Co]\[Dept]\[Agency]\[Dv]\[Branch]\Changes\[Change]"  - If running without administrative rights
	The following values are recorded within the registry key created.  They are all string values.
		Date Installed	[Date] and [Time] the package was run
		Description "$PackageName"
		NumTimesInstalled	This records the number of times the package was installed
		Version	This records the version of the package installed.
	
        .PARAMETER Co
        Specifies the name of the company or organization that is making the change.  This parameter is not mandatory.

        .PARAMETER Dept
        Specifies the name of the department within the company or organization that is making the change.  This parameter is not mandatory.

        .PARAMETER Agency
        Specifies the name of the agency within the department within the company or organization that is making the change.  This parameter is not mandatory.

        .PARAMETER Division
        Specifies the name of the division within the agency within the department within the company or organization that is making the change.  This parameter is not mandatory.

        .PARAMETER Branch
        Specifies the name of the branch within the division within the agency within the department within the company or organization that is making the change.  This parameter is not mandatory.

        .PARAMETER Change
        Specifies the change number for the change within your change tracking system.  This parameter is not mandatory.
		ex. RFC 11221
		ex. CRQ00001

        .PARAMETER PackageName
        Specifies the name of the change.  This parameter is not mandatory.
		ex. Adobe Acrobat Reader XI
		ex. Microsoft Office 365 Pro
	
        .PARAMETER Version
        Specifies the version of the package.  This parameter is not mandatory.
		ex. 20.009.20063

        .OUTPUTS
        Registry key and values

        .EXAMPLE
        C:\PS> Add-ChangeInformation -Co [Co] -Dept [Dept] -Agency [Agency] -Division [Dv] -Branch [Branch] -Change CRQ0001 -PackageName "Test 1" -Version "20.009.20063"
		The registry key "HKLM\Software\[Co]\[Dept]\[Agency]\[Dv]\[Branch]\Changes\[Change]" with the values below will be created
		Date Installed	2020-05-18 19:30:26
		Description	"Test 1"
		NumTimesInstalled	1
		Version	20.009.20063
#>
	[CmdletBinding(SupportsShouldProcess=$true)]	
	Param(
		[AllowEmptyString()]
		[AllowNull()]
		[String] $Co,
		[AllowEmptyString()]
		[AllowNull()]
		[String] $Dept,
		[AllowEmptyString()]
		[AllowNull()]
		[String] $Agency,
		[AllowEmptyString()]
		[AllowNull()]
		[String] $Division,
		[AllowEmptyString()]
		[AllowNull()]
		[String] $Branch,
		[parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]
		[String] $Change = "00000001",
		[parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]
		[String] $PackageName = "NameNotSpecified",
		[parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]
		[String] $Version = "0.00.00.01"
	)
	Begin {
		Write-Verbose "Beginning function to add the change information to the registry..."
		$AdminRights = Test-AdminRights -User $env:username
		# Only put variables together if they contain data
		IF ($Co -notmatch "^$") {$RegistryPathEnd = "Software\" + $Co  + "\"} ELSE {$RegistryPathEnd = "Software\"}
		IF ($Dept -notmatch "^$") {$RegistryPathEnd = $RegistryPathEnd + $Dept + "\"} ELSE {$RegistryPathEnd = $RegistryPathEnd}
		IF ($Agency -notmatch "^$") {$RegistryPathEnd = $RegistryPathEnd + $Agency + "\"} ELSE {$RegistryPathEnd = $RegistryPathEnd}
		IF ($Division -notmatch "^$") {$RegistryPathEnd = $RegistryPathEnd + $Division + "\"} ELSE {$RegistryPathEnd = $RegistryPathEnd}
		IF ($Branch -notmatch "^$") {$RegistryPathEnd = $RegistryPathEnd + $Branch + "\"} ELSE {$RegistryPathEnd = $RegistryPathEnd}
		$RegistryPathEnd = $RegistryPathEnd + "Changes\$Change"
		IF ($AdminRights -eq $False) {
			$RegistryPath = "HKCU:\" + $RegistryPathEnd
		}
		ELSE {
			$RegistryPath = "HKLM:\" + $RegistryPathEnd
		}
		Write-Verbose "Record of Change path: $RegistryPath"
	}
	Process {	
		IF (!(Test-Path $RegistryPath)) {
			# Registry Path was not found - Create Path
			New-Item -Path $RegistryPath -Force |Out-Null
			Write-Verbose "Created Change Path: $RegistryPath"
		}
		$RegistryValues = Get-ItemProperty $RegistryPath
		IF ([String]::IsNullOrWhiteSpace($($RegistryValues.NumTimesInstalled))) {
			# Set it to 1
			$NumTimesInstalled = 1
		}
		ELSE {
			# Find number and add one to it
			$NumTimesInstalled = [Int]$($RegistryValues.NumTimesInstalled) + 1	
		}
		TRY {
			New-ItemProperty -Path $RegistryPath -Name "NumTimesInstalled" -PropertyType String -value $NumTimesInstalled -Force |Out-Null
			$DateNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
			New-ItemProperty -Path $RegistryPath -Name "Date Installed" -PropertyType String -value $DateNow -Force |Out-Null
			New-ItemProperty -Path $RegistryPath -Name "Description" -PropertyType String -value $PackageName -Force |Out-Null
			New-ItemProperty -Path $RegistryPath -Name "Version" -PropertyType String -value $Version -Force |Out-Null
			Write-LogandHost "Record of change added to $RegistryPath...." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green
		}
		CATCH {
			Write-LogandHost "Error adding record of change to $RegistryPath -Error: $_" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
		}
	}
	END { }
}
Function Remove-ChangeInformation {
<#
	.SYNOPSIS
	Removes a record of change on the system's registry. 

        .DESCRIPTION
	Removes a record of change on the system's registry.
	The change is removed from the following path on the system depending on how it was created:  
		"HKLM\Software\[Co]\[Dept]\[Agency]\[Dv]\[Branch]\Changes\[Change]" - If running with administrative rights
		"HKLM\Software\WOW6432Node\[Co]\[Dept]\[Agency]\[Dv]\[Branch]\Changes\[Change]"  - If running with administrative rights and started from a 32-bit process on a 64-bit system.  An example process is "ccmexe.exe"
		"HKCU\Software\[Co]\[Dept]\[Agency]\[Dv]\[Branch]\Changes\[Change]"  - If running without administrative rights
	
        .PARAMETER Co
        Specifies the name of the company or organization that is making the change.  This parameter is not mandatory.

        .PARAMETER Dept
        Specifies the name of the department within the company or organization that is making the change.  This parameter is not mandatory.

        .PARAMETER Agency
        Specifies the name of the agency within the department within the company or organization that is making the change.  This parameter is not mandatory.

        .PARAMETER Division
        Specifies the name of the division within the agency within the department within the company or organization that is making the change.  This parameter is not mandatory.

        .PARAMETER Branch
        Specifies the name of the branch within the division within the agency within the department within the company or organization that is making the change.  This parameter is not mandatory.

        .PARAMETER Change
        Specifies the change number for the change within your change tracking system.  This parameter is not mandatory.
		ex. RFC 11221
		ex. CRQ00001

        .OUTPUTS
        Deletes the registry keys and values for a change, if they exist

        .EXAMPLE
        C:\PS> Remove-ChangeInformation -Co [Co] -Dept [Dept] -Agency [Agency] -Division [Dv] -Branch [Branch] -Change CRQ0001
		The registry key "HKLM\Software\[Co]\[Dept]\[Agency]\[Dv]\[Branch]\Changes\CRQ0001" and it's values will be removed from the system.

#>
	[CmdletBinding(SupportsShouldProcess=$true)]	
	Param(
		[AllowEmptyString()]
		[AllowNull()]
		[String] $Co,
		[AllowEmptyString()]
		[AllowNull()]
		[String] $Dept,
		[AllowEmptyString()]
		[AllowNull()]
		[String] $Agency,
		[AllowEmptyString()]
		[AllowNull()]
		[String] $Division,
		[AllowEmptyString()]
		[AllowNull()]
		[String] $Branch,
		[parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$true)]
		[String] $Change = "00000001"
	)
	Begin {
		Write-Verbose "Beginning function to remove the change information from the registry..."
		$AdminRights = Test-AdminRights -User $env:username
		# Only put variables together if they contain data
		IF ($Co -notmatch "^$") {$RegistryPathEnd = "\" + $Co  + "\"} ELSE {$RegistryPathEnd = "\"}
		IF ($Dept -notmatch "^$") {$RegistryPathEnd = $RegistryPathEnd + $Dept + "\"} ELSE {$RegistryPathEnd = $RegistryPathEnd}
		IF ($Agency -notmatch "^$") {$RegistryPathEnd = $RegistryPathEnd + $Agency + "\"} ELSE {$RegistryPathEnd = $RegistryPathEnd}
		IF ($Division -notmatch "^$") {$RegistryPathEnd = $RegistryPathEnd + $Division + "\"} ELSE {$RegistryPathEnd = $RegistryPathEnd}
		IF ($Branch -notmatch "^$") {$RegistryPathEnd = $RegistryPathEnd + $Branch + "\"} ELSE {$RegistryPathEnd = $RegistryPathEnd}
		$RegistryPathEnd = $RegistryPathEnd + "Changes\$Change"		
		IF ($AdminRights -eq $False) {
			$RegistryPaths = @("HKCU:\Software$RegistryPathEnd")
		}
		ELSE {
			$RegistryPaths = @("HKLM:\Software$RegistryPathEnd", "HKLM:\Software\Wow6432Node$RegistryPathEnd")
		}
	}
	Process {
		$RegistryPaths | Foreach-Object {
			$RegistryPath = $_
			IF (Test-Path $RegistryPath){
				Try {
					Remove-Item $RegistryPath -Force
					Write-LogandHost "Removed record of change from $RegistryPath" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green
				}
				Catch {
					Write-LogandHost "Error removing record of change from $RegistryPath -Error: $_" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
				}
			}
		}
	}
	END { }
}
Function Remove-Item2 {
<#
	.SYNOPSIS
	Removes items from a system, verifies their removal, and if they were not removed tries again.

        .DESCRIPTION
	Removes items from a system, verifies their removal, and if they were not removed tries again.
	By default it tries to remove the item 5 times and it pauses 2 seconds between attempts.
	
        .PARAMETER Path
        Specifies the path to the item that needs to be deleted.  This parameter is mandatory.

        .PARAMETER Attempts
        Specifies the number of times it will try to delete an item.  This parameter is not mandatory.

        .PARAMETER SleepTime
        Specifies the number of seconds to sleep before attempting to delete it again.  This parameter is not mandatory.

        .OUTPUTS
        None

        .EXAMPLE
        C:\PS> Remove-Item2 -Path "C:\temp\test.exe"
		The item "C:\temp\test.exe" was deleted from the host system.

#>
	[CmdletBinding(SupportsShouldProcess=$true)]
	Param(
		[Parameter(Mandatory=$true,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[string[]] $Path,
		[Parameter(Mandatory=$false)]
		[Int] $Attempts = 5,
		[Int] $SleepTime = 2
	)
	Begin {
		# ASCII Characters
		$tab= [char]9
		# Prepare Variables
		$CmdExitCode = 0
		# Begin
		Write-Verbose "Beginning function to remove items with retry set to $Attempts"		
	}
	Process {
		IF ($Path -Match "|") {
			$Path = $Path.Split("|")
		}
		$Path|Foreach-Object {
			$A = $_
			$i=0
			$A = $A.Trim()
			write-verbose "Attempting to remove: $A"
			DO {
				If (Test-path $A){
					write-verbose "Removing $A"
					TRY {
						Remove-Item $A -Recurse -Force -ErrorAction Stop
						write-verbose "Waiting $sleeptime seconds before checking to see if the remove worked"
						Start-Sleep -s $sleeptime
						IF(!(Test-path $A)) {
							Write-LogandHost "Success: $A was removed" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green
							$i=$Attempts
						}
						ELSE {
							write-verbose "$A exists, incrementing loop by 1"
							$i++
							Write-LogandHost "Attempting to remove, $A, again" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
							# (Get-Item c:\fso) -is [System.IO.DirectoryInfo]
							IF ((Get-Item $A) -is [System.IO.DirectoryInfo]) {
								# Item is a directory
								IF ($PSCmdlet.ShouldProcess("$A","Removing the directory")) {
									& CMD.EXE "/C RD /S /Q $A 2>nul 1>nul"
									$CmdExitCode = $LASTEXITCODE
								}
							}
							ELSE {
								# Item is a file
								IF ($PSCmdlet.ShouldProcess("$A","Removing the file")) {
									& CMD.EXE "/C DEL /S /F $A 2>nul 1>nul"
									$CmdExitCode = $LASTEXITCODE
								}
							}
							Write-verbose "Last Exit Code: $CmdExitCode"
							IF($CmdExitCode -eq 0){
								Write-LogandHost "Success: $A was removed" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green
								$i=$Attempts
							}
						}
					}
					CATCH {
						Write-LogandHost "Error removing item $A, $_" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
						$i++
					}
				} 
				ELSE {
					IF ($vl) {Write-LogandHost "Warning: $A does NOT exist" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow}
					$i=$Attempts
				}
			} Until ($i -eq $Attempts)
		}
	}
	END { }
}
Function Remove-Cache {
<#
	.SYNOPSIS
	Removes the cached package from the specified location.

        .DESCRIPTION
	Removes the cached package from the specified location.
	
        .PARAMETER CachePath
       Specifies the path that the package was cached to.  This parameter is mandatory.

        .OUTPUTS
        None

        .EXAMPLE
        C:\PS> Remove-Cache -CachePath "C:\temp\test"
		The item "C:\temp\test" was removed from the host system.

#>
	[OutputType('System.Management.Automation.PSCustomObject')]
	[CmdletBinding(SupportsShouldProcess=$true)]
	Param (	
		[String] $CachePath
	)
	Begin {
		$CacheInfo = [PSCustomObject]@{"Cached"=$null;"Location"=$null}
		IF (!(Test-Path $CachePath)) {
			Write-Error "Error: The cached path does not exist and cannot be removed"
			[System.Environment]::Exit(3)	
		} 
	}
	Process {
		Write-LogandHost "******************* REMOVING CACHE *************************************" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		$scriptName = & { $myInvocation.ScriptName }
		$ScriptPath = (Split-Path -Parent -Path $scriptName)
		Set-Location $ScriptPath
		$CachePath|Remove-Item2
	}
	End {}
}
Function New-Shortcut {
<#
	.SYNOPSIS
	Creates a shortcut to a file 
	.DESCRIPTION
	
	Creates a shortcut to a file or folder
	
	.EXAMPLE
	C:\PS> New-Shortcut -ShortCutPath "*USERPROFILE*\Desktop\Test.lnk" -TargetPath "H:\scripts\PowerShell\bin\LogOff.cmd"
	A Shortcut, Test, was created on the current user's desktop

#>
	[Cmdletbinding( )]
	param (
		[parameter(Mandatory=$True, ValueFromPipeline=$True, Position=0)]
		[String]$ShortCutPath,
		[parameter(Mandatory=$True)]
		[String]$TargetPath,
		[parameter(Mandatory=$False)]
		[String]$ShortCutArguments = $null,
		[parameter(Mandatory=$False)]
		[String]$Description = "None",
		[parameter(Mandatory=$False)]
		[String]$WorkingDirectory = $null
	)
	Begin {
		$appdata = $env:appdata
		$userprofile = $env:USERPROFILE
		$HomeShare = $env:HOMESHARE
		$ShortCutPath = $ShortCutPath -replace "\*Appdata\*", $appdata.Trim()
		$ShortCutPath = $ShortCutPath -replace "\*USERPROFILE\*", $userprofile.Trim()
		$ShortCutPath = $ShortCutPath -replace "\*HOMESHARE\*", $HomeShare.Trim()
	}
	Process {
		Write-Verbose "Creating shortcut..."
		TRY {
			IF ($WorkingDirectory -eq "") { $WorkingDirectory = Split-Path $TargetPath.Trim() }
			$Executable = Split-Path $TargetPath.Trim() -leaf
			$Shell = New-Object -ComObject ("WScript.Shell")
			$ShortCut = $Shell.CreateShortcut($ShortCutPath)
			$ShortCut.TargetPath=$TargetPath
			$ShortCut.Arguments=$ShortCutArguments
			$ShortCut.WorkingDirectory = $WorkingDirectory;
			$ShortCut.WindowStyle = 1;
			$ShortCut.Hotkey = "$null";
			$ShortCut.IconLocation = "$TargetPath, 0";
			$ShortCut.Description = $Description;
			$ShortCut.Save()
			Write-Verbose "Shortcut created ..."
		}
		CATCH {
			Write-Warning "Warning shortcut for $TargetPath was not created correctly"
		}
	}
	END {}
}
Function Start-Framework {
<#
	.SYNOPSIS
        A Windows application deployment function with an emphasis on standarization and simplicity that is able to reboot a system and continue where it left off.

        .DESCRIPTION

	One script to control the uninstall, install, and repair of applications for a Windows system.
	The sole purpose of the Installation Framework is to enable maintainability when managing application deployments on the Windows platform. This allows an administrator to consolidate multiple uninstall, install, and repair scripts into one Framework.
	Modifying the script itself is not typically necessary, as it processes custom instructions, or task entries, in an accompanying XML package file, Install.xml, leaving the original codebase of said script intact.
	The Installation Framework was purposely designed to process tasks in the following order, uninstall then install. If a package repair is needed a command line switch can be passed to the framework to intiate those tasks. The reason it is processing uninstalls then installs is because when an administrator has to install a new application that is order typically used, remove the old version, install the new version. If an upgrade to an existing application is needed the creator would just not include an uninstall task for that item.
	The framework has the ability to reboot after a tasks completes and pickup on the next task.

        .PARAMETER Install
        Specifies that the function should run the tasks that have a designated task type of install or that have no task designation. This is not mandatory.

        .PARAMETER Uninstall
        Specifies that the function should run the tasks that have a designated task type of uninstall. This is not mandatory.
	
        .PARAMETER UninstallCurrent
	Specifies that the function should run the tasks that have a designated task type of uninstallcurrent. This is not mandatory.

        .PARAMETER Repair
        Specifies that the function should run the tasks that have a designated task type of repair. This is not mandatory.

        .PARAMETER ContinueAtTask
        Specifies the task number within install.xml that it should start with.  This is not mandatory.

        .PARAMETER Scheduled
        Specifies whether the function should wait a predetermined amount of time before continuing with the next task.  This is not mandatory.
	This should be used in conjunction with the PauseFor parameter.

        .PARAMETER ExitCodeOut
        Specifies that the function should return an exit code to the starting process.  This is not mandatory.  
	The function defaults to returning an PS custom object.

        .PARAMETER PauseFor
        Specifies the number of seconds to wait before continuing the next task. This is mandatory.
	This should be used in conjunction with the Scheduled parameter.
	If the parameter is not specified it defaults to 300 seconds.
	
        .PARAMETER LogRoot
        Specifies the root of the log and cache files. This is not mandatory.
	If no parameter is specified it defaults to $env:ProgramData

        .PARAMETER vl
        Specifies that logging and host output should include verbose output. This is not mandatory.

        .OUTPUTS
        PS Custom Object or Exit code

        .EXAMPLE
        C:\PS> Start-Framework -Install
        Host, Success, TaskName, ExitCode, Id, StartTime, ExitTime, OutPut, RunspaceId
	
        .EXAMPLE
        C:\PS> Start-Framework -Uninstall -ExitCodeOut
        0
#>
	[OutputType('System.Management.Automation.PSCustomObject')]
	[CmdletBinding(SupportsShouldProcess=$true)]
	Param (
		[parameter(Mandatory=$False)]
		[Switch] $Install,
		[parameter(Mandatory=$False)]
		[Switch] $Uninstall,
		[parameter(Mandatory=$False)]
		[Switch] $UninstallCurrent,
		[parameter(Mandatory=$False)]
		[Switch] $Repair,
		[parameter(Mandatory=$False)]
		[Int] $ContinueAtTask = 0,
		[parameter(Mandatory=$False)]
		[Switch] $Scheduled,
		[parameter(Mandatory=$False)]
		[Switch] $ExitCodeOut,
		[parameter(Mandatory=$False)]
		[Int] $PauseFor = 300,
		[parameter(Mandatory=$False)]
		[String] $LogRoot,
		[parameter(Mandatory=$False)]
		[Switch] $vl
	)
Begin {
	# Script Information
	$Script = [PSCustomObject]@{ 
		"DefaultSuccessCodes" = @(0,1641,3010)
		"DefaultTimeOut" = 60
		"version" = "3.00.01.00"
		"Name" = $PSCommandPath
		"Path" = $PSScriptRoot
	}
	$Parent = $Script.Path |Split-Path
	# Install framework File
	$FrameworkFile = "Install.xml"
	$FrameworkFile2 = "Install.json" # Not ready to be used
	# ASCII Characters
	$tab= [char]9
	# Counters
	$TasksProcessed = 0 ; $SuccessCount = 0 ; $SkipCount = 0 ; $FailedCount = 0
	# Booleans
	$CachedPackage = $false ; $CleanUpScheduledTasks = $False
	# Get System Information
	$System = Get-SystemInformation
	# Minimum required PowerShell version
	[Version]$PowerShellMinimumVersion = "5.0.0.0"
	# Empty Arrays
	$AllTaskResults = @() ; $UninstallStringsTasks = @(); $UninstallAllTasks = @(); $ExitCodes = @()
	# Empty Variables
	$XML = $null ; $XMLText = $null ; $XMLText2 = $null ; $TempSuccessCodes = $null ; $ReturnCode = $null
	# Empty Objects
	$EnvInfo = [PSCustomObject]@{ "Co"=$null ; "Dept"=$null ; "Agency"= $null ; "Division"= $null ; "Branch"= $null ; "doAdminCheck"=$false ; "Logging"=$false ; "DisplayOutput"=$false 	}
	$Package = [PSCustomObject]@{ "PackageName"=$null ; "Change"=$null ; "Version"=$null ; "Cache"=$false }
	$ValidationItems  = [PSCustomObject]@{ "Name" = $null ; "Type" = $null ; "RequestedResult" = $null ; "ActualResult" = $null }
	$WaitItems  = [PSCustomObject]@{ "Switch" = $null ; "Type" = $null ; "Timeout" = $null ; "Item" = $null }
	$TaskResult = [PSCustomObject]@{ "Host" = $null ; "TaskName" = $null ; "ExitCode" = $null ; "Id" = $null ; "StartTime" = $null ; "ExitTime" = $null  ; "OutPut" = $null ;"RunspaceId" = $null ; "Success" = $null}
	
	# Begin
	# Clear-Host
	$DateNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
	Write-Verbose "$DateNow - Beginning Install Framework..."
	Write-Verbose "$tab Command line Arguments: `n $tab Install = $install `n $tab Uninstall = $Uninstall `n $tab Repair = $Repair `n $tab Task number = $ContinueAtTask `n $tab ScriptPath = $($Script.Path)`n $tab ScriptName = $($Script.Name)"
	
	# Find Install.XML file and get the content
	IF (Test-Path "$($Script.Path)\$FrameworkFile") {$FrameworkFilePath = "$($Script.Path)\$FrameworkFile" ; $xmlYesorNo = "yes"}
	ELSEIF (Test-Path "$($Script.Path)\$FrameworkFile2") {$FrameworkFilePath = "$($Script.Path)\$FrameworkFile2"  ; $xmlYesorNo = "no"}
	ELSE {$FrameworkFilePath = ".\$FrameworkFile"}
	Write-Verbose "`n User Config File Path: $FrameworkFilePath"
	IF (Test-Path $FrameworkFilePath) {
		Write-Verbose "Importing data from file, $FrameworkFile"
		IF ($xmlYesorNo -eq "yes") { [XML]$XML = Get-Content -Path $FrameworkFilePath } ELSE {$XML = Get-Content -raw -path $FrameworkFilePath|ConvertFrom-Json}
		# Process the environment information
		IF ($XML.Framework.Environment -notmatch "^$") {
			IF ($XML.Framework.Environment.Co -notmatch "^$") {$EnvInfo.Co = $XML.Framework.Environment.Co}
			IF ($XML.Framework.Environment.Dept -notmatch "^$") {$EnvInfo.Dept = $XML.Framework.Environment.Dept}
			IF ($XML.Framework.Environment.Agency -notmatch "^$") {$EnvInfo.Agency = $XML.Framework.Environment.Agency}
			IF ($XML.Framework.Environment.Division -notmatch "^$") {$EnvInfo.Division = $XML.Framework.Environment.Division}
			IF ($XML.Framework.Environment.Branch -notmatch "^$") {$EnvInfo.Branch = $XML.Framework.Environment.Branch}
			IF ($XML.Framework.Environment.CheckAdminRights -notmatch "^$") { IF ($XML.Framework.Environment.CheckAdminRights -eq "True"){$EnvInfo.doAdminCheck = $True} }
			IF ($XML.Framework.Environment.Logging -notmatch "^$") { IF ($XML.Framework.Environment.Logging -eq "True"){$EnvInfo.Logging = $True} }
			IF ($XML.Framework.Environment.DisplayOutput -notmatch "^$") { IF ($XML.Framework.Environment.DisplayOutput -eq "True"){$EnvInfo.DisplayOutput = $True} }
			Write-Verbose "$tab Environment Information: `n $tab Dept = $($EnvInfo.Dept) `n $tab Agency = $($EnvInfo.Agency) `n $tab Division = $($EnvInfo.Division) `n $tab Branch = $($EnvInfo.Branch) `n $tab Admin Check = $($EnvInfo.doAdminCheck) `n $tab Logging = $($EnvInfo.Logging) `n $tab Display Output = $($EnvInfo.DisplayOutput)"

			# Only put variables together if they contain data
			IF ($LogRoot -match "^$") {$System.InstallationRootFolder = $System.ProgramData} 
			ELSE {
				$Length = $LogRoot.length
				$LastChar = $LogRoot.substring($Length-1,1)
				IF ($LastChar -Match "\\") { $System.InstallationRootFolder = $LogRoot } ELSE { $System.InstallationRootFolder = $LogRoot + "\"}
			}
			IF ($EnvInfo.Co -notmatch "^$") {$LogFilePath = $System.InstallationRootFolder + $EnvInfo.Co  + "\"} ELSE {$LogFilePath = $System.InstallationRootFolder}
			IF ($EnvInfo.Dept -notmatch "^$") {$LogFilePath = $LogFilePath + $EnvInfo.Dept + "\"} ELSE {$LogFilePath = $LogFilePath}
			IF ($EnvInfo.Agency -notmatch "^$") {$LogFilePath = $LogFilePath + $EnvInfo.Agency + "\"} ELSE {$LogFilePath = $LogFilePath}
			IF ($EnvInfo.Division -notmatch "^$") {$LogFilePath = $LogFilePath + $EnvInfo.Division + "\"} ELSE {$LogFilePath = $LogFilePath}
			IF ($EnvInfo.Branch -notmatch "^$") {$LogFilePath = $LogFilePath + $EnvInfo.Branch + "\"} ELSE {$LogFilePath = $LogFilePath}
			$LogFilePath = $LogFilePath + "logs\"
		}
		Else {
			Write-Warning "No Environment information was found in the framework the logging path will default to $env:temp"
			$LogFilePath = $env:temp + "\logs\"
		}
		# Process the package information
		IF ($XML.Framework.Package -notmatch "^$") {
			IF ($XML.Framework.Package.Change -notmatch "^$") {
				$Package.Change = $XML.Framework.Package.Change
				$LogFilePath = $LogFilePath + $Package.Change + "-"					
			} 
			ELSE {
				$RandomDate = get-date -Format "yyyyMMddHHmmss"
				$Package.Change = $RandomDate
				Write-Warning "No change information was found in the framework, the change number was randomly generated as $($Package.Change)"
				$LogFilePath = $LogFilePath + $Package.Change + "-"
				$Package.PackageName = $RandomDate
				$Package.Version = $Script.version
			}
			IF ($XML.Framework.Package.PackageName -notmatch "^$") {
				$Package.PackageName = $XML.Framework.Package.PackageName
				# Remove Invalid file name characters from package name
				Foreach ($ch in [System.IO.Path]::GetInvalidFileNameChars()) {
					$Package.PackageName = $($Package.PackageName).Replace($ch.ToString(), "")
				}
				$Package.PackageName = $Package.PackageName.Trim()
				$LogFilePath = $LogFilePath + $Package.PackageName + "\"
				$LogFile = $LogFilePath + $env:computername + "." + $Package.Change + ".ps1.log"
			}
			ELSE {
				$Package.PackageName = "none"
				$LogFilePath = $LogFilePath + $Package.PackageName + "\"
				$LogFile = $LogFilePath + $env:computername + "." + $Package.Change + ".ps1.log"				
			}
			# Remove Spaces from log file path
			$LogFile = $LogFile.Replace(" ", "")
			$LogFilePath  = $LogFilePath.Replace(" ", "")
			$CachePath = $LogFilePath.Replace("\logs\","\cache\")
			Write-Verbose $CachePath
			IF (!(Test-Path $LogFilePath)){
				New-Item -itemtype directory -path $LogFilePath -Force > $Null
			}				
			IF ($XML.Framework.Package.Version -notmatch "^$") {$Package.Version = $XML.Framework.Package.Version}
			IF ($XML.Framework.Package.Cache -notmatch "^$") {IF ($XML.Framework.Package.Cache -eq "True"){$Package.Cache = $True} else {$Package.Cache = $False}}
			Write-Verbose "$tab Package Information: `n $tab Change # = $($Package.Change) `n $tab Package Name = $($Package.PackageName) `n $tab Version = $($Package.Version) `n $tab Cache = $($Package.Cache)"
		}
		Else {
			$RandomDate = get-date -Format "yyyyMMddHHmmss"
			$Package.Change = $RandomDate
			$LogFilePath = $LogFilePath + $Package.Change + "\"
			$LogFile = $LogFilePath + $env:computername + "." + $Package.Change + ".ps1.log"
			$EnvInfo.Logging = $True
			Write-Warning "No change information was found in the framework, the change number was randomly generated as $($Package.Change) `nLog File: $LogFile"
			$Package.PackageName = $RandomDate
			$Package.Version = $Script.version
		}
		# Search and replace all items within the XML file
		$XMLText = Get-Content -Path $FrameworkFilePath
		$XMLText| Foreach-Object {
			$_ = $_ -replace "\.\\", "$($Script.Path)\"
			$_ = $_ -replace "\*SYSTEMDRIVE\*", "$($System.InstallationRootFolder)"
			$_ = $_ -replace "\*LDIR\*", "$LogFilePath"
			$_ = $_ -replace "\*CDIR\*", "$CachePath"
			$_ = $_ -replace "\*CHG\*", "$($Package.Change)"
			$_ = $_ -replace "\*WINDIR\*", "$env:windir"
			$_ = $_ -replace "\*PKGDIR\*", "$($Script.Path)"
			$_ = $_ -replace "\*HNAME\*", "$env:computername"
			$_ = $_.Replace("HKEY_LOCAL_MACHINE\", "HKLM:\")
			$_ = $_.Replace("HKLM\", "HKLM:\")
			$_ = $_.Replace("HKEY_CURRENT_CONFIG\", "HKCC:\")
			$_ = $_.Replace("HKCC\", "HKCC:\")
			$_ = $_.Replace("HKEY_CLASSES_ROOT\.", "HKCR:\")
			$_ = $_.Replace("HKCR\", "HKCR:\")
			$_ = $_.Replace("HKEY_CURRENT_USER\", "HKCU:\")
			$_ = $_.Replace("HKCU\", "HKCU:\")
			$_ = $_.Replace("HKEY_USERS\", "HKU:\")
			$_ = $_.Replace("HKU\", "HKU:\")
			$XMLText2 += $_
		}
		Write-Verbose "Finished replacement !!!!!"
		# Update XML File with replaced text
		[XML]$XML = $XMLText2			
		# Find FrameworkOwnerName - start with Branch and work backwards
		IF ($($EnvInfo.Branch) -NotMatch "^$") {$FrameworkOwnerName = $($EnvInfo.Branch)}
		ELSEIF ($($EnvInfo.Division) -NotMatch "^$") {$FrameworkOwnerName = $($EnvInfo.Division)}
		ELSEIF ($($EnvInfo.Agency) -NotMatch "^$") {$FrameworkOwnerName = $($EnvInfo.Agency)}
		ELSEIF ($($EnvInfo.Dept) -NotMatch "^$") {$FrameworkOwnerName = $($EnvInfo.Dept)}
		ELSEIF ($($EnvInfo.Co) -NotMatch "^$") {$FrameworkOwnerName = $($EnvInfo.Co)}
		ELSE {$FrameworkOwnerName = ""}
		
		# Write heading information, system info, package info
		Write-Header -EnvInfo $EnvInfo -Package $Package
		# Check to see IF cache is true and cache package
		IF ($Package.Cache -eq $True) {
			$CachedPackage = Copy-ToCache -CachePath $CachePath
			IF (Test-Path -Path "$($CachedPackage.Location)\PKG") { $Script.Path = $($CachedPackage.Location) + "PKG" ; Set-Location -Path "$($CachedPackage.Location)\PKG" } else {$Script.Path = "$($CachedPackage.Location)" ; Set-Location -Path "$($CachedPackage.Location)"}
			$Parent = $Script.Path |Split-Path
		}
		# Check to see IF the script should check for Admin rights
		$AdminRights = Test-AdminRights -User $Env:Username -NotSilent
		IF ($EnvInfo.doAdminCheck -eq $True) {
			IF ($AdminRights -eq $False) {
				Write-LogandHost "Error:  Running script without administrative rights" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
				Stop-Framework -ExitCodes 8344
			}
		}
	}
	Else {
		Write-Error -Category ObjectNotFound  -Message "Error: $FrameworkFile does not exist, exiting script" -ErrorId 22000
		[System.Environment]::Exit(22000)
	}
	# Determine which task types to run
	IF (!($Repair) -and !($UninstallCurrent) -and !($Uninstall) -and !($Install)) {$TaskTypesToProcess = @("Uninstall","Install")}
	IF (!($Repair) -and !($UninstallCurrent) -and ($Uninstall) -and ($Install)) {$TaskTypesToProcess = @("Uninstall","Install")}
	IF (($Repair) -and !($UninstallCurrent) -and !($Uninstall) -and !($Install)) {$TaskTypesToProcess = @("Repair")}
	IF (!($Repair) -and !($UninstallCurrent) -and !($Uninstall) -and ($Install)) {$TaskTypesToProcess = @("Install") }
	IF (!($Repair) -and !($UninstallCurrent) -and ($Uninstall) -and !($Install)) {$RemoveCache = $True ; $TaskTypesToProcess = @("Uninstall") }
	IF (!($Repair) -and ($UninstallCurrent) -and !($Uninstall) -and !($Install)) {$RemoveCache = $True ; $TaskTypesToProcess = @("Uninstall") ; $Current = $True}
	IF (($Repair) -and !($UninstallCurrent) -and !($Uninstall) -and ($Install)) {$TaskTypesToProcess = @("Install","Repair")}
	IF (($Repair) -and !($UninstallCurrent) -and ($Uninstall) -and ($Install)) {$TaskTypesToProcess = @("Uninstall","Install","Repair")}
}
Process {
	Write-LogandHost "******************** PROCESSING TASKS **********************************" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
	$XMLTaskCount = $XML.Framework.Tasks.Task.Count
	IF ([String]::IsNullOrWhiteSpace($XMLTaskCount)) {$XMLTaskCount = 1}
	Write-LogandHost "Tasks in XML File to be processed, $XMLTaskCount" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
	IF ($ContinueAtTask -gt $XMLTaskCount) {
		Write-LogandHost "Error: The task specified, $ContinueAtTask, is greater than the number of tasks in the Framework file, the script will exit" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
		Write-Error "Error: The task specified, $ContinueAtTask, is greater than the number of tasks in the Framework file, the script will exit"  -Category InvalidArgument -ErrorId 26004
		[System.Environment]::Exit(26004)
	}
	IF ($ContinueAtTask -gt 0) {Write-LogandHost "Processing starting from task number $ContinueAtTask" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
	:Taskloop Foreach ($Task in $XML.Framework.Tasks.Task){
		$TasksProcessed++
		IF (($ContinueAtTask -eq $TasksProcessed) -OR ($ContinueAtTask -eq 0)){
			IF (($ContinueAtTask -ne 0) -AND ($Scheduled)) {
				Write-LogandHost "Pausing Install Framework for $PauseFor seconds before continuing" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
				Start-Sleep -s $PauseFor
				$CleanUpScheduledTasks = $True
			}
			### Create Initial Task Result Object
			$TaskResult = [PSCustomObject]@{
				"Host" = $env:Computername ; "TaskName" = "Task ($TasksProcessed): $($Task.Name)" ; "ExitCode" = $null
				"Id" = "none" ; "StartTime" = Get-Date -Format "MM/dd/yyyy HH:mm:ss" ; "ExitTime" = $null  ; "OutPut" = $null
				"RunspaceId" = $null ; "Success" = "Not Started"
			}
			### See IF the requested task type matches the task being processed
			IF ([String]::IsNullOrWhiteSpace($($Task.Tasktype))) {$Task | Add-Member -MemberType NoteProperty -Name "TaskType" -Value "Install" -Force}
			IF ($TaskTypesToProcess -Contains $Task.Tasktype){
				Write-LogandHost "Task ($TasksProcessed): $($Task.Name) is being processed" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Cyan
				### Check System type, server (S) or workstation (W)	
				IF ($Task.SystemType -Match "^$"){
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): No Product Type specified, this will run on the current host" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSEIF (($Task.SystemType -match $System.SystemType) -or ($Task.SystemType -eq "B")) {
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): Valid Product Type specified, $($Task.SystemType) this will run on current host" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): $($Task.Name) is being skipped, Product Type: $($Task.SystemType) is a requirement." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
					$SkipCount++
					$ContinueAtTask = 0
					Continue
				}
				### Check Host type, Physical (P) or Virtual (V)
				IF ($Task.HostType -Match "^$"){
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): No Host Type specified, this will run on the current host" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSEIF ($Task.HostType -match $System.HostType) {
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): Valid Host Type specified, $($Task.HostType) this will run on current host" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): $($Task.Name) is being skipped, Host Type: $($Task.HostType) is a requirement." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
					$SkipCount++
					$ContinueAtTask = 0
					Continue
				}	
				### Check the Operating System (OS)
				IF ($Task.OperatingSystem -Match "^$"){
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): No Operating system specified, this will run on the current host" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSEIF (Compare-OS -OperatingSystems $($Task.OperatingSystem)){
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): The OS matches, this will run on the current host" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): $($Task.Name) is being skipped,  OS $($Task.OperatingSystem) is a requirement, the task will not run" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
					$SkipCount++
					$ContinueAtTask = 0
					Continue
				}
				### Check the Processor Architecture to see IF the system is 32 or 64-bit
				IF ($Task.Architecture -Match "^$"){
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): No System Architecture specified, this will run on the current host" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
					IF ([String]::IsNullOrEmpty($($Task.Architecture))) {
						$Task | Add-Member -MemberType NoteProperty -Name "Architecture" -Value "B"
					}
					ELSE {
						$Task.Architecture = "B"
					}
				}
				ELSEIF (($Task.Architecture -match $System.SystemArch) -or ($Task.Architecture -eq "B")) {
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): Valid System Architecture specified, $($Task.Architecture) this will run on current host" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): $($Task.Name) is being skipped, System Architecture: $($Task.Architecture) is a requirement." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
					$SkipCount++
					$ContinueAtTask = 0
					Continue
				}
				### Check If the framework calls for postponing after the task is finished
				IF ($Task.Postpone -Match "^$"){
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): No Postpone specified, this will not Postpone the framework tasks after the current task" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSEIF ($Task.Postpone -Match "true"){
					Write-LogandHost "Task ($TasksProcessed): Postpone is True, this will Postpone the framework tasks after the current task" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					IF ($Task.PauseFor  -Match "^$") {
						IF ($vl) {Write-LogandHost "Task ($TasksProcessed): No Pause after postponing framework task specified, it will default to $PauseFor" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
						$Task | Add-Member -MemberType NoteProperty -Name "PauseFor" -Value $PauseFor
					}
					ELSE {
						IF ($vl) {Write-LogandHost "Task ($TasksProcessed): Pause after postponing framework tasks: $($Task.PauseFor)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
					}					
					# Schedule the task to run during startup after the Postponing the framework tasks
					IF (Schtasks /Query /FO csv | ConvertFrom-CSV | Where-Object {$_.TaskName -Match $Package.PackageName}) {
						Schtasks /delete /TN $Package.PackageName /F > $null 2>&1
					}
					$TaskToRunNext = $TasksProcessed + 1
					IF ($TaskToRunNext -gt $XMLTaskCount) {
						Write-LogandHost "Task ($TasksProcessed): This is the last task, no tasks will be scheduled after the Postponing the framework tasks" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
					}
					ELSE {
						IF ($Package.Cache -eq $False) {
							#Cache package
							$CachedPackage = Copy-ToCache -CachePath $CachePath
							IF (Test-Path -Path "$($CachedPackage.Location)\PKG") { $Script.Path = $($CachedPackage.Location) + "PKG" ; Set-Location -Path "$($CachedPackage.Location)\PKG" } else {$Script.Path = "$($CachedPackage.Location)" ; Set-Location -Path "$($CachedPackage.Location)"}
							$Parent = $Script.Path |Split-Path
						}
						IF ($AdminRights -eq $False) {
							$ShortcutPath = $System.Startup + "\Install.cmd.lnk"
							$ShortCutArguments = " -ContinueAtTask $TaskToRunNext -Scheduled -PauseFor $($Task.PauseFor)"
							New-Shortcut -ShortCutPath $ShortcutPath -TargetPath "$Parent\Install.cmd" -ShortCutArguments $ShortCutArguments
							Write-LogandHost "Task ($TasksProcessed): Scheduled next task, # $TaskToRunNext , will run during $Env:Username's startup after the postponing the framework taks with a command line of $Parent\Install.cmd"  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
						}
						ELSE {
							Schtasks /create /RU "NT AUTHORITY\SYSTEM" /SC ONSTART /TN $Package.PackageName /TR "$Parent\Install.cmd -ContinueAtTask $TaskToRunNext -Scheduled -PauseFor $($Task.PauseFor)" > $null 2>&1
							Write-LogandHost "Task ($TasksProcessed): Scheduled Task # $TaskToRunNext to run after the postponing the framework tasks with a command line of $Parent\Install.cmd"  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
						}
					}

				}
				ELSEIF ($Task.Postpone -Match "false"){
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): Postpone is false, this will not Postpone the framework tasks after the current task" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSE{
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): This will not Postpone the framework tasks after the current task" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				### Check IF the framework calls for a reboot after the task is finished
				IF ($Task.Reboot -Match "^$"){
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): No Reboot specified, this will not reboot the system after the current task" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSEIF ($Task.Reboot -Match "true"){
					Write-LogandHost "Task ($TasksProcessed): Reboot is True, this will reboot the system after the current task" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					IF ($Task.RebootTimer  -Match "^$") {
						IF ($vl) {Write-LogandHost "Task ($TasksProcessed): No Reboot time out specified, it will default to $($Script.DefaultTimeOut)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
						$Task | Add-Member -MemberType NoteProperty -Name "PauseFor" -Value $($Script.DefaultTimeOut)
					}
					ELSE {
						IF ($vl) {Write-LogandHost "Task ($TasksProcessed): Reboot time out specified, $($Task.RebootTimer)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
					}
					IF ($Task.PauseFor  -Match "^$") {
						IF ($vl) {Write-LogandHost "Task ($TasksProcessed): No Pause after reboot time out specified, it will default to $PauseFor" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
						$Task | Add-Member -MemberType NoteProperty -Name "PauseFor" -Value $PauseFor
					}
					ELSE {
						IF ($vl) {Write-LogandHost "Task ($TasksProcessed): Pause after reboot: $($Task.PauseFor)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
					}
					# Schedule the task to run during startup after the reboot
					IF (Schtasks /Query /FO csv | ConvertFrom-CSV | Where-Object {$_.TaskName -Match $Package.PackageName}) {
						Schtasks /delete /TN $Package.PackageName /F > $null 2>&1
					}
					$TaskToRunNext = $TasksProcessed + 1
					IF ($TaskToRunNext -gt $XMLTaskCount) {
						Write-LogandHost "Task ($TasksProcessed): This is the last task, no tasks will be scheduled after the reboot" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
					}
					ELSE {
						IF ($Package.Cache -eq $False) {
							#Cache package
							$CachedPackage = Copy-ToCache -CachePath $CachePath
							IF (Test-Path -Path "$($CachedPackage.Location)\PKG") { $Script.Path = $($CachedPackage.Location) + "PKG" ; Set-Location -Path "$($CachedPackage.Location)\PKG" } else {$Script.Path = "$($CachedPackage.Location)" ; Set-Location -Path "$($CachedPackage.Location)"}
							$Parent = $Script.Path |Split-Path
						}
						IF ($AdminRights -eq $False) {
							$ShortcutPath = $System.Startup + "\Install.cmd.lnk"
							$ShortCutArguments = " -ContinueAtTask $TaskToRunNext -Scheduled -PauseFor $($Task.PauseFor)"
							New-Shortcut -ShortCutPath $ShortcutPath -TargetPath "$Parent\Install.cmd" -ShortCutArguments $ShortCutArguments
							Write-LogandHost "Task ($TasksProcessed): Next task, # $TaskToRunNext ,will run during $Env:Username's startup after the reboot with a command line of $Parent\Install.cmd"  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
						}
						ELSE {
							Schtasks /create /RU "NT AUTHORITY\SYSTEM" /SC ONSTART /TN $Package.PackageName /TR "$Parent\Install.cmd -ContinueAtTask $TaskToRunNext -Scheduled -PauseFor $($Task.PauseFor)" > $null 2>&1
							Write-LogandHost "Task ($TasksProcessed): Scheduled Task # $TaskToRunNext to run after the reboot with a command line of $Parent\Install.cmd"  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
						}
					}

				}
				ELSEIF ($Task.Reboot -Match "false"){
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): Reboot is false, this will not reboot the system after the current task" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSE{
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): This will not reboot the system after the current task" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				### Check for ShowProgress, True or False
				IF ($Task.ShowProgress -Match "^$"){
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): Show Progress was not specified, no execution progress will be shown" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
					$Task | Add-Member -MemberType NoteProperty -Name "ShowProgress" -Value "False"
				}
				ELSEIF ($Task.ShowProgress -match "True") {
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): Execution Progress will be shown" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): Show Progress was not specified, no execution progress will be shown" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					$Task | Add-Member -MemberType NoteProperty -Name "ShowProgress" -Value "False"
				}
				### Check to see if the task will run interactively
				IF ($Task.Interactive -Match "^$"){
					$Task | Add-Member -MemberType NoteProperty -Name "Interactive" -Value "False"
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): Interactive was not specified, this will run as a background job" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSEIF ($Task.Interactive -eq "True"){
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): The current task will run interactively with the user, $env:username" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSEIF ($Task.Interactive -eq "False"){
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): The current task will run as a background job" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSE {
					$Task | Add-Member -MemberType NoteProperty -Name "Interactive" -Value "False"
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): Defaulting to the current task running as a background job" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				### Check the validations
				$BadValidation = $False
				$ValidationNumber = 0
				IF ($Task.Validation -Match "^$"){
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): No Validations specified, the task will run on the current host" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)}
				}
				ELSE {
					$ValidationCount = $Task.Validation.Count
					$ValidationCount++
					IF ($vl) {Write-LogandHost "Task ($TasksProcessed): Validation Count: $ValidationCount" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) }
					:Validationloop Foreach ($Validation in $Task.Validation){
						$ValidationNumber++
						$Switch = $true
						$ValidationItems.Type = $Validation.Type
						$ValidationItems.RequestedResult = $Validation.Switch
						$ValidationSwitch = $Validation.Switch.ToString()
						IF ($ValidationSwitch -eq "true") {$ValidationSwitch = $True} 
						ELSEIF ($ValidationSwitch -eq "false") {$ValidationSwitch = $False} 
						ELSE {$ValidationSwitch = $False}
						Write-LogandHost "Task ($TasksProcessed): Validation ($ValidationNumber): Validating $($Validation.Type), $($Validation.InnerText) to be $ValidationSwitch" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
						# Check the validation types
						Switch ($Validation.Type) {
							"^$" { IF ($vl) {Write-LogandHost "Task ($TasksProcessed): Validation ($ValidationNumber): No Validation Type specified, the task will run on the current host" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)} }
							"directory" {IF (Find-Path $Validation.InnerText -Switch $ValidationSwitch){ } ELSE {$BadValidation = $True ; Break}}
							"file" {IF (Find-Path $Validation.InnerText -Switch $ValidationSwitch){ } ELSE {$BadValidation = $True ; Break }} 
							"registry key" {IF (Find-Path $Validation.InnerText -Switch $ValidationSwitch){ } ELSE {$BadValidation = $True ; Break }}
							"fileversion" { IF (Find-FileVersion $Validation.InnerText -Switch $ValidationSwitch) {} ELSE {$BadValidation = $True ; BREAK}}
							"freespace" { IF ((Compare-LocalDiskSpace $Validation.InnerText) -eq $ValidationSwitch) {} ELSE {$BadValidation = $True ; Break } }
							"GUID" { IF ((Find-GUID -GUIDS $Validation.InnerText) -eq $ValidationSwitch) {} ELSE {$BadValidation = $True ; BREAK } }
							"PROCESS" { IF ((Find-Process $Validation.InnerText) -eq $ValidationSwitch) {} ELSE {$BadValidation = $True ; BREAK } }
							"OU" { IF ((Find-OU -OU $Validation.InnerText) -eq $ValidationSwitch) {} ELSE {$BadValidation = $True ; BREAK } }
							"REGISTRY VALUE" { IF ((Find-RegistryValue -Value $Validation.InnerText) -eq $ValidationSwitch) {} ELSE {$BadValidation = $True ; BREAK }}
							"SERVICESTATE" { IF ((Find-ServiceState -Service $Validation.InnerText) -eq $ValidationSwitch) {} ELSE {$BadValidation = $True ; Break } }
							"MemberOf" { IF ((Find-ADGroupMembership -GroupName $Validation.InnerText) -eq $ValidationSwitch) {} ELSE {$BadValidation = $True ; Break } }
							"BlockedHost" { IF ((Test-Host -ComputerName $Validation.InnerText) -eq $ValidationSwitch) {} ELSE {$BadValidation = $True ; Break } }
							"Checksum" { IF ((Compare-Checksum -CheckSumInfo $Validation.InnerText) -eq $ValidationSwitch) {} ELSE {$BadValidation = $True ; Break } }
							"PendingReboot" { IF ((Test-PendingReboot).IsRebootPending -eq $ValidationSwitch) {$BadValidation = $True ; Break} ELSE { } }
							"PATCH" {IF (Find-Patch $Validation.InnerText -Switch $ValidationSwitch){ } ELSE {$BadValidation = $True ; Break }}
							"SCRIPT" {
								IF ((Start-Script $Validation.InnerText -Switch $ValidationSwitch) -Match $ValidationSwitch) {
									Write-Verbose "$($Validation.InnerText) is $ValidationSwitch"
								} 
								ELSE {
									$BadValidation = $True ; Break }
							} 
							Default { Write-LogandHost "Task ($TasksProcessed): Validation ($ValidationNumber): A valid validation type was not specified, type specified: $($Validation.Type)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow }
						}
					}
				}
				IF ($BadValidation -eq $True ) { 
					Write-Verbose "Got to Badvalidation Check true" ; 
					$SkipCount++
					IF (!($ExitCodeOut)) {
						$TaskResult.ExitCode = 0
						$TaskResult.ExitTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
						$TaskResult.Success = "Skipped"
						Write-OutPut $TaskResult
					}
					$ContinueAtTask = 0
					CONTINUE 
				} ELSE {Write-Verbose "Got to Badvalidation Check false"}
				### Check IF Kill Processes exist and kill the specified processes
				IF ($Task.KillProcess -NotMatch "^$"){
					Write-LogandHost "Task ($TasksProcessed): Process(es) to be killed $($Task.KillProcess)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					$ProcessToKill = $Task.KillProcess.Split("|")
					$ProcessToKill|Stop-Item
				}
				### Check If Remove exist and delete the specified items if they exist
				IF ($Task.Remove -NotMatch "^$"){
					Write-LogandHost "Task ($TasksProcessed): Item(s) to be removed $($Task.Remove)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					$($Task.Remove)|Remove-Item2
				}
				### Check if copy jobs exist and copy items to their specified locations
				$CopyJobNum = 0
				$CopyLoopsAllowed = 3
				$CopyLoopsProcessed = 0
				$BadCopy = $False
				IF ($Task.CopyJobs -NotMatch "^$"){
					$CopyCount = $Task.CopyJobs.CopyJob.Count
					If ($CopyCount -eq $null){$CopyCount = 1}
					Write-LogandHost "Task ($TasksProcessed): $CopyCount Copy jobs to process..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					$BadCopy = Copy-Item2 -CopyJobs $Task.CopyJobs
				}
				IF ($BadCopy -eq $True) {
					Write-LogandHost "Task ($TasksProcessed): $($Task.Name) is being skipped, failed to copy file"  -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
					$SkipCount++
					IF (!($ExitCodeOut)) {
						$TaskResult.ExitCode = 0
						$TaskResult.ExitTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
						$TaskResult.Success = "Skipped"
						Write-OutPut $TaskResult
					}
					$ContinueAtTask = 0
					CONTINUE
				}
				IF ($Task.Executable -NotMatch "^$"){
					Write-LogandHost "Task ($TasksProcessed): Executing: $($Task.Executable)..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					IF ($Task.Arguments  -NotMatch "^$") {
						Write-LogandHost "Task ($TasksProcessed): with arguments: $($Task.Arguments)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					} 
					ELSE {[String]::IsNullOrEmpty($($Task.Arguments))}
					# Add in extra success codes for the item being executed
					$SuccessCodes = @()
					IF ($Task.SuccessCodes -NotMatch "^$") {
						$TempSuccessCodes = ($Task.SuccessCodes.Split("|")).Trim()
						$SuccessCodes += $Script.DefaultSuccessCodes
						$SuccessCodes += $TempSuccessCodes
					}
					ELSE {
						$SuccessCodes += $Script.DefaultSuccessCodes
					}
					Write-Verbose "Task ($TasksProcessed): Valid Success Codes: $SuccessCodes"
					# Check to see IF the executable should wait for an item / amount of time
					IF ($Task.Wait -NotMatch "^$") {
						$WaitItems.Switch = $Task.Wait.Switch
						$WaitItems.Type = $Task.Wait.Type
						$WaitItems.Timeout = $Task.Wait.Timeout
						$WaitItems.Item = $Task.Wait.InnerText
						
						# Get Wait time out value
						Write-Verbose "$tab Wait Information: `n $tab Wait Switch = $($WaitItems.Switch) `n $tab Wait Type = $($WaitItems.Type) `n $tab Wait Timeout = $($WaitItems.Timeout) `n $tab Wait InnerText = $($WaitItems.Item)"
						
						IF ($WaitItems.Timeout -NotMatch "^$") {
							$WaitItems.Timeout = $WaitItems.Timeout.ToString()
						}
						ELSE {
							$WaitItems.Timeout = $Script.DefaultTimeOut
						}
						# Check Wait Switch
						IF ($WaitItems.Switch -NotMatch "^$") {
							IF ($WaitItems.Switch -eq "true") {$WaitItems.Switch = $True} else {$WaitItems.Switch = $False}
						}
						ELSE {
							$WaitItems.Switch = $True
						}
						#Check Wait Inner Text
						IF ($Task.Wait.InnerText  -NotMatch "^$") { } ELSE { $Task.Wait.InnerText = $null }
						IF ($Task.Wait.Type -NotMatch "^$"){ } ELSE { $Task.Wait.Type = "" }
						$InvokeCommandLine = @{ 
							"Executable" = $Task.Executable ; "TaskName" = "Task ($TasksProcessed): $($Task.Name)" ; "Arguments" = $Task.Arguments
							"WaitTimeOut" = $WaitItems.Timeout ; "WaitType" = $WaitItems.Type ; "WaitSwitch" = $WaitItems.Switch
							"WaitItem" = $WaitItems.Item ; "JobCount" = 3 ; "ScriptPath" = $($Script.Path) ; "ShowProgress" = "$($Task.ShowProgress)"
						}
					} 
					ELSE {
						$InvokeCommandLine = @{ 
							"Executable" = $Task.Executable ; "TaskName" = "Task ($TasksProcessed): $($Task.Name)" ; "Arguments" = $Task.Arguments
							"WaitTimeOut" = $null ; "WaitType" = $null ; "WaitSwitch" = $null ; "WaitItem" = $null
							"JobCount" = 3 ; "ScriptPath" = $($Script.Path) ; "ShowProgress" = "$($Task.ShowProgress)" ; "Interactive" = $Task.Interactive
						}
					}
					$TaskResult.Success = "Unknown"
					$TaskResult = Invoke-Task @InvokeCommandLine
					IF ([String]::IsNullOrWhiteSpace($TaskResult.ExitCode)) {
						$TaskResult.ExitCode = 0
						$TaskResult.ExitTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
						$TaskResult.Success = $True
					}
					# $TaskResult | Add-Member -MemberType NoteProperty -Name "TaskName" -Value $Task.Name
					Write-LogandHost "Task ($TasksProcessed): Result Code: $($TaskResult.ExitCode)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
					$ExitCode = ($TaskResult.ExitCode).ToString()
					IF (Compare-SuccessCode -SplitCodes $SuccessCodes -ExitCode $ExitCode) {
						$SuccessCount++
						Write-LogandHost  "Task ($TasksProcessed): $($Task.Name) completed successfully with exit code: $($TaskResult.ExitCode)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Green
						$TaskResult | Add-Member -MemberType NoteProperty -Name "Success" -Value $True -Force
						IF (!($ExitCodeOut)) {Write-OutPut $TaskResult}
						$AllTaskResults += $TaskResult
						$ExitCodes += $AllTaskResults.ExitCode
						IF ($Task.Reboot -Match "true") {
							$ExitCodes += 1641
							Stop-Framework -ExitCodes $ExitCodes
							Break
						}
						IF ($Task.Postpone -Match "true") { Stop-Framework -ExitCodes $ExitCodes ; Break }
					}
					ELSE {
						$FailedCount++
						Write-LogandHost  "Task ($TasksProcessed): $($Task.Name) failed with exit code: $($TaskResult.ExitCode)" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Red
						$TaskResult | Add-Member -MemberType NoteProperty -Name "Success" -Value $False -Force
						IF (!($ExitCodeOut)) {Write-OutPut $TaskResult}
						$AllTaskResults += $TaskResult
						$ExitCodes = $($TaskResult.ExitCode)
						Break
					}
				}
				ELSEIF ($Task.Name -Match "ProcessUninstallStrings") {
					IF (!($ExitCodeOut)) {
						$UninstallStringsTasks += Start-UninstallString -Path "$($Script.Path)\Uninstallstrings.txt" -TasksProcessed $TasksProcessed -Taskname $($Task.Name) -ScriptPath "$($Script.Path)\" -Interactive $($Task.Interactive)
						IF ($UninstallStringsTasks.ExitCode -eq 2) { $SkipCount++ } ELSE { $SuccessCount++ }
						$AllTaskResults += $UninstallStringsTasks
						Write-Output $UninstallStringsTasks
						$ExitCodes += $UninstallStringsTasks.ExitCode
					}
					ELSE {
						$UninstallStringsTasks += Start-UninstallString -Path "$($Script.Path)\Uninstallstrings.txt" -TasksProcessed $TasksProcessed -Taskname $($Task.Name) -ScriptPath "$($Script.Path)\" -ExitCodeOut -Interactive $($Task.Interactive)
						IF ($UninstallStringsTasks.ExitCode -eq 2) { $SkipCount++ } ELSE { $SuccessCount++ }
						$AllTaskResults += $UninstallStringsTasks
						$ExitCodes += $UninstallStringsTasks.ExitCode
					}
				}
				ELSEIF ($Task.Name -Match "UninstallAll") {
					$SuccessCodes = @()
					$UninstallAllTasks = @()
					IF ($Task.SuccessCodes -NotMatch "^$") {
						$TempSuccessCodes = ($Task.SuccessCodes.Split("|")).Trim()
						$SuccessCodes += $Script.DefaultSuccessCodes
						$SuccessCodes += $TempSuccessCodes
					}
					ELSE {
						$SuccessCodes += $Script.DefaultSuccessCodes
					}
					IF ($Task.Interactive -NotMatch "^$") {
						$Interactive = $($Task.Interactive)
					}
					ELSE {
						$Interactive = "False"
					}
					Write-Verbose "In uninstall all, Interactive = $Interactive"
					IF ($Task.ArchitectureOfApplication -NotMatch "^$") {
						$ArchitectureOfApplication = $($Task.ArchitectureOfApplication)
					}
					ELSE {
						$ArchitectureOfApplication = "B"
					}
					IF ($Task.DisplayNameLike -NotMatch "^$"){
						IF ($Task.ItemsToExclude -NotMatch "^$"){
							IF (!($ExitCodeOut)) {
								$UninstallAllTasks += Start-UninstallAll -DisplayNameLike $($Task.DisplayNameLike) -ItemsToExclude $($Task.ItemsToExclude) -Architecture $ArchitectureOfApplication -SuccessCodes $SuccessCodes -TasksProcessed $TasksProcessed -Taskname $($Task.Name) -Interactive $Interactive -ScriptPath "$($Script.Path)\"
								IF ($UninstallAllTasks.Success -Contains "True") {$ExitCodes += 0 ; $SuccessCount++} ELSE {$ExitCodes += 26005}
								$AllTaskResults += $UninstallAllTasks
								Write-Output $UninstallAllTasks
							}
							ELSE {
								$UninstallAllTasks += Start-UninstallAll -DisplayNameLike $Task.DisplayNameLike -ItemsToExclude $Task.ItemsToExclude -Architecture $ArchitectureOfApplication -SuccessCodes $SuccessCodes -TasksProcessed $TasksProcessed -Taskname $($Task.Name) -Interactive $Interactive -ScriptPath "$($Script.Path)\" -ExitCodeOut
								IF ($UninstallAllTasks.Success -Contains "True") {$ExitCodes += 0 ; $SuccessCount++} ELSE {$ExitCodes += 26005}
							}
						}
						ELSE {
							IF (!($ExitCodeOut)) {
								$UninstallAllTasks += Start-UninstallAll -DisplayNameLike $Task.DisplayNameLike  -Architecture $ArchitectureOfApplication -SuccessCodes $SuccessCodes -TasksProcessed $TasksProcessed -Taskname $($Task.Name) -Interactive $Interactive
								IF ($UninstallAllTasks.Success -NotContains "True") {$ExitCodes += 0 ; $SuccessCount++} ELSE {$ExitCodes += 26005}
								$AllTaskResults += $UninstallAllTasks
								Write-Output $UninstallAllTasks
							}
							ELSE {
								$UninstallAllTasks += Start-UninstallAll -DisplayNameLike $Task.DisplayNameLike -Architecture $ArchitectureOfApplication -SuccessCodes $SuccessCodes -TasksProcessed $TasksProcessed -Taskname $($Task.Name) -Interactive $Interactive -ExitCodeOut
								IF ($UninstallAllTasks.Success -NotContains "False") {$ExitCodes += 0 ; $SuccessCount++} ELSE {$ExitCodes += 26005}
							}
						}
					}
					ELSE {
						Write-LogandHost "Task ($TasksProcessed): $($Task.Name) is being skipped, a DisplayNameLike is a requirement." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
						$SkipCount++
						$ContinueAtTask = 0
						Continue
					}
				}
				ELSE {
					Write-LogandHost "Task ($TasksProcessed): $($Task.Name) is being skipped" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
					IF (!($ExitCodeOut)) {
						$TaskResult.ExitCode = 0
						$TaskResult.ExitTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
						$TaskResult.Success = "Skipped"
						Write-OutPut $TaskResult
					}
					$SkipCount++
					$ContinueAtTask = 0
					Continue
				}
			}
			ELSE {
				Write-LogandHost "Task ($TasksProcessed): $($Task.Name) is a $($Task.Tasktype), which was not the requested task type, the task will be skipped" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Yellow
				$SkipCount++
				IF (!($ExitCodeOut)) {
					$TaskResult.ExitCode = 0
					$TaskResult.ExitTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
					$TaskResult.Success = "Skipped"
					$ExitCodes += 0
					Write-OutPut $TaskResult
				}
				ELSE {
					$TaskResult.ExitCode = 0
					$TaskResult.ExitTime = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
					$TaskResult.Success = "Skipped"
					$ExitCodes += 	0			
				}
			}
			$ContinueAtTask = 0
		}
		ELSE {
			# Continue looping until the task requested by the TaskNumber switch is being processed
			Continue
		}
	}
	# Add Registry Change information
	IF (($SuccessCount -gt 0) -AND ($TaskTypesToProcess -Contains "Install")) {
		#Record change information in Registry
		Add-ChangeInformation -Co $($EnvInfo.Co) -Dept $($EnvInfo.Dept) -Agency $($EnvInfo.Agency) -Division $($EnvInfo.Division) -Branch $($EnvInfo.Branch) -Change $($Package.Change) -PackageName $($Package.PackageName) -Version $($Package.Version)
	}
	# Remove Registry Change information
	IF ($RemoveCache -eq $True){
		#Remove change information from Registy
		Remove-ChangeInformation -Co $($EnvInfo.Co) -Dept $($EnvInfo.Dept) -Agency $($EnvInfo.Agency) -Division $($EnvInfo.Division) -Branch $($EnvInfo.Branch) -Change $($Package.Change)
		IF ($Package.Cache -eq $True) {
			Remove-Cache -CachePath $CachePath
		}
	}
	IF (($TaskTypesToProcess -NotContains "Repair") -AND (($Task.Reboot -Match "^$") -OR ($Task.Reboot -Match "false"))) {
		$Cleanup = $($XML.Framework.Cleanup)
		IF ($Cleanup -Match "^$"){ 
			# Nothing in Cleanup
			Write-LogandHost "Info: No cleanup items specified" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
		}
		ELSE {
			Write-LogandHost "******************* CLEANUP ********************************************" -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging)
			Write-LogandHost "Info: Beginning cleanup of items..." -logfile $LogFile -DisplayOutput $($EnvInfo.DisplayOutput) -LogOutput $($EnvInfo.Logging) -Color Cyan
			$Cleanup|Remove-Item2
		}
	}
}
End {
	# Clean up old scheduled tasks / startup folder shortcuts
	IF ($CleanUpScheduledTasks) {
		Write-Verbose "Clean up scheduled tasks is true"
		IF (Schtasks /Query /FO csv | ConvertFrom-CSV | Where-Object {$_.TaskName -Match $Package.PackageName}) {
			Schtasks /delete /TN $Package.PackageName /F > $null 2>&1
		}
		$ShortcutPath = $System.Startup + "\Install.cmd.lnk"
		IF (Test-Path $ShortcutPath) { $ShortcutPath|Remove-Item2 }
	}	
	Stop-Framework -ExitCodes $ExitCodes
}
}