<#
.DESCRIPTION
    Nexthink Remote Action script to report on the status of the Teams Meeting Add-in. Run as the logged in user.
#>

#==========================================================================#
# Script parameters                                                        #
#==========================================================================#

Param()

#==========================================================================#
# NxtSession                                                               #
#==========================================================================#

Function Test-IsSystemAccount {
    [CmdletBinding()]
    Param ()
    # Check if the current user context is running as the system account
    Return ([Security.Principal.WindowsIdentity]::GetCurrent().Name -eq "NT AUTHORITY\SYSTEM")
}

Function Open-NxtSession {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [string]$LogName
    )
    # Initalise logging
    $VerbosePreference = "Continue"; $InformationPreference = "Continue"
    $IsSystemAccount = Test-IsSystemAccount
    Switch ($IsSystemAccount) {
        $true {
            Start-Transcript -Path "$env:ProgramData\Nexthink\RemoteActions\Logs\$LogName.log" -Force | Out-Null
        }
        $false {
            Start-Transcript -Path "$env:LOCALAPPDATA\Nexthink\RemoteActions\Logs\$LogName.log" -Force | Out-Null
        }
    }
    # Import Nexthink DLLs
    Get-ChildItem -Path "$env:NEXTHINK\RemoteActions" -Filter "*.dll" | Foreach-Object {
        Try {
            Add-Type -Path $_.FullName -ErrorAction Stop
        } Catch {
            Write-Warning -Message "Failed to load assembly: $($_.Name). Error: $($_.Exception.Message)"
        }
    }
    # Default error handler for any unhandled exceptions to return the error to Nexthink
    Trap {
        $Host.UI.WriteErrorLine($_.ToString())
        Exit 1
    }
    # Create Nexthink hashtable for tracking script success or failure
    Return @{
        'ExitCode' = '-'
        'Message' = '-'
    }
}

Function Close-NxtSession {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$NxtSession
    )
    # Stop transcript
    Stop-Transcript | Out-Null
    # Return the Nexthink script status and exit code back to Nexthink
    $Host.UI.WriteErrorLine($NxtSession['Message'])
    Exit $NxtSession['ExitCode']
}

#==========================================================================#
# Main                                                                     #
#==========================================================================#

# Start the Nexthink session and create nxtSession object
$nxtSession = Open-NxtSession -LogName "Get-TeamsMeetingAddinStatus"

# Search for MSTeams and output the installation location
$MSTeams = Get-AppxPackage -Name "MSTeams" -ErrorAction SilentlyContinue
If ($MSTeams) {
    # Write to log
    Write-Output "- MSTeamsInstallationLocation: $($MSTeams.InstallLocation)"
    Write-Output "- MSTeamsVersion: $($MSTeams.Version)"
    # Write to Nexthink data layer
    [Nxt]::WriteOutputString("MSTeamsInstallLocation", $MSTeams.InstallLocation)
    [Nxt]::WriteOutputString("MSTeamsVersion", $MSTeams.Version)
}

# Search for the Teams Meeting Add-in Uninstall key and output the installation location
$TMA = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall' | Get-ItemProperty | Where-Object {$_.DisplayName -eq 'Microsoft Teams Meeting Add-in for Microsoft Office'}
If ($TMA) {
    # Write to log
    Write-Output "- TMAInstallLocation: $($TMA.InstallSource)"
    Write-Output "- TMAVersion: $($TMA.DisplayVersion)"
    # Write to Nexthink data layer
    [Nxt]::WriteOutputString("TMAInstallLocation", $TMA.InstallSource)
    [Nxt]::WriteOutputString("TMAVersion", $TMA.DisplayVersion)
}

# Search for the Teams Meeting Add-in InstallProperties key to find out the local package and installed the application
Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData' | Foreach-Object {
    $User = $_.PSChildName
    $TMAInstallProperties = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\$User\Products\*\InstallProperties" -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object {$_.DisplayName -eq 'Microsoft Teams Meeting Add-in for Microsoft Office'}
    If ($TMAInstallProperties) {
        # Convert the username from the SID format to the domain\username format
        Try {
            $Username = (New-Object System.Security.Principal.SecurityIdentifier($User)).Translate([System.Security.Principal.NTAccount]).Value
        } Catch {
            $Username = "Could not resolve username from SID"
        }
        # Test if the local package path exists
        $LocalPackageExists = Test-Path -Path $TMAInstallProperties.LocalPackage -PathType Leaf
        # Write to log
        Write-Output "- TMAInstalledBy: $Username"
        Write-Output "- TMAInstalledBySID: $User"
        Write-Output "- TMALocalPackage: $($TMAInstallProperties.LocalPackage)"
        Write-Output "- TMALocalPackageExists: $LocalPackageExists"
        # Write to Nexthink data layer
        [Nxt]::WriteOutputString("TMAInstalledBy", $Username)
        [Nxt]::WriteOutputString("TMAInstalledBySID", $User)
        [Nxt]::WriteOutputString("TMALocalPackage", $TMAInstallProperties.LocalPackage)
        [Nxt]::WriteOutputBool("TMALocalPackageExists", $LocalPackageExists)
    }
}

# Map the add-in load behaviour values to a human readable format
$LoadBehaviourMap = @{
    0 = "Do not load automatically"
    1 = "Load on demand"
    2 = "Load at first use"
    3 = "Load at startup"
}

# Search for the Teams Meeting Add-in load behaviour in HKCU and HKLM hives and output the value
$Addins = Get-ChildItem -Path 'HKCU:\SOFTWARE\Microsoft\Office\Outlook\Addins','HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins' -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object {$_.FriendlyName -eq 'Microsoft Teams Meeting Add-in for Microsoft Office'}
If ($Addins) {
    Foreach ($Key in $Addins) {
        Switch -Wildcard ($Key.PSPath) {
            "Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER*" {
                # Write to log
                Write-Output "- TMAUserLoadBehaviour: $($LoadBehaviourMap[[int]$Key.LoadBehavior])"
                # Write to Nexthink data layer
                [Nxt]::WriteOutputString("TMAUserLoadBehaviour", $LoadBehaviourMap[[int]$Key.LoadBehavior])
            }
            "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE*" {
                # Write to log
                Write-Output "- TMAMachineLoadBehaviour: $($LoadBehaviourMap[[int]$Key.LoadBehavior])"
                # Write to Nexthink data layer
                [Nxt]::WriteOutputString("TMAMachineLoadBehaviour", $LoadBehaviourMap[[int]$Key.LoadBehavior])
            }
        }
    }
}

# Map the add-in DoNotDisableAddinList resiliency values to a human readable format
$DoNotDisableAddinListMap = @{
    0 = "Always disabled (blocked)"
    1 = "Always enabled"
    2 = "Configurable by the user and not blocked by the Block all unmanaged add-ins policy setting when enabled"
}

# Search for the DoNotDisableAddinList registry key to see if the Teams Meeting Add-in is listed to prevent it from being disabled by Outlook
$DoNotDisableAddinList = Get-Item -Path 'HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Resiliency\DoNotDisableAddinList','HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\Resiliency\DoNotDisableAddinList' -ErrorAction SilentlyContinue | Get-ItemProperty
If ($DoNotDisableAddinList) {
    Foreach ($Key in $DoNotDisableAddinList) {
        Switch -Wildcard ($Key.PSPath) {
            "Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER*" {
                # Write to log
                Write-Output "- TMAUserInDoNotDisableAddinList: $($DoNotDisableAddinListMap[[int]$Key.'TeamsAddin.FastConnect'])"
                # Write to Nexthink data layer
                [Nxt]::WriteOutputString("TMAUserInDoNotDisableAddinList", $DoNotDisableAddinListMap[[int]$Key.'TeamsAddin.FastConnect'])
            }
            "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE*" {
                # Write to log
                Write-Output "- TMAMachineInDoNotDisableAddinList: $($DoNotDisableAddinListMap[[int]$Key.'TeamsAddin.FastConnect'])"
                # Write to Nexthink data layer
                [Nxt]::WriteOutputString("TMAMachineInDoNotDisableAddinList", $DoNotDisableAddinListMap[[int]$Key.'TeamsAddin.FastConnect'])
            }
        }
    }
}

# Update nxtSession hashtable with success to pass back to Nexthink
$nxtSession['ExitCode'] = 0
$nxtSession['Message'] = $null

# Exit the script with the session details
Close-NxtSession -NxtSession $nxtSession
