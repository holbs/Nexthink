<#
.DESCRIPTION
    Nexthink Remote Action script to set registry properties for the Teams Meeting Add-in, including setting the LoadBehavior and DoNotDisableAddinList values. Script will detect if it's running as system or user context and set the appropriate registry keys for the context.
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
$nxtSession = Open-NxtSession -LogName "Set-TeamsMeetingAddinRegistry"

# Check if we are running as system or user context
$IsSystemAccount = Test-IsSystemAccount

# Check MSTeams is installed
Switch ($IsSystemAccount) {
    $true {
        $MSTeams = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -eq 'MSTeams'}
    }
    $false {
        $MSTeams = Get-AppxPackage -Name 'MSTeams' -ErrorAction SilentlyContinue
    }
}

# Check the Teams Meeting Add-in is installed
$TMA = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall' | Get-ItemProperty | Where-Object {$_.DisplayName -eq 'Microsoft Teams Meeting Add-in for Microsoft Office'}

# If both MSTeams and the Teams Meeting Add-in are installed then we can update the registry keys based on who is running the script
If ($MSTeams -and $TMA) {
    Switch ($IsSystemAccount) {
        $true {
            Try {
                # Running as the system account, so change the values in HKEY_LOCAL_MACHINE
                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect" -Name "LoadBehavior" -Value 3 -Force -ErrorAction Stop
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\Resiliency\DoNotDisableAddinList" -Name "TeamsAddin.FastConnect" -Value 1 -Type DWord -Force -ErrorAction Stop
            } Catch {
                # If there was an error, return the error message to Nexthink
                $nxtSession['ExitCode'] = 1
                $nxtSession['Message'] = "Failed to set registry keys for the Teams Meeting Add-in. Error: $($_.Exception.Message)"
                Close-NxtSession -NxtSession $nxtSession
            }
        }
        $false {
            Try {
                # Running as a user account, so change the values in HKEY_CURRENT_USER
                New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect" -Name "LoadBehavior" -Value 3 -Force -ErrorAction Stop
                New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Resiliency\DoNotDisableAddinList" -Name "TeamsAddin.FastConnect" -Value 1 -Type DWord -Force -ErrorAction Stop
            } Catch {
                # If there was an error, return the error message to Nexthink
                $nxtSession['ExitCode'] = 1
                $nxtSession['Message'] = "Failed to set registry keys for the Teams Meeting Add-in. Error: $($_.Exception.Message)"
                Close-NxtSession -NxtSession $nxtSession
            }
        }
    }
} Else {
    # Determine which component(s) is missing and return an appropriate message to Nexthink
    If (-not $MSTeams -and -not $TMA) {
        $nxtSession['ExitCode'] = 1
        $nxtSession['Message'] = "MSTeams and the Teams Meeting Add-in are not installed on this device. Please install MSTeams to get the Teams Meeting Add-in."
    } ElseIf (-not $MSTeams) {
        $nxtSession['ExitCode'] = 1
        $nxtSession['Message'] = "MSTeams is not installed on this device. Please install MSTeams to get the Teams Meeting Add-in."
    } Elseif (-not $TMA) {
        $nxtSession['ExitCode'] = 1
        $nxtSession['Message'] = "The Teams Meeting Add-in is not installed on this device. Please ensure MSTeams is up to date to get the Teams Meeting Add-in."
    }
    # Close the Nexthink session
    Close-NxtSession -NxtSession $nxtSession
}

# Update nxtSession hashtable with success if the script hasn't already closed the session
$nxtSession['ExitCode'] = 0
$nxtSession['Message'] = $null

# Exit the script with the session details
Close-NxtSession -NxtSession $nxtSession
