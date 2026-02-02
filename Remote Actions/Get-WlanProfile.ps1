<#
.DESCRIPTION
    Nexthink Remote Action script to check if a wireless profile exists and return a boolean to Nexthink. This is done by attempting to export it using netsh. If the profile does not exist it cannot be exported.
.PARAMETER ProfileName
    The name of the wireless profile to check for existence.
#>

#==========================================================================#
# Script parameters                                                        #
#==========================================================================#

Param (
    [Parameter(Mandatory = $true)]
    [string]$ProfileName
)

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
$nxtSession = Open-NxtSession -LogName "Get-WlanProfile"

# Create C:\Temp directory if it does not exist
If (-not (Test-Path -Path "C:\Temp")) {
    New-Item -Path "C:\Temp" -ItemType Directory | Out-Null
}

# Export the wireless profile using netsh
$Export = & $env:WINDIR\System32\netsh.exe wlan export profile name="$ProfileName" folder="C:\Temp"

# Check $Export to see if the profile export failed. If it failed, the profile does not exist
If ($Export -match "Profile `"$ProfileName`" is not found on any interface") {
    # Write to the Nexthink data layer that the profile does not exist
    [Nxt]::WriteOutputBool("Installed", $false)
    # Update the Nexthink session object
    $nxtSession['ExitCode'] = 1
    $nxtSession['Message'] = "Wireless profile '$ProfileName' does not exist."
} Else {
    # Write to the Nexthink data layer that the profile exists
    [Nxt]::WriteOutputBool("Installed", $true)
    # Update the Nexthink session object
    $nxtSession['ExitCode'] = 0
    $nxtSession['Message'] = "Wireless profile '$ProfileName' exists."
}

# Delete the exported XML file if it exists
Get-ChildItem -Path "C:\Temp" -Filter "*$ProfileName*.xml" | Remove-Item -Force

# Exit the script with the session details
Close-NxtSession -NxtSession $nxtSession
