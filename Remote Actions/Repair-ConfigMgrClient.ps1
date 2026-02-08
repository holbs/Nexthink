<#
.DESCRIPTION
    Nexthink Remote Action script that triggers a reinstall of the ConfigMgr client. This script should be ran as the system account.
.PARAMETER ccmsetupSource
    The path to the ccmsetup.exe source file
.PARAMETER Parameters
    Parameters to pass to ccmsetup.exe during the installation. For a reference of valid parameters please consult the official Microsoft documentation: https://learn.microsoft.com/en-us/intune/configmgr/core/clients/deploy/about-client-installation-properties
#>

#==========================================================================#
# Script parameters                                                        #
#==========================================================================#

Param (
    [Parameter(Mandatory = $true)] 
    [string]$ccmsetupSource,
    [Parameter(Mandatory = $true)]
    [string]$Parameters
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
$nxtSession = Open-NxtSession -LogName "Repair-ConfigMgrClient"

# Check if ccmsetup is already running and exit early if it is to prevent this Remote Action being misused
If (Get-Process -Name "ccmsetup" -ErrorAction SilentlyContinue) {
    $nxtSession['ExitCode'] = 1
    $nxtSession['Message'] = "ccmsetup.exe is already running. Please wait for the current installation to finish before running this script again."
    Close-NxtSession -NxtSession $nxtSession
}

# Check if the ccmsetup service is already running and exit early if it is to prevent this Remote Action being misused
If (Get-Service -Name "ccmsetup" -ErrorAction SilentlyContinue) {
    $nxtSession['ExitCode'] = 1
    $nxtSession['Message'] = "ccmsetup service is already running. Exiting script to prevent multiple concurrent installations."
    Close-NxtSession -NxtSession $nxtSession
}

# Create %%windir%%\ccmsetup if it doesn't exist. This prevents errors copying from the provided $Source
If (-not (Test-Path -Path "$env:WINDIR\ccmsetup")) {
    New-Item -Path "$env:WINDIR\ccmsetup" -ItemType Directory -Force | Out-Null
}

# Test that ccmsetupSource is a leaf path and is named ccmsetup.exe
Try {
    If (Test-Path -Path $ccmsetupSource -PathType Leaf) {
        $Test = Get-Item -Path $ccmsetupSource
        If ($Test.Name -ne "ccmsetup.exe") {
            # $ccmsetupSource is invalid
            Throw "Invalid ccmsetup source file: $($Test.Name). Expected 'ccmsetup.exe'."
        }
    } Else {
        # $ccmsetupSource is invalid
        Throw "Invalid ccmsetup source path: $ccmsetupSource. Expected a file path to 'ccmsetup.exe'."
    }
} Catch {
    $nxtSession['ExitCode'] = 1
    $nxtSession['Message'] = "Failed to validate ccmsetup source path. Error: $($_.Exception.Message)"
    Close-NxtSession -NxtSession $nxtSession
}

# Test if provided ccmsetupSource path is a UNC path, or local path. If it's a UNC path we need to copy it locally to %windir%\ccmsetup
If ($ccmsetupSource -match '^\\\\') {
    # UNC path detected, copy to local ccmsetup directory
    Try {
        Copy-Item -Path $ccmsetupSource -Destination "$env:WINDIR\ccmsetup\ccmsetup.exe" -Force -ErrorAction Stop
        # Set the source for the installation to the local path we just copied to
        $Source = "$env:WINDIR\ccmsetup\ccmsetup.exe"
        Write-Verbose -Message "Copied ccmsetup.exe from UNC path to $env:WINDIR\ccmsetup"
    } Catch {
        $nxtSession['ExitCode'] = 1
        $nxtSession['Message'] = "Failed to copy ccmsetup.exe from UNC path. Error: $($_.Exception.Message)"
        Close-NxtSession -NxtSession $nxtSession
    }
} Else {
    # Local path, use ccmsetupSource as the Source
    $Source = $ccmsetupSource
}

# Run ccmsetup.exe with the provided parameters, wait for it to finish for up to 15 minutes. Use Write-Verbose and Write-Warning to write to the transcript log
Try {
    $Process = Start-Process -FilePath $Source -ArgumentList $Parameters
    # Briefly wait to ensure the process has started
    Start-Sleep -Seconds 1
    # Wait for the ccmsetup.exe process to complete for up to 15 minutes
    Wait-Process -Name "ccmsetup" -Timeout 900 -ErrorAction Stop
} Catch {
    $nxtSession['ExitCode'] = 1
    $nxtSession['Message'] = "Failed to execute ccmsetup.exe. Error: $($_.Exception.Message)"
    Close-NxtSession -NxtSession $nxtSession
}

# Check the exit code of the ccmsetup.exe process and set the nxtSession accordingly
If ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 7) {
    $nxtSession['ExitCode'] = 0
    $nxtSession['Message'] = "ccmsetup.exe exited with exit code: $($Process.ExitCode)."
} Else {
    $nxtSession['ExitCode'] = 1
    $nxtSession['Message'] = "ccmsetup.exe failed with exit code: $($Process.ExitCode)."
}

# Exit the script
Close-NxtSession -NxtSession $nxtSession
