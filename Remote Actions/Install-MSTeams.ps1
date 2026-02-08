<#
.DESCRIPTION
    Nexthink Remote Action script to install MSTeams. This script downloads then uses the teamsbootstrapper.exe installer, and the -p switch.
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
$nxtSession = Open-NxtSession -LogName "Install-TeamsMeetingAddin"

# Check if C:\Temp exists, if not create it as the teamsbootstrapper.exe installer will be downloaded here
If (-not (Test-Path -Path "C:\Temp" -PathType Container)) {
    Try {
        New-Item -Path "C:\Temp" -ItemType Directory -ErrorAction Stop | Out-Null
    } Catch {
        $nxtSession['ExitCode'] = 1
        $nxtSession['Message'] = "Failed to create C:\Temp directory. Error: $($_.Exception.Message)"
        Close-NxtSession -NxtSession $nxtSession
    }
}

# Delete any pre-existing teamsbootstrapper.exe installer in C:\Temp to ensure a clean install
If (Test-Path -Path "C:\Temp\teamsbootstrapper.exe" -PathType Leaf) {
    Try {
        Remove-Item -Path "C:\Temp\teamsbootstrapper.exe" -Force -ErrorAction Stop
    } Catch {
        $nxtSession['ExitCode'] = 1
        $nxtSession['Message'] = "Failed to delete pre-existing teamsbootstrapper.exe installer from C:\Temp. Error: $($_.Exception.Message)"
        Close-NxtSession -NxtSession $nxtSession
    }
}

# Download the latest teamsbootstrapper.exe installer to C:\Temp
Try {
    Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409" -OutFile "C:\Temp\teamsbootstrapper.exe" -UseBasicParsing
} Catch {
    $nxtSession['ExitCode'] = 1
    $nxtSession['Message'] = "Failed to download teamsbootstrapper.exe from Microsoft. Error: $($_.Exception.Message)"
    Close-NxtSession -NxtSession $nxtSession
}

# Execute teamsbootstrapper.exe with the -p switch for a per-machine install, and to ensure that the MSTeams installation is up to date
& "C:\Temp\teamsbootstrapper.exe" -p | Out-Null

# Check the $LASTEXITCODE from teamsbootstrapper.exe to confirm the installation was successful
If ($LASTEXITCODE -eq 0) {
    $nxtSession['ExitCode'] = 0
    $nxtSession['Message'] = $null
} Else {
    $nxtSession['ExitCode'] = $LASTEXITCODE
    $nxtSession['Message'] = "teamsbootstrapper.exe failed to install MSTeams. Exit code: $LASTEXITCODE"
}

# Exit the script with the session details
Close-NxtSession -NxtSession $nxtSession
