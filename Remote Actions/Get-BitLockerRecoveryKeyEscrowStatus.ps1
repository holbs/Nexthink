<#
.DESCRIPTION
    Nexthink Remote Action script to check if the BitLocker recovery key has been escrowed to Entra.
#>

#==========================================================================#
# Script parameters                                                        #
#==========================================================================#

Param ()

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
# Trap and unhandled exceptions                                            #
#==========================================================================#

# Esure there's no unhandled exceptions
Trap {
    $Host.UI.WriteErrorLine($_.ToString())
    Exit 1
}

#==========================================================================#
# Main                                                                     #
#==========================================================================#

# Start the Nexthink session and create nxtSession object
$nxtSession = Open-NxtSession -LogName "Get-BitLockerRecoveryKeyEscrowStatus"

# Check if the BitLocker recovery key has been escrowed to Entra by querying the Event Log for the relevant event for the System Drive's RecoveryPassword Protector
Try {
    # Get the BitLocker Volume for the System Drive (C:) and its Recovery Password Protector and GUID
    $BitLockerSystemDriveVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $BitLockerRecoveryPasswordProtector = $BitLockerSystemDriveVolume.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'} -ErrorAction Stop
    If ($BitLockerRecoveryPasswordProtector) {
        $BitLockerRecoveryPasswordProtectorGuid = $BitLockerRecoveryPasswordProtector[0].KeyProtectorId
        # Query the Event Log for BitLocker Recovery Key Backup Event (Event ID 845) for the System Drive's Recovery Password Protector GUID
        $BitLockerBackupEvent = Get-WinEvent -ProviderName Microsoft-Windows-BitLocker-API -FilterXPath "*[System[(EventID=845)] and EventData[Data[@Name='ProtectorGUID'] and (Data='$BitLockerRecoveryPasswordProtectorGuid')]]" -MaxEvents 1 -ErrorAction SilentlyContinue
        # If the Backup Event is found, output the event message and exit with success
        If ($BitLockerBackupEvent) {
            # Write details back to Nexthink data layer
            [Nxt]::WriteOutputString("BitLockerProtectorGuid", $BitLockerRecoveryPasswordProtectorGuid)
            [Nxt]::WriteOutputString("BitLockerEventLogMessage", $BitLockerBackupEvent.Message)
            [Nxt]::WriteOutputDateTime("BitLockerEventLogDate", (Get-Date $BitLockerBackupEvent.TimeCreated))
            [Nxt]::WriteOutputBool("BitLockerRecoveryKeyToEntra", $true)
        } Else {
            # If no Backup Event is found update update the Nexthink data layer with the relevant details
            [Nxt]::WriteOutputBool("BitLockerRecoveryKeyToEntra", $false)
        }
    } Else {
        # If no RecoveryPassword protector is found for the System Drive, update the Nexthink data layer with the relevant details and exit with success
        [Nxt]::WriteOutputBool("BitLockerRecoveryKeyToEntra", $false)
    }
} Catch {
    # If any errors occur during the check update Nexthink hashtable with the error message and exit with failure
    $nxtSession['ExitCode'] = 1
    $nxtSession['Message'] = "Failed to check BitLocker Recovery Key Backup status: $($_.Exception.Message)"
    Close-NxtSession -NxtSession $nxtSession
}

# Update Nexthink hashtable with a success exit code
$nxtSession['ExitCode'] = 0
$nxtSession['Message'] = $null

# Exit the script with the session details
Close-NxtSession -NxtSession $nxtSession
