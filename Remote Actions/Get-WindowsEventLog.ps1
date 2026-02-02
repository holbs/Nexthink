<#
.DESCRIPTION
    Nexthink Remote Action script to collect a provided event ID from the Windows Event Log and send it to Nexthink. This will return the most recent event matching the provided ID, and then all events as a JSON object.
.PARAMETER LogName
    The name of the event log to collect from.
.PARAMETER EventId
    The ID of the event to collect from the Windows Event Log.
#>

#==========================================================================#
# Script parameters                                                        #
#==========================================================================#

Param (
    [Parameter(Mandatory = $true)] # Set the log to collect events from
    [string]$LogName,
    [Parameter(Mandatory = $true)] # Set the event ID to collect from the Windows Event Log
    [int]$EventId
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
$nxtSession = Open-NxtSession -LogName "Get-WindowsEventLog"

# Get the event log with Get-WinEvent
Try {
    $WinEvents = Get-WinEvent -FilterHashtable @{LogName=$LogName;Id=$EventId} -ErrorAction Stop | Sort-Object TimeCreated -Descending
    If ($WinEvents) {
        # Select the first event
        $WinEventsFirst = $WinEvents | Select-Object -First 1 | Select-Object -Property TimeCreated, Id, LevelDisplayName, Message, ProviderName, LogName
        # Write the first event details back to the Nexthink data layer
        [Nxt]::WriteOutputDateTime("TimeCreated", [datetime]$WinEventsFirst.TimeCreated)
        [Nxt]::WriteOutputString("Id", $WinEventsFirst.Id)
        [Nxt]::WriteOutputString("LevelDisplayName", $WinEventsFirst.LevelDisplayName)
        [Nxt]::WriteOutputString("Message", $WinEventsFirst.Message)
        [Nxt]::WriteOutputString("ProviderName", $WinEventsFirst.ProviderName)
        [Nxt]::WriteOutputString("LogName", $WinEventsFirst.LogName)
        # Convert all events to JSON and write back to the Nexthink data layer
        $WinEventsToJson = $WinEvents | Select-Object -Property TimeCreated, Id, LevelDisplayName, Message, ProviderName, LogName | ConvertTo-Json -Compress
        [Nxt]::WriteOutputString("Json", $WinEventsToJson)
    } Else {
        $nxtSession['ExitCode'] = 0
        $nxtSession['Message'] = "No event found with ID $EventId in $LogName."
    }
} Catch {
    $nxtSession['ExitCode'] = 1
    $nxtSession['Message'] = "Error retrieving event ID $EventId from $LogName : $($_.Exception.Message)"
}

# Update nxtSession hashtable with success or errors to be passed back to Nexthink
$nxtSession['ExitCode'] = 0
$nxtSession['Message'] = $null

# Exit the script with the session details
Close-NxtSession -NxtSession $nxtSession
