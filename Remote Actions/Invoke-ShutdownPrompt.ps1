<#
.DESCRIPTION
    Nexthink Remote Action script to prompt for a shutdown on a workstation within a specified time window. This is to shutdown workstations that may have been left on overnight or during weekends. If there is a user using this they can dismiss it.
.PARAMETER StartHour
    This is the start of the window where the shutdown prompt can be shown. For example set as 21 to start the window at 21:00 (9pm).
.PARAMETER EndHour
    This is the end of the window where the shutdown prompt can be shown. For example set as 05 to end the window at 05:00 (5am).
.PARAMETER CampaignNqlId
    The NQL ID of the campaign to trigger the shutdown prompt. This campaign should be created in Nexthink ahead of time and should contain the shutdown message to show the user.
.PARAMETER MaxWaitTimeInSeconds
    The maximum wait time in seconds for the user to respond to the campaign. For example set as 900 to wait for 15 minutes.
#>

#==========================================================================#
# Script parameters                                                        #
#==========================================================================#

Param (
    [Parameter(Mandatory = $true)] # Set the start hour of the shutdown window
    [int]$StartHour,
    [Parameter(Mandatory = $true)] # Set the end time of the shutdown window
    [int]$EndHour,
    [Parameter(Mandatory = $true)] # Set the NQL ID of the campaign to trigger the shutdown prompt
    [string]$CampaignNqlId,
    [Parameter(Mandatory = $true)] # Set the max wait time in seconds for the user to respond to the campaign
    [int]$MaxWaitTimeInSeconds
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
# Functions                                                                #
#==========================================================================#

Function Test-IsShutdownAllowed {
    [CmdletBinding()]
    Param (
        [ValidateRange(0,23)][int]$StartHour,
        [ValidateRange(0,23)][int]$EndHour
    )
    # Get the current hour and check against the Start and End hours provided
    $CurrentHour = (Get-Date).Hour
    # Account for when $EndHour may be smaller than the $StartHour if it wraps past midnight
    If ($EndHour -gt $StartHour) {
        Return ($CurrentHour -ge $StartHour -and $CurrentHour -lt $EndHour)
    } Else {
        # Here we wrap past midnight
        Return ($CurrentHour -ge $StartHour -or $CurrentHour -lt $EndHour)
    }
}

#==========================================================================#
# Main                                                                     #
#==========================================================================#

# Start the Nexthink session and create nxtSession object
$nxtSession = Open-NxtSession -LogName "Invoke-ShutdownPrompt"

# Check if current time is within the shutdown window first before proceeding
If (-not (Test-IsShutdownAllowed -StartHour $StartHour -EndHour $EndHour)) {
    # Exit the script by closing the session
    $nxtSession['ExitCode'] = 0
    $nxtSession['Message'] = "Current time is outside the shutdown window of $($StartHour):00 to $($EndHour):00. Exiting script."
    Close-NxtSession -NxtSession $nxtSession
}

# Check if there is a user logged in (we use query.exe USER for this to avoid issues with RDP sessions). If there is no user logged in shutdown without prompting.
$LoggedInUser = (& $env:WINDIR\System32\query.exe USER) -Split "\n" -Replace "\s{2,}","," -Replace ">","" | ConvertFrom-Csv | Where-Object {$_.State -eq "Active"}
If (-not $LoggedInUser) {
    # No user is logged in so proceed to shutdown the computer without prompting
    Try {
        # Use shutdown.exe to perform the shutdown so we can queue it up in 60 seconds to allow the campaign to close properly and write back to Nexthink
        $Shutdown = Start-Process -WindowStyle Hidden -FilePath "$env:WINDIR\System32\shutdown.exe" -ArgumentList '/s','/t','60' -PassThru
        Get-Process -Id $Shutdown.Id -ErrorAction SilentlyContinue | Wait-Process -Timeout 60
        If ($Shutdown.HasExited -and $Shutdown.ExitCode -eq 0) {
            $nxtSession['ExitCode'] = 0
            $nxtSession['Message'] = $null
            Close-NxtSession -NxtSession $nxtSession
        } Else {
            Throw # Throw an error into the catch block to update the $nxtSession
        }
    } Catch {
        $nxtSession['ExitCode'] = 1
        $nxtSession['Message'] = "Failed to shutdown the computer. Error: $($_.Exception.Message)"
        Close-NxtSession -NxtSession $nxtSession
    }    
}

# There is a user logged in so trigger campaign to prompt the user about shutting down
$Result = [Nxt.CampaignAction]::RunCampaign($CampaignNqlId, $MaxWaitTimeInSeconds)
$Status = [Nxt.CampaignAction]::GetResponseStatus($Result)

# Check if the campaign was completed and didn't time out, then check the answer
If ($Status -eq "fully" -or $Status -eq "timed_out") {
    $Answer = [Nxt.CampaignAction]::GetResponseAnswer($Result, "shutdown_prompt")
    If ([string]$Answer -ne "OK") {
        $nxtSession['ExitCode'] = 0
        $nxtSession['Message'] = "The campaign was cancelled by the user."
        Close-NxtSession -NxtSession $nxtSession
    }
} Else {
    $nxtSession['ExitCode'] = 1
    $nxtSession['Message'] = "Campaign did not fully complete. Status: $Status"
    Close-NxtSession -NxtSession $nxtSession
}

# User answered "OK" to the campaign or it timed out so shutdown the computer 60 seconds from now (this is to allow the communication back to Nexthink that this has succeeded)
Try {
    # Use shutdown.exe to perform the shutdown so we can queue it up in 60 seconds to allow the campaign to close properly and write back to Nexthink
    $Shutdown = Start-Process -WindowStyle Hidden -FilePath "$env:WINDIR\System32\shutdown.exe" -ArgumentList '/s','/t','60' -PassThru
    Get-Process -Id $Shutdown.Id -ErrorAction SilentlyContinue | Wait-Process -Timeout 60
    If ($Shutdown.HasExited -and $Shutdown.ExitCode -eq 0) {
        $nxtSession['ExitCode'] = 0
        $nxtSession['Message'] = "Shutdown command succeeded. Scheduled shutdown in 60 seconds."
    } Else {
        Throw # Throw an error into the catch block to update the $nxtSession
    }
} Catch {
    $nxtSession['ExitCode'] = 1
    $nxtSession['Message'] = "Failed to shutdown the computer. Error: $($_.Exception.Message)"
    Close-NxtSession -NxtSession $nxtSession
}

# Update nxtSession hashtable with success or errors to be passed back to Nexthink
$nxtSession['ExitCode'] = 0
$nxtSession['Message'] = $null

# Exit the script with the session details
Close-NxtSession -NxtSession $nxtSession
