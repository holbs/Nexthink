<#
.DESCRIPTION
    Nexthink Remote Action script that downloads du.exe from SysInternals and uses it to create a disk usage report for a specified directory.
.PARAMETER Directory
    The directory path to analyse disk usage for.
#>

#==========================================================================#
# Script parameters                                                        #
#==========================================================================#

Param(
    [Parameter(Mandatory=$true)]
    [string]$Directory
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
$nxtSession = Open-NxtSession -LogName "Get-DirectorySize"

# Check if $Directory parameter is a directory. If it is get a list of directories from within the directory for reporting, or exit with error if not.
If (Test-Path -Path $Directory -PathType Container) {
    $Directories = Get-ChildItem -Path $Directory -Directory
    If ($Directories) {
        $Directories = $Directories.FullName -Join ", "
    }
} Else {
    $nxtSession['ExitCode'] = 1
    $nxtSession['Message'] = "The specified directory path '$Directory' does not exist or is not a directory."
    Close-NxtSession -NxtSession $nxtSession
}

# Create C:\Temp directory if it does not exist
If (-not (Test-Path -Path "C:\Temp")) {
    New-Item -Path "C:\Temp" -ItemType Directory | Out-Null
}

# Download du.exe from SysInternals to C:\Temp if it does not already exist
Try {
    If (-not (Test-Path -Path "C:\Temp\du.exe")) {
        Invoke-WebRequest -Uri "https://live.sysinternals.com/du.exe" -OutFile "C:\Temp\du.exe" -UseBasicParsing
    }
} Catch {
    $nxtSession['ExitCode'] = 1
    $nxtSession['Message'] = "Failed to download du.exe from SysInternals. Error: $($_.Exception.Message)"
    Close-NxtSession -NxtSession $nxtSession
}

# Run du.exe to generate disk usage report for the specified directory as a CSV
$Report = & "C:\Temp\du.exe" -accepteula -nobanner -c $Directory

# Check the LASTEXITCODE to determine if the command succeeded or failed, pass results back to Nexthink if successful, or set error details in nxtSession if failed
If ($LASTEXITCODE -ne 0) {
    $nxtSession['ExitCode'] = $LASTEXITCODE
    $nxtSession['Message'] = "du.exe failed to generate directory size report for '$Directory'. Exit code: $LASTEXITCODE."
    Close-NxtSession -NxtSession $nxtSession
} Else {
    $nxtSession['ExitCode'] = $LASTEXITCODE
    $nxtSession['Message'] = $null
}

# Convert the report from CSV to object for easier data extraction
$Report = $Report | ConvertFrom-Csv

# Set the Nexthink data layer outputs
[Nxt]::WriteOutputString("Directory", $Directory)
[Nxt]::WriteOutputSize("Size", $Report.DirectorySizeOnDisk)
[Nxt]::WriteOutputUInt32("Files", $Report.FileCount)
[Nxt]::WriteOutputUInt32("Directories", $Report.DirectoryCount)
[Nxt]::WriteOutputString("Children", $Directories)

# Exit the script with the session details
Close-NxtSession -NxtSession $nxtSession
