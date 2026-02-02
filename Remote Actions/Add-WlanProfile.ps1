<#
.DESCRIPTION
    Nexthink Remote Action script to create a wireless profile on a Windows workstation. Parameters define the WiFi configuration then the script generates the XML internally and imports it using netsh.exe. This script is intentionally limited to Pre-Shared Keys (PSK) WiFi profiles. It does not build or import certificate‑based (802.1X/EAP) profiles, which require complex EAPConfig blocks and certificate bindings beyond the scope of this Remote Action.
.PARAMETER SSID
    The name of the WiFi network you want to add to the device.
.PARAMETER Authentication
    The security type used by the WiFi network (e.g., WPA2‑PSK). Choose the option that matches the network’s configuration. Defaults to WPA2PSK.
.PARAMETER Encryption
    Encryption type (e.g., AES, TKIP). Defaults to AES.
.PARAMETER Key
    The password for the network.
.PARAMETER ConnectionMode
    Choose whether the device should connect automatically (auto) or only when the user selects it (manual). Usually set to auto. Defaults to auto.
.PARAMETER EnableMacRandomisation
    Enable or disable MAC address randomisation (true or false). Leave as false unless the network specifically requires it. Defaults to false.
.PARAMETER RandomisationSeed
    A number used only when MAC randomisation is enabled. Leave as 0 unless instructed otherwise.
.PARAMETER Scope
    Choose whether the WiFi profile is created for the current user (current) or for all users on the device (all). Usually set to all. Defaults to all.
#>

#==========================================================================#
# Script parameters                                                        #
#==========================================================================#

Param(
    [Parameter(Mandatory=$true)]
    [string]$SSID,
    [Parameter(Mandatory=$true)]
    [string]$Authentication,
    [Parameter(Mandatory=$true)]
    [string]$Encryption,
    [Parameter(Mandatory=$true)]
    [string]$Key,
    [Parameter(Mandatory=$true)]
    [string]$ConnectionMode,
    [Parameter(Mandatory=$true)]
    [string]$MacRandomisation,
    [Parameter(Mandatory=$true)]
    [string]$RandomisationSeed,
    [Parameter(Mandatory=$true)]
    [string]$Scope
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
$nxtSession = Open-NxtSession -LogName "Add-WlanProfile"

# Auto-generate hex SSID from ASCII
$Hex = ([System.Text.Encoding]::ASCII.GetBytes($SSID) | Foreach-Object {$_.ToString("X2")}) -Join ""

# Validate Authentication, default to 'WPA2PSK' if not specified or invalid
$ValidAuth = @("WPA2PSK","WPA3SAE","WPAPSK")
If (-not $Authentication -or -not ($ValidAuth -contains $Authentication)) {
    $Authentication = "WPA2PSK"
}

# Validate Encryption, default to 'AES' if not specified or invalid
$ValidEnc = @("AES","TKIP")
If (-not $Encryption -or -not ($ValidEnc -contains $Encryption)) {
    $Encryption = "AES"
}

# Validate ConnectionMode, default to 'auto' if not specified or invalid
$ValidConnectionModes = @('auto', 'manual')
If (-not $ConnectionMode -or -not ($ValidConnectionModes -contains $ConnectionMode.ToLower())) {
    $ConnectionMode = 'auto'
}

# Validate MacRandomisation, default to false if not specified or invalid
If (-not $MacRandomisation -or -not ($MacRandomisation.ToLower() -eq 'true')) {
    $MacRandomisation = $false
} Else {
    $MacRandomisation = $true
}

# Validate RandomisationSeed, default to 0 if not specified or invalid
If (-not $RandomisationSeed -or -not ([int]::TryParse($RandomisationSeed, [ref]$null))) {
    $RandomisationSeed = 0
}

# Validate Scope, default to 'all' if not specified or invalid
$ValidScopes = @('current', 'all')
If (-not $Scope -or -not ($ValidScopes -contains $Scope.ToLower())) {
    $Scope = 'all'
}

# Write all parameters to the log for debugging if required
Write-Verbose -Message "- SSID              : $SSID"
Write-Verbose -Message "- Authentication    : $Authentication"
Write-Verbose -Message "- Encryption        : $Encryption"
Write-Verbose -Message "- ConnectionMode    : $ConnectionMode"
Write-Verbose -Message "- MacRandomisation  : $MacRandomisation"
Write-Verbose -Message "- RandomisationSeed : $RandomisationSeed"
Write-Verbose -Message "- Scope             : $Scope"

# Build XML
$Xml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$SSID</name>
    <SSIDConfig>
        <SSID>
            <hex>$Hex</hex>
            <name>$SSID</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>$ConnectionMode</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>$Authentication</authentication>
                <encryption>$Encryption</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>$Key</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
    <MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">
        <enableRandomization>$MacRandomisation</enableRandomization>
        <randomizationSeed>$RandomisationSeed</randomizationSeed>
    </MacRandomization>
</WLANProfile>
"@

# Remove existing profile if name matches
& $env:WINDIR\System32\netsh.exe wlan delete profile name="$SSID"

# Create C:\Temp directory if it does not exist
If (-not (Test-Path -Path "C:\Temp")) {
    New-Item -Path "C:\Temp" -ItemType Directory | Out-Null
}

# Write the XML to a temporary file in C:\Temp
$Guid = [Guid]::NewGuid().ToString()
$Temp = "C:\Temp\$Guid.xml"
[System.IO.File]::WriteAllText($Temp, $Xml)

# Import the wireless profile using netsh
& $env:WINDIR\System32\netsh.exe wlan add profile filename="$Temp" user=$Scope

# Check the LASTEXITCODE to determine if the command succeeded
If ($LASTEXITCODE -eq 0) {
    $nxtSession['ExitCode'] = 0
    $nxtSession['Message'] = $null
} Else {
    $nxtSession['ExitCode'] = $LASTEXITCODE
    $nxtSession['Message'] = $null
}

# Remove the temporary XML file
Remove-Item -Path $Temp -Force

# Exit the script with the session details
Close-NxtSession -NxtSession $nxtSession
