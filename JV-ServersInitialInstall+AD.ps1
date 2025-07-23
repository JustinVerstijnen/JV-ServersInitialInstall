# Justin Verstijnen Server Initial Installation script + Installation of Active Directory Forest
# Github page: https://github.com/JustinVerstijnen/JV-ServersInitialInstall
# Let's start!
Write-Host "Script made by..." -ForegroundColor DarkCyan
Write-Host "     _           _   _        __     __            _   _  _                  
    | |_   _ ___| |_(_)_ __   \ \   / /__ _ __ ___| |_(_)(_)_ __   ___ _ __  
 _  | | | | / __| __| | '_ \   \ \ / / _ \ '__/ __| __| || | '_ \ / _ \ '_ \ 
| |_| | |_| \__ \ |_| | | | |   \ V /  __/ |  \__ \ |_| || | | | |  __/ | | |
 \___/ \__,_|___/\__|_|_| |_|    \_/ \___|_|  |___/\__|_|/ |_| |_|\___|_| |_|
                                                       |__/                  " -ForegroundColor DarkCyan

                                                       
# === PARAMETERS ===
$logFile = Join-Path -Path $PSScriptRoot -ChildPath "JV-ServersInitialInstall+AD-Log_$(Get-Date -Format dd-MM-yyyy).txt"
$TimeZoneToSet = "W. Europe Standard Time"  # Example: Amsterdam (UTC+1/UTC+2 DST)
$culture = "nl-NL"
$geoid = "176" #  Check this page: https://learn.microsoft.com/en-us/windows/win32/intl/table-of-geographical-locations
$DomainName = "internal.justinverstijnen.nl"
$SafeModePwd = "XPa$$W0rd!24"  # DSRM wachtwoord (hardcoded)
$DomainNetbiosName = "JV-INT"
# === END PARAMETERS ===


# Step 1: First check if the script runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Warning "This script must be runned as Administrator. The script will now end."
    exit
}


# Step 2: Logging will be enabled for checking the functionality of the script, even after it ran unattended.
function Log {
    param ($message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $message"
    Write-Host $logEntry
    Add-Content -Path $logFile -Value $logEntry
}
Log ""


# Step 3: The timezone will be corrected to the script settings ensure the correct logging times are displayed
Log "=== STEP 3: TIME ZONE CHECK STARTED ==="
try {
    $currentTZ = (Get-TimeZone).Id
    Log "Current time zone: $currentTZ"
    
    if ($currentTZ -ne $TimeZoneToSet) {
        Log "Changing time zone to: $TimeZoneToSet"
        Set-TimeZone -Id $TimeZoneToSet
        Log "Time zone successfully changed to: $TimeZoneToSet"
    } else {
        Log "Time zone already set correctly. No change needed."
    }
} catch {
    Log "ERROR: Failed to set time zone to '$TimeZoneToSet'. Exception: $_"
}
Log "=== STEP 3: TIME ZONE CHECK COMPLETED ==="


# Step 4: Regional settings correction
Log "=== STEP 4: REGION SETTINGS CONFIGURATION STARTED ==="
try {
    Set-Culture -CultureInfo $culture
    Set-WinHomeLocation -GeoId $geoid
    Set-WinUserLanguageList -LanguageList $culture -Force

    Log "Culture set to: $culture"
    Log "Home location set to Netherlands (GeoID: $geoid)"
    Log "User language list updated to: $culture"
    $regPath = "HKCU:\Control Panel\International"
    Set-ItemProperty -Path $regPath -Name "sShortTime" -Value "HH:mm"
    Set-ItemProperty -Path $regPath -Name "sTimeFormat" -Value "HH:mm:ss"
    Set-ItemProperty -Path $regPath -Name "sDecimal" -Value ","
    Set-ItemProperty -Path $regPath -Name "sThousand" -Value "."
    Set-ItemProperty -Path $regPath -Name "sDate" -Value "dd-MM-yyyy"

    Log "Time format set to 24-hour (HH:mm:ss)"
    Log "Decimal separator set to ',' and thousand separator to '.'"
    Log "Date format set to dd-MM-yyyy"

    Log "Regional settings configured successfully."
} catch {
    Log "ERROR while setting regional settings: $_"
}

Log "=== STEP 4: REGION SETTINGS CONFIGURATION COMPLETED ==="


# Step 5: Disable Internet Explorer Enhanced Security
Log "=== STEP 5: DISABLE IE ENHANCED SECURITY ==="
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" -Name "IEHardenAdmin" -Value 0 #Admins
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0
Log "Disabled IE Enhanced Security for Administrators"
Log "=== STEP 5: DISABLE IE ENHANCED SECURITY COMPLETED ==="


# Step 6: Enable response to ping
Log "=== STEP 6: ENABLE PING RESPONSE ==="
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*ICMPv4-In*" -and $_.DisplayGroup -like "*File and Printer Sharing*"} | Enable-NetFirewallRule
Log "Enabled for IPv4"
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*ICMPv6-In*" -and $_.DisplayGroup -like "*File and Printer Sharing*"} | Enable-NetFirewallRule
Log "Enabled for IPv6"
Log "=== STEP 6: ENABLE PING RESPONSE COMPLETED ==="


# Step 7: Install ADDS
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
$SecureStringPwd = ConvertTo-SecureString $SafeModePwd -AsPlainText -Force


# Step 8: Creating Forest and promote to DC
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $DomainNetbiosName `
    -SafeModeAdministratorPassword $SecureStringPwd `
    -InstallDns `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -Force:$true

Write-Host "Rebooting system now" -ForegroundColor Green
Log "End of script"
Restart-Computer -Force
# End of script
