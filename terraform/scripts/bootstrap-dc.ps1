param(
    [Parameter(Mandatory = $true)]
    [string] $ConfigBase64
)

$installRoot = "C:\JV-Install"

if (-not (Test-Path $installRoot)) {
    New-Item -Path $installRoot -ItemType Directory -Force | Out-Null
}

$bootstrapLogFile = Join-Path -Path $installRoot -ChildPath "JV-Bootstrap-Log_$(Get-Date -Format dd-MM-yyyy_HH-mm-ss).txt"

function Write-Log {
    param([string] $Message)

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp - $Message"
    Write-Host $entry
    Add-Content -Path $bootstrapLogFile -Value $entry
}

Write-Log "Bootstrap started."
Write-Log "Creating scheduled task for Active Directory Domain Services promotion."

$promoteScriptPath = Join-Path -Path $installRoot -ChildPath "Promote-DC.ps1"

$promoteScript = @'
param(
    [Parameter(Mandatory = $true)]
    [string] $ConfigBase64
)

$installRoot = "C:\JV-Install"

if (-not (Test-Path $installRoot)) {
    New-Item -Path $installRoot -ItemType Directory -Force | Out-Null
}

$logFile = Join-Path -Path $installRoot -ChildPath "JV-ServersInitialInstall-AD-Log_$(Get-Date -Format dd-MM-yyyy_HH-mm-ss).txt"

function Write-Log {
    param([string] $Message)

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp - $Message"
    Write-Host $entry
    Add-Content -Path $logFile -Value $entry
}

function Test-IsDomainController {
    try {
        $feature = Get-WindowsFeature -Name AD-Domain-Services -ErrorAction Stop

        if ($feature.InstallState -ne "Installed") {
            return $false
        }

        Import-Module ActiveDirectory -ErrorAction Stop
        $null = Get-ADDomain -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

try {
    $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($ConfigBase64))
    $config = $json | ConvertFrom-Json
}
catch {
    Write-Log "ERROR: Could not decode configuration. Exception: $_"
    exit 1
}

Write-Log "Script created by Justin Verstijnen."
Write-Log "Starting server initial installation and Active Directory forest deployment."

$TimeZoneToSet     = $config.time_zone
$culture           = $config.culture
$geoid             = $config.geoid
$DomainName        = $config.domain_name
$DomainNetbiosName = $config.domain_netbios_name
$SafeModePwd       = $config.safe_mode_password

Write-Log "=== ADMINISTRATOR CHECK STARTED ==="

try {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

    if (-not $isAdmin) {
        Write-Log "ERROR: Script is not running as Administrator."
        exit 1
    }

    Write-Log "Administrator check passed. Running as: $($currentIdentity.Name)"
}
catch {
    Write-Log "ERROR during administrator check: $_"
    exit 1
}

Write-Log "=== ADMINISTRATOR CHECK COMPLETED ==="

if (Test-IsDomainController) {
    Write-Log "This server already appears to be a domain controller. No promotion will be performed."
    exit 0
}

Write-Log "=== TIME ZONE CHECK STARTED ==="

try {
    $currentTZ = (Get-TimeZone).Id
    Write-Log "Current time zone: $currentTZ"

    if ($currentTZ -ne $TimeZoneToSet) {
        Write-Log "Changing time zone to: $TimeZoneToSet"
        Set-TimeZone -Id $TimeZoneToSet
        Write-Log "Time zone changed to: $TimeZoneToSet"
    }
    else {
        Write-Log "Time zone is already configured correctly."
    }
}
catch {
    Write-Log "ERROR: Failed to set time zone to '$TimeZoneToSet'. Exception: $_"
}

Write-Log "=== TIME ZONE CHECK COMPLETED ==="

Write-Log "=== REGIONAL SETTINGS CONFIGURATION STARTED ==="

try {
    Set-Culture -CultureInfo $culture
    Set-WinHomeLocation -GeoId $geoid
    Set-WinUserLanguageList -LanguageList $culture -Force

    $regPath = "HKCU:\Control Panel\International"

    Set-ItemProperty -Path $regPath -Name "sShortTime" -Value "HH:mm"
    Set-ItemProperty -Path $regPath -Name "sTimeFormat" -Value "HH:mm:ss"
    Set-ItemProperty -Path $regPath -Name "sDecimal" -Value ","
    Set-ItemProperty -Path $regPath -Name "sThousand" -Value "."
    Set-ItemProperty -Path $regPath -Name "sDate" -Value "dd-MM-yyyy"

    Write-Log "Culture set to: $culture"
    Write-Log "Home location set to GeoID: $geoid"
    Write-Log "Regional settings configured successfully."
}
catch {
    Write-Log "ERROR while configuring regional settings: $_"
}

Write-Log "=== REGIONAL SETTINGS CONFIGURATION COMPLETED ==="

Write-Log "=== DISABLE INTERNET EXPLORER ENHANCED SECURITY STARTED ==="

try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" -Name "IEHardenAdmin" -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0 -ErrorAction SilentlyContinue
    Write-Log "Internet Explorer Enhanced Security disabled for Administrators."
}
catch {
    Write-Log "ERROR while disabling Internet Explorer Enhanced Security: $_"
}

Write-Log "=== DISABLE INTERNET EXPLORER ENHANCED SECURITY COMPLETED ==="

Write-Log "=== ENABLE PING RESPONSE STARTED ==="

try {
    Get-NetFirewallRule | Where-Object {
        $_.DisplayName -like "*ICMPv4-In*" -and $_.DisplayGroup -like "*File and Printer Sharing*"
    } | Enable-NetFirewallRule

    Write-Log "ICMPv4 response enabled."

    Get-NetFirewallRule | Where-Object {
        $_.DisplayName -like "*ICMPv6-In*" -and $_.DisplayGroup -like "*File and Printer Sharing*"
    } | Enable-NetFirewallRule

    Write-Log "ICMPv6 response enabled."
}
catch {
    Write-Log "ERROR while enabling ping response: $_"
}

Write-Log "=== ENABLE PING RESPONSE COMPLETED ==="

Write-Log "=== INSTALL ACTIVE DIRECTORY DOMAIN SERVICES STARTED ==="

try {
    $feature = Get-WindowsFeature -Name AD-Domain-Services

    if ($feature.InstallState -ne "Installed") {
        Write-Log "Installing Active Directory Domain Services."
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
        Write-Log "Active Directory Domain Services installed."
    }
    else {
        Write-Log "Active Directory Domain Services is already installed."
    }
}
catch {
    Write-Log "ERROR while installing Active Directory Domain Services: $_"
    exit 1
}

Write-Log "=== INSTALL ACTIVE DIRECTORY DOMAIN SERVICES COMPLETED ==="

Write-Log "=== CREATE FOREST AND PROMOTE SERVER TO DOMAIN CONTROLLER STARTED ==="

try {
    Import-Module ADDSDeployment -ErrorAction Stop

    $SecureStringPwd = ConvertTo-SecureString $SafeModePwd -AsPlainText -Force

    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $DomainNetbiosName `
        -SafeModeAdministratorPassword $SecureStringPwd `
        -InstallDns `
        -ForestMode "WinThreshold" `
        -DomainMode "WinThreshold" `
        -NoRebootOnCompletion:$true `
        -Force:$true

    Write-Log "Active Directory forest installation completed. Rebooting system."
    Restart-Computer -Force
}
catch {
    Write-Log "ERROR while creating Active Directory forest: $_"
    exit 1
}

Write-Log "=== CREATE FOREST AND PROMOTE SERVER TO DOMAIN CONTROLLER COMPLETED ==="
'@

Set-Content -Path $promoteScriptPath -Value $promoteScript -Encoding UTF8 -Force

$taskName = "JV-Promote-DC"
$taskActionArgument = "-NoProfile -ExecutionPolicy Bypass -File `"$promoteScriptPath`" -ConfigBase64 `"$ConfigBase64`""
$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskActionArgument
$taskTrigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1))
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $taskAction `
    -Trigger $taskTrigger `
    -Principal $taskPrincipal `
    -Force | Out-Null

Write-Log "Scheduled task '$taskName' created. It will start in approximately 1 minute."
Write-Log "Bootstrap completed."
