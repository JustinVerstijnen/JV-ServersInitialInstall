terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

############################################################
# PROVIDERS
############################################################

provider "azurerm" {
  features {}

  subscription_id = var.subscription_id
}

############################################################
# VARIABLES - adjust this block per project
############################################################

variable "subscription_id" {
  description = "Azure Subscription ID used by the AzureRM provider."
  type        = string
}

variable "project" {
  description = "Project name. Used for naming: rg-jv-project, vm-jv-project, and so on."
  type        = string
  default     = "testdc"

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]{2,20}$", var.project))
    error_message = "Use only letters, numbers and hyphens. Length: 2 to 20 characters."
  }
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "westeurope"
}

variable "vnet_address_space" {
  description = "Address space for the virtual network."
  type        = list(string)
  default     = ["10.69.0.0/16"]
}

variable "subnet_address_prefixes" {
  description = "Subnet address prefix where the VM will be deployed."
  type        = list(string)
  default     = ["10.69.0.0/24"]
}

variable "vnet_dns_servers" {
  description = "DNS servers configured on the virtual network."
  type        = list(string)
  default     = ["10.69.0.4", "168.63.129.16"]
}

variable "internal_ip" {
  description = "Static private IP address for the domain controller."
  type        = string
  default     = "10.69.0.4"
}

variable "ad_forest_name" {
  description = "Active Directory forest name."
  type        = string
  default     = "internal.justinverstijnen.nl"
}

variable "domain_netbios_name" {
  description = "NetBIOS name of the domain."
  type        = string
  default     = "JV-INT"
}

variable "admin_username" {
  description = "Local administrator username for the Windows VM."
  type        = string
  default     = "jvadmin"
}

variable "admin_password" {
  description = "Administrator password for the VM. Change this before deployment."
  type        = string
  sensitive   = true
  default     = "ChangeM3-This-Password-Now!"
}

variable "safe_mode_password" {
  description = "DSRM / Safe Mode Administrator password for AD DS. Change this before deployment."
  type        = string
  sensitive   = true
  default     = "ChangeM3-This-DSRM-Password-Now!"
}

variable "vm_size" {
  description = "Azure VM size."
  type        = string
  default     = "Standard_B2ms"
}

variable "os_disk_type" {
  description = "OS disk storage type."
  type        = string
  default     = "StandardSSD_LRS"
}

variable "image_publisher" {
  description = "Azure Marketplace image publisher."
  type        = string
  default     = "MicrosoftWindowsServer"
}

variable "image_offer" {
  description = "Azure Marketplace image offer."
  type        = string
  default     = "WindowsServer"
}

variable "image_sku" {
  description = "Azure Marketplace image SKU."
  type        = string
  default     = "2022-datacenter"
}

variable "image_version" {
  description = "Azure Marketplace image version."
  type        = string
  default     = "latest"
}

variable "rdp_source_address_prefix" {
  description = "Source IP address prefix allowed for RDP. Preferably set this to your own public IP address with /32."
  type        = string
  default     = "*"
}

variable "time_zone" {
  description = "Windows time zone."
  type        = string
  default     = "W. Europe Standard Time"
}

variable "culture" {
  description = "Windows culture and language."
  type        = string
  default     = "nl-NL"
}

variable "geoid" {
  description = "Windows geographical location. 176 = Netherlands."
  type        = string
  default     = "176"
}

variable "tags" {
  description = "Azure tags."
  type        = map(string)
  default = {
    owner       = "Justin Verstijnen"
    environment = "lab"
    deployedBy  = "terraform"
  }
}

############################################################
# LOCALS - naming and bootstrap script
############################################################

locals {
  project_clean = lower(var.project)

  resource_group_name = "rg-jv-${local.project_clean}"
  vm_name             = "vm-jv-${local.project_clean}"
  computer_name       = substr(replace("vmjv${local.project_clean}", "-", ""), 0, 15)
  os_disk_name        = "osdisk-jv-${local.project_clean}"
  vnet_name           = "vnet-jv-${local.project_clean}"
  subnet_name         = "snet-jv-${local.project_clean}"
  nic_name            = "nic-jv-${local.project_clean}"
  pip_name            = "pip-jv-${local.project_clean}"
  nsg_name            = "nsg-jv-${local.project_clean}"

  bootstrap_blob_name = "bootstrap-dc.ps1"

  cse_config_base64 = base64encode(jsonencode({
    time_zone           = var.time_zone
    culture             = var.culture
    geoid               = var.geoid
    domain_name         = var.ad_forest_name
    domain_netbios_name = var.domain_netbios_name
    safe_mode_password  = var.safe_mode_password
  }))

  bootstrap_blob_url = "https://${azurerm_storage_account.scripts.name}.blob.core.windows.net/${azurerm_storage_container.scripts.name}/${local.bootstrap_blob_name}"

  bootstrap_script = <<-POWERSHELL
    param(
        [Parameter(Mandatory = $true)]
        [string] $ConfigBase64
    )

    $installRoot = "C:\JV-Install"

    if (-not (Test-Path $installRoot)) {
        New-Item -Path $installRoot -ItemType Directory -Force | Out-Null
    }

    $bootstrapLogFile = Join-Path -Path $installRoot -ChildPath "JV-Bootstrap-Log_$(Get-Date -Format dd-MM-yyyy_HH-mm-ss).txt"

    function Log {
        param([string] $Message)

        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $entry = "$timestamp - $Message"
        Write-Host $entry
        Add-Content -Path $bootstrapLogFile -Value $entry
    }

    Log "Bootstrap started."
    Log "Creating scheduled task for AD DS promotion."

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

    function Log {
        param([string] $Message)

        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $entry = "$timestamp - $Message"
        Write-Host $entry
        Add-Content -Path $logFile -Value $entry
    }

    try {
        $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($ConfigBase64))
        $config = $json | ConvertFrom-Json
    }
    catch {
        Log "ERROR: Could not decode configuration. Exception: $_"
        exit 1
    }

    Log "Script created by Justin Verstijnen."
    Log "Starting server initial installation and Active Directory forest deployment."

    $TimeZoneToSet     = $config.time_zone
    $culture           = $config.culture
    $geoid             = $config.geoid
    $DomainName        = $config.domain_name
    $DomainNetbiosName = $config.domain_netbios_name
    $SafeModePwd       = $config.safe_mode_password

    Log "=== ADMINISTRATOR CHECK STARTED ==="

    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

        if (-not $isAdmin) {
            Log "ERROR: Script is not running as Administrator."
            exit 1
        }

        Log "Administrator check passed. Running as: $($currentIdentity.Name)"
    }
    catch {
        Log "ERROR during administrator check: $_"
        exit 1
    }

    Log "=== ADMINISTRATOR CHECK COMPLETED ==="

    Log "=== TIME ZONE CHECK STARTED ==="

    try {
        $currentTZ = (Get-TimeZone).Id
        Log "Current time zone: $currentTZ"

        if ($currentTZ -ne $TimeZoneToSet) {
            Log "Changing time zone to: $TimeZoneToSet"
            Set-TimeZone -Id $TimeZoneToSet
            Log "Time zone changed to: $TimeZoneToSet"
        }
        else {
            Log "Time zone is already configured correctly."
        }
    }
    catch {
        Log "ERROR: Failed to set time zone to '$TimeZoneToSet'. Exception: $_"
    }

    Log "=== TIME ZONE CHECK COMPLETED ==="

    Log "=== REGIONAL SETTINGS CONFIGURATION STARTED ==="

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

        Log "Culture set to: $culture"
        Log "Home location set to GeoID: $geoid"
        Log "Regional settings configured successfully."
    }
    catch {
        Log "ERROR while configuring regional settings: $_"
    }

    Log "=== REGIONAL SETTINGS CONFIGURATION COMPLETED ==="

    Log "=== DISABLE IE ENHANCED SECURITY STARTED ==="

    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" -Name "IEHardenAdmin" -Value 0 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0 -ErrorAction SilentlyContinue
        Log "Internet Explorer Enhanced Security disabled for Administrators."
    }
    catch {
        Log "ERROR while disabling Internet Explorer Enhanced Security: $_"
    }

    Log "=== DISABLE IE ENHANCED SECURITY COMPLETED ==="

    Log "=== ENABLE PING RESPONSE STARTED ==="

    try {
        Get-NetFirewallRule | Where-Object {
            $_.DisplayName -like "*ICMPv4-In*" -and $_.DisplayGroup -like "*File and Printer Sharing*"
        } | Enable-NetFirewallRule

        Log "ICMPv4 response enabled."

        Get-NetFirewallRule | Where-Object {
            $_.DisplayName -like "*ICMPv6-In*" -and $_.DisplayGroup -like "*File and Printer Sharing*"
        } | Enable-NetFirewallRule

        Log "ICMPv6 response enabled."
    }
    catch {
        Log "ERROR while enabling ping response: $_"
    }

    Log "=== ENABLE PING RESPONSE COMPLETED ==="

    Log "=== INSTALL ACTIVE DIRECTORY DOMAIN SERVICES STARTED ==="

    try {
        $feature = Get-WindowsFeature -Name AD-Domain-Services

        if ($feature.InstallState -ne "Installed") {
            Log "Installing Active Directory Domain Services."
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
            Log "Active Directory Domain Services installed."
        }
        else {
            Log "Active Directory Domain Services is already installed."
        }
    }
    catch {
        Log "ERROR while installing Active Directory Domain Services: $_"
        exit 1
    }

    Log "=== INSTALL ACTIVE DIRECTORY DOMAIN SERVICES COMPLETED ==="

    Log "=== CREATE FOREST AND PROMOTE SERVER TO DOMAIN CONTROLLER STARTED ==="

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

        Log "Active Directory forest installation completed. Rebooting system."
        Restart-Computer -Force
    }
    catch {
        Log "ERROR while creating Active Directory forest: $_"
        exit 1
    }

    Log "=== CREATE FOREST AND PROMOTE SERVER TO DOMAIN CONTROLLER COMPLETED ==="
    '@

    Set-Content -Path $promoteScriptPath -Value $promoteScript -Encoding UTF8 -Force

    $taskName = "JV-Promote-DC"
    $taskActionArgument = "-NoProfile -ExecutionPolicy Bypass -File `"$promoteScriptPath`" -ConfigBase64 $ConfigBase64"
    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskActionArgument
    $taskTrigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1))
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $taskAction `
        -Trigger $taskTrigger `
        -Principal $taskPrincipal `
        -Force | Out-Null

    Log "Scheduled task '$taskName' created. It will start in approximately 1 minute."
    Log "Bootstrap completed."
  POWERSHELL

  custom_script_extension_timestamp = parseint(substr(sha256(local.bootstrap_script), 0, 8), 16)
}

############################################################
# RESOURCE GROUP
############################################################

resource "azurerm_resource_group" "rg" {
  name     = local.resource_group_name
  location = var.location
  tags     = var.tags
}

############################################################
# NETWORK
############################################################

resource "azurerm_virtual_network" "vnet" {
  name                = local.vnet_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = var.vnet_address_space
  dns_servers         = var.vnet_dns_servers
  tags                = var.tags
}

resource "azurerm_subnet" "subnet" {
  name                 = local.subnet_name
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = var.subnet_address_prefixes
}

resource "azurerm_public_ip" "pip" {
  name                = local.pip_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_security_group" "nsg" {
  name                = local.nsg_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tags                = var.tags

  security_rule {
    name                       = "Allow-RDP"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = var.rdp_source_address_prefix
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "Allow-ICMP"
    priority                   = 1010
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Icmp"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = var.rdp_source_address_prefix
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface" "nic" {
  name                = local.nic_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  dns_servers         = var.vnet_dns_servers
  tags                = var.tags

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Static"
    private_ip_address            = var.internal_ip
    public_ip_address_id          = azurerm_public_ip.pip.id
  }
}

resource "azurerm_network_interface_security_group_association" "nic_nsg" {
  network_interface_id      = azurerm_network_interface.nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

############################################################
# STORAGE FOR CUSTOM SCRIPT EXTENSION
############################################################

resource "random_string" "storage_suffix" {
  length  = 10
  upper   = false
  lower   = true
  numeric = true
  special = false
}

resource "azurerm_storage_account" "scripts" {
  name                            = "stjv${random_string.storage_suffix.result}"
  resource_group_name             = azurerm_resource_group.rg.name
  location                        = azurerm_resource_group.rg.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  tags                            = var.tags
}

resource "azurerm_storage_container" "scripts" {
  name                  = "scripts"
  storage_account_id    = azurerm_storage_account.scripts.id
  container_access_type = "private"
}

resource "azurerm_storage_blob" "bootstrap" {
  name                   = local.bootstrap_blob_name
  storage_account_name   = azurerm_storage_account.scripts.name
  storage_container_name = azurerm_storage_container.scripts.name
  type                   = "Block"
  content_type           = "text/x-powershell"
  source_content         = local.bootstrap_script
}

############################################################
# WINDOWS SERVER VM
############################################################

resource "azurerm_windows_virtual_machine" "vm" {
  name                = local.vm_name
  computer_name       = local.computer_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  size                = var.vm_size

  admin_username = var.admin_username
  admin_password = var.admin_password

  network_interface_ids = [
    azurerm_network_interface.nic.id
  ]

  provision_vm_agent       = true
  enable_automatic_updates = true
  patch_mode               = "AutomaticByOS"

  os_disk {
    name                 = local.os_disk_name
    caching              = "ReadWrite"
    storage_account_type = var.os_disk_type
  }

  source_image_reference {
    publisher = var.image_publisher
    offer     = var.image_offer
    sku       = var.image_sku
    version   = var.image_version
  }

  tags = var.tags

  depends_on = [
    azurerm_network_interface_security_group_association.nic_nsg
  ]
}

############################################################
# CUSTOM SCRIPT EXTENSION
############################################################

resource "azurerm_virtual_machine_extension" "bootstrap_dc" {
  name                       = "jv-bootstrap-dc"
  virtual_machine_id         = azurerm_windows_virtual_machine.vm.id
  publisher                  = "Microsoft.Compute"
  type                       = "CustomScriptExtension"
  type_handler_version       = "1.10"
  auto_upgrade_minor_version = true

  settings = jsonencode({
    timestamp = local.custom_script_extension_timestamp
  })

  protected_settings = jsonencode({
    storageAccountName = azurerm_storage_account.scripts.name
    storageAccountKey  = azurerm_storage_account.scripts.primary_access_key
    fileUris           = [local.bootstrap_blob_url]
    commandToExecute   = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File ${local.bootstrap_blob_name} -ConfigBase64 ${local.cse_config_base64}"
  })

  depends_on = [
    azurerm_storage_blob.bootstrap,
    azurerm_windows_virtual_machine.vm
  ]
}

############################################################
# OUTPUTS
############################################################

output "resource_group_name" {
  value = azurerm_resource_group.rg.name
}

output "vm_name" {
  value = azurerm_windows_virtual_machine.vm.name
}

output "vm_private_ip" {
  value = azurerm_network_interface.nic.private_ip_address
}

output "vm_public_ip" {
  value = azurerm_public_ip.pip.ip_address
}

output "rdp_command" {
  value = "mstsc /v:${azurerm_public_ip.pip.ip_address}"
}

output "ad_forest_name" {
  value = var.ad_forest_name
}
