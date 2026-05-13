############################################################
# VARIABLES - adjust values in terraform.tfvars
############################################################

variable "subscription_id" {
  description = "Azure Subscription ID used by the AzureRM provider."
  type        = string
}

variable "project" {
  description = "Project name. Used for naming: rg-jv-project, vm-jv-project, and so on. Keep it short because the Windows computer name will be vm-jv-<project>."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9-]{0,7}[a-zA-Z0-9]$", var.project))
    error_message = "Use 2 to 9 characters. Only letters, numbers and hyphens are allowed. The value cannot start or end with a hyphen. This keeps the Windows computer name within the 15-character limit."
  }
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "vnet_address_space" {
  description = "Address space for the virtual network."
  type        = list(string)
}

variable "subnet_address_prefixes" {
  description = "Subnet address prefix where the VM will be deployed."
  type        = list(string)
}

variable "vnet_dns_servers" {
  description = "DNS servers configured on the virtual network."
  type        = list(string)
}

variable "internal_ip" {
  description = "Static private IP address for the domain controller."
  type        = string
}

variable "ad_forest_name" {
  description = "Active Directory forest name."
  type        = string
}

variable "domain_netbios_name" {
  description = "NetBIOS name of the domain."
  type        = string
}

variable "admin_username" {
  description = "Local administrator username for the Windows VM."
  type        = string
}

variable "admin_password" {
  description = "Administrator password for the VM. Store this in terraform.tfvars, not in Git."
  type        = string
  sensitive   = true
}

variable "safe_mode_password" {
  description = "DSRM / Safe Mode Administrator password for AD DS. Store this in terraform.tfvars, not in Git."
  type        = string
  sensitive   = true
}

variable "vm_size" {
  description = "Azure VM size."
  type        = string
}

variable "os_disk_type" {
  description = "OS disk storage type."
  type        = string
}

variable "image_publisher" {
  description = "Azure Marketplace image publisher."
  type        = string
}

variable "image_offer" {
  description = "Azure Marketplace image offer."
  type        = string
}

variable "image_sku" {
  description = "Azure Marketplace image SKU."
  type        = string
}

variable "image_version" {
  description = "Azure Marketplace image version."
  type        = string
}

variable "rdp_source_address_prefixes" {
  description = "Source IP address prefixes allowed for RDP. Preferably use public IP addresses with /32, for example [\"203.0.113.10/32\", \"203.0.113.11/32\"]."
  type        = list(string)

  validation {
    condition     = length(var.rdp_source_address_prefixes) > 0
    error_message = "At least one RDP source address prefix must be provided."
  }
}

variable "bootstrap_script_url" {
  description = "Public raw URL to the bootstrap PowerShell script, for example a raw.githubusercontent.com URL."
  type        = string

  validation {
    condition     = can(regex("^https://", var.bootstrap_script_url))
    error_message = "The bootstrap_script_url must start with https://."
  }
}

variable "bootstrap_script_file_name" {
  description = "The file name of the bootstrap script after it is downloaded by the Custom Script Extension. Keep this aligned with the script URL file name."
  type        = string
  default     = "bootstrap-dc.ps1"
}

variable "bootstrap_script_version" {
  description = "Manual version value used to force the Custom Script Extension to run again after changing the GitHub-hosted script. Increase this value when needed."
  type        = string
  default     = "1"
}

variable "time_zone" {
  description = "Windows time zone."
  type        = string
}

variable "culture" {
  description = "Windows culture and language."
  type        = string
}

variable "geoid" {
  description = "Windows geographical location. 176 = Netherlands."
  type        = string
}

variable "tags" {
  description = "Azure tags."
  type        = map(string)
}
