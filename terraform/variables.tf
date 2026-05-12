############################################################
# VARIABLES - adjust values in terraform.tfvars
############################################################

variable "subscription_id" {
  description = "Azure Subscription ID used by the AzureRM provider."
  type        = string
}

variable "project" {
  description = "Project name. Used for naming: rg-jv-project, vm-jv-project, and so on."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]{2,20}$", var.project))
    error_message = "Use only letters, numbers and hyphens. Length: 2 to 20 characters."
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

variable "rdp_source_address_prefix" {
  description = "Source IP address prefix allowed for RDP. Preferably set this to your own public IP address with /32."
  type        = string
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
