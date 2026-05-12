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
  source                 = local.bootstrap_script_path
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
    commandToExecute   = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File ${local.bootstrap_blob_name} -ConfigBase64 \"${local.cse_config_base64}\""
  })

  depends_on = [
    azurerm_storage_blob.bootstrap,
    azurerm_windows_virtual_machine.vm
  ]
}
