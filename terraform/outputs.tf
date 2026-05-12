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
