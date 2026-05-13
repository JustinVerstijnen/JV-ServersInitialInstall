############################################################
# LOCALS - naming and script configuration
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

  bootstrap_script_path = "${path.module}/scripts/bootstrap-dc.ps1"

  cse_config_base64 = base64encode(jsonencode({
    time_zone           = var.time_zone
    culture             = var.culture
    geoid               = var.geoid
    domain_name         = var.ad_forest_name
    domain_netbios_name = var.domain_netbios_name
    safe_mode_password  = var.safe_mode_password
  }))

  # Changing this value causes the Custom Script Extension to run again when the local script copy,
  # script URL, or manual version value changes. When using GitHub, publish the updated local script
  # to the repository and increase bootstrap_script_version when you want to force a rerun.
  custom_script_extension_timestamp = parseint(substr(sha256(join("|", [
    var.bootstrap_script_url,
    var.bootstrap_script_file_name,
    var.bootstrap_script_version,
    filemd5(local.bootstrap_script_path)
  ])), 0, 7), 16)
}
