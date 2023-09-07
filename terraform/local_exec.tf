resource "null_resource" "deployment_summary" {
  provisioner "local-exec" {
    command     = "${local.setup_folder_path}CustomScripts/Write-DeploymentSummary.ps1 -HideSessionLaunchPassword ${var.hide_session_launch_password} -CoreResourceGroupName \"${azurerm_resource_group.ctx_resource_group.name}\" -WebStudioMachine \"${var.webstudio_count == 0 ? azurerm_windows_virtual_machine.ddc.name : azurerm_windows_virtual_machine.webstudio[0].name}\" -VdaResourceGroupName \"${local.deployment_summary_vda_resource_group_name}\" -AdDomainName \"${var.active_directory_domain_name}\" -AdPublicIP \"${azurerm_public_ip.ad_public_ip.ip_address}\" -AdComputerName \"${azurerm_windows_virtual_machine.adVM.name}\" -AdAdminUsername \"${var.advm_admin_username}\" -AdAdminPassword \"${local.advm_admin_password}\" -DdcComputerName \"${azurerm_windows_virtual_machine.ddc.name}\" -DdcPublicIp \"${azurerm_public_ip.ddc_public_ip.ip_address}\" -DdcPrivateIp \"${var.ddc_private_ip_addr}\" -StoreVirtualPath \"${var.store_virtual_path}\" -StoreUserPassword \"${local.ad_default_user_password}\" -MachineCatalogName \"${var.machine_catalog_name}\" -SessionSupport \"${var.catalog_session_support}\" -VdaCount \"${var.vda_machine_count}\""
    interpreter = ["PowerShell", "-Command"]
  }
  triggers = {
    always_run = "${timestamp()}"
  }

  depends_on = [azurerm_virtual_machine_extension.ddc_setup_extension]
}
